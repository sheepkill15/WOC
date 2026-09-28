use cleaner_core::{Definitions, DirectoryResult, Inventory, ReferenceInventory, ScanMode, ScanSummary, ScanTarget};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::AtomicBool};

use crate::{history, logging, public_data, storage};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanFinishedEvent {
    pub summary: ScanSummary,
    pub saved_at_unix: Option<u64>,
    pub save_error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostUninstallReport {
    pub removed: history::RemovedReport,
    pub results: Vec<DirectoryResult>,
    pub summary: ScanSummary,
}

pub fn definitions_directory(local_data_dir: &Path) -> PathBuf {
    local_data_dir.join("definitions")
}

/// Everything applied to a measured directory after the core classification.
struct Annotator<'a> {
    inventory: &'a Inventory,
    previous: Option<&'a storage::SavedScan>,
    previous_by_path: HashMap<String, &'a DirectoryResult>,
    knowledge: public_data::Knowledge,
    definitions: &'a Definitions,
    references: &'a ReferenceInventory,
}

impl<'a> Annotator<'a> {
    fn new(inventory: &'a Inventory, previous: Option<&'a storage::SavedScan>, knowledge: public_data::Knowledge, definitions: &'a Definitions, references: &'a ReferenceInventory) -> Self {
        let previous_by_path = previous
            .map(|scan| scan.results.iter().map(|result| (result.path.to_lowercase(), result)).collect())
            .unwrap_or_default();
        Self { inventory, previous, previous_by_path, knowledge, definitions, references }
    }

    fn annotate(&self, result: &mut DirectoryResult) {
        if let Some(previous) = self.previous {
            cleaner_core::apply_history(result, self.inventory, &previous.inventory, self.previous_by_path.get(&result.path.to_lowercase()).copied());
        }
        self.knowledge.annotate(result);
        self.definitions.annotate(result, &self.inventory.applications);
        cleaner_core::apply_references(result, &self.references.references);
        cleaner_core::finalize(result);
    }
}

pub fn execute<I, R, P, F>(
    local_data_dir: PathBuf,
    mode: ScanMode,
    cancel: Arc<AtomicBool>,
    mut on_inventory: I,
    mut on_references: F,
    mut on_result: R,
    mut on_progress: P,
) -> ScanFinishedEvent
where
    I: FnMut(&Inventory),
    F: FnMut(&ReferenceInventory),
    R: FnMut(&DirectoryResult),
    P: FnMut(String),
{
    logging::info(&local_data_dir, &format!("{} scan started", mode.as_str()));
    on_progress("Reading installed applications".into());
    let mut inventory = cleaner_core::installed_applications();
    let database = local_data_dir.join("scans.sqlite3");
    let previous_scan = match storage::load_latest(&database) {
        Ok(scan) => scan,
        Err(error) => {
            inventory.warnings.push(format!("Historical scan could not be loaded: {error}"));
            None
        }
    };
    on_inventory(&inventory);
    on_progress("Reading startup entries, services, scheduled tasks and shortcuts".into());
    let references = cleaner_core::references::collect(&inventory.applications);
    on_references(&references);
    let definitions = Definitions::load(&definitions_directory(&local_data_dir));
    let (knowledge, public_data_warning) = match public_data::load(&local_data_dir) {
        Ok((knowledge, _)) => (knowledge, None),
        Err(error) => (Default::default(), Some(error)),
    };
    let annotator = Annotator::new(&inventory, previous_scan.as_ref(), knowledge, &definitions, &references);
    let excluded_paths = vec![local_data_dir.clone()];
    let mut results = Vec::new();
    let mut summary = cleaner_core::scan_with_mode(
        &inventory.applications,
        mode,
        &excluded_paths,
        &cancel,
        |mut result: DirectoryResult| {
            annotator.annotate(&mut result);
            on_result(&result);
            results.push(result);
        },
        |path| on_progress(path),
    );
    if let Some(warning) = public_data_warning {
        summary.warnings.push(warning);
    }
    summary.warnings.extend(references.warnings.iter().cloned());
    summary.warnings.extend(definitions.warnings.iter().map(|warning| format!("Definitions: {warning}")));
    let (saved_at_unix, save_error) = if summary.canceled {
        (None, None)
    } else if !summary.complete || !inventory.warnings.is_empty() {
        (None, Some("The scan or application inventory was incomplete; the previous saved scan was kept.".into()))
    } else {
        match storage::save(&database, inventory, summary.clone(), results, references.clone()) {
            Ok(time) => (Some(time), None),
            Err(error) => (None, Some(format!("Scan completed, but saving failed: {error}"))),
        }
    };
    logging::info(&local_data_dir, &format!(
        "{} scan finished: {} directories, {} bytes, canceled={}, saved={}, {} ms",
        mode.as_str(), summary.directories, summary.bytes, summary.canceled, saved_at_unix.is_some(), summary.duration_ms,
    ));
    if let Some(error) = &save_error { logging::warn(&local_data_dir, error); }
    ScanFinishedEvent { summary, saved_at_unix, save_error }
}

/// Lists applications removed since the latest saved scan.
pub fn detect_removed(local_data_dir: &Path) -> Result<history::RemovedReport, String> {
    let Some(latest) = storage::load_latest(&local_data_dir.join("scans.sqlite3"))? else {
        return Ok(history::RemovedReport::default());
    };
    let current = cleaner_core::installed_applications();
    Ok(history::detect_removed(&latest, &current, |path| Path::new(path).is_dir()))
}

/// Post-uninstall scan (spec §29): re-measures only directories previously linked
/// to applications that have since disappeared. Results are not saved as a snapshot.
pub fn post_uninstall(local_data_dir: &Path, cancel: &AtomicBool) -> Result<PostUninstallReport, String> {
    let database = local_data_dir.join("scans.sqlite3");
    let Some(latest) = storage::load_latest(&database)? else {
        return Err("Run a full scan first; the post-uninstall check compares against it.".into());
    };
    let inventory = cleaner_core::installed_applications();
    let removed = history::detect_removed(&latest, &inventory, |path| Path::new(path).is_dir());
    let targets: Vec<ScanTarget> = removed.applications.iter()
        .flat_map(|application| application.directories.iter())
        .filter_map(|directory| {
            let previous = latest.results.iter().find(|result| result.path.eq_ignore_ascii_case(&directory.path))?;
            Some(ScanTarget {
                path: PathBuf::from(&directory.path),
                root: directory.root.clone(),
                parent_path: previous.parent_path.as_ref().map(PathBuf::from),
                count_bytes: previous.parent_path.is_none(),
                loose_only: false,
            })
        })
        .collect();
    let started = std::time::Instant::now();
    let mut summary = ScanSummary { mode: "post_uninstall".into(), started_at_unix: storage::now_unix(), complete: true, ..Default::default() };
    let definitions = Definitions::load(&definitions_directory(local_data_dir));
    let knowledge = public_data::load(local_data_dir).map(|(knowledge, _)| knowledge).unwrap_or_default();
    let references = cleaner_core::references::collect(&inventory.applications);
    let annotator = Annotator::new(&inventory, Some(&latest), knowledge, &definitions, &references);
    let mut results = Vec::new();
    cleaner_core::scan_targets(targets, &inventory.applications, cancel, &mut summary, |mut result| {
        annotator.annotate(&mut result);
        results.push(result);
    }, |_| {});
    summary.canceled = cancel.load(std::sync::atomic::Ordering::Relaxed);
    summary.duration_ms = started.elapsed().as_millis() as u64;
    logging::info(local_data_dir, &format!("post-uninstall check: {} removed applications, {} directories", removed.applications.len(), results.len()));
    Ok(PostUninstallReport { removed, results, summary })
}
