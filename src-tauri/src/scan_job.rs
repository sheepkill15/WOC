use cleaner_core::{DirectoryResult, Inventory, ScanSummary};
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, atomic::AtomicBool};

use crate::{public_data, storage};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanFinishedEvent {
    pub summary: ScanSummary,
    pub saved_at_unix: Option<u64>,
    pub save_error: Option<String>,
}

pub fn execute<I, R, P>(
    local_data_dir: PathBuf,
    cancel: Arc<AtomicBool>,
    mut on_inventory: I,
    mut on_result: R,
    on_progress: P,
) -> ScanFinishedEvent
where
    I: FnMut(&Inventory),
    R: FnMut(&DirectoryResult),
    P: FnMut(String),
{
    let mut inventory = cleaner_core::installed_applications();
    let database = local_data_dir.join("scans.sqlite3");
    let previous_scan = match storage::load_latest(&database) {
        Ok(scan) => scan,
        Err(error) => {
            inventory
                .warnings
                .push(format!("Historical scan could not be loaded: {error}"));
            None
        }
    };
    on_inventory(&inventory);
    let previous_by_path: HashMap<String, &DirectoryResult> = previous_scan
        .as_ref()
        .map(|scan| {
            scan.results
                .iter()
                .map(|result| (result.path.to_lowercase(), result))
                .collect()
        })
        .unwrap_or_default();
    let excluded_paths = vec![local_data_dir.clone()];
    let (knowledge, public_data_warning) = match public_data::load(&local_data_dir) {
        Ok((knowledge, _)) => (knowledge, None),
        Err(error) => (Default::default(), Some(error)),
    };
    let mut results = Vec::new();
    let mut summary = cleaner_core::scan(
        &inventory.applications,
        &excluded_paths,
        &cancel,
        |mut result: DirectoryResult| {
            if let Some(previous) = previous_scan.as_ref() {
                let path_key = result.path.to_lowercase();
                cleaner_core::apply_history(
                    &mut result,
                    &inventory,
                    &previous.inventory,
                    previous_by_path.get(&path_key).copied(),
                );
            }
            knowledge.annotate(&mut result);
            on_result(&result);
            results.push(result);
        },
        on_progress,
    );
    if let Some(warning) = public_data_warning {
        summary.warnings.push(warning);
    }
    let (saved_at_unix, save_error) = if summary.canceled {
        (None, None)
    } else if summary.scanned_roots.len() != 4 || !inventory.warnings.is_empty() {
        (None, Some("The scan or application inventory was incomplete; the previous saved scan was kept.".into()))
    } else {
        match storage::save(&database, inventory, summary.clone(), results) {
            Ok(time) => (Some(time), None),
            Err(error) => (
                None,
                Some(format!("Scan completed, but saving failed: {error}")),
            ),
        }
    };
    ScanFinishedEvent {
        summary,
        saved_at_unix,
        save_error,
    }
}
