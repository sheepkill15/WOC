//! One command dispatcher shared by the Tauri shell and the loopback agent, so
//! both frontends always have the same capabilities.

use cleaner_core::{Definitions, ScanMode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};

use crate::{candidates, cleanup, diagnostics, history, logging, public_data, scan_job, storage};

pub type Emitter = Arc<dyn Fn(&'static str, Value) + Send + Sync>;

pub struct Service {
    pub app_local_data: PathBuf,
    pub downloads: PathBuf,
    pub backend: &'static str,
    active: Mutex<Option<Arc<AtomicBool>>>,
    /// Serializes cleanup, restore and purge so plans never race each other.
    cleanup_lock: Mutex<()>,
    emit: Emitter,
}

fn arg<T: for<'de> Deserialize<'de>>(args: &Value, name: &str) -> Result<T, String> {
    serde_json::from_value(args.get(name).cloned().unwrap_or(Value::Null))
        .map_err(|error| format!("Invalid argument '{name}': {error}"))
}

fn to_value<T: serde::Serialize>(value: T) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|error| error.to_string())
}

impl Service {
    pub fn new(app_local_data: PathBuf, downloads: PathBuf, backend: &'static str, emit: Emitter) -> Arc<Self> {
        Arc::new(Self { app_local_data, downloads, backend, active: Mutex::new(None), cleanup_lock: Mutex::new(()), emit })
    }

    fn database(&self) -> PathBuf { self.app_local_data.join("scans.sqlite3") }

    pub fn is_running(&self) -> bool {
        self.active.lock().ok().is_some_and(|active| active.is_some())
    }

    pub fn dispatch(self: &Arc<Self>, command: &str, args: &Value) -> Result<Value, String> {
        let root = &self.app_local_data;
        match command {
            "app_info" => to_value(json!({
                "version": env!("CARGO_PKG_VERSION"),
                "backend": self.backend,
                "running": self.is_running(),
                "dataDirectory": root.to_string_lossy(),
                "quarantineDirectory": cleanup::quarantine_root(root).to_string_lossy(),
                "definitionsDirectory": scan_job::definitions_directory(root).to_string_lossy(),
                "logFile": logging::log_path(root).to_string_lossy(),
            })),
            "installed_applications" => to_value(cleaner_core::installed_applications()),
            "load_latest_scan" => to_value(storage::load_latest(&self.database())?),
            "load_history_report" => {
                let (latest, inventories) = storage::load_history_inputs(&self.database())?;
                to_value(latest.map(|latest| history::build_from(&latest, &inventories)).unwrap_or_default())
            }
            "load_candidates" => {
                let (latest, inventories) = storage::load_history_inputs(&self.database())?;
                let Some(latest) = latest else { return to_value(candidates::CandidateReport::default()); };
                let rules = storage::list_ignore_rules(&self.database())?;
                let history = history::build_from(&latest, &inventories);
                let newly: HashSet<String> = history.applications.iter().filter(|item| item.newly_missing)
                    .map(|item| cleaner_core::normalize_name(&item.application.name)).collect();
                let quarantined = cleanup::quarantined_paths(root);
                to_value(candidates::build(&latest, &rules, &quarantined, &newly))
            }
            "detect_removed_applications" => to_value(scan_job::detect_removed(root)?),
            "post_uninstall_scan" => {
                let cancel = AtomicBool::new(false);
                to_value(scan_job::post_uninstall(root, &cancel)?)
            }
            "public_data_status" => public_data::load(root).map(|(_, status)| status).and_then(to_value),
            "update_public_data" => to_value(public_data::update(root)?),
            "export_diagnostics" => {
                let scans = storage::load_recent(&self.database(), storage::RETAINED_SCANS)?;
                let status = public_data::load(root).map(|(_, status)| status).unwrap_or_default();
                to_value(diagnostics::export(&self.downloads, root, &scans, &status)?)
            }
            "start_scan" => {
                let mode: Option<String> = arg(args, "mode")?;
                let mode = match mode.as_deref() {
                    Some(value) => ScanMode::parse(value).ok_or_else(|| format!("Unknown scan mode: {value}"))?,
                    None => ScanMode::parse(&storage::load_settings(&self.database())?.default_scan_mode).unwrap_or_default(),
                };
                self.start_scan(mode)?;
                to_value(json!({ "started": true, "mode": mode.as_str() }))
            }
            "cancel_scan" => {
                let active = self.active.lock().map_err(|_| "Scan state is unavailable")?;
                if let Some(cancel) = active.as_ref() { cancel.store(true, Ordering::Relaxed); }
                to_value(json!({ "canceled": active.is_some() }))
            }
            "list_ignore_rules" => to_value(storage::list_ignore_rules(&self.database())?),
            "add_ignore_rule" => {
                let kind: String = arg(args, "kind")?;
                let value: String = arg(args, "value")?;
                let label: Option<String> = arg(args, "label")?;
                let scan_at = if kind == "once" { storage::load_latest(&self.database())?.map(|scan| scan.captured_at_unix) } else { None };
                let rule = storage::add_ignore_rule(&self.database(), &kind, &value, label.as_deref().unwrap_or(&value), scan_at)?;
                logging::info(root, &format!("ignore rule added: {} {}", rule.kind, rule.value));
                to_value(rule)
            }
            "remove_ignore_rule" => {
                let id: i64 = arg(args, "id")?;
                storage::remove_ignore_rule(&self.database(), id)?;
                to_value(json!({ "removed": id }))
            }
            "plan_cleanup" => {
                let paths: Vec<String> = arg(args, "paths")?;
                let scan = storage::load_latest(&self.database())?;
                let ignored = self.ignored_paths(scan.as_ref())?;
                let inventory = cleaner_core::installed_applications();
                to_value(cleanup::plan(root, scan.as_ref(), &paths, &inventory.applications, &ignored))
            }
            "execute_cleanup" => {
                if self.is_running() { return Err("Wait for the running scan to finish before cleaning.".into()); }
                let _guard = self.cleanup_lock.lock().map_err(|_| "Cleanup state is unavailable")?;
                let request: cleanup::CleanupRequest = serde_json::from_value(args.clone()).map_err(|error| format!("Invalid cleanup request: {error}"))?;
                let scan = storage::load_latest(&self.database())?;
                let inventory = cleaner_core::installed_applications();
                if !inventory.warnings.is_empty() {
                    return Err("The installed-application inventory is incomplete right now, so ownership cannot be revalidated. Nothing was moved.".into());
                }
                let ignored = self.ignored_paths(scan.as_ref())?;
                to_value(cleanup::execute(root, scan.as_ref(), &request, &inventory.applications, &ignored)?)
            }
            "list_quarantine" => {
                let _guard = self.cleanup_lock.lock().map_err(|_| "Cleanup state is unavailable")?;
                to_value(cleanup::report(root)?)
            }
            "restore_quarantine" => {
                let _guard = self.cleanup_lock.lock().map_err(|_| "Cleanup state is unavailable")?;
                to_value(cleanup::restore(root, arg(args, "id")?)?)
            }
            "purge_quarantine" => {
                let _guard = self.cleanup_lock.lock().map_err(|_| "Cleanup state is unavailable")?;
                to_value(cleanup::purge(root, arg(args, "id")?)?)
            }
            "get_settings" => to_value(storage::load_settings(&self.database())?),
            "update_settings" => {
                let settings: storage::Settings = arg(args, "settings")?;
                storage::save_settings(&self.database(), &settings)?;
                to_value(settings)
            }
            "definitions_status" => {
                let directory = scan_job::definitions_directory(root);
                let _ = std::fs::create_dir_all(&directory);
                let definitions = Definitions::load(&directory);
                to_value(json!({
                    "directory": directory.to_string_lossy(),
                    "builtIn": definitions.definitions.len() - definitions.user_definition_count(),
                    "user": definitions.user_definition_count(),
                    "warnings": definitions.warnings,
                    "products": definitions.definitions.iter().map(|definition| json!({ "id": definition.id, "product": definition.product, "source": definition.source, "paths": definition.paths.len() })).collect::<Vec<_>>(),
                }))
            }
            "open_path" => {
                let path: String = arg(args, "path")?;
                open_in_explorer(&path)?;
                to_value(json!({ "opened": true }))
            }
            other => Err(format!("Unknown command: {other}")),
        }
    }

    /// Paths kept by "always ignore" rules and by "hide once" rules for the current scan.
    fn ignored_paths(&self, scan: Option<&storage::SavedScan>) -> Result<Vec<String>, String> {
        let captured = scan.map(|scan| scan.captured_at_unix);
        Ok(storage::list_ignore_rules(&self.database())?.into_iter()
            .filter(|rule| rule.kind == "path" || (rule.kind == "once" && rule.scan_at_unix == captured))
            .map(|rule| rule.value)
            .collect())
    }

    fn start_scan(self: &Arc<Self>, mode: ScanMode) -> Result<(), String> {
        // A scan saves a new snapshot; never start one while a cleanup is moving files.
        let _cleanup = self.cleanup_lock.try_lock().map_err(|_| "A cleanup is in progress; start the scan when it finishes.")?;
        let cancel = Arc::new(AtomicBool::new(false));
        {
            let mut active = self.active.lock().map_err(|_| "Scan state is unavailable")?;
            if active.is_some() { return Err("A scan is already running".into()); }
            *active = Some(cancel.clone());
        }
        let service = Arc::clone(self);
        std::thread::spawn(move || {
            let emit = service.emit.clone();
            let emit_value = |name: &'static str, value: Result<Value, serde_json::Error>| {
                if let Ok(value) = value { emit(name, value); }
            };
            let finished = scan_job::execute(
                service.app_local_data.clone(),
                mode,
                cancel,
                |inventory| emit_value("scan-inventory", serde_json::to_value(inventory)),
                |references| emit_value("scan-references", serde_json::to_value(references)),
                |result| emit_value("scan-result", serde_json::to_value(result)),
                |path| emit_value("scan-progress", Ok(json!({ "path": path }))),
            );
            if let Ok(mut active) = service.active.lock() { *active = None; }
            emit_value("scan-finished", serde_json::to_value(&finished));
        });
        Ok(())
    }
}

/// Opens a folder, or selects a file, in Explorer. Never launches the item itself.
fn open_in_explorer(path: &str) -> Result<(), String> {
    let candidate = Path::new(path);
    if !candidate.is_absolute() || path.starts_with(r"\\") || path.contains('"') {
        return Err("Only local absolute paths can be opened.".into());
    }
    let metadata = std::fs::symlink_metadata(candidate).map_err(|_| "The path no longer exists.")?;
    let explorer = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows")).join("explorer.exe");
    let mut command = std::process::Command::new(explorer);
    let argument = if metadata.is_dir() {
        // "<folder>\." only resolves to a folder: if the path were swapped for a file
        // after the check, Explorer fails instead of opening the file.
        format!("\"{}\\.\"", path.trim_end_matches('\\'))
    } else {
        // /select only highlights the file; it is not opened or executed.
        format!("/select,\"{path}\"")
    };
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.raw_arg(argument);
    }
    #[cfg(not(windows))]
    command.arg(argument);
    command.spawn().map(|_| ()).map_err(|error| format!("Explorer could not be started: {error}"))
}
