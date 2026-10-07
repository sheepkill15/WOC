//! One command dispatcher shared by the Tauri shell and the loopback agent, so
//! both frontends always have the same capabilities.

use cleaner_core::{Definitions, ScanMode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};

use crate::{candidates, cleanup, diagnostics, folder_links, history, logging, maintenance, public_data, scan_job, storage, uninstall};

pub type Emitter = Arc<dyn Fn(&'static str, Value) + Send + Sync>;

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanState {
    run_id: u64,
    running: bool,
    mode: Option<String>,
    inventory: Option<cleaner_core::Inventory>,
    references: Option<cleaner_core::ReferenceInventory>,
    results: Vec<cleaner_core::DirectoryResult>,
    progress_path: String,
    finished: Option<scan_job::ScanFinishedEvent>,
}

pub struct Service {
    pub app_local_data: PathBuf,
    pub downloads: PathBuf,
    pub backend: &'static str,
    active: Mutex<Option<Arc<AtomicBool>>>,
    scan_state: Mutex<ScanState>,
    /// Serializes cleanup, restore and purge so plans never race each other.
    cleanup_lock: Mutex<()>,
    uninstall_plans: Mutex<HashMap<String, (uninstall::UninstallPlan, bool)>>,
    maintenance_reviews: Mutex<maintenance::Reviews>,
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
        Arc::new(Self { app_local_data, downloads, backend, active: Mutex::new(None), scan_state: Mutex::new(ScanState::default()), cleanup_lock: Mutex::new(()), uninstall_plans: Mutex::new(HashMap::new()), maintenance_reviews: Mutex::new(maintenance::Reviews::default()), emit })
    }

    fn database(&self) -> PathBuf { self.app_local_data.join("scans.sqlite3") }

    pub fn is_running(&self) -> bool {
        self.active.lock().ok().is_some_and(|active| active.is_some())
    }

    pub fn dispatch(self: &Arc<Self>, command: &str, args: &Value) -> Result<Value, String> {
        let root = &self.app_local_data;
        match command {
            "scan_maintenance" => to_value(self.maintenance_reviews.lock().map_err(|_| "Maintenance reviews are unavailable.")?.scan()),
            "maintenance_backups" => to_value(maintenance::backups(&self.database())?),
            "apply_maintenance" => {
                let _guard = self.cleanup_lock.try_lock().map_err(|_| "Another operation is in progress.")?;
                if self.is_running() { return Err("Wait for the scan to finish before changing startup or registry entries.".into()); }
                let token: String = arg(args, "token")?;
                let ids: Vec<String> = arg(args, "ids")?;
                let action: String = arg(args, "action")?;
                let selected = self.maintenance_reviews.lock().map_err(|_| "Maintenance reviews are unavailable.")?.select(&token, &ids, &action)?;
                let outcomes = maintenance::apply(&self.database(), &selected, &action);
                for outcome in &outcomes { logging::info(root, &format!("maintenance {action}: {} ({})", outcome.name, if outcome.success { "success" } else { "failed" })); }
                to_value(outcomes)
            }
            "restore_maintenance" => {
                let _guard = self.cleanup_lock.try_lock().map_err(|_| "Another operation is in progress.")?;
                if self.is_running() { return Err("Wait for the scan to finish before restoring an entry.".into()); }
                let id: i64 = arg(args, "id")?;
                maintenance::restore(&self.database(), id)?;
                logging::info(root, &format!("maintenance backup restored: {id}"));
                to_value(json!({ "restored": true }))
            }
            "open_startup_settings" => {
                let app = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
                std::process::Command::new(Path::new(&app).join("explorer.exe")).arg("ms-settings:startupapps").spawn().map_err(|e| e.to_string())?;
                to_value(json!({ "opened": true }))
            }
            "list_folder_links" => to_value(folder_links::list(&self.database())?),
            "connect_folder" => {
                let _guard = self.cleanup_lock.try_lock().map_err(|_| "A cleanup is in progress.")?;
                if self.is_running() { return Err("Wait for the scan to finish before connecting folders.".into()); }
                let path: String = arg(args, "path")?;
                let application_id: Option<String> = arg(args, "applicationId")?;
                let latest = storage::load_latest(&self.database())?.ok_or("Scan folders before connecting them.")?;
                let result = latest.results.iter().find(|r| r.path.eq_ignore_ascii_case(&path)).ok_or("This folder is not in the latest saved scan.")?;
                let inventory = cleaner_core::installed_applications();
                let application = application_id.as_ref().map(|id| inventory.applications.iter().find(|a| &a.id == id).ok_or("The selected application is no longer installed.")).transpose()?;
                folder_links::save(&self.database(), &result.path, application)?;
                logging::info(root, &format!("folder connection changed: {}", result.path));
                to_value(json!({ "saved": true }))
            }
            "plan_uninstall" => {
                let id: String = arg(args, "applicationId")?;
                let inventory = cleaner_core::installed_applications();
                if !inventory.warnings.is_empty() { return Err("Application inventory is incomplete; try again when Windows can be read.".into()); }
                let application = inventory.applications.iter().find(|a| a.id == id).ok_or("This application is no longer installed.")?;
                let latest = storage::load_latest(&self.database())?;
                let plan = uninstall::plan(application, latest.as_ref().map(|s| s.results.as_slice()).unwrap_or_default(), &inventory.applications)?;
                let token = format!("{}-{}", storage::now_unix(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
                let mut plans = self.uninstall_plans.lock().map_err(|_| "Uninstall state is unavailable")?;
                if plans.len() > 64 { plans.clear(); }
                plans.insert(token.clone(), (plan.clone(), false));
                to_value(json!({ "plan": plan, "token": token }))
            }
            "launch_uninstall" => {
                let _guard = self.cleanup_lock.try_lock().map_err(|_| "A cleanup is in progress.")?;
                if self.is_running() { return Err("Wait for the scan to finish before uninstalling.".into()); }
                let token: String = arg(args, "token")?;
                let mut plans = self.uninstall_plans.lock().map_err(|_| "Uninstall state is unavailable")?;
                let (reviewed, launched) = plans.get_mut(&token).ok_or("Review this application again before uninstalling.")?;
                if *launched { return Err("This uninstaller has already been started. Check whether it finished.".into()); }
                let inventory = cleaner_core::installed_applications();
                let app = inventory.applications.iter().find(|a| a.id == reviewed.application.id).ok_or("This application is no longer installed.")?;
                let latest = storage::load_latest(&self.database())?;
                let fresh = uninstall::plan(app, latest.as_ref().map(|s| s.results.as_slice()).unwrap_or_default(), &inventory.applications)?;
                if fresh != *reviewed { return Err("The uninstaller or linked folders changed. Review this application again.".into()); }
                uninstall::launch(reviewed)?;
                *launched = true;
                logging::info(root, &format!("uninstaller launched: {}", app.name));
                to_value(json!({ "started": true }))
            }
            "finish_uninstall" => {
                let _guard = self.cleanup_lock.try_lock().map_err(|_| "A cleanup is in progress.")?;
                if self.is_running() { return Err("Wait for the scan to finish before checking uninstall.".into()); }
                let token: String = arg(args, "token")?;
                let plans = self.uninstall_plans.lock().map_err(|_| "Uninstall state is unavailable")?;
                let (plan, launched) = plans.get(&token).ok_or("This uninstall review has expired.")?;
                if !launched { return Err("Start the reviewed uninstaller first.".into()); }
                let inventory = cleaner_core::installed_applications();
                uninstall::verify(&plan.application, &inventory)?;
                let paths: Vec<_> = plan.folders.iter().filter(|p| Path::new(p).exists()).cloned().collect();
                to_value(json!({ "paths": paths, "inventory": inventory }))
            }
            "scan_state" => to_value(self.scan_state.lock().map_err(|_| "Scan state is unavailable")?.clone()),
            "scan_status" => {
                let state = self.scan_state.lock().map_err(|_| "Scan state is unavailable")?;
                to_value(json!({ "runId": state.run_id, "running": state.running, "resultCount": state.results.len() }))
            }
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
            "load_latest_scan" => {
                let mut scan = storage::load_latest(&self.database())?;
                let excluded = cleanup::quarantined_paths(root);
                if let Some(scan) = &mut scan {
                    let conn = storage::open_db(&self.database())?;
                    let removed: Vec<_> = excluded.iter().map(|path| {
                        let saved_size = scan.results.iter().find(|r| r.path.eq_ignore_ascii_case(path)).map(|r| r.size_bytes)
                            .or_else(|| scan.results.iter().find_map(|r| r.content.items.iter().find(|item| Path::new(&r.path).join(&item.name).to_string_lossy().eq_ignore_ascii_case(path)).map(|item| item.size_bytes)));
                        let bytes = saved_size.unwrap_or_else(|| conn.query_row("SELECT size_bytes FROM quarantine_items WHERE original_path = ?1 COLLATE NOCASE ORDER BY id DESC LIMIT 1", [path], |row| row.get::<_, i64>(0)).unwrap_or_default().max(0) as u64);
                        (path.clone(), bytes)
                    }).collect();
                    prune_removed_results(&mut scan.results, &removed);
                }
                to_value(scan)
            }
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
                let _guard = self.cleanup_lock.try_lock().map_err(|_| "Another operation is in progress.")?;
                if self.is_running() { return Err("Wait for the current scan to finish first.".into()); }
                let cancel = AtomicBool::new(false);
                to_value(scan_job::post_uninstall(root, &cancel)?)
            }
            "public_data_status" => public_data::load(root).map(|(_, status)| status).and_then(to_value),
            "update_public_data" => {
                let _guard = self.cleanup_lock.try_lock().map_err(|_| "Another operation is in progress.")?;
                if self.is_running() { return Err("The running scan is already updating folder databases.".into()); }
                to_value(public_data::update(root)?)
            }
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
                let rules = storage::list_ignore_rules(&self.database())?;
                let manual_cleanup: Option<bool> = arg(args, "manualCleanup")?;
                let inventory = cleaner_core::installed_applications();
                self.validate_uninstall_cleanup(args, &paths, &inventory)?;
                let options = cleanup::PlanOptions { rules: &rules, manual_cleanup: manual_cleanup.unwrap_or(false), inventory_incomplete: !inventory.warnings.is_empty() };
                to_value(cleanup::plan(root, scan.as_ref(), &paths, &inventory.applications, &options))
            }
            "execute_cleanup" => {
                let _guard = self.cleanup_lock.lock().map_err(|_| "Cleanup state is unavailable")?;
                if self.is_running() { return Err("Wait for the running scan to finish before cleaning.".into()); }
                let request: cleanup::CleanupRequest = serde_json::from_value(args.clone()).map_err(|error| format!("Invalid cleanup request: {error}"))?;
                let scan = storage::load_latest(&self.database())?;
                let inventory = cleaner_core::installed_applications();
                self.validate_uninstall_cleanup(args, &request.paths, &inventory)?;
                let rules = storage::list_ignore_rules(&self.database())?;
                let options = cleanup::PlanOptions { rules: &rules, manual_cleanup: request.manual_cleanup, inventory_incomplete: !inventory.warnings.is_empty() };
                to_value(cleanup::execute(root, scan.as_ref(), &request, &inventory.applications, &options)?)
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

    fn validate_uninstall_cleanup(&self, args: &Value, paths: &[String], inventory: &cleaner_core::Inventory) -> Result<(), String> {
        let Some(token) = arg::<Option<String>>(args, "uninstallToken")? else { return Ok(()); };
        let plans = self.uninstall_plans.lock().map_err(|_| "Uninstall state is unavailable")?;
        let (plan, launched) = plans.get(&token).ok_or("Uninstall review expired. Review the remaining folders again.")?;
        if !launched { return Err("The reviewed uninstaller has not been started.".into()); }
        uninstall::verify(&plan.application, inventory)?;
        if paths.iter().any(|path| !plan.folders.iter().any(|p| p.eq_ignore_ascii_case(path))) { return Err("The selected folders are outside the reviewed uninstall.".into()); }
        let latest = storage::load_latest(&self.database())?;
        if let Some(latest) = latest {
            let (included, _) = uninstall::removal_folders(&plan.application, &latest.results, &inventory.applications);
            if paths.iter().any(|path| !included.iter().any(|p| p.eq_ignore_ascii_case(path))) { return Err("Folder ownership changed since the uninstall review. Review the folders again.".into()); }
        }
        Ok(())
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
        let state = {
            let mut state = self.scan_state.lock().map_err(|_| "Scan state is unavailable")?;
            let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
            *state = ScanState { run_id: timestamp.max(state.run_id.saturating_add(1)), running: true, mode: Some(mode.as_str().into()), ..Default::default() };
            json!({ "runId": state.run_id, "mode": state.mode })
        };
        (self.emit)("scan-started", state);
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
                |inventory| {
                    if let Ok(mut state) = service.scan_state.lock() { state.inventory = Some(inventory.clone()); }
                    emit_value("scan-inventory", serde_json::to_value(inventory));
                },
                |references| {
                    if let Ok(mut state) = service.scan_state.lock() { state.references = Some(references.clone()); }
                    emit_value("scan-references", serde_json::to_value(references));
                },
                |result| {
                    if let Ok(mut state) = service.scan_state.lock() { state.results.push(result.clone()); }
                    emit_value("scan-result", serde_json::to_value(result));
                },
                |path| {
                    if let Ok(mut state) = service.scan_state.lock() { state.progress_path = path.clone(); }
                    emit_value("scan-progress", Ok(json!({ "path": path })));
                },
            );
            if let Ok(mut state) = service.scan_state.lock() {
                state.running = false;
                state.progress_path.clear();
                state.finished = Some(finished.clone());
            }
            if let Ok(mut active) = service.active.lock() { *active = None; }
            emit_value("scan-finished", serde_json::to_value(&finished));
        });
        Ok(())
    }
}

fn prune_removed_results(results: &mut Vec<cleaner_core::DirectoryResult>, removed: &[(String, u64)]) {
    let within = cleaner_core::references::path_is_within;
    let roots: Vec<_> = removed.iter().filter(|(path, _)| !removed.iter().any(|(parent, _)| !parent.eq_ignore_ascii_case(path) && within(path, parent))).collect();
    results.retain(|r| !roots.iter().any(|(path, _)| within(&r.path, path)));
    for result in results {
        let bytes: u64 = roots.iter().filter(|(path, _)| within(path, &result.path)).map(|(_, bytes)| *bytes).sum();
        result.size_bytes = result.size_bytes.saturating_sub(bytes);
    }
}

#[cfg(test)]
mod catalog_tests {
    use super::*;
    #[test]
    fn persisted_cleanup_exclusions_also_reduce_parent_totals() {
        let mut results = vec![cleaner_core::DirectoryResult { path: r"C:\App".into(), size_bytes: 100, ..Default::default() }, cleaner_core::DirectoryResult { path: r"C:\App\Cache".into(), size_bytes: 30, ..Default::default() }];
        prune_removed_results(&mut results, &[(r"c:\app\cache".into(), 30)]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].size_bytes, 70);
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
