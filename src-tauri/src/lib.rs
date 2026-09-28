use cleaner_core::Inventory;
use serde::Serialize;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use tauri::{AppHandle, Emitter, Manager, State};

mod storage;
mod public_data;
mod history;
mod diagnostics;
mod scan_job;
mod agent;

#[derive(Default)]
struct ScanState {
    active: Mutex<Option<Arc<AtomicBool>>>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProgressEvent {
    path: String,
}

#[tauri::command]
fn installed_applications() -> Inventory {
    cleaner_core::installed_applications()
}

#[tauri::command]
fn load_latest_scan(app: AppHandle) -> Result<Option<storage::SavedScan>, String> {
    let directory = app.path().app_local_data_dir().map_err(|err| err.to_string())?;
    storage::load_latest(&directory.join("scans.sqlite3"))
}

#[tauri::command]
fn load_history_report(app: AppHandle) -> Result<history::HistoryReport, String> {
    let directory = app.path().app_local_data_dir().map_err(|err| err.to_string())?;
    let scans = storage::load_recent(&directory.join("scans.sqlite3"), 10)?;
    Ok(history::build(&scans))
}

#[tauri::command]
fn export_diagnostics(app: AppHandle) -> Result<diagnostics::DiagnosticsExport, String> {
    let app_local_data = app.path().app_local_data_dir().map_err(|err| err.to_string())?;
    let downloads = app.path().download_dir().map_err(|err| err.to_string())?;
    let scans = storage::load_recent(&app_local_data.join("scans.sqlite3"), 10)?;
    let status = public_data::load(&app_local_data).map(|(_, status)| status).unwrap_or_default();
    diagnostics::export(&downloads, &app_local_data, &scans, &status)
}

#[tauri::command]
fn public_data_status(app: AppHandle) -> Result<public_data::PublicDataStatus, String> {
    let directory = app.path().app_local_data_dir().map_err(|err| err.to_string())?;
    public_data::load(&directory).map(|(_, status)| status)
}

#[tauri::command]
async fn update_public_data(app: AppHandle) -> Result<public_data::PublicDataStatus, String> {
    let directory = app.path().app_local_data_dir().map_err(|err| err.to_string())?;
    tauri::async_runtime::spawn_blocking(move || public_data::update(&directory))
        .await.map_err(|err| err.to_string())?
}

#[tauri::command]
fn start_scan(app: AppHandle, state: State<'_, ScanState>) -> Result<(), String> {
    let local_data_dir = app.path().app_local_data_dir().map_err(|err| err.to_string())?;
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let mut active = state.active.lock().map_err(|_| "Scan state is unavailable")?;
        if active.is_some() {
            return Err("A scan is already running".into());
        }
        *active = Some(cancel.clone());
    }
    std::thread::spawn(move || {
        let finished = scan_job::execute(
            local_data_dir,
            cancel,
            |inventory| { let _ = app.emit("scan-inventory", inventory); },
            |result| { let _ = app.emit("scan-result", result); },
            |path| { let _ = app.emit("scan-progress", ProgressEvent { path }); },
        );
        if let Ok(mut active) = app.state::<ScanState>().active.lock() {
            *active = None;
        }
        let _ = app.emit("scan-finished", finished);
    });
    Ok(())
}

#[tauri::command]
fn cancel_scan(state: State<'_, ScanState>) -> Result<(), String> {
    let active = state.active.lock().map_err(|_| "Scan state is unavailable")?;
    if let Some(cancel) = active.as_ref() {
        cancel.store(true, Ordering::Relaxed);
    }
    Ok(())
}

pub fn run() {
    tauri::Builder::default()
        .manage(ScanState::default())
        .invoke_handler(tauri::generate_handler![installed_applications, load_latest_scan, load_history_report, export_diagnostics, public_data_status, update_public_data, start_scan, cancel_scan])
        .run(tauri::generate_context!())
        .expect("failed to start Windows Orphan Cleaner");
}

pub async fn run_agent() -> Result<(), String> {
    agent::run().await
}
