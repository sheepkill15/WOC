use cleaner_core::{DirectoryResult, Inventory, ScanSummary};
use serde::Serialize;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use tauri::{AppHandle, Emitter, Manager, State};

mod storage;

#[derive(Default)]
struct ScanState {
    active: Mutex<Option<Arc<AtomicBool>>>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProgressEvent {
    path: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanFinishedEvent {
    summary: ScanSummary,
    saved_at_unix: Option<u64>,
    save_error: Option<String>,
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
fn start_scan(app: AppHandle, state: State<'_, ScanState>) -> Result<(), String> {
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let mut active = state.active.lock().map_err(|_| "Scan state is unavailable")?;
        if active.is_some() {
            return Err("A scan is already running".into());
        }
        *active = Some(cancel.clone());
    }
    std::thread::spawn(move || {
        let inventory = cleaner_core::installed_applications();
        let _ = app.emit("scan-inventory", &inventory);
        let local_data_dir = app.path().app_local_data_dir().map_err(|err| err.to_string());
        let excluded_paths = local_data_dir.as_ref().map(|path| vec![path.clone()]).unwrap_or_default();
        let mut results = Vec::new();
        let summary = cleaner_core::scan(
            &inventory.applications,
            &excluded_paths,
            &cancel,
            |result: DirectoryResult| {
                let _ = app.emit("scan-result", &result);
                results.push(result);
            },
            |path| { let _ = app.emit("scan-progress", ProgressEvent { path }); },
        );
        let (saved_at_unix, save_error) = if summary.canceled {
            (None, None)
        } else if summary.scanned_roots.len() != 4 {
            (None, Some("The scan did not cover all four roots; the previous saved scan was kept.".into()))
        } else {
            let result = local_data_dir
                .and_then(|directory| storage::save(&directory.join("scans.sqlite3"), inventory, summary.clone(), results));
            match result {
                Ok(time) => (Some(time), None),
                Err(error) => (None, Some(format!("Scan completed, but saving failed: {error}"))),
            }
        };
        if let Ok(mut active) = app.state::<ScanState>().active.lock() {
            *active = None;
        }
        let _ = app.emit("scan-finished", ScanFinishedEvent { summary, saved_at_unix, save_error });
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
        .invoke_handler(tauri::generate_handler![installed_applications, load_latest_scan, start_scan, cancel_scan])
        .run(tauri::generate_context!())
        .expect("failed to start Windows Orphan Cleaner");
}
