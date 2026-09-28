use cleaner_core::{DirectoryResult, Inventory, ScanSummary};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use tauri::{AppHandle, Emitter, Manager, State};

mod storage;
mod public_data;

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
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let mut active = state.active.lock().map_err(|_| "Scan state is unavailable")?;
        if active.is_some() {
            return Err("A scan is already running".into());
        }
        *active = Some(cancel.clone());
    }
    std::thread::spawn(move || {
        let local_data_dir = app.path().app_local_data_dir().map_err(|err| err.to_string());
        let mut inventory = cleaner_core::installed_applications();
        let previous_scan = match local_data_dir.as_ref() {
            Ok(directory) => match storage::load_latest(&directory.join("scans.sqlite3")) {
                Ok(scan) => scan,
                Err(error) => {
                    inventory.warnings.push(format!("Historical scan could not be loaded: {error}"));
                    None
                }
            },
            Err(_) => None,
        };
        let _ = app.emit("scan-inventory", &inventory);
        let previous_by_path: HashMap<String, &DirectoryResult> = previous_scan.as_ref()
            .map(|scan| scan.results.iter().map(|result| (result.path.to_lowercase(), result)).collect())
            .unwrap_or_default();
        let excluded_paths = local_data_dir.as_ref().map(|path| vec![path.clone()]).unwrap_or_default();
        let (knowledge, public_data_warning) = match local_data_dir.as_ref() {
            Ok(directory) => match public_data::load(directory) {
                Ok((knowledge, _)) => (knowledge, None),
                Err(error) => (Default::default(), Some(error)),
            },
            Err(_) => (Default::default(), None),
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
                        &mut result, &inventory, &previous.inventory,
                        previous_by_path.get(&path_key).copied(),
                    );
                }
                knowledge.annotate(&mut result);
                let _ = app.emit("scan-result", &result);
                results.push(result);
            },
            |path| { let _ = app.emit("scan-progress", ProgressEvent { path }); },
        );
        if let Some(warning) = public_data_warning { summary.warnings.push(warning); }
        let (saved_at_unix, save_error) = if summary.canceled {
            (None, None)
        } else if summary.scanned_roots.len() != 4 || !inventory.warnings.is_empty() {
            (None, Some("The scan or application inventory was incomplete; the previous saved scan was kept.".into()))
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
        .invoke_handler(tauri::generate_handler![installed_applications, load_latest_scan, public_data_status, update_public_data, start_scan, cancel_scan])
        .run(tauri::generate_context!())
        .expect("failed to start Windows Orphan Cleaner");
}
