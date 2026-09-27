use cleaner_core::{Application, DirectoryResult, ScanSummary};
use serde::Serialize;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use tauri::{AppHandle, Emitter, Manager, State};

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
fn installed_applications() -> Vec<Application> {
    cleaner_core::installed_applications()
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
        let apps = cleaner_core::installed_applications();
        let summary = cleaner_core::scan(
            &apps,
            &cancel,
            |result: DirectoryResult| { let _ = app.emit("scan-result", result); },
            |path| { let _ = app.emit("scan-progress", ProgressEvent { path }); },
        );
        if let Ok(mut active) = app.state::<ScanState>().active.lock() {
            *active = None;
        }
        let _ = app.emit::<ScanSummary>("scan-finished", summary);
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
        .invoke_handler(tauri::generate_handler![installed_applications, start_scan, cancel_scan])
        .run(tauri::generate_context!())
        .expect("failed to start Windows Orphan Cleaner");
}
