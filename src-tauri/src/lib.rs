use serde_json::Value;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager, State};

mod agent;
mod candidates;
mod cleanup;
mod diagnostics;
mod folder_links;
mod maintenance;
mod uninstall;
mod history;
mod logging;
mod public_data;
mod scan_job;
mod service;
mod storage;

use service::Service;

/// Single IPC entry point; see `service::Service::dispatch` for the command list.
#[tauri::command]
async fn backend(state: State<'_, Arc<Service>>, command: String, args: Option<Value>) -> Result<Value, String> {
    let service = state.inner().clone();
    let args = args.unwrap_or(Value::Null);
    tauri::async_runtime::spawn_blocking(move || service.dispatch(&command, &args))
        .await
        .map_err(|error| error.to_string())?
}

pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let handle: AppHandle = app.handle().clone();
            let local = app.path().app_local_data_dir()?;
            let downloads = app.path().download_dir().unwrap_or_else(|_| local.join("exports"));
            let emitter = handle.clone();
            let service = Service::new(local, downloads, "tauri", Arc::new(move |name, payload| { let _ = emitter.emit(name, payload); }));
            app.manage(service);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![backend])
        .run(tauri::generate_context!())
        .expect("failed to start Windows Orphan Cleaner");
}

pub async fn run_agent() -> Result<(), String> {
    agent::run().await
}
