use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header::CONTENT_TYPE};
use axum::response::{
    IntoResponse, Response,
    sse::{Event, KeepAlive, Sse},
};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use serde_json::{Value, json};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::broadcast;
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::{diagnostics, history, public_data, scan_job, storage};

const CLIENT_HEADER: &str = "x-orphan-cleaner-client";

#[derive(Clone)]
struct AgentState {
    app_local_data: PathBuf,
    downloads: PathBuf,
    active: Arc<Mutex<Option<Arc<AtomicBool>>>>,
    events: broadcast::Sender<AgentEvent>,
}

#[derive(Clone, Debug)]
struct AgentEvent {
    name: &'static str,
    payload: Value,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

impl From<String> for ApiError {
    fn from(value: String) -> Self {
        Self::internal(value)
    }
}

fn require_client(headers: &HeaderMap) -> Result<(), ApiError> {
    if headers
        .get(CLIENT_HEADER)
        .and_then(|value| value.to_str().ok())
        == Some("web-v1")
    {
        Ok(())
    } else {
        Err(ApiError::forbidden("Missing cleaner-agent client header"))
    }
}

fn emit<T: Serialize>(sender: &broadcast::Sender<AgentEvent>, name: &'static str, payload: &T) {
    if let Ok(payload) = serde_json::to_value(payload) {
        let _ = sender.send(AgentEvent { name, payload });
    }
}

async fn health(State(state): State<AgentState>) -> Json<Value> {
    let running = state
        .active
        .lock()
        .ok()
        .is_some_and(|active| active.is_some());
    Json(json!({
        "service": "windows-orphan-cleaner-agent",
        "version": env!("CARGO_PKG_VERSION"),
        "transportVersion": 1,
        "running": running,
    }))
}

async fn installed_applications() -> Result<Json<cleaner_core::Inventory>, ApiError> {
    tokio::task::spawn_blocking(cleaner_core::installed_applications)
        .await
        .map(Json)
        .map_err(|error| ApiError::internal(error.to_string()))
}

async fn load_latest_scan(
    State(state): State<AgentState>,
) -> Result<Json<Option<storage::SavedScan>>, ApiError> {
    storage::load_latest(&state.app_local_data.join("scans.sqlite3"))
        .map(Json)
        .map_err(Into::into)
}

async fn load_history_report(
    State(state): State<AgentState>,
) -> Result<Json<history::HistoryReport>, ApiError> {
    let scans = storage::load_recent(&state.app_local_data.join("scans.sqlite3"), 10)?;
    Ok(Json(history::build(&scans)))
}

async fn public_data_status(
    State(state): State<AgentState>,
) -> Result<Json<public_data::PublicDataStatus>, ApiError> {
    public_data::load(&state.app_local_data)
        .map(|(_, status)| Json(status))
        .map_err(Into::into)
}

async fn update_public_data(
    headers: HeaderMap,
    State(state): State<AgentState>,
) -> Result<Json<public_data::PublicDataStatus>, ApiError> {
    require_client(&headers)?;
    let directory = state.app_local_data.clone();
    tokio::task::spawn_blocking(move || public_data::update(&directory))
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
        .map(Json)
        .map_err(Into::into)
}

async fn export_diagnostics(
    headers: HeaderMap,
    State(state): State<AgentState>,
) -> Result<Json<diagnostics::DiagnosticsExport>, ApiError> {
    require_client(&headers)?;
    let scans = storage::load_recent(&state.app_local_data.join("scans.sqlite3"), 10)?;
    let status = public_data::load(&state.app_local_data)
        .map(|(_, status)| status)
        .unwrap_or_default();
    diagnostics::export(&state.downloads, &state.app_local_data, &scans, &status)
        .map(Json)
        .map_err(Into::into)
}

async fn start_scan(
    headers: HeaderMap,
    State(state): State<AgentState>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    require_client(&headers)?;
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let mut active = state
            .active
            .lock()
            .map_err(|_| ApiError::internal("Scan state is unavailable"))?;
        if active.is_some() {
            return Err(ApiError::conflict("A scan is already running"));
        }
        *active = Some(cancel.clone());
    }
    let job_state = state.clone();
    std::thread::spawn(move || {
        let events = job_state.events.clone();
        let progress_events = events.clone();
        let result_events = events.clone();
        let finished = scan_job::execute(
            job_state.app_local_data.clone(),
            cancel,
            |inventory| emit(&events, "scan-inventory", inventory),
            |result| emit(&result_events, "scan-result", result),
            |path| emit(&progress_events, "scan-progress", &json!({ "path": path })),
        );
        if let Ok(mut active) = job_state.active.lock() {
            *active = None;
        }
        emit(&job_state.events, "scan-finished", &finished);
    });
    Ok((StatusCode::ACCEPTED, Json(json!({ "started": true }))))
}

async fn cancel_scan(
    headers: HeaderMap,
    State(state): State<AgentState>,
) -> Result<Json<Value>, ApiError> {
    require_client(&headers)?;
    let active = state
        .active
        .lock()
        .map_err(|_| ApiError::internal("Scan state is unavailable"))?;
    if let Some(cancel) = active.as_ref() {
        cancel.store(true, Ordering::Relaxed);
    }
    Ok(Json(json!({ "canceled": active.is_some() })))
}

async fn events(
    State(state): State<AgentState>,
) -> Sse<impl futures_core::Stream<Item = Result<Event, Infallible>>> {
    let mut receiver = state.events.subscribe();
    let stream = async_stream::stream! {
        loop {
            match receiver.recv().await {
                Ok(message) => {
                    let event = Event::default().event(message.name)
                        .data(serde_json::to_string(&message.payload).unwrap_or_else(|_| "null".into()));
                    yield Ok(event);
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}

fn allowed_origins() -> Result<Vec<HeaderValue>, String> {
    let configured = std::env::var("ORPHAN_CLEANER_ALLOWED_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:1420,http://127.0.0.1:1420".into());
    configured
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .map(|origin| {
            HeaderValue::from_str(origin)
                .map_err(|error| format!("Invalid allowed origin {origin}: {error}"))
        })
        .collect()
}

pub async fn run() -> Result<(), String> {
    let address: SocketAddr = std::env::var("ORPHAN_CLEANER_AGENT_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:47653".into())
        .parse()
        .map_err(|error| format!("Invalid agent address: {error}"))?;
    if !matches!(address.ip(), IpAddr::V4(ip) if ip.is_loopback())
        && !matches!(address.ip(), IpAddr::V6(ip) if ip.is_loopback())
    {
        return Err("The cleaner agent only binds to a loopback address".into());
    }
    let local = cleaner_core::local_app_data_path()
        .ok_or("Windows Local AppData could not be resolved")?
        .join("dev.orphancleaner.desktop");
    let downloads =
        cleaner_core::downloads_path().ok_or("Windows Downloads could not be resolved")?;
    let (events_tx, _) = broadcast::channel(1024);
    let state = AgentState {
        app_local_data: local,
        downloads,
        active: Arc::new(Mutex::new(None)),
        events: events_tx,
    };
    let origins = allowed_origins()?;
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins.clone()))
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([CONTENT_TYPE, HeaderName::from_static(CLIENT_HEADER)]);
    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/installed-applications", get(installed_applications))
        .route("/api/latest-scan", get(load_latest_scan))
        .route("/api/history-report", get(load_history_report))
        .route("/api/public-data/status", get(public_data_status))
        .route("/api/public-data/update", post(update_public_data))
        .route("/api/diagnostics/export", post(export_diagnostics))
        .route("/api/scan/start", post(start_scan))
        .route("/api/scan/cancel", post(cancel_scan))
        .route("/api/events", get(events))
        .with_state(state)
        .layer(cors);
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|error| error.to_string())?;
    println!("Windows Orphan Cleaner agent listening on http://{address}");
    println!(
        "Allowed browser origins: {}",
        origins
            .iter()
            .filter_map(|origin| origin.to_str().ok())
            .collect::<Vec<_>>()
            .join(", ")
    );
    axum::serve(listener, app)
        .await
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_header_is_required_for_mutating_requests() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            require_client(&headers).unwrap_err().status,
            StatusCode::FORBIDDEN
        );
        headers.insert(CLIENT_HEADER, HeaderValue::from_static("web-v1"));
        assert!(require_client(&headers).is_ok());
    }
}
