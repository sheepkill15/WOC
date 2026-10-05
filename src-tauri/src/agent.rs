//! Loopback HTTP/SSE agent that exposes the same command dispatcher as the
//! Tauri shell to a browser frontend on an allowed origin.

use axum::extract::{Path as UrlPath, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header::CONTENT_TYPE};
use axum::response::{IntoResponse, Response, sse::{Event, KeepAlive, Sse}};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::broadcast;
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::service::Service;

const CLIENT_HEADER: &str = "x-orphan-cleaner-client";
const TRANSPORT_VERSION: u32 = 3;

#[derive(Clone)]
struct AgentState {
    service: Arc<Service>,
    /// Host header values the agent answers to; blocks DNS-rebinding pages.
    hosts: Arc<Vec<String>>,
    events: broadcast::Sender<(&'static str, Value)>,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

fn require_host(headers: &HeaderMap, hosts: &[String]) -> Result<(), ApiError> {
    let host = headers.get(axum::http::header::HOST).and_then(|value| value.to_str().ok()).unwrap_or_default().to_ascii_lowercase();
    if hosts.iter().any(|allowed| *allowed == host) {
        Ok(())
    } else {
        Err(ApiError { status: StatusCode::FORBIDDEN, message: "Unexpected Host header".into() })
    }
}

fn require_client(headers: &HeaderMap) -> Result<(), ApiError> {
    if headers.get(CLIENT_HEADER).and_then(|value| value.to_str().ok()) == Some("web-v3") {
        Ok(())
    } else {
        Err(ApiError { status: StatusCode::FORBIDDEN, message: "Missing cleaner-agent client header".into() })
    }
}

async fn health(State(state): State<AgentState>) -> Json<Value> {
    Json(json!({
        "service": "windows-orphan-cleaner-agent",
        "version": env!("CARGO_PKG_VERSION"),
        "transportVersion": TRANSPORT_VERSION,
        "running": state.service.is_running(),
    }))
}

async fn invoke(
    headers: HeaderMap,
    State(state): State<AgentState>,
    UrlPath(command): UrlPath<String>,
    body: axum::body::Bytes,
) -> Result<Json<Value>, ApiError> {
    require_host(&headers, &state.hosts)?;
    require_client(&headers)?;
    let args = if body.is_empty() { Value::Null } else {
        serde_json::from_slice(&body).map_err(|error| ApiError { status: StatusCode::BAD_REQUEST, message: format!("Request body is not valid JSON: {error}") })?
    };
    let service = state.service.clone();
    let result = tokio::task::spawn_blocking(move || service.dispatch(&command, &args))
        .await
        .map_err(|error| ApiError { status: StatusCode::INTERNAL_SERVER_ERROR, message: error.to_string() })?;
    match result {
        Ok(value) => Ok(Json(value)),
        Err(message) if message.starts_with("Unknown command") => Err(ApiError { status: StatusCode::NOT_FOUND, message }),
        Err(message) if message.contains("already running") => Err(ApiError { status: StatusCode::CONFLICT, message }),
        Err(message) => Err(ApiError { status: StatusCode::UNPROCESSABLE_ENTITY, message }),
    }
}

async fn events(headers: HeaderMap, State(state): State<AgentState>) -> Result<Sse<impl futures_core::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    require_host(&headers, &state.hosts)?;
    let mut receiver = state.events.subscribe();
    let stream = async_stream::stream! {
        loop {
            match receiver.recv().await {
                Ok((name, payload)) => {
                    let event = Event::default().event(name)
                        .data(serde_json::to_string(&payload).unwrap_or_else(|_| "null".into()));
                    yield Ok(event);
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    yield Ok(Event::default().event("scan-resync").data("{}"));
                },
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

fn allowed_origins() -> Result<Vec<HeaderValue>, String> {
    let configured = std::env::var("ORPHAN_CLEANER_ALLOWED_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:1420,http://127.0.0.1:1420".into());
    configured.split(',').map(str::trim).filter(|origin| !origin.is_empty())
        .map(|origin| HeaderValue::from_str(origin).map_err(|error| format!("Invalid allowed origin {origin}: {error}")))
        .collect()
}

pub async fn run() -> Result<(), String> {
    let address: SocketAddr = std::env::var("ORPHAN_CLEANER_AGENT_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:47653".into())
        .parse()
        .map_err(|error| format!("Invalid agent address: {error}"))?;
    if !matches!(address.ip(), IpAddr::V4(ip) if ip.is_loopback()) && !matches!(address.ip(), IpAddr::V6(ip) if ip.is_loopback()) {
        return Err("The cleaner agent only binds to a loopback address".into());
    }
    let local = match std::env::var_os("ORPHAN_CLEANER_DATA_DIR") {
        Some(path) => {
            let path = std::path::PathBuf::from(path);
            if !path.is_absolute() || path.to_string_lossy().starts_with(r"\\") {
                return Err("The agent data directory must be a local absolute path".into());
            }
            path
        }
        None => cleaner_core::local_app_data_path()
            .ok_or("Windows Local AppData could not be resolved")?
            .join("dev.orphancleaner.desktop"),
    };
    let downloads = cleaner_core::downloads_path().ok_or("Windows Downloads could not be resolved")?;
    // Scan results arrive in bursts; a deep buffer keeps slow browsers from lagging out.
    let (events_tx, _) = broadcast::channel::<(&'static str, Value)>(8192);
    let sender = events_tx.clone();
    let service = Service::new(local, downloads, "agent", Arc::new(move |name, payload| { let _ = sender.send((name, payload)); }));
    let port = address.port();
    let hosts = vec![format!("127.0.0.1:{port}"), format!("localhost:{port}"), format!("[::1]:{port}"), address.to_string().to_ascii_lowercase()];
    let state = AgentState { service, hosts: Arc::new(hosts), events: events_tx };
    let origins = allowed_origins()?;
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins.clone()))
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([CONTENT_TYPE, HeaderName::from_static(CLIENT_HEADER)]);
    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/invoke/{command}", post(invoke))
        .route("/api/events", get(events))
        .with_state(state)
        .layer(cors);
    let listener = tokio::net::TcpListener::bind(address).await.map_err(|error| error.to_string())?;
    println!("Windows Orphan Cleaner agent listening on http://{address}");
    println!("Allowed browser origins: {}", origins.iter().filter_map(|origin| origin.to_str().ok()).collect::<Vec<_>>().join(", "));
    axum::serve(listener, app).await.map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_header_is_required() {
        let mut headers = HeaderMap::new();
        assert_eq!(require_client(&headers).unwrap_err().status, StatusCode::FORBIDDEN);
        headers.insert(CLIENT_HEADER, HeaderValue::from_static("web-v2"));
        assert!(require_client(&headers).is_err(), "old clients are rejected after the transport change");
        headers.insert(CLIENT_HEADER, HeaderValue::from_static("web-v3"));
        assert!(require_client(&headers).is_ok());
    }

    #[test]
    fn host_header_must_be_loopback() {
        let hosts = vec!["127.0.0.1:47653".to_string(), "localhost:47653".to_string()];
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::HOST, HeaderValue::from_static("evil.example:47653"));
        assert!(require_host(&headers, &hosts).is_err());
        headers.insert(axum::http::header::HOST, HeaderValue::from_static("127.0.0.1:47653"));
        assert!(require_host(&headers, &hosts).is_ok());
    }
}
