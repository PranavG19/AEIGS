use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use tower_http::cors::CorsLayer;

use crate::dashboard::DASHBOARD_HTML;
use crate::export_api;
use crate::graph_api;
use crate::scan_bridge;
use crate::state::AppState;
use crate::CliArgs;

/// Builds the complete axum router with all routes and middleware.
pub fn build_router(args: CliArgs) -> Router {
    let state = AppState::new(args.clone());

    if args.demo {
        scan_bridge::start_demo_scan(state.clone());
    }

    Router::new()
        .route("/", get(serve_dashboard))
        .route("/api/graph", get(graph_api::sse_graph_stream))
        .route("/api/findings", get(get_findings))
        .route("/api/stats", get(get_stats))
        .route("/api/control", post(post_control))
        .route("/api/export/html", get(export_api::export_html))
        .route("/api/export/sarif", get(export_api::export_sarif))
        .route("/api/export/json", get(export_api::export_json))
        .route("/api/export/graph.svg", get(export_api::export_svg))
        .route("/api/export/graph.dot", get(export_api::export_dot))
        .route("/api/share", post(export_api::create_share_link))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn serve_dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

async fn get_findings(State(state): State<AppState>) -> impl IntoResponse {
    let graph = state.graph.read();
    let findings = &graph.findings;
    axum::Json(serde_json::json!({
        "findings": findings,
        "count": findings.len(),
    }))
}

async fn get_stats(State(state): State<AppState>) -> impl IntoResponse {
    let status = state.scan_status.read().clone();
    let graph = state.graph.read();
    axum::Json(serde_json::json!({
        "phase": status.phase,
        "progress_pct": status.progress_pct,
        "is_running": status.is_running,
        "is_paused": status.is_paused,
        "total_findings": status.total_findings,
        "risk_score": status.risk_score,
        "duration_ms": status.duration_ms,
        "target": status.target,
        "node_count": graph.nodes.len(),
        "edge_count": graph.edges.len(),
    }))
}

#[derive(Deserialize)]
struct ControlRequest {
    action: String,
}

async fn post_control(
    State(state): State<AppState>,
    axum::Json(payload): axum::Json<ControlRequest>,
) -> impl IntoResponse {
    let mut status = state.scan_status.write();
    match payload.action.as_str() {
        "pause" => {
            status.is_paused = true;
            (StatusCode::OK, axum::Json(serde_json::json!({"status": "paused"})))
        }
        "resume" => {
            status.is_paused = false;
            (StatusCode::OK, axum::Json(serde_json::json!({"status": "resumed"})))
        }
        "stop" => {
            status.is_running = false;
            status.is_paused = false;
            (StatusCode::OK, axum::Json(serde_json::json!({"status": "stopped"})))
        }
        _ => (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({"error": "unknown action, use: pause, resume, stop"})),
        ),
    }
}

#[cfg(test)]
#[path = "server_test.rs"]
mod server_test;
