use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::graph_api::GraphEvent;
use crate::CliArgs;

/// Shared application state passed to all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub args: CliArgs,
    pub graph: Arc<RwLock<GraphState>>,
    pub event_tx: broadcast::Sender<GraphEvent>,
    pub scan_status: Arc<RwLock<ScanStatus>>,
}

impl AppState {
    pub fn new(args: CliArgs) -> Self {
        let (event_tx, _) = broadcast::channel(1024);
        Self {
            args,
            graph: Arc::new(RwLock::new(GraphState::default())),
            event_tx,
            scan_status: Arc::new(RwLock::new(ScanStatus::default())),
        }
    }
}

/// In-memory representation of the current graph for state persistence across
/// browser refreshes.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct GraphState {
    pub nodes: HashMap<String, GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub findings: Vec<Finding>,
    pub log_lines: Vec<String>,
    pub events: Vec<GraphEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub node_type: String,
    pub label: String,
    pub severity: Option<String>,
    pub status: String,
    pub confidence: Option<f64>,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub vuln_class: String,
    pub severity: String,
    pub endpoint: String,
    pub confidence: f64,
    pub evidence_preview: String,
    pub timestamp_ms: u64,
}

/// Current scan execution status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatus {
    pub phase: String,
    pub progress_pct: f64,
    pub is_running: bool,
    pub is_paused: bool,
    pub total_findings: u64,
    pub risk_score: f64,
    pub duration_ms: u64,
    pub target: String,
}

impl Default for ScanStatus {
    fn default() -> Self {
        Self {
            phase: "idle".to_string(),
            progress_pct: 0.0,
            is_running: false,
            is_paused: false,
            total_findings: 0,
            risk_score: 0.0,
            duration_ms: 0,
            target: String::new(),
        }
    }
}

#[cfg(test)]
#[path = "state_test.rs"]
mod state_test;
