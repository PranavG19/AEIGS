use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Scan context serialized for IPC transport to the Python hypothesis-engine bridge.
///
/// Fields match the Python `ScanContextIpc` Pydantic model exactly. Both sides
/// must stay in sync: update both when adding/removing fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanContextIpc {
    pub technology_stack: Vec<String>,
    pub findings_summary: Vec<String>,
    pub high_centrality_nodes: Vec<String>,
    pub defense_posture: serde_json::Value,
    #[serde(default)]
    pub class_confirmation_rates: HashMap<String, f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
}

/// Hypothesis serialized for IPC transport between Rust orchestrator and Python bridge.
///
/// Fields match the Python `HypothesisIpc` Pydantic model exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisIpc {
    pub vulnerability_class: String,
    pub description: String,
    pub confidence: f64,
    pub test_specification: Option<String>,
}

/// Defense context serialized for IPC transport.
///
/// Fields match the Python `DefenseContextIpc` Pydantic model exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseContextIpc {
    pub has_waf: bool,
    pub waf_vendor: Option<String>,
    pub rate_limit_rps: Option<f64>,
    pub bot_detection_present: bool,
}

/// Request sent from the Rust orchestrator to the Python bridge process
/// over a persistent Unix domain socket connection.
///
/// Uses serde's internally-tagged representation with `"type"` as the tag field.
/// Must stay in sync with the Python `BridgeRequest` discriminated union.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum BridgeRequest {
    GenerateHypotheses {
        request_id: u64,
        scan_context: ScanContextIpc,
        vulnerability_class: String,
        feedback_summary: Option<String>,
    },
    CompilePayloads {
        request_id: u64,
        hypotheses: Vec<HypothesisIpc>,
    },
    EvasionGenerate {
        request_id: u64,
        defense_context: DefenseContextIpc,
    },
    Shutdown,
}

/// Response sent from the Python bridge process to the Rust orchestrator
/// over a persistent Unix domain socket connection.
///
/// Uses serde's internally-tagged representation with `"type"` as the tag field.
/// Must stay in sync with the Python `BridgeResponse` discriminated union.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum BridgeResponse {
    Ready,
    Hypotheses {
        request_id: u64,
        hypotheses: Vec<HypothesisIpc>,
        reasoning_trace: String,
        input_tokens: u64,
        output_tokens: u64,
    },
    CompiledPayloads {
        request_id: u64,
        payloads: Vec<String>,
        input_tokens: u64,
        output_tokens: u64,
    },
    EvasionPayloads {
        request_id: u64,
        payloads: Vec<String>,
        input_tokens: u64,
        output_tokens: u64,
    },
    Error {
        request_id: u64,
        message: String,
    },
}
