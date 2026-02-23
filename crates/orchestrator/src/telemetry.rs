use serde::{Deserialize, Serialize};

use crate::util::timestamp_ms;

/// Configuration for opt-in telemetry collection.
///
/// Telemetry is disabled by default and must be explicitly enabled via CLI flag.
/// When enabled, only aggregate metrics are collected — never raw findings, payloads,
/// or target details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    pub enabled: bool,
    pub endpoint: Option<String>,
    pub include_timing: bool,
    pub include_counts: bool,
    pub include_llm_usage: bool,
    pub session_id: String,
}

/// A single telemetry event with type, session context, and payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub event_type: TelemetryEventType,
    pub session_id: String,
    pub timestamp_ms: u64,
    pub payload: TelemetryPayload,
}

/// Discriminant for telemetry event categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TelemetryEventType {
    ScanStarted,
    ScanCompleted,
    ScanFailed,
    PhaseCompleted,
}

/// Payload variants carrying aggregate-only scan data.
///
/// No variant includes raw findings, payloads, target URLs, or file paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TelemetryPayload {
    ScanStart {
        crate_count: usize,
        has_llm: bool,
        stealth_preset: String,
    },
    ScanEnd {
        total_findings: usize,
        total_endpoints: usize,
        duration_ms: u64,
    },
    ScanError {
        error_category: String,
    },
    PhaseComplete {
        phase_name: String,
        duration_ms: u64,
        item_count: usize,
    },
    LlmUsage {
        total_calls: u64,
        total_input_tokens: u64,
        total_output_tokens: u64,
    },
}

/// Collects telemetry events during a scan session.
///
/// All `record_*` methods silently no-op when telemetry is not enabled,
/// so callers do not need guard checks.
#[derive(Debug)]
pub struct TelemetryCollector {
    config: TelemetryConfig,
    events: Vec<TelemetryEvent>,
    started_at_ms: u64,
}

/// Errors that can occur during telemetry operations.
#[derive(Debug)]
pub enum TelemetryError {
    NotEnabled,
    SerializationFailed(String),
    ExportFailed(String),
}

impl std::fmt::Display for TelemetryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotEnabled => write!(f, "telemetry is not enabled"),
            Self::SerializationFailed(msg) => write!(f, "telemetry serialization failed: {msg}"),
            Self::ExportFailed(msg) => write!(f, "telemetry export failed: {msg}"),
        }
    }
}

impl std::error::Error for TelemetryError {}

impl TelemetryCollector {
    /// Creates a new collector initialized with the given config and current timestamp.
    pub fn new(config: TelemetryConfig) -> Self {
        Self {
            config,
            events: Vec::new(),
            started_at_ms: timestamp_ms(),
        }
    }

    /// Returns `true` if telemetry collection is opted in.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Records a scan-started event if telemetry is enabled.
    pub fn record_scan_start(&mut self, crate_count: usize, has_llm: bool, stealth_preset: &str) {
        if !self.config.enabled {
            return;
        }
        self.push_event(
            TelemetryEventType::ScanStarted,
            TelemetryPayload::ScanStart {
                crate_count,
                has_llm,
                stealth_preset: stealth_preset.to_string(),
            },
        );
    }

    /// Records a scan-completed event with duration calculated from collector start.
    pub fn record_scan_end(&mut self, total_findings: usize, total_endpoints: usize) {
        if !self.config.enabled {
            return;
        }
        let duration_ms = timestamp_ms().saturating_sub(self.started_at_ms);
        self.push_event(
            TelemetryEventType::ScanCompleted,
            TelemetryPayload::ScanEnd {
                total_findings,
                total_endpoints,
                duration_ms,
            },
        );
    }

    /// Records a scan-failed event with a sanitized error category.
    pub fn record_scan_error(&mut self, error_category: &str) {
        if !self.config.enabled {
            return;
        }
        self.push_event(
            TelemetryEventType::ScanFailed,
            TelemetryPayload::ScanError {
                error_category: sanitize_error_category(error_category),
            },
        );
    }

    /// Records a phase-completed event if telemetry and timing collection are enabled.
    pub fn record_phase_complete(&mut self, phase_name: &str, duration_ms: u64, item_count: usize) {
        if !self.config.enabled || !self.config.include_timing {
            return;
        }
        self.push_event(
            TelemetryEventType::PhaseCompleted,
            TelemetryPayload::PhaseComplete {
                phase_name: phase_name.to_string(),
                duration_ms,
                item_count,
            },
        );
    }

    /// Records LLM usage statistics if telemetry and LLM usage collection are enabled.
    pub fn record_llm_usage(&mut self, total_calls: u64, input_tokens: u64, output_tokens: u64) {
        if !self.config.enabled || !self.config.include_llm_usage {
            return;
        }
        self.push_event(
            TelemetryEventType::PhaseCompleted,
            TelemetryPayload::LlmUsage {
                total_calls,
                total_input_tokens: input_tokens,
                total_output_tokens: output_tokens,
            },
        );
    }

    /// Returns the number of collected events.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Returns a read-only slice of all collected events.
    pub fn events(&self) -> &[TelemetryEvent] {
        &self.events
    }

    /// Serializes all collected events to a JSON string.
    pub fn export_json(&self) -> Result<String, TelemetryError> {
        if !self.config.enabled {
            return Err(TelemetryError::NotEnabled);
        }
        serde_json::to_string_pretty(&self.events)
            .map_err(|e| TelemetryError::SerializationFailed(e.to_string()))
    }

    /// Writes all collected events as JSON to the given file path.
    pub async fn export_to_file(&self, path: &std::path::Path) -> Result<(), TelemetryError> {
        let json = self.export_json()?;
        tokio::fs::write(path, json)
            .await
            .map_err(|e| TelemetryError::ExportFailed(e.to_string()))
    }

    fn push_event(&mut self, event_type: TelemetryEventType, payload: TelemetryPayload) {
        self.events.push(TelemetryEvent {
            event_type,
            session_id: self.config.session_id.clone(),
            timestamp_ms: timestamp_ms(),
            payload,
        });
    }
}

/// Generates a random 16-byte hex session ID (32 hex characters).
pub fn generate_session_id() -> String {
    let bytes: [u8; 16] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Returns a disabled telemetry config with sensible defaults.
pub fn default_telemetry_config() -> TelemetryConfig {
    TelemetryConfig {
        enabled: false,
        endpoint: None,
        include_timing: true,
        include_counts: true,
        include_llm_usage: false,
        session_id: generate_session_id(),
    }
}

/// Extracts a safe error category from a raw error message.
///
/// Returns the first word before `:` or the first 50 characters, whichever is shorter.
/// Never includes full error details, paths, or stack traces.
pub fn sanitize_error_category(error: &str) -> String {
    if error.is_empty() {
        return "unknown".to_string();
    }
    let category = error.split(':').next().unwrap_or(error).trim();
    if category.len() > 50 {
        category[..50].to_string()
    } else {
        category.to_string()
    }
}

#[cfg(test)]
#[path = "telemetry_test.rs"]
mod telemetry_test;
