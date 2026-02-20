use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::finding::VulnerabilityClass;
use crate::operation::ModuleIdentifier;

/// A typed event emitted during a scan, representing a significant occurrence
/// that other modules can observe and react to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanEvent {
    EndpointDiscovered {
        endpoint: String,
        method: String,
        source_module: ModuleIdentifier,
    },
    HypothesisGenerated {
        vulnerability_class: VulnerabilityClass,
        condition: String,
        confidence: f64,
    },
    PayloadTested {
        endpoint: String,
        payload_hash: String,
        vulnerability_class: VulnerabilityClass,
        anomaly_score: f64,
    },
    AnomalyDetected {
        endpoint: String,
        vulnerability_class: VulnerabilityClass,
        anomaly_type: String,
        score: f64,
    },
    FindingConfirmed {
        finding_id: u64,
        vulnerability_class: VulnerabilityClass,
        severity: f64,
        confidence: f64,
    },
    PhaseCompleted {
        phase_name: String,
        operations_applied: u64,
        findings_count: u64,
        duration_ms: u64,
    },
}

/// Wraps a `ScanEvent` with metadata: a unique ID, timestamp, and the module
/// that produced it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanEventEnvelope {
    pub event_id: u64,
    pub timestamp_unix_ms: u64,
    pub source_module: ModuleIdentifier,
    pub event: ScanEvent,
}

impl ScanEventEnvelope {
    /// Creates a new envelope, auto-filling the timestamp from the system clock.
    pub fn new(event_id: u64, source_module: ModuleIdentifier, event: ScanEvent) -> Self {
        let timestamp_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        Self {
            event_id,
            timestamp_unix_ms,
            source_module,
            event,
        }
    }
}
