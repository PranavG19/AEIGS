use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    ScanStarted {
        target_description: String,
    },
    ModuleStarted {
        module: crate::operation::ModuleIdentifier,
    },
    FindingRecorded {
        finding_id: u64,
        vulnerability_class: crate::finding::VulnerabilityClass,
    },
    ScanCompleted {
        total_findings: u64,
    },
    KeyEvent {
        description: String,
    },
    ConfigChange {
        key: String,
        old_value: String,
        new_value: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub sequence_number: u64,
    pub previous_hash: [u8; 32],
    pub timestamp_unix_ms: u64,
    pub event: AuditEventType,
    pub payload_cbor: Vec<u8>,
    pub hmac: [u8; 32],
}
