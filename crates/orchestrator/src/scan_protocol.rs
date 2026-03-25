use serde::{Deserialize, Serialize};
use std::fmt;

use aegis_protocol::finding::FindingData;

/// Protocol version for message compatibility.
pub const PROTOCOL_VERSION: u32 = 1;

/// Unique message identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId {
    pub id: u64,
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "msg-{}", self.id)
    }
}

/// All message types for worker communication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtocolMessage {
    /// Coordinator assigns scan work to a worker.
    TaskAssignment {
        worker_id: String,
        endpoints: Vec<String>,
        modules: Vec<String>,
        priority: f64,
    },
    /// Worker reports scan results.
    TaskResult {
        worker_id: String,
        task_id: String,
        findings: Vec<FindingData>,
        duration_ms: u64,
    },
    /// Periodic heartbeat from worker to coordinator.
    Heartbeat {
        worker_id: String,
        load_percent: f64,
        tasks_completed: u64,
        tasks_remaining: u64,
    },
    /// Coordinator broadcasts a new finding to all workers.
    FindingBroadcast {
        finding: FindingData,
        source_worker: String,
    },
    /// State synchronization: full state snapshot.
    StateSync {
        phase: String,
        active_workers: Vec<String>,
        total_findings: u64,
    },
    /// Coordinator signals a phase transition.
    PhaseTransition {
        from_phase: String,
        to_phase: String,
    },
    /// Coordinator requests graceful shutdown of a worker.
    ShutdownRequest { worker_id: String, reason: String },
}

/// Wire-format envelope wrapping a protocol message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    pub version: u32,
    pub message_id: u64,
    pub timestamp_ms: u64,
    pub sender: String,
    pub payload: ProtocolMessage,
}

/// Errors from protocol operations.
#[derive(Debug)]
pub enum ProtocolError {
    SerializationError(String),
    DeserializationError(String),
    VersionMismatch { expected: u32, got: u32 },
    InvalidMessage(String),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SerializationError(msg) => write!(f, "serialization error: {msg}"),
            Self::DeserializationError(msg) => write!(f, "deserialization error: {msg}"),
            Self::VersionMismatch { expected, got } => {
                write!(f, "version mismatch: expected {expected}, got {got}")
            }
            Self::InvalidMessage(msg) => write!(f, "invalid message: {msg}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// Serializes a message envelope to JSON bytes.
pub fn serialize_envelope(envelope: &MessageEnvelope) -> Result<Vec<u8>, ProtocolError> {
    serde_json::to_vec(envelope).map_err(|e| ProtocolError::SerializationError(e.to_string()))
}

/// Deserializes a message envelope from JSON bytes.
pub fn deserialize_envelope(data: &[u8]) -> Result<MessageEnvelope, ProtocolError> {
    let envelope: MessageEnvelope = serde_json::from_slice(data)
        .map_err(|e| ProtocolError::DeserializationError(e.to_string()))?;
    if envelope.version != PROTOCOL_VERSION {
        return Err(ProtocolError::VersionMismatch {
            expected: PROTOCOL_VERSION,
            got: envelope.version,
        });
    }
    Ok(envelope)
}

/// Validates a protocol message for required fields.
pub fn validate_message(msg: &ProtocolMessage) -> Result<(), ProtocolError> {
    match msg {
        ProtocolMessage::TaskAssignment {
            worker_id,
            endpoints,
            ..
        } => {
            if worker_id.is_empty() {
                return Err(ProtocolError::InvalidMessage(
                    "task assignment missing worker_id".to_string(),
                ));
            }
            if endpoints.is_empty() {
                return Err(ProtocolError::InvalidMessage(
                    "task assignment has no endpoints".to_string(),
                ));
            }
            Ok(())
        }
        ProtocolMessage::TaskResult {
            worker_id, task_id, ..
        } => {
            if worker_id.is_empty() || task_id.is_empty() {
                return Err(ProtocolError::InvalidMessage(
                    "task result missing worker_id or task_id".to_string(),
                ));
            }
            Ok(())
        }
        ProtocolMessage::Heartbeat { worker_id, .. } => {
            if worker_id.is_empty() {
                return Err(ProtocolError::InvalidMessage(
                    "heartbeat missing worker_id".to_string(),
                ));
            }
            Ok(())
        }
        ProtocolMessage::ShutdownRequest { worker_id, .. } => {
            if worker_id.is_empty() {
                return Err(ProtocolError::InvalidMessage(
                    "shutdown request missing worker_id".to_string(),
                ));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Creates a new message envelope with auto-incremented ID and current timestamp.
pub fn create_envelope(sender: &str, payload: ProtocolMessage) -> MessageEnvelope {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    MessageEnvelope {
        version: PROTOCOL_VERSION,
        message_id: COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        timestamp_ms: crate::util::timestamp_ms(),
        sender: sender.to_string(),
        payload,
    }
}

/// Returns a human-readable description of a protocol message.
pub fn describe_message(msg: &ProtocolMessage) -> String {
    match msg {
        ProtocolMessage::TaskAssignment {
            worker_id,
            endpoints,
            ..
        } => format!(
            "TaskAssignment: {} endpoint(s) -> worker {worker_id}",
            endpoints.len()
        ),
        ProtocolMessage::TaskResult {
            worker_id,
            findings,
            ..
        } => format!(
            "TaskResult: {} finding(s) from worker {worker_id}",
            findings.len()
        ),
        ProtocolMessage::Heartbeat { worker_id, .. } => {
            format!("Heartbeat from worker {worker_id}")
        }
        ProtocolMessage::FindingBroadcast { source_worker, .. } => {
            format!("FindingBroadcast from {source_worker}")
        }
        ProtocolMessage::StateSync { total_findings, .. } => {
            format!("StateSync: {total_findings} total findings")
        }
        ProtocolMessage::PhaseTransition {
            from_phase,
            to_phase,
        } => format!("PhaseTransition: {from_phase} -> {to_phase}"),
        ProtocolMessage::ShutdownRequest {
            worker_id, reason, ..
        } => format!("Shutdown worker {worker_id}: {reason}"),
    }
}
