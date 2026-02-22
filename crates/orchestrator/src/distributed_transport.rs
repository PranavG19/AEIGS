use aegis_protocol::finding::FindingData;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::distributed::{WorkAssignment, WorkerId, WorkerRole};

static MESSAGE_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Messages sent from coordinator to worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CoordinatorMessage {
    AssignWork(WorkAssignment),
    Pause,
    Resume,
    Shutdown,
}

/// Messages sent from worker to coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkerMessage {
    Register {
        worker_id: WorkerId,
        role: WorkerRole,
    },
    Heartbeat {
        worker_id: WorkerId,
        targets_completed: u64,
        targets_remaining: u64,
        findings_count: u64,
    },
    FindingsBatch {
        worker_id: WorkerId,
        findings: Vec<FindingData>,
    },
    WorkComplete {
        worker_id: WorkerId,
    },
    Error {
        worker_id: WorkerId,
        message: String,
    },
}

/// Envelope wrapping either message direction with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportEnvelope {
    pub message_id: u64,
    pub timestamp_ms: u64,
    pub payload: TransportPayload,
}

/// Discriminated union of coordinator and worker messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransportPayload {
    FromCoordinator(CoordinatorMessage),
    FromWorker(WorkerMessage),
}

/// Configuration for the transport layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    pub bind_address: String,
    pub port: u16,
    pub max_frame_size: usize,
    pub connection_timeout_ms: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1".to_string(),
            port: 9100,
            // 64 MiB, matching hypothesis bridge
            max_frame_size: 64 * 1024 * 1024,
            connection_timeout_ms: 10_000,
        }
    }
}

impl TransportConfig {
    /// Sets the bind address for the transport listener.
    pub fn with_bind_address(mut self, addr: &str) -> Self {
        self.bind_address = addr.to_string();
        self
    }

    /// Sets the port for the transport listener.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }
}

/// Errors arising from the transport layer.
#[derive(Debug)]
pub enum TransportError {
    Io(std::io::Error),
    Serialization(String),
    FrameTooLarge { size: usize, max: usize },
    ConnectionClosed,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "transport I/O error: {e}"),
            Self::Serialization(msg) => write!(f, "transport serialization error: {msg}"),
            Self::FrameTooLarge { size, max } => {
                write!(f, "frame size {size} exceeds maximum {max}")
            }
            Self::ConnectionClosed => write!(f, "connection closed"),
        }
    }
}

impl std::error::Error for TransportError {}

impl fmt::Display for CoordinatorMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AssignWork(a) => write!(f, "AssignWork({})", a.worker_id),
            Self::Pause => write!(f, "Pause"),
            Self::Resume => write!(f, "Resume"),
            Self::Shutdown => write!(f, "Shutdown"),
        }
    }
}

impl fmt::Display for WorkerMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Register { worker_id, role } => {
                write!(f, "Register({worker_id}, {role:?})")
            }
            Self::Heartbeat { worker_id, .. } => write!(f, "Heartbeat({worker_id})"),
            Self::FindingsBatch {
                worker_id,
                findings,
            } => {
                write!(f, "FindingsBatch({worker_id}, {} findings)", findings.len())
            }
            Self::WorkComplete { worker_id } => write!(f, "WorkComplete({worker_id})"),
            Self::Error { worker_id, message } => write!(f, "Error({worker_id}, {message})"),
        }
    }
}

impl fmt::Display for TransportPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FromCoordinator(msg) => write!(f, "FromCoordinator({msg})"),
            Self::FromWorker(msg) => write!(f, "FromWorker({msg})"),
        }
    }
}

/// Writes a length-prefixed JSON frame to the given writer.
///
/// Protocol: 4-byte little-endian u32 length prefix followed by the JSON payload.
/// Returns `TransportError::FrameTooLarge` if the serialized envelope exceeds
/// `u32::MAX` bytes.
pub fn write_transport_frame<W: std::io::Write>(
    writer: &mut W,
    envelope: &TransportEnvelope,
) -> Result<(), TransportError> {
    let payload =
        serde_json::to_vec(envelope).map_err(|e| TransportError::Serialization(e.to_string()))?;
    let len = u32::try_from(payload.len()).map_err(|_| TransportError::FrameTooLarge {
        size: payload.len(),
        max: u32::MAX as usize,
    })?;
    writer
        .write_all(&len.to_le_bytes())
        .map_err(TransportError::Io)?;
    writer.write_all(&payload).map_err(TransportError::Io)?;
    Ok(())
}

/// Reads a length-prefixed JSON frame from the given reader and deserializes it.
///
/// Protocol: 4-byte little-endian u32 length prefix followed by the JSON payload.
/// Returns `TransportError::FrameTooLarge` if the declared frame size exceeds
/// `max_frame_size`.
pub fn read_transport_frame<R: std::io::Read>(
    reader: &mut R,
    max_frame_size: usize,
) -> Result<TransportEnvelope, TransportError> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(TransportError::ConnectionClosed);
        }
        Err(e) => return Err(TransportError::Io(e)),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > max_frame_size {
        return Err(TransportError::FrameTooLarge {
            size: len,
            max: max_frame_size,
        });
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        reader
            .read_exact(&mut payload)
            .map_err(TransportError::Io)?;
    }
    serde_json::from_slice(&payload).map_err(|e| TransportError::Serialization(e.to_string()))
}

/// Creates a `TransportEnvelope` wrapping a coordinator message with
/// auto-incrementing message ID and current timestamp.
pub fn wrap_coordinator_message(msg: CoordinatorMessage) -> TransportEnvelope {
    TransportEnvelope {
        message_id: MESSAGE_COUNTER.fetch_add(1, Ordering::Relaxed),
        timestamp_ms: crate::util::timestamp_ms(),
        payload: TransportPayload::FromCoordinator(msg),
    }
}

/// Creates a `TransportEnvelope` wrapping a worker message with
/// auto-incrementing message ID and current timestamp.
pub fn wrap_worker_message(msg: WorkerMessage) -> TransportEnvelope {
    TransportEnvelope {
        message_id: MESSAGE_COUNTER.fetch_add(1, Ordering::Relaxed),
        timestamp_ms: crate::util::timestamp_ms(),
        payload: TransportPayload::FromWorker(msg),
    }
}
