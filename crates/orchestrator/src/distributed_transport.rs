use aegis_protocol::finding::FindingData;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::distributed::{
    CoordinatorState, DistributedConfig, WorkAssignment, WorkerId, WorkerRole, WorkerState,
};

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

/// Handle to a connected worker stream.
struct WorkerConnection {
    #[allow(dead_code)]
    stream: std::net::TcpStream,
    #[allow(dead_code)]
    worker_id: Option<WorkerId>,
}

/// Coordinator runtime state machine that processes worker messages and
/// manages the distributed scan lifecycle.
///
/// Wraps `CoordinatorState` with message dispatch logic. The actual TCP
/// accept loop is wired externally; this struct is a pure state machine.
pub struct Coordinator {
    config: DistributedConfig,
    pub state: CoordinatorState,
    #[allow(dead_code)]
    connections: Vec<WorkerConnection>,
    findings_received: Vec<FindingData>,
}

impl Coordinator {
    /// Creates a new coordinator with the given transport and distributed configs.
    pub fn new(transport: TransportConfig, distributed: DistributedConfig) -> Self {
        let _ = transport;
        let state = CoordinatorState::new(&distributed);
        Self {
            config: distributed,
            state,
            connections: Vec::new(),
            findings_received: Vec::new(),
        }
    }

    /// Processes a single `WorkerMessage`, updating internal state and returning
    /// an optional `CoordinatorMessage` to send back to the worker.
    pub fn handle_message(&mut self, msg: &WorkerMessage) -> Option<CoordinatorMessage> {
        match msg {
            WorkerMessage::Register { worker_id, role } => self.handle_register(worker_id, *role),
            WorkerMessage::Heartbeat {
                worker_id,
                targets_completed,
                targets_remaining,
                findings_count,
            } => {
                self.handle_heartbeat(
                    worker_id,
                    *targets_completed,
                    *targets_remaining,
                    *findings_count,
                );
                None
            }
            WorkerMessage::FindingsBatch {
                worker_id,
                findings,
            } => {
                self.handle_findings_batch(worker_id, findings);
                None
            }
            WorkerMessage::WorkComplete { worker_id } => self.handle_work_complete(worker_id),
            WorkerMessage::Error { worker_id, message } => self.handle_error(worker_id, message),
        }
    }

    /// Checks if all registered workers have completed (or failed).
    pub fn all_workers_complete(&self) -> bool {
        self.state.all_complete()
    }

    /// Returns the findings collected from workers so far.
    pub fn collected_findings(&self) -> &[FindingData] {
        &self.findings_received
    }

    /// Returns the current coordinator state snapshot.
    pub fn state(&self) -> &CoordinatorState {
        &self.state
    }

    fn handle_register(
        &mut self,
        worker_id: &WorkerId,
        role: WorkerRole,
    ) -> Option<CoordinatorMessage> {
        self.state.register_worker(worker_id.clone(), role);
        None
    }

    fn handle_heartbeat(
        &mut self,
        worker_id: &WorkerId,
        targets_completed: u64,
        targets_remaining: u64,
        findings_count: u64,
    ) {
        self.state.update_worker_status(
            worker_id,
            WorkerState::Working,
            targets_completed,
            targets_remaining,
            findings_count,
        );
    }

    fn handle_findings_batch(&mut self, worker_id: &WorkerId, findings: &[FindingData]) {
        self.findings_received.extend_from_slice(findings);
        if let Some(ws) = self
            .state
            .workers
            .iter_mut()
            .find(|w| w.worker_id == *worker_id)
        {
            ws.findings_count += findings.len() as u64;
        }
    }

    fn handle_work_complete(&mut self, worker_id: &WorkerId) -> Option<CoordinatorMessage> {
        self.state
            .update_worker_status(worker_id, WorkerState::Completed, 0, 0, 0);
        None
    }

    fn handle_error(&mut self, worker_id: &WorkerId, _message: &str) -> Option<CoordinatorMessage> {
        self.state
            .update_worker_status(worker_id, WorkerState::Failed, 0, 0, 0);
        if self.config.rebalance_on_failure
            && let Some(new_assignments) = self.state.rebalance(worker_id)
        {
            return new_assignments
                .into_iter()
                .next()
                .map(CoordinatorMessage::AssignWork);
        }
        None
    }
}

/// Worker runtime state machine that processes coordinator messages and
/// tracks local fuzz execution progress.
///
/// This is a pure state machine — no networking. The actual TCP connection
/// loop is wired externally; this struct handles message processing only.
pub struct Worker {
    worker_id: WorkerId,
    role: WorkerRole,
    state: WorkerState,
    assigned_endpoints: Vec<String>,
    findings: Vec<FindingData>,
    targets_completed: u64,
    paused: bool,
}

impl Worker {
    /// Creates a new worker with the given ID and role, starting in `Idle` state.
    pub fn new(worker_id: WorkerId, role: WorkerRole) -> Self {
        Self {
            worker_id,
            role,
            state: WorkerState::Idle,
            assigned_endpoints: Vec::new(),
            findings: Vec::new(),
            targets_completed: 0,
            paused: false,
        }
    }

    /// Creates the `Register` message for this worker.
    pub fn register_message(&self) -> WorkerMessage {
        WorkerMessage::Register {
            worker_id: self.worker_id.clone(),
            role: self.role,
        }
    }

    /// Creates a `Heartbeat` message reflecting current progress.
    pub fn heartbeat_message(&self) -> WorkerMessage {
        let total = self.assigned_endpoints.len() as u64;
        WorkerMessage::Heartbeat {
            worker_id: self.worker_id.clone(),
            targets_completed: self.targets_completed,
            targets_remaining: total.saturating_sub(self.targets_completed),
            findings_count: self.findings.len() as u64,
        }
    }

    /// Processes a coordinator message and returns an optional response.
    ///
    /// - `AssignWork`: stores endpoints, transitions to `Working`.
    /// - `Pause`: sets paused flag, transitions to `Paused`.
    /// - `Resume`: clears paused flag, transitions to `Working`.
    /// - `Shutdown`: transitions to `Completed`.
    pub fn handle_message(&mut self, msg: &CoordinatorMessage) -> Option<WorkerMessage> {
        match msg {
            CoordinatorMessage::AssignWork(assignment) => {
                self.assigned_endpoints = assignment.endpoints.clone();
                self.state = WorkerState::Working;
                None
            }
            CoordinatorMessage::Pause => {
                self.paused = true;
                self.state = WorkerState::Paused;
                None
            }
            CoordinatorMessage::Resume => {
                self.paused = false;
                self.state = WorkerState::Working;
                None
            }
            CoordinatorMessage::Shutdown => {
                self.state = WorkerState::Completed;
                None
            }
        }
    }

    /// Records a completed target and returns a `FindingsBatch` if findings are pending.
    ///
    /// Increments `targets_completed`. If `new_findings` is non-empty, accumulates
    /// them and returns a `FindingsBatch` containing all pending findings.
    pub fn complete_target(&mut self, new_findings: Vec<FindingData>) -> Option<WorkerMessage> {
        self.targets_completed += 1;
        if new_findings.is_empty() {
            return None;
        }
        self.findings.extend(new_findings);
        let batch = self.findings.drain(..).collect();
        Some(WorkerMessage::FindingsBatch {
            worker_id: self.worker_id.clone(),
            findings: batch,
        })
    }

    /// Marks all assigned work as complete and returns a `WorkComplete` message.
    pub fn finish(&mut self) -> WorkerMessage {
        self.state = WorkerState::Completed;
        WorkerMessage::WorkComplete {
            worker_id: self.worker_id.clone(),
        }
    }

    /// Returns whether the worker is currently paused.
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Returns whether the worker has been shut down.
    pub fn is_shutdown(&self) -> bool {
        self.state == WorkerState::Completed
    }

    /// Returns the worker's current state.
    pub fn state(&self) -> WorkerState {
        self.state
    }

    /// Returns assigned endpoints.
    pub fn assigned_endpoints(&self) -> &[String] {
        &self.assigned_endpoints
    }
}
