use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

use aegis_protocol::finding::FindingData;

/// Phases in a distributed scan pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScanPhase {
    Recon,
    Crawl,
    Fingerprint,
    Fuzz,
    Analyze,
    DomVerify,
    Report,
}

impl fmt::Display for ScanPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Recon => write!(f, "recon"),
            Self::Crawl => write!(f, "crawl"),
            Self::Fingerprint => write!(f, "fingerprint"),
            Self::Fuzz => write!(f, "fuzz"),
            Self::Analyze => write!(f, "analyze"),
            Self::DomVerify => write!(f, "dom-verify"),
            Self::Report => write!(f, "report"),
        }
    }
}

/// Barrier state: tracks which workers have reached a synchronization point.
#[derive(Debug, Clone)]
pub struct PhaseBarrier {
    pub phase: ScanPhase,
    pub expected_workers: HashSet<String>,
    pub arrived_workers: HashSet<String>,
}

impl PhaseBarrier {
    /// Creates a barrier for the given phase expecting the listed workers.
    pub fn new(phase: ScanPhase, worker_ids: &[String]) -> Self {
        Self {
            phase,
            expected_workers: worker_ids.iter().cloned().collect(),
            arrived_workers: HashSet::new(),
        }
    }

    /// Records a worker arriving at the barrier. Returns `true` if all workers have arrived.
    pub fn arrive(&mut self, worker_id: &str) -> bool {
        self.arrived_workers.insert(worker_id.to_string());
        self.is_complete()
    }

    /// Returns `true` if all expected workers have arrived.
    pub fn is_complete(&self) -> bool {
        self.expected_workers
            .iter()
            .all(|w| self.arrived_workers.contains(w))
    }

    /// Returns worker IDs that haven't arrived yet.
    pub fn pending_workers(&self) -> Vec<String> {
        self.expected_workers
            .difference(&self.arrived_workers)
            .cloned()
            .collect()
    }
}

/// A broadcast message to share with all workers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BroadcastMessage {
    NewFinding(FindingData),
    PhaseTransition(ScanPhase),
    WorkerJoined(String),
    WorkerLeft(String),
    Custom(String),
}

/// Errors from scan coordination.
#[derive(Debug)]
pub enum CoordinatorError {
    PhaseNotActive(ScanPhase),
    BarrierTimeout(ScanPhase),
    WorkerNotRegistered(String),
    InvalidPhaseTransition { from: ScanPhase, to: ScanPhase },
    NoWorkersRegistered,
}

impl fmt::Display for CoordinatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PhaseNotActive(p) => write!(f, "phase not active: {p}"),
            Self::BarrierTimeout(p) => write!(f, "barrier timeout at phase: {p}"),
            Self::WorkerNotRegistered(id) => write!(f, "worker not registered: {id}"),
            Self::InvalidPhaseTransition { from, to } => {
                write!(f, "invalid phase transition: {from} -> {to}")
            }
            Self::NoWorkersRegistered => write!(f, "no workers registered"),
        }
    }
}

impl std::error::Error for CoordinatorError {}

/// Top-level coordination of distributed scans.
pub struct ScanCoordinator {
    current_phase: ScanPhase,
    registered_workers: HashSet<String>,
    barriers: HashMap<ScanPhase, PhaseBarrier>,
    broadcast_log: Vec<BroadcastMessage>,
    phase_history: Vec<ScanPhase>,
}

impl Default for ScanCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanCoordinator {
    /// Creates a coordinator starting at the Recon phase.
    pub fn new() -> Self {
        Self {
            current_phase: ScanPhase::Recon,
            registered_workers: HashSet::new(),
            barriers: HashMap::new(),
            broadcast_log: Vec::new(),
            phase_history: vec![ScanPhase::Recon],
        }
    }

    /// Registers a worker for coordination.
    pub fn register_worker(&mut self, worker_id: &str) {
        self.registered_workers.insert(worker_id.to_string());
        self.broadcast_log
            .push(BroadcastMessage::WorkerJoined(worker_id.to_string()));
    }

    /// Removes a worker gracefully. Its barrier arrivals are also removed.
    pub fn remove_worker(&mut self, worker_id: &str) -> Result<(), CoordinatorError> {
        if !self.registered_workers.remove(worker_id) {
            return Err(CoordinatorError::WorkerNotRegistered(worker_id.to_string()));
        }
        for barrier in self.barriers.values_mut() {
            barrier.expected_workers.remove(worker_id);
            barrier.arrived_workers.remove(worker_id);
        }
        self.broadcast_log
            .push(BroadcastMessage::WorkerLeft(worker_id.to_string()));
        Ok(())
    }

    /// Creates a barrier for the current phase, expecting all registered workers.
    pub fn create_barrier(&mut self) -> Result<(), CoordinatorError> {
        if self.registered_workers.is_empty() {
            return Err(CoordinatorError::NoWorkersRegistered);
        }
        let worker_ids: Vec<String> = self.registered_workers.iter().cloned().collect();
        let barrier = PhaseBarrier::new(self.current_phase, &worker_ids);
        self.barriers.insert(self.current_phase, barrier);
        Ok(())
    }

    /// Records a worker arriving at the current phase barrier.
    /// Returns `true` if all workers have arrived (barrier complete).
    pub fn worker_phase_complete(&mut self, worker_id: &str) -> Result<bool, CoordinatorError> {
        if !self.registered_workers.contains(worker_id) {
            return Err(CoordinatorError::WorkerNotRegistered(worker_id.to_string()));
        }
        let barrier = self
            .barriers
            .get_mut(&self.current_phase)
            .ok_or(CoordinatorError::PhaseNotActive(self.current_phase))?;
        let all_done = barrier.arrive(worker_id);
        Ok(all_done)
    }

    /// Advances to the next phase. Only valid if the current barrier is complete.
    pub fn advance_phase(&mut self, next: ScanPhase) -> Result<(), CoordinatorError> {
        if let Some(barrier) = self.barriers.get(&self.current_phase)
            && !barrier.is_complete()
        {
            return Err(CoordinatorError::BarrierTimeout(self.current_phase));
        }
        let valid = matches!(
            (self.current_phase, next),
            (ScanPhase::Recon, ScanPhase::Crawl)
                | (ScanPhase::Crawl, ScanPhase::Fingerprint)
                | (ScanPhase::Fingerprint, ScanPhase::Fuzz)
                | (ScanPhase::Fuzz, ScanPhase::Analyze)
                | (ScanPhase::Analyze, ScanPhase::DomVerify)
                | (ScanPhase::DomVerify, ScanPhase::Report)
        );
        if !valid {
            return Err(CoordinatorError::InvalidPhaseTransition {
                from: self.current_phase,
                to: next,
            });
        }
        self.current_phase = next;
        self.phase_history.push(next);
        self.broadcast_log
            .push(BroadcastMessage::PhaseTransition(next));
        Ok(())
    }

    /// Broadcasts a finding to all workers.
    pub fn broadcast_finding(&mut self, finding: FindingData) {
        self.broadcast_log
            .push(BroadcastMessage::NewFinding(finding));
    }

    /// Broadcasts a custom message to all workers.
    pub fn broadcast_custom(&mut self, message: String) {
        self.broadcast_log.push(BroadcastMessage::Custom(message));
    }

    /// Returns the current scan phase.
    pub fn current_phase(&self) -> ScanPhase {
        self.current_phase
    }

    /// Returns the full phase history.
    pub fn phase_history(&self) -> &[ScanPhase] {
        &self.phase_history
    }

    /// Returns the broadcast log.
    pub fn broadcast_log(&self) -> &[BroadcastMessage] {
        &self.broadcast_log
    }

    /// Returns pending workers for the current barrier, if one exists.
    pub fn pending_workers(&self) -> Vec<String> {
        self.barriers
            .get(&self.current_phase)
            .map(|b| b.pending_workers())
            .unwrap_or_default()
    }

    /// Returns the count of registered workers.
    pub fn worker_count(&self) -> usize {
        self.registered_workers.len()
    }
}
