use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use crate::distributed::{WorkerId, WorkerRole, WorkerState};

/// Capability a worker advertises during registration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WorkerCapability {
    Fuzzing,
    Recon,
    BruteForce,
    CrawlHeadless,
    ExploitVerification,
    DomVerification,
}

impl fmt::Display for WorkerCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fuzzing => write!(f, "fuzzing"),
            Self::Recon => write!(f, "recon"),
            Self::BruteForce => write!(f, "brute-force"),
            Self::CrawlHeadless => write!(f, "crawl-headless"),
            Self::ExploitVerification => write!(f, "exploit-verification"),
            Self::DomVerification => write!(f, "dom-verification"),
        }
    }
}

/// Geographic region hint for IP diversity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Region {
    UsEast,
    UsWest,
    EuWest,
    EuCentral,
    AsiaPacific,
    Custom(String),
}

impl fmt::Display for Region {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UsEast => write!(f, "us-east"),
            Self::UsWest => write!(f, "us-west"),
            Self::EuWest => write!(f, "eu-west"),
            Self::EuCentral => write!(f, "eu-central"),
            Self::AsiaPacific => write!(f, "asia-pacific"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

/// Health snapshot from a single heartbeat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub last_heartbeat_ms: u64,
    pub latency_ms: u64,
    pub load_percent: f64,
    pub consecutive_failures: u32,
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self {
            last_heartbeat_ms: 0,
            latency_ms: 0,
            load_percent: 0.0,
            consecutive_failures: 0,
        }
    }
}

/// Full registration info for a single worker node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerNode {
    pub worker_id: WorkerId,
    pub role: WorkerRole,
    pub capabilities: Vec<WorkerCapability>,
    pub available_tools: Vec<String>,
    pub ip_address: String,
    pub region: Region,
    pub state: WorkerState,
    pub health: HealthStatus,
    pub assigned_tasks: u64,
    pub completed_tasks: u64,
    pub findings_reported: u64,
}

/// Errors from WorkerNodeManager operations.
#[derive(Debug)]
pub enum WorkerNodeError {
    WorkerNotFound(String),
    DuplicateWorker(String),
    PoolBelowMinimum { current: usize, minimum: usize },
    NoCapableWorker(WorkerCapability),
}

impl fmt::Display for WorkerNodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkerNotFound(id) => write!(f, "worker not found: {id}"),
            Self::DuplicateWorker(id) => write!(f, "duplicate worker: {id}"),
            Self::PoolBelowMinimum { current, minimum } => {
                write!(f, "pool size {current} below minimum {minimum}")
            }
            Self::NoCapableWorker(cap) => write!(f, "no worker with capability: {cap}"),
        }
    }
}

impl std::error::Error for WorkerNodeError {}

/// Configuration for the worker pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerPoolConfig {
    pub min_workers: usize,
    pub heartbeat_timeout_ms: u64,
    pub max_consecutive_failures: u32,
    pub load_threshold_percent: f64,
}

impl Default for WorkerPoolConfig {
    fn default() -> Self {
        Self {
            min_workers: 1,
            heartbeat_timeout_ms: 30_000,
            max_consecutive_failures: 3,
            load_threshold_percent: 80.0,
        }
    }
}

/// Manages a fleet of distributed scan workers.
pub struct WorkerNodeManager {
    workers: HashMap<String, WorkerNode>,
    config: WorkerPoolConfig,
}

impl WorkerNodeManager {
    /// Creates an empty manager with the given pool configuration.
    pub fn new(config: WorkerPoolConfig) -> Self {
        Self {
            workers: HashMap::new(),
            config,
        }
    }

    /// Registers a worker. Returns error if a worker with the same ID already exists.
    pub fn register(
        &mut self,
        worker_id: WorkerId,
        role: WorkerRole,
        capabilities: Vec<WorkerCapability>,
        available_tools: Vec<String>,
        ip_address: String,
        region: Region,
    ) -> Result<(), WorkerNodeError> {
        if self.workers.contains_key(&worker_id.id) {
            return Err(WorkerNodeError::DuplicateWorker(worker_id.id.clone()));
        }
        let node = WorkerNode {
            worker_id: worker_id.clone(),
            role,
            capabilities,
            available_tools,
            ip_address,
            region,
            state: WorkerState::Idle,
            health: HealthStatus {
                last_heartbeat_ms: crate::util::timestamp_ms(),
                ..Default::default()
            },
            assigned_tasks: 0,
            completed_tasks: 0,
            findings_reported: 0,
        };
        self.workers.insert(worker_id.id, node);
        Ok(())
    }

    /// Removes a worker from the pool.
    pub fn deregister(&mut self, worker_id: &str) -> Result<WorkerNode, WorkerNodeError> {
        self.workers
            .remove(worker_id)
            .ok_or_else(|| WorkerNodeError::WorkerNotFound(worker_id.to_string()))
    }

    /// Records a heartbeat with latency and load metrics.
    pub fn record_heartbeat(
        &mut self,
        worker_id: &str,
        latency_ms: u64,
        load_percent: f64,
    ) -> Result<(), WorkerNodeError> {
        let node = self
            .workers
            .get_mut(worker_id)
            .ok_or_else(|| WorkerNodeError::WorkerNotFound(worker_id.to_string()))?;
        node.health.last_heartbeat_ms = crate::util::timestamp_ms();
        node.health.latency_ms = latency_ms;
        node.health.load_percent = load_percent;
        node.health.consecutive_failures = 0;
        Ok(())
    }

    /// Marks workers as failed if their last heartbeat exceeds the timeout.
    /// Returns the IDs of newly-failed workers.
    pub fn check_health(&mut self, current_time_ms: u64) -> Vec<String> {
        let timeout = self.config.heartbeat_timeout_ms;
        let max_failures = self.config.max_consecutive_failures;
        let mut failed = Vec::new();
        for node in self.workers.values_mut() {
            if node.state == WorkerState::Failed || node.state == WorkerState::Completed {
                continue;
            }
            let elapsed = current_time_ms.saturating_sub(node.health.last_heartbeat_ms);
            if elapsed > timeout {
                node.health.consecutive_failures += 1;
                if node.health.consecutive_failures >= max_failures {
                    node.state = WorkerState::Failed;
                    failed.push(node.worker_id.id.clone());
                }
            }
        }
        failed
    }

    /// Selects the best worker for a given capability based on lowest load.
    pub fn assign_task(
        &mut self,
        capability: &WorkerCapability,
    ) -> Result<String, WorkerNodeError> {
        let best = self
            .workers
            .values()
            .filter(|w| w.state == WorkerState::Idle || w.state == WorkerState::Working)
            .filter(|w| w.capabilities.contains(capability))
            .min_by(|a, b| {
                a.health
                    .load_percent
                    .partial_cmp(&b.health.load_percent)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|w| w.worker_id.id.clone());
        match best {
            Some(id) => {
                let node = self.workers.get_mut(&id).unwrap();
                node.state = WorkerState::Working;
                node.assigned_tasks += 1;
                Ok(id)
            }
            None => Err(WorkerNodeError::NoCapableWorker(capability.clone())),
        }
    }

    /// Records task completion for a worker.
    pub fn record_task_complete(
        &mut self,
        worker_id: &str,
        findings_count: u64,
    ) -> Result<(), WorkerNodeError> {
        let node = self
            .workers
            .get_mut(worker_id)
            .ok_or_else(|| WorkerNodeError::WorkerNotFound(worker_id.to_string()))?;
        node.completed_tasks += 1;
        node.findings_reported += findings_count;
        if node.assigned_tasks == node.completed_tasks {
            node.state = WorkerState::Idle;
        }
        Ok(())
    }

    /// Returns the current pool size (all registered workers regardless of state).
    pub fn pool_size(&self) -> usize {
        self.workers.len()
    }

    /// Returns the count of active (Idle or Working) workers.
    pub fn active_count(&self) -> usize {
        self.workers
            .values()
            .filter(|w| w.state == WorkerState::Idle || w.state == WorkerState::Working)
            .count()
    }

    /// Checks whether the active worker count is below the configured minimum.
    pub fn pool_below_minimum(&self) -> Option<WorkerNodeError> {
        let active = self.active_count();
        if active < self.config.min_workers {
            Some(WorkerNodeError::PoolBelowMinimum {
                current: active,
                minimum: self.config.min_workers,
            })
        } else {
            None
        }
    }

    /// Returns a reference to a worker by ID.
    pub fn get_worker(&self, worker_id: &str) -> Option<&WorkerNode> {
        self.workers.get(worker_id)
    }

    /// Returns all workers in the pool.
    pub fn all_workers(&self) -> Vec<&WorkerNode> {
        self.workers.values().collect()
    }

    /// Returns workers filtered by region.
    pub fn workers_in_region(&self, region: &Region) -> Vec<&WorkerNode> {
        self.workers
            .values()
            .filter(|w| w.region == *region)
            .collect()
    }

    /// Returns workers that have the given capability.
    pub fn workers_with_capability(&self, cap: &WorkerCapability) -> Vec<&WorkerNode> {
        self.workers
            .values()
            .filter(|w| w.capabilities.contains(cap))
            .collect()
    }

    /// Returns overloaded workers (load above threshold).
    pub fn overloaded_workers(&self) -> Vec<&WorkerNode> {
        let threshold = self.config.load_threshold_percent;
        self.workers
            .values()
            .filter(|w| w.health.load_percent > threshold)
            .collect()
    }

    /// Returns idle workers sorted by load ascending (lightest first).
    pub fn idle_workers(&self) -> Vec<&WorkerNode> {
        let mut idle: Vec<&WorkerNode> = self
            .workers
            .values()
            .filter(|w| w.state == WorkerState::Idle)
            .collect();
        idle.sort_by(|a, b| {
            a.health
                .load_percent
                .partial_cmp(&b.health.load_percent)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        idle
    }

    /// Returns a summary of the worker pool state.
    pub fn summary(&self) -> WorkerPoolSummary {
        let total = self.workers.len();
        let active = self.active_count();
        let failed = self
            .workers
            .values()
            .filter(|w| w.state == WorkerState::Failed)
            .count();
        let total_findings: u64 = self.workers.values().map(|w| w.findings_reported).sum();
        WorkerPoolSummary {
            total_workers: total,
            active_workers: active,
            failed_workers: failed,
            total_findings,
        }
    }
}

/// Snapshot summary of the worker pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerPoolSummary {
    pub total_workers: usize,
    pub active_workers: usize,
    pub failed_workers: usize,
    pub total_findings: u64,
}
