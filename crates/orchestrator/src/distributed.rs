use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identifier for a scan worker in a distributed AEGIS deployment.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkerId {
    pub id: String,
}

impl fmt::Display for WorkerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

/// Role a worker plays in the distributed scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerRole {
    /// Assigns work, collects results, produces final report.
    Coordinator,
    /// Executes assigned fuzz targets.
    FuzzWorker,
    /// Performs reconnaissance only.
    ReconWorker,
}

/// Lifecycle state of a worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerState {
    /// Waiting for work.
    Idle,
    /// Actively fuzzing.
    Working,
    /// Paused by coordinator.
    Paused,
    /// Finished assigned work.
    Completed,
    /// Errored out.
    Failed,
}

/// A bundle of work assigned to a single worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkAssignment {
    pub worker_id: WorkerId,
    pub endpoints: Vec<String>,
    pub vulnerability_classes: Vec<String>,
    pub priority_range: (f64, f64),
}

/// Current status snapshot for a single worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerStatus {
    pub worker_id: WorkerId,
    pub role: WorkerRole,
    pub state: WorkerState,
    pub targets_completed: u64,
    pub targets_remaining: u64,
    pub findings_count: u64,
    pub last_heartbeat_ms: u64,
}

/// Strategy for partitioning endpoints across workers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssignmentStrategy {
    /// Distribute endpoints evenly, cycling through workers.
    RoundRobin,
    /// Sort by complexity (length proxy), give hardest batch to worker 0.
    PriorityBased,
    /// Group by vulnerability class (falls back to RoundRobin for endpoint-only partitioning).
    VulnerabilityClass,
}

/// Configuration for distributed scan coordination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedConfig {
    pub worker_count: usize,
    pub assignment_strategy: AssignmentStrategy,
    pub heartbeat_interval_ms: u64,
    pub worker_timeout_ms: u64,
    pub rebalance_on_failure: bool,
}

/// Errors arising from distributed scan coordination.
#[derive(Debug)]
pub enum DistributedError {
    /// No workers registered.
    NoWorkers,
    /// Unknown worker ID.
    WorkerNotFound(String),
    /// Every worker has failed.
    AllWorkersFailed,
    /// Bad configuration.
    InvalidConfig(String),
}

impl fmt::Display for DistributedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoWorkers => write!(f, "no workers registered"),
            Self::WorkerNotFound(id) => write!(f, "worker not found: {id}"),
            Self::AllWorkersFailed => write!(f, "all workers have failed"),
            Self::InvalidConfig(msg) => write!(f, "invalid distributed config: {msg}"),
        }
    }
}

impl std::error::Error for DistributedError {}

/// Coordinator's view of the distributed scan state.
#[derive(Debug)]
pub struct CoordinatorState {
    pub workers: Vec<WorkerStatus>,
    pub assignments: Vec<WorkAssignment>,
    pub unassigned_endpoints: Vec<String>,
    pub collected_findings: u64,
    pub started_at_ms: u64,
}

/// Partitions endpoints among `worker_count` workers according to the given strategy.
///
/// `VulnerabilityClass` is not applicable to endpoint-only partitioning and falls back
/// to round-robin.
pub fn partition_endpoints(
    endpoints: &[String],
    worker_count: usize,
    strategy: AssignmentStrategy,
) -> Vec<Vec<String>> {
    if worker_count == 0 {
        return Vec::new();
    }
    let mut buckets: Vec<Vec<String>> = (0..worker_count).map(|_| Vec::new()).collect();
    match strategy {
        AssignmentStrategy::RoundRobin | AssignmentStrategy::VulnerabilityClass => {
            for (i, ep) in endpoints.iter().enumerate() {
                buckets[i % worker_count].push(ep.clone());
            }
        }
        AssignmentStrategy::PriorityBased => {
            let mut sorted: Vec<&String> = endpoints.iter().collect();
            sorted.sort_by_key(|s| std::cmp::Reverse(s.len()));
            for (i, ep) in sorted.into_iter().enumerate() {
                buckets[i % worker_count].push(ep.clone());
            }
        }
    }
    buckets
}

/// Creates a `WorkAssignment` for each worker from the partitioned endpoints.
pub fn create_assignments(
    endpoints: &[String],
    workers: &[WorkerId],
    strategy: AssignmentStrategy,
) -> Vec<WorkAssignment> {
    let partitions = partition_endpoints(endpoints, workers.len(), strategy);
    workers
        .iter()
        .zip(partitions)
        .map(|(wid, eps)| WorkAssignment {
            worker_id: wid.clone(),
            endpoints: eps,
            vulnerability_classes: Vec::new(),
            priority_range: (0.0, 1.0),
        })
        .collect()
}

/// Returns a `DistributedConfig` with sensible defaults.
pub fn default_distributed_config(worker_count: usize) -> DistributedConfig {
    DistributedConfig {
        worker_count,
        assignment_strategy: AssignmentStrategy::RoundRobin,
        heartbeat_interval_ms: 5000,
        worker_timeout_ms: 30000,
        rebalance_on_failure: true,
    }
}

/// Returns a human-readable summary of work assignments.
pub fn describe_assignments(assignments: &[WorkAssignment]) -> String {
    let mut lines: Vec<String> = Vec::with_capacity(assignments.len() + 1);
    lines.push(format!("{} worker(s) assigned:", assignments.len()));
    for a in assignments {
        lines.push(format!(
            "  {} -> {} endpoint(s)",
            a.worker_id,
            a.endpoints.len()
        ));
    }
    lines.join("\n")
}

impl CoordinatorState {
    /// Initializes coordinator state with no workers and no assignments.
    pub fn new(config: &DistributedConfig) -> Self {
        let _ = config;
        Self {
            workers: Vec::new(),
            assignments: Vec::new(),
            unassigned_endpoints: Vec::new(),
            collected_findings: 0,
            started_at_ms: crate::util::timestamp_ms(),
        }
    }

    /// Registers a worker with the given role, starting in `Idle` state.
    pub fn register_worker(&mut self, worker_id: WorkerId, role: WorkerRole) {
        self.workers.push(WorkerStatus {
            worker_id,
            role,
            state: WorkerState::Idle,
            targets_completed: 0,
            targets_remaining: 0,
            findings_count: 0,
            last_heartbeat_ms: crate::util::timestamp_ms(),
        });
    }

    /// Partitions endpoints and creates assignments for all registered `FuzzWorker`s.
    pub fn assign_work(
        &mut self,
        endpoints: &[String],
        strategy: AssignmentStrategy,
    ) -> Result<Vec<WorkAssignment>, DistributedError> {
        let fuzz_workers: Vec<WorkerId> = self
            .workers
            .iter()
            .filter(|w| w.role == WorkerRole::FuzzWorker)
            .map(|w| w.worker_id.clone())
            .collect();
        if fuzz_workers.is_empty() {
            return Err(DistributedError::NoWorkers);
        }
        let assignments = create_assignments(endpoints, &fuzz_workers, strategy);
        self.assignments = assignments.clone();
        self.unassigned_endpoints.clear();
        Ok(assignments)
    }

    /// Updates a worker's status fields. Returns quietly if the worker is unknown.
    pub fn update_worker_status(
        &mut self,
        worker_id: &WorkerId,
        state: WorkerState,
        targets_completed: u64,
        targets_remaining: u64,
        findings_count: u64,
    ) {
        if let Some(ws) = self.workers.iter_mut().find(|w| w.worker_id == *worker_id) {
            ws.state = state;
            ws.targets_completed = targets_completed;
            ws.targets_remaining = targets_remaining;
            ws.findings_count = findings_count;
            ws.last_heartbeat_ms = crate::util::timestamp_ms();
        }
    }

    /// Returns workers whose last heartbeat is older than `timeout_ms` from `current_time_ms`.
    pub fn detect_failed_workers(&self, current_time_ms: u64, timeout_ms: u64) -> Vec<WorkerId> {
        self.workers
            .iter()
            .filter(|w| {
                w.state != WorkerState::Completed
                    && w.state != WorkerState::Failed
                    && current_time_ms.saturating_sub(w.last_heartbeat_ms) > timeout_ms
            })
            .map(|w| w.worker_id.clone())
            .collect()
    }

    /// Redistributes the failed worker's endpoints to remaining active workers.
    ///
    /// Returns `None` if there are no active workers left to receive the work.
    pub fn rebalance(&mut self, failed_worker: &WorkerId) -> Option<Vec<WorkAssignment>> {
        let failed_endpoints: Vec<String> = self
            .assignments
            .iter()
            .filter(|a| a.worker_id == *failed_worker)
            .flat_map(|a| a.endpoints.clone())
            .collect();
        let active_workers: Vec<WorkerId> = self
            .workers
            .iter()
            .filter(|w| {
                w.worker_id != *failed_worker
                    && (w.state == WorkerState::Working || w.state == WorkerState::Idle)
            })
            .map(|w| w.worker_id.clone())
            .collect();
        if active_workers.is_empty() {
            return None;
        }
        let new_assignments = create_assignments(
            &failed_endpoints,
            &active_workers,
            AssignmentStrategy::RoundRobin,
        );
        self.assignments.retain(|a| a.worker_id != *failed_worker);
        self.assignments.extend(new_assignments.clone());
        Some(new_assignments)
    }

    /// Returns `true` when every worker is in `Completed` or `Failed` state.
    pub fn all_complete(&self) -> bool {
        self.workers
            .iter()
            .all(|w| w.state == WorkerState::Completed || w.state == WorkerState::Failed)
    }

    /// Returns the count of workers in `Working` or `Idle` state.
    pub fn active_worker_count(&self) -> usize {
        self.workers
            .iter()
            .filter(|w| w.state == WorkerState::Working || w.state == WorkerState::Idle)
            .count()
    }

    /// Returns the sum of all workers' findings counts.
    pub fn total_findings(&self) -> u64 {
        self.workers.iter().map(|w| w.findings_count).sum()
    }
}
