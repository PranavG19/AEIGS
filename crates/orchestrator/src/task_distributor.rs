use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use crate::distributed::{WorkerId, WorkerState};
use crate::worker_node::{Region, WorkerCapability, WorkerNode, WorkerNodeManager};

/// Strategy for distributing tasks across workers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DistributionStrategy {
    /// Each worker scans different endpoints.
    EndpointBased,
    /// Each worker runs different attack modules.
    ModuleBased,
    /// Workers in different regions for IP diversity.
    Geographic,
    /// High-priority targets get more workers.
    PriorityBased,
}

/// A scan task to be distributed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTask {
    pub task_id: String,
    pub endpoint: String,
    pub modules: Vec<String>,
    pub priority: f64,
}

/// Result of distributing tasks: which worker gets what.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskAssignment {
    pub worker_id: String,
    pub tasks: Vec<ScanTask>,
}

/// Errors from task distribution.
#[derive(Debug)]
pub enum TaskDistributorError {
    NoWorkersAvailable,
    NoTasksProvided,
    InvalidPriority(f64),
    WorkerOverloaded(String),
}

impl fmt::Display for TaskDistributorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoWorkersAvailable => write!(f, "no workers available for task distribution"),
            Self::NoTasksProvided => write!(f, "no tasks provided for distribution"),
            Self::InvalidPriority(p) => write!(f, "invalid priority value: {p}"),
            Self::WorkerOverloaded(id) => write!(f, "worker {id} is overloaded"),
        }
    }
}

impl std::error::Error for TaskDistributorError {}

/// Distributes scan tasks across workers intelligently.
pub struct TaskDistributor {
    assignments: HashMap<String, Vec<ScanTask>>,
    _load_threshold: f64,
}

impl TaskDistributor {
    /// Creates a new distributor with the given load threshold (0.0–100.0).
    pub fn new(load_threshold: f64) -> Self {
        Self {
            assignments: HashMap::new(),
            _load_threshold: load_threshold,
        }
    }

    /// Distributes tasks by endpoint: round-robin across available workers.
    pub fn distribute_by_endpoint(
        &mut self,
        tasks: &[ScanTask],
        workers: &[&WorkerNode],
    ) -> Result<Vec<TaskAssignment>, TaskDistributorError> {
        if workers.is_empty() {
            return Err(TaskDistributorError::NoWorkersAvailable);
        }
        if tasks.is_empty() {
            return Err(TaskDistributorError::NoTasksProvided);
        }
        let active: Vec<&&WorkerNode> = workers
            .iter()
            .filter(|w| w.state == WorkerState::Idle || w.state == WorkerState::Working)
            .collect();
        if active.is_empty() {
            return Err(TaskDistributorError::NoWorkersAvailable);
        }
        self.assignments.clear();
        for (i, task) in tasks.iter().enumerate() {
            let worker = active[i % active.len()];
            self.assignments
                .entry(worker.worker_id.id.clone())
                .or_default()
                .push(task.clone());
        }
        Ok(self.build_assignments())
    }

    /// Distributes tasks by module: each worker gets tasks with distinct modules.
    pub fn distribute_by_module(
        &mut self,
        tasks: &[ScanTask],
        workers: &[&WorkerNode],
    ) -> Result<Vec<TaskAssignment>, TaskDistributorError> {
        if workers.is_empty() {
            return Err(TaskDistributorError::NoWorkersAvailable);
        }
        if tasks.is_empty() {
            return Err(TaskDistributorError::NoTasksProvided);
        }
        let active: Vec<&&WorkerNode> = workers
            .iter()
            .filter(|w| w.state == WorkerState::Idle || w.state == WorkerState::Working)
            .collect();
        if active.is_empty() {
            return Err(TaskDistributorError::NoWorkersAvailable);
        }
        self.assignments.clear();
        let mut module_to_worker: HashMap<String, String> = HashMap::new();
        let mut next_worker = 0usize;
        for task in tasks {
            let primary_module = task.modules.first().cloned().unwrap_or_default();
            let worker_id = module_to_worker
                .entry(primary_module)
                .or_insert_with(|| {
                    let id = active[next_worker % active.len()].worker_id.id.clone();
                    next_worker += 1;
                    id
                })
                .clone();
            self.assignments
                .entry(worker_id)
                .or_default()
                .push(task.clone());
        }
        Ok(self.build_assignments())
    }

    /// Distributes tasks geographically: tasks go to workers in unique regions.
    pub fn distribute_by_geography(
        &mut self,
        tasks: &[ScanTask],
        workers: &[&WorkerNode],
    ) -> Result<Vec<TaskAssignment>, TaskDistributorError> {
        if workers.is_empty() {
            return Err(TaskDistributorError::NoWorkersAvailable);
        }
        if tasks.is_empty() {
            return Err(TaskDistributorError::NoTasksProvided);
        }
        let active: Vec<&&WorkerNode> = workers
            .iter()
            .filter(|w| w.state == WorkerState::Idle || w.state == WorkerState::Working)
            .collect();
        if active.is_empty() {
            return Err(TaskDistributorError::NoWorkersAvailable);
        }
        self.assignments.clear();
        let mut region_workers: HashMap<String, Vec<String>> = HashMap::new();
        for w in &active {
            region_workers
                .entry(format!("{}", w.region))
                .or_default()
                .push(w.worker_id.id.clone());
        }
        let regions: Vec<String> = region_workers.keys().cloned().collect();
        for (i, task) in tasks.iter().enumerate() {
            let region = &regions[i % regions.len()];
            let region_w = &region_workers[region];
            let worker_id = &region_w[i / regions.len() % region_w.len()];
            self.assignments
                .entry(worker_id.clone())
                .or_default()
                .push(task.clone());
        }
        Ok(self.build_assignments())
    }

    /// Distributes tasks by priority: high-priority tasks get workers with lowest load.
    pub fn distribute_by_priority(
        &mut self,
        tasks: &[ScanTask],
        workers: &[&WorkerNode],
    ) -> Result<Vec<TaskAssignment>, TaskDistributorError> {
        if workers.is_empty() {
            return Err(TaskDistributorError::NoWorkersAvailable);
        }
        if tasks.is_empty() {
            return Err(TaskDistributorError::NoTasksProvided);
        }
        let mut active: Vec<&&WorkerNode> = workers
            .iter()
            .filter(|w| w.state == WorkerState::Idle || w.state == WorkerState::Working)
            .collect();
        if active.is_empty() {
            return Err(TaskDistributorError::NoWorkersAvailable);
        }
        active.sort_by(|a, b| {
            a.health
                .load_percent
                .partial_cmp(&b.health.load_percent)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        self.assignments.clear();
        let mut sorted_tasks: Vec<&ScanTask> = tasks.iter().collect();
        sorted_tasks.sort_by(|a, b| {
            b.priority
                .partial_cmp(&a.priority)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for (i, task) in sorted_tasks.iter().enumerate() {
            let worker = active[i % active.len()];
            self.assignments
                .entry(worker.worker_id.id.clone())
                .or_default()
                .push((*task).clone());
        }
        Ok(self.build_assignments())
    }

    /// Redistributes tasks from overloaded workers to idle workers.
    pub fn rebalance(&mut self, manager: &WorkerNodeManager) -> Vec<TaskAssignment> {
        let overloaded = manager.overloaded_workers();
        let idle = manager.idle_workers();
        if overloaded.is_empty() || idle.is_empty() {
            return Vec::new();
        }
        let mut redistributed: Vec<TaskAssignment> = Vec::new();
        let mut idle_idx = 0;
        for ow in &overloaded {
            if let Some(tasks) = self.assignments.remove(&ow.worker_id.id) {
                let half = tasks.len() / 2;
                if half == 0 {
                    self.assignments.insert(ow.worker_id.id.clone(), tasks);
                    continue;
                }
                let (keep, give) = tasks.split_at(tasks.len() - half);
                self.assignments
                    .insert(ow.worker_id.id.clone(), keep.to_vec());
                let target = &idle[idle_idx % idle.len()];
                self.assignments
                    .entry(target.worker_id.id.clone())
                    .or_default()
                    .extend_from_slice(give);
                redistributed.push(TaskAssignment {
                    worker_id: target.worker_id.id.clone(),
                    tasks: give.to_vec(),
                });
                idle_idx += 1;
            }
        }
        redistributed
    }

    /// Returns current assignment count per worker.
    pub fn assignment_counts(&self) -> HashMap<String, usize> {
        self.assignments
            .iter()
            .map(|(k, v)| (k.clone(), v.len()))
            .collect()
    }

    /// Returns total number of tasks currently assigned.
    pub fn total_assigned(&self) -> usize {
        self.assignments.values().map(|v| v.len()).sum()
    }

    fn build_assignments(&self) -> Vec<TaskAssignment> {
        self.assignments
            .iter()
            .map(|(worker_id, tasks)| TaskAssignment {
                worker_id: worker_id.clone(),
                tasks: tasks.clone(),
            })
            .collect()
    }
}
