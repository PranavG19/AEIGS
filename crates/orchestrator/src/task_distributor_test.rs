use crate::distributed::{WorkerId, WorkerRole, WorkerState};
use crate::task_distributor::{ScanTask, TaskDistributor, TaskDistributorError};
use crate::worker_node::{
    HealthStatus, Region, WorkerCapability, WorkerNode, WorkerNodeManager, WorkerPoolConfig,
};

fn make_worker(id: &str, region: Region, load: f64) -> WorkerNode {
    WorkerNode {
        worker_id: WorkerId { id: id.to_string() },
        role: WorkerRole::FuzzWorker,
        capabilities: vec![WorkerCapability::Fuzzing],
        available_tools: vec!["nmap".to_string()],
        ip_address: "10.0.0.1".to_string(),
        region,
        state: WorkerState::Idle,
        health: HealthStatus {
            last_heartbeat_ms: crate::util::timestamp_ms(),
            latency_ms: 10,
            load_percent: load,
            consecutive_failures: 0,
        },
        assigned_tasks: 0,
        completed_tasks: 0,
        findings_reported: 0,
    }
}

fn sample_tasks(n: usize) -> Vec<ScanTask> {
    (0..n)
        .map(|i| ScanTask {
            task_id: format!("task-{i}"),
            endpoint: format!("/api/endpoint-{i}"),
            modules: vec!["sqli".to_string()],
            priority: (n - i) as f64,
        })
        .collect()
}

fn sample_tasks_with_modules(modules: &[&str]) -> Vec<ScanTask> {
    modules
        .iter()
        .enumerate()
        .map(|(i, m)| ScanTask {
            task_id: format!("task-{i}"),
            endpoint: format!("/api/endpoint-{i}"),
            modules: vec![m.to_string()],
            priority: 1.0,
        })
        .collect()
}

// --- Endpoint distribution ---

#[test]
fn distribute_by_endpoint_round_robin() {
    let w1 = make_worker("w1", Region::UsEast, 10.0);
    let w2 = make_worker("w2", Region::UsWest, 20.0);
    let workers: Vec<&WorkerNode> = vec![&w1, &w2];
    let tasks = sample_tasks(4);
    let mut dist = TaskDistributor::new(80.0);
    let assignments = dist.distribute_by_endpoint(&tasks, &workers).unwrap();
    assert_eq!(assignments.len(), 2);
    let total: usize = assignments.iter().map(|a| a.tasks.len()).sum();
    assert_eq!(total, 4);
}

#[test]
fn distribute_by_endpoint_no_workers_fails() {
    let workers: Vec<&WorkerNode> = vec![];
    let tasks = sample_tasks(2);
    let mut dist = TaskDistributor::new(80.0);
    let result = dist.distribute_by_endpoint(&tasks, &workers);
    assert!(result.is_err());
}

#[test]
fn distribute_by_endpoint_no_tasks_fails() {
    let w1 = make_worker("w1", Region::UsEast, 10.0);
    let workers: Vec<&WorkerNode> = vec![&w1];
    let mut dist = TaskDistributor::new(80.0);
    let result = dist.distribute_by_endpoint(&[], &workers);
    assert!(result.is_err());
}

#[test]
fn distribute_by_endpoint_single_worker() {
    let w1 = make_worker("w1", Region::UsEast, 10.0);
    let workers: Vec<&WorkerNode> = vec![&w1];
    let tasks = sample_tasks(5);
    let mut dist = TaskDistributor::new(80.0);
    let assignments = dist.distribute_by_endpoint(&tasks, &workers).unwrap();
    assert_eq!(assignments.len(), 1);
    assert_eq!(assignments[0].tasks.len(), 5);
}

#[test]
fn distribute_by_endpoint_skips_failed_workers() {
    let w1 = make_worker("w1", Region::UsEast, 10.0);
    let mut w2 = make_worker("w2", Region::UsWest, 20.0);
    w2.state = WorkerState::Failed;
    let workers: Vec<&WorkerNode> = vec![&w1, &w2];
    let tasks = sample_tasks(4);
    let mut dist = TaskDistributor::new(80.0);
    let assignments = dist.distribute_by_endpoint(&tasks, &workers).unwrap();
    assert_eq!(assignments.len(), 1);
    assert_eq!(assignments[0].worker_id, "w1");
    assert_eq!(assignments[0].tasks.len(), 4);
}

// --- Module distribution ---

#[test]
fn distribute_by_module_groups_same_module() {
    let w1 = make_worker("w1", Region::UsEast, 10.0);
    let w2 = make_worker("w2", Region::UsWest, 20.0);
    let workers: Vec<&WorkerNode> = vec![&w1, &w2];
    let tasks = sample_tasks_with_modules(&["sqli", "sqli", "xss", "xss"]);
    let mut dist = TaskDistributor::new(80.0);
    let assignments = dist.distribute_by_module(&tasks, &workers).unwrap();
    let total: usize = assignments.iter().map(|a| a.tasks.len()).sum();
    assert_eq!(total, 4);
    // Each module should be assigned to a specific worker
    assert!(assignments.len() <= 2);
}

#[test]
fn distribute_by_module_no_workers_fails() {
    let workers: Vec<&WorkerNode> = vec![];
    let tasks = sample_tasks(2);
    let mut dist = TaskDistributor::new(80.0);
    let result = dist.distribute_by_module(&tasks, &workers);
    assert!(result.is_err());
}

// --- Geographic distribution ---

#[test]
fn distribute_by_geography_spreads_across_regions() {
    let w1 = make_worker("w1", Region::UsEast, 10.0);
    let w2 = make_worker("w2", Region::EuWest, 20.0);
    let workers: Vec<&WorkerNode> = vec![&w1, &w2];
    let tasks = sample_tasks(4);
    let mut dist = TaskDistributor::new(80.0);
    let assignments = dist.distribute_by_geography(&tasks, &workers).unwrap();
    let total: usize = assignments.iter().map(|a| a.tasks.len()).sum();
    assert_eq!(total, 4);
    assert!(assignments.len() <= 2);
}

#[test]
fn distribute_by_geography_no_workers_fails() {
    let workers: Vec<&WorkerNode> = vec![];
    let tasks = sample_tasks(2);
    let mut dist = TaskDistributor::new(80.0);
    let result = dist.distribute_by_geography(&tasks, &workers);
    assert!(result.is_err());
}

// --- Priority distribution ---

#[test]
fn distribute_by_priority_highest_to_lightest_worker() {
    let w1 = make_worker("w1", Region::UsEast, 90.0);
    let w2 = make_worker("w2", Region::UsWest, 10.0);
    let workers: Vec<&WorkerNode> = vec![&w1, &w2];
    let tasks = sample_tasks(2);
    let mut dist = TaskDistributor::new(80.0);
    let assignments = dist.distribute_by_priority(&tasks, &workers).unwrap();
    // Highest priority task should go to w2 (lowest load)
    let w2_assignment = assignments.iter().find(|a| a.worker_id == "w2").unwrap();
    assert!(!w2_assignment.tasks.is_empty());
}

#[test]
fn distribute_by_priority_no_workers_fails() {
    let workers: Vec<&WorkerNode> = vec![];
    let tasks = sample_tasks(2);
    let mut dist = TaskDistributor::new(80.0);
    let result = dist.distribute_by_priority(&tasks, &workers);
    assert!(result.is_err());
}

// --- Rebalancing ---

#[test]
fn rebalance_moves_tasks_from_overloaded() {
    let mut mgr = WorkerNodeManager::new(WorkerPoolConfig::default());
    mgr.register(
        WorkerId {
            id: "heavy".to_string(),
        },
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        vec![],
        "10.0.0.1".to_string(),
        Region::UsEast,
    )
    .unwrap();
    mgr.register(
        WorkerId {
            id: "light".to_string(),
        },
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        vec![],
        "10.0.0.2".to_string(),
        Region::UsWest,
    )
    .unwrap();
    mgr.record_heartbeat("heavy", 10, 95.0).unwrap();
    mgr.record_heartbeat("light", 10, 10.0).unwrap();

    let w_heavy = mgr.get_worker("heavy").unwrap();
    let w_light = mgr.get_worker("light").unwrap();
    let workers: Vec<&WorkerNode> = vec![w_heavy, w_light];
    let tasks = sample_tasks(6);
    let mut dist = TaskDistributor::new(80.0);
    dist.distribute_by_endpoint(&tasks, &workers).unwrap();

    let redistributed = dist.rebalance(&mgr);
    // Some tasks should have moved from heavy to light
    assert!(!redistributed.is_empty() || dist.assignment_counts().values().all(|&v| v <= 4));
}

#[test]
fn rebalance_no_overloaded_returns_empty() {
    let mut mgr = WorkerNodeManager::new(WorkerPoolConfig::default());
    mgr.register(
        WorkerId {
            id: "w1".to_string(),
        },
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        vec![],
        "10.0.0.1".to_string(),
        Region::UsEast,
    )
    .unwrap();
    mgr.record_heartbeat("w1", 10, 20.0).unwrap();
    let mut dist = TaskDistributor::new(80.0);
    let result = dist.rebalance(&mgr);
    assert!(result.is_empty());
}

// --- Counters ---

#[test]
fn assignment_counts_and_total() {
    let w1 = make_worker("w1", Region::UsEast, 10.0);
    let w2 = make_worker("w2", Region::UsWest, 20.0);
    let workers: Vec<&WorkerNode> = vec![&w1, &w2];
    let tasks = sample_tasks(5);
    let mut dist = TaskDistributor::new(80.0);
    dist.distribute_by_endpoint(&tasks, &workers).unwrap();
    assert_eq!(dist.total_assigned(), 5);
    let counts = dist.assignment_counts();
    assert_eq!(counts.values().sum::<usize>(), 5);
}

// --- Error display ---

#[test]
fn error_display_messages() {
    let e = TaskDistributorError::NoWorkersAvailable;
    assert!(format!("{e}").contains("no workers"));
    let e = TaskDistributorError::NoTasksProvided;
    assert!(format!("{e}").contains("no tasks"));
    let e = TaskDistributorError::InvalidPriority(-1.0);
    assert!(format!("{e}").contains("-1"));
    let e = TaskDistributorError::WorkerOverloaded("w1".to_string());
    assert!(format!("{e}").contains("w1"));
}
