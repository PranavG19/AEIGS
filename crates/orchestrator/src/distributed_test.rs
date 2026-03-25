use crate::distributed::{
    AssignmentStrategy, CoordinatorState, DistributedConfig, DistributedError, WorkAssignment,
    WorkerId, WorkerRole, WorkerState, WorkerStatus, create_assignments,
    default_distributed_config, describe_assignments, partition_endpoints,
};

fn worker_id(name: &str) -> WorkerId {
    WorkerId {
        id: name.to_string(),
    }
}

fn sample_endpoints(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("/api/endpoint-{i}")).collect()
}

#[test]
fn worker_id_display() {
    let wid = worker_id("alpha");
    assert_eq!(format!("{wid}"), "alpha");
}

#[test]
fn worker_id_equality() {
    assert_eq!(worker_id("a"), worker_id("a"));
    assert_ne!(worker_id("a"), worker_id("b"));
}

#[test]
fn worker_role_equality() {
    assert_eq!(WorkerRole::Coordinator, WorkerRole::Coordinator);
    assert_eq!(WorkerRole::FuzzWorker, WorkerRole::FuzzWorker);
    assert_eq!(WorkerRole::ReconWorker, WorkerRole::ReconWorker);
    assert_ne!(WorkerRole::Coordinator, WorkerRole::FuzzWorker);
}

#[test]
fn worker_state_equality() {
    assert_eq!(WorkerState::Idle, WorkerState::Idle);
    assert_eq!(WorkerState::Working, WorkerState::Working);
    assert_eq!(WorkerState::Paused, WorkerState::Paused);
    assert_eq!(WorkerState::Completed, WorkerState::Completed);
    assert_eq!(WorkerState::Failed, WorkerState::Failed);
    assert_ne!(WorkerState::Idle, WorkerState::Working);
}

#[test]
fn partition_round_robin_even_split() {
    let eps = sample_endpoints(6);
    let parts = partition_endpoints(&eps, 3, AssignmentStrategy::RoundRobin);
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0].len(), 2);
    assert_eq!(parts[1].len(), 2);
    assert_eq!(parts[2].len(), 2);
}

#[test]
fn partition_round_robin_odd_count() {
    let eps = sample_endpoints(7);
    let parts = partition_endpoints(&eps, 3, AssignmentStrategy::RoundRobin);
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0].len(), 3);
    assert_eq!(parts[1].len(), 2);
    assert_eq!(parts[2].len(), 2);
}

#[test]
fn partition_round_robin_single_worker_gets_all() {
    let eps = sample_endpoints(5);
    let parts = partition_endpoints(&eps, 1, AssignmentStrategy::RoundRobin);
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].len(), 5);
}

#[test]
fn partition_priority_based_sorts_by_length() {
    let eps = vec![
        "/a".to_string(),
        "/abc".to_string(),
        "/ab".to_string(),
        "/abcde".to_string(),
    ];
    let parts = partition_endpoints(&eps, 2, AssignmentStrategy::PriorityBased);
    assert_eq!(parts.len(), 2);
    assert!(parts[0][0].len() >= parts[1][0].len());
}

#[test]
fn partition_empty_endpoints() {
    let parts = partition_endpoints(&[], 3, AssignmentStrategy::RoundRobin);
    assert_eq!(parts.len(), 3);
    for p in &parts {
        assert!(p.is_empty());
    }
}

#[test]
fn partition_zero_workers() {
    let eps = sample_endpoints(3);
    let parts = partition_endpoints(&eps, 0, AssignmentStrategy::RoundRobin);
    assert!(parts.is_empty());
}

#[test]
fn partition_vulnerability_class_falls_back_to_round_robin() {
    let eps = sample_endpoints(4);
    let rr = partition_endpoints(&eps, 2, AssignmentStrategy::RoundRobin);
    let vc = partition_endpoints(&eps, 2, AssignmentStrategy::VulnerabilityClass);
    assert_eq!(rr, vc);
}

#[test]
fn create_assignments_matches_worker_count() {
    let eps = sample_endpoints(6);
    let workers = vec![worker_id("w1"), worker_id("w2"), worker_id("w3")];
    let assignments = create_assignments(&eps, &workers, AssignmentStrategy::RoundRobin);
    assert_eq!(assignments.len(), 3);
}

#[test]
fn create_assignments_assigns_all_endpoints() {
    let eps = sample_endpoints(7);
    let workers = vec![worker_id("w1"), worker_id("w2")];
    let assignments = create_assignments(&eps, &workers, AssignmentStrategy::RoundRobin);
    let total: usize = assignments.iter().map(|a| a.endpoints.len()).sum();
    assert_eq!(total, 7);
}

#[test]
fn create_assignments_sets_default_priority_range() {
    let eps = sample_endpoints(2);
    let workers = vec![worker_id("w1")];
    let assignments = create_assignments(&eps, &workers, AssignmentStrategy::RoundRobin);
    assert_eq!(assignments[0].priority_range, (0.0, 1.0));
}

#[test]
fn coordinator_state_new_starts_empty() {
    let config = default_distributed_config(3);
    let state = CoordinatorState::new(&config);
    assert!(state.workers.is_empty());
    assert!(state.assignments.is_empty());
    assert!(state.unassigned_endpoints.is_empty());
    assert_eq!(state.collected_findings, 0);
}

#[test]
fn register_worker_adds_to_state() {
    let config = default_distributed_config(2);
    let mut state = CoordinatorState::new(&config);
    state.register_worker(worker_id("w1"), WorkerRole::FuzzWorker);
    assert_eq!(state.workers.len(), 1);
    assert_eq!(state.workers[0].worker_id, worker_id("w1"));
    assert_eq!(state.workers[0].role, WorkerRole::FuzzWorker);
    assert_eq!(state.workers[0].state, WorkerState::Idle);
}

#[test]
fn assign_work_distributes_to_fuzz_workers_only() {
    let config = default_distributed_config(3);
    let mut state = CoordinatorState::new(&config);
    state.register_worker(worker_id("coord"), WorkerRole::Coordinator);
    state.register_worker(worker_id("fuzz1"), WorkerRole::FuzzWorker);
    state.register_worker(worker_id("fuzz2"), WorkerRole::FuzzWorker);

    let eps = sample_endpoints(4);
    let assignments = state
        .assign_work(&eps, AssignmentStrategy::RoundRobin)
        .unwrap();
    assert_eq!(assignments.len(), 2);
    assert_eq!(assignments[0].worker_id, worker_id("fuzz1"));
    assert_eq!(assignments[1].worker_id, worker_id("fuzz2"));
}

#[test]
fn assign_work_no_workers_errors() {
    let config = default_distributed_config(1);
    let mut state = CoordinatorState::new(&config);
    state.register_worker(worker_id("coord"), WorkerRole::Coordinator);

    let eps = sample_endpoints(3);
    let result = state.assign_work(&eps, AssignmentStrategy::RoundRobin);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert_eq!(msg, "no workers registered");
}

#[test]
fn assign_work_skips_recon_workers() {
    let config = default_distributed_config(3);
    let mut state = CoordinatorState::new(&config);
    state.register_worker(worker_id("recon"), WorkerRole::ReconWorker);
    state.register_worker(worker_id("fuzz1"), WorkerRole::FuzzWorker);

    let eps = sample_endpoints(4);
    let assignments = state
        .assign_work(&eps, AssignmentStrategy::RoundRobin)
        .unwrap();
    assert_eq!(assignments.len(), 1);
    assert_eq!(assignments[0].worker_id, worker_id("fuzz1"));
    assert_eq!(assignments[0].endpoints.len(), 4);
}

#[test]
fn update_worker_status_changes_state() {
    let config = default_distributed_config(1);
    let mut state = CoordinatorState::new(&config);
    state.register_worker(worker_id("w1"), WorkerRole::FuzzWorker);

    state.update_worker_status(&worker_id("w1"), WorkerState::Working, 5, 10, 2);
    assert_eq!(state.workers[0].state, WorkerState::Working);
    assert_eq!(state.workers[0].targets_completed, 5);
    assert_eq!(state.workers[0].targets_remaining, 10);
    assert_eq!(state.workers[0].findings_count, 2);
}

#[test]
fn update_worker_status_unknown_worker_is_noop() {
    let config = default_distributed_config(1);
    let mut state = CoordinatorState::new(&config);
    state.register_worker(worker_id("w1"), WorkerRole::FuzzWorker);
    state.update_worker_status(&worker_id("unknown"), WorkerState::Failed, 0, 0, 0);
    assert_eq!(state.workers[0].state, WorkerState::Idle);
}

#[test]
fn detect_failed_workers_finds_timed_out() {
    let config = default_distributed_config(2);
    let mut state = CoordinatorState::new(&config);
    state.register_worker(worker_id("w1"), WorkerRole::FuzzWorker);
    state.register_worker(worker_id("w2"), WorkerRole::FuzzWorker);

    state.workers[0].last_heartbeat_ms = 1000;
    state.workers[0].state = WorkerState::Working;
    state.workers[1].last_heartbeat_ms = 50000;
    state.workers[1].state = WorkerState::Working;

    let failed = state.detect_failed_workers(60000, 30000);
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0], worker_id("w1"));
}

#[test]
fn detect_failed_workers_all_healthy_returns_empty() {
    let config = default_distributed_config(2);
    let mut state = CoordinatorState::new(&config);
    state.register_worker(worker_id("w1"), WorkerRole::FuzzWorker);
    state.register_worker(worker_id("w2"), WorkerRole::FuzzWorker);
    state.workers[0].state = WorkerState::Working;
    state.workers[1].state = WorkerState::Working;

    let now = crate::util::timestamp_ms();
    let failed = state.detect_failed_workers(now, 30000);
    assert!(failed.is_empty());
}

#[test]
fn detect_failed_workers_skips_completed_and_failed() {
    let config = default_distributed_config(2);
    let mut state = CoordinatorState::new(&config);
    state.register_worker(worker_id("w1"), WorkerRole::FuzzWorker);
    state.register_worker(worker_id("w2"), WorkerRole::FuzzWorker);
    state.workers[0].last_heartbeat_ms = 0;
    state.workers[0].state = WorkerState::Completed;
    state.workers[1].last_heartbeat_ms = 0;
    state.workers[1].state = WorkerState::Failed;

    let failed = state.detect_failed_workers(100000, 5000);
    assert!(failed.is_empty());
}

#[test]
fn rebalance_redistributes_work() {
    let config = default_distributed_config(3);
    let mut state = CoordinatorState::new(&config);
    state.register_worker(worker_id("w1"), WorkerRole::FuzzWorker);
    state.register_worker(worker_id("w2"), WorkerRole::FuzzWorker);

    let eps = sample_endpoints(4);
    state
        .assign_work(&eps, AssignmentStrategy::RoundRobin)
        .unwrap();
    state.workers[0].state = WorkerState::Working;
    state.workers[1].state = WorkerState::Failed;

    let new_assignments = state.rebalance(&worker_id("w2")).unwrap();
    assert_eq!(new_assignments.len(), 1);
    assert_eq!(new_assignments[0].worker_id, worker_id("w1"));
}

#[test]
fn rebalance_returns_none_when_no_active_workers() {
    let config = default_distributed_config(2);
    let mut state = CoordinatorState::new(&config);
    state.register_worker(worker_id("w1"), WorkerRole::FuzzWorker);
    state.register_worker(worker_id("w2"), WorkerRole::FuzzWorker);

    let eps = sample_endpoints(4);
    state
        .assign_work(&eps, AssignmentStrategy::RoundRobin)
        .unwrap();
    state.workers[0].state = WorkerState::Failed;
    state.workers[1].state = WorkerState::Failed;

    let result = state.rebalance(&worker_id("w1"));
    assert!(result.is_none());
}

#[test]
fn all_complete_true_when_all_done() {
    let config = default_distributed_config(2);
    let mut state = CoordinatorState::new(&config);
    state.register_worker(worker_id("w1"), WorkerRole::FuzzWorker);
    state.register_worker(worker_id("w2"), WorkerRole::FuzzWorker);
    state.workers[0].state = WorkerState::Completed;
    state.workers[1].state = WorkerState::Failed;
    assert!(state.all_complete());
}

#[test]
fn all_complete_false_when_working() {
    let config = default_distributed_config(2);
    let mut state = CoordinatorState::new(&config);
    state.register_worker(worker_id("w1"), WorkerRole::FuzzWorker);
    state.register_worker(worker_id("w2"), WorkerRole::FuzzWorker);
    state.workers[0].state = WorkerState::Completed;
    state.workers[1].state = WorkerState::Working;
    assert!(!state.all_complete());
}

#[test]
fn all_complete_true_when_empty() {
    let config = default_distributed_config(0);
    let state = CoordinatorState::new(&config);
    assert!(state.all_complete());
}

#[test]
fn active_worker_count_counts_correctly() {
    let config = default_distributed_config(4);
    let mut state = CoordinatorState::new(&config);
    state.register_worker(worker_id("w1"), WorkerRole::FuzzWorker);
    state.register_worker(worker_id("w2"), WorkerRole::FuzzWorker);
    state.register_worker(worker_id("w3"), WorkerRole::FuzzWorker);
    state.register_worker(worker_id("w4"), WorkerRole::FuzzWorker);
    state.workers[0].state = WorkerState::Working;
    state.workers[1].state = WorkerState::Idle;
    state.workers[2].state = WorkerState::Failed;
    state.workers[3].state = WorkerState::Completed;
    assert_eq!(state.active_worker_count(), 2);
}

#[test]
fn total_findings_sums_all_workers() {
    let config = default_distributed_config(3);
    let mut state = CoordinatorState::new(&config);
    state.register_worker(worker_id("w1"), WorkerRole::FuzzWorker);
    state.register_worker(worker_id("w2"), WorkerRole::FuzzWorker);
    state.register_worker(worker_id("w3"), WorkerRole::FuzzWorker);
    state.workers[0].findings_count = 3;
    state.workers[1].findings_count = 7;
    state.workers[2].findings_count = 2;
    assert_eq!(state.total_findings(), 12);
}

#[test]
fn default_distributed_config_has_correct_defaults() {
    let config = default_distributed_config(4);
    assert_eq!(config.worker_count, 4);
    assert_eq!(config.assignment_strategy, AssignmentStrategy::RoundRobin);
    assert_eq!(config.heartbeat_interval_ms, 5000);
    assert_eq!(config.worker_timeout_ms, 30000);
    assert!(config.rebalance_on_failure);
}

#[test]
fn describe_assignments_produces_readable_output() {
    let assignments = vec![
        WorkAssignment {
            worker_id: worker_id("w1"),
            endpoints: sample_endpoints(3),
            vulnerability_classes: Vec::new(),
            priority_range: (0.0, 1.0),
        },
        WorkAssignment {
            worker_id: worker_id("w2"),
            endpoints: sample_endpoints(2),
            vulnerability_classes: Vec::new(),
            priority_range: (0.0, 1.0),
        },
    ];
    let desc = describe_assignments(&assignments);
    assert!(desc.contains("2 worker(s) assigned:"));
    assert!(desc.contains("w1 -> 3 endpoint(s)"));
    assert!(desc.contains("w2 -> 2 endpoint(s)"));
}

#[test]
fn distributed_error_display_no_workers() {
    let err = DistributedError::NoWorkers;
    assert_eq!(format!("{err}"), "no workers registered");
}

#[test]
fn distributed_error_display_worker_not_found() {
    let err = DistributedError::WorkerNotFound("ghost".to_string());
    assert_eq!(format!("{err}"), "worker not found: ghost");
}

#[test]
fn distributed_error_display_all_workers_failed() {
    let err = DistributedError::AllWorkersFailed;
    assert_eq!(format!("{err}"), "all workers have failed");
}

#[test]
fn distributed_error_display_invalid_config() {
    let err = DistributedError::InvalidConfig("bad count".to_string());
    assert_eq!(format!("{err}"), "invalid distributed config: bad count");
}

#[test]
fn distributed_error_is_std_error() {
    let err = DistributedError::NoWorkers;
    let _: &dyn std::error::Error = &err;
}

#[test]
fn assignment_strategy_equality() {
    assert_eq!(
        AssignmentStrategy::RoundRobin,
        AssignmentStrategy::RoundRobin
    );
    assert_eq!(
        AssignmentStrategy::PriorityBased,
        AssignmentStrategy::PriorityBased
    );
    assert_eq!(
        AssignmentStrategy::VulnerabilityClass,
        AssignmentStrategy::VulnerabilityClass
    );
    assert_ne!(
        AssignmentStrategy::RoundRobin,
        AssignmentStrategy::PriorityBased
    );
}

#[test]
fn distributed_config_serialization_roundtrip() {
    let config = default_distributed_config(3);
    let json = serde_json::to_string(&config).unwrap();
    let deserialized: DistributedConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.worker_count, 3);
    assert_eq!(
        deserialized.assignment_strategy,
        AssignmentStrategy::RoundRobin
    );
    assert_eq!(deserialized.heartbeat_interval_ms, 5000);
    assert_eq!(deserialized.worker_timeout_ms, 30000);
    assert!(deserialized.rebalance_on_failure);
}

#[test]
fn worker_id_serialization_roundtrip() {
    let wid = worker_id("test-worker-42");
    let json = serde_json::to_string(&wid).unwrap();
    let deserialized: WorkerId = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, wid);
}

#[test]
fn work_assignment_serialization_roundtrip() {
    let assignment = WorkAssignment {
        worker_id: worker_id("w1"),
        endpoints: sample_endpoints(2),
        vulnerability_classes: vec!["SqlInjection".to_string()],
        priority_range: (0.5, 1.0),
    };
    let json = serde_json::to_string(&assignment).unwrap();
    let deserialized: WorkAssignment = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.worker_id, worker_id("w1"));
    assert_eq!(deserialized.endpoints.len(), 2);
    assert_eq!(deserialized.vulnerability_classes, vec!["SqlInjection"]);
    assert_eq!(deserialized.priority_range, (0.5, 1.0));
}

#[test]
fn worker_status_serialization_roundtrip() {
    let status = WorkerStatus {
        worker_id: worker_id("w1"),
        role: WorkerRole::FuzzWorker,
        state: WorkerState::Working,
        targets_completed: 10,
        targets_remaining: 5,
        findings_count: 3,
        last_heartbeat_ms: 1700000000000,
    };
    let json = serde_json::to_string(&status).unwrap();
    let deserialized: WorkerStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.worker_id, worker_id("w1"));
    assert_eq!(deserialized.role, WorkerRole::FuzzWorker);
    assert_eq!(deserialized.state, WorkerState::Working);
    assert_eq!(deserialized.targets_completed, 10);
    assert_eq!(deserialized.targets_remaining, 5);
    assert_eq!(deserialized.findings_count, 3);
}

#[test]
fn coordinator_state_debug_format() {
    let config = default_distributed_config(1);
    let state = CoordinatorState::new(&config);
    let dbg = format!("{state:?}");
    assert!(dbg.contains("CoordinatorState"));
}

#[test]
fn partition_more_workers_than_endpoints() {
    let eps = sample_endpoints(2);
    let parts = partition_endpoints(&eps, 5, AssignmentStrategy::RoundRobin);
    assert_eq!(parts.len(), 5);
    let total: usize = parts.iter().map(|p| p.len()).sum();
    assert_eq!(total, 2);
    let non_empty = parts.iter().filter(|p| !p.is_empty()).count();
    assert_eq!(non_empty, 2);
}

#[test]
fn describe_assignments_empty_list() {
    let desc = describe_assignments(&[]);
    assert!(desc.contains("0 worker(s) assigned:"));
}

#[test]
fn worker_id_hash_works_in_collections() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(worker_id("a"));
    set.insert(worker_id("b"));
    set.insert(worker_id("a"));
    assert_eq!(set.len(), 2);
}

#[test]
fn partition_single_endpoint_single_worker() {
    let eps = sample_endpoints(1);
    let parts = partition_endpoints(&eps, 1, AssignmentStrategy::RoundRobin);
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].len(), 1);
}

#[test]
fn partition_zero_endpoints() {
    let eps: Vec<String> = Vec::new();
    let parts = partition_endpoints(&eps, 3, AssignmentStrategy::RoundRobin);
    assert_eq!(parts.len(), 3);
    for part in &parts {
        assert!(part.is_empty());
    }
}

#[test]
fn worker_id_empty_string() {
    let wid = worker_id("");
    assert_eq!(format!("{wid}"), "");
    assert_eq!(wid, worker_id(""));
}

#[test]
fn worker_id_unicode() {
    let wid = WorkerId {
        id: "ワーカー-1".to_string(),
    };
    assert_eq!(format!("{wid}"), "ワーカー-1");
}

#[test]
fn coordinator_state_new_has_zero_active_workers() {
    let config = default_distributed_config(1);
    let state = CoordinatorState::new(&config);
    assert_eq!(state.active_worker_count(), 0);
}

#[test]
fn distributed_config_roundtrip_json() {
    let config = default_distributed_config(3);
    let json = serde_json::to_string(&config).unwrap();
    let deserialized: DistributedConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.worker_count, config.worker_count);
}
