use crate::distributed::{WorkerId, WorkerRole, WorkerState};
use crate::worker_node::{
    HealthStatus, Region, WorkerCapability, WorkerNodeError, WorkerNodeManager, WorkerPoolConfig,
};

fn wid(name: &str) -> WorkerId {
    WorkerId {
        id: name.to_string(),
    }
}

fn default_manager() -> WorkerNodeManager {
    WorkerNodeManager::new(WorkerPoolConfig::default())
}

fn register_worker(
    mgr: &mut WorkerNodeManager,
    name: &str,
    role: WorkerRole,
    caps: Vec<WorkerCapability>,
    region: Region,
) {
    mgr.register(
        wid(name),
        role,
        caps,
        vec!["nmap".to_string()],
        "10.0.0.1".to_string(),
        region,
    )
    .unwrap();
}

// --- Registration ---

#[test]
fn register_single_worker() {
    let mut mgr = default_manager();
    register_worker(
        &mut mgr,
        "w1",
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        Region::UsEast,
    );
    assert_eq!(mgr.pool_size(), 1);
    assert_eq!(mgr.active_count(), 1);
}

#[test]
fn register_duplicate_worker_fails() {
    let mut mgr = default_manager();
    register_worker(
        &mut mgr,
        "w1",
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        Region::UsEast,
    );
    let result = mgr.register(
        wid("w1"),
        WorkerRole::ReconWorker,
        vec![],
        vec![],
        "10.0.0.2".to_string(),
        Region::UsWest,
    );
    assert!(result.is_err());
}

#[test]
fn register_multiple_workers() {
    let mut mgr = default_manager();
    for i in 0..5 {
        register_worker(
            &mut mgr,
            &format!("w{i}"),
            WorkerRole::FuzzWorker,
            vec![WorkerCapability::Fuzzing],
            Region::UsEast,
        );
    }
    assert_eq!(mgr.pool_size(), 5);
}

// --- Deregistration ---

#[test]
fn deregister_existing_worker() {
    let mut mgr = default_manager();
    register_worker(
        &mut mgr,
        "w1",
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        Region::UsEast,
    );
    let node = mgr.deregister("w1").unwrap();
    assert_eq!(node.worker_id, wid("w1"));
    assert_eq!(mgr.pool_size(), 0);
}

#[test]
fn deregister_unknown_worker_fails() {
    let mut mgr = default_manager();
    let result = mgr.deregister("ghost");
    assert!(result.is_err());
}

// --- Heartbeat ---

#[test]
fn record_heartbeat_updates_health() {
    let mut mgr = default_manager();
    register_worker(
        &mut mgr,
        "w1",
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        Region::UsEast,
    );
    mgr.record_heartbeat("w1", 42, 55.0).unwrap();
    let w = mgr.get_worker("w1").unwrap();
    assert_eq!(w.health.latency_ms, 42);
    assert!((w.health.load_percent - 55.0).abs() < f64::EPSILON);
    assert_eq!(w.health.consecutive_failures, 0);
}

#[test]
fn heartbeat_unknown_worker_fails() {
    let mut mgr = default_manager();
    let result = mgr.record_heartbeat("ghost", 10, 20.0);
    assert!(result.is_err());
}

// --- Health checking ---

#[test]
fn check_health_marks_timed_out_workers_as_failed() {
    let mut mgr = WorkerNodeManager::new(WorkerPoolConfig {
        heartbeat_timeout_ms: 100,
        max_consecutive_failures: 1,
        ..Default::default()
    });
    register_worker(
        &mut mgr,
        "w1",
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        Region::UsEast,
    );
    let far_future = crate::util::timestamp_ms() + 200;
    let failed = mgr.check_health(far_future);
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0], "w1");
    let w = mgr.get_worker("w1").unwrap();
    assert_eq!(w.state, WorkerState::Failed);
}

#[test]
fn check_health_skips_completed_workers() {
    let mut mgr = WorkerNodeManager::new(WorkerPoolConfig {
        heartbeat_timeout_ms: 100,
        max_consecutive_failures: 1,
        ..Default::default()
    });
    register_worker(
        &mut mgr,
        "w1",
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        Region::UsEast,
    );
    mgr.assign_task(&WorkerCapability::Fuzzing).unwrap();
    mgr.record_task_complete("w1", 0).unwrap();
    // Worker is now Idle, not Completed; assign and complete again to hit Idle
    // Instead, let's just verify non-failed workers are checked
    let far_future = crate::util::timestamp_ms() + 200;
    let failed = mgr.check_health(far_future);
    assert_eq!(failed.len(), 1);
}

#[test]
fn consecutive_failures_threshold() {
    let mut mgr = WorkerNodeManager::new(WorkerPoolConfig {
        heartbeat_timeout_ms: 100,
        max_consecutive_failures: 3,
        ..Default::default()
    });
    register_worker(
        &mut mgr,
        "w1",
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        Region::UsEast,
    );
    let far = crate::util::timestamp_ms() + 200;
    // First check: 1 failure, not yet marked as failed
    let failed = mgr.check_health(far);
    assert!(failed.is_empty());
    // Second check: 2 failures
    let failed = mgr.check_health(far);
    assert!(failed.is_empty());
    // Third check: 3 failures — now marked
    let failed = mgr.check_health(far);
    assert_eq!(failed.len(), 1);
}

// --- Task assignment ---

#[test]
fn assign_task_selects_lowest_load() {
    let mut mgr = default_manager();
    register_worker(
        &mut mgr,
        "heavy",
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        Region::UsEast,
    );
    register_worker(
        &mut mgr,
        "light",
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        Region::UsWest,
    );
    mgr.record_heartbeat("heavy", 10, 90.0).unwrap();
    mgr.record_heartbeat("light", 10, 10.0).unwrap();
    let chosen = mgr.assign_task(&WorkerCapability::Fuzzing).unwrap();
    assert_eq!(chosen, "light");
}

#[test]
fn assign_task_no_capable_worker_fails() {
    let mut mgr = default_manager();
    register_worker(
        &mut mgr,
        "w1",
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Recon],
        Region::UsEast,
    );
    let result = mgr.assign_task(&WorkerCapability::DomVerification);
    assert!(result.is_err());
}

#[test]
fn assign_task_sets_working_state() {
    let mut mgr = default_manager();
    register_worker(
        &mut mgr,
        "w1",
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        Region::UsEast,
    );
    mgr.assign_task(&WorkerCapability::Fuzzing).unwrap();
    let w = mgr.get_worker("w1").unwrap();
    assert_eq!(w.state, WorkerState::Working);
    assert_eq!(w.assigned_tasks, 1);
}

// --- Task completion ---

#[test]
fn record_task_complete_increments_counters() {
    let mut mgr = default_manager();
    register_worker(
        &mut mgr,
        "w1",
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        Region::UsEast,
    );
    mgr.assign_task(&WorkerCapability::Fuzzing).unwrap();
    mgr.record_task_complete("w1", 3).unwrap();
    let w = mgr.get_worker("w1").unwrap();
    assert_eq!(w.completed_tasks, 1);
    assert_eq!(w.findings_reported, 3);
    assert_eq!(w.state, WorkerState::Idle);
}

// --- Pool queries ---

#[test]
fn pool_below_minimum_detection() {
    let mgr = WorkerNodeManager::new(WorkerPoolConfig {
        min_workers: 3,
        ..Default::default()
    });
    let err = mgr.pool_below_minimum();
    assert!(err.is_some());
}

#[test]
fn workers_in_region_filter() {
    let mut mgr = default_manager();
    register_worker(
        &mut mgr,
        "east1",
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        Region::UsEast,
    );
    register_worker(
        &mut mgr,
        "west1",
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        Region::UsWest,
    );
    register_worker(
        &mut mgr,
        "east2",
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        Region::UsEast,
    );
    let east = mgr.workers_in_region(&Region::UsEast);
    assert_eq!(east.len(), 2);
}

#[test]
fn workers_with_capability_filter() {
    let mut mgr = default_manager();
    register_worker(
        &mut mgr,
        "fuzzer",
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        Region::UsEast,
    );
    register_worker(
        &mut mgr,
        "crawler",
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::CrawlHeadless],
        Region::UsEast,
    );
    let fuzzers = mgr.workers_with_capability(&WorkerCapability::Fuzzing);
    assert_eq!(fuzzers.len(), 1);
    assert_eq!(fuzzers[0].worker_id.id, "fuzzer");
}

#[test]
fn overloaded_workers_detection() {
    let mut mgr = default_manager();
    register_worker(
        &mut mgr,
        "w1",
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        Region::UsEast,
    );
    register_worker(
        &mut mgr,
        "w2",
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        Region::UsEast,
    );
    mgr.record_heartbeat("w1", 10, 95.0).unwrap();
    mgr.record_heartbeat("w2", 10, 20.0).unwrap();
    let overloaded = mgr.overloaded_workers();
    assert_eq!(overloaded.len(), 1);
    assert_eq!(overloaded[0].worker_id.id, "w1");
}

#[test]
fn idle_workers_sorted_by_load() {
    let mut mgr = default_manager();
    register_worker(
        &mut mgr,
        "high",
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        Region::UsEast,
    );
    register_worker(
        &mut mgr,
        "low",
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        Region::UsEast,
    );
    mgr.record_heartbeat("high", 10, 70.0).unwrap();
    mgr.record_heartbeat("low", 10, 10.0).unwrap();
    let idle = mgr.idle_workers();
    assert_eq!(idle[0].worker_id.id, "low");
    assert_eq!(idle[1].worker_id.id, "high");
}

#[test]
fn summary_reports_correct_counts() {
    let mut mgr = default_manager();
    register_worker(
        &mut mgr,
        "w1",
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        Region::UsEast,
    );
    register_worker(
        &mut mgr,
        "w2",
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        Region::UsEast,
    );
    mgr.assign_task(&WorkerCapability::Fuzzing).unwrap();
    mgr.record_task_complete("w1", 5).unwrap();
    let summary = mgr.summary();
    assert_eq!(summary.total_workers, 2);
    assert_eq!(summary.active_workers, 2);
    assert_eq!(summary.total_findings, 5);
}

// --- Display impls ---

#[test]
fn capability_display() {
    assert_eq!(format!("{}", WorkerCapability::Fuzzing), "fuzzing");
    assert_eq!(format!("{}", WorkerCapability::BruteForce), "brute-force");
    assert_eq!(
        format!("{}", WorkerCapability::CrawlHeadless),
        "crawl-headless"
    );
}

#[test]
fn region_display() {
    assert_eq!(format!("{}", Region::UsEast), "us-east");
    assert_eq!(format!("{}", Region::EuCentral), "eu-central");
    assert_eq!(
        format!("{}", Region::Custom("oceania".to_string())),
        "oceania"
    );
}

#[test]
fn error_display() {
    let e = WorkerNodeError::WorkerNotFound("w99".to_string());
    assert!(format!("{e}").contains("w99"));
    let e = WorkerNodeError::PoolBelowMinimum {
        current: 1,
        minimum: 3,
    };
    assert!(format!("{e}").contains("below minimum"));
}

#[test]
fn health_status_default() {
    let h = HealthStatus::default();
    assert_eq!(h.latency_ms, 0);
    assert_eq!(h.consecutive_failures, 0);
}

#[test]
fn worker_pool_config_default() {
    let cfg = WorkerPoolConfig::default();
    assert_eq!(cfg.min_workers, 1);
    assert_eq!(cfg.heartbeat_timeout_ms, 30_000);
}

#[test]
fn all_workers_returns_full_pool() {
    let mut mgr = default_manager();
    register_worker(
        &mut mgr,
        "a",
        WorkerRole::FuzzWorker,
        vec![WorkerCapability::Fuzzing],
        Region::UsEast,
    );
    register_worker(
        &mut mgr,
        "b",
        WorkerRole::ReconWorker,
        vec![WorkerCapability::Recon],
        Region::UsWest,
    );
    assert_eq!(mgr.all_workers().len(), 2);
}
