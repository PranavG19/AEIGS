use std::time::Duration;

use crate::campaign_manager::{
    CampaignFinding, CampaignManager, CampaignState, ResourceBudget, StopReason,
};

#[test]
fn campaign_starts_in_created_state() {
    let cm = CampaignManager::new("test-001");
    assert_eq!(cm.state(), CampaignState::Created);
    assert_eq!(cm.campaign_id(), "test-001");
    assert_eq!(cm.total_requests(), 0);
}

#[test]
fn start_transitions_to_running() {
    let mut cm = CampaignManager::new("test-001");
    cm.start();
    assert_eq!(cm.state(), CampaignState::Running);
}

#[test]
fn pause_transitions_to_paused() {
    let mut cm = CampaignManager::new("test-001");
    cm.start();
    cm.pause();
    assert_eq!(cm.state(), CampaignState::Paused);
}

#[test]
fn resume_after_pause() {
    let mut cm = CampaignManager::new("test-001");
    cm.start();
    cm.pause();
    cm.start();
    assert_eq!(cm.state(), CampaignState::Running);
}

#[test]
fn abort_transitions_to_aborted() {
    let mut cm = CampaignManager::new("test-001");
    cm.start();
    cm.abort();
    assert_eq!(cm.state(), CampaignState::Aborted);
}

#[test]
fn record_execution_increments_requests() {
    let mut cm = CampaignManager::new("test-001");
    cm.start();
    cm.record_execution(false);
    cm.record_execution(true);
    cm.record_execution(false);
    assert_eq!(cm.total_requests(), 3);
    assert_eq!(cm.unique_coverage(), 1);
}

#[test]
fn record_execution_while_not_running_is_noop() {
    let mut cm = CampaignManager::new("test-001");
    cm.record_execution(true);
    assert_eq!(cm.total_requests(), 0);
}

#[test]
fn max_requests_budget_stops_campaign() {
    let budget = ResourceBudget::new().with_max_requests(5);
    let mut cm = CampaignManager::new("test-001").with_budget(budget);
    cm.start();
    for i in 0..4 {
        let result = cm.record_execution(i % 2 == 0);
        assert!(result.is_none());
    }
    let result = cm.record_execution(false);
    assert_eq!(result, Some(StopReason::MaxRequestsReached));
    assert_eq!(cm.state(), CampaignState::Completed);
}

#[test]
fn max_findings_budget_stops_campaign() {
    let budget = ResourceBudget::new().with_max_findings(2);
    let mut cm = CampaignManager::new("test-001").with_budget(budget);
    cm.start();
    cm.record_finding(make_finding("p1"));
    let result = cm.record_finding(make_finding("p2"));
    assert_eq!(result, Some(StopReason::MaxFindingsReached));
}

#[test]
fn coverage_plateau_stops_campaign() {
    let budget = ResourceBudget::new()
        .with_plateau_threshold(10)
        .with_max_requests(1_000_000);
    let mut cm = CampaignManager::new("test-001").with_budget(budget);
    cm.start();
    cm.record_execution(true);
    for _ in 0..9 {
        let result = cm.record_execution(false);
        assert!(result.is_none());
    }
    let result = cm.record_execution(false);
    assert_eq!(result, Some(StopReason::CoveragePlateau));
}

#[test]
fn plateau_detection() {
    let budget = ResourceBudget::new().with_plateau_threshold(5);
    let mut cm = CampaignManager::new("test-001").with_budget(budget);
    cm.start();
    cm.record_execution(true);
    assert!(!cm.is_plateaued());
    for _ in 0..5 {
        cm.record_execution(false);
    }
    assert!(cm.is_plateaued());
}

#[test]
fn corpus_management() {
    let mut cm = CampaignManager::new("test-001");
    cm.add_corpus_entry("payload_a");
    cm.add_corpus_entry("payload_b");
    assert_eq!(cm.corpus().len(), 2);
    assert_eq!(cm.corpus()[0], "payload_a");
}

#[test]
fn snapshot_captures_state() {
    let mut cm = CampaignManager::new("test-001");
    cm.start();
    cm.add_corpus_entry("p1");
    cm.record_execution(true);
    cm.take_snapshot();
    assert_eq!(cm.snapshots().len(), 1);
    assert_eq!(cm.snapshots()[0].corpus_size, 1);
    assert_eq!(cm.snapshots()[0].total_executions, 1);
    assert_eq!(cm.snapshots()[0].unique_coverage, 1);
}

#[test]
fn multiple_snapshots_track_evolution() {
    let mut cm = CampaignManager::new("test-001");
    cm.start();
    cm.add_corpus_entry("p1");
    cm.record_execution(true);
    cm.take_snapshot();

    cm.add_corpus_entry("p2");
    cm.add_corpus_entry("p3");
    cm.record_execution(true);
    cm.record_execution(false);
    cm.take_snapshot();

    assert_eq!(cm.snapshots().len(), 2);
    assert_eq!(cm.snapshots()[1].corpus_size, 3);
    assert_eq!(cm.snapshots()[1].total_executions, 3);
}

#[test]
fn stability_consistent_runs() {
    let mut cm = CampaignManager::new("test-001");
    cm.record_stability_run("payload_x", true);
    cm.record_stability_run("payload_x", true);
    cm.record_stability_run("payload_x", true);
    let result = cm.stability_results().get("payload_x").unwrap();
    assert!(result.is_stable);
    assert_eq!(result.consistent_runs, 3);
    assert_eq!(result.total_runs, 3);
}

#[test]
fn stability_inconsistent_runs() {
    let mut cm = CampaignManager::new("test-001");
    cm.record_stability_run("payload_y", true);
    cm.record_stability_run("payload_y", false);
    cm.record_stability_run("payload_y", false);
    let result = cm.stability_results().get("payload_y").unwrap();
    assert!(!result.is_stable);
}

#[test]
fn stability_needs_minimum_runs() {
    let mut cm = CampaignManager::new("test-001");
    cm.record_stability_run("payload_z", true);
    cm.record_stability_run("payload_z", true);
    let result = cm.stability_results().get("payload_z").unwrap();
    assert!(!result.is_stable);
}

#[test]
fn checkpoint_and_restore() {
    let mut cm = CampaignManager::new("test-001");
    cm.start();
    cm.add_corpus_entry("p1");
    cm.add_corpus_entry("p2");
    cm.record_execution(true);
    cm.record_execution(false);
    cm.record_finding(make_finding("f1"));
    cm.take_snapshot();

    let checkpoint = cm.checkpoint();
    assert_eq!(checkpoint.campaign_id, "test-001");
    assert_eq!(checkpoint.total_requests, 2);
    assert_eq!(checkpoint.total_findings, 1);
    assert_eq!(checkpoint.corpus_entries.len(), 2);
    assert_eq!(checkpoint.snapshots.len(), 1);

    let serialized = serde_json::to_string(&checkpoint).unwrap();
    let deserialized: crate::campaign_manager::CampaignCheckpoint =
        serde_json::from_str(&serialized).unwrap();

    let restored = CampaignManager::restore(deserialized);
    assert_eq!(restored.state(), CampaignState::Paused);
    assert_eq!(restored.total_requests(), 2);
    assert_eq!(restored.total_findings(), 1);
    assert_eq!(restored.corpus().len(), 2);
}

#[test]
fn findings_tracked() {
    let mut cm = CampaignManager::new("test-001");
    cm.start();
    cm.record_finding(make_finding("sqli_payload"));
    assert_eq!(cm.findings().len(), 1);
    assert_eq!(cm.findings()[0].payload, "sqli_payload");
    assert_eq!(cm.total_findings(), 1);
}

#[test]
fn budget_defaults() {
    let budget = ResourceBudget::new();
    assert_eq!(budget.max_requests, 100_000);
    assert_eq!(budget.max_findings, 1000);
    assert_eq!(budget.max_duration, Duration::from_secs(3600));
    assert_eq!(budget.plateau_threshold, 5000);
}

#[test]
fn executions_since_novel_tracks() {
    let mut cm = CampaignManager::new("test-001");
    cm.start();
    cm.record_execution(true);
    assert_eq!(cm.executions_since_novel(), 0);
    cm.record_execution(false);
    assert_eq!(cm.executions_since_novel(), 1);
    cm.record_execution(false);
    assert_eq!(cm.executions_since_novel(), 2);
    cm.record_execution(true);
    assert_eq!(cm.executions_since_novel(), 0);
}

#[test]
fn resource_budget_builder() {
    let budget = ResourceBudget::new()
        .with_max_duration(Duration::from_secs(60))
        .with_max_requests(500)
        .with_max_findings(10)
        .with_plateau_threshold(100);
    assert_eq!(budget.max_duration, Duration::from_secs(60));
    assert_eq!(budget.max_requests, 500);
    assert_eq!(budget.max_findings, 10);
    assert_eq!(budget.plateau_threshold, 100);
}

#[test]
fn resource_budget_default_trait() {
    let budget = ResourceBudget::default();
    assert_eq!(budget.max_requests, 100_000);
}

fn make_finding(payload: &str) -> CampaignFinding {
    CampaignFinding {
        payload: payload.to_string(),
        endpoint: "/api/test".to_string(),
        finding_type: "sqli".to_string(),
        confidence: 0.9,
        discovered_at_execution: 1,
    }
}
