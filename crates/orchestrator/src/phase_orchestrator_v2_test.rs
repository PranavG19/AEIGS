use super::phase_orchestrator_v2::*;
use std::time::Duration;

fn make_outcome(phase: PhaseId, status: PhaseStatus) -> PhaseOutcome {
    PhaseOutcome {
        phase,
        status,
        duration: Duration::from_millis(100),
        operations_applied: 5,
        findings_count: 0,
        endpoints_discovered: 0,
    }
}

#[test]
fn initial_ready_phases_are_recon_and_crawl() {
    let orch = PhaseOrchestratorV2::new();
    let ready = orch.ready_phases();
    assert!(ready.contains(&PhaseId::Recon));
    assert!(ready.contains(&PhaseId::Crawl));
    assert_eq!(ready.len(), 2);
}

#[test]
fn recon_and_crawl_are_parallel() {
    let orch = PhaseOrchestratorV2::new();
    let groups = orch.parallel_groups();
    assert!(!groups.is_empty());
    let first = &groups[0];
    assert!(first.contains(&PhaseId::Recon));
    assert!(first.contains(&PhaseId::Crawl));
}

#[test]
fn fingerprint_needs_crawl() {
    let mut orch = PhaseOrchestratorV2::new();
    orch.record_outcome(make_outcome(PhaseId::Recon, PhaseStatus::Completed));
    let ready = orch.ready_phases();
    assert!(
        !ready.contains(&PhaseId::Fingerprint),
        "fingerprint should wait for crawl"
    );

    orch.record_outcome(make_outcome(PhaseId::Crawl, PhaseStatus::Completed));
    let ready = orch.ready_phases();
    assert!(ready.contains(&PhaseId::Fingerprint));
}

#[test]
fn skip_phase_removes_from_pipeline() {
    let mut orch = PhaseOrchestratorV2::new();
    orch.skip_phase(PhaseId::Enumerate);

    orch.record_outcome(make_outcome(PhaseId::Recon, PhaseStatus::Completed));
    orch.record_outcome(make_outcome(PhaseId::Crawl, PhaseStatus::Completed));
    orch.record_outcome(make_outcome(PhaseId::Fingerprint, PhaseStatus::Completed));

    let ready = orch.ready_phases();
    assert!(!ready.contains(&PhaseId::Enumerate));
    assert!(
        ready.contains(&PhaseId::Fuzz),
        "fuzz should be ready when enumerate is skipped"
    );
}

#[test]
fn full_pipeline_completes() {
    let mut orch = PhaseOrchestratorV2::new();
    let phases = [
        PhaseId::Recon,
        PhaseId::Crawl,
        PhaseId::Fingerprint,
        PhaseId::Enumerate,
        PhaseId::Fuzz,
        PhaseId::Exploit,
        PhaseId::ChainSynthesis,
        PhaseId::Report,
    ];
    for phase in phases {
        orch.record_outcome(make_outcome(phase, PhaseStatus::Completed));
    }
    assert!(orch.is_complete());
    assert_eq!(orch.completed_phases().len(), 8);
}

#[test]
fn not_complete_when_phases_pending() {
    let mut orch = PhaseOrchestratorV2::new();
    orch.record_outcome(make_outcome(PhaseId::Recon, PhaseStatus::Completed));
    assert!(!orch.is_complete());
}

#[test]
fn event_driven_endpoint_discovery() {
    let mut orch = PhaseOrchestratorV2::new();
    orch.on_endpoint_discovered("/api/users".into(), "GET".into());
    orch.on_endpoint_discovered("/api/admin".into(), "POST".into());

    let pending = orch.drain_pending_endpoints();
    assert_eq!(pending.len(), 2);
    assert!(pending.contains(&"/api/users".to_string()));
    assert!(pending.contains(&"/api/admin".to_string()));

    assert!(
        orch.drain_pending_endpoints().is_empty(),
        "drain should clear"
    );
}

#[test]
fn events_are_recorded() {
    let mut orch = PhaseOrchestratorV2::new();
    orch.record_outcome(make_outcome(PhaseId::Recon, PhaseStatus::Completed));
    orch.on_endpoint_discovered("/test".into(), "GET".into());

    assert!(orch.events().len() >= 2);
}

#[test]
fn sequential_order_returns_all_non_skipped() {
    let mut orch = PhaseOrchestratorV2::new();
    orch.skip_phase(PhaseId::Exploit);
    let order = orch.sequential_order();
    assert!(!order.contains(&PhaseId::Exploit));
    assert!(order.contains(&PhaseId::Recon));
    assert!(order.contains(&PhaseId::Report));
}

#[test]
fn phase_display() {
    assert_eq!(format!("{}", PhaseId::Recon), "recon");
    assert_eq!(format!("{}", PhaseId::ChainSynthesis), "chain-synthesis");
    assert_eq!(format!("{}", PhaseId::Report), "report");
}

#[test]
fn failed_phase_blocks_dependents() {
    let mut orch = PhaseOrchestratorV2::new();
    orch.record_outcome(make_outcome(PhaseId::Recon, PhaseStatus::Completed));
    orch.record_outcome(make_outcome(PhaseId::Crawl, PhaseStatus::Failed));

    let ready = orch.ready_phases();
    assert!(
        !ready.contains(&PhaseId::Fingerprint),
        "fingerprint should not be ready when crawl failed"
    );
}

#[test]
fn max_fuzz_iterations_builder() {
    let orch = PhaseOrchestratorV2::new().with_max_fuzz_iterations(10);
    assert_eq!(orch.max_fuzz_iterations(), 10);
}
