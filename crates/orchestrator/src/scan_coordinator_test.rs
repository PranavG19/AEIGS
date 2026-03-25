use crate::scan_coordinator::{
    BroadcastMessage, CoordinatorError, PhaseBarrier, ScanCoordinator, ScanPhase,
};
use aegis_protocol::finding::{
    Confidence, EvidenceLevel, FindingConfidence, FindingData, VulnerabilityClass,
};
use aegis_protocol::operation::ModuleIdentifier;

fn sample_finding() -> FindingData {
    FindingData {
        id: 1,
        linked_node_ids: vec![10],
        vulnerability_class: VulnerabilityClass::SqlInjection,
        severity: 7.5,
        confidence: FindingConfidence::from_simple(Confidence::new(0.9).unwrap()),
        certificate: Vec::new(),
        provenance_module: ModuleIdentifier::Fuzzing,
        timestamp_unix_ms: crate::util::timestamp_ms(),
        evidence_level: EvidenceLevel::Confirmed,
        stable_id: None,
    }
}

// --- PhaseBarrier ---

#[test]
fn barrier_tracks_arrivals() {
    let mut barrier = PhaseBarrier::new(ScanPhase::Recon, &["w1".to_string(), "w2".to_string()]);
    assert!(!barrier.is_complete());
    assert!(!barrier.arrive("w1"));
    assert!(barrier.arrive("w2"));
    assert!(barrier.is_complete());
}

#[test]
fn barrier_pending_workers() {
    let barrier = PhaseBarrier::new(
        ScanPhase::Fuzz,
        &["w1".to_string(), "w2".to_string(), "w3".to_string()],
    );
    let pending = barrier.pending_workers();
    assert_eq!(pending.len(), 3);
}

#[test]
fn barrier_single_worker() {
    let mut barrier = PhaseBarrier::new(ScanPhase::Recon, &["solo".to_string()]);
    assert!(barrier.arrive("solo"));
}

// --- ScanCoordinator creation ---

#[test]
fn coordinator_starts_at_recon() {
    let coord = ScanCoordinator::new();
    assert_eq!(coord.current_phase(), ScanPhase::Recon);
}

#[test]
fn coordinator_registers_workers() {
    let mut coord = ScanCoordinator::new();
    coord.register_worker("w1");
    coord.register_worker("w2");
    assert_eq!(coord.worker_count(), 2);
}

// --- Worker removal ---

#[test]
fn remove_worker_succeeds() {
    let mut coord = ScanCoordinator::new();
    coord.register_worker("w1");
    let result = coord.remove_worker("w1");
    assert!(result.is_ok());
    assert_eq!(coord.worker_count(), 0);
}

#[test]
fn remove_unknown_worker_fails() {
    let mut coord = ScanCoordinator::new();
    let result = coord.remove_worker("ghost");
    assert!(result.is_err());
}

#[test]
fn remove_worker_updates_barriers() {
    let mut coord = ScanCoordinator::new();
    coord.register_worker("w1");
    coord.register_worker("w2");
    coord.create_barrier().unwrap();
    coord.remove_worker("w1").unwrap();
    // Only w2 needs to arrive now
    let done = coord.worker_phase_complete("w2").unwrap();
    assert!(done);
}

// --- Barrier synchronization ---

#[test]
fn create_barrier_for_current_phase() {
    let mut coord = ScanCoordinator::new();
    coord.register_worker("w1");
    coord.register_worker("w2");
    let result = coord.create_barrier();
    assert!(result.is_ok());
}

#[test]
fn create_barrier_no_workers_fails() {
    let mut coord = ScanCoordinator::new();
    let result = coord.create_barrier();
    assert!(result.is_err());
}

#[test]
fn worker_phase_complete_tracks_progress() {
    let mut coord = ScanCoordinator::new();
    coord.register_worker("w1");
    coord.register_worker("w2");
    coord.create_barrier().unwrap();
    let done = coord.worker_phase_complete("w1").unwrap();
    assert!(!done);
    let done = coord.worker_phase_complete("w2").unwrap();
    assert!(done);
}

#[test]
fn worker_phase_complete_unknown_worker_fails() {
    let mut coord = ScanCoordinator::new();
    coord.register_worker("w1");
    coord.create_barrier().unwrap();
    let result = coord.worker_phase_complete("ghost");
    assert!(result.is_err());
}

// --- Phase transitions ---

#[test]
fn advance_phase_recon_to_crawl() {
    let mut coord = ScanCoordinator::new();
    coord.register_worker("w1");
    coord.create_barrier().unwrap();
    coord.worker_phase_complete("w1").unwrap();
    let result = coord.advance_phase(ScanPhase::Crawl);
    assert!(result.is_ok());
    assert_eq!(coord.current_phase(), ScanPhase::Crawl);
}

#[test]
fn advance_phase_without_barrier_succeeds() {
    let mut coord = ScanCoordinator::new();
    coord.register_worker("w1");
    let result = coord.advance_phase(ScanPhase::Crawl);
    assert!(result.is_ok());
}

#[test]
fn advance_phase_incomplete_barrier_fails() {
    let mut coord = ScanCoordinator::new();
    coord.register_worker("w1");
    coord.register_worker("w2");
    coord.create_barrier().unwrap();
    coord.worker_phase_complete("w1").unwrap();
    let result = coord.advance_phase(ScanPhase::Crawl);
    assert!(result.is_err());
}

#[test]
fn advance_phase_invalid_transition_fails() {
    let mut coord = ScanCoordinator::new();
    coord.register_worker("w1");
    let result = coord.advance_phase(ScanPhase::Fuzz);
    assert!(result.is_err());
}

#[test]
fn full_phase_sequence() {
    let mut coord = ScanCoordinator::new();
    coord.register_worker("w1");
    let phases = [
        ScanPhase::Crawl,
        ScanPhase::Fingerprint,
        ScanPhase::Fuzz,
        ScanPhase::Analyze,
        ScanPhase::DomVerify,
        ScanPhase::Report,
    ];
    for next in phases {
        coord.create_barrier().unwrap();
        coord.worker_phase_complete("w1").unwrap();
        coord.advance_phase(next).unwrap();
    }
    assert_eq!(coord.current_phase(), ScanPhase::Report);
    assert_eq!(coord.phase_history().len(), 7);
}

// --- Broadcasting ---

#[test]
fn broadcast_finding_logged() {
    let mut coord = ScanCoordinator::new();
    coord.broadcast_finding(sample_finding());
    assert_eq!(coord.broadcast_log().len(), 1);
    assert!(matches!(
        coord.broadcast_log()[0],
        BroadcastMessage::NewFinding(_)
    ));
}

#[test]
fn broadcast_custom_logged() {
    let mut coord = ScanCoordinator::new();
    coord.broadcast_custom("test message".to_string());
    assert_eq!(coord.broadcast_log().len(), 1);
    assert!(matches!(
        coord.broadcast_log()[0],
        BroadcastMessage::Custom(_)
    ));
}

#[test]
fn worker_join_leave_broadcast() {
    let mut coord = ScanCoordinator::new();
    coord.register_worker("w1");
    coord.remove_worker("w1").unwrap();
    assert_eq!(coord.broadcast_log().len(), 2);
    assert!(matches!(
        coord.broadcast_log()[0],
        BroadcastMessage::WorkerJoined(_)
    ));
    assert!(matches!(
        coord.broadcast_log()[1],
        BroadcastMessage::WorkerLeft(_)
    ));
}

#[test]
fn phase_transition_broadcast() {
    let mut coord = ScanCoordinator::new();
    coord.register_worker("w1");
    coord.create_barrier().unwrap();
    coord.worker_phase_complete("w1").unwrap();
    coord.advance_phase(ScanPhase::Crawl).unwrap();
    let transitions: Vec<_> = coord
        .broadcast_log()
        .iter()
        .filter(|m| matches!(m, BroadcastMessage::PhaseTransition(_)))
        .collect();
    assert_eq!(transitions.len(), 1);
}

// --- Pending workers ---

#[test]
fn pending_workers_reports_missing() {
    let mut coord = ScanCoordinator::new();
    coord.register_worker("w1");
    coord.register_worker("w2");
    coord.create_barrier().unwrap();
    coord.worker_phase_complete("w1").unwrap();
    let pending = coord.pending_workers();
    assert_eq!(pending.len(), 1);
    assert!(pending.contains(&"w2".to_string()));
}

#[test]
fn pending_workers_empty_when_no_barrier() {
    let coord = ScanCoordinator::new();
    assert!(coord.pending_workers().is_empty());
}

// --- Phase display ---

#[test]
fn scan_phase_display() {
    assert_eq!(format!("{}", ScanPhase::Recon), "recon");
    assert_eq!(format!("{}", ScanPhase::Fuzz), "fuzz");
    assert_eq!(format!("{}", ScanPhase::Report), "report");
    assert_eq!(format!("{}", ScanPhase::DomVerify), "dom-verify");
}

// --- Error display ---

#[test]
fn error_display() {
    let e = CoordinatorError::PhaseNotActive(ScanPhase::Fuzz);
    assert!(format!("{e}").contains("fuzz"));
    let e = CoordinatorError::NoWorkersRegistered;
    assert!(format!("{e}").contains("no workers"));
    let e = CoordinatorError::InvalidPhaseTransition {
        from: ScanPhase::Recon,
        to: ScanPhase::Report,
    };
    assert!(format!("{e}").contains("recon"));
}
