use aegis_knowledge_graph::GraphStore;
use aegis_knowledge_graph::graph::{GraphError, KnowledgeGraph};
use aegis_protocol::finding::{FindingData, VulnerabilityClass};
use aegis_protocol::node::{NodeData, NodeType};
use aegis_protocol::operation::{ModuleIdentifier, OperationLogEntry};
use aegis_protocol::request::{FuzzRequest, FuzzResponse};
use aegis_protocol::scan_event::{ScanEvent, ScanEventEnvelope};
use aegis_supervisor::capability_manager::CapabilityManager;

use super::*;

struct FakeGraphStore {
    ops_applied: u64,
    nodes: Vec<NodeData>,
}

impl FakeGraphStore {
    fn new() -> Self {
        Self {
            ops_applied: 0,
            nodes: Vec::new(),
        }
    }
}

impl GraphStore for FakeGraphStore {
    fn apply_operations(&mut self, ops: &[OperationLogEntry]) -> Result<(), GraphError> {
        self.ops_applied += ops.len() as u64;
        Ok(())
    }

    fn nodes_by_type(&self, node_type: NodeType) -> Result<Vec<u64>, GraphError> {
        Ok(self
            .nodes
            .iter()
            .filter(|n| n.node_type == node_type)
            .map(|n| n.id)
            .collect())
    }

    fn get_node(&self, id: u64) -> Result<Option<NodeData>, GraphError> {
        Ok(self.nodes.iter().find(|n| n.id == id).cloned())
    }

    fn total_operations_applied(&self) -> Result<u64, GraphError> {
        Ok(self.ops_applied)
    }

    fn all_findings(&self) -> Result<Vec<FindingData>, GraphError> {
        Ok(Vec::new())
    }

    fn node_count(&self) -> Result<u64, GraphError> {
        Ok(self.nodes.len() as u64)
    }

    fn findings_by_class(
        &self,
        _vulnerability_class: VulnerabilityClass,
    ) -> Result<Vec<u64>, GraphError> {
        Ok(Vec::new())
    }

    fn get_finding(&self, _id: u64) -> Result<Option<FindingData>, GraphError> {
        Ok(None)
    }
}

struct MockTransport;

impl phase_fuzz::FuzzTransport for MockTransport {
    async fn send(&mut self, request: &FuzzRequest) -> Result<FuzzResponse, String> {
        Ok(FuzzResponse {
            request_id: request.request_id,
            status_code: 200,
            body: String::new(),
            headers: vec![],
            response_time: std::time::Duration::from_millis(10),
            body_size_bytes: 0,
        })
    }
}

fn test_capability_manager() -> CapabilityManager {
    let mut manager = CapabilityManager::new(vec![0u8; 32]);
    pipeline::register_default_policies(&mut manager);
    manager
}

fn localhost_config() -> scan_config::ScanConfig {
    scan_config::ScanConfig {
        preset: None,
        target: "http://localhost:8080".to_string(),
        output: std::env::temp_dir().join("aegis-actor-test.sarif"),
        report_format: "developer".to_string(),
        source_dir: None,
        verbose: false,
        stealth: scan_config::StealthOptions {
            persona: "chrome".to_string(),
            stealth: false,
            stealth_level: "default".to_string(),
            max_rps: None,
            skip_evasion: false,
            accept_self_signed: false,
            persona_catalog: None,
        },
        pipeline: scan_config::PipelineOptions {
            max_iterations: 1,
            convergence_threshold: 2,
            skip_fingerprint: false,
            paranoia_sweep: false,
            resume: false,
        },
        llm: scan_config::LlmOptions {
            no_llm: false,
            bypass_corpus: None,
            python_cmd: "python3".to_string(),
        },
        audit: scan_config::AuditOptions {
            no_audit: false,
            scope_attestation: None,
            signed_config: None,
        },
        scope: scan_config::ScopeOptions {
            include_endpoints: None,
            exclude_endpoints: None,
            context_file: None,
            graph_db: None,
            history_db: None,
            export_graph: None,
            vuln_db: None,
        },
        auth: scan_config::AuthOptions {
            auth_flow: None,
            auth_input: Vec::new(),
        },
        distributed: scan_config::DistributedOptions {
            distributed: false,
            coordinator_addr: "127.0.0.1:9100".to_string(),
            workers: 1,
            worker_connect: None,
            worker_id: "worker-0".to_string(),
        },
    }
}

fn make_ctx_with_fake_graph() -> pipeline::ScanContext {
    pipeline::ScanContext {
        config: localhost_config(),
        graph: Box::new(FakeGraphStore::new()),
        defense_profile: None,
        capabilities: test_capability_manager(),
        refuted: convergence::RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
    }
}

fn make_ctx_with_real_graph() -> pipeline::ScanContext {
    pipeline::ScanContext {
        config: localhost_config(),
        graph: Box::new(KnowledgeGraph::new()),
        defense_profile: None,
        capabilities: test_capability_manager(),
        refuted: convergence::RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
    }
}

fn has_phase_completed(events: &[ScanEventEnvelope], phase: &str) -> bool {
    events.iter().any(|e| {
        matches!(
            &e.event,
            ScanEvent::PhaseCompleted { phase_name, .. } if phase_name == phase
        )
    })
}

fn count_event_kind(events: &[ScanEventEnvelope], kind: &str) -> usize {
    events
        .iter()
        .filter(|e| match &e.event {
            ScanEvent::EndpointDiscovered { .. } => kind == "EndpointDiscovered",
            ScanEvent::HypothesisGenerated { .. } => kind == "HypothesisGenerated",
            ScanEvent::PayloadTested { .. } => kind == "PayloadTested",
            ScanEvent::AnomalyDetected { .. } => kind == "AnomalyDetected",
            ScanEvent::FindingConfirmed { .. } => kind == "FindingConfirmed",
            ScanEvent::PhaseCompleted { .. } => kind == "PhaseCompleted",
        })
        .count()
}

// --- ReconActor tests ---

#[test]
fn recon_actor_name() {
    let actor = actor::ReconActor;
    assert_eq!(actor.name(), "recon");
}

#[test]
fn recon_actor_empty_events_emits_phase_completed() {
    let mut ctx = make_ctx_with_fake_graph();
    let mut actor = actor::ReconActor;
    let events = actor.process(&mut ctx, &[]).unwrap();
    assert!(has_phase_completed(&events, "recon"));
}

#[test]
fn recon_actor_with_source_dir_emits_phase_completed() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("app.toml"), b"[server]").unwrap();
    let mut ctx = make_ctx_with_real_graph();
    ctx.config.source_dir = Some(tmp.path().to_path_buf());
    let mut actor = actor::ReconActor;
    let events = actor.process(&mut ctx, &[]).unwrap();
    assert!(has_phase_completed(&events, "recon"));
}

#[test]
fn recon_actor_event_ids_are_unique() {
    let mut ctx = make_ctx_with_fake_graph();
    let mut actor = actor::ReconActor;
    let events = actor.process(&mut ctx, &[]).unwrap();
    let ids: Vec<u64> = events.iter().map(|e| e.event_id).collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len());
}

#[test]
fn recon_actor_phase_completed_has_zero_findings() {
    let mut ctx = make_ctx_with_fake_graph();
    let mut actor = actor::ReconActor;
    let events = actor.process(&mut ctx, &[]).unwrap();
    let pc = events
        .iter()
        .find(|e| matches!(&e.event, ScanEvent::PhaseCompleted { .. }))
        .unwrap();
    if let ScanEvent::PhaseCompleted { findings_count, .. } = &pc.event {
        assert_eq!(*findings_count, 0);
    }
}

// --- FingerprintActor tests ---

#[test]
fn fingerprint_actor_name() {
    let actor = actor::FingerprintActor;
    assert_eq!(actor.name(), "fingerprint");
}

#[test]
fn fingerprint_actor_emits_phase_completed() {
    let mut ctx = make_ctx_with_fake_graph();
    let mut actor = actor::FingerprintActor;
    let events = actor.process(&mut ctx, &[]).unwrap();
    assert!(has_phase_completed(&events, "fingerprint"));
    assert_eq!(events.len(), 1);
}

#[test]
fn fingerprint_actor_sets_defense_profile() {
    let mut ctx = make_ctx_with_fake_graph();
    assert!(ctx.defense_profile.is_none());
    let mut actor = actor::FingerprintActor;
    actor.process(&mut ctx, &[]).unwrap();
    assert!(ctx.defense_profile.is_some());
}

#[test]
fn fingerprint_actor_applies_operations_to_graph() {
    let mut ctx = make_ctx_with_real_graph();
    let mut actor = actor::FingerprintActor;
    actor.process(&mut ctx, &[]).unwrap();
    assert!(ctx.graph.total_operations_applied().unwrap() > 0);
}

// --- FuzzActor tests ---

#[tokio::test]
async fn fuzz_actor_emits_phase_completed() {
    let mut ctx = make_ctx_with_real_graph();
    let mut actor = actor::FuzzActor::new(MockTransport);
    let events = actor.process_async(&mut ctx, &[]).await.unwrap();
    assert!(has_phase_completed(&events, "fuzz"));
}

#[tokio::test]
async fn fuzz_actor_empty_graph_zero_findings() {
    let mut ctx = make_ctx_with_real_graph();
    let mut actor = actor::FuzzActor::new(MockTransport);
    let events = actor.process_async(&mut ctx, &[]).await.unwrap();
    let pc = events
        .iter()
        .find(|e| matches!(&e.event, ScanEvent::PhaseCompleted { .. }))
        .unwrap();
    if let ScanEvent::PhaseCompleted { findings_count, .. } = &pc.event {
        assert_eq!(*findings_count, 0);
    }
}

// --- AnalyzeActor tests ---

#[test]
fn analyze_actor_name() {
    let actor = actor::AnalyzeActor;
    assert_eq!(actor.name(), "analyze");
}

#[test]
fn analyze_actor_emits_phase_completed() {
    let mut ctx = make_ctx_with_real_graph();
    let mut actor = actor::AnalyzeActor;
    let events = actor.process(&mut ctx, &[]).unwrap();
    assert!(has_phase_completed(&events, "analyze"));
}

#[test]
fn analyze_actor_empty_graph_zero_findings() {
    let mut ctx = make_ctx_with_real_graph();
    let mut actor = actor::AnalyzeActor;
    let events = actor.process(&mut ctx, &[]).unwrap();
    assert_eq!(count_event_kind(&events, "FindingConfirmed"), 0);
}

// --- ReportActor tests ---

#[test]
fn report_actor_name() {
    let actor = actor::ReportActor::new(None, None);
    assert_eq!(actor.name(), "report");
}

#[test]
fn report_actor_emits_phase_completed() {
    let mut ctx = make_ctx_with_real_graph();
    let mut actor = actor::ReportActor::new(None, None);
    let events = actor.process(&mut ctx, &[]).unwrap();
    assert!(has_phase_completed(&events, "report"));
    assert_eq!(events.len(), 1);
}

// --- ConvergenceActor tests ---

#[test]
fn convergence_actor_name() {
    let actor = actor::ConvergenceActor::new(2);
    assert_eq!(actor.name(), "convergence");
}

#[test]
fn convergence_actor_initially_does_not_stop() {
    let actor = actor::ConvergenceActor::new(2);
    assert!(!actor.should_stop());
}

#[test]
fn convergence_actor_stops_after_threshold_zero_finding_rounds() {
    let mut ctx = make_ctx_with_fake_graph();
    let mut actor = actor::ConvergenceActor::new(2);

    let round_events = vec![ScanEventEnvelope::new(
        1,
        ModuleIdentifier::ChainSynthesis,
        ScanEvent::PhaseCompleted {
            phase_name: "analyze".to_string(),
            operations_applied: 0,
            findings_count: 0,
            duration_ms: 10,
        },
    )];

    actor.process(&mut ctx, &round_events).unwrap();
    assert!(!actor.should_stop());
    assert_eq!(actor.consecutive_zero_rounds(), 1);

    actor.process(&mut ctx, &round_events).unwrap();
    assert!(actor.should_stop());
    assert_eq!(actor.consecutive_zero_rounds(), 2);
}

#[test]
fn convergence_actor_resets_on_finding() {
    let mut ctx = make_ctx_with_fake_graph();
    let mut actor = actor::ConvergenceActor::new(2);

    let zero_round = vec![ScanEventEnvelope::new(
        1,
        ModuleIdentifier::ChainSynthesis,
        ScanEvent::PhaseCompleted {
            phase_name: "analyze".to_string(),
            operations_applied: 0,
            findings_count: 0,
            duration_ms: 10,
        },
    )];
    actor.process(&mut ctx, &zero_round).unwrap();
    assert_eq!(actor.consecutive_zero_rounds(), 1);

    let finding_round = vec![
        ScanEventEnvelope::new(
            2,
            ModuleIdentifier::Fuzzing,
            ScanEvent::FindingConfirmed {
                finding_id: 1,
                vulnerability_class: VulnerabilityClass::SqlInjection,
                severity: 5.0,
                confidence: 0.9,
            },
        ),
        ScanEventEnvelope::new(
            3,
            ModuleIdentifier::ChainSynthesis,
            ScanEvent::PhaseCompleted {
                phase_name: "analyze".to_string(),
                operations_applied: 1,
                findings_count: 1,
                duration_ms: 10,
            },
        ),
    ];
    actor.process(&mut ctx, &finding_round).unwrap();
    assert_eq!(actor.consecutive_zero_rounds(), 0);
    assert!(!actor.should_stop());
}

#[test]
fn convergence_actor_threshold_one_stops_after_one_zero_round() {
    let mut ctx = make_ctx_with_fake_graph();
    let mut actor = actor::ConvergenceActor::new(1);

    let zero_round = vec![ScanEventEnvelope::new(
        1,
        ModuleIdentifier::ChainSynthesis,
        ScanEvent::PhaseCompleted {
            phase_name: "analyze".to_string(),
            operations_applied: 0,
            findings_count: 0,
            duration_ms: 5,
        },
    )];
    actor.process(&mut ctx, &zero_round).unwrap();
    assert!(actor.should_stop());
}

#[test]
fn convergence_actor_ignores_non_analyze_phase_completed() {
    let mut ctx = make_ctx_with_fake_graph();
    let mut actor = actor::ConvergenceActor::new(1);

    let fuzz_complete = vec![ScanEventEnvelope::new(
        1,
        ModuleIdentifier::Fuzzing,
        ScanEvent::PhaseCompleted {
            phase_name: "fuzz".to_string(),
            operations_applied: 0,
            findings_count: 0,
            duration_ms: 5,
        },
    )];
    actor.process(&mut ctx, &fuzz_complete).unwrap();
    assert!(!actor.should_stop());
    assert_eq!(actor.consecutive_zero_rounds(), 0);
}

// --- ActorError tests ---

#[test]
fn actor_error_display_phase() {
    let err = actor::ActorError::Phase("recon failed".to_string());
    assert_eq!(format!("{err}"), "phase: recon failed");
}

#[test]
fn actor_error_display_internal() {
    let err = actor::ActorError::Internal("lock poisoned".to_string());
    assert_eq!(format!("{err}"), "internal: lock poisoned");
}

#[test]
fn actor_error_debug() {
    let err = actor::ActorError::Phase("test".to_string());
    let dbg = format!("{err:?}");
    assert!(dbg.contains("Phase"));
}

#[test]
fn actor_error_is_std_error() {
    let err = actor::ActorError::Phase("boom".to_string());
    let _: &dyn std::error::Error = &err;
}

// --- run_actor_pipeline integration test ---

#[tokio::test]
async fn run_actor_pipeline_emits_all_phase_completed_events() {
    let mut ctx = make_ctx_with_real_graph();
    let events = actor::run_actor_pipeline(&mut ctx, MockTransport, None)
        .await
        .unwrap();

    assert!(has_phase_completed(&events, "recon"));
    assert!(has_phase_completed(&events, "crawl"));
    assert!(has_phase_completed(&events, "fingerprint"));
    assert!(has_phase_completed(&events, "fuzz"));
    assert!(has_phase_completed(&events, "analyze"));
    assert!(has_phase_completed(&events, "dom_verify"));
    assert!(has_phase_completed(&events, "report"));
}

#[tokio::test]
async fn run_actor_pipeline_skip_fingerprint() {
    let mut ctx = make_ctx_with_real_graph();
    ctx.config.pipeline.skip_fingerprint = true;
    ctx.config.output = std::env::temp_dir().join("aegis-actor-skip-fp.sarif");
    let events = actor::run_actor_pipeline(&mut ctx, MockTransport, None)
        .await
        .unwrap();

    assert!(has_phase_completed(&events, "recon"));
    assert!(has_phase_completed(&events, "crawl"));
    assert!(!has_phase_completed(&events, "fingerprint"));
    assert!(has_phase_completed(&events, "fuzz"));
}

#[tokio::test]
async fn run_actor_pipeline_convergence_stops_early() {
    let mut ctx = make_ctx_with_real_graph();
    ctx.config.pipeline.max_iterations = 5;
    ctx.config.pipeline.convergence_threshold = 1;
    ctx.config.output = std::env::temp_dir().join("aegis-actor-converge.sarif");
    let events = actor::run_actor_pipeline(&mut ctx, MockTransport, None)
        .await
        .unwrap();

    let fuzz_completed_count = events
        .iter()
        .filter(|e| {
            matches!(
                &e.event,
                ScanEvent::PhaseCompleted { phase_name, .. } if phase_name == "fuzz"
            )
        })
        .count();
    assert!(
        fuzz_completed_count < 5,
        "convergence should stop early, got {fuzz_completed_count} fuzz phases"
    );
}
