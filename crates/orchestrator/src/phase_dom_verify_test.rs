use aegis_knowledge_graph::graph::KnowledgeGraph;
use aegis_protocol::finding::{FindingData, VulnerabilityClass};
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier};
use aegis_protocol::scan_event::ScanEvent;
use aegis_supervisor::capability_manager::CapabilityManager;

use crate::actor::{DomVerifyActor, ScanActor};
use crate::convergence::RefutedTracker;
use crate::phase_dom_verify::{DomVerifyOutcome, dom_verify_to_operations};
use crate::pipeline;
use crate::scan_config;

fn make_xss_finding(id: u64, confidence: f64) -> FindingData {
    FindingData::new(
        id,
        VulnerabilityClass::CrossSiteScripting,
        7.0,
        confidence,
        ModuleIdentifier::Fuzzing,
        1000,
    )
}

fn test_capability_manager() -> CapabilityManager {
    let mut manager = CapabilityManager::new(vec![0u8; 32]);
    pipeline::register_default_policies(&mut manager);
    manager
}

fn localhost_config() -> scan_config::ScanConfig {
    scan_config::ScanConfig {
        target: "http://localhost:8080".to_string(),
        output: std::env::temp_dir().join("aegis-dom-verify-test.sarif"),
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
        },
        auth: scan_config::AuthOptions {
            auth_flow: None,
            auth_input: Vec::new(),
        },
    }
}

fn make_ctx_with_real_graph() -> pipeline::ScanContext {
    pipeline::ScanContext {
        config: localhost_config(),
        graph: Box::new(KnowledgeGraph::new()),
        defense_profile: None,
        capabilities: test_capability_manager(),
        refuted: RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
    }
}

#[test]
fn dom_verify_to_operations_creates_findings_for_executed() {
    let findings = vec![make_xss_finding(0, 0.5), make_xss_finding(1, 0.6)];
    let outcomes = vec![
        DomVerifyOutcome {
            finding_index: 0,
            dom_executed: true,
            confidence_adjustment: 0.3,
        },
        DomVerifyOutcome {
            finding_index: 1,
            dom_executed: false,
            confidence_adjustment: -0.2,
        },
    ];

    let mut seq = 0u64;
    let ops = dom_verify_to_operations(&outcomes, &findings, &mut seq);

    assert_eq!(ops.len(), 1, "only dom_executed=true outcomes produce ops");
    assert_eq!(seq, 1);

    match &ops[0].operation {
        GraphOperation::AddFinding {
            vulnerability_class,
            confidence,
            severity,
            ..
        } => {
            assert_eq!(*vulnerability_class, VulnerabilityClass::CrossSiteScripting);
            assert!((confidence - 0.8).abs() < f64::EPSILON);
            assert!((severity - 7.0).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding operation"),
    }
}

#[test]
fn dom_verify_to_operations_empty_outcomes() {
    let findings = vec![make_xss_finding(0, 0.5)];
    let mut seq = 5u64;
    let ops = dom_verify_to_operations(&[], &findings, &mut seq);

    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn dom_verify_to_operations_preserves_sequence_numbers() {
    let findings = vec![
        make_xss_finding(0, 0.4),
        make_xss_finding(1, 0.5),
        make_xss_finding(2, 0.6),
    ];
    let outcomes = vec![
        DomVerifyOutcome {
            finding_index: 0,
            dom_executed: true,
            confidence_adjustment: 0.2,
        },
        DomVerifyOutcome {
            finding_index: 1,
            dom_executed: true,
            confidence_adjustment: 0.3,
        },
        DomVerifyOutcome {
            finding_index: 2,
            dom_executed: true,
            confidence_adjustment: 0.1,
        },
    ];

    let mut seq = 10u64;
    let ops = dom_verify_to_operations(&outcomes, &findings, &mut seq);

    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 13);
    assert_eq!(ops[0].sequence_number, 11);
    assert_eq!(ops[1].sequence_number, 12);
    assert_eq!(ops[2].sequence_number, 13);
}

#[test]
fn dom_verify_outcome_construction() {
    let outcome = DomVerifyOutcome {
        finding_index: 42,
        dom_executed: true,
        confidence_adjustment: 0.3,
    };
    assert_eq!(outcome.finding_index, 42);
    assert!(outcome.dom_executed);
    assert!((outcome.confidence_adjustment - 0.3).abs() < f64::EPSILON);
}

#[test]
fn dom_verify_actor_name() {
    let actor = DomVerifyActor;
    assert_eq!(actor.name(), "dom_verify");
}

#[test]
fn dom_verify_actor_produces_phase_completed_event() {
    let mut ctx = make_ctx_with_real_graph();
    let mut actor = DomVerifyActor;
    let events = actor.process(&mut ctx, &[]).unwrap();

    assert_eq!(events.len(), 1);
    match &events[0].event {
        ScanEvent::PhaseCompleted {
            phase_name,
            operations_applied,
            findings_count,
            ..
        } => {
            assert_eq!(phase_name, "dom_verify");
            assert_eq!(*operations_applied, 0);
            assert_eq!(*findings_count, 0);
        }
        _ => panic!("expected PhaseCompleted event"),
    }
}

#[test]
fn dom_verify_to_operations_clamps_confidence_to_one() {
    let findings = vec![make_xss_finding(0, 0.9)];
    let outcomes = vec![DomVerifyOutcome {
        finding_index: 0,
        dom_executed: true,
        confidence_adjustment: 0.5,
    }];

    let mut seq = 0u64;
    let ops = dom_verify_to_operations(&outcomes, &findings, &mut seq);

    assert_eq!(ops.len(), 1);
    match &ops[0].operation {
        GraphOperation::AddFinding { confidence, .. } => {
            assert!((confidence - 1.0).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding operation"),
    }
}

#[test]
fn dom_verify_to_operations_skips_out_of_bounds_index() {
    let findings = vec![make_xss_finding(0, 0.5)];
    let outcomes = vec![DomVerifyOutcome {
        finding_index: 99,
        dom_executed: true,
        confidence_adjustment: 0.3,
    }];

    let mut seq = 0u64;
    let ops = dom_verify_to_operations(&outcomes, &findings, &mut seq);

    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}
