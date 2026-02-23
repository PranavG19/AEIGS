use aegis_knowledge_graph::graph::KnowledgeGraph;
use aegis_protocol::finding::{FindingData, VulnerabilityClass};
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};
use aegis_protocol::scan_event::ScanEvent;
use aegis_supervisor::capability_manager::CapabilityManager;

use crate::actor::{DomVerifyActor, ScanActor};
use crate::convergence::RefutedTracker;
use crate::phase_dom_verify::{DomVerifyOutcome, dom_verify_to_operations, run_dom_verify};
use crate::pipeline;
use crate::scan_config;
use crate::util::timestamp_ms;

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

fn make_add_node_op(seq: u64, path: &str, method: &str) -> OperationLogEntry {
    OperationLogEntry {
        sequence_number: seq,
        module: ModuleIdentifier::Enumeration,
        operation: GraphOperation::AddNode {
            node_type: NodeType::Endpoint,
            properties: vec![
                ("path".to_string(), path.to_string()),
                ("method".to_string(), method.to_string()),
            ],
        },
        timestamp_unix_ms: timestamp_ms(),
    }
}

fn make_add_finding_op(
    seq: u64,
    linked_node_ids: Vec<u64>,
    vuln_class: VulnerabilityClass,
    severity: f64,
    confidence: f64,
) -> OperationLogEntry {
    OperationLogEntry {
        sequence_number: seq,
        module: ModuleIdentifier::Fuzzing,
        operation: GraphOperation::AddFinding {
            linked_node_ids,
            vulnerability_class: vuln_class,
            severity,
            confidence,
            certificate: Vec::new(),
        },
        timestamp_unix_ms: timestamp_ms(),
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
            skip_crawl: false,
            paranoia_sweep: false,
            resume: false,
            interactive: false,
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
            i_am_authorized: false,
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
        telemetry: false,
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

// --- Integration tests: graph round-trip ---

#[test]
fn dom_verify_upgrades_evidence_in_graph() {
    let mut ctx = make_ctx_with_real_graph();

    let seed_ops = vec![
        make_add_finding_op(1, vec![], VulnerabilityClass::CrossSiteScripting, 7.0, 0.5),
        make_add_finding_op(2, vec![], VulnerabilityClass::CrossSiteScripting, 6.0, 0.4),
    ];
    ctx.graph.apply_operations(&seed_ops).unwrap();

    let original_findings = ctx.graph.all_findings().unwrap();
    assert_eq!(original_findings.len(), 2);

    let outcomes = vec![
        DomVerifyOutcome {
            finding_index: 0,
            dom_executed: true,
            confidence_adjustment: 0.3,
        },
        DomVerifyOutcome {
            finding_index: 1,
            dom_executed: true,
            confidence_adjustment: 0.2,
        },
    ];

    let mut seq = 2u64;
    let verify_ops = dom_verify_to_operations(&outcomes, &original_findings, &mut seq);
    assert_eq!(verify_ops.len(), 2);

    ctx.graph.apply_operations(&verify_ops).unwrap();

    let all_findings = ctx.graph.all_findings().unwrap();
    assert_eq!(all_findings.len(), 4, "2 originals + 2 boosted");

    let boosted_0 = ctx.graph.get_finding(2).unwrap().unwrap();
    assert!(
        (boosted_0.confidence.composite.value() - 0.8).abs() < f64::EPSILON,
        "0.5 + 0.3 = 0.8"
    );

    let boosted_1 = ctx.graph.get_finding(3).unwrap().unwrap();
    assert!(
        (boosted_1.confidence.composite.value() - 0.6).abs() < f64::EPSILON,
        "0.4 + 0.2 = 0.6"
    );
}

#[test]
fn dom_verify_run_returns_empty_for_no_xss_findings() {
    let mut ctx = make_ctx_with_real_graph();

    let seed_ops = vec![make_add_finding_op(
        1,
        vec![],
        VulnerabilityClass::SqlInjection,
        9.0,
        0.8,
    )];
    ctx.graph.apply_operations(&seed_ops).unwrap();

    let result = run_dom_verify(&mut ctx).unwrap();
    assert_eq!(result.operations_applied, 0);
    assert_eq!(result.findings_count, 0);
}

#[test]
fn dom_verify_run_returns_empty_for_empty_graph() {
    let mut ctx = make_ctx_with_real_graph();

    let result = run_dom_verify(&mut ctx).unwrap();
    assert_eq!(result.operations_applied, 0);
    assert_eq!(result.findings_count, 0);
}

#[test]
fn dom_verify_preserves_linked_node_ids() {
    let mut ctx = make_ctx_with_real_graph();

    let node_ops = vec![
        make_add_node_op(1, "/api/a", "GET"),
        make_add_node_op(2, "/api/b", "POST"),
        make_add_node_op(3, "/api/c", "PUT"),
    ];
    ctx.graph.apply_operations(&node_ops).unwrap();

    let seed_ops = vec![make_add_finding_op(
        4,
        vec![0, 1, 2],
        VulnerabilityClass::CrossSiteScripting,
        7.0,
        0.5,
    )];
    ctx.graph.apply_operations(&seed_ops).unwrap();

    let findings = ctx.graph.all_findings().unwrap();
    assert_eq!(findings[0].linked_node_ids, vec![0, 1, 2]);

    let outcomes = vec![DomVerifyOutcome {
        finding_index: 0,
        dom_executed: true,
        confidence_adjustment: 0.2,
    }];

    let mut seq = 4u64;
    let verify_ops = dom_verify_to_operations(&outcomes, &findings, &mut seq);
    assert_eq!(verify_ops.len(), 1);

    match &verify_ops[0].operation {
        GraphOperation::AddFinding {
            linked_node_ids, ..
        } => {
            assert_eq!(*linked_node_ids, vec![0, 1, 2]);
        }
        _ => panic!("expected AddFinding operation"),
    }

    ctx.graph.apply_operations(&verify_ops).unwrap();
    let boosted = ctx.graph.get_finding(1).unwrap().unwrap();
    assert_eq!(boosted.linked_node_ids, vec![0, 1, 2]);
}

#[test]
fn dom_verify_preserves_vulnerability_class() {
    let mut ctx = make_ctx_with_real_graph();

    let seed_ops = vec![make_add_finding_op(
        1,
        vec![],
        VulnerabilityClass::CrossSiteScripting,
        8.5,
        0.6,
    )];
    ctx.graph.apply_operations(&seed_ops).unwrap();

    let findings = ctx.graph.all_findings().unwrap();
    let outcomes = vec![DomVerifyOutcome {
        finding_index: 0,
        dom_executed: true,
        confidence_adjustment: 0.15,
    }];

    let mut seq = 1u64;
    let verify_ops = dom_verify_to_operations(&outcomes, &findings, &mut seq);
    ctx.graph.apply_operations(&verify_ops).unwrap();

    let boosted = ctx.graph.get_finding(1).unwrap().unwrap();
    assert_eq!(
        boosted.vulnerability_class,
        VulnerabilityClass::CrossSiteScripting
    );
    assert!((boosted.severity - 8.5).abs() < f64::EPSILON);
}

#[test]
fn dom_verify_downgrades_false_positive_no_ops() {
    let mut ctx = make_ctx_with_real_graph();

    let seed_ops = vec![make_add_finding_op(
        1,
        vec![],
        VulnerabilityClass::CrossSiteScripting,
        7.0,
        0.5,
    )];
    ctx.graph.apply_operations(&seed_ops).unwrap();

    let findings = ctx.graph.all_findings().unwrap();
    let outcomes = vec![DomVerifyOutcome {
        finding_index: 0,
        dom_executed: false,
        confidence_adjustment: -0.3,
    }];

    let mut seq = 1u64;
    let verify_ops = dom_verify_to_operations(&outcomes, &findings, &mut seq);
    assert!(
        verify_ops.is_empty(),
        "non-executed outcomes should not produce ops"
    );

    let all_findings = ctx.graph.all_findings().unwrap();
    assert_eq!(all_findings.len(), 1, "graph unchanged");
    assert!(
        (all_findings[0].confidence.composite.value() - 0.5).abs() < f64::EPSILON,
        "original confidence preserved"
    );
}

#[test]
fn dom_verify_confidence_clamped_in_graph() {
    let mut ctx = make_ctx_with_real_graph();

    let seed_ops = vec![make_add_finding_op(
        1,
        vec![],
        VulnerabilityClass::CrossSiteScripting,
        7.0,
        0.95,
    )];
    ctx.graph.apply_operations(&seed_ops).unwrap();

    let findings = ctx.graph.all_findings().unwrap();
    let outcomes = vec![DomVerifyOutcome {
        finding_index: 0,
        dom_executed: true,
        confidence_adjustment: 0.5,
    }];

    let mut seq = 1u64;
    let verify_ops = dom_verify_to_operations(&outcomes, &findings, &mut seq);
    ctx.graph.apply_operations(&verify_ops).unwrap();

    let boosted = ctx.graph.get_finding(1).unwrap().unwrap();
    assert!(
        (boosted.confidence.composite.value() - 1.0).abs() < f64::EPSILON,
        "0.95 + 0.5 clamped to 1.0"
    );
    assert!(
        boosted.confidence.composite.value() <= 1.0,
        "confidence must not exceed 1.0 in graph"
    );
}

#[test]
fn dom_verify_actor_with_seeded_xss_findings() {
    let mut ctx = make_ctx_with_real_graph();

    let seed_ops = vec![
        make_add_finding_op(1, vec![], VulnerabilityClass::CrossSiteScripting, 7.0, 0.5),
        make_add_finding_op(2, vec![], VulnerabilityClass::SqlInjection, 9.0, 0.8),
    ];
    ctx.graph.apply_operations(&seed_ops).unwrap();

    let xss_ids = ctx
        .graph
        .findings_by_class(VulnerabilityClass::CrossSiteScripting)
        .unwrap();
    assert_eq!(xss_ids.len(), 1);

    let sqli_ids = ctx
        .graph
        .findings_by_class(VulnerabilityClass::SqlInjection)
        .unwrap();
    assert_eq!(sqli_ids.len(), 1);

    let mut actor = DomVerifyActor;
    let events = actor.process(&mut ctx, &[]).unwrap();

    assert_eq!(events.len(), 1);
    match &events[0].event {
        ScanEvent::PhaseCompleted {
            phase_name,
            operations_applied,
            ..
        } => {
            assert_eq!(phase_name, "dom_verify");
            assert_eq!(
                *operations_applied, 0,
                "placeholder phase applies no ops yet"
            );
        }
        _ => panic!("expected PhaseCompleted event"),
    }
}
