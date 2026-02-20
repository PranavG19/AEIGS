use super::*;

use aegis_fuzzing::{BotDetectionProfile, DefenseProfile, RateLimitProfile, WafProfile, WafVendor};
use aegis_knowledge_graph::graph::KnowledgeGraph;
use aegis_protocol::edge::EdgeLabel;
use aegis_protocol::operation::GraphOperation;
use clap::Parser;

fn test_config() -> ScanConfig {
    ScanConfig::try_parse_from(["aegis", "--target", "http://localhost:8080"]).unwrap()
}

fn test_context() -> ScanContext {
    let mut capabilities =
        aegis_supervisor::capability_manager::CapabilityManager::new(vec![0u8; 32]);
    pipeline::register_default_policies(&mut capabilities);
    ScanContext {
        config: test_config(),
        graph: Box::new(KnowledgeGraph::new()),
        defense_profile: None,
        capabilities,
        refuted: convergence::RefutedTracker::new(),
    }
}

#[test]
fn run_fingerprint_adds_defense_node() {
    let mut ctx = test_context();
    let before = ctx.graph.node_count().unwrap();

    let result = run_fingerprint(&mut ctx).unwrap();

    assert_eq!(ctx.graph.node_count().unwrap(), before + 1);
    assert_eq!(result.operations_applied, 1);
}

#[test]
fn run_fingerprint_sets_defense_profile() {
    let mut ctx = test_context();
    assert!(ctx.defense_profile.is_none());

    run_fingerprint(&mut ctx).unwrap();

    assert!(ctx.defense_profile.is_some());
}

#[test]
fn defense_properties_empty_profile_returns_empty() {
    let profile = DefenseProfile::empty(0);

    let props = phase_fingerprint::defense_properties(&profile);

    assert!(props.is_empty());
}

#[test]
fn defense_properties_waf_profile_includes_vendor_and_code() {
    let profile = DefenseProfile::empty(0).with_waf(WafProfile {
        vendor: WafVendor::Cloudflare,
        paranoia_level: None,
        blocked_response_code: 403,
        blocked_categories: vec![],
    });

    let props = phase_fingerprint::defense_properties(&profile);

    let keys: Vec<&str> = props.iter().map(|(k, _)| k.as_str()).collect();
    assert!(keys.contains(&"waf_vendor"));
    assert!(keys.contains(&"waf_blocked_code"));
    let code = props.iter().find(|(k, _)| k == "waf_blocked_code").unwrap();
    assert_eq!(code.1, "403");
}

#[test]
fn defense_properties_rate_limit_includes_code() {
    let profile = DefenseProfile::empty(0).with_rate_limit(RateLimitProfile {
        requests_per_second: Some(100.0),
        burst_allowance: Some(10),
        limit_response_code: 429,
        limit_window_seconds: Some(60),
    });

    let props = phase_fingerprint::defense_properties(&profile);

    let entry = props.iter().find(|(k, _)| k == "rate_limit_code").unwrap();
    assert_eq!(entry.1, "429");
}

#[test]
fn defense_properties_bot_detection_includes_detected() {
    let profile = DefenseProfile::empty(0).with_bot_detection(BotDetectionProfile {
        detected: true,
        detection_method: "js_challenge".to_string(),
        challenge_response_code: Some(503),
    });

    let props = phase_fingerprint::defense_properties(&profile);

    let entry = props.iter().find(|(k, _)| k == "bot_detected").unwrap();
    assert_eq!(entry.1, "true");
}

#[test]
fn build_protected_by_edges_creates_correct_edges() {
    let defense_node_id = 42;
    let endpoint_ids = vec![10, 20, 30];

    let entries = build_protected_by_edges(defense_node_id, &endpoint_ids, 0);

    assert_eq!(entries.len(), 3);
    for (i, entry) in entries.iter().enumerate() {
        assert_eq!(entry.sequence_number, i as u64 + 1);
        match &entry.operation {
            GraphOperation::AddEdge {
                source_node_id,
                target_node_id,
                label,
                weight,
            } => {
                assert_eq!(*source_node_id, endpoint_ids[i]);
                assert_eq!(*target_node_id, defense_node_id);
                assert!(matches!(label, EdgeLabel::ProtectedBy));
                assert!((weight - 1.0).abs() < f64::EPSILON);
            }
            _ => panic!("expected AddEdge operation"),
        }
    }
}

#[test]
fn build_protected_by_edges_empty_endpoints_returns_empty() {
    let entries = build_protected_by_edges(42, &[], 0);

    assert!(entries.is_empty());
}
