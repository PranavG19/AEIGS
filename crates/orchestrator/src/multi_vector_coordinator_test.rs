use super::multi_vector_coordinator::*;
use aegis_protocol::finding::{EvidenceLevel, VulnerabilityClass};

fn build_test_coordinator() -> MultiVectorCoordinator {
    let mut coord = MultiVectorCoordinator::new();

    coord.add_node(AttackNode {
        id: "ssrf-1".to_string(),
        endpoint: "/api/fetch".to_string(),
        vulnerability_class: VulnerabilityClass::ServerSideRequestForgery,
        evidence_level: EvidenceLevel::Confirmed,
        confidence: 0.9,
        difficulty: 3.0,
        requires_auth: false,
        centrality_score: 0.85,
    });

    coord.add_node(AttackNode {
        id: "deser-1".to_string(),
        endpoint: "/internal/process".to_string(),
        vulnerability_class: VulnerabilityClass::InsecureDeserialization,
        evidence_level: EvidenceLevel::Controlled,
        confidence: 0.7,
        difficulty: 5.0,
        requires_auth: true,
        centrality_score: 0.6,
    });

    coord.add_node(AttackNode {
        id: "jwt-1".to_string(),
        endpoint: "/auth/token".to_string(),
        vulnerability_class: VulnerabilityClass::JwtVulnerability,
        evidence_level: EvidenceLevel::Confirmed,
        confidence: 0.85,
        difficulty: 2.0,
        requires_auth: false,
        centrality_score: 0.75,
    });

    coord.add_node(AttackNode {
        id: "sqli-1".to_string(),
        endpoint: "/api/users".to_string(),
        vulnerability_class: VulnerabilityClass::SqlInjection,
        evidence_level: EvidenceLevel::Confirmed,
        confidence: 0.95,
        difficulty: 2.0,
        requires_auth: false,
        centrality_score: 0.9,
    });

    coord.add_node(AttackNode {
        id: "auth-bypass-1".to_string(),
        endpoint: "/admin/login".to_string(),
        vulnerability_class: VulnerabilityClass::BrokenAuthentication,
        evidence_level: EvidenceLevel::Controlled,
        confidence: 0.6,
        difficulty: 6.0,
        requires_auth: false,
        centrality_score: 0.5,
    });

    coord.add_edge(AttackEdge {
        source_id: "ssrf-1".to_string(),
        target_id: "deser-1".to_string(),
        chain_type: ChainType::NetworkPivot,
        feasibility: 0.8,
        description: "SSRF to reach internal deserialization endpoint".to_string(),
    });

    coord.add_edge(AttackEdge {
        source_id: "deser-1".to_string(),
        target_id: "jwt-1".to_string(),
        chain_type: ChainType::CredentialReuse,
        feasibility: 0.7,
        description: "Deser RCE to extract JWT signing key".to_string(),
    });

    coord.add_edge(AttackEdge {
        source_id: "jwt-1".to_string(),
        target_id: "sqli-1".to_string(),
        chain_type: ChainType::PrivilegeChain,
        feasibility: 0.9,
        description: "Forged admin JWT enables SQLi on protected endpoint".to_string(),
    });

    coord.add_edge(AttackEdge {
        source_id: "sqli-1".to_string(),
        target_id: "auth-bypass-1".to_string(),
        chain_type: ChainType::DataFlow,
        feasibility: 0.6,
        description: "Extract admin creds via SQLi".to_string(),
    });

    coord
}

#[test]
fn coordinator_tracks_nodes_and_edges() {
    let coord = build_test_coordinator();
    assert_eq!(coord.node_count(), 5);
    assert_eq!(coord.edge_count(), 4);
}

#[test]
fn find_attack_paths_from_unauthenticated() {
    let coord = build_test_coordinator();
    let paths = coord.find_attack_paths(6);
    assert!(!paths.is_empty());

    for path in &paths {
        assert!(path.nodes.len() >= 2);
        assert!(path.estimated_success_probability > 0.0);
        assert!(path.estimated_success_probability <= 1.0);
    }
}

#[test]
fn paths_sorted_by_success_probability() {
    let coord = build_test_coordinator();
    let paths = coord.find_attack_paths(6);

    for w in paths.windows(2) {
        assert!(w[0].estimated_success_probability >= w[1].estimated_success_probability);
    }
}

#[test]
fn replan_produces_result() {
    let mut coord = build_test_coordinator();
    let result = coord.replan();

    assert!(!result.reasoning.is_empty());
    assert!(!result.goal_stack.is_empty());
}

#[test]
fn blocking_node_removes_from_paths() {
    let mut coord = build_test_coordinator();
    let before = coord.find_attack_paths(6);

    coord.mark_blocked("ssrf-1", "WAF blocked all SSRF payloads");
    let after = coord.find_attack_paths(6);

    let before_with_ssrf = before
        .iter()
        .filter(|p| p.nodes.contains(&"ssrf-1".to_string()))
        .count();
    let after_with_ssrf = after
        .iter()
        .filter(|p| p.nodes.contains(&"ssrf-1".to_string()))
        .count();

    assert!(before_with_ssrf > 0);
    assert_eq!(after_with_ssrf, 0);
}

#[test]
fn replan_after_block_redistributes() {
    let mut coord = build_test_coordinator();
    coord.mark_blocked("ssrf-1", "All SSRF payloads blocked");
    let result = coord.replan();

    let still_has_active = !result.active_paths.is_empty()
        || result.recommended_next_action.is_some()
        || !result.reasoning.is_empty();
    assert!(still_has_active);
}

#[test]
fn mark_goal_achieved() {
    let mut coord = build_test_coordinator();
    coord.mark_achieved(&AttackGoal::InitialAccess, "sqli-1");

    let initial = coord
        .goal_stack()
        .iter()
        .find(|g| g.goal == AttackGoal::InitialAccess)
        .unwrap();
    assert_eq!(initial.status, GoalStatus::Achieved);
    assert_eq!(initial.achieved_via.as_deref(), Some("sqli-1"));
}

#[test]
fn default_goal_stack_present() {
    let coord = MultiVectorCoordinator::new();
    assert!(coord.goal_stack().len() >= 4);
    assert_eq!(coord.goal_stack()[0].goal, AttackGoal::InitialAccess);
}

#[test]
fn custom_goal_stack() {
    let coord = MultiVectorCoordinator::new()
        .with_goals(vec![AttackGoal::InitialAccess, AttackGoal::DenialOfService]);
    assert_eq!(coord.goal_stack().len(), 2);
    assert_eq!(coord.goal_stack()[1].goal, AttackGoal::DenialOfService);
}

#[test]
fn paths_contain_valid_edges() {
    let coord = build_test_coordinator();
    let paths = coord.find_attack_paths(6);

    for path in &paths {
        for edge in &path.edges {
            assert!(path.nodes.contains(&edge.source_id));
            assert!(path.nodes.contains(&edge.target_id));
        }
    }
}

#[test]
fn goals_inferred_from_sqli_path() {
    let coord = build_test_coordinator();
    let paths = coord.find_attack_paths(6);

    let sqli_path = paths
        .iter()
        .find(|p| p.nodes.contains(&"sqli-1".to_string()));
    assert!(sqli_path.is_some());

    let path = sqli_path.unwrap();
    assert!(path.goals_achieved.contains(&AttackGoal::InitialAccess));
}

#[test]
fn centrality_ranking() {
    let coord = build_test_coordinator();
    let ranked = nodes_by_centrality(&coord);
    assert!(!ranked.is_empty());

    assert_eq!(ranked[0].id, "sqli-1");
    for w in ranked.windows(2) {
        assert!(w[0].centrality_score >= w[1].centrality_score);
    }
}

#[test]
fn path_description_contains_vuln_classes() {
    let coord = build_test_coordinator();
    let paths = coord.find_attack_paths(6);

    for path in &paths {
        assert!(!path.description.is_empty());
        assert!(path.description.contains('→') || path.nodes.len() <= 2);
    }
}

#[test]
fn recommended_action_has_priority() {
    let mut coord = build_test_coordinator();
    let result = coord.replan();

    if let Some(action) = &result.recommended_next_action {
        assert!(action.priority > 0.0);
        assert!(!action.target_node.is_empty());
        assert!(!action.rationale.is_empty());
    }
}

#[test]
fn empty_coordinator_no_panic() {
    let mut coord = MultiVectorCoordinator::new();
    let result = coord.replan();
    assert!(result.active_paths.is_empty());
}

#[test]
fn total_difficulty_sums_nodes() {
    let coord = build_test_coordinator();
    let paths = coord.find_attack_paths(6);

    for path in &paths {
        assert!(path.total_difficulty > 0.0);
    }
}

#[test]
fn no_cycles_in_paths() {
    let coord = build_test_coordinator();
    let paths = coord.find_attack_paths(6);

    for path in &paths {
        let unique: HashSet<&String> = path.nodes.iter().collect();
        assert_eq!(unique.len(), path.nodes.len(), "Path contains cycle");
    }
}

use std::collections::HashSet;
