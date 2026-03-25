use crate::attack_graph::{AttackGraph, AttackNodeType};
use crate::impact_propagation::{ImpactPropagationEngine, ImpactType};
use std::collections::HashSet;

fn build_chain_graph() -> AttackGraph {
    let mut g = AttackGraph::new();
    let entry = g.add_node("Entry".into(), AttackNodeType::EntryPoint);
    let vuln_a = g.add_node("SQLi".into(), AttackNodeType::Vulnerability);
    let vuln_b = g.add_node("XSS".into(), AttackNodeType::Vulnerability);
    let asset = g.add_node("Database".into(), AttackNodeType::Asset);

    g.add_edge(entry, vuln_a, 2.0, None);
    g.add_edge(vuln_a, vuln_b, 1.0, None);
    g.add_edge(vuln_b, asset, 3.0, None);
    g
}

fn build_wide_graph() -> AttackGraph {
    let mut g = AttackGraph::new();
    let entry = g.add_node("Entry".into(), AttackNodeType::EntryPoint);
    let v1 = g.add_node("Vuln1".into(), AttackNodeType::Vulnerability);
    let v2 = g.add_node("Vuln2".into(), AttackNodeType::Vulnerability);
    let v3 = g.add_node("Vuln3".into(), AttackNodeType::Vulnerability);
    let a1 = g.add_node("Asset1".into(), AttackNodeType::Asset);
    let a2 = g.add_node("Asset2".into(), AttackNodeType::Asset);

    g.add_edge(entry, v1, 1.0, None);
    g.add_edge(entry, v2, 2.0, None);
    g.add_edge(entry, v3, 3.0, None);
    g.add_edge(v1, a1, 1.0, None);
    g.add_edge(v2, a2, 1.0, None);
    g
}

#[test]
fn propagate_from_entry_reaches_all() {
    let g = build_chain_graph();
    let engine = ImpactPropagationEngine::new(&g);
    let report = engine.propagate(0).unwrap();

    assert_eq!(report.origin_node, 0);
    assert_eq!(report.blast_radius, 3);
    assert_eq!(report.impacted_assets.len(), 1);
    assert!(report.impacted_assets.contains(&3));
}

#[test]
fn propagate_from_middle_reaches_downstream() {
    let g = build_chain_graph();
    let engine = ImpactPropagationEngine::new(&g);
    let report = engine.propagate(1).unwrap();

    assert!(report.reachable_nodes.contains(&2));
    assert!(report.reachable_nodes.contains(&3));
    assert!(!report.reachable_nodes.contains(&0));
}

#[test]
fn shared_credentials_expand_blast_radius() {
    let g = build_wide_graph();
    let mut engine = ImpactPropagationEngine::new(&g);

    let mut cred_group = HashSet::new();
    cred_group.insert(1); // Vuln1
    cred_group.insert(2); // Vuln2
    engine.add_credential_group("shared_db_cred".into(), cred_group);

    let report = engine.propagate(1).unwrap();
    assert!(report.reachable_nodes.contains(&2));
    assert!(report.reachable_nodes.contains(&4)); // Asset1

    let cred_steps: Vec<_> = report
        .propagation_steps
        .iter()
        .filter(|s| s.impact_type == ImpactType::SharedCredential)
        .collect();
    assert!(!cred_steps.is_empty());
}

#[test]
fn trust_relationship_enables_lateral_movement() {
    let g = build_wide_graph();
    let mut engine = ImpactPropagationEngine::new(&g);
    engine.add_trust_relationship(1, 3);

    let report = engine.propagate(1).unwrap();
    assert!(report.reachable_nodes.contains(&3));

    let trust_steps: Vec<_> = report
        .propagation_steps
        .iter()
        .filter(|s| s.impact_type == ImpactType::TrustRelationship)
        .collect();
    assert!(!trust_steps.is_empty());
}

#[test]
fn nonexistent_node_returns_none() {
    let g = build_chain_graph();
    let engine = ImpactPropagationEngine::new(&g);
    assert!(engine.propagate(999).is_none());
}

#[test]
fn blast_radius_ranking_orders_by_impact() {
    let g = build_wide_graph();
    let engine = ImpactPropagationEngine::new(&g);
    let ranking = engine.blast_radius_ranking();

    assert!(!ranking.is_empty());
    for i in 1..ranking.len() {
        assert!(ranking[i - 1].1 >= ranking[i].1);
    }
}

#[test]
fn propagation_steps_have_valid_hop_distances() {
    let g = build_chain_graph();
    let engine = ImpactPropagationEngine::new(&g);
    let report = engine.propagate(0).unwrap();

    for step in &report.propagation_steps {
        assert!(step.hop_distance >= 1);
        assert!(step.cumulative_difficulty >= 0.0);
    }
    assert!(report.max_hop_distance >= 1);
}

#[test]
fn risk_score_is_positive() {
    let g = build_chain_graph();
    let engine = ImpactPropagationEngine::new(&g);
    let report = engine.propagate(0).unwrap();

    assert!(report.total_risk_score > 0.0);
}

#[test]
fn impact_type_display() {
    assert_eq!(format!("{}", ImpactType::DirectExploit), "Direct Exploit");
    assert_eq!(
        format!("{}", ImpactType::SharedCredential),
        "Shared Credential"
    );
    assert_eq!(
        format!("{}", ImpactType::LateralMovement),
        "Lateral Movement"
    );
}
