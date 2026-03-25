use crate::attack_graph::{AttackGraph, AttackNodeType};
use crate::kill_chain_mapper::{KillChainMapper, KillChainPhase};

fn build_full_chain_graph() -> AttackGraph {
    let mut g = AttackGraph::new();
    let recon = g.add_node("Port Scan Recon".into(), AttackNodeType::EntryPoint);
    let weapon = g.add_node("Payload Craft".into(), AttackNodeType::Vulnerability);
    let deliver = g.add_node("Phishing Email".into(), AttackNodeType::EntryPoint);
    let exploit = g.add_node("SQLi Exploit".into(), AttackNodeType::Vulnerability);
    let install = g.add_node("Webshell Persist".into(), AttackNodeType::SecurityBoundary);
    let c2 = g.add_node("C2 Beacon".into(), AttackNodeType::SecurityBoundary);
    let action = g.add_node("Database Dump".into(), AttackNodeType::Asset);

    g.add_edge(recon, weapon, 1.0, None);
    g.add_edge(weapon, deliver, 2.0, None);
    g.add_edge(deliver, exploit, 3.0, None);
    g.add_edge(exploit, install, 2.0, None);
    g.add_edge(install, c2, 1.0, None);
    g.add_edge(c2, action, 1.0, None);
    g
}

fn build_partial_graph() -> AttackGraph {
    let mut g = AttackGraph::new();
    let entry = g.add_node("Web Entry".into(), AttackNodeType::EntryPoint);
    let vuln = g.add_node("XSS".into(), AttackNodeType::Vulnerability);
    let asset = g.add_node("Session Token".into(), AttackNodeType::Asset);

    g.add_edge(entry, vuln, 2.0, None);
    g.add_edge(vuln, asset, 3.0, None);
    g
}

#[test]
fn full_chain_covers_all_phases() {
    let g = build_full_chain_graph();
    let mapper = KillChainMapper::new(&g);
    let report = mapper.map();

    assert_eq!(report.achievable_phases.len(), 7);
    assert!((report.coverage_ratio - 1.0).abs() < f64::EPSILON);
}

#[test]
fn partial_graph_shows_gaps() {
    let g = build_partial_graph();
    let mapper = KillChainMapper::new(&g);
    let report = mapper.map();

    assert!(report.coverage_ratio < 1.0);
    assert!(report.achievable_phases.len() < 7);
}

#[test]
fn phase_coverage_maps_nodes_correctly() {
    let g = build_full_chain_graph();
    let mapper = KillChainMapper::new(&g);
    let report = mapper.map();

    assert!(
        report
            .phase_coverage
            .contains_key(&KillChainPhase::Reconnaissance)
    );
    assert!(
        report
            .phase_coverage
            .contains_key(&KillChainPhase::ActionsOnObjectives)
    );
}

#[test]
fn longest_chain_computed_correctly() {
    let g = build_full_chain_graph();
    let mapper = KillChainMapper::new(&g);
    let report = mapper.map();

    assert!(report.longest_chain_length >= 3);
}

#[test]
fn custom_rule_overrides_default() {
    let g = build_partial_graph();
    let mut mapper = KillChainMapper::new(&g);
    mapper.add_rule(|label, _| {
        if label.to_lowercase().contains("xss") {
            Some(KillChainPhase::CommandAndControl)
        } else {
            None
        }
    });

    let report = mapper.map();
    let xss_mappings: Vec<_> = report
        .mappings
        .iter()
        .filter(|m| m.label == "XSS")
        .collect();
    assert!(!xss_mappings.is_empty());
    assert_eq!(xss_mappings[0].phase, KillChainPhase::CommandAndControl);
}

#[test]
fn empty_graph_produces_empty_report() {
    let g = AttackGraph::new();
    let mapper = KillChainMapper::new(&g);
    let report = mapper.map();

    assert!(report.mappings.is_empty());
    assert!(report.achievable_phases.is_empty());
    assert_eq!(report.coverage_ratio, 0.0);
    assert_eq!(report.longest_chain_length, 0);
}

#[test]
fn kill_chain_phase_display() {
    assert_eq!(
        format!("{}", KillChainPhase::Reconnaissance),
        "Reconnaissance"
    );
    assert_eq!(
        format!("{}", KillChainPhase::CommandAndControl),
        "Command & Control"
    );
    assert_eq!(
        format!("{}", KillChainPhase::ActionsOnObjectives),
        "Actions on Objectives"
    );
}

#[test]
fn mappings_have_nonzero_confidence() {
    let g = build_full_chain_graph();
    let mapper = KillChainMapper::new(&g);
    let report = mapper.map();

    for m in &report.mappings {
        assert!(m.confidence > 0.0);
        assert!(m.confidence <= 1.0);
        assert!(!m.rationale.is_empty());
    }
}
