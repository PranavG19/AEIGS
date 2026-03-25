use crate::attack_graph::{AttackGraph, AttackNodeType};
use crate::remediation_prioritizer::RemediationPrioritizer;

fn build_single_path_graph() -> AttackGraph {
    let mut g = AttackGraph::new();
    let entry = g.add_node("Entry".into(), AttackNodeType::EntryPoint);
    let vuln = g.add_node("SQLi".into(), AttackNodeType::Vulnerability);
    let asset = g.add_node("Database".into(), AttackNodeType::Asset);

    g.add_edge(entry, vuln, 2.0, None);
    g.add_edge(vuln, asset, 3.0, None);
    g
}

fn build_multi_path_graph() -> AttackGraph {
    let mut g = AttackGraph::new();
    let entry = g.add_node("Entry".into(), AttackNodeType::EntryPoint);
    let vuln_a = g.add_node("SQLi".into(), AttackNodeType::Vulnerability);
    let vuln_b = g.add_node("XSS".into(), AttackNodeType::Vulnerability);
    let vuln_c = g.add_node("SSRF".into(), AttackNodeType::Vulnerability);
    let asset = g.add_node("Database".into(), AttackNodeType::Asset);

    // Three parallel paths
    g.add_edge(entry, vuln_a, 2.0, None);
    g.add_edge(entry, vuln_b, 3.0, None);
    g.add_edge(entry, vuln_c, 4.0, None);
    g.add_edge(vuln_a, asset, 1.0, None);
    g.add_edge(vuln_b, asset, 1.0, None);
    g.add_edge(vuln_c, asset, 1.0, None);
    g
}

fn build_bottleneck_graph() -> AttackGraph {
    let mut g = AttackGraph::new();
    let e1 = g.add_node("Entry1".into(), AttackNodeType::EntryPoint);
    let e2 = g.add_node("Entry2".into(), AttackNodeType::EntryPoint);
    let bottleneck = g.add_node("Auth Bypass".into(), AttackNodeType::Vulnerability);
    let side = g.add_node("XSS".into(), AttackNodeType::Vulnerability);
    let asset = g.add_node("Admin Panel".into(), AttackNodeType::Asset);

    g.add_edge(e1, bottleneck, 2.0, None);
    g.add_edge(e2, bottleneck, 3.0, None);
    g.add_edge(bottleneck, asset, 1.0, None);
    g.add_edge(e1, side, 5.0, None);
    g.add_edge(side, asset, 2.0, None);
    g
}

#[test]
fn single_vuln_gets_priority_one() {
    let g = build_single_path_graph();
    let prioritizer = RemediationPrioritizer::new(&g);
    let plan = prioritizer.prioritize();

    assert_eq!(plan.items.len(), 1);
    assert_eq!(plan.items[0].priority_rank, 1);
    assert_eq!(plan.items[0].label, "SQLi");
    assert_eq!(plan.items[0].attack_paths_removed, 1);
    assert!((plan.items[0].risk_reduction_pct - 100.0).abs() < f64::EPSILON);
}

#[test]
fn parallel_paths_all_equally_ranked() {
    let g = build_multi_path_graph();
    let prioritizer = RemediationPrioritizer::new(&g);
    let plan = prioritizer.prioritize();

    assert_eq!(plan.items.len(), 3);
    assert_eq!(plan.total_paths_before, 3);

    for item in &plan.items {
        assert_eq!(item.attack_paths_removed, 1);
    }
}

#[test]
fn bottleneck_gets_highest_priority() {
    let g = build_bottleneck_graph();
    let prioritizer = RemediationPrioritizer::new(&g);
    let plan = prioritizer.prioritize();

    assert_eq!(plan.items[0].label, "Auth Bypass");
    assert!(plan.items[0].attack_paths_removed >= 2);
    assert!(plan.items[0].risk_reduction_pct > plan.items[1].risk_reduction_pct);
}

#[test]
fn optimal_fix_order_starts_with_bottleneck() {
    let g = build_bottleneck_graph();
    let prioritizer = RemediationPrioritizer::new(&g);
    let plan = prioritizer.prioritize();

    assert!(!plan.optimal_fix_order.is_empty());
    let first_fix = plan.optimal_fix_order[0];
    let first_label = &plan
        .items
        .iter()
        .find(|i| i.node_id == first_fix)
        .unwrap()
        .label;
    assert_eq!(first_label, "Auth Bypass");
}

#[test]
fn cumulative_reduction_is_monotonic() {
    let g = build_bottleneck_graph();
    let prioritizer = RemediationPrioritizer::new(&g);
    let plan = prioritizer.prioritize();

    for i in 1..plan.cumulative_risk_reduction.len() {
        assert!(plan.cumulative_risk_reduction[i] >= plan.cumulative_risk_reduction[i - 1]);
    }
}

#[test]
fn cumulative_reduction_reaches_100() {
    let g = build_bottleneck_graph();
    let prioritizer = RemediationPrioritizer::new(&g);
    let plan = prioritizer.prioritize();

    if let Some(&last) = plan.cumulative_risk_reduction.last() {
        assert!((last - 100.0).abs() < f64::EPSILON);
    }
}

#[test]
fn empty_graph_empty_plan() {
    let g = AttackGraph::new();
    let prioritizer = RemediationPrioritizer::new(&g);
    let plan = prioritizer.prioritize();

    assert!(plan.items.is_empty());
    assert_eq!(plan.total_paths_before, 0);
}

#[test]
fn no_vulns_no_items() {
    let mut g = AttackGraph::new();
    g.add_node("Entry".into(), AttackNodeType::EntryPoint);
    g.add_node("Asset".into(), AttackNodeType::Asset);
    g.add_edge(0, 1, 1.0, None);

    let prioritizer = RemediationPrioritizer::new(&g);
    let plan = prioritizer.prioritize();

    assert!(plan.items.is_empty());
}

#[test]
fn custom_depth_works() {
    let g = build_single_path_graph();
    let prioritizer = RemediationPrioritizer::new(&g).with_max_depth(4);
    let plan = prioritizer.prioritize();

    assert_eq!(plan.items.len(), 1);
}
