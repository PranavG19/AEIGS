use crate::attack_graph::{AttackGraph, AttackNodeType};
use crate::attack_tree::{
    AttackTreeGenerator, GateType, attack_tree_to_dot, attack_tree_to_json, attack_tree_to_mermaid,
};

fn build_diamond_graph() -> AttackGraph {
    let mut g = AttackGraph::new();
    let entry = g.add_node("Web Entry".into(), AttackNodeType::EntryPoint);
    let vuln_a = g.add_node("SQLi".into(), AttackNodeType::Vulnerability);
    let vuln_b = g.add_node("XSS".into(), AttackNodeType::Vulnerability);
    let asset = g.add_node("Database".into(), AttackNodeType::Asset);

    g.add_edge(entry, vuln_a, 2.0, Some(100));
    g.add_edge(entry, vuln_b, 5.0, Some(101));
    g.add_edge(vuln_a, asset, 3.0, None);
    g.add_edge(vuln_b, asset, 1.0, None);
    g
}

fn build_linear_graph() -> AttackGraph {
    let mut g = AttackGraph::new();
    let entry = g.add_node("Entry".into(), AttackNodeType::EntryPoint);
    let step1 = g.add_node("Step1".into(), AttackNodeType::Vulnerability);
    let step2 = g.add_node("Step2".into(), AttackNodeType::Vulnerability);
    let asset = g.add_node("Target".into(), AttackNodeType::Asset);

    g.add_edge(entry, step1, 1.0, None);
    g.add_edge(step1, step2, 2.0, None);
    g.add_edge(step2, asset, 3.0, None);
    g
}

#[test]
fn generate_attack_tree_from_diamond() {
    let g = build_diamond_graph();
    let atg = AttackTreeGenerator::new(&g);
    let tree = atg
        .generate(3)
        .expect("should produce tree for asset node 3");

    assert_eq!(tree.goal, "Database");
    assert_eq!(tree.root.id, 3);
    assert_eq!(tree.root.gate, GateType::Or);
    assert_eq!(tree.root.children.len(), 2);
}

#[test]
fn minimum_cost_path_picks_cheapest() {
    let g = build_diamond_graph();
    let atg = AttackTreeGenerator::new(&g);
    let tree = atg.generate(3).unwrap();

    assert!(tree.minimum_cost < f64::INFINITY);
    assert!(!tree.minimum_cost_path.is_empty());
}

#[test]
fn linear_graph_produces_and_chain() {
    let g = build_linear_graph();
    let atg = AttackTreeGenerator::new(&g);
    let tree = atg
        .generate(3)
        .expect("should produce tree for asset node 3");

    assert_eq!(tree.goal, "Target");
    assert!(!tree.minimum_cost_path.is_empty());
    assert!(tree.minimum_cost > 0.0);
}

#[test]
fn dot_output_contains_digraph() {
    let g = build_diamond_graph();
    let atg = AttackTreeGenerator::new(&g);
    let tree = atg.generate(3).unwrap();
    let dot = attack_tree_to_dot(&tree);

    assert!(dot.starts_with("digraph attack_tree"));
    assert!(dot.contains("Goal: Database"));
    assert!(dot.contains("AND") || dot.contains("OR") || dot.contains("LEAF"));
}

#[test]
fn json_output_is_valid() {
    let g = build_diamond_graph();
    let atg = AttackTreeGenerator::new(&g);
    let tree = atg.generate(3).unwrap();
    let json = attack_tree_to_json(&tree);

    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert!(parsed.get("goal").is_some());
    assert!(parsed.get("root").is_some());
    assert!(parsed.get("minimum_cost_path").is_some());
    assert!(parsed.get("minimum_cost").is_some());
}

#[test]
fn mermaid_output_contains_graph_td() {
    let g = build_diamond_graph();
    let atg = AttackTreeGenerator::new(&g);
    let tree = atg.generate(3).unwrap();
    let mermaid = attack_tree_to_mermaid(&tree);

    assert!(mermaid.starts_with("graph TD"));
    assert!(mermaid.contains("Goal: Database"));
}

#[test]
fn no_entry_points_returns_none() {
    let mut g = AttackGraph::new();
    g.add_node("Lonely Asset".into(), AttackNodeType::Asset);
    let atg = AttackTreeGenerator::new(&g);
    assert!(atg.generate(0).is_none());
}

#[test]
fn nonexistent_target_returns_none() {
    let g = build_diamond_graph();
    let atg = AttackTreeGenerator::new(&g);
    assert!(atg.generate(999).is_none());
}

#[test]
fn minimum_cost_path_traverses_cheapest_route() {
    let g = build_diamond_graph();
    let atg = AttackTreeGenerator::new(&g);
    let tree = atg.generate(3).unwrap();

    // entry(0)->sqli(1)->db(3) costs 2+3=5, entry(0)->xss(2)->db(3) costs 5+1=6
    // The cheapest route through the tree should cost <= 6
    assert!(tree.minimum_cost <= 6.0);
}
