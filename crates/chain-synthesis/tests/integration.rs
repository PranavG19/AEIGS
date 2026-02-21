use aegis_chain_synthesis::attack_graph::{AttackGraph, AttackNodeType};
use aegis_chain_synthesis::graph_export::{analyze_defense_gaps, export_d3_json, export_dot};
use aegis_chain_synthesis::path_analysis::{
    MAX_TOTAL_PATHS, all_simple_paths, betweenness_centrality, graph_influence_ranking,
    shortest_attack_path,
};

fn build_linear_graph() -> AttackGraph {
    let mut g = AttackGraph::new();
    let entry = g.add_node("entry".to_string(), AttackNodeType::EntryPoint);
    let vuln = g.add_node("vuln".to_string(), AttackNodeType::Vulnerability);
    let asset = g.add_node("asset".to_string(), AttackNodeType::Asset);
    g.add_edge(entry, vuln, 2.0, None);
    g.add_edge(vuln, asset, 3.0, Some(1));
    g
}

fn build_diamond_graph() -> AttackGraph {
    let mut g = AttackGraph::new();
    let entry = g.add_node("entry".to_string(), AttackNodeType::EntryPoint);
    let left = g.add_node("left-vuln".to_string(), AttackNodeType::Vulnerability);
    let right = g.add_node("right-vuln".to_string(), AttackNodeType::Vulnerability);
    let asset = g.add_node("asset".to_string(), AttackNodeType::Asset);
    g.add_edge(entry, left, 1.0, None);
    g.add_edge(entry, right, 5.0, None);
    g.add_edge(left, asset, 2.0, Some(1));
    g.add_edge(right, asset, 1.0, Some(2));
    g
}

fn build_chokepoint_graph() -> AttackGraph {
    let mut g = AttackGraph::new();
    let e1 = g.add_node("entry-1".to_string(), AttackNodeType::EntryPoint);
    let e2 = g.add_node("entry-2".to_string(), AttackNodeType::EntryPoint);
    let chokepoint = g.add_node("chokepoint".to_string(), AttackNodeType::Vulnerability);
    let a1 = g.add_node("asset-1".to_string(), AttackNodeType::Asset);
    let a2 = g.add_node("asset-2".to_string(), AttackNodeType::Asset);
    g.add_edge(e1, chokepoint, 1.0, None);
    g.add_edge(e2, chokepoint, 1.0, None);
    g.add_edge(chokepoint, a1, 1.0, None);
    g.add_edge(chokepoint, a2, 1.0, None);
    g
}

#[test]
fn attack_graph_from_findings() {
    let g = build_linear_graph();

    assert_eq!(g.node_count(), 3);
    assert_eq!(g.edge_count(), 2);
    assert_eq!(g.entry_points().len(), 1);
    assert_eq!(g.assets().len(), 1);
    assert_eq!(g.nodes_by_type(AttackNodeType::Vulnerability).len(), 1);

    let vuln_id = g.nodes_by_type(AttackNodeType::Vulnerability)[0];
    let vuln_node = g.node(vuln_id).unwrap();
    assert_eq!(vuln_node.label, "vuln");
    assert_eq!(vuln_node.node_type, AttackNodeType::Vulnerability);
}

#[test]
fn shortest_path_through_vulns() {
    let g = build_diamond_graph();
    let entry = g.entry_points()[0];
    let asset = g.assets()[0];

    let path = shortest_attack_path(&g, entry, asset).unwrap();

    assert_eq!(path.nodes.len(), 3);
    assert_eq!(*path.nodes.first().unwrap(), entry);
    assert_eq!(*path.nodes.last().unwrap(), asset);
    assert!((path.total_difficulty - 3.0).abs() < f64::EPSILON);
}

#[test]
fn all_paths_bounded() {
    let mut g = AttackGraph::new();
    let entry = g.add_node("entry".to_string(), AttackNodeType::EntryPoint);

    let mut intermediates = Vec::new();
    for i in 0..12 {
        let node = g.add_node(format!("vuln-{i}"), AttackNodeType::Vulnerability);
        intermediates.push(node);
    }
    let asset = g.add_node("asset".to_string(), AttackNodeType::Asset);

    for &mid in &intermediates {
        g.add_edge(entry, mid, 1.0, None);
        g.add_edge(mid, asset, 1.0, None);
    }
    for i in 0..intermediates.len() {
        for j in 0..intermediates.len() {
            if i != j {
                g.add_edge(intermediates[i], intermediates[j], 1.0, None);
            }
        }
    }

    let paths = all_simple_paths(&g, entry, asset, 6);
    assert!(paths.len() <= MAX_TOTAL_PATHS);
    assert!(!paths.is_empty());
}

#[test]
fn betweenness_centrality_identifies_bottleneck() {
    let g = build_chokepoint_graph();
    let centrality = betweenness_centrality(&g);

    let chokepoint_id = g.nodes_by_type(AttackNodeType::Vulnerability)[0];
    let chokepoint_score = centrality.get(&chokepoint_id).copied().unwrap_or(0.0);
    assert!(
        chokepoint_score > 0.0,
        "chokepoint should have nonzero centrality, got {chokepoint_score}"
    );

    for (&node_id, &score) in &centrality {
        if node_id != chokepoint_id {
            assert!(
                chokepoint_score >= score,
                "chokepoint centrality {chokepoint_score} should be >= other node centrality {score}"
            );
        }
    }
}

#[test]
fn mitigation_impact_removes_findings() {
    let g = build_chokepoint_graph();
    let chokepoint_id = g.nodes_by_type(AttackNodeType::Vulnerability)[0];
    let chokepoint_idx = g.node_index(chokepoint_id).unwrap();

    let result = g.estimated_mitigation_impact(chokepoint_idx);

    assert_eq!(result.removed_findings.len(), 2);
    assert_eq!(result.findings_remaining, 0);
    assert!((result.impact_score - 1.0).abs() < f64::EPSILON);
}

#[test]
fn mitigation_ranking_orders_by_value() {
    let mut g = AttackGraph::new();
    let entry = g.add_node("entry".to_string(), AttackNodeType::EntryPoint);
    let high_value = g.add_node("high-value".to_string(), AttackNodeType::Vulnerability);
    let low_value = g.add_node("low-value".to_string(), AttackNodeType::Vulnerability);
    let asset1 = g.add_node("asset-1".to_string(), AttackNodeType::Asset);
    let asset2 = g.add_node("asset-2".to_string(), AttackNodeType::Asset);
    let asset3 = g.add_node("asset-3".to_string(), AttackNodeType::Asset);

    g.add_edge(entry, high_value, 1.0, None);
    g.add_edge(entry, low_value, 1.0, None);
    g.add_edge(high_value, asset1, 1.0, None);
    g.add_edge(high_value, asset2, 1.0, None);
    g.add_edge(high_value, asset3, 1.0, None);
    g.add_edge(low_value, asset1, 1.0, None);

    let ranking = graph_influence_ranking(&g);
    assert!(!ranking.is_empty());
    assert!(
        ranking[0].1.impact_score >= ranking.last().unwrap().1.impact_score,
        "ranking should be sorted by descending impact_score"
    );
}

#[test]
fn defense_gap_finds_unprotected_entries() {
    let mut g = AttackGraph::new();
    let protected_entry = g.add_node("protected-entry".to_string(), AttackNodeType::EntryPoint);
    let unprotected_entry = g.add_node("unprotected-entry".to_string(), AttackNodeType::EntryPoint);
    let boundary = g.add_node("waf".to_string(), AttackNodeType::SecurityBoundary);
    let asset = g.add_node("asset".to_string(), AttackNodeType::Asset);

    g.add_edge(protected_entry, boundary, 1.0, None);
    g.add_edge(boundary, asset, 1.0, None);
    g.add_edge(unprotected_entry, asset, 2.0, None);

    let report = analyze_defense_gaps(&g);

    assert_eq!(report.total_entry_points, 2);
    assert_eq!(report.unprotected_entry_points.len(), 1);
    assert!(report.unprotected_entry_points.contains(&unprotected_entry));
}

#[test]
fn defense_gap_all_protected() {
    let mut g = AttackGraph::new();
    let entry = g.add_node("entry".to_string(), AttackNodeType::EntryPoint);
    let boundary = g.add_node("firewall".to_string(), AttackNodeType::SecurityBoundary);
    let asset = g.add_node("db".to_string(), AttackNodeType::Asset);

    g.add_edge(entry, boundary, 1.0, None);
    g.add_edge(boundary, asset, 1.0, None);

    let report = analyze_defense_gaps(&g);

    assert!(
        report.unprotected_entry_points.is_empty(),
        "all entry points are adjacent to a boundary"
    );
    assert!(
        report.unprotected_assets.is_empty(),
        "all assets are adjacent to a boundary"
    );
}

#[test]
fn dot_export_valid_graphviz() {
    let g = build_linear_graph();
    let dot = export_dot(&g);

    assert!(
        dot.starts_with("digraph"),
        "DOT output must start with 'digraph'"
    );
    assert!(dot.contains("entry"));
    assert!(dot.contains("vuln"));
    assert!(dot.contains("asset"));
    assert!(dot.contains("->"), "DOT output must contain edges");
    assert!(
        dot.ends_with("}\n"),
        "DOT output must end with closing brace"
    );
}

#[test]
fn dot_export_escapes_special_chars() {
    let mut g = AttackGraph::new();
    g.add_node(
        "node \"with\" quotes".to_string(),
        AttackNodeType::EntryPoint,
    );
    g.add_node("node <with> angles".to_string(), AttackNodeType::Asset);

    let dot = export_dot(&g);

    assert!(
        !dot.contains("\"with\""),
        "raw unescaped quotes should not appear in DOT output"
    );
    assert!(
        dot.contains("\\\"with\\\""),
        "quotes should be backslash-escaped"
    );
}

#[test]
fn d3_json_export_structure() {
    let g = build_linear_graph();
    let json_str = export_d3_json(&g);
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    assert!(
        parsed.get("nodes").is_some(),
        "D3 JSON must have 'nodes' array"
    );
    assert!(
        parsed.get("links").is_some(),
        "D3 JSON must have 'links' array"
    );

    let nodes = parsed["nodes"].as_array().unwrap();
    let links = parsed["links"].as_array().unwrap();

    assert_eq!(nodes.len(), 3);
    assert_eq!(links.len(), 2);

    for node in nodes {
        assert!(node.get("id").is_some());
        assert!(node.get("label").is_some());
        assert!(node.get("type").is_some());
        assert!(node.get("color").is_some());
    }

    for link in links {
        assert!(link.get("source").is_some());
        assert!(link.get("target").is_some());
        assert!(link.get("difficulty").is_some());
    }
}
