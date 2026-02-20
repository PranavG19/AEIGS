#[cfg(test)]
mod tests {
    use crate::attack_graph::{AttackGraph, AttackNodeType};
    use crate::graph_export::{analyze_defense_gaps, export_d3_json, export_dot};

    fn sample_graph() -> AttackGraph {
        let mut g = AttackGraph::new();
        let entry = g.add_node("/api/users".to_string(), AttackNodeType::EntryPoint);
        let boundary = g.add_node("WAF".to_string(), AttackNodeType::SecurityBoundary);
        let vuln = g.add_node(
            "SQLi-CVE-2024-001".to_string(),
            AttackNodeType::Vulnerability,
        );
        let asset = g.add_node("users_db".to_string(), AttackNodeType::Asset);

        g.add_edge(entry, boundary, 1.0, None);
        g.add_edge(boundary, vuln, 5.0, Some(42));
        g.add_edge(vuln, asset, 8.5, Some(42));
        g
    }

    #[test]
    fn dot_contains_node_colors_and_shapes() {
        let g = sample_graph();
        let dot = export_dot(&g);

        assert!(dot.contains("fillcolor=\"green\""));
        assert!(dot.contains("shape=diamond"));
        assert!(dot.contains("fillcolor=\"blue\""));
        assert!(dot.contains("shape=hexagon"));
        assert!(dot.contains("fillcolor=\"red\""));
        assert!(dot.contains("shape=octagon"));
        assert!(dot.contains("fillcolor=\"gold\""));
        assert!(dot.contains("shape=box"));
    }

    #[test]
    fn dot_contains_node_labels() {
        let g = sample_graph();
        let dot = export_dot(&g);

        assert!(dot.contains("/api/users"));
        assert!(dot.contains("WAF"));
        assert!(dot.contains("SQLi-CVE-2024-001"));
        assert!(dot.contains("users_db"));
    }

    #[test]
    fn dot_contains_edge_labels_and_colors() {
        let g = sample_graph();
        let dot = export_dot(&g);

        assert!(dot.contains("label=\"1.0\""));
        assert!(dot.contains("label=\"5.0\""));
        assert!(dot.contains("label=\"8.5\""));

        assert!(dot.contains("color=\"green\""));
        assert!(dot.contains("color=\"orange\""));
        assert!(dot.contains("color=\"red\""));
    }

    #[test]
    fn dot_is_valid_digraph() {
        let g = sample_graph();
        let dot = export_dot(&g);

        assert!(dot.starts_with("digraph attack_graph {"));
        assert!(dot.ends_with("}\n"));
        assert!(dot.contains("->"));
    }

    #[test]
    fn d3_json_parses_with_expected_structure() {
        let g = sample_graph();
        let json_str = export_d3_json(&g);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let nodes = parsed["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 4);

        let links = parsed["links"].as_array().unwrap();
        assert_eq!(links.len(), 3);
    }

    #[test]
    fn d3_json_node_fields() {
        let g = sample_graph();
        let json_str = export_d3_json(&g);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let nodes = parsed["nodes"].as_array().unwrap();
        let entry_node = &nodes[0];
        assert_eq!(entry_node["id"], 0);
        assert_eq!(entry_node["label"], "/api/users");
        assert_eq!(entry_node["type"], "EntryPoint");
        assert_eq!(entry_node["color"], "#2ecc71");
    }

    #[test]
    fn d3_json_link_fields() {
        let g = sample_graph();
        let json_str = export_d3_json(&g);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let links = parsed["links"].as_array().unwrap();
        let first_link = &links[0];
        assert!(first_link.get("source").is_some());
        assert!(first_link.get("target").is_some());
        assert!(first_link.get("difficulty").is_some());
        assert!(first_link.get("vulnerability_id").is_some());
        assert!(first_link.get("color").is_some());
    }

    #[test]
    fn d3_json_vulnerability_id_present_when_set() {
        let g = sample_graph();
        let json_str = export_d3_json(&g);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let links = parsed["links"].as_array().unwrap();
        let link_with_vuln = links
            .iter()
            .find(|l| !l["vulnerability_id"].is_null())
            .unwrap();
        assert_eq!(link_with_vuln["vulnerability_id"], 42);
    }

    #[test]
    fn empty_graph_dot_is_valid() {
        let g = AttackGraph::new();
        let dot = export_dot(&g);

        assert!(dot.starts_with("digraph attack_graph {"));
        assert!(dot.ends_with("}\n"));
        assert!(!dot.contains("->"));
    }

    #[test]
    fn empty_graph_d3_json_is_valid() {
        let g = AttackGraph::new();
        let json_str = export_d3_json(&g);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["nodes"].as_array().unwrap().len(), 0);
        assert_eq!(parsed["links"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn defense_gaps_finds_unprotected_entry_points() {
        let mut g = AttackGraph::new();
        let ep1 = g.add_node("/login".to_string(), AttackNodeType::EntryPoint);
        let ep2 = g.add_node("/admin".to_string(), AttackNodeType::EntryPoint);
        let boundary = g.add_node("WAF".to_string(), AttackNodeType::SecurityBoundary);
        let asset = g.add_node("db".to_string(), AttackNodeType::Asset);

        g.add_edge(ep1, boundary, 1.0, None);
        g.add_edge(boundary, asset, 2.0, None);

        let report = analyze_defense_gaps(&g);

        assert_eq!(report.total_entry_points, 2);
        assert_eq!(report.unprotected_entry_points, vec![ep2]);
    }

    #[test]
    fn defense_gaps_finds_unprotected_assets() {
        let mut g = AttackGraph::new();
        let entry = g.add_node("/api".to_string(), AttackNodeType::EntryPoint);
        let boundary = g.add_node("WAF".to_string(), AttackNodeType::SecurityBoundary);
        let asset1 = g.add_node("protected_db".to_string(), AttackNodeType::Asset);
        let asset2 = g.add_node("exposed_db".to_string(), AttackNodeType::Asset);

        g.add_edge(entry, boundary, 1.0, None);
        g.add_edge(boundary, asset1, 2.0, None);
        g.add_edge(entry, asset2, 3.0, None);

        let report = analyze_defense_gaps(&g);

        assert_eq!(report.total_assets, 2);
        assert_eq!(report.unprotected_assets, vec![asset2]);
    }

    #[test]
    fn defense_gaps_fully_protected_graph() {
        let mut g = AttackGraph::new();
        let entry = g.add_node("/api".to_string(), AttackNodeType::EntryPoint);
        let boundary = g.add_node("WAF".to_string(), AttackNodeType::SecurityBoundary);
        let asset = g.add_node("db".to_string(), AttackNodeType::Asset);

        g.add_edge(entry, boundary, 1.0, None);
        g.add_edge(boundary, asset, 2.0, None);

        let report = analyze_defense_gaps(&g);

        assert!(report.unprotected_entry_points.is_empty());
        assert!(report.unprotected_assets.is_empty());
        assert_eq!(report.total_entry_points, 1);
        assert_eq!(report.total_assets, 1);
    }

    #[test]
    fn defense_gaps_empty_graph() {
        let g = AttackGraph::new();
        let report = analyze_defense_gaps(&g);

        assert!(report.unprotected_entry_points.is_empty());
        assert!(report.unprotected_assets.is_empty());
        assert_eq!(report.total_entry_points, 0);
        assert_eq!(report.total_assets, 0);
    }

    #[test]
    fn dot_escapes_quotes_in_labels() {
        let mut g = AttackGraph::new();
        g.add_node(
            "node \"with\" quotes".to_string(),
            AttackNodeType::EntryPoint,
        );

        let dot = export_dot(&g);
        assert!(dot.contains("node \\\"with\\\" quotes"));
    }

    #[test]
    fn d3_json_difficulty_colors_match_thresholds() {
        let mut g = AttackGraph::new();
        let a = g.add_node("a".to_string(), AttackNodeType::EntryPoint);
        let b = g.add_node("b".to_string(), AttackNodeType::Vulnerability);
        let c = g.add_node("c".to_string(), AttackNodeType::Asset);

        g.add_edge(a, b, 2.0, None);
        g.add_edge(b, c, 8.0, None);

        let json_str = export_d3_json(&g);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let links = parsed["links"].as_array().unwrap();

        let easy_link = links.iter().find(|l| l["difficulty"] == 2.0).unwrap();
        assert_eq!(easy_link["color"], "#2ecc71");

        let hard_link = links.iter().find(|l| l["difficulty"] == 8.0).unwrap();
        assert_eq!(hard_link["color"], "#e74c3c");
    }
}
