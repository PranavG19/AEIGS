#[cfg(test)]
mod tests {
    use crate::attack_graph::{AttackGraph, AttackNodeType};
    use crate::graph_visualizer::{
        build_visualization, export_vis_d3_json, export_vis_dot, export_vis_mermaid,
        extract_subgraph,
    };

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

    fn diamond_graph() -> AttackGraph {
        let mut g = AttackGraph::new();
        let entry = g.add_node("entry".to_string(), AttackNodeType::EntryPoint);
        let left = g.add_node("left-vuln".to_string(), AttackNodeType::Vulnerability);
        let right = g.add_node(
            "right-boundary".to_string(),
            AttackNodeType::SecurityBoundary,
        );
        let asset = g.add_node("target-db".to_string(), AttackNodeType::Asset);

        g.add_edge(entry, left, 2.0, Some(10));
        g.add_edge(entry, right, 4.0, None);
        g.add_edge(left, asset, 3.0, Some(10));
        g.add_edge(right, asset, 6.0, None);
        g
    }

    #[test]
    fn build_visualization_from_simple_graph() {
        let g = sample_graph();
        let vis = build_visualization(&g);

        assert_eq!(vis.metadata.total_nodes, 4);
        assert_eq!(vis.metadata.total_edges, 3);
        assert_eq!(vis.metadata.entry_point_count, 1);
        assert_eq!(vis.metadata.asset_count, 1);
        assert_eq!(vis.nodes.len(), 4);
        assert_eq!(vis.edges.len(), 3);

        let entry_node = vis.nodes.iter().find(|n| n.id == 0).unwrap();
        assert_eq!(entry_node.node_type, "entry-point");
        assert_eq!(entry_node.color, "#2ecc71");
        assert_eq!(entry_node.shape, "diamond");

        let vuln_node = vis.nodes.iter().find(|n| n.id == 2).unwrap();
        assert_eq!(vuln_node.node_type, "vulnerability");
        assert_eq!(vuln_node.color, "#e74c3c");
        assert_eq!(vuln_node.shape, "octagon");
        assert!(vuln_node.details.is_some());

        let asset_node = vis.nodes.iter().find(|n| n.id == 3).unwrap();
        assert_eq!(asset_node.node_type, "asset");
        assert_eq!(asset_node.color, "#f1c40f");
        assert_eq!(asset_node.shape, "box");
        assert!(asset_node.details.is_some());
    }

    #[test]
    fn layer_assignment_correctness() {
        let g = sample_graph();
        let vis = build_visualization(&g);

        let layer_of = |id: u64| vis.nodes.iter().find(|n| n.id == id).unwrap().layer;

        assert_eq!(layer_of(0), 0, "entry point should be layer 0");
        assert_eq!(layer_of(1), 1, "boundary should be layer 1");
        assert_eq!(layer_of(2), 2, "vulnerability should be layer 2");
        assert_eq!(layer_of(3), 3, "asset should be layer 3");

        assert_eq!(vis.metadata.max_depth, 3);
        assert_eq!(vis.layers.len(), 4);
        assert!(vis.layers[0].contains(&0));
        assert!(vis.layers[3].contains(&3));
    }

    #[test]
    fn layer_assignment_diamond_graph() {
        let g = diamond_graph();
        let vis = build_visualization(&g);

        let layer_of = |id: u64| vis.nodes.iter().find(|n| n.id == id).unwrap().layer;

        assert_eq!(layer_of(0), 0, "entry at layer 0");
        assert_eq!(layer_of(1), 1, "left branch at layer 1");
        assert_eq!(layer_of(2), 1, "right branch at layer 1");
        assert_eq!(layer_of(3), 2, "asset at layer 2");
    }

    #[test]
    fn subgraph_extraction_specific_path() {
        let g = diamond_graph();
        let vis = extract_subgraph(&g, 0, 3);

        assert!(vis.metadata.total_nodes >= 2);
        assert!(vis.metadata.total_edges >= 1);

        let node_ids: Vec<u64> = vis.nodes.iter().map(|n| n.id).collect();
        assert!(node_ids.contains(&0), "subgraph must contain source");
        assert!(node_ids.contains(&3), "subgraph must contain target");

        for edge in &vis.edges {
            assert!(
                node_ids.contains(&edge.source),
                "edge source must be in subgraph"
            );
            assert!(
                node_ids.contains(&edge.target),
                "edge target must be in subgraph"
            );
        }

        assert_eq!(vis.layers.len() as u32, vis.metadata.max_depth + 1);
    }

    #[test]
    fn subgraph_no_path_returns_empty() {
        let mut g = AttackGraph::new();
        let a = g.add_node("isolated-a".to_string(), AttackNodeType::EntryPoint);
        let b = g.add_node("isolated-b".to_string(), AttackNodeType::Asset);

        let vis = extract_subgraph(&g, a, b);
        assert_eq!(vis.metadata.total_nodes, 0);
        assert_eq!(vis.metadata.total_edges, 0);
        assert!(vis.nodes.is_empty());
        assert!(vis.edges.is_empty());
    }

    #[test]
    fn dot_export_format_validation() {
        let g = sample_graph();
        let vis = build_visualization(&g);
        let dot = export_vis_dot(&vis);

        assert!(dot.starts_with("digraph attack_graph {"));
        assert!(dot.ends_with("}\n"));
        assert!(dot.contains("rankdir=TB"));
        assert!(dot.contains("->"));

        assert!(dot.contains("fillcolor=\"#2ecc71\""));
        assert!(dot.contains("shape=diamond"));
        assert!(dot.contains("fillcolor=\"#e74c3c\""));
        assert!(dot.contains("shape=octagon"));
        assert!(dot.contains("fillcolor=\"#f1c40f\""));
        assert!(dot.contains("shape=box"));

        assert!(dot.contains("penwidth="));
    }

    #[test]
    fn d3_json_export_structure() {
        let g = sample_graph();
        let vis = build_visualization(&g);
        let json_str = export_vis_d3_json(&vis);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let nodes = parsed["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 4);

        let first_node = &nodes[0];
        assert!(first_node.get("id").is_some());
        assert!(first_node.get("label").is_some());
        assert!(first_node.get("type").is_some());
        assert!(first_node.get("color").is_some());
        assert!(first_node.get("shape").is_some());
        assert!(first_node.get("layer").is_some());
        assert!(first_node.get("details").is_some());

        let links = parsed["links"].as_array().unwrap();
        assert_eq!(links.len(), 3);

        let first_link = &links[0];
        assert!(first_link.get("source").is_some());
        assert!(first_link.get("target").is_some());
        assert!(first_link.get("edge_type").is_some());
        assert!(first_link.get("color").is_some());
        assert!(first_link.get("width").is_some());

        assert!(parsed.get("layers").is_some());
        assert!(parsed.get("metadata").is_some());

        let meta = &parsed["metadata"];
        assert_eq!(meta["total_nodes"], 4);
        assert_eq!(meta["total_edges"], 3);
    }

    #[test]
    fn mermaid_export_format() {
        let g = sample_graph();
        let vis = build_visualization(&g);
        let mermaid = export_vis_mermaid(&vis);

        assert!(mermaid.starts_with("graph TD\n"));
        assert!(mermaid.contains("-->|"));

        assert!(mermaid.contains("style n0 fill:#2ecc71"));
        assert!(mermaid.contains("style n2 fill:#e74c3c"));
        assert!(mermaid.contains("style n3 fill:#f1c40f"));
    }

    #[test]
    fn empty_graph_produces_empty_visualization() {
        let g = AttackGraph::new();
        let vis = build_visualization(&g);

        assert_eq!(vis.metadata.total_nodes, 0);
        assert_eq!(vis.metadata.total_edges, 0);
        assert_eq!(vis.metadata.max_depth, 0);
        assert_eq!(vis.metadata.entry_point_count, 0);
        assert_eq!(vis.metadata.asset_count, 0);
        assert!(vis.nodes.is_empty());
        assert!(vis.edges.is_empty());

        let dot = export_vis_dot(&vis);
        assert!(dot.starts_with("digraph attack_graph {"));
        assert!(dot.ends_with("}\n"));
        assert!(!dot.contains("->"));

        let json_str = export_vis_d3_json(&vis);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["nodes"].as_array().unwrap().len(), 0);
        assert_eq!(parsed["links"].as_array().unwrap().len(), 0);

        let mermaid = export_vis_mermaid(&vis);
        assert!(mermaid.starts_with("graph TD\n"));
        assert!(!mermaid.contains("-->"));
    }

    #[test]
    fn edge_colors_reflect_difficulty_thresholds() {
        let g = sample_graph();
        let vis = build_visualization(&g);

        let easy_edge = vis.edges.iter().find(|e| e.source == 0).unwrap();
        assert_eq!(easy_edge.color, "#2ecc71", "difficulty 1.0 should be green");

        let medium_edge = vis.edges.iter().find(|e| e.source == 1).unwrap();
        assert_eq!(
            medium_edge.color, "#f39c12",
            "difficulty 5.0 should be orange"
        );

        let hard_edge = vis.edges.iter().find(|e| e.source == 2).unwrap();
        assert_eq!(hard_edge.color, "#e74c3c", "difficulty 8.5 should be red");
    }

    #[test]
    fn edge_width_inversely_proportional_to_difficulty() {
        let g = sample_graph();
        let vis = build_visualization(&g);

        let easy_edge = vis.edges.iter().find(|e| e.source == 0).unwrap();
        let hard_edge = vis.edges.iter().find(|e| e.source == 2).unwrap();

        assert!(
            easy_edge.width > hard_edge.width,
            "easy edge ({}) should be wider than hard edge ({})",
            easy_edge.width,
            hard_edge.width
        );
    }

    #[test]
    fn edge_type_reflects_vulnerability_presence() {
        let g = sample_graph();
        let vis = build_visualization(&g);

        let no_vuln_edge = vis.edges.iter().find(|e| e.source == 0).unwrap();
        assert_eq!(no_vuln_edge.edge_type, "chains-to");

        let vuln_edge = vis.edges.iter().find(|e| e.source == 1).unwrap();
        assert_eq!(vuln_edge.edge_type, "exploits");
    }

    #[test]
    fn vulnerability_and_asset_nodes_have_details() {
        let g = sample_graph();
        let vis = build_visualization(&g);

        let entry = vis.nodes.iter().find(|n| n.id == 0).unwrap();
        assert!(
            entry.details.is_none(),
            "entry point should not have details"
        );

        let boundary = vis.nodes.iter().find(|n| n.id == 1).unwrap();
        assert!(
            boundary.details.is_none(),
            "security boundary should not have details"
        );

        let vuln = vis.nodes.iter().find(|n| n.id == 2).unwrap();
        let vuln_details = vuln.details.as_ref().unwrap();
        assert!(vuln_details.description.contains("Vulnerability"));

        let asset = vis.nodes.iter().find(|n| n.id == 3).unwrap();
        let asset_details = asset.details.as_ref().unwrap();
        assert!(asset_details.description.contains("Data asset"));
    }

    #[test]
    fn dot_export_escapes_quotes_in_labels() {
        let mut g = AttackGraph::new();
        g.add_node(
            "node \"with\" quotes".to_string(),
            AttackNodeType::EntryPoint,
        );

        let vis = build_visualization(&g);
        let dot = export_vis_dot(&vis);

        assert!(dot.contains("node \\\"with\\\" quotes"));
    }
}
