#[cfg(test)]
mod tests {
    use crate::attack_graph::{AttackGraph, AttackNodeType};

    #[test]
    fn add_nodes_and_edges() {
        let mut graph = AttackGraph::new();
        let n1 = graph.add_node("entry".to_string(), AttackNodeType::EntryPoint);
        let n2 = graph.add_node("vuln".to_string(), AttackNodeType::Vulnerability);
        graph.add_edge(n1, n2, 0.5, Some(100));

        assert_eq!(graph.node_count(), 2);
        assert_eq!(graph.edge_count(), 1);
    }

    #[test]
    fn node_retrieval() {
        let mut graph = AttackGraph::new();
        let id = graph.add_node("db".to_string(), AttackNodeType::Asset);

        let node = graph.node(id).unwrap();
        assert_eq!(node.label, "db");
        assert_eq!(node.node_type, AttackNodeType::Asset);
        assert!(graph.node(999).is_none());
    }

    #[test]
    fn outgoing_edges() {
        let mut graph = AttackGraph::new();
        let a = graph.add_node("a".to_string(), AttackNodeType::EntryPoint);
        let b = graph.add_node("b".to_string(), AttackNodeType::Vulnerability);
        let c = graph.add_node("c".to_string(), AttackNodeType::Asset);

        graph.add_edge(a, b, 0.3, None);
        graph.add_edge(a, c, 0.7, None);

        let edges = graph.outgoing_edges(a);
        assert_eq!(edges.len(), 2);
        assert_eq!(graph.outgoing_edges(c).len(), 0);
    }

    #[test]
    fn entry_points_and_assets() {
        let mut graph = AttackGraph::new();
        graph.add_node("entry1".to_string(), AttackNodeType::EntryPoint);
        graph.add_node("entry2".to_string(), AttackNodeType::EntryPoint);
        graph.add_node("vuln".to_string(), AttackNodeType::Vulnerability);
        graph.add_node("db".to_string(), AttackNodeType::Asset);

        assert_eq!(graph.entry_points().len(), 2);
        assert_eq!(graph.assets().len(), 1);
    }

    #[test]
    fn nodes_by_type() {
        let mut graph = AttackGraph::new();
        graph.add_node("bound".to_string(), AttackNodeType::SecurityBoundary);
        graph.add_node("bound2".to_string(), AttackNodeType::SecurityBoundary);

        assert_eq!(
            graph.nodes_by_type(AttackNodeType::SecurityBoundary).len(),
            2
        );
        assert_eq!(graph.nodes_by_type(AttackNodeType::EntryPoint).len(), 0);
    }

    #[test]
    fn contains_node() {
        let mut graph = AttackGraph::new();
        let id = graph.add_node("test".to_string(), AttackNodeType::Vulnerability);
        assert!(graph.contains_node(id));
        assert!(!graph.contains_node(999));
    }

    #[test]
    fn all_edges() {
        let mut graph = AttackGraph::new();
        let a = graph.add_node("a".to_string(), AttackNodeType::EntryPoint);
        let b = graph.add_node("b".to_string(), AttackNodeType::Asset);
        graph.add_edge(a, b, 0.5, Some(1));

        let edges = graph.all_edges();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].exploitation_difficulty, 0.5);
        assert_eq!(edges[0].vulnerability_id, Some(1));
    }

    #[test]
    fn attack_node_type_display() {
        assert_eq!(AttackNodeType::EntryPoint.to_string(), "entry-point");
        assert_eq!(
            AttackNodeType::SecurityBoundary.to_string(),
            "security-boundary"
        );
        assert_eq!(AttackNodeType::Vulnerability.to_string(), "vulnerability");
        assert_eq!(AttackNodeType::Asset.to_string(), "asset");
    }

    #[test]
    fn default_creates_empty_graph() {
        let graph = AttackGraph::default();
        assert_eq!(graph.node_count(), 0);
        assert_eq!(graph.edge_count(), 0);
    }

    #[test]
    fn ids_are_sequential() {
        let mut graph = AttackGraph::new();
        let a = graph.add_node("a".to_string(), AttackNodeType::EntryPoint);
        let b = graph.add_node("b".to_string(), AttackNodeType::Asset);
        assert_eq!(a, 0);
        assert_eq!(b, 1);
    }

    #[test]
    fn empty_graph_node_lookup_returns_none() {
        let graph = AttackGraph::new();
        assert!(graph.node(0).is_none());
        assert!(graph.node(u64::MAX).is_none());
    }

    #[test]
    fn empty_graph_outgoing_edges_returns_empty() {
        let graph = AttackGraph::new();
        assert!(graph.outgoing_edges(0).is_empty());
    }

    #[test]
    fn empty_graph_all_edges_returns_empty() {
        let graph = AttackGraph::new();
        assert!(graph.all_edges().is_empty());
    }

    #[test]
    fn empty_graph_entry_points_and_assets_empty() {
        let graph = AttackGraph::new();
        assert!(graph.entry_points().is_empty());
        assert!(graph.assets().is_empty());
    }

    #[test]
    fn empty_graph_contains_node_false() {
        let graph = AttackGraph::new();
        assert!(!graph.contains_node(0));
    }

    #[test]
    fn self_loop_edge() {
        let mut graph = AttackGraph::new();
        let n = graph.add_node("loop-node".to_string(), AttackNodeType::Vulnerability);
        graph.add_edge(n, n, 0.9, Some(42));

        assert_eq!(graph.edge_count(), 1);
        let outgoing = graph.outgoing_edges(n);
        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].source, n);
        assert_eq!(outgoing[0].target, n);
        assert_eq!(outgoing[0].exploitation_difficulty, 0.9);
    }

    #[test]
    fn self_loop_appears_in_all_edges() {
        let mut graph = AttackGraph::new();
        let n = graph.add_node("self".to_string(), AttackNodeType::EntryPoint);
        graph.add_edge(n, n, 1.0, None);

        let all = graph.all_edges();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].source, n);
        assert_eq!(all[0].target, n);
    }

    #[test]
    fn disconnected_components_node_counts() {
        let mut graph = AttackGraph::new();
        let a = graph.add_node("a".to_string(), AttackNodeType::EntryPoint);
        let b = graph.add_node("b".to_string(), AttackNodeType::Asset);
        let c = graph.add_node("c".to_string(), AttackNodeType::Vulnerability);
        let d = graph.add_node("d".to_string(), AttackNodeType::Asset);

        graph.add_edge(a, b, 0.2, None);
        graph.add_edge(c, d, 0.8, None);

        assert_eq!(graph.node_count(), 4);
        assert_eq!(graph.edge_count(), 2);
        assert_eq!(graph.outgoing_edges(a).len(), 1);
        assert_eq!(graph.outgoing_edges(b).len(), 0);
        assert_eq!(graph.outgoing_edges(c).len(), 1);
        assert_eq!(graph.outgoing_edges(d).len(), 0);
    }

    #[test]
    fn disconnected_components_no_cross_edges() {
        let mut graph = AttackGraph::new();
        let a = graph.add_node("a".to_string(), AttackNodeType::EntryPoint);
        let b = graph.add_node("b".to_string(), AttackNodeType::Vulnerability);
        let c = graph.add_node("c".to_string(), AttackNodeType::Asset);

        graph.add_edge(a, b, 0.5, None);

        let edges_from_a = graph.outgoing_edges(a);
        assert_eq!(edges_from_a.len(), 1);
        assert_eq!(edges_from_a[0].target, b);

        assert!(graph.outgoing_edges(c).is_empty());
        assert!(graph.outgoing_edges(b).is_empty());
    }

    #[test]
    fn default_trait_equivalent_to_new() {
        let from_new = AttackGraph::new();
        let from_default = AttackGraph::default();

        assert_eq!(from_new.node_count(), from_default.node_count());
        assert_eq!(from_new.edge_count(), from_default.edge_count());
        assert!(from_new.all_edges().is_empty());
        assert!(from_default.all_edges().is_empty());
        assert!(from_new.entry_points().is_empty());
        assert!(from_default.entry_points().is_empty());
    }

    #[test]
    fn default_graph_supports_subsequent_mutations() {
        let mut graph = AttackGraph::default();
        let n = graph.add_node("added".to_string(), AttackNodeType::SecurityBoundary);

        assert_eq!(graph.node_count(), 1);
        assert!(graph.contains_node(n));
        assert_eq!(graph.node(n).unwrap().label, "added");
    }

    #[test]
    fn mitigation_impact_chokepoint_eliminates_downstream() {
        let mut graph = AttackGraph::new();
        let entry = graph.add_node("entry".to_string(), AttackNodeType::EntryPoint);
        let chokepoint = graph.add_node("choke".to_string(), AttackNodeType::Vulnerability);
        let asset1 = graph.add_node("asset1".to_string(), AttackNodeType::Asset);
        let asset2 = graph.add_node("asset2".to_string(), AttackNodeType::Asset);

        graph.add_edge(entry, chokepoint, 0.3, None);
        graph.add_edge(chokepoint, asset1, 0.5, None);
        graph.add_edge(chokepoint, asset2, 0.7, None);

        let choke_idx = graph.node_index(chokepoint).unwrap();
        let result = graph.mitigation_impact(choke_idx);

        assert_eq!(result.removed_findings.len(), 2);
        assert_eq!(result.findings_remaining, 0);
        assert!((result.impact_score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn mitigation_impact_leaf_affects_only_direct() {
        let mut graph = AttackGraph::new();
        let entry = graph.add_node("entry".to_string(), AttackNodeType::EntryPoint);
        let vuln = graph.add_node("vuln".to_string(), AttackNodeType::Vulnerability);
        let asset_a = graph.add_node("asset_a".to_string(), AttackNodeType::Asset);
        let asset_b = graph.add_node("asset_b".to_string(), AttackNodeType::Asset);

        graph.add_edge(entry, vuln, 0.3, None);
        graph.add_edge(entry, asset_a, 0.4, None);
        graph.add_edge(vuln, asset_b, 0.5, None);

        let vuln_idx = graph.node_index(vuln).unwrap();
        let result = graph.mitigation_impact(vuln_idx);

        assert_eq!(result.removed_findings.len(), 1);
        assert_eq!(result.findings_remaining, 1);
        assert!((result.impact_score - 0.5).abs() < f64::EPSILON);

        let removed_node = result.removed_findings[0];
        assert_eq!(graph.inner_graph()[removed_node].id, asset_b);
    }

    #[test]
    fn mitigation_impact_empty_graph_zero_impact() {
        let graph = AttackGraph::new();
        let dummy_idx = petgraph::graph::NodeIndex::new(0);
        let result = graph.mitigation_impact(dummy_idx);

        assert!(result.removed_findings.is_empty());
        assert_eq!(result.findings_remaining, 0);
        assert!((result.impact_score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn sorted_neighbors_deterministic_regardless_of_insertion_order() {
        let mut g1 = AttackGraph::new();
        let entry = g1.add_node("entry".to_string(), AttackNodeType::EntryPoint);
        let a = g1.add_node("a".to_string(), AttackNodeType::Vulnerability);
        let b = g1.add_node("b".to_string(), AttackNodeType::Vulnerability);
        let c = g1.add_node("c".to_string(), AttackNodeType::Asset);
        g1.add_edge(entry, c, 0.1, None);
        g1.add_edge(entry, a, 0.2, None);
        g1.add_edge(entry, b, 0.3, None);

        let mut g2 = AttackGraph::new();
        let entry2 = g2.add_node("entry".to_string(), AttackNodeType::EntryPoint);
        let a2 = g2.add_node("a".to_string(), AttackNodeType::Vulnerability);
        let b2 = g2.add_node("b".to_string(), AttackNodeType::Vulnerability);
        let c2 = g2.add_node("c".to_string(), AttackNodeType::Asset);
        g2.add_edge(entry2, b2, 0.3, None);
        g2.add_edge(entry2, c2, 0.1, None);
        g2.add_edge(entry2, a2, 0.2, None);

        let entry_idx1 = g1.node_index(entry).unwrap();
        let entry_idx2 = g2.node_index(entry2).unwrap();

        let neighbors1 = g1.sorted_neighbors(entry_idx1);
        let neighbors2 = g2.sorted_neighbors(entry_idx2);

        assert_eq!(neighbors1.len(), neighbors2.len());
        for (n1, n2) in neighbors1.iter().zip(neighbors2.iter()) {
            assert_eq!(
                g1.inner_graph()[*n1].label,
                g2.inner_graph()[*n2].label
            );
        }
    }

    #[test]
    fn sorted_neighbors_does_not_alter_graph() {
        let mut graph = AttackGraph::new();
        let entry = graph.add_node("entry".to_string(), AttackNodeType::EntryPoint);
        let a = graph.add_node("a".to_string(), AttackNodeType::Vulnerability);
        let b = graph.add_node("b".to_string(), AttackNodeType::Asset);
        graph.add_edge(entry, a, 0.5, None);
        graph.add_edge(entry, b, 0.3, None);

        let entry_idx = graph.node_index(entry).unwrap();
        let _ = graph.sorted_neighbors(entry_idx);

        assert_eq!(graph.node_count(), 3);
        assert_eq!(graph.edge_count(), 2);
    }
}
