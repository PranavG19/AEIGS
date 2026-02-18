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
}
