#[cfg(test)]
mod tests {
    use crate::edge_store::EdgeStore;
    use crate::node_store::NodeStore;
    use crate::query::reachability::{
        betweenness_centrality, cut_vertices, nodes_by_type, reachable_from,
    };
    use aegis_protocol::edge::EdgeLabel;
    use aegis_protocol::node::NodeType;
    use aegis_protocol::operation::ModuleIdentifier;
    use std::collections::HashMap;

    fn build_branching_graph() -> (NodeStore, EdgeStore) {
        let mut nodes = NodeStore::new();
        let mut edges = EdgeStore::new();

        for _ in 0..5 {
            nodes.insert(NodeType::Endpoint, HashMap::new());
        }

        edges.insert(
            0,
            1,
            EdgeLabel::Calls,
            1.0,
            ModuleIdentifier::PassiveRecon,
            0,
        );
        edges.insert(
            0,
            2,
            EdgeLabel::Reads,
            1.0,
            ModuleIdentifier::PassiveRecon,
            1,
        );
        edges.insert(
            1,
            3,
            EdgeLabel::Calls,
            1.0,
            ModuleIdentifier::PassiveRecon,
            2,
        );
        edges.insert(
            2,
            4,
            EdgeLabel::Writes,
            1.0,
            ModuleIdentifier::PassiveRecon,
            3,
        );

        (nodes, edges)
    }

    #[test]
    fn reachable_from_start_includes_all_connected() {
        let (nodes, edges) = build_branching_graph();
        let reachable = reachable_from(0, &[], &nodes, &edges);

        assert!(reachable.contains(&0));
        assert!(reachable.contains(&1));
        assert!(reachable.contains(&2));
        assert!(reachable.contains(&3));
        assert!(reachable.contains(&4));
        assert_eq!(reachable.len(), 5);
    }

    #[test]
    fn reachable_from_with_edge_label_filter() {
        let (nodes, edges) = build_branching_graph();
        let reachable = reachable_from(0, &[EdgeLabel::Calls], &nodes, &edges);

        assert!(reachable.contains(&0));
        assert!(reachable.contains(&1));
        assert!(reachable.contains(&3));
        assert!(!reachable.contains(&2));
        assert!(!reachable.contains(&4));
    }

    #[test]
    fn reachable_from_leaf_node() {
        let (nodes, edges) = build_branching_graph();
        let reachable = reachable_from(3, &[], &nodes, &edges);

        assert_eq!(reachable.len(), 1);
        assert!(reachable.contains(&3));
    }

    #[test]
    fn reachable_from_nonexistent_node() {
        let (nodes, edges) = build_branching_graph();
        let reachable = reachable_from(999, &[], &nodes, &edges);

        assert!(reachable.is_empty());
    }

    #[test]
    fn nodes_by_type_filters_correctly() {
        let mut nodes = NodeStore::new();
        nodes.insert(NodeType::Endpoint, HashMap::new());
        nodes.insert(NodeType::Function, HashMap::new());
        nodes.insert(NodeType::Endpoint, HashMap::new());
        nodes.insert(NodeType::DataStore, HashMap::new());

        let endpoints = nodes_by_type(NodeType::Endpoint, &nodes);
        assert_eq!(endpoints, vec![0, 2]);

        let datastores = nodes_by_type(NodeType::DataStore, &nodes);
        assert_eq!(datastores, vec![3]);

        let roles = nodes_by_type(NodeType::Role, &nodes);
        assert!(roles.is_empty());
    }

    #[test]
    fn cut_vertices_in_bridge_graph() {
        let mut nodes = NodeStore::new();
        let mut edges = EdgeStore::new();

        for _ in 0..5 {
            nodes.insert(NodeType::Endpoint, HashMap::new());
        }

        edges.insert(
            0,
            1,
            EdgeLabel::Calls,
            1.0,
            ModuleIdentifier::PassiveRecon,
            0,
        );
        edges.insert(
            1,
            0,
            EdgeLabel::Calls,
            1.0,
            ModuleIdentifier::PassiveRecon,
            1,
        );
        edges.insert(
            1,
            2,
            EdgeLabel::Calls,
            1.0,
            ModuleIdentifier::PassiveRecon,
            2,
        );
        edges.insert(
            2,
            1,
            EdgeLabel::Calls,
            1.0,
            ModuleIdentifier::PassiveRecon,
            3,
        );
        edges.insert(
            2,
            3,
            EdgeLabel::Calls,
            1.0,
            ModuleIdentifier::PassiveRecon,
            4,
        );
        edges.insert(
            3,
            2,
            EdgeLabel::Calls,
            1.0,
            ModuleIdentifier::PassiveRecon,
            5,
        );
        edges.insert(
            3,
            4,
            EdgeLabel::Calls,
            1.0,
            ModuleIdentifier::PassiveRecon,
            6,
        );
        edges.insert(
            4,
            3,
            EdgeLabel::Calls,
            1.0,
            ModuleIdentifier::PassiveRecon,
            7,
        );

        let cuts = cut_vertices(&nodes, &edges);

        assert!(cuts.contains(&1));
        assert!(cuts.contains(&2));
        assert!(cuts.contains(&3));
    }

    #[test]
    fn cut_vertices_empty_graph() {
        let nodes = NodeStore::new();
        let edges = EdgeStore::new();
        let cuts = cut_vertices(&nodes, &edges);

        assert!(cuts.is_empty());
    }

    #[test]
    fn cut_vertices_fully_connected_triangle() {
        let mut nodes = NodeStore::new();
        let mut edges = EdgeStore::new();

        for _ in 0..3 {
            nodes.insert(NodeType::Endpoint, HashMap::new());
        }

        edges.insert(
            0,
            1,
            EdgeLabel::Calls,
            1.0,
            ModuleIdentifier::PassiveRecon,
            0,
        );
        edges.insert(
            1,
            0,
            EdgeLabel::Calls,
            1.0,
            ModuleIdentifier::PassiveRecon,
            1,
        );
        edges.insert(
            1,
            2,
            EdgeLabel::Calls,
            1.0,
            ModuleIdentifier::PassiveRecon,
            2,
        );
        edges.insert(
            2,
            1,
            EdgeLabel::Calls,
            1.0,
            ModuleIdentifier::PassiveRecon,
            3,
        );
        edges.insert(
            0,
            2,
            EdgeLabel::Calls,
            1.0,
            ModuleIdentifier::PassiveRecon,
            4,
        );
        edges.insert(
            2,
            0,
            EdgeLabel::Calls,
            1.0,
            ModuleIdentifier::PassiveRecon,
            5,
        );

        let cuts = cut_vertices(&nodes, &edges);
        assert!(cuts.is_empty());
    }

    #[test]
    fn betweenness_centrality_star_topology() {
        let mut nodes = NodeStore::new();
        let mut edges = EdgeStore::new();

        for _ in 0..5 {
            nodes.insert(NodeType::Endpoint, HashMap::new());
        }

        for i in 1..5u64 {
            edges.insert(
                0,
                i,
                EdgeLabel::Calls,
                1.0,
                ModuleIdentifier::PassiveRecon,
                i - 1,
            );
            edges.insert(
                i,
                0,
                EdgeLabel::Calls,
                1.0,
                ModuleIdentifier::PassiveRecon,
                i + 3,
            );
        }

        let centrality = betweenness_centrality(&nodes, &edges);

        let center_centrality = centrality[&0];
        for i in 1..5u64 {
            assert!(
                center_centrality >= centrality[&i],
                "center node should have highest centrality"
            );
        }
    }

    #[test]
    fn betweenness_centrality_linear_chain() {
        let mut nodes = NodeStore::new();
        let mut edges = EdgeStore::new();

        for _ in 0..3 {
            nodes.insert(NodeType::Endpoint, HashMap::new());
        }

        edges.insert(
            0,
            1,
            EdgeLabel::Calls,
            1.0,
            ModuleIdentifier::PassiveRecon,
            0,
        );
        edges.insert(
            1,
            2,
            EdgeLabel::Calls,
            1.0,
            ModuleIdentifier::PassiveRecon,
            1,
        );

        let centrality = betweenness_centrality(&nodes, &edges);

        assert!(
            centrality[&1] > centrality[&0],
            "middle node should have higher centrality than endpoints"
        );
        assert!(
            centrality[&1] > centrality[&2],
            "middle node should have higher centrality than endpoints"
        );
    }

    #[test]
    fn betweenness_centrality_empty_graph() {
        let nodes = NodeStore::new();
        let edges = EdgeStore::new();
        let centrality = betweenness_centrality(&nodes, &edges);

        assert!(centrality.is_empty());
    }
}
