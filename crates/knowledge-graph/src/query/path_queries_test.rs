#[cfg(test)]
mod tests {
    use crate::edge_store::EdgeStore;
    use crate::node_store::NodeStore;
    use crate::query::path_queries::{
        all_simple_paths_bounded, bfs_shortest_path_unweighted, find_paths_between, shortest_path,
    };
    use aegis_protocol::edge::EdgeLabel;
    use aegis_protocol::node::NodeType;
    use aegis_protocol::operation::ModuleIdentifier;
    use std::collections::HashMap;

    fn build_linear_graph() -> (NodeStore, EdgeStore) {
        let mut nodes = NodeStore::new();
        let mut edges = EdgeStore::new();

        for _ in 0..4 {
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
            2.0,
            ModuleIdentifier::PassiveRecon,
            1,
        );
        edges.insert(
            2,
            3,
            EdgeLabel::Calls,
            1.0,
            ModuleIdentifier::PassiveRecon,
            2,
        );

        (nodes, edges)
    }

    fn build_diamond_graph() -> (NodeStore, EdgeStore) {
        let mut nodes = NodeStore::new();
        let mut edges = EdgeStore::new();

        for _ in 0..4 {
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
            EdgeLabel::Calls,
            3.0,
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
            3,
            EdgeLabel::Calls,
            1.0,
            ModuleIdentifier::PassiveRecon,
            3,
        );

        (nodes, edges)
    }

    #[test]
    fn find_paths_in_linear_graph() {
        let (nodes, edges) = build_linear_graph();
        let result = find_paths_between(0, 3, 5, &nodes, &edges);

        assert_eq!(result.paths.len(), 1);
        assert_eq!(result.paths[0], vec![0, 1, 2, 3]);
    }

    #[test]
    fn find_paths_respects_max_hops() {
        let (nodes, edges) = build_linear_graph();
        let result = find_paths_between(0, 3, 2, &nodes, &edges);

        assert!(result.paths.is_empty());
    }

    #[test]
    fn find_paths_no_path_returns_empty() {
        let (nodes, edges) = build_linear_graph();
        let result = find_paths_between(3, 0, 10, &nodes, &edges);

        assert!(result.paths.is_empty());
    }

    #[test]
    fn find_paths_same_node_returns_self() {
        let (nodes, edges) = build_linear_graph();
        let result = find_paths_between(1, 1, 5, &nodes, &edges);

        assert_eq!(result.paths.len(), 1);
        assert_eq!(result.paths[0], vec![1]);
    }

    #[test]
    fn find_paths_nonexistent_node_returns_empty() {
        let (nodes, edges) = build_linear_graph();
        let result = find_paths_between(0, 999, 5, &nodes, &edges);

        assert!(result.paths.is_empty());
    }

    #[test]
    fn find_paths_diamond_finds_both_paths() {
        let (nodes, edges) = build_diamond_graph();
        let result = find_paths_between(0, 3, 5, &nodes, &edges);

        assert_eq!(result.paths.len(), 2);
    }

    #[test]
    fn shortest_path_linear_graph() {
        let (nodes, edges) = build_linear_graph();
        let result = shortest_path(0, 3, &nodes, &edges);

        assert!(result.found);
        assert_eq!(result.path, vec![0, 1, 2, 3]);
        assert!((result.total_weight - 4.0).abs() < f64::EPSILON);
    }

    #[test]
    fn shortest_path_diamond_picks_cheaper_route() {
        let (nodes, edges) = build_diamond_graph();
        let result = shortest_path(0, 3, &nodes, &edges);

        assert!(result.found);
        assert_eq!(result.path, vec![0, 1, 3]);
        assert!((result.total_weight - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn shortest_path_same_node() {
        let (nodes, edges) = build_linear_graph();
        let result = shortest_path(0, 0, &nodes, &edges);

        assert!(result.found);
        assert_eq!(result.path, vec![0]);
        assert!((result.total_weight - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn shortest_path_no_path() {
        let (nodes, edges) = build_linear_graph();
        let result = shortest_path(3, 0, &nodes, &edges);

        assert!(!result.found);
        assert!(result.path.is_empty());
    }

    #[test]
    fn shortest_path_nonexistent_node() {
        let (nodes, edges) = build_linear_graph();
        let result = shortest_path(0, 999, &nodes, &edges);

        assert!(!result.found);
    }

    #[test]
    fn all_simple_paths_bounded_diamond() {
        let (nodes, edges) = build_diamond_graph();
        let paths = all_simple_paths_bounded(0, 3, 4, &nodes, &edges);

        assert_eq!(paths.len(), 2);

        let path_sets: Vec<Vec<u64>> = paths.clone();
        assert!(path_sets.contains(&vec![0, 1, 3]));
        assert!(path_sets.contains(&vec![0, 2, 3]));
    }

    #[test]
    fn all_simple_paths_bounded_linear() {
        let (nodes, edges) = build_linear_graph();
        let paths = all_simple_paths_bounded(0, 3, 8, &nodes, &edges);

        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], vec![0, 1, 2, 3]);
    }

    #[test]
    fn all_simple_paths_bounded_respects_max_length() {
        let (nodes, edges) = build_linear_graph();
        let paths = all_simple_paths_bounded(0, 3, 2, &nodes, &edges);

        assert!(paths.is_empty());
    }

    #[test]
    fn all_simple_paths_bounded_nonexistent_returns_empty() {
        let (nodes, edges) = build_linear_graph();
        let paths = all_simple_paths_bounded(0, 999, 5, &nodes, &edges);

        assert!(paths.is_empty());
    }

    #[test]
    fn bfs_shortest_linear() {
        let (nodes, edges) = build_linear_graph();
        let path = bfs_shortest_path_unweighted(0, 3, &nodes, &edges);

        assert_eq!(path, Some(vec![0, 1, 2, 3]));
    }

    #[test]
    fn bfs_shortest_diamond() {
        let (nodes, edges) = build_diamond_graph();
        let path = bfs_shortest_path_unweighted(0, 3, &nodes, &edges);

        let path = path.unwrap();
        assert_eq!(path.len(), 3);
        assert_eq!(path[0], 0);
        assert_eq!(path[2], 3);
    }

    #[test]
    fn bfs_shortest_same_node() {
        let (nodes, edges) = build_linear_graph();
        let path = bfs_shortest_path_unweighted(0, 0, &nodes, &edges);

        assert_eq!(path, Some(vec![0]));
    }

    #[test]
    fn bfs_shortest_no_path() {
        let (nodes, edges) = build_linear_graph();
        let path = bfs_shortest_path_unweighted(3, 0, &nodes, &edges);

        assert!(path.is_none());
    }

    #[test]
    fn bfs_shortest_nonexistent_node() {
        let (nodes, edges) = build_linear_graph();
        let path = bfs_shortest_path_unweighted(0, 999, &nodes, &edges);

        assert!(path.is_none());
    }

    #[test]
    fn cycle_handling_no_infinite_loop() {
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

        let result = find_paths_between(0, 2, 5, &nodes, &edges);
        assert_eq!(result.paths.len(), 1);
        assert_eq!(result.paths[0], vec![0, 1, 2]);
    }
}
