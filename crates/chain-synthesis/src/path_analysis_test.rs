#[cfg(test)]
mod tests {
    use crate::attack_graph::{AttackGraph, AttackNodeType};
    use crate::path_analysis::{
        all_simple_paths, betweenness_centrality, critical_fix_targets, reachable_assets,
        shortest_attack_path,
    };

    fn linear_graph() -> AttackGraph {
        let mut g = AttackGraph::new();
        let e = g.add_node("entry".to_string(), AttackNodeType::EntryPoint);
        let v = g.add_node("vuln".to_string(), AttackNodeType::Vulnerability);
        let a = g.add_node("asset".to_string(), AttackNodeType::Asset);
        g.add_edge(e, v, 0.3, None);
        g.add_edge(v, a, 0.5, None);
        g
    }

    fn diamond_graph() -> AttackGraph {
        let mut g = AttackGraph::new();
        let entry = g.add_node("entry".to_string(), AttackNodeType::EntryPoint);
        let left = g.add_node("left".to_string(), AttackNodeType::Vulnerability);
        let right = g.add_node("right".to_string(), AttackNodeType::Vulnerability);
        let asset = g.add_node("asset".to_string(), AttackNodeType::Asset);

        g.add_edge(entry, left, 0.2, None);
        g.add_edge(entry, right, 0.8, None);
        g.add_edge(left, asset, 0.3, None);
        g.add_edge(right, asset, 0.1, None);
        g
    }

    #[test]
    fn reachable_assets_from_entry() {
        let g = linear_graph();
        let result = reachable_assets(&g);
        assert_eq!(result.len(), 1);
        let assets = result.values().next().unwrap();
        assert_eq!(assets.len(), 1);
    }

    #[test]
    fn reachable_assets_empty_graph() {
        let g = AttackGraph::new();
        let result = reachable_assets(&g);
        assert!(result.is_empty());
    }

    #[test]
    fn shortest_path_linear() {
        let g = linear_graph();
        let path = shortest_attack_path(&g, 0, 2).unwrap();
        assert_eq!(path.nodes, vec![0, 1, 2]);
        assert!((path.total_difficulty - 0.8).abs() < 0.001);
    }

    #[test]
    fn shortest_path_diamond_picks_cheaper() {
        let g = diamond_graph();
        let path = shortest_attack_path(&g, 0, 3).unwrap();
        assert_eq!(path.nodes.len(), 3);
        assert!(path.total_difficulty < 0.8 + 0.001);
    }

    #[test]
    fn shortest_path_no_route_returns_none() {
        let mut g = AttackGraph::new();
        let a = g.add_node("a".to_string(), AttackNodeType::EntryPoint);
        let b = g.add_node("b".to_string(), AttackNodeType::Asset);
        let _ = (a, b);
        assert!(shortest_attack_path(&g, 0, 1).is_none());
    }

    #[test]
    fn all_simple_paths_diamond() {
        let g = diamond_graph();
        let paths = all_simple_paths(&g, 0, 3, 8);
        assert_eq!(paths.len(), 2);
        assert!(paths[0].total_difficulty <= paths[1].total_difficulty);
    }

    #[test]
    fn all_simple_paths_depth_limited() {
        let g = linear_graph();
        let paths = all_simple_paths(&g, 0, 2, 1);
        assert!(paths.is_empty());
    }

    #[test]
    fn all_simple_paths_no_cycles() {
        let mut g = AttackGraph::new();
        let a = g.add_node("a".to_string(), AttackNodeType::EntryPoint);
        let b = g.add_node("b".to_string(), AttackNodeType::Vulnerability);
        let c = g.add_node("c".to_string(), AttackNodeType::Asset);

        g.add_edge(a, b, 0.1, None);
        g.add_edge(b, a, 0.1, None);
        g.add_edge(b, c, 0.1, None);

        let paths = all_simple_paths(&g, a, c, 8);
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn betweenness_centrality_diamond() {
        let g = diamond_graph();
        let centrality = betweenness_centrality(&g);

        assert!(centrality.get(&1).is_some());
        assert!(centrality.get(&2).is_some());
    }

    #[test]
    fn betweenness_centrality_empty_graph() {
        let g = AttackGraph::new();
        let centrality = betweenness_centrality(&g);
        assert!(centrality.is_empty());
    }

    #[test]
    fn critical_fix_targets_budget() {
        let g = diamond_graph();
        let targets = critical_fix_targets(&g, 1);
        assert_eq!(targets.len(), 1);
    }

    #[test]
    fn critical_fix_targets_zero_budget() {
        let g = diamond_graph();
        let targets = critical_fix_targets(&g, 0);
        assert!(targets.is_empty());
    }

    #[test]
    fn linear_graph_single_path() {
        let g = linear_graph();
        let paths = all_simple_paths(&g, 0, 2, 8);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].nodes, vec![0, 1, 2]);
    }

    #[test]
    fn reachable_assets_disconnected() {
        let mut g = AttackGraph::new();
        let entry = g.add_node("entry".to_string(), AttackNodeType::EntryPoint);
        g.add_node("isolated_asset".to_string(), AttackNodeType::Asset);
        let _ = entry;

        let result = reachable_assets(&g);
        assert_eq!(result.len(), 1);
        assert!(result.values().next().unwrap().is_empty());
    }
}
