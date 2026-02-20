use crate::attack_graph::{AttackGraph, AttackNodeType, AttackPath, MitigationResult};
use petgraph::algo::astar;
use petgraph::graph::NodeIndex;
use petgraph::visit::Bfs;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

pub const MAX_TOTAL_PATHS: usize = 100_000;

pub fn reachable_assets(graph: &AttackGraph) -> HashMap<u64, Vec<u64>> {
    let entry_points = graph.entry_points();
    let assets: HashSet<u64> = graph.assets().into_iter().collect();
    let mut result = HashMap::new();

    for entry in &entry_points {
        let reachable = bfs_reachable_petgraph(graph, *entry);
        let reachable_assets: Vec<u64> = reachable
            .into_iter()
            .filter(|n| assets.contains(n))
            .collect();
        result.insert(*entry, reachable_assets);
    }

    result
}

fn bfs_reachable_petgraph(graph: &AttackGraph, start: u64) -> HashSet<u64> {
    let Some(start_idx) = graph.node_index(start) else {
        return HashSet::new();
    };
    let inner = graph.inner_graph();
    let mut bfs = Bfs::new(inner, start_idx);
    let mut visited = HashSet::new();

    while let Some(node_idx) = bfs.next(inner) {
        visited.insert(inner[node_idx].id);
    }

    visited
}

pub fn shortest_attack_path(graph: &AttackGraph, source: u64, target: u64) -> Option<AttackPath> {
    let source_idx = graph.node_index(source)?;
    let target_idx = graph.node_index(target)?;
    let inner = graph.inner_graph();

    let (cost, idx_path) = astar(
        inner,
        source_idx,
        |n| n == target_idx,
        |e| e.weight().exploitation_difficulty,
        |_| 0.0,
    )?;

    let nodes: Vec<u64> = idx_path.iter().map(|&idx| inner[idx].id).collect();
    let edges = collect_path_edges(graph, &nodes);

    Some(AttackPath {
        nodes,
        total_difficulty: cost,
        edges,
    })
}

fn collect_path_edges(graph: &AttackGraph, nodes: &[u64]) -> Vec<crate::attack_graph::AttackEdge> {
    let mut edges = Vec::new();
    for window in nodes.windows(2) {
        let (src, tgt) = (window[0], window[1]);
        if let Some(edge) = graph
            .outgoing_edges(src)
            .into_iter()
            .find(|e| e.target == tgt)
        {
            edges.push(edge.clone());
        }
    }
    edges
}

// Priority-bounded DFS: explores lowest-difficulty edges first, bounded by MAX_TOTAL_PATHS.
// This ensures the most exploitable paths are discovered first when the cap is hit.
pub fn all_simple_paths(
    graph: &AttackGraph,
    source: u64,
    target: u64,
    max_depth: usize,
) -> Vec<AttackPath> {
    if max_depth < 2 {
        return Vec::new();
    }

    if graph.node_index(source).is_none() {
        return Vec::new();
    }
    if graph.node_index(target).is_none() {
        return Vec::new();
    };

    let mut results = Vec::new();
    let mut visited = HashSet::new();
    visited.insert(source);

    let mut ctx = DfsContext {
        graph,
        target,
        max_depth,
        visited,
        current_path: vec![source],
        results,
    };

    priority_dfs_recurse(&mut ctx, source, 0.0);
    results = ctx.results;

    results.sort_by(|a, b| {
        a.total_difficulty
            .partial_cmp(&b.total_difficulty)
            .unwrap_or(Ordering::Equal)
    });
    results
}

struct DfsContext<'a> {
    graph: &'a AttackGraph,
    target: u64,
    max_depth: usize,
    visited: HashSet<u64>,
    current_path: Vec<u64>,
    results: Vec<AttackPath>,
}

fn priority_dfs_recurse(ctx: &mut DfsContext<'_>, current: u64, current_cost: f64) {
    if ctx.results.len() >= MAX_TOTAL_PATHS {
        return;
    }

    let Some(current_idx) = ctx.graph.node_index(current) else {
        return;
    };

    let inner = ctx.graph.inner_graph();
    let mut neighbors: Vec<(u64, f64)> = ctx
        .graph
        .sorted_neighbors(current_idx)
        .into_iter()
        .map(|idx| {
            let id = inner[idx].id;
            let difficulty = ctx
                .graph
                .outgoing_edges(current)
                .into_iter()
                .find(|e| e.target == id)
                .map(|e| e.exploitation_difficulty)
                .unwrap_or(f64::INFINITY);
            (id, difficulty)
        })
        .collect();

    neighbors.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(Ordering::Equal));

    for (next_id, edge_cost) in neighbors {
        if ctx.results.len() >= MAX_TOTAL_PATHS {
            return;
        }

        let next_cost = current_cost + edge_cost;

        if next_id == ctx.target {
            let mut path_nodes = ctx.current_path.clone();
            path_nodes.push(ctx.target);
            ctx.results.push(AttackPath {
                nodes: path_nodes,
                total_difficulty: next_cost,
                edges: Vec::new(),
            });
        } else if !ctx.visited.contains(&next_id) && ctx.current_path.len() < ctx.max_depth - 1 {
            ctx.visited.insert(next_id);
            ctx.current_path.push(next_id);
            priority_dfs_recurse(ctx, next_id, next_cost);
            ctx.current_path.pop();
            ctx.visited.remove(&next_id);
        }
    }
}

// Complexity: O(E × A × b^d) where E=entry points, A=assets, b=branching factor, d=max_depth.
// For typical graphs (E=20, A=10, b=3, d=8): ~1.3M paths. Capped at MAX_TOTAL_PATHS to prevent
// runaway computation.
pub fn betweenness_centrality(graph: &AttackGraph) -> HashMap<u64, f64> {
    let mut centrality: HashMap<u64, f64> = HashMap::new();
    let entry_points = graph.entry_points();
    let assets = graph.assets();
    let mut cumulative_paths: usize = 0;

    'outer: for entry in &entry_points {
        for asset in &assets {
            let paths = all_simple_paths(graph, *entry, *asset, 8);
            let total_paths = paths.len() as f64;

            if total_paths == 0.0 {
                continue;
            }

            cumulative_paths += paths.len();

            let mut node_counts: HashMap<u64, f64> = HashMap::new();
            for path in &paths {
                for &node in &path.nodes {
                    if node != *entry && node != *asset {
                        *node_counts.entry(node).or_default() += 1.0;
                    }
                }
            }

            for (node, count) in node_counts {
                *centrality.entry(node).or_default() += count / total_paths;
            }

            if cumulative_paths >= MAX_TOTAL_PATHS {
                break 'outer;
            }
        }
    }

    centrality
}

pub fn critical_fix_targets(graph: &AttackGraph, budget: usize) -> Vec<(u64, f64)> {
    let centrality = betweenness_centrality(graph);
    let mut ranked: Vec<(u64, f64)> = centrality.into_iter().collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal));
    ranked.truncate(budget);
    ranked
}

/// Graph-theoretic estimate of node influence on asset reachability. Ranks
/// intermediate nodes by the fraction of assets that become unreachable when
/// each node is removed. This is a structural analysis — actual mitigation
/// impact depends on factors not represented in the graph.
pub fn graph_influence_ranking(graph: &AttackGraph) -> Vec<(NodeIndex, MitigationResult)> {
    let inner = graph.inner_graph();
    let mut results: Vec<(NodeIndex, MitigationResult)> = inner
        .node_indices()
        .filter(|&idx| {
            let node_type = inner[idx].node_type;
            node_type != AttackNodeType::EntryPoint && node_type != AttackNodeType::Asset
        })
        .map(|idx| {
            let mitigation = graph.estimated_mitigation_impact(idx);
            (idx, mitigation)
        })
        .collect();

    results.sort_by(|a, b| {
        b.1.impact_score
            .partial_cmp(&a.1.impact_score)
            .unwrap_or(Ordering::Equal)
            .then_with(|| a.0.index().cmp(&b.0.index()))
    });

    results
}
