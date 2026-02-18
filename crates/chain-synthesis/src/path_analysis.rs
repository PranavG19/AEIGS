use crate::attack_graph::{AttackEdge, AttackGraph, AttackPath};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};

pub fn reachable_assets(graph: &AttackGraph) -> HashMap<u64, Vec<u64>> {
    let entry_points = graph.entry_points();
    let assets: HashSet<u64> = graph.assets().into_iter().collect();
    let mut result = HashMap::new();

    for entry in &entry_points {
        let reachable = bfs_reachable(graph, *entry);
        let reachable_assets: Vec<u64> = reachable
            .into_iter()
            .filter(|n| assets.contains(n))
            .collect();
        result.insert(*entry, reachable_assets);
    }

    result
}

fn bfs_reachable(graph: &AttackGraph, start: u64) -> HashSet<u64> {
    let mut visited = HashSet::new();
    let mut queue = std::collections::VecDeque::new();

    visited.insert(start);
    queue.push_back(start);

    while let Some(current) = queue.pop_front() {
        for edge in graph.outgoing_edges(current) {
            if visited.insert(edge.target) {
                queue.push_back(edge.target);
            }
        }
    }

    visited
}

struct DijkstraState {
    node: u64,
    cost: f64,
}

impl PartialEq for DijkstraState {
    fn eq(&self, other: &Self) -> bool {
        self.cost == other.cost
    }
}

impl Eq for DijkstraState {}

impl PartialOrd for DijkstraState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DijkstraState {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .cost
            .partial_cmp(&self.cost)
            .unwrap_or(Ordering::Equal)
    }
}

pub fn shortest_attack_path(graph: &AttackGraph, source: u64, target: u64) -> Option<AttackPath> {
    let mut dist: HashMap<u64, f64> = HashMap::new();
    let mut prev: HashMap<u64, (u64, AttackEdge)> = HashMap::new();
    let mut heap = BinaryHeap::new();

    dist.insert(source, 0.0);
    heap.push(DijkstraState {
        node: source,
        cost: 0.0,
    });

    while let Some(DijkstraState { node, cost }) = heap.pop() {
        if node == target {
            return Some(reconstruct_path(&prev, source, target, cost));
        }

        if cost > *dist.get(&node).unwrap_or(&f64::INFINITY) {
            continue;
        }

        for edge in graph.outgoing_edges(node) {
            let next_cost = cost + edge.exploitation_difficulty;
            if next_cost < *dist.get(&edge.target).unwrap_or(&f64::INFINITY) {
                dist.insert(edge.target, next_cost);
                prev.insert(edge.target, (node, edge.clone()));
                heap.push(DijkstraState {
                    node: edge.target,
                    cost: next_cost,
                });
            }
        }
    }

    None
}

fn reconstruct_path(
    prev: &HashMap<u64, (u64, AttackEdge)>,
    source: u64,
    target: u64,
    total_difficulty: f64,
) -> AttackPath {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut current = target;

    while current != source {
        nodes.push(current);
        if let Some((prev_node, edge)) = prev.get(&current) {
            edges.push(edge.clone());
            current = *prev_node;
        } else {
            break;
        }
    }
    nodes.push(source);
    nodes.reverse();
    edges.reverse();

    AttackPath {
        nodes,
        total_difficulty,
        edges,
    }
}

pub fn all_simple_paths(
    graph: &AttackGraph,
    source: u64,
    target: u64,
    max_depth: usize,
) -> Vec<AttackPath> {
    let mut results = Vec::new();
    let mut path = vec![source];
    let mut visited = HashSet::new();
    visited.insert(source);

    dfs_paths(
        graph,
        source,
        target,
        max_depth,
        &mut path,
        &mut visited,
        &mut results,
        0.0,
    );

    results.sort_by(|a, b| {
        a.total_difficulty
            .partial_cmp(&b.total_difficulty)
            .unwrap_or(Ordering::Equal)
    });
    results
}

#[allow(clippy::too_many_arguments)]
fn dfs_paths(
    graph: &AttackGraph,
    current: u64,
    target: u64,
    max_depth: usize,
    path: &mut Vec<u64>,
    visited: &mut HashSet<u64>,
    results: &mut Vec<AttackPath>,
    current_cost: f64,
) {
    if current == target && path.len() > 1 {
        results.push(AttackPath {
            nodes: path.clone(),
            total_difficulty: current_cost,
            edges: Vec::new(),
        });
        return;
    }

    if path.len() > max_depth {
        return;
    }

    for edge in graph.outgoing_edges(current) {
        if !visited.contains(&edge.target) {
            visited.insert(edge.target);
            path.push(edge.target);

            dfs_paths(
                graph,
                edge.target,
                target,
                max_depth,
                path,
                visited,
                results,
                current_cost + edge.exploitation_difficulty,
            );

            path.pop();
            visited.remove(&edge.target);
        }
    }
}

pub fn betweenness_centrality(graph: &AttackGraph) -> HashMap<u64, f64> {
    let mut centrality: HashMap<u64, f64> = HashMap::new();
    let entry_points = graph.entry_points();
    let assets = graph.assets();

    for entry in &entry_points {
        for asset in &assets {
            let paths = all_simple_paths(graph, *entry, *asset, 8);
            let total_paths = paths.len() as f64;

            if total_paths == 0.0 {
                continue;
            }

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
