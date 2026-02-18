use crate::edge_store::EdgeStore;
use crate::node_store::NodeStore;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::cmp::Ordering;

#[derive(Debug, Clone)]
pub struct PathResult {
    pub paths: Vec<Vec<u64>>,
}

pub fn find_paths_between(
    from: u64,
    to: u64,
    max_hops: u32,
    node_store: &NodeStore,
    edge_store: &EdgeStore,
) -> PathResult {
    if node_store.get(from).is_none() || node_store.get(to).is_none() {
        return PathResult { paths: vec![] };
    }

    if from == to {
        return PathResult {
            paths: vec![vec![from]],
        };
    }

    let mut paths = Vec::new();
    let mut stack: Vec<(u64, Vec<u64>)> = vec![(from, vec![from])];

    while let Some((current, path)) = stack.pop() {
        if path.len() > max_hops as usize + 1 {
            continue;
        }

        for &edge_id in edge_store.outgoing_edges(current) {
            let edge = edge_store.get(edge_id).unwrap();
            let next = edge.target_node_id;

            if next == to {
                let mut complete_path = path.clone();
                complete_path.push(next);
                paths.push(complete_path);
            } else if !path.contains(&next) && path.len() < max_hops as usize + 1 {
                let mut new_path = path.clone();
                new_path.push(next);
                stack.push((next, new_path));
            }
        }
    }

    PathResult { paths }
}

#[derive(Debug, Clone)]
struct DijkstraState {
    cost: f64,
    node: u64,
}

impl PartialEq for DijkstraState {
    fn eq(&self, other: &Self) -> bool {
        self.cost.to_bits() == other.cost.to_bits() && self.node == other.node
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
            .then_with(|| self.node.cmp(&other.node))
    }
}

#[derive(Debug, Clone)]
pub struct ShortestPathResult {
    pub path: Vec<u64>,
    pub total_weight: f64,
    pub found: bool,
}

pub fn shortest_path(
    from: u64,
    to: u64,
    node_store: &NodeStore,
    edge_store: &EdgeStore,
) -> ShortestPathResult {
    if node_store.get(from).is_none() || node_store.get(to).is_none() {
        return ShortestPathResult {
            path: vec![],
            total_weight: f64::INFINITY,
            found: false,
        };
    }

    if from == to {
        return ShortestPathResult {
            path: vec![from],
            total_weight: 0.0,
            found: true,
        };
    }

    let mut dist: HashMap<u64, f64> = HashMap::new();
    let mut prev: HashMap<u64, u64> = HashMap::new();
    let mut heap = BinaryHeap::new();

    dist.insert(from, 0.0);
    heap.push(DijkstraState {
        cost: 0.0,
        node: from,
    });

    while let Some(DijkstraState { cost, node }) = heap.pop() {
        if node == to {
            let mut path = vec![to];
            let mut current = to;
            while let Some(&p) = prev.get(&current) {
                path.push(p);
                current = p;
            }
            path.reverse();
            return ShortestPathResult {
                path,
                total_weight: cost,
                found: true,
            };
        }

        if cost > *dist.get(&node).unwrap_or(&f64::INFINITY) {
            continue;
        }

        for &edge_id in edge_store.outgoing_edges(node) {
            let edge = edge_store.get(edge_id).unwrap();
            let next = edge.target_node_id;
            let next_cost = cost + edge.weight;

            if next_cost < *dist.get(&next).unwrap_or(&f64::INFINITY) {
                dist.insert(next, next_cost);
                prev.insert(next, node);
                heap.push(DijkstraState {
                    cost: next_cost,
                    node: next,
                });
            }
        }
    }

    ShortestPathResult {
        path: vec![],
        total_weight: f64::INFINITY,
        found: false,
    }
}

pub fn all_simple_paths_bounded(
    from: u64,
    to: u64,
    max_length: u32,
    node_store: &NodeStore,
    edge_store: &EdgeStore,
) -> Vec<Vec<u64>> {
    if node_store.get(from).is_none() || node_store.get(to).is_none() {
        return vec![];
    }

    let mut result = Vec::new();
    let mut visited = HashSet::new();
    let mut current_path = vec![from];
    visited.insert(from);

    enumerate_paths(
        from,
        to,
        max_length,
        edge_store,
        &mut visited,
        &mut current_path,
        &mut result,
    );

    result
}

fn enumerate_paths(
    current: u64,
    target: u64,
    max_length: u32,
    edge_store: &EdgeStore,
    visited: &mut HashSet<u64>,
    current_path: &mut Vec<u64>,
    result: &mut Vec<Vec<u64>>,
) {
    if current_path.len() > max_length as usize {
        return;
    }

    for &edge_id in edge_store.outgoing_edges(current) {
        let edge = edge_store.get(edge_id).unwrap();
        let next = edge.target_node_id;

        if next == target {
            let mut path = current_path.clone();
            path.push(next);
            result.push(path);
        } else if !visited.contains(&next) && current_path.len() < max_length as usize {
            visited.insert(next);
            current_path.push(next);
            enumerate_paths(next, target, max_length, edge_store, visited, current_path, result);
            current_path.pop();
            visited.remove(&next);
        }
    }
}

pub fn bfs_shortest_path_unweighted(
    from: u64,
    to: u64,
    node_store: &NodeStore,
    edge_store: &EdgeStore,
) -> Option<Vec<u64>> {
    if node_store.get(from).is_none() || node_store.get(to).is_none() {
        return None;
    }

    if from == to {
        return Some(vec![from]);
    }

    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    let mut prev: HashMap<u64, u64> = HashMap::new();

    visited.insert(from);
    queue.push_back(from);

    while let Some(current) = queue.pop_front() {
        for &edge_id in edge_store.outgoing_edges(current) {
            let edge = edge_store.get(edge_id).unwrap();
            let next = edge.target_node_id;

            if next == to {
                let mut path = vec![next];
                let mut trace = current;
                loop {
                    path.push(trace);
                    match prev.get(&trace) {
                        Some(&p) => trace = p,
                        None => break,
                    }
                }
                path.reverse();
                return Some(path);
            }

            if visited.insert(next) {
                prev.insert(next, current);
                queue.push_back(next);
            }
        }
    }

    None
}
