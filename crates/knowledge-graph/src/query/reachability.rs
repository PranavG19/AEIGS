use crate::edge_store::EdgeStore;
use crate::node_store::NodeStore;
use aegis_protocol::edge::EdgeLabel;
use aegis_protocol::node::NodeType;
use std::collections::{HashMap, HashSet, VecDeque};

pub fn reachable_from(
    start: u64,
    edge_labels: &[EdgeLabel],
    node_store: &NodeStore,
    edge_store: &EdgeStore,
) -> HashSet<u64> {
    let mut visited = HashSet::new();

    if node_store.get(start).is_none() {
        return visited;
    }

    let label_set: HashSet<EdgeLabel> = edge_labels.iter().copied().collect();
    let filter_by_label = !label_set.is_empty();

    let mut queue = VecDeque::new();
    visited.insert(start);
    queue.push_back(start);

    while let Some(current) = queue.pop_front() {
        for &edge_id in edge_store.outgoing_edges(current) {
            let edge = edge_store.get(edge_id).unwrap();

            if filter_by_label && !label_set.contains(&edge.label) {
                continue;
            }

            let next = edge.target_node_id;
            if visited.insert(next) {
                queue.push_back(next);
            }
        }
    }

    visited
}

pub fn nodes_by_type(node_type: NodeType, node_store: &NodeStore) -> Vec<u64> {
    node_store.nodes_by_type(node_type).to_vec()
}

pub fn cut_vertices(node_store: &NodeStore, edge_store: &EdgeStore) -> Vec<u64> {
    let node_count = node_store.count();
    if node_count == 0 {
        return vec![];
    }

    let mut visited = vec![false; node_count];
    let mut disc = vec![0u64; node_count];
    let mut low = vec![0u64; node_count];
    let mut parent = vec![None::<u64>; node_count];
    let mut is_articulation = vec![false; node_count];
    let mut timer = 0u64;

    for start in 0..node_count as u64 {
        if !visited[start as usize] {
            tarjan_dfs(
                start,
                &mut visited,
                &mut disc,
                &mut low,
                &mut parent,
                &mut is_articulation,
                &mut timer,
                edge_store,
            );
        }
    }

    is_articulation
        .iter()
        .enumerate()
        .filter_map(|(i, &is_cut)| if is_cut { Some(i as u64) } else { None })
        .collect()
}

fn tarjan_dfs(
    u: u64,
    visited: &mut [bool],
    disc: &mut [u64],
    low: &mut [u64],
    parent: &mut [Option<u64>],
    is_articulation: &mut [bool],
    timer: &mut u64,
    edge_store: &EdgeStore,
) {
    visited[u as usize] = true;
    disc[u as usize] = *timer;
    low[u as usize] = *timer;
    *timer += 1;
    let mut child_count = 0u32;

    let outgoing: Vec<u64> = edge_store.outgoing_edges(u).to_vec();
    let incoming: Vec<u64> = edge_store.incoming_edges(u).to_vec();

    let mut neighbors = HashSet::new();
    for &eid in &outgoing {
        let edge = edge_store.get(eid).unwrap();
        neighbors.insert(edge.target_node_id);
    }
    for &eid in &incoming {
        let edge = edge_store.get(eid).unwrap();
        neighbors.insert(edge.source_node_id);
    }

    for v in neighbors {
        if !visited[v as usize] {
            child_count += 1;
            parent[v as usize] = Some(u);
            tarjan_dfs(v, visited, disc, low, parent, is_articulation, timer, edge_store);

            low[u as usize] = low[u as usize].min(low[v as usize]);

            if parent[u as usize].is_none() && child_count > 1 {
                is_articulation[u as usize] = true;
            }

            if parent[u as usize].is_some() && low[v as usize] >= disc[u as usize] {
                is_articulation[u as usize] = true;
            }
        } else if Some(v) != parent[u as usize] {
            low[u as usize] = low[u as usize].min(disc[v as usize]);
        }
    }
}

pub fn betweenness_centrality(
    node_store: &NodeStore,
    edge_store: &EdgeStore,
) -> HashMap<u64, f64> {
    let node_count = node_store.count();
    let mut centrality: HashMap<u64, f64> = (0..node_count as u64).map(|id| (id, 0.0)).collect();

    for source in 0..node_count as u64 {
        let mut stack = Vec::new();
        let mut predecessors: HashMap<u64, Vec<u64>> = HashMap::new();
        let mut sigma: HashMap<u64, f64> = HashMap::new();
        let mut dist: HashMap<u64, i64> = HashMap::new();

        sigma.insert(source, 1.0);
        dist.insert(source, 0);

        let mut queue = VecDeque::new();
        queue.push_back(source);

        while let Some(v) = queue.pop_front() {
            stack.push(v);
            let d_v = dist[&v];

            for &edge_id in edge_store.outgoing_edges(v) {
                let edge = edge_store.get(edge_id).unwrap();
                let w = edge.target_node_id;

                if !dist.contains_key(&w) {
                    dist.insert(w, d_v + 1);
                    queue.push_back(w);
                }

                if dist[&w] == d_v + 1 {
                    *sigma.entry(w).or_insert(0.0) += sigma[&v];
                    predecessors.entry(w).or_default().push(v);
                }
            }
        }

        let mut delta: HashMap<u64, f64> = HashMap::new();
        while let Some(w) = stack.pop() {
            if let Some(preds) = predecessors.get(&w) {
                for &v in preds {
                    let contribution =
                        (sigma.get(&v).copied().unwrap_or(0.0) / sigma.get(&w).copied().unwrap_or(1.0))
                            * (1.0 + delta.get(&w).copied().unwrap_or(0.0));
                    *delta.entry(v).or_insert(0.0) += contribution;
                }
            }
            if w != source {
                *centrality.entry(w).or_insert(0.0) += delta.get(&w).copied().unwrap_or(0.0);
            }
        }
    }

    let n = node_count as f64;
    if n > 2.0 {
        let normalization = 1.0 / ((n - 1.0) * (n - 2.0));
        for value in centrality.values_mut() {
            *value *= normalization;
        }
    }

    centrality
}
