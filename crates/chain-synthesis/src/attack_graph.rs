use petgraph::Direction;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq)]
pub struct AttackNode {
    pub id: u64,
    pub label: String,
    pub node_type: AttackNodeType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackNodeType {
    EntryPoint,
    SecurityBoundary,
    Vulnerability,
    Asset,
}

impl std::fmt::Display for AttackNodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::EntryPoint => "entry-point",
            Self::SecurityBoundary => "security-boundary",
            Self::Vulnerability => "vulnerability",
            Self::Asset => "asset",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone)]
pub struct AttackEdge {
    pub source: u64,
    pub target: u64,
    pub vulnerability_id: Option<u64>,
    pub exploitation_difficulty: f64,
}

#[derive(Debug, Clone)]
pub struct AttackPath {
    pub nodes: Vec<u64>,
    pub total_difficulty: f64,
    pub edges: Vec<AttackEdge>,
}

#[derive(Debug, Clone)]
pub struct MitigationResult {
    pub removed_findings: Vec<NodeIndex>,
    pub findings_remaining: usize,
    pub impact_score: f64,
}

pub struct AttackGraph {
    graph: DiGraph<AttackNode, AttackEdge>,
    index_map: HashMap<u64, NodeIndex>,
    next_id: u64,
}

impl AttackGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            index_map: HashMap::new(),
            next_id: 0,
        }
    }

    pub fn add_node(&mut self, label: String, node_type: AttackNodeType) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let node = AttackNode {
            id,
            label,
            node_type,
        };
        let idx = self.graph.add_node(node);
        self.index_map.insert(id, idx);
        id
    }

    pub fn add_edge(
        &mut self,
        source: u64,
        target: u64,
        difficulty: f64,
        vulnerability_id: Option<u64>,
    ) {
        let source_idx = self.index_map[&source];
        let target_idx = self.index_map[&target];
        let edge = AttackEdge {
            source,
            target,
            vulnerability_id,
            exploitation_difficulty: difficulty,
        };
        self.graph.add_edge(source_idx, target_idx, edge);
    }

    pub fn node(&self, id: u64) -> Option<&AttackNode> {
        self.index_map.get(&id).map(|&idx| &self.graph[idx])
    }

    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    pub fn outgoing_edges(&self, node_id: u64) -> Vec<&AttackEdge> {
        let Some(&idx) = self.index_map.get(&node_id) else {
            return Vec::new();
        };
        self.graph
            .edges_directed(idx, Direction::Outgoing)
            .map(|e| e.weight())
            .collect()
    }

    pub fn sorted_neighbors(&self, node_idx: NodeIndex) -> Vec<NodeIndex> {
        let mut neighbors: Vec<NodeIndex> = self
            .graph
            .neighbors_directed(node_idx, Direction::Outgoing)
            .collect();
        neighbors.sort_by_key(|idx| idx.index());
        neighbors
    }

    pub fn entry_points(&self) -> Vec<u64> {
        self.nodes_by_type(AttackNodeType::EntryPoint)
    }

    pub fn assets(&self) -> Vec<u64> {
        self.nodes_by_type(AttackNodeType::Asset)
    }

    pub fn nodes_by_type(&self, node_type: AttackNodeType) -> Vec<u64> {
        self.graph
            .node_weights()
            .filter(|n| n.node_type == node_type)
            .map(|n| n.id)
            .collect()
    }

    pub fn all_edges(&self) -> Vec<&AttackEdge> {
        self.graph.edge_weights().collect()
    }

    pub fn contains_node(&self, id: u64) -> bool {
        self.index_map.contains_key(&id)
    }

    pub fn inner_graph(&self) -> &DiGraph<AttackNode, AttackEdge> {
        &self.graph
    }

    pub fn node_index(&self, id: u64) -> Option<NodeIndex> {
        self.index_map.get(&id).copied()
    }

    pub fn mitigation_impact(&self, node_idx: NodeIndex) -> MitigationResult {
        let asset_indices: Vec<NodeIndex> = self
            .graph
            .node_indices()
            .filter(|&idx| self.graph[idx].node_type == AttackNodeType::Asset)
            .collect();

        let total_findings = asset_indices.len();

        if total_findings == 0 {
            return MitigationResult {
                removed_findings: Vec::new(),
                findings_remaining: 0,
                impact_score: 0.0,
            };
        }

        let entry_indices: Vec<NodeIndex> = self
            .graph
            .node_indices()
            .filter(|&idx| self.graph[idx].node_type == AttackNodeType::EntryPoint)
            .collect();

        let mut reachable_assets: HashSet<NodeIndex> = HashSet::new();

        for &entry_idx in &entry_indices {
            if entry_idx == node_idx {
                continue;
            }
            let mut visited_set: HashSet<NodeIndex> = HashSet::new();
            let mut queue = std::collections::VecDeque::new();
            visited_set.insert(entry_idx);
            queue.push_back(entry_idx);

            while let Some(current) = queue.pop_front() {
                if self.graph[current].node_type == AttackNodeType::Asset {
                    reachable_assets.insert(current);
                }
                for neighbor in self.graph.neighbors_directed(current, Direction::Outgoing) {
                    if neighbor != node_idx && visited_set.insert(neighbor) {
                        queue.push_back(neighbor);
                    }
                }
            }
        }

        let removed: Vec<NodeIndex> = asset_indices
            .iter()
            .filter(|idx| !reachable_assets.contains(idx))
            .copied()
            .collect();

        let findings_remaining = total_findings - removed.len();
        let impact_score = removed.len() as f64 / total_findings as f64;

        MitigationResult {
            removed_findings: removed,
            findings_remaining,
            impact_score,
        }
    }
}

impl Default for AttackGraph {
    fn default() -> Self {
        Self::new()
    }
}
