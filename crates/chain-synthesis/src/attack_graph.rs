use std::collections::HashMap;

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

pub struct AttackGraph {
    nodes: HashMap<u64, AttackNode>,
    edges: Vec<AttackEdge>,
    adjacency: HashMap<u64, Vec<usize>>,
    next_id: u64,
}

impl AttackGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
            adjacency: HashMap::new(),
            next_id: 0,
        }
    }

    pub fn add_node(&mut self, label: String, node_type: AttackNodeType) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.insert(
            id,
            AttackNode {
                id,
                label,
                node_type,
            },
        );
        id
    }

    pub fn add_edge(
        &mut self,
        source: u64,
        target: u64,
        difficulty: f64,
        vulnerability_id: Option<u64>,
    ) {
        let edge_idx = self.edges.len();
        self.edges.push(AttackEdge {
            source,
            target,
            vulnerability_id,
            exploitation_difficulty: difficulty,
        });
        self.adjacency.entry(source).or_default().push(edge_idx);
    }

    pub fn node(&self, id: u64) -> Option<&AttackNode> {
        self.nodes.get(&id)
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub fn outgoing_edges(&self, node_id: u64) -> Vec<&AttackEdge> {
        self.adjacency
            .get(&node_id)
            .map(|indices| indices.iter().map(|&i| &self.edges[i]).collect())
            .unwrap_or_default()
    }

    pub fn entry_points(&self) -> Vec<u64> {
        self.nodes
            .values()
            .filter(|n| n.node_type == AttackNodeType::EntryPoint)
            .map(|n| n.id)
            .collect()
    }

    pub fn assets(&self) -> Vec<u64> {
        self.nodes
            .values()
            .filter(|n| n.node_type == AttackNodeType::Asset)
            .map(|n| n.id)
            .collect()
    }

    pub fn nodes_by_type(&self, node_type: AttackNodeType) -> Vec<u64> {
        self.nodes
            .values()
            .filter(|n| n.node_type == node_type)
            .map(|n| n.id)
            .collect()
    }

    pub fn all_edges(&self) -> &[AttackEdge] {
        &self.edges
    }

    pub fn contains_node(&self, id: u64) -> bool {
        self.nodes.contains_key(&id)
    }
}

impl Default for AttackGraph {
    fn default() -> Self {
        Self::new()
    }
}
