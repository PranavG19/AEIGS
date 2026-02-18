use aegis_protocol::node::{NodeData, NodeType};
use std::collections::HashMap;

pub struct NodeStore {
    nodes: Vec<NodeData>,
    type_index: HashMap<NodeType, Vec<u64>>,
}

impl NodeStore {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            type_index: HashMap::new(),
        }
    }

    pub fn insert(&mut self, node_type: NodeType, properties: HashMap<String, String>) -> u64 {
        let id = self.nodes.len() as u64;
        let node = NodeData {
            id,
            node_type,
            properties,
        };
        self.nodes.push(node);
        self.type_index.entry(node_type).or_default().push(id);
        id
    }

    pub fn get(&self, id: u64) -> Option<&NodeData> {
        self.nodes.get(id as usize)
    }

    pub fn get_mut(&mut self, id: u64) -> Option<&mut NodeData> {
        self.nodes.get_mut(id as usize)
    }

    pub fn count(&self) -> usize {
        self.nodes.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &NodeData> {
        self.nodes.iter()
    }

    pub fn nodes_by_type(&self, node_type: NodeType) -> &[u64] {
        self.type_index
            .get(&node_type)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

impl Default for NodeStore {
    fn default() -> Self {
        Self::new()
    }
}
