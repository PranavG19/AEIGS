use aegis_protocol::edge::{EdgeData, EdgeLabel};
use aegis_protocol::operation::ModuleIdentifier;
use std::collections::HashMap;

pub struct EdgeStore {
    edges: Vec<EdgeData>,
    outgoing: HashMap<u64, Vec<u64>>,
    incoming: HashMap<u64, Vec<u64>>,
}

impl EdgeStore {
    pub fn new() -> Self {
        Self {
            edges: Vec::new(),
            outgoing: HashMap::new(),
            incoming: HashMap::new(),
        }
    }

    pub fn insert(
        &mut self,
        source_node_id: u64,
        target_node_id: u64,
        label: EdgeLabel,
        weight: f64,
        provenance_module: ModuleIdentifier,
        provenance_sequence: u64,
    ) -> u64 {
        let id = self.edges.len() as u64;
        let edge = EdgeData::new(
            id,
            source_node_id,
            target_node_id,
            label,
            weight,
            provenance_module,
            provenance_sequence,
        );
        self.edges.push(edge);

        let outgoing_list = self.outgoing.entry(source_node_id).or_default();
        let insert_pos = outgoing_list
            .binary_search_by_key(&target_node_id, |eid| {
                self.edges[*eid as usize].target_node_id
            })
            .unwrap_or_else(|pos| pos);
        outgoing_list.insert(insert_pos, id);

        self.incoming.entry(target_node_id).or_default().push(id);

        id
    }

    pub fn get(&self, id: u64) -> Option<&EdgeData> {
        self.edges.get(id as usize)
    }

    pub fn outgoing_edges(&self, node_id: u64) -> &[u64] {
        self.outgoing
            .get(&node_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn incoming_edges(&self, node_id: u64) -> &[u64] {
        self.incoming
            .get(&node_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn count(&self) -> usize {
        self.edges.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &EdgeData> {
        self.edges.iter()
    }

    pub fn update_weight(&mut self, edge_id: u64, new_weight: f64) -> bool {
        if let Some(edge) = self.edges.get_mut(edge_id as usize) {
            edge.weight = new_weight;
            true
        } else {
            false
        }
    }
}

impl Default for EdgeStore {
    fn default() -> Self {
        Self::new()
    }
}
