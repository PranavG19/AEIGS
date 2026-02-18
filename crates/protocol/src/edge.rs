use crate::operation::ModuleIdentifier;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeLabel {
    Calls,
    Trusts,
    Authenticates,
    Reads,
    Writes,
    DependsOn,
    Exposes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeData {
    pub id: u64,
    pub source_node_id: u64,
    pub target_node_id: u64,
    pub label: EdgeLabel,
    pub weight: f64,
    pub provenance_module: ModuleIdentifier,
    pub provenance_sequence: u64,
}

impl EdgeData {
    pub fn new(
        id: u64,
        source_node_id: u64,
        target_node_id: u64,
        label: EdgeLabel,
        weight: f64,
        provenance_module: ModuleIdentifier,
        provenance_sequence: u64,
    ) -> Self {
        Self {
            id,
            source_node_id,
            target_node_id,
            label,
            weight,
            provenance_module,
            provenance_sequence,
        }
    }
}
