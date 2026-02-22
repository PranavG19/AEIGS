use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GraphOperation {
    AddNode {
        node_type: crate::node::NodeType,
        properties: Vec<(String, String)>,
    },
    AddEdge {
        source_node_id: u64,
        target_node_id: u64,
        label: crate::edge::EdgeLabel,
        weight: f64,
    },
    UpdateWeight {
        edge_id: u64,
        new_weight: f64,
    },
    AddFinding {
        linked_node_ids: Vec<u64>,
        vulnerability_class: crate::finding::VulnerabilityClass,
        severity: f64,
        confidence: f64,
        certificate: Vec<u8>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModuleIdentifier {
    PassiveRecon,
    Enumeration,
    Fuzzing,
    HypothesisEngine,
    ChainSynthesis,
    Discovery,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationLogEntry {
    pub sequence_number: u64,
    pub module: ModuleIdentifier,
    pub operation: GraphOperation,
    pub timestamp_unix_ms: u64,
}
