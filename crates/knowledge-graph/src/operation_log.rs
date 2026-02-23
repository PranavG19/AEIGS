use crate::edge_store::EdgeStore;
use crate::finding_store::FindingStore;
use crate::node_store::NodeStore;
use aegis_protocol::edge::EdgeLabel;
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};
use std::collections::{HashMap, HashSet};

#[derive(Debug, PartialEq)]
pub enum ValidationError {
    DuplicateNodeInBatch(u64),
    DanglingEdgeSource(u64),
    DanglingEdgeTarget(u64),
    EdgeNotFound(u64),
    NodeNotFoundForFinding(u64),
    InvalidEdgeSemantics {
        source_type: NodeType,
        label: EdgeLabel,
        target_type: NodeType,
    },
    DuplicateEdge {
        source: u64,
        target: u64,
        label: EdgeLabel,
    },
    InvalidWeight(f64),
    InvalidSeverity(f64),
    InvalidConfidence(f64),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateNodeInBatch(id) => write!(f, "duplicate node {id} in batch"),
            Self::DanglingEdgeSource(id) => write!(f, "dangling edge source node {id}"),
            Self::DanglingEdgeTarget(id) => write!(f, "dangling edge target node {id}"),
            Self::EdgeNotFound(id) => write!(f, "edge {id} not found"),
            Self::NodeNotFoundForFinding(id) => write!(f, "node {id} not found for finding"),
            Self::DuplicateEdge {
                source,
                target,
                label,
            } => write!(f, "duplicate edge {source} -{label}-> {target}"),
            Self::InvalidEdgeSemantics {
                source_type,
                label,
                target_type,
            } => write!(
                f,
                "invalid edge semantics: {source_type} -{label}-> {target_type}"
            ),
            Self::InvalidWeight(w) => write!(f, "invalid weight: {w}"),
            Self::InvalidSeverity(s) => write!(f, "invalid severity: {s}"),
            Self::InvalidConfidence(c) => write!(f, "invalid confidence: {c}"),
        }
    }
}

impl std::error::Error for ValidationError {}

#[derive(Debug)]
pub enum OperationLogError {
    SequenceOutOfOrder {
        module: ModuleIdentifier,
        expected_min: u64,
        received: u64,
    },
    SequenceGap {
        module: ModuleIdentifier,
        expected: u64,
        actual: u64,
    },
    NodeNotFound(u64),
    EdgeNotFound(u64),
}

impl std::fmt::Display for OperationLogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SequenceOutOfOrder {
                module,
                expected_min,
                received,
            } => write!(
                f,
                "sequence out of order for {module:?}: expected >= {expected_min}, got {received}"
            ),
            Self::SequenceGap {
                module,
                expected,
                actual,
            } => write!(
                f,
                "sequence gap for {module:?}: expected {expected}, got {actual}"
            ),
            Self::NodeNotFound(id) => write!(f, "node {id} not found"),
            Self::EdgeNotFound(id) => write!(f, "edge {id} not found"),
        }
    }
}

impl std::error::Error for OperationLogError {}

/// Ordered log of graph operations with per-module sequence tracking.
///
/// Supports two sequencing modes:
///
/// - **Relaxed** (default via `new()`): sequence numbers must be monotonically
///   increasing per module but may have gaps. Suitable for distributed or async
///   operation submission where producers cannot coordinate sequence numbers.
///
/// - **Strict** (via `new_strict()`): sequence numbers must be consecutive with
///   no gaps (0, 1, 2, ...) per module. Suitable for single-writer audit trails
///   where any gap indicates lost operations.
///
/// Both modes reject out-of-order sequences (going backwards). The mode cannot
/// be changed after construction.
pub struct OperationLog {
    module_sequences: HashMap<ModuleIdentifier, u64>,
    total_applied: u64,
    strict_sequencing: bool,
}

impl OperationLog {
    /// Creates an operation log with relaxed sequencing (gaps allowed).
    pub fn new() -> Self {
        Self {
            module_sequences: HashMap::new(),
            total_applied: 0,
            strict_sequencing: false,
        }
    }

    /// Creates an operation log with strict sequencing (no gaps allowed).
    pub fn new_strict() -> Self {
        Self {
            module_sequences: HashMap::new(),
            total_applied: 0,
            strict_sequencing: true,
        }
    }

    pub fn validate_batch(
        &self,
        operations: &[GraphOperation],
        node_store: &NodeStore,
        edge_store: &EdgeStore,
    ) -> Result<(), ValidationError> {
        let mut batch_nodes: HashMap<u64, NodeType> = HashMap::new();
        let mut batch_edges: HashSet<(u64, u64, EdgeLabel)> = HashSet::new();
        let mut next_node_id = node_store.count() as u64;
        let mut next_edge_id = edge_store.count() as u64;

        for operation in operations {
            match operation {
                GraphOperation::AddNode { node_type, .. } => {
                    if batch_nodes.contains_key(&next_node_id) {
                        return Err(ValidationError::DuplicateNodeInBatch(next_node_id));
                    }
                    batch_nodes.insert(next_node_id, *node_type);
                    next_node_id += 1;
                }
                GraphOperation::AddEdge {
                    source_node_id,
                    target_node_id,
                    label,
                    weight,
                } => {
                    Self::validate_node_exists(
                        *source_node_id,
                        node_store,
                        &batch_nodes,
                        ValidationError::DanglingEdgeSource(*source_node_id),
                    )?;
                    Self::validate_node_exists(
                        *target_node_id,
                        node_store,
                        &batch_nodes,
                        ValidationError::DanglingEdgeTarget(*target_node_id),
                    )?;
                    Self::validate_weight(*weight)?;
                    let source_type =
                        Self::resolve_node_type(*source_node_id, node_store, &batch_nodes);
                    let target_type =
                        Self::resolve_node_type(*target_node_id, node_store, &batch_nodes);
                    if let (Some(st), Some(tt)) = (source_type, target_type)
                        && !aegis_protocol::edge::is_valid_edge(st, *label, tt)
                    {
                        return Err(ValidationError::InvalidEdgeSemantics {
                            source_type: st,
                            label: *label,
                            target_type: tt,
                        });
                    }
                    if edge_store.has_edge(*source_node_id, *target_node_id, *label) {
                        return Err(ValidationError::DuplicateEdge {
                            source: *source_node_id,
                            target: *target_node_id,
                            label: *label,
                        });
                    }
                    if batch_edges.contains(&(*source_node_id, *target_node_id, *label)) {
                        return Err(ValidationError::DuplicateEdge {
                            source: *source_node_id,
                            target: *target_node_id,
                            label: *label,
                        });
                    }
                    batch_edges.insert((*source_node_id, *target_node_id, *label));
                    next_edge_id += 1;
                }
                GraphOperation::UpdateWeight {
                    edge_id,
                    new_weight,
                } => {
                    let exists_in_store = edge_store.get(*edge_id).is_some();
                    let exists_in_batch =
                        *edge_id >= edge_store.count() as u64 && *edge_id < next_edge_id;
                    if !exists_in_store && !exists_in_batch {
                        return Err(ValidationError::EdgeNotFound(*edge_id));
                    }
                    Self::validate_weight(*new_weight)?;
                }
                GraphOperation::AddFinding {
                    linked_node_ids,
                    severity,
                    confidence: _,
                    ..
                } => {
                    for node_id in linked_node_ids {
                        Self::validate_node_exists(
                            *node_id,
                            node_store,
                            &batch_nodes,
                            ValidationError::NodeNotFoundForFinding(*node_id),
                        )?;
                    }
                    if !severity.is_finite() || !(0.0..=10.0).contains(severity) {
                        return Err(ValidationError::InvalidSeverity(*severity));
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_weight(weight: f64) -> Result<(), ValidationError> {
        if !weight.is_finite() || weight < 0.0 {
            return Err(ValidationError::InvalidWeight(weight));
        }
        Ok(())
    }

    fn resolve_node_type(
        node_id: u64,
        node_store: &NodeStore,
        batch_nodes: &HashMap<u64, NodeType>,
    ) -> Option<NodeType> {
        if let Some(node) = node_store.get(node_id) {
            Some(node.node_type)
        } else {
            batch_nodes.get(&node_id).copied()
        }
    }

    fn validate_node_exists(
        node_id: u64,
        node_store: &NodeStore,
        batch_nodes: &HashMap<u64, NodeType>,
        error: ValidationError,
    ) -> Result<(), ValidationError> {
        if node_store.get(node_id).is_some() || batch_nodes.contains_key(&node_id) {
            Ok(())
        } else {
            Err(error)
        }
    }

    pub fn apply_batch(
        &mut self,
        entries: &[OperationLogEntry],
        node_store: &mut NodeStore,
        edge_store: &mut EdgeStore,
        finding_store: &mut FindingStore,
    ) -> Result<u64, OperationLogError> {
        let mut applied = 0u64;

        for entry in entries {
            let current_seq = self
                .module_sequences
                .get(&entry.module)
                .copied()
                .unwrap_or(0);
            if self.strict_sequencing {
                if entry.sequence_number != current_seq {
                    return if entry.sequence_number < current_seq {
                        Err(OperationLogError::SequenceOutOfOrder {
                            module: entry.module,
                            expected_min: current_seq,
                            received: entry.sequence_number,
                        })
                    } else {
                        Err(OperationLogError::SequenceGap {
                            module: entry.module,
                            expected: current_seq,
                            actual: entry.sequence_number,
                        })
                    };
                }
            } else if entry.sequence_number < current_seq {
                return Err(OperationLogError::SequenceOutOfOrder {
                    module: entry.module,
                    expected_min: current_seq,
                    received: entry.sequence_number,
                });
            }

            self.apply_operation(
                &entry.operation,
                entry.module,
                entry.sequence_number,
                node_store,
                edge_store,
                finding_store,
            )?;

            self.module_sequences
                .insert(entry.module, entry.sequence_number + 1);
            self.total_applied += 1;
            applied += 1;
        }

        Ok(applied)
    }

    fn apply_operation(
        &self,
        operation: &GraphOperation,
        provenance_module: ModuleIdentifier,
        provenance_sequence: u64,
        node_store: &mut NodeStore,
        edge_store: &mut EdgeStore,
        finding_store: &mut FindingStore,
    ) -> Result<(), OperationLogError> {
        match operation {
            GraphOperation::AddNode {
                node_type,
                properties,
            } => {
                let props = properties.iter().cloned().collect();
                node_store.insert(*node_type, props);
            }
            GraphOperation::AddEdge {
                source_node_id,
                target_node_id,
                label,
                weight,
            } => {
                if node_store.get(*source_node_id).is_none() {
                    return Err(OperationLogError::NodeNotFound(*source_node_id));
                }
                if node_store.get(*target_node_id).is_none() {
                    return Err(OperationLogError::NodeNotFound(*target_node_id));
                }
                edge_store.insert(
                    *source_node_id,
                    *target_node_id,
                    *label,
                    *weight,
                    provenance_module,
                    provenance_sequence,
                );
            }
            GraphOperation::UpdateWeight {
                edge_id,
                new_weight,
            } => {
                if !edge_store.update_weight(*edge_id, *new_weight) {
                    return Err(OperationLogError::EdgeNotFound(*edge_id));
                }
            }
            GraphOperation::AddFinding {
                linked_node_ids,
                vulnerability_class,
                severity,
                confidence,
                certificate,
            } => {
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                finding_store.insert(
                    linked_node_ids.clone(),
                    *vulnerability_class,
                    *severity,
                    confidence.value(),
                    certificate.clone(),
                    provenance_module,
                    timestamp,
                );
            }
        }
        Ok(())
    }

    pub fn current_sequence(&self, module: ModuleIdentifier) -> u64 {
        self.module_sequences.get(&module).copied().unwrap_or(0)
    }

    pub fn total_applied(&self) -> u64 {
        self.total_applied
    }
}

impl Default for OperationLog {
    fn default() -> Self {
        Self::new()
    }
}
