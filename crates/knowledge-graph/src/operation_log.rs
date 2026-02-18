use crate::edge_store::EdgeStore;
use crate::finding_store::FindingStore;
use crate::node_store::NodeStore;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};
use std::collections::HashMap;

#[derive(Debug)]
pub enum OperationLogError {
    SequenceOutOfOrder {
        module: ModuleIdentifier,
        expected_min: u64,
        received: u64,
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
            Self::NodeNotFound(id) => write!(f, "node {id} not found"),
            Self::EdgeNotFound(id) => write!(f, "edge {id} not found"),
        }
    }
}

impl std::error::Error for OperationLogError {}

pub struct OperationLog {
    module_sequences: HashMap<ModuleIdentifier, u64>,
    total_applied: u64,
}

impl OperationLog {
    pub fn new() -> Self {
        Self {
            module_sequences: HashMap::new(),
            total_applied: 0,
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
            if entry.sequence_number < current_seq {
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
                    *confidence,
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
