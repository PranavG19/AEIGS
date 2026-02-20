use aegis_protocol::finding::{FindingData, VulnerabilityClass};
use aegis_protocol::node::{NodeData, NodeType};
use aegis_protocol::operation::OperationLogEntry;

use crate::graph::GraphError;

/// Minimal graph access surface required by the scan pipeline.
///
/// All phase functions operate through this trait so that tests can inject
/// lightweight fakes instead of constructing a full `KnowledgeGraph`.
///
/// # Invariants
///
/// Implementations must be `Send + Sync` so `ScanContext` can be moved across
/// async boundaries. Methods that mutate state take `&mut self`; read-only
/// queries take `&self`.
pub trait GraphStore: Send + Sync {
    /// Validate and apply a batch of operations atomically.
    fn apply_operations(&mut self, ops: &[OperationLogEntry]) -> Result<(), GraphError>;

    /// Return the ids of all nodes whose `node_type` matches `node_type`.
    fn nodes_by_type(&self, node_type: NodeType) -> Result<Vec<u64>, GraphError>;

    /// Return the `NodeData` for `id`, or `None` if no such node exists.
    fn get_node(&self, id: u64) -> Result<Option<NodeData>, GraphError>;

    /// Return the total number of operations applied since construction.
    fn total_operations_applied(&self) -> Result<u64, GraphError>;

    /// Return all findings stored in the graph, regardless of class.
    fn all_findings(&self) -> Result<Vec<FindingData>, GraphError>;

    /// Return the number of nodes currently in the graph.
    fn node_count(&self) -> Result<u64, GraphError>;

    /// Return the ids of all findings whose `vulnerability_class` matches.
    fn findings_by_class(
        &self,
        vulnerability_class: VulnerabilityClass,
    ) -> Result<Vec<u64>, GraphError>;

    /// Return the `FindingData` for `id`, or `None` if no such finding exists.
    fn get_finding(&self, id: u64) -> Result<Option<FindingData>, GraphError>;
}
