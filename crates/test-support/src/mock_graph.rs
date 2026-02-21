use aegis_protocol::operation::{GraphOperation, OperationLogEntry};

/// A lightweight recording store for graph operations.
///
/// Does not implement the full `GraphStore` trait from `knowledge-graph` —
/// instead provides a standalone `Vec`-backed store for capturing and
/// asserting on operations during integration tests.
pub struct MockGraphStore {
    operations: Vec<OperationLogEntry>,
}

impl MockGraphStore {
    pub fn new() -> Self {
        Self {
            operations: Vec::new(),
        }
    }

    /// Records a single operation log entry.
    pub fn apply(&mut self, entry: OperationLogEntry) {
        self.operations.push(entry);
    }

    /// Records a batch of operation log entries.
    pub fn apply_batch(&mut self, entries: &[OperationLogEntry]) {
        self.operations.extend_from_slice(entries);
    }

    /// Returns all recorded operations.
    pub fn operations(&self) -> &[OperationLogEntry] {
        &self.operations
    }

    /// Returns the number of `AddNode` operations recorded.
    pub fn node_count(&self) -> usize {
        self.operations
            .iter()
            .filter(|e| matches!(e.operation, GraphOperation::AddNode { .. }))
            .count()
    }

    /// Returns the number of `AddEdge` operations recorded.
    pub fn edge_count(&self) -> usize {
        self.operations
            .iter()
            .filter(|e| matches!(e.operation, GraphOperation::AddEdge { .. }))
            .count()
    }

    /// Returns the number of `AddFinding` operations recorded.
    pub fn finding_count(&self) -> usize {
        self.operations
            .iter()
            .filter(|e| matches!(e.operation, GraphOperation::AddFinding { .. }))
            .count()
    }

    /// Returns the total number of operations recorded.
    pub fn total_count(&self) -> usize {
        self.operations.len()
    }
}

impl Default for MockGraphStore {
    fn default() -> Self {
        Self::new()
    }
}
