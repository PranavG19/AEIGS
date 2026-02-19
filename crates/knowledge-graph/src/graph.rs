use crate::edge_store::EdgeStore;
use crate::finding_store::FindingStore;
use crate::node_store::NodeStore;
use crate::operation_log::{OperationLog, OperationLogError, ValidationError};
use crate::query::path_queries::{self, PathResult, ShortestPathResult};
use crate::query::reachability;
use aegis_protocol::edge::EdgeLabel;
use aegis_protocol::finding::{FindingData, VulnerabilityClass};
use aegis_protocol::node::{NodeData, NodeType};
use aegis_protocol::operation::{ModuleIdentifier, OperationLogEntry};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[derive(Debug)]
pub enum GraphError {
    Validation(ValidationError),
    OperationLog(OperationLogError),
    Io(String),
}

impl std::fmt::Display for GraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(e) => write!(f, "batch validation failed: {e}"),
            Self::OperationLog(e) => write!(f, "operation log error: {e}"),
            Self::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for GraphError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Validation(e) => Some(e),
            Self::OperationLog(e) => Some(e),
            Self::Io(_) => None,
        }
    }
}

impl From<ValidationError> for GraphError {
    fn from(err: ValidationError) -> Self {
        Self::Validation(err)
    }
}

impl From<OperationLogError> for GraphError {
    fn from(err: OperationLogError) -> Self {
        Self::OperationLog(err)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GraphMetadata {
    pub scan_timestamp_unix_ms: u64,
    pub target_url: String,
    pub aegis_version: String,
}

/// Thread-safe knowledge graph facade with atomic validate-then-apply semantics.
///
/// All public methods acquire locks internally — callers never see raw locks.
/// Read-only queries use a shared read lock (multiple concurrent readers allowed).
/// Mutations use an upgradable read lock that atomically upgrades to a write lock,
/// eliminating the TOCTOU gap between validation and application.
///
/// # Graph Invariant
///
/// After every successful `apply_operations` call, the graph maintains:
/// 1. All edges satisfy [`is_valid_edge`](aegis_protocol::edge::is_valid_edge) — only the 28 valid semantic triples accepted
/// 2. All edge weights are finite and >= 0.0
/// 3. All finding severities are in \[0.0, 10.0\] and confidences in \[0.0, 1.0\]
/// 4. No duplicate edges (same source, target, and label)
/// 5. Operation sequences are consecutive per module (in strict mode)
///
/// A batch that violates any constraint is rejected entirely — no partial application.
pub struct KnowledgeGraph {
    inner: RwLock<KnowledgeGraphInner>,
}

struct KnowledgeGraphInner {
    node_store: NodeStore,
    edge_store: EdgeStore,
    finding_store: FindingStore,
    operation_log: OperationLog,
}

impl KnowledgeGraph {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(KnowledgeGraphInner {
                node_store: NodeStore::new(),
                edge_store: EdgeStore::new(),
                finding_store: FindingStore::new(),
                operation_log: OperationLog::new(),
            }),
        }
    }

    /// Validates and applies a batch of operations atomically.
    ///
    /// Acquires an upgradable read lock for validation (allowing concurrent readers),
    /// then atomically upgrades to a write lock for application. No other writer can
    /// intervene between validation and application.
    ///
    /// Returns the number of operations applied, or an error if validation fails
    /// (in which case the graph is completely unchanged).
    pub fn apply_operations(&self, entries: &[OperationLogEntry]) -> Result<u64, GraphError> {
        let operations: Vec<_> = entries.iter().map(|e| e.operation.clone()).collect();

        let upgradable = self.inner.upgradable_read();
        upgradable.operation_log.validate_batch(
            &operations,
            &upgradable.node_store,
            &upgradable.edge_store,
        )?;

        let mut inner = parking_lot::RwLockUpgradableReadGuard::upgrade(upgradable);
        let KnowledgeGraphInner {
            ref mut node_store,
            ref mut edge_store,
            ref mut finding_store,
            ref mut operation_log,
        } = *inner;
        Ok(operation_log.apply_batch(entries, node_store, edge_store, finding_store)?)
    }

    pub fn find_paths_between(
        &self,
        from: u64,
        to: u64,
        max_hops: u32,
    ) -> Result<PathResult, GraphError> {
        let inner = self.inner.read();
        Ok(path_queries::find_paths_between(
            from,
            to,
            max_hops,
            &inner.node_store,
            &inner.edge_store,
        ))
    }

    pub fn shortest_path(&self, from: u64, to: u64) -> Result<ShortestPathResult, GraphError> {
        let inner = self.inner.read();
        Ok(path_queries::shortest_path(
            from,
            to,
            &inner.node_store,
            &inner.edge_store,
        ))
    }

    pub fn all_simple_paths_bounded(
        &self,
        from: u64,
        to: u64,
        max_length: u32,
    ) -> Result<Vec<Vec<u64>>, GraphError> {
        let inner = self.inner.read();
        Ok(path_queries::all_simple_paths_bounded(
            from,
            to,
            max_length,
            &inner.node_store,
            &inner.edge_store,
        ))
    }

    pub fn reachable_from(
        &self,
        start: u64,
        edge_labels: &[EdgeLabel],
    ) -> Result<HashSet<u64>, GraphError> {
        let inner = self.inner.read();
        Ok(reachability::reachable_from(
            start,
            edge_labels,
            &inner.node_store,
            &inner.edge_store,
        ))
    }

    pub fn cut_vertices(&self) -> Result<Vec<u64>, GraphError> {
        let inner = self.inner.read();
        Ok(reachability::cut_vertices(
            &inner.node_store,
            &inner.edge_store,
        ))
    }

    pub fn betweenness_centrality(&self) -> Result<HashMap<u64, f64>, GraphError> {
        let inner = self.inner.read();
        Ok(reachability::betweenness_centrality(
            &inner.node_store,
            &inner.edge_store,
        ))
    }

    pub fn nodes_by_type(&self, node_type: NodeType) -> Result<Vec<u64>, GraphError> {
        let inner = self.inner.read();
        Ok(reachability::nodes_by_type(node_type, &inner.node_store))
    }

    pub fn get_node(&self, id: u64) -> Result<Option<NodeData>, GraphError> {
        let inner = self.inner.read();
        Ok(inner.node_store.get(id).cloned())
    }

    pub fn get_finding(&self, id: u64) -> Result<Option<FindingData>, GraphError> {
        let inner = self.inner.read();
        Ok(inner.finding_store.get(id).cloned())
    }

    pub fn findings_by_class(
        &self,
        vulnerability_class: VulnerabilityClass,
    ) -> Result<Vec<u64>, GraphError> {
        let inner = self.inner.read();
        Ok(inner
            .finding_store
            .findings_by_class(vulnerability_class)
            .to_vec())
    }

    pub fn findings_for_node(&self, node_id: u64) -> Result<Vec<u64>, GraphError> {
        let inner = self.inner.read();
        Ok(inner.finding_store.findings_for_node(node_id).to_vec())
    }

    pub fn node_count(&self) -> Result<usize, GraphError> {
        let inner = self.inner.read();
        Ok(inner.node_store.count())
    }

    pub fn edge_count(&self) -> Result<usize, GraphError> {
        let inner = self.inner.read();
        Ok(inner.edge_store.count())
    }

    pub fn finding_count(&self) -> Result<usize, GraphError> {
        let inner = self.inner.read();
        Ok(inner.finding_store.count())
    }

    pub fn current_sequence(&self, module: ModuleIdentifier) -> Result<u64, GraphError> {
        let inner = self.inner.read();
        Ok(inner.operation_log.current_sequence(module))
    }

    pub fn total_operations_applied(&self) -> Result<u64, GraphError> {
        let inner = self.inner.read();
        Ok(inner.operation_log.total_applied())
    }

    pub fn save_to_file(&self, path: &Path, metadata: &GraphMetadata) -> Result<(), GraphError> {
        let inner = self.inner.read();
        let nodes = inner.node_store.snapshot();
        let edges = inner.edge_store.snapshot();
        let findings = inner.finding_store.snapshot();

        let nodes_val: serde_json::Value =
            serde_json::from_slice(&nodes).map_err(|e| GraphError::Io(e.to_string()))?;
        let edges_val: serde_json::Value =
            serde_json::from_slice(&edges).map_err(|e| GraphError::Io(e.to_string()))?;
        let findings_val: serde_json::Value =
            serde_json::from_slice(&findings).map_err(|e| GraphError::Io(e.to_string()))?;
        let metadata_val =
            serde_json::to_value(metadata).map_err(|e| GraphError::Io(e.to_string()))?;

        let bundle = serde_json::json!({
            "nodes": nodes_val,
            "edges": edges_val,
            "findings": findings_val,
            "metadata": metadata_val,
        });

        let bytes = serde_json::to_vec(&bundle).map_err(|e| GraphError::Io(e.to_string()))?;
        std::fs::write(path, bytes).map_err(|e| GraphError::Io(e.to_string()))
    }

    pub fn load_from_file(path: &Path) -> Result<Self, GraphError> {
        let bytes = std::fs::read(path).map_err(|e| GraphError::Io(e.to_string()))?;
        let bundle: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| GraphError::Io(e.to_string()))?;

        let nodes_bytes = serde_json::to_vec(
            bundle
                .get("nodes")
                .ok_or_else(|| GraphError::Io("missing 'nodes' key".into()))?,
        )
        .map_err(|e| GraphError::Io(e.to_string()))?;
        let edges_bytes = serde_json::to_vec(
            bundle
                .get("edges")
                .ok_or_else(|| GraphError::Io("missing 'edges' key".into()))?,
        )
        .map_err(|e| GraphError::Io(e.to_string()))?;
        let findings_bytes = serde_json::to_vec(
            bundle
                .get("findings")
                .ok_or_else(|| GraphError::Io("missing 'findings' key".into()))?,
        )
        .map_err(|e| GraphError::Io(e.to_string()))?;

        let node_store =
            NodeStore::restore(&nodes_bytes).map_err(|e| GraphError::Io(e.to_string()))?;
        let edge_store =
            EdgeStore::restore(&edges_bytes).map_err(|e| GraphError::Io(e.to_string()))?;
        let finding_store =
            FindingStore::restore(&findings_bytes).map_err(|e| GraphError::Io(e.to_string()))?;

        Ok(Self {
            inner: RwLock::new(KnowledgeGraphInner {
                node_store,
                edge_store,
                finding_store,
                operation_log: OperationLog::new(),
            }),
        })
    }
}

impl Default for KnowledgeGraph {
    fn default() -> Self {
        Self::new()
    }
}
