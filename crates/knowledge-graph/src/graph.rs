use crate::edge_store::EdgeStore;
use crate::finding_store::FindingStore;
use crate::node_store::NodeStore;
use crate::operation_log::{OperationLog, OperationLogError};
use crate::query::path_queries::{self, PathResult, ShortestPathResult};
use crate::query::reachability;
use aegis_protocol::edge::EdgeLabel;
use aegis_protocol::finding::{FindingData, VulnerabilityClass};
use aegis_protocol::node::{NodeData, NodeType};
use aegis_protocol::operation::{ModuleIdentifier, OperationLogEntry};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

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

    pub fn apply_operations(
        &self,
        entries: &[OperationLogEntry],
    ) -> Result<u64, OperationLogError> {
        let mut inner = self.inner.write().unwrap();
        let KnowledgeGraphInner {
            ref mut node_store,
            ref mut edge_store,
            ref mut finding_store,
            ref mut operation_log,
        } = *inner;
        operation_log.apply_batch(entries, node_store, edge_store, finding_store)
    }

    pub fn find_paths_between(&self, from: u64, to: u64, max_hops: u32) -> PathResult {
        let inner = self.inner.read().unwrap();
        path_queries::find_paths_between(from, to, max_hops, &inner.node_store, &inner.edge_store)
    }

    pub fn shortest_path(&self, from: u64, to: u64) -> ShortestPathResult {
        let inner = self.inner.read().unwrap();
        path_queries::shortest_path(from, to, &inner.node_store, &inner.edge_store)
    }

    pub fn all_simple_paths_bounded(&self, from: u64, to: u64, max_length: u32) -> Vec<Vec<u64>> {
        let inner = self.inner.read().unwrap();
        path_queries::all_simple_paths_bounded(
            from,
            to,
            max_length,
            &inner.node_store,
            &inner.edge_store,
        )
    }

    pub fn reachable_from(&self, start: u64, edge_labels: &[EdgeLabel]) -> HashSet<u64> {
        let inner = self.inner.read().unwrap();
        reachability::reachable_from(start, edge_labels, &inner.node_store, &inner.edge_store)
    }

    pub fn cut_vertices(&self) -> Vec<u64> {
        let inner = self.inner.read().unwrap();
        reachability::cut_vertices(&inner.node_store, &inner.edge_store)
    }

    pub fn betweenness_centrality(&self) -> HashMap<u64, f64> {
        let inner = self.inner.read().unwrap();
        reachability::betweenness_centrality(&inner.node_store, &inner.edge_store)
    }

    pub fn nodes_by_type(&self, node_type: NodeType) -> Vec<u64> {
        let inner = self.inner.read().unwrap();
        reachability::nodes_by_type(node_type, &inner.node_store)
    }

    pub fn get_node(&self, id: u64) -> Option<NodeData> {
        let inner = self.inner.read().unwrap();
        inner.node_store.get(id).cloned()
    }

    pub fn get_finding(&self, id: u64) -> Option<FindingData> {
        let inner = self.inner.read().unwrap();
        inner.finding_store.get(id).cloned()
    }

    pub fn findings_by_class(&self, vulnerability_class: VulnerabilityClass) -> Vec<u64> {
        let inner = self.inner.read().unwrap();
        inner
            .finding_store
            .findings_by_class(vulnerability_class)
            .to_vec()
    }

    pub fn findings_for_node(&self, node_id: u64) -> Vec<u64> {
        let inner = self.inner.read().unwrap();
        inner.finding_store.findings_for_node(node_id).to_vec()
    }

    pub fn node_count(&self) -> usize {
        let inner = self.inner.read().unwrap();
        inner.node_store.count()
    }

    pub fn edge_count(&self) -> usize {
        let inner = self.inner.read().unwrap();
        inner.edge_store.count()
    }

    pub fn finding_count(&self) -> usize {
        let inner = self.inner.read().unwrap();
        inner.finding_store.count()
    }

    pub fn current_sequence(&self, module: ModuleIdentifier) -> u64 {
        let inner = self.inner.read().unwrap();
        inner.operation_log.current_sequence(module)
    }

    pub fn total_operations_applied(&self) -> u64 {
        let inner = self.inner.read().unwrap();
        inner.operation_log.total_applied()
    }
}

impl Default for KnowledgeGraph {
    fn default() -> Self {
        Self::new()
    }
}
