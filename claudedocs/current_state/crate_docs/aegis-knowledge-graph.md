<!-- metadata:
  crate: aegis-knowledge-graph
  purpose: In-memory semantic graph engine tracking application structure and scan findings
  public_api: KnowledgeGraph, GraphStore (trait), GraphMetadata, GraphError,
              NodeStore, EdgeStore, FindingStore, OperationLog,
              ValidationError, OperationLogError,
              PathResult, ShortestPathResult,
              path_queries (find_paths_between, shortest_path, all_simple_paths_bounded, bfs_shortest_path_unweighted),
              reachability (reachable_from, cut_vertices, betweenness_centrality, nodes_by_type)
  modules: graph, graph_store, node_store, edge_store, finding_store, operation_log,
           query/path_queries, query/reachability
  dependencies: aegis-protocol, parking_lot, serde, serde_json
-->

# aegis-knowledge-graph

## Purpose

`aegis-knowledge-graph` is the in-memory graph engine that accumulates the AEGIS scan's
understanding of the target application. It stores nodes (endpoints, functions, data stores,
defenses, etc.), directed edges between them, and security findings, all within a single
thread-safe facade. The graph is the central data structure passed through every scan phase; each
phase reads from it and writes new `OperationLogEntry` batches back to it. The design enforces
semantic correctness (only 28 valid edge triples are accepted), prevents duplicate edges, and
ensures numeric bounds on weights and scores — making the graph an auditable, invariant-preserving
representation of the attack surface.

## Crate Type

Library

## Dependencies on Workspace Crates

- `aegis-protocol` — `NodeType`, `EdgeLabel`, `VulnerabilityClass`, `FindingData`,
  `NodeData`, `EdgeData`, `GraphOperation`, `OperationLogEntry`, `ModuleIdentifier`

## External Dependencies

| Dependency | Version | Role |
|---|---|---|
| parking_lot | 0.12 | `RwLock<Inner>` facade; upgradable read locks for TOCTOU-free validate-then-apply; no lock poisoning |
| serde | 1 | Store snapshot serialization/deserialization |
| serde_json | 1 | JSON persistence format for save/load |

Dev dependencies: `proptest` (1), `tempfile` (3)

## Module Structure

| Module | Responsibility |
|---|---|
| `graph` | `KnowledgeGraph` (public facade), `GraphError`, `GraphMetadata` |
| `graph_store` | `GraphStore` trait — minimal interface used by all pipeline phases; enables test fakes |
| `node_store` | `NodeStore` — arena-style Vec storage with type index; snapshot/restore |
| `edge_store` | `EdgeStore` — Vec storage with sorted outgoing + incoming adjacency lists; snapshot/restore |
| `finding_store` | `FindingStore` — Vec storage with node and class indexes; snapshot/restore |
| `operation_log` | `OperationLog` — per-module sequence tracking; batch validation + application; two sequencing modes |
| `query/path_queries` | DFS multi-path, Dijkstra shortest path, bounded DFS enumeration, BFS unweighted |
| `query/reachability` | BFS reachability (label-filtered), node-by-type lookup, cut vertex detection (Tarjan DFS), betweenness centrality (Brandes) |

## Public API Summary

### Trait: GraphStore

The primary interface that pipeline phases operate through. All phases accept `&dyn GraphStore` (or
a boxed/mutably-borrowed version), allowing lightweight test fakes to be injected without
constructing a full `KnowledgeGraph`.

```rust
pub trait GraphStore: Send + Sync {
    fn apply_operations(&mut self, ops: &[OperationLogEntry]) -> Result<(), GraphError>;
    fn nodes_by_type(&self, node_type: NodeType) -> Result<Vec<u64>, GraphError>;
    fn get_node(&self, id: u64) -> Result<Option<NodeData>, GraphError>;
    fn total_operations_applied(&self) -> Result<u64, GraphError>;
    fn all_findings(&self) -> Result<Vec<FindingData>, GraphError>;
    fn node_count(&self) -> Result<u64, GraphError>;
    fn findings_by_class(&self, vulnerability_class: VulnerabilityClass) -> Result<Vec<u64>, GraphError>;
    fn get_finding(&self, id: u64) -> Result<Option<FindingData>, GraphError>;
    // Default implementation is a no-op (appropriate for test fakes):
    fn save_to_file(&self, _path: &Path, _metadata: &GraphMetadata) -> Result<(), GraphError> { Ok(()) }
}
```

`Send + Sync` is required because `ScanContext` is moved across async tokio task boundaries.
Mutating methods take `&mut self`; read-only queries take `&self`.

### Struct: KnowledgeGraph

Thread-safe facade. All public methods acquire internal locks; callers never see raw lock guards.

```rust
pub struct KnowledgeGraph { inner: RwLock<KnowledgeGraphInner> }

impl KnowledgeGraph {
    pub fn new() -> Self;

    // Atomic validate-then-apply (upgradable read -> write lock upgrade)
    pub fn apply_operations(&self, entries: &[OperationLogEntry]) -> Result<u64, GraphError>;
    // Returns count of operations applied. Entire batch rejected if any validation fails.

    // Path queries (shared read lock)
    pub fn find_paths_between(&self, from: u64, to: u64, max_hops: u32) -> Result<PathResult, GraphError>;
    pub fn shortest_path(&self, from: u64, to: u64) -> Result<ShortestPathResult, GraphError>;
    pub fn all_simple_paths_bounded(&self, from: u64, to: u64, max_length: u32) -> Result<Vec<Vec<u64>>, GraphError>;

    // Reachability queries (shared read lock)
    pub fn reachable_from(&self, start: u64, edge_labels: &[EdgeLabel]) -> Result<HashSet<u64>, GraphError>;
    pub fn cut_vertices(&self) -> Result<Vec<u64>, GraphError>;
    pub fn betweenness_centrality(&self) -> Result<HashMap<u64, f64>, GraphError>;

    // Store queries (shared read lock)
    pub fn nodes_by_type(&self, node_type: NodeType) -> Result<Vec<u64>, GraphError>;
    pub fn get_node(&self, id: u64) -> Result<Option<NodeData>, GraphError>;
    pub fn get_finding(&self, id: u64) -> Result<Option<FindingData>, GraphError>;
    pub fn findings_by_class(&self, vulnerability_class: VulnerabilityClass) -> Result<Vec<u64>, GraphError>;
    pub fn findings_for_node(&self, node_id: u64) -> Result<Vec<u64>, GraphError>;
    pub fn all_findings(&self) -> Result<Vec<FindingData>, GraphError>;

    // Counters (shared read lock)
    pub fn node_count(&self) -> Result<u64, GraphError>;
    pub fn edge_count(&self) -> Result<usize, GraphError>;
    pub fn finding_count(&self) -> Result<usize, GraphError>;
    pub fn current_sequence(&self, module: ModuleIdentifier) -> Result<u64, GraphError>;
    pub fn total_operations_applied(&self) -> Result<u64, GraphError>;

    // Persistence (shared read lock + filesystem write)
    pub fn save_to_file(&self, path: &Path, metadata: &GraphMetadata) -> Result<(), GraphError>;
    pub fn load_from_file(path: &Path) -> Result<(Self, Option<GraphMetadata>), GraphError>;
}

impl GraphStore for KnowledgeGraph { ... }  // delegates to the methods above
impl Default for KnowledgeGraph { ... }
```

### Struct: GraphMetadata

```rust
pub struct GraphMetadata {
    pub scan_timestamp_unix_ms: u64,
    pub target_url: String,
    pub aegis_version: String,
    pub scan_count: u64,  // incremented each save; 0 on first save
}
```

### Enum: GraphError

```rust
pub enum GraphError {
    Validation(ValidationError),
    OperationLog(OperationLogError),
    Io(String),
}
impl std::error::Error for GraphError { fn source(&self) -> Option<&dyn Error + 'static> { ... } }
```

### Enum: ValidationError (from operation_log)

Returned when a batch violates graph invariants:

```rust
pub enum ValidationError {
    DuplicateNodeInBatch(u64),
    DanglingEdgeSource(u64),
    DanglingEdgeTarget(u64),
    EdgeNotFound(u64),
    NodeNotFoundForFinding(u64),
    InvalidEdgeSemantics { source_type: NodeType, label: EdgeLabel, target_type: NodeType },
    DuplicateEdge { source: u64, target: u64, label: EdgeLabel },
    InvalidWeight(f64),
    InvalidSeverity(f64),
    InvalidConfidence(f64),
}
```

### Enum: OperationLogError (from operation_log)

Returned during batch application when sequence ordering is violated:

```rust
pub enum OperationLogError {
    SequenceOutOfOrder { module: ModuleIdentifier, expected_min: u64, received: u64 },
    SequenceGap { module: ModuleIdentifier, expected: u64, actual: u64 },
    NodeNotFound(u64),
    EdgeNotFound(u64),
}
```

### Struct: OperationLog

```rust
pub struct OperationLog { ... }

impl OperationLog {
    pub fn new() -> Self;         // relaxed mode: gaps allowed, monotonically increasing
    pub fn new_strict() -> Self;  // strict mode: no gaps, consecutive per module

    pub fn validate_batch(
        &self,
        operations: &[GraphOperation],
        node_store: &NodeStore,
        edge_store: &EdgeStore,
    ) -> Result<(), ValidationError>;

    pub fn apply_batch(
        &mut self,
        entries: &[OperationLogEntry],
        node_store: &mut NodeStore,
        edge_store: &mut EdgeStore,
        finding_store: &mut FindingStore,
    ) -> Result<u64, OperationLogError>;

    pub fn current_sequence(&self, module: ModuleIdentifier) -> u64;
    pub fn total_applied(&self) -> u64;
}
```

### Stores (internal, used by KnowledgeGraph — exposed for query layers)

```rust
// Arena-style Vec with type index
pub struct NodeStore { ... }
impl NodeStore {
    pub fn insert(&mut self, node_type: NodeType, properties: HashMap<String, String>) -> u64;
    pub fn get(&self, id: u64) -> Option<&NodeData>;
    pub fn get_mut(&mut self, id: u64) -> Option<&mut NodeData>;
    pub fn count(&self) -> usize;
    pub fn iter(&self) -> impl Iterator<Item = &NodeData>;
    pub fn nodes_by_type(&self, node_type: NodeType) -> &[u64];
    pub fn snapshot(&self) -> Vec<u8>;
    pub fn restore(data: &[u8]) -> Result<Self, String>;
}

// Vec with sorted outgoing adjacency + incoming adjacency (for Tarjan)
pub struct EdgeStore { ... }
impl EdgeStore {
    pub fn insert(source, target, label, weight, provenance_module, provenance_sequence) -> u64;
    pub fn get(&self, id: u64) -> Option<&EdgeData>;
    pub fn outgoing_edges(&self, node_id: u64) -> &[u64];  // sorted by target_node_id
    pub fn incoming_edges(&self, node_id: u64) -> &[u64];
    pub fn count(&self) -> usize;
    pub fn iter(&self) -> impl Iterator<Item = &EdgeData>;
    pub fn has_edge(&self, source: u64, target: u64, label: EdgeLabel) -> bool;
    pub fn update_weight(&mut self, edge_id: u64, new_weight: f64) -> bool;
    pub fn snapshot(&self) -> Vec<u8>;
    pub fn restore(data: &[u8]) -> Result<Self, String>;
}

// Vec with node and class indexes
pub struct FindingStore { ... }
impl FindingStore {
    pub fn insert(linked_node_ids, vulnerability_class, severity, confidence, certificate, provenance_module, timestamp_unix_ms) -> u64;
    pub fn get(&self, id: u64) -> Option<&FindingData>;
    pub fn findings_for_node(&self, node_id: u64) -> &[u64];
    pub fn findings_by_class(&self, vulnerability_class: VulnerabilityClass) -> &[u64];
    pub fn count(&self) -> usize;
    pub fn iter(&self) -> impl Iterator<Item = &FindingData>;
    pub fn snapshot(&self) -> Vec<u8>;
    pub fn restore(data: &[u8]) -> Result<Self, String>;
}
```

### Query Functions

```rust
// path_queries module
pub struct PathResult { pub paths: Vec<Vec<u64>> }
pub struct ShortestPathResult { pub path: Vec<u64>, pub total_weight: f64, pub found: bool }

pub fn find_paths_between(from, to, max_hops, node_store, edge_store) -> PathResult;
// Iterative DFS, avoids revisiting nodes within a path, returns all paths up to max_hops

pub fn shortest_path(from, to, node_store, edge_store) -> ShortestPathResult;
// Dijkstra with BinaryHeap; uses edge weights as costs

pub fn all_simple_paths_bounded(from, to, max_length, node_store, edge_store) -> Vec<Vec<u64>>;
// Recursive DFS with visited set; returns all simple paths up to max_length hops

pub fn bfs_shortest_path_unweighted(from, to, node_store, edge_store) -> Option<Vec<u64>>;
// BFS for hop-count shortest path (ignores weights)

// reachability module
pub fn reachable_from(start, edge_labels: &[EdgeLabel], node_store, edge_store) -> HashSet<u64>;
// BFS; if edge_labels is empty, traverses all edge types

pub fn nodes_by_type(node_type: NodeType, node_store: &NodeStore) -> Vec<u64>;
// Delegates to NodeStore's type index

pub fn cut_vertices(node_store, edge_store) -> Vec<u64>;
// Tarjan's articulation point algorithm on the undirected underlying graph
// (uses both outgoing and incoming edges as neighbors)

pub fn betweenness_centrality(node_store, edge_store) -> HashMap<u64, f64>;
// Brandes algorithm; normalized by 1/((n-1)*(n-2)) when n > 2
```

## Error Types

All public `KnowledgeGraph` methods return `Result<T, GraphError>`. `GraphError` wraps:
- `ValidationError` for semantic violations (bad edge type, duplicate edge, out-of-range values)
- `OperationLogError` for sequence violations
- `Io(String)` for persistence errors

`parking_lot::RwLock` does not poison on panic (unlike `std::sync::RwLock`), so
`GraphError::LockPoisoned` does not exist. `EdgeStore.get()` is used instead of direct indexing to
avoid panics on out-of-bounds access.

## Key Implementation Notes

**Atomic validate-then-apply is the central correctness guarantee.** `apply_operations` acquires a
`parking_lot::RwLockUpgradableReadGuard` for validation. This allows concurrent readers during
validation while ensuring no writer can intervene between validation completion and lock upgrade.
The upgrade to `RwLockWriteGuard` is atomic — no other write can occur in the gap.

**Batch validation tracks intra-batch state.** `OperationLog::validate_batch` builds a
`HashMap<u64, NodeType>` of nodes added within the current batch and a
`HashSet<(u64, u64, EdgeLabel)>` of edges added within the current batch. This catches within-batch
duplicates and allows edges to reference nodes defined earlier in the same batch, before those
nodes have been written to the actual store.

**Arena storage uses Vec index as the stable ID.** Node id = `nodes.len()` before push; edge id =
`edges.len()` before push. This is O(1) for both insert and lookup. IDs are monotonically
increasing and never reused (append-only). No deletion is supported — dead code must be tracked
externally if needed.

**Outgoing edges are kept sorted by target_node_id.** `EdgeStore::insert` performs a binary search
to maintain the sorted outgoing list. This enables deterministic traversal order in path algorithms
(the chain-synthesis crate relies on this for reproducible path enumeration).

**Snapshot/restore serializes index structures alongside data.** Both the `Vec` of items and the
`HashMap` indexes are serialized in `snapshot()`. While the indexes are derivable from the Vec
data, re-serializing them avoids a full re-index pass on `restore()`.

**Operation log has two sequencing modes.** `new()` (relaxed) allows sequence number gaps per
module; `new_strict()` requires perfectly consecutive numbers with no gaps. The pipeline uses
relaxed mode by default. Strict mode is available for single-writer audit trails where a gap
indicates a lost operation.

**Load from file resets the operation log.** `KnowledgeGraph::load_from_file` restores node, edge,
and finding stores from the JSON bundle but starts with a fresh `OperationLog::new()`. Operation
history is not persisted — only store state. The returned `Option<GraphMetadata>` is present
whenever the file contains a `"metadata"` key.

**`GraphStore` trait default `save_to_file` is a no-op.** Test fakes that implement `GraphStore`
do not need to implement persistence. Only the concrete `KnowledgeGraph` overrides this with an
actual file write.

## Usage Context

`KnowledgeGraph` is constructed once in the orchestrator's `ScanContext` and passed by `Box<dyn
GraphStore>` reference through each scan phase. Phases accumulate `OperationLogEntry` slices and
call `apply_operations`. After all phases complete, the orchestrator calls `all_findings()` to
collect results for reporting. If `--graph-db` is specified, `save_to_file` is called after each
phase for checkpoint/resume. The chain-synthesis crate builds its petgraph attack graph by reading
from a `KnowledgeGraph` instance.
