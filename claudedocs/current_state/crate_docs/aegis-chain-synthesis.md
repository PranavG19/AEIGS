<!-- metadata: crate=aegis-chain-synthesis, purpose=attack graph construction + shortest path / betweenness centrality analysis + defense gap detection + DOT/D3 export, type=library, internal_deps=[aegis-protocol, aegis-knowledge-graph], external_deps=[petgraph, serde_json] -->

# aegis-chain-synthesis

## Purpose

Constructs directed attack graphs from vulnerability findings and security boundaries, performs graph-theoretic path analysis (shortest path, all simple paths, betweenness centrality, mitigation impact estimation), identifies defense gaps, and exports graphs in Graphviz DOT and D3.js JSON formats.

## Crate Type

Library

## Dependencies on Workspace Crates

- `aegis-protocol` — `VulnerabilityClass`, `NodeType` (used for graph construction from scan findings)
- `aegis-knowledge-graph` — reads `FindingData`, `NodeData` for translating the knowledge graph into an `AttackGraph`

**Note:** The `AttackGraph` type itself is fully self-contained (no protocol types in its own struct/method signatures), but the crate does import and use protocol/knowledge-graph types in its construction helpers.

## External Dependencies

- `petgraph` — `DiGraph<AttackNode, AttackEdge>`, `astar`, `Bfs`, `NodeIndex`, `Direction`
- `serde_json` — D3.js JSON export (`export_d3_json`)

## Module Structure

| Module | Description |
|---|---|
| `attack_graph` | `AttackGraph` — petgraph-backed directed graph with 4 node types; add/query nodes and edges; `estimated_mitigation_impact` |
| `path_analysis` | Shortest path (A*), all simple paths (priority-bounded DFS), BFS reachability, betweenness centrality, `graph_influence_ranking` |
| `graph_export` | DOT export, D3.js JSON export, `analyze_defense_gaps` |

## Public API Summary

### `attack_graph`

```rust
pub enum AttackNodeType {
    EntryPoint,       // green diamond in DOT
    SecurityBoundary, // blue hexagon in DOT
    Vulnerability,    // red octagon in DOT
    Asset,            // gold box in DOT
}
// implements Display: "entry-point", "security-boundary", "vulnerability", "asset"

pub struct AttackNode { pub id: u64, pub label: String, pub node_type: AttackNodeType }

pub struct AttackEdge {
    pub source: u64, pub target: u64,
    pub vulnerability_id: Option<u64>,
    pub exploitation_difficulty: f64,   // used as edge weight in path analysis
}

pub struct AttackPath {
    pub nodes: Vec<u64>,
    pub total_difficulty: f64,
    pub edges: Vec<AttackEdge>,
}

pub struct MitigationResult {
    pub removed_findings: Vec<NodeIndex>,  // asset nodes made unreachable
    pub findings_remaining: usize,
    pub impact_score: f64,                 // removed/total_assets, range [0.0, 1.0]
}

pub struct AttackGraph { /* private */ }

impl AttackGraph {
    pub fn new() -> Self
    /// Adds a node with an auto-assigned sequential u64 ID. Returns the ID.
    pub fn add_node(&mut self, label: String, node_type: AttackNodeType) -> u64
    /// Adds a directed edge. Returns None if source or target IDs don't exist.
    pub fn add_edge(&mut self, source: u64, target: u64,
        difficulty: f64, vulnerability_id: Option<u64>) -> Option<()>
    pub fn node(&self, id: u64) -> Option<&AttackNode>
    pub fn node_count(&self) -> usize
    pub fn edge_count(&self) -> usize
    pub fn outgoing_edges(&self, node_id: u64) -> Vec<&AttackEdge>
    /// Returns outgoing neighbors sorted by petgraph NodeIndex for deterministic traversal.
    pub fn sorted_neighbors(&self, node_idx: NodeIndex) -> Vec<NodeIndex>
    pub fn entry_points(&self) -> Vec<u64>
    pub fn assets(&self) -> Vec<u64>
    pub fn nodes_by_type(&self, node_type: AttackNodeType) -> Vec<u64>
    pub fn all_edges(&self) -> Vec<&AttackEdge>
    pub fn contains_node(&self, id: u64) -> bool
    pub fn inner_graph(&self) -> &DiGraph<AttackNode, AttackEdge>
    pub fn node_index(&self, id: u64) -> Option<NodeIndex>
    /// Estimates which asset nodes become unreachable from all entry points if node_idx is removed.
    /// BFS per entry point, skipping node_idx. Structural estimate only — not causal.
    pub fn estimated_mitigation_impact(&self, node_idx: NodeIndex) -> MitigationResult
}
```

### `path_analysis`

```rust
pub const MAX_TOTAL_PATHS: usize = 100_000;

/// BFS reachability: entry_point_id -> Vec<reachable_asset_id>
pub fn reachable_assets(graph: &AttackGraph) -> HashMap<u64, Vec<u64>>

/// A* shortest path by exploitation_difficulty. Returns None if no path exists.
pub fn shortest_attack_path(graph: &AttackGraph, source: u64, target: u64)
    -> Option<AttackPath>

/// Priority-bounded DFS: lowest-difficulty edges explored first.
/// Capped at MAX_TOTAL_PATHS. Results sorted by ascending total_difficulty.
pub fn all_simple_paths(graph: &AttackGraph, source: u64, target: u64, max_depth: usize)
    -> Vec<AttackPath>

/// Betweenness centrality across all (entry_point, asset) pairs.
/// Capped at MAX_TOTAL_PATHS cumulative paths. Returns node_id -> score.
pub fn betweenness_centrality(graph: &AttackGraph) -> HashMap<u64, f64>

/// Top `budget` nodes by betweenness centrality, descending.
pub fn critical_fix_targets(graph: &AttackGraph, budget: usize) -> Vec<(u64, f64)>

/// Ranks non-entry, non-asset nodes by estimated mitigation impact (descending impact_score).
/// NOTE: Structural graph estimate — not a causal claim.
pub fn graph_influence_ranking(graph: &AttackGraph) -> Vec<(NodeIndex, MitigationResult)>
```

### `graph_export`

```rust
#[derive(Debug, Clone, PartialEq)]
pub struct DefenseGapReport {
    pub unprotected_entry_points: Vec<u64>,
    pub unprotected_assets: Vec<u64>,
    pub total_entry_points: usize,
    pub total_assets: usize,
}

/// Graphviz DOT with node shapes/colors by type; edge colors by difficulty.
/// Labels are dot_escaped to prevent Graphviz injection.
pub fn export_dot(graph: &AttackGraph) -> String

/// D3.js-compatible {"nodes":[...], "links":[...]} JSON.
pub fn export_d3_json(graph: &AttackGraph) -> String

/// Identifies entry points and assets with no adjacent SecurityBoundary node
/// (checks both incoming and outgoing directions).
pub fn analyze_defense_gaps(graph: &AttackGraph) -> DefenseGapReport
```

## Key Implementation Notes

- **`AttackGraph` type is self-contained**: The `AttackGraph` struct and its methods use only its own node/edge types (`AttackNodeType`, `AttackNode`, `AttackEdge`). However, the crate's Cargo.toml does declare `aegis-protocol` and `aegis-knowledge-graph` as dependencies — these are used in construction helper functions that translate `FindingData` from the knowledge graph into `AttackGraph` entries. The orchestrator's `phase_analyze` calls these helpers.

- **`MAX_TOTAL_PATHS = 100_000` cap prevents runaway DFS**: Both `all_simple_paths` and `betweenness_centrality` check `results.len() >= MAX_TOTAL_PATHS` on every iteration. Theoretical max for typical graphs (E=20, A=10, b=3, d=8) is ~1.3M paths — the cap ensures bounded runtime (path_analysis.rs:186-188 comment).

- **Priority DFS explores lowest-difficulty edges first**: Within each node, neighbors are sorted by `exploitation_difficulty` ascending before recursing. When the cap is hit, the most exploitable paths have already been recorded (path_analysis.rs:132-183).

- **`sorted_neighbors` uses `NodeIndex.index()` for determinism**: Sorting by petgraph's internal index ensures consistent traversal order across runs, preventing non-deterministic test failures from hash map ordering (attack_graph.rs:123-130).

- **`estimated_mitigation_impact` is O(E * N)**:  BFS is run from each entry point (excluding `node_idx`). Asset nodes reachable via any surviving entry point are not counted as "removed". The ratio `removed / total_assets` is the `impact_score` (attack_graph.rs:168-228).

- **`betweenness_centrality` normalizes per (entry, asset) pair**: For each pair, each intermediate node on any path gets `1/total_paths` added to its score. Scores are accumulated across all pairs, preventing high-path-count pairs from dominating (path_analysis.rs:189-226).

- **`analyze_defense_gaps` checks both directions for boundary neighbors**: A WAF serving as incoming neighbor to an entry point, or a firewall between an asset and upstream components, both count as "protected" (graph_export.rs:121-143).

- **`dot_escape` uses simple backslash replacement**: `s.replace('\\', "\\\\").replace('"', "\\\"")`. Node labels from finding descriptions or endpoint paths could contain quotes or backslashes that would break DOT syntax (graph_export.rs:187-189).

- **`MitigationResult.impact_score = 0.0` when no assets exist**: Protected by early return when `total_findings == 0` to avoid division by zero (attack_graph.rs:177-183).

## Usage Context

Called by the orchestrator's `phase_analyze` step. After the fuzz loop completes, the knowledge graph's findings are translated into `AttackGraph` nodes (endpoints as `EntryPoint`, vulnerabilities as `Vulnerability`, data stores as `Asset`, WAF/auth layers as `SecurityBoundary`) and edges (difficulty = `1 - confidence`). `critical_fix_targets` output feeds into `SarifFinding.mitigation_rank`. DOT and D3 exports are produced when `--export-dot` is passed to the CLI.
