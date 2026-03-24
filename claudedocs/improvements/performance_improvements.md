# Performance Improvements

Generated: 2026-02-23 | Source depth: 2 (source-confirmed for high/critical)

---

### PERF-001: Blocking File I/O on Tokio Thread Pool (Critical Path)
**Severity:** high
**Effort:** medium
**Affected:** aegis-orchestrator
**Source confirmed:** yes (0 uses of tokio::fs, 0 uses of spawn_blocking)

The scan pipeline is async but uses `std::fs` blocking I/O throughout:
- SARIF report write: `std::fs::write(&ctx.config.output, json)` in `phase_report.rs:163`
- Checkpoint write/read: `std::fs::write`, `std::fs::rename`, `std::fs::read_to_string` in `checkpoint.rs`
- Audit log: Every `append_event()` call does `file.write_all()` + `file.flush()`

The audit log writes are most impactful since they happen multiple times per scan phase. Blocking a Tokio worker thread for disk I/O prevents it from processing other ready futures.

**Recommendation:**
- Convert all `std::fs::write` in async functions to `tokio::fs::write().await`
- For the audit log (synchronous by design), consider batched writes: buffer entries in memory and flush on a `tokio::task::spawn_blocking` thread periodically, or use `tokio::io::AsyncWrite`
- For checkpoints, `std::fs::rename` is typically fast (same-filesystem), but wrapping in `spawn_blocking` is still correct

---

### PERF-002: Recon and Crawl Phases Run Sequentially When They Could Parallelize
**Severity:** medium
**Effort:** medium
**Affected:** aegis-orchestrator
**Source confirmed:** yes (pipeline.rs lines 1522-1543 shows sequential execution)

The pipeline DAG correctly marks `recon` and `crawl` as independent Source phases (both can start immediately). However, execution is sequential. While the current crawl is a stub (`CrawlResult::default()`), when the crawler is wired, running recon (filesystem + DB operations) concurrently with browser crawling (network + CPU) could reduce total scan time.

**Recommendation:** Once the crawler is wired, use:
```rust
let (recon_ops, crawl_result) = tokio::join!(
    run_recon_phase_async(ctx, ...),
    run_crawl_phase_async(ctx, ...)
);
```
Add async versions of both phase functions.

---

### PERF-003: Hypothesis Bridge Round-Trip Per Iteration is Synchronous
**Severity:** medium
**Effort:** large
**Affected:** aegis-orchestrator
**Source confirmed:** yes (hypothesis_bridge.rs shows request-response on single socket)

The hypothesis bridge performs one request-response per operation:
1. `generate_hypotheses()` → send + wait → receive
2. `compile_payloads()` → send + wait → receive

For scans with many iterations, this adds 2 × network round-trips to Python per iteration. The 120-second timeout per call means a slow LLM could block the pipeline for up to 4 minutes per iteration.

**Recommendation:**
- Add a `generate_and_compile()` combined RPC to the bridge protocol that does both steps server-side, halving round-trips
- Consider making the bridge async (using `tokio::net::UnixStream`) so the scan can continue doing lightweight work while waiting for the LLM

---

### PERF-004: FuzzScheduler UCB1 Scoring Recalculated on Every Dequeue
**Severity:** low
**Effort:** medium
**Affected:** aegis-fuzzing
**Source confirmed:** partial

`PayloadSelector::ucb1_score()` is called during scheduling. If the score calculation is expensive (involves `sqrt` and `ln`), and if the scheduler dequeues thousands of targets, this could be measurable. However, the UCB1 formula is O(1) so this is likely not a real bottleneck.

**Recommendation:** Profile before optimizing. If measurements show scheduling overhead, cache UCB1 scores and invalidate on `record_outcome()`.

---

### PERF-005: Knowledge Graph Lock Acquisition Pattern
**Severity:** low
**Effort:** small
**Affected:** aegis-knowledge-graph
**Source confirmed:** yes (graph.rs shows multiple methods)

`KnowledgeGraph` acquires the read lock on every method call:
```rust
pub fn get_node(&self, id: u64) -> Result<Option<NodeData>, GraphError> {
    let inner = self.inner.read();
    Ok(inner.node_store.get(id).cloned())
}
```

When pipeline phases need to read multiple nodes (e.g., building hypothesis context reads all Dependency nodes, then all Endpoint nodes), this acquires and releases the lock multiple times. For each phase, this could be replaced with a single lock acquisition via a batch query method.

**Recommendation:** Add batch query methods to `GraphStore`:
```rust
fn nodes_by_types(&self, types: &[NodeType]) -> Result<HashMap<NodeType, Vec<NodeData>>, GraphError>;
fn all_findings_with_nodes(&self) -> Result<Vec<(FindingData, Vec<NodeData>)>, GraphError>;
```

---

### PERF-006: Large Struct Clones in Pipeline Hot Paths
**Severity:** low
**Effort:** small
**Affected:** aegis-orchestrator
**Source confirmed:** yes (pipeline.rs:1258 clones llm_payloads Vec)

`ctx.llm_payloads.clone()` at `pipeline.rs:1258` clones the entire Vec of LLM-generated payload strings on each iteration (to detect zero-finding iterations). Also, `progress.completed_phases.clone()` at line 771 clones a `Vec<String>` that grows over time.

**Recommendation:**
- For `llm_payloads`: use `std::mem::take(&mut ctx.llm_payloads)` if the Vec is consumed anyway in the next fuzz iteration, avoiding the clone
- For `completed_phases`: consider using a `HashSet<String>` (faster lookup) if the phases list grows large

**Code location:** `crates/orchestrator/src/pipeline.rs:1258, 771`

---

### PERF-007: SQLite Without WAL Mode for Scan History DB
**Severity:** low
**Effort:** small
**Affected:** aegis-orchestrator (scan_history.rs)
**Source confirmed:** partial

The scan history SQLite database likely uses the default journal mode (DELETE). For workloads with frequent small writes (per-payload outcomes), WAL (Write-Ahead Logging) mode provides significantly better write performance and allows concurrent readers.

**Recommendation:** Enable WAL mode on database open:
```rust
conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
```

---

### PERF-008: tracing Structured Fields Not Always Used
**Severity:** low
**Effort:** small
**Affected:** multiple crates
**Source confirmed:** partial

`tracing` macros perform best when fields are key-value pairs (`tracing::info!(count = n, "message")`) rather than format strings (`tracing::info!("found {} endpoints", n)`). Format string arguments are evaluated even when the log level is disabled; structured fields are lazy.

**Recommendation:** Review all `tracing::info!`, `tracing::debug!`, `tracing::warn!` calls and convert format-string arguments to structured fields where the key name adds clarity. Example:
```rust
// Before:
tracing::info!("discovered {} endpoints from OpenAPI spec", endpoints.len());
// After:
tracing::info!(endpoint_count = endpoints.len(), url = %url, "discovered endpoints from OpenAPI spec");
```
