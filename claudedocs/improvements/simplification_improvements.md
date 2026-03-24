# Simplification Improvements

Generated: 2026-02-23 | Source depth: 2 (source-confirmed for high/critical)

---

### SIMP-001: Three Unintegrated Feature Modules Are API Surface Without Functionality
**Severity:** high
**Effort:** medium
**Affected:** aegis-orchestrator
**Source confirmed:** yes (grep confirms no production call sites for IdorAnalyzer, AdaptiveScanStrategy, run_coordinator)

`IdorAnalyzer` (351 lines + test file), `AdaptiveScanStrategy` (190 lines), and distributed scanning (`distributed.rs` 323 lines + `distributed_transport.rs` 495 lines) are publicly exported from `aegis-orchestrator` but not called from the scan pipeline. They are:
- Not invoked in `run_scan()`
- Not triggered by any CLI flag at runtime
- Tests exist but integration tests for the combined pipeline don't cover them

This creates a misleading public API where users (or developers) might assume `--distributed` does something.

**Recommendation:**
- For `IdorAnalyzer` and `AdaptiveScanStrategy`: wire them into the pipeline at the next opportunity, or hide with `#[doc(hidden)]` and a doc comment "Not yet integrated into scan pipeline"
- For distributed scanning: either wire the `--distributed` flag into `run_scan()` to call `run_coordinator()` / `run_worker()`, or explicitly document as "planned feature, not operational"

---

### SIMP-002: ProcessManager Infrastructure for Non-Existent Multi-Process Architecture
**Severity:** medium
**Effort:** small
**Affected:** aegis-supervisor
**Source confirmed:** yes (298 lines, no callers in production code)

`ProcessManager` manages lifecycle state of external processes (`NotStarted → Running → Stopped/Failed → Restarting`), provides restart backoff logic, and tracks PIDs. However, AEGIS is a single-process application — there are no external component processes to manage. The `CapabilityManager` in the same crate IS used; only `ProcessManager` appears unused.

**Recommendation:** Remove `ProcessManager` from `aegis-supervisor` (or move to a `#[doc(hidden)]` internal module) until a multi-process deployment model is actually implemented. The `ComponentId` enum and `ProcessState` machine are well-written but currently add maintenance surface without value.

---

### SIMP-003: pipeline_composer Topological Sort for Sequential Execution
**Severity:** medium
**Effort:** small
**Affected:** aegis-orchestrator
**Source confirmed:** yes (validate_pipeline called at runtime, but no parallel execution)

`PipelineDefinition::validate()` runs Kahn's topological sort algorithm to detect cycles and validate at least one Source/Sink exists. This is called at scan startup. But since execution is always sequential (phases run in a fixed order in `run_scan_phases()`), the topological sort adds complexity without enabling the parallelism it implies.

**Recommendation:** If parallel execution is not planned, replace the DAG with a simple `Vec<PhaseName>` and a validation function that just checks the list is non-empty. This removes ~250 lines of topological sort code. If parallel execution IS planned, document this clearly.

---

### SIMP-004: WORKSPACE_CRATE_COUNT = 11 Stale Constant
**Severity:** low
**Effort:** small
**Affected:** aegis-orchestrator
**Source confirmed:** yes (pipeline.rs:1705, actual count = 17)

One-line fix: update the constant from 11 to 17, or better, remove it and compute dynamically.

**Code location:** `crates/orchestrator/src/pipeline.rs:1705`

---

### SIMP-005: GraphQL Fallback Discovery Hardcoded Field Lists
**Severity:** low
**Effort:** small
**Affected:** aegis-enumeration
**Source confirmed:** partial (21 COMMON_QUERY_FIELDS, 13 COMMON_MUTATION_FIELDS documented in CLAUDE.md)

The GraphQL fallback discovery uses hardcoded lists of 21 query field names and 13 mutation field names for brute-force field discovery. These lists are compile-time constants but are application-specific data that should be data-driven.

**Recommendation:** Move these lists to a JSON or TOML data file loaded at startup, allowing users to provide custom field lists without recompiling. Alternatively, expose them as a configuration option.

**Code location:** `crates/enumeration/src/graphql_discovery.rs`

---

### SIMP-006: auth_session Module Could Be Merged into phase_fuzz
**Severity:** low
**Effort:** small
**Affected:** aegis-orchestrator
**Source confirmed:** yes (`phase_fuzz.rs:10` imports from `auth_session`)

`auth_session.rs` (226 lines) is used only by `phase_fuzz.rs`. It provides authenticated session management for the fuzz phase. As a standalone module with one consumer, it may be better inlined into `phase_fuzz.rs` or at least reduced in visibility (`mod auth_session` instead of `pub mod auth_session`).

**Recommendation:** Change `pub mod auth_session` to `mod auth_session` in `lib.rs` since it's only needed internally. This reduces the public API surface of the orchestrator crate.

---

### SIMP-007: 10 Persona IDs — Some May Be Untested/Unused
**Severity:** low
**Effort:** small
**Affected:** aegis-evasion-engine
**Source confirmed:** partial

`PersonaId` has 10 variants but the CLI `--persona` flag only resolves 5 (`chrome, firefox, safari, mobile, googlebot`). The other 5 (`EdgeDesktop, OperaDesktop, SafariMobile, CurlClient, PythonRequests`) can only be used programmatically.

**Recommendation:** Either expose all 10 via the CLI `--persona` flag or document which ones are CLI-accessible. Consider whether `CurlClient` and `PythonRequests` (which look like scanner-identifiable personas) should be used for legitimate security testing.

---

### SIMP-008: Re-exported Wildcard Exports in orchestrator/src/lib.rs Create Large Public Surface
**Severity:** low
**Effort:** medium
**Affected:** aegis-orchestrator
**Source confirmed:** yes (lib.rs has 30+ `pub use module::*`)

Every orchestrator module is wildcard re-exported (`pub use actor::*`, `pub use auth_session::*`, etc.). This creates a massive public API surface where every internal type is publicly accessible. For a binary crate, this is unusual — the types in orchestrator are implementation details of the `aegis` binary.

**Recommendation:** Since `aegis-orchestrator` is a library + binary crate (used in integration tests), audit which types actually need to be public. Move the binary-only implementation modules to `pub(crate)` visibility. Types needed for integration tests can be exposed via `#[cfg(test)]` or test-only feature flag.

---

### SIMP-009: BridgeRequest::Shutdown Variant Never Sent
**Severity:** low
**Effort:** small
**Affected:** aegis-orchestrator
**Source confirmed:** partial

`BridgeRequest::Shutdown` is defined in the IPC protocol but the `HypothesisBridge` Drop impl likely terminates via socket close/SIGKILL rather than sending an explicit Shutdown message. Verify whether the Shutdown message is actually sent or if it's dead protocol.

**Recommendation:** Either use the Shutdown message in the Drop impl (allowing the Python process to clean up gracefully before the 2-second grace period), or remove the variant from the protocol to reduce surface area.

---

### SIMP-010: Zero Doc Test Examples Across Entire Codebase
**Severity:** low
**Effort:** medium
**Affected:** all public crates
**Source confirmed:** yes (grep found 0 doc test examples)

There are zero `/// # Examples` sections with code blocks in the entire codebase. Doc tests serve as both documentation and lightweight integration tests for public APIs.

**Recommendation:** Add doc test examples for the most commonly used public APIs:
- `KnowledgeGraph::apply_operations()` — show adding a node and querying it
- `Confidence::new()` — show valid and invalid values
- `FuzzScheduler::enqueue()` / `dequeue()` — show basic usage
- `AuditLogWriter::create()` — show creating and appending
