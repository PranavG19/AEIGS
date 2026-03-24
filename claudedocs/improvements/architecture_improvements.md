# Architecture Improvements

Generated: 2026-02-23 | Source depth: 2 (source-confirmed for high/critical)

---

### ARCH-001: Orchestrator is a God Crate
**Severity:** high
**Effort:** large
**Affected:** aegis-orchestrator
**Source confirmed:** yes (lib.rs shows 30+ public modules)

The `aegis-orchestrator` crate has 30+ modules including pipeline phases, authentication, distributed coordination, telemetry, benchmarks, calibration, interactive mode, checkpointing, convergence, endpoint similarity, IDOR analysis, scan strategy, and more. This violates the single-responsibility principle and creates a crate that is extremely difficult to test in isolation.

**Recommendation:** Extract cohesive sub-systems into separate crates:
- `aegis-pipeline-core` — ScanContext, PhaseResult, PipelineError, checkpoint
- `aegis-llm-bridge` — HypothesisBridge and IPC types
- `aegis-reporting-pipeline` — SARIF generation (currently split between orchestrator and reporting)
At minimum, separate internal (`pub(crate)`) modules from the public API surface.

**Code location:** `crates/orchestrator/src/lib.rs:1-60`

---

### ARCH-002: Three Major Features Implemented but Not Wired
**Severity:** high
**Effort:** medium
**Affected:** aegis-orchestrator
**Source confirmed:** yes (grep confirmed no calls from pipeline.rs)

Three substantial feature modules (1,585 lines) are implemented with tests but not called from `run_scan()` or `main()`:
- `IdorAnalyzer` (`idor_analyzer.rs`, 351 lines) — IDOR heuristic detection
- `AdaptiveScanStrategy` (`scan_strategy.rs`, 190 lines) — adaptive scan behavior
- Distributed scanning (`distributed.rs` 323 lines + `distributed_transport.rs` 495 lines) — coordinator/worker mode

The `--distributed` and `--worker-connect` CLI flags exist in `ScanConfig` but are never checked in `run_scan()`.

**Recommendation:** Either wire these features into the scan pipeline (with appropriate CLI flags) or document them clearly as "not yet integrated" with `#[doc(hidden)]` until they are. The distributed modules especially represent significant dead API surface.

**Code location:** `crates/orchestrator/src/pipeline.rs` (no `is_coordinator_mode` / `is_worker_mode` checks)

---

### ARCH-003: ProcessManager Infrastructure for Non-Existent Multi-Process Architecture
**Severity:** medium
**Effort:** small
**Affected:** aegis-supervisor
**Source confirmed:** yes

`ProcessManager` (298 lines) provides lifecycle management (`mark_started`, `mark_stopped`, `mark_restarting`) and restart-backoff logic for external processes. However, AEGIS runs as a single process — there are no worker processes to manage. The supervisor crate's `ProcessManager` is not called from any production code path. The `CapabilityManager` in supervisor is used, but `ProcessManager` appears to be dead infrastructure.

**Recommendation:** Either remove `ProcessManager` or document it as infrastructure for a future multi-process deployment model (with a clear migration path). The `CapabilityManager` should be retained.

**Code location:** `crates/supervisor/src/process_manager.rs`

---

### ARCH-004: pipeline_composer DAG Validated but Not Used for Parallel Execution
**Severity:** medium
**Effort:** medium
**Affected:** aegis-orchestrator
**Source confirmed:** yes (`validate_pipeline()` called, but execution is sequential)

The `PipelineDefinition` correctly models the DAG (recon and crawl are independent Sources; fingerprint depends on both; fuzz follows fingerprint), and `validate_pipeline()` is called to verify the DAG has no cycles and has at least one Source/Sink. However, the actual execution is completely sequential — phases are called one after another regardless of the DAG topology. The DAG adds cycle detection and structure validation but provides no actual parallelism benefit.

**Recommendation:** Either implement parallel execution of independent DAG stages using `tokio::join!` (recon + crawl can run concurrently since crawl currently returns `CrawlResult::default()`), or simplify by replacing the DAG with a simple sequential list and removing the topological sorting code. The current approach adds complexity without delivering parallelism.

**Code location:** `crates/orchestrator/src/pipeline_composer.rs`, `crates/orchestrator/src/pipeline.rs:1504-1508`

---

### ARCH-005: CrawlResult::default() Stub in Production Pipeline
**Severity:** medium
**Effort:** large
**Affected:** aegis-orchestrator, aegis-crawler
**Source confirmed:** yes (`pipeline.rs:1533` uses `CrawlResult::default()`)

`run_crawl_phase()` always uses `CrawlResult::default()` — an empty result — instead of actually invoking the crawler. The `aegis-crawler` crate is a runtime dependency of orchestrator but never calls `Crawler::crawl()`. This means the entire browser crawling capability is silently disabled in every scan.

**Recommendation:** Wire the actual crawler: if `--skip-crawl` is not set and a target URL is available, instantiate a `Crawler` and call `crawler.crawl()`. Gate headless browser usage on the `browser` feature flag. Provide a fallback to `CrawlResult::default()` only when the feature is disabled or `--skip-crawl` is set.

**Code location:** `crates/orchestrator/src/pipeline.rs:1533`

---

### ARCH-006: aegis-proxy has No Consumers in Workspace
**Severity:** low
**Effort:** small
**Affected:** aegis-proxy
**Source confirmed:** yes (no crate depends on proxy in workspace)

`aegis-proxy` (recording proxy, repeater, 4-mode intruder) is a workspace member but is not a dependency of any other crate. It's a standalone tool. Its presence in the workspace adds build time without providing value to the main `aegis` binary.

**Recommendation:** Either integrate the proxy into the orchestrator as an optional scan mode (accessible via `aegis proxy listen --port 8080`), or move it to a separate workspace or binary crate. At minimum, document its standalone nature clearly and ensure it's excluded from the default build if not needed.

---

### ARCH-007: Dev-Only Crates (compliance, discovery, exploiter) Add Build Overhead
**Severity:** low
**Effort:** small
**Affected:** aegis-compliance, aegis-discovery, aegis-exploiter
**Source confirmed:** yes (dev-dependencies in orchestrator's Cargo.toml)

Three crates (compliance, discovery, exploiter) are dev-only dependencies. They compile with the test suite but not the production binary. However, they're still workspace members that `cargo build --workspace` compiles, adding ~3-5 seconds to full workspace builds.

**Recommendation:** Consider whether these should remain as workspace members or be separated into a `tools/` workspace. Alternatively, use `cargo build -p aegis-orchestrator` in CI to avoid compiling unused crates.

---

### ARCH-008: Feature Flag `browser` in crawler Not Declared in workspace Cargo.toml
**Severity:** low
**Effort:** small
**Affected:** aegis-crawler
**Source confirmed:** partial (lib.rs shows `#[cfg(feature = "browser")]` but workspace Cargo.toml has no feature flags)

The `aegis-crawler` crate uses `#[cfg(feature = "browser")]` to gate chromiumoxide-dependent modules, but the workspace `Cargo.toml` declares no feature flags. This means the `browser` feature can only be enabled at the crate level, not via workspace-level feature composition.

**Recommendation:** Document the `browser` feature flag explicitly. Add a note in the workspace `Cargo.toml` or in a top-level doc comment about enabling browser-based crawling. Consider adding a workspace-level `full` or `browser` feature that enables it for the orchestrator.

---

### ARCH-009: compliance_mapper Uses Display Strings for Pattern Matching
**Severity:** medium
**Effort:** small
**Affected:** aegis-compliance
**Source confirmed:** yes (inconsistencies.md documents this)

`compliance_mapper` matches on `VulnerabilityClass::Display` strings rather than enum variants. Adding a new `VulnerabilityClass` variant will produce no compile-time error — the compliance mapping will silently be missing for the new variant.

**Recommendation:** Change `compliance_mapper` to `match` directly on `VulnerabilityClass` enum variants. The compiler will then enforce exhaustiveness, making it impossible to add a new variant without updating the compliance mappings.

**Code location:** `crates/compliance/src/compliance_mapper.rs`

---

### ARCH-010: Single-Implementor Traits That Add Pure Indirection
**Severity:** low
**Effort:** medium
**Affected:** aegis-knowledge-graph, aegis-audit-log
**Source confirmed:** partial

`GraphStore` and `AuditWriter` each have one "real" implementation (`KnowledgeGraph` and `AuditLogWriter`) plus a no-op/test implementation. The traits are justified for testing (dependency injection) but the `GraphStore` trait's `save_to_file` default no-op is a code smell — callers cannot know if persistence actually happened.

**Recommendation:** This is acceptable for the stated purpose (test injection). No immediate change needed. However, consider adding a `fn is_persistent(&self) -> bool` to `GraphStore` to allow callers to know if `save_to_file` is a no-op, preventing silent data loss in production.

---

### ARCH-012: Reporting Crate Depends on Fuzzing — Cross-Layer Violation
**Severity:** medium
**Effort:** medium
**Affected:** aegis-reporting, aegis-fuzzing
**Source confirmed:** yes (reporting Cargo.toml depends on aegis-fuzzing)

`aegis-reporting` imports `DefenseProfile`, `WafFingerprint`, `RateLimitProfile`, `BotDetectionResult` from `aegis-fuzzing` for defense-aware risk scoring. This creates an unexpected cross-layer dependency: reporting (sink phase, Layer 2) depends on fuzzing (transform phase, Layer 2), when both should only depend on Layer 1 (knowledge-graph) and Layer 0 (protocol).

**Root cause:** Defense-fingerprinting types were merged into the fuzzing crate during refactoring, but reporting continued to depend on them.

**Recommendation:** Move `DefenseProfile`, `WafFingerprint`, `RateLimitProfile`, `BotDetectionResult` to `aegis-protocol` crate (Layer 0). This removes the reporting→fuzzing dependency. The fuzzing crate can re-export from protocol for backwards compatibility.

**Code location:** `crates/reporting/Cargo.toml` (depends on aegis-fuzzing), `crates/reporting/src/risk_scorer.rs`

---

### ARCH-011: WORKSPACE_CRATE_COUNT Constant is Stale
**Severity:** low
**Effort:** small
**Affected:** aegis-orchestrator
**Source confirmed:** yes (pipeline.rs:1705 = 11, actual = 17)

`const WORKSPACE_CRATE_COUNT: usize = 11` in `pipeline.rs:1705` is used in telemetry and is wrong (actual count: 17).

**Recommendation:** Either compute this dynamically from `cargo metadata` at build time via `build.rs`, or simply remove the constant and use a hardcoded 17 with a comment. Since this only affects telemetry, impact is low.

**Code location:** `crates/orchestrator/src/pipeline.rs:1705`
