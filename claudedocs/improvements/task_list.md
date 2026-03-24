# AEGIS Production Readiness — Full Task Hierarchy

Generated: 2026-02-23 | 83 improvements → ~120 actionable tasks across 5 phases
Source: All 8 improvement analysis files + agent findings

---

## Phase 1 — Safety & Correctness Fixes (Weeks 1-2)

*Goal: Eliminate correctness bugs and safety risks. No new features. Block nothing, unblock everything.*

---

### Epic 1.1: Fix Async Runtime Correctness
**Why:** Blocking `std::fs` on Tokio threads can starve async tasks. Zero `tokio::fs` usage across the entire codebase is a systemic issue confirmed by grep.

**1.1.1** Add tokio/fs feature to orchestrator Cargo.toml
  - Add `"fs"` to tokio features list
  - Verify `cargo build -p aegis-orchestrator` succeeds

**1.1.2** Replace blocking checkpoint I/O with async
  - `std::fs::write → tokio::fs::write().await` (`checkpoint.rs:56`)
  - `std::fs::rename → tokio::fs::rename().await` (`checkpoint.rs:57`)
  - `std::fs::remove_file → tokio::fs::remove_file().await` (`checkpoint.rs:58, 81`)
  - `std::fs::read_to_string → tokio::fs::read_to_string().await` (`checkpoint.rs:70`)
  - Acceptance: `grep -r "std::fs::" crates/orchestrator/src/checkpoint.rs` returns nothing

**1.1.3** Replace blocking SARIF/graph export write with async
  - `std::fs::write → tokio::fs::write().await` (`phase_report.rs:163, 417, 422`)
  - Acceptance: No blocking I/O in phase_report.rs

**1.1.4** Replace blocking telemetry write with async
  - `std::fs::write → tokio::fs::write().await` (`telemetry.rs:210`)

**1.1.5** Wrap HypothesisBridge socket I/O in spawn_blocking
  - Wrap `write_ipc_frame()` + `read_ipc_frame()` calls in `tokio::task::spawn_blocking()`
  - Acceptance: Hypothesis bridge does not block Tokio worker threads

---

### Epic 1.2: Fix Mutex Poisoning Risk
**Why:** `std::sync::Mutex` in interactive session can poison on any thread panic, causing all future lock calls to panic and crash the scan.

**1.2.1** Replace std::sync::Mutex with parking_lot::Mutex for interactive session
  - Change `use std::sync::{Arc, Mutex}` → `use parking_lot::Mutex; use std::sync::Arc` (`pipeline.rs:3`)
  - Remove all `.unwrap()` after `.lock()` calls (parking_lot never poisons): lines 177, 179, 231, 246, 312, 329, 336, 1248
  - Add `parking_lot` to orchestrator Cargo.toml if not already transitive
  - Acceptance: `cargo test --workspace` passes; interactive `--interactive` mode works

---

### Epic 1.3: Audit and Fix unwrap()/expect() Calls

**1.3.1** Fix update_db genuine panic risks
  - Replace `current_introduced.take().unwrap()` in `update_db.rs:297, 299` with `ok_or_else(|| UpdateDbError::MalformedOsvData(...))?`
  - Acceptance: Malformed OSV API response produces `UpdateDbError`, not panic

**1.3.2** Document invariant-based unwrap()s in graph traversal
  - Add `// INVARIANT: edge_store IDs come from validated graph; this cannot fail` before each `edge_store.get(edge_id).unwrap()` in `path_queries.rs` and `reachability.rs`
  - Add equivalent comments for other guaranteed-valid lookups
  - Acceptance: All non-test unwrap() calls are either converted to `?` or documented

**1.3.3** Add clippy lint for undocumented panics
  - Add `#![deny(clippy::unwrap_used)]` or configure `[workspace.lints.clippy]` to warn on unwrap
  - Add `#[allow(clippy::unwrap_used)]` with reason comment on documented invariant unwraps
  - Acceptance: `cargo clippy --workspace` surface all new undocumented panics

---

### Epic 1.4: Target Validation Security Audit

**1.4.1** Verify and test obfuscation bypass coverage
  - Read `crates/protocol/src/target_validation.rs` fully
  - Add/verify tests for: `0x7f000001`, `0177.0.0.1`, `127.1`, `[::ffff:127.0.0.1]`
  - Add test: each bypass pattern is rejected when `--i-am-authorized` not set
  - Add test: each is allowed when `scope_attestation` matches target

**1.4.2** Add scope attestation edge case tests
  - Test: expired attestation is rejected with clear error message
  - Test: attestation for wrong target is rejected
  - Test: tampered attestation signature fails verification

---

### Epic 1.5: Resource Safety

**1.5.1** Add socket file cleanup on abnormal exit
  - Register `std::panic::set_hook` or `scopeguard::defer!` to remove socket file
  - Alternative: add `cleanup_stale_sockets()` at scan startup that deletes `/tmp/aegis-hypothesis-*.sock` files older than 1 hour
  - Acceptance: No stale socket files after `kill -9` of scan process

**1.5.2** Add HMAC key zeroization
  - Add `zeroize` feature to `ed25519-dalek` in workspace Cargo.toml
  - Use `zeroize::Zeroizing<[u8; 32]>` for HMAC key in `pipeline.rs:1838`
  - Verify key is not accessible after `AuditLogWriter` is created
  - Acceptance: HMAC key bytes cleared from stack after writer construction

---

## Phase 2 — Type Safety & API Quality (Weeks 3-4)

*Goal: Make invariants compiler-enforced, not runtime-validated. Reduce surprise.*

---

### Epic 2.1: Fix GraphOperation Type Safety

**2.1.1** Change AddFinding::confidence from f64 to Confidence
  - Change field type in `protocol/src/operation.rs:22`
  - Update `phase_fuzz.rs:442`: pass `.composite` not `.composite.value()`
  - Update `phase_recon.rs`, `phase_analyze.rs` construction sites
  - Update `operation_log.rs:224, 385` handlers
  - Simplify or remove confidence bounds check in `validate_batch()` (now redundant)
  - Update all tests that construct `AddFinding`
  - Acceptance: `confidence: f64` removed from `AddFinding`; all tests pass

**2.1.2** Add Confidence arithmetic methods
  - Add `fn clamp_scale(&self, factor: f64) -> Confidence`
  - Add `fn clamp_add(&self, delta: f64) -> Confidence`
  - Add `fn min(self, other: Confidence) -> Confidence`
  - Add `fn max(self, other: Confidence) -> Confidence`
  - Acceptance: No `.value()` followed by arithmetic in production code

---

### Epic 2.2: Fix StealthLevel Type Safety

**2.2.1** Make StealthLevel a clap ValueEnum
  - Add `#[derive(clap::ValueEnum)]` to `StealthLevel`
  - Change `StealthOptions::stealth_level` from `String` to `StealthLevel`
  - Remove `parse_stealth_level()` function
  - Update call sites
  - Acceptance: `aegis --stealth-level=invalid` fails at arg parse, not pipeline start

**2.2.2** Add TryFrom<&str> for remaining CLI string types
  - Implement `TryFrom<&str>` for `PersonaId`
  - Implement `TryFrom<&str>` for `ReportFormat`
  - Remove or delegate standalone `resolve_*()` functions
  - Acceptance: Standard `TryFrom` pattern works for all CLI string parsing

---

### Epic 2.3: Remove Type Aliases That Confuse

**2.3.1** Remove ScanContextJson alias
  - Replace all `ScanContextJson` with `ScanContextIpc` in `hypothesis_bridge.rs` and callers
  - Remove the alias declaration
  - Acceptance: `ScanContextJson` not found in codebase

---

### Epic 2.4: Adopt thiserror Across All Error Types

**2.4.1** Convert GraphError to thiserror (model for others)
  - Add `#[derive(thiserror::Error)]` to `GraphError`
  - Replace manual Display impl with `#[error("...")]`
  - Add `#[from]` for `ValidationError`, `OperationLogError`
  - Remove manual `From` impls
  - Acceptance: GraphError compiles with thiserror; zero manual Display

**2.4.2** Convert PhaseError to thiserror
  - Same treatment for `PhaseError` and `CheckpointError`

**2.4.3** Convert all remaining error types
  - `LogWriterError` (audit-log)
  - `ConfigError` (orchestrator)
  - `TransportError` (evasion-engine)
  - `CapabilityError` (supervisor)
  - `VulnDatabaseError` (passive-recon)
  - `CrawlError` (crawler)
  - `HypothesisBridgeError` (orchestrator)
  - Acceptance: Zero manual `Display` impls for error types; all use thiserror

---

### Epic 2.5: Name Magic Constants

**2.5.1** Name EvidenceLevel confidence constants
  - Add `const STATISTICAL_CONFIDENCE: f64 = 0.4` with doc comment in `finding.rs`
  - Add `CONTROLLED_CONFIDENCE`, `CONFIRMED_CONFIDENCE`, `CHAINED_CONFIDENCE`
  - Update `Confidence::from_evidence()` to use constants
  - Acceptance: No bare float literals in `from_evidence()`

**2.5.2** Name magic numbers across codebase
  - `MAX_BATCH_SIZE = 64` in `request_patterns.rs`
  - Retry counts in `update_db.rs` (2s/4s/8s backoff)
  - Bot detection scoring weights (0.4, 0.6)
  - Any other unnamed numeric constants in production code

---

### Epic 2.6: Add #[must_use] to Builder Methods

**2.6.1** Protocol crate builders
  - `FindingData::with_stable_id()`, `with_evidence_level()`, `with_certificate()`, `with_confidence()`, `with_finding_confidence()`, `with_linked_nodes()`
  - `NodeData::with_property()`

**2.6.2** Fuzzing/evasion builders
  - `EvasionTransportBuilder::with_*()` methods
  - `DefenseProfile::with_*()` methods
  - `StealthConfig::with_*()` methods
  - Acceptance: All `with_*` builder methods have `#[must_use = "builder methods return modified value"]`

---

### Epic 2.7: Configure Workspace Lints

**2.7.1** Add [workspace.lints.clippy] to Cargo.toml
  - Add clippy pedantic warns: `must_use_candidate`, `missing_errors_doc`, `missing_panics_doc`
  - Add `#![allow(clippy::module_name_repetitions)]` in crates where it's acceptable
  - Fix or allow all lint warnings produced
  - Acceptance: `cargo clippy --workspace -- -D warnings` passes with new lint config

---

## Phase 3 — Feature Completion (Weeks 5-7)

*Goal: Wire the implemented-but-not-integrated features. No new capabilities — just making what's built actually work.*

---

### Epic 3.1: Wire Crawler into Scan Pipeline

**3.1.1** Design crawler-pipeline integration
  - Document which `ScanConfig` fields map to `CrawlConfig`
  - Decide fallback behavior: `--skip-crawl` flag, `browser` feature absent
  - Write integration test spec

**3.1.2** Implement CrawlerConfig from ScanConfig
  - Map `config.target` → `CrawlConfig::seed_url`
  - Map `config.pipeline.skip_crawl` → skip flag
  - Implement `crawler_config_from_scan_config()`

**3.1.3** Wire run_crawl_phase to actual Crawler
  - Replace `CrawlResult::default()` in `pipeline.rs:1533` with `Crawler::new(config)?.crawl(&mut fetcher).await?`
  - Gate `BrowserFetcher` on `browser` feature flag; fall back to HTTP-only otherwise
  - Map `CrawlError` → `PipelineError::Crawl(PhaseError::...)`

**3.1.4** Process crawl results into graph operations
  - Convert `DiscoveredEndpoint` → `GraphOperation::AddNode(NodeType::Endpoint, ...)`
  - Deduplicate against existing graph endpoints
  - Set correct sequence numbers

**3.1.5** Add Docker Tier 2 crawl integration test
  - Test: scan Express app with crawler, JS-dynamic endpoints discovered
  - Test: `--skip-crawl` skips phase without error
  - Test: crawl error doesn't crash scan

---

### Epic 3.2: Wire IdorAnalyzer into Analyze Phase

**3.2.1** Audit IdorAnalyzer API
  - Read `idor_analyzer.rs` in full
  - Determine inputs (graph? HTTP transport?) and output format

**3.2.2** Integrate IdorAnalyzer into phase_analyze.rs
  - Call `IdorAnalyzer::analyze()` in `run_analyze()`
  - Convert results to `OperationLogEntry` with `GraphOperation::AddFinding`
  - Add `--skip-idor` flag to `PipelineOptions`
  - Add to phase timing metrics

**3.2.3** Add IDOR test fixtures
  - Docker Express test: `/api/users/{id}` generates IDOR finding
  - Verify finding appears in SARIF output

---

### Epic 3.3: Fix compliance_mapper Exhaustiveness

**3.3.1** Convert compliance_mapper to enum variant matching
  - Change `fn map_to_owasp(class: &str) -> ...` → `fn map_to_owasp(class: VulnerabilityClass) -> ...`
  - Write exhaustive `match class { VulnerabilityClass::SqlInjection => ..., ... }`
  - Fill any missing mappings for new variants

**3.3.2** Propagate enum type through class_mapper
  - Similarly update `class_mapper.rs`
  - Both mappers now exhaustive at compile time

**3.3.3** Add exhaustiveness test
  - Add test iterating all `VulnerabilityClass` variants
  - Verify each has non-empty OWASP + CWE mapping
  - Acceptance: Adding a new variant causes compile error until mapping added

---

### Epic 3.4: Wire or Remove Distributed Scanning (Decision Required)

**3.4.1** Evaluate distributed scanning completeness
  - Read `distributed.rs` and `distributed_transport.rs` in full
  - List what's implemented vs what's missing
  - Decision point: GO (wire it) or NO-GO (remove it)

**3.4.2A** [If GO] Wire distributed mode into run_scan()
  - Check `is_coordinator_mode()` / `is_worker_mode()` in run_scan
  - Route to coordinator or worker path
  - Add Docker Tier 2 test: 1 coordinator + 1 worker
  - Add documentation

**3.4.2B** [If NO-GO] Remove distributed scanning
  - Delete `distributed.rs`, `distributed_transport.rs` and their test files
  - Remove `--distributed`, `--coordinator-addr`, `--workers`, `--worker-connect`, `--worker-id` flags
  - Update CLAUDE.md and documentation

---

### Epic 3.5: Resolve ScanActor vs Direct Phase Calls Inconsistency

**3.5.1** Audit actor.rs vs pipeline.rs inconsistency
  - Verify actors in `actor.rs` duplicate or call phase functions
  - Determine if actors are tested independently from pipeline

**3.5.2** Choose canonical dispatch approach
  - Option A: Use actor dispatch in `run_scan_phases()` via `Vec<Box<dyn ScanActor>>`
  - Option B: Remove `actor.rs` entirely — keep direct function calls
  - Document decision in CLAUDE.md

**3.5.3** Implement chosen approach
  - If A: build actor Vec from DAG; dispatch via `actor.process(ctx, events)`
  - If B: delete `actor.rs` and remove from `lib.rs`
  - Acceptance: One consistent phase dispatch pattern

---

### Epic 3.6: Wire AdaptiveScanStrategy

**3.6.1** Review scan_strategy.rs
  - Read in full; understand `StrategyDecision` variants and inputs

**3.6.2** Integrate into scan pipeline
  - Create strategy from `ScanHistoryDb` at scan start
  - Apply `StrategyDecision` to adjust payload selection / phase ordering
  - Document strategy algorithm

---

## Phase 4 — Testing & Observability (Weeks 8-10)

*Goal: Build comprehensive test coverage and structured observability.*

---

### Epic 4.1: Add Doc Tests to Public APIs

**4.1.1** aegis-protocol doc tests
  - `Confidence::new()` — valid and invalid values
  - `Confidence::from_evidence()` — all 4 EvidenceLevel variants
  - `FindingData::new()` + builder chain
  - `is_valid_edge()` — valid and invalid triples
  - `NodeData::new().with_property()`

**4.1.2** aegis-knowledge-graph doc tests
  - `KnowledgeGraph::apply_operations()` — AddNode + AddEdge example
  - `KnowledgeGraph::all_findings()` — after adding a finding

**4.1.3** aegis-fuzzing doc tests
  - `FuzzScheduler::enqueue()` / `dequeue()` — basic usage
  - `StealthConfig::paranoid()` — preset builder

**4.1.4** aegis-audit-log doc tests
  - `AuditLogWriter::create()` — create and append example

---

### Epic 4.2: Add Missing Unit Tests

**4.2.1** Convergence detection edge cases
  - Counter resets when analyze finds something even if fuzz finds nothing
  - `convergence_threshold=1` stops after first zero-finding iteration
  - Counter restored correctly from checkpoint on resume
  - fuzz=0 + analyze>0 does NOT increment counter

**4.2.2** Audit log tamper detection
  - Detect modified payload (flip a byte)
  - Detect deleted entry (sequence gap)
  - Detect HMAC failure (wrong key)
  - Clean log verification succeeds

**4.2.3** Risk scorer defense constants
  - Severity 8.0 + WAF → score ≈ 4.8 (40% reduction)
  - Severity 8.0 + rate-limit → score ≈ 6.4 (20% reduction)
  - Severity 8.0 + auth → score ≈ 5.6 (30% reduction)
  - Combined defenses compound correctly
  - Fully defended endpoint has floor > 0

**4.2.4** Target validation bypass patterns
  - `0x7f000001` rejected
  - `0177.0.0.1` rejected
  - `127.1` rejected
  - `[::ffff:127.0.0.1]` rejected

**4.2.5** HypothesisBridge mock server tests
  - Create `MockBridgeServer` in test-support (listens on socket, returns canned responses)
  - Test: `generate_hypotheses()` returns correct response from mock
  - Test: frame > 64 MiB returns error, not panic
  - Test: socket file deleted on `HypothesisBridge` drop

**4.2.6** Checkpoint resume unit tests
  - Completed phases are skipped
  - Not-completed phases are executed
  - Checkpoint deleted on successful completion
  - Convergence counter restored from checkpoint

**4.2.7** VulnerabilityClass exhaustiveness tests
  - All 34 variants have CWE mapping (after Epic 3.3)
  - All 34 variants have OWASP mapping
  - All 34 variants have ATT&CK mapping (if applicable)

---

### Epic 4.3: Add Property-Based Tests

**4.3.1** GraphOperation validation with proptest
  - Expand proptest coverage to all 28 valid edge triples
  - Property: random valid triple → `is_valid_edge()` returns true
  - Property: random invalid triple → returns false
  - Property: confidence in [0.0, 1.0] → `Confidence::new()` returns Ok

**4.3.2** CBOR certificate round-trip tests
  - All 6 CertificateType variants serialize → deserialize → equals original
  - Property: any valid certificate survives round-trip

---

### Epic 4.4: Add Performance Benchmarks

**4.4.1** Knowledge graph benchmarks
  - `bench_apply_operations_small`: 10 ops
  - `bench_apply_operations_medium`: 1,000 ops
  - `bench_apply_operations_large`: 10,000 ops
  - `bench_all_findings`: 1,000 findings
  - `bench_nodes_by_type`: 10,000 nodes

**4.4.2** Fuzzing scheduler benchmarks
  - `bench_enqueue_dequeue`: 1,000 targets
  - `bench_deduplication`: 1,000 targets with 50% duplicates

**4.4.3** Endpoint similarity benchmarks
  - 10, 100, 500 endpoint similarity matrices

---

### Epic 4.5: Docker Tier 2 Test Expansion

**4.5.1** Add remaining vulnerability class coverage
  - Add NoSQL injection endpoint to Express or new fixture
  - Add CORS misconfiguration endpoint
  - Add prototype pollution endpoint
  - Add mass assignment endpoint
  - Update `ground-truth.json` for each
  - Add Docker test for each new vulnerability

**4.5.2** Add crawler Docker integration test (depends on Epic 3.1)
  - JS-dynamic endpoints discovered via browser crawl

**4.5.3** Add IDOR Docker test (depends on Epic 3.2)
  - Express app `/api/users/{id}` → IDOR finding in output

---

### Epic 4.6: Structured Observability

**4.6.1** Convert format strings to structured tracing fields
  - Audit `pipeline.rs` and all phase files for `tracing::info!("found {} x", n)` patterns
  - Convert to `tracing::info!(count = n, "found x")`
  - Apply to all warn/error/debug calls

**4.6.2** Add phase timing tracing spans
  - Wrap each phase in `let _span = tracing::span!(Level::INFO, "phase.recon").entered()`
  - Repeat for crawl, fingerprint, fuzz, analyze, dom_verify, report
  - Enables distributed tracing tooling

---

## Phase 5 — Architecture & Performance (Weeks 11+)

*Goal: Structural improvements for long-term maintainability and scalability.*

---

### Epic 5.1: Performance Quick Wins (Start Early)

**5.1.1** Fix FuzzScheduler deduplication string clones
  - Use references for key check before cloning: `(&endpoint, &parameter, vuln_class)`
  - Only clone if insertion succeeds
  - Code: `crates/fuzzing/src/scheduler.rs:78-92`

**5.1.2** Enable SQLite WAL mode
  - Add `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;` to vuln.db and scan_history.db open
  - Reduces write latency and enables concurrent readers

**5.1.3** Batch scan history queries
  - Load all class confirmation rates in one SQL query at scan start
  - Cache in HashMap<String, f64> for O(1) per-class lookup
  - Batch writes at scan end

---

### Epic 5.2: Orchestrator God Crate Decomposition

**5.2.1** Define new crate boundaries
  - Document proposed split: `aegis-scan-core`, `aegis-llm-bridge`, thin `aegis-orchestrator` (CLI only)
  - Write ADR (Architecture Decision Record)

**5.2.2** Extract aegis-llm-bridge crate
  - Create `crates/llm-bridge/`
  - Move `hypothesis_bridge.rs` + IPC types
  - Update `aegis-protocol` re-exports if needed
  - Update `aegis-orchestrator` Cargo.toml

**5.2.3** Extract aegis-scan-core crate
  - Move `ScanContext`, `PhaseResult`, `ScanSummary`, `PipelineError`
  - Move all `phase_*.rs` modules
  - Move checkpoint, convergence, interactive, pipeline_composer
  - Keep CLI argument parsing in `aegis-orchestrator`
  - Acceptance: `aegis-orchestrator` contains only main.rs and CLI types

---

### Epic 5.3: Replace NodeData Property Bag

**5.3.1** Design typed NodeProperties enum
  - Define variants per NodeType: `Endpoint { path, method }`, `Dependency { name, version, ecosystem }`, `Defense { has_waf, ... }`, etc.
  - Design backwards-compatible JSON persistence (migration for existing graph DBs)

**5.3.2** Implement NodeProperties in protocol
  - Replace `HashMap<String, String>` with `NodeProperties` enum
  - Update `NodeData::with_property()` to typed setters

**5.3.3** Update all construction sites
  - Update all `GraphOperation::AddNode { properties: vec![...] }` calls
  - Update graph persistence serialization

**5.3.4** Update all read sites
  - Replace `n.properties.get("path")` with `n.properties.endpoint_path()`
  - Acceptance: No more string key lookups for node properties

---

### Epic 5.4: Dependency Cleanup

**5.4.1** Restrict tokio features
  - Replace `features = ["full"]` with `["rt-multi-thread", "macros", "time", "sync", "fs"]`
  - Verify in all crates that use tokio

**5.4.2** Make chromiumoxide optional in crawler
  - Move `chromiumoxide` + `futures` to optional dependencies
  - Add `[features] browser = ["chromiumoxide", "futures"]`
  - Verify build without browser: `cargo build -p aegis-crawler`
  - Estimated compile time savings: significant

**5.4.3** Add cargo-deny for license/security policy
  - Add `deny.toml` to workspace root
  - Configure license allowlist (MIT, Apache-2.0, BSD-3-Clause, ISC)
  - Configure advisory check
  - Add `cargo deny check` to CI

---

### Epic 5.5: Parallelism Improvements

**5.5.1** Recon + Crawl concurrent execution (once crawler is wired)
  - After Epic 3.1, use `tokio::join!(run_recon_phase(), run_crawl_phase())` in pipeline
  - Both are Source phases with no data dependency between them

**5.5.2** Discovery HTTP request batching
  - Use `futures::stream::FuturesUnordered` for concurrent path probing
  - Implement adaptive concurrency (detect rate limiting, back off)
  - Benchmark vs current approach

---

### Epic 5.6: Function Length Refactoring

**5.6.1** Break up run_scan_phases() (200+ lines → <40 lines)
  - Extract initialization into `initialize_scan(ctx) -> Result<...>`
  - Extract phase sequencing into smaller helpers
  - Acceptance: No function in orchestrator exceeds 40 lines

**5.6.2** Break up run_fingerprint_phase() and other long phase functions
  - Similar treatment for any phase function > 40 lines

---

## Appendix: Cleanup Items (Do When Touching Nearby Code)

| ID | Task | Location | Time |
|----|------|----------|------|
| C-01 | Fix `WORKSPACE_CRATE_COUNT = 11` → 17 | `pipeline.rs:1705` | 5 min |
| C-02 | Move GraphQL field lists to data file | `graphql_discovery.rs` | 30 min |
| C-03 | Document `#[serde(alias = "Counterfactual")]` with migration note | `finding.rs:151` | 5 min |
| C-04 | Verify or remove `BridgeRequest::Shutdown` variant | `hypothesis_ipc.rs` | 15 min |
| C-05 | Change `auth_session` to `pub(crate)` | `lib.rs` | 5 min |
| C-06 | Add `Display` impl to `PersonaId` | `persona.rs` | 30 min |
| C-07 | Add `Display` impl to `MutationOrigin` | `mutator.rs` | 30 min |
| C-08 | Add `Display` impl to `AnomalyType` | `oracle.rs` | 30 min |
| C-09 | Add `#[non_exhaustive]` to `VulnerabilityClass` | `finding.rs` | 5 min |
| C-10 | Name `DEFAULT_CONCURRENCY=20` constant in brute_forcer | `brute_forcer.rs` | 5 min |

---

## Phase Summary

| Phase | Goal | Weeks | Epic Count | Sub-task Count |
|-------|------|-------|-----------|----------------|
| 1 | Safety & Correctness | 1-2 | 5 epics | ~22 tasks |
| 2 | Type Safety & API Quality | 3-4 | 7 epics | ~30 tasks |
| 3 | Feature Completion | 5-7 | 6 epics | ~28 tasks |
| 4 | Testing & Observability | 8-10 | 6 epics | ~35 tasks |
| 5 | Architecture & Performance | 11+ | 6 epics | ~25 tasks |
| Cleanup | When-you're-there | — | — | 10 items |

**Total: ~150 addressable work items**

---

## Task Dependency Graph

```
Phase 1 must be done before everything else.

Epic 1.1 (async I/O) ─────────────────────────────► Epic 5.5 (parallelism)
Epic 1.2 (parking_lot) ───────────────────────────► All phases (safety first)
Epic 2.1 (Confidence type) ───────────────────────► Epic 3.2 (IDOR uses AddFinding)
Epic 2.4 (thiserror) ─────────────────────────────► All phases (concurrent)
Epic 3.1 (wire crawler) ──────────────────────────► Epic 4.5 (crawler Docker tests)
                                                    ► Epic 5.5 (recon+crawl parallel)
Epic 3.3 (compliance enum) ───────────────────────► Epic 4.2.7 (exhaustiveness tests)
Epic 3.4 (distributed decision) ─────────────────► Epic 5.2 (orchestrator split)
Epic 3.5 (actor decision) ────────────────────────► Epic 5.2 (orchestrator split)
Epic 5.2 (orchestrator split) ────────────────────► Epic 5.3 (NodeData, needs stable API)
```
