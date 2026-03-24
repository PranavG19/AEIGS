# AEGIS Consolidated Documentation

<!-- metadata: full project overview, architecture, type system, interfaces, data models, workflows, crate summaries, dependencies, gaps -->

*Generated: 2026-02-23. Source of truth: `claudedocs/current_state/`. For detailed information, consult the individual files referenced in each section.*

---

## Table of Contents

| # | Section | Summary |
|---|---------|---------|
| 1 | [Project Overview](#1-project-overview) | 17 crates, 749 lines of tests, Python hypothesis engine |
| 2 | [Architecture](#2-architecture) | Pipeline-around-graph design, 5 key decisions, security model |
| 3 | [Type System](#3-type-system) | 34 VulnerabilityClass, 3 traits, newtypes, error hierarchy |
| 4 | [Interfaces and APIs](#4-interfaces-and-apis) | CLI (40+ flags), Unix socket IPC, storage schemas |
| 5 | [Data Models](#5-data-models) | Graph model, SARIF, CBOR, SQLite schemas |
| 6 | [Workflows and Control Flow](#6-workflows-and-control-flow) | 7-phase pipeline, convergence loop, checkpoint |
| 7 | [Per-Crate Summaries](#7-per-crate-summaries) | All 17 crates, 2-3 paragraphs each |
| 8 | [Dependencies](#8-dependencies) | All 40+ external dependencies by category |
| 9 | [Module Tree Summary](#9-module-tree-summary) | Top-level modules per crate |
| 10 | [Known Gaps](#10-known-gaps) | Areas for further investigation |

---

## 1. Project Overview

<!-- metadata: project metadata, crate listing, binary, Python component, test counts -->

**AEGIS — Adversarial Vulnerability Discovery Framework.** A security testing framework for web applications providing automated vulnerability discovery through passive recon, active enumeration, AI-driven fuzzing, attack chain synthesis, and compliance reporting. Designed for authorized pentesting of localhost targets.

**Scale:** 17 Rust crates, 149 modules, 750+ public items, 1 Python package. Single binary: `aegis`. Rust edition 2024, MIT license.

**Test coverage:** 4,073 Rust tests, 511 Python tests, 34 Docker Tier 2 integration tests (gated: `AEGIS_INTEGRATION_TESTS=1`).

### Crate Layers

```
Layer 3 — Integration:   aegis-orchestrator (binary: aegis)
Layer 2 — Capabilities:  passive-recon, enumeration, fuzzing, chain-synthesis,
                          reporting, evasion-engine, crawler, supervisor,
                          compliance*, discovery*, exploiter*, proxy, test-support†
Layer 1 — Storage:       knowledge-graph, audit-log
Layer 0 — Foundation:    protocol (no internal deps)
```
`*` dev-only in orchestrator  `†` test utilities only

**Detail:** `claudedocs/current_state/workspace_info.md`

---

## 2. Architecture

<!-- metadata: pipeline design, knowledge graph, design patterns, concurrency, security model, data flow -->

### Core Design: Knowledge Graph as Shared State

All pipeline phases communicate through a central in-memory knowledge graph. Each phase returns `Vec<OperationLogEntry>` and applies them via `graph.apply_operations()` — atomic, validated, all-or-nothing.

```
CLI → ScanConfig → run_scan()
  ↓
KnowledgeGraph (parking_lot RwLock<Inner{NodeStore, EdgeStore, FindingStore}>)
  ↑ all phases read/write via GraphStore trait
  ↓
recon → crawl → fingerprint → (fuzz → LLM → analyze)* → dom_verify → report
  ↓
SARIF report + CBOR audit log (SHA3-256 hash-chained)
```

### Five Core Architectural Decisions

| Decision | Rationale |
|---------|-----------|
| Knowledge graph as shared state | Clean phase boundaries; incremental scan resumption; cross-phase analysis |
| `GraphStore` trait + `AuditWriter` trait | Test injection of fakes without constructing full implementations |
| `aegis-protocol` as contract layer | Zero internal deps — all crates depend on it, preventing circular dependencies |
| Atomic validate-then-apply via `RwLockUpgradableReadGuard` | Eliminates TOCTOU gap; batch either fully applies or is entirely rejected |
| Localhost enforcement at 3 layers | Defense-in-depth: protocol crate + evasion-engine transport + fuzzing executor |

### Design Patterns

- **Builder** — `with_*` fluent methods on config structs (`NodeData`, `EvasionTransport`, `DefenseProfile`)
- **Repository** — `GraphStore` trait for graph access; `AuditWriter` for audit logging
- **Command** — `GraphOperation` enum; `OperationLogEntry` wraps with module/sequence/timestamp
- **Actor** — `ScanActor` trait: Source → Transform → Sink → Observer types
- **Facade** — `KnowledgeGraph` wraps `RwLock<Inner>`; callers never see raw locks
- **Event Sourcing** — operation log enables replay; `replay_from_entries()` reconstructs state
- **Strategy** — `ReportFormat`, `JitterDistribution`, `LlmBackend`, `HttpClientBackend` pluggable

### Concurrency Model

**Runtime:** Tokio multi-threaded (`#[tokio::main]`). The `run_scan()` function and phase loop are async. Evasion transport `send()` is async.

**Shared state:** `KnowledgeGraph` via `parking_lot::RwLock` — upgradable read for atomic validate-then-apply. `AuditWriter` is single-writer (`&mut self`). `Arc<Mutex<InteractiveSession>>` for interactive mode.

**OS threads:** Defense fingerprinting, OpenAPI/GraphQL discovery (blocking reqwest cannot run in tokio). Interactive stdin reader.

**Python IPC:** Unix domain socket at `/tmp/aegis-hypothesis-{pid}-{timestamp}.sock`, 4-byte LE u32 framing.

### Security Architecture

```
Layer 1: Target validation (localhost enforcement at 3 points)
Layer 2: Scope attestation (Ed25519-signed ScopeDocument)
Layer 3: Capability tokens (HMAC-SHA3-256, per-module least-privilege, subtle::ct_eq)
Layer 4: Audit logging (SHA3-256 hash chain + HMAC, mandatory by default)
Layer 5: Signed config (Ed25519 + SHA3-256 content hash)
```

**Detail:** `claudedocs/current_state/architecture.md`

---

## 3. Type System

<!-- metadata: VulnerabilityClass, NodeType, EdgeLabel, EvidenceLevel, traits, error types, newtypes -->

### Key Enums (all in `aegis-protocol`)

**`VulnerabilityClass`** (34 variants) — Core taxonomy. `Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display`. Adding a variant requires: `is_valid_edge()` whitelist, compliance crate exhaustive matches, LLM prompt, fixture tests.

**`NodeType`** (9 variants): `Endpoint, Function, DataStore, Role, Dependency, Config, User, Service, Defense`

**`EdgeLabel`** (8 variants): `Calls, Trusts, Authenticates, Reads, Writes, DependsOn, Exposes, ProtectedBy`

**`EvidenceLevel`** (4 variants): `Statistical(0.4) | Controlled(0.7) | Confirmed(0.9) | Chained(0.95)` — Note: `Controlled` has `#[serde(alias = "Counterfactual")]` for backwards compatibility.

**`AuditEventType`** (6 variants): `ScanStarted | ModuleStarted | FindingRecorded | ScanCompleted | KeyEvent | ConfigChange`

### Key Structs

**`FindingData`** — Core finding. `confidence: FindingConfidence` (NOT raw f64). Access score via `.confidence.composite.value()`. Custom `Deserialize` handles 3 legacy formats. Builder: `with_stable_id()`, `with_evidence_level()`, `with_certificate()`.

**`Confidence`** (newtype over f64) — Enforces [0.0, 1.0] and finiteness. `Confidence::new(v)` → `Result`. Default: 0.5. `Confidence::from_evidence(EvidenceLevel)` maps to scores.

**`FindingConfidence`** — Provenance-tracked: `prior × likelihood_ratio × methodology_reliability → composite`. `FindingConfidence::from_simple(confidence)` for legacy wrapping.

**`ScanContext`** — Pipeline carrier: `config: ScanConfig, graph: Box<dyn GraphStore>, defense_profile, capabilities, refuted, scope_attestation, auth_flow, llm_payloads`.

### Public Traits

**`GraphStore: Send + Sync`** — 9 methods. `apply_operations(&mut self, ...)`, `nodes_by_type`, `all_findings`, `save_to_file` (default: no-op). Implemented by `KnowledgeGraph`; test fakes inject lightweight stubs.

**`AuditWriter`** — `append_event_full(&mut self, event) → Result<AuditEntry, LogWriterError>` (required); `append_event` defaults to delegating. Implemented by `AuditLogWriter` (disk) and `NoOpAuditLogWriter` (discards). Pipeline holds `Box<dyn AuditWriter>`.

**`ScanActor`** — `name() → &str`, `process(&mut self, ctx, events) → Result<Vec<ScanEventEnvelope>, ActorError>`. Source actors ignore input; Transform consume and produce; Sink consume without output; Observer read without modifying state.

### Edge Validation

28 valid `(NodeType, EdgeLabel, NodeType)` triples in `EDGE_WHITELIST` (`protocol/src/edge.rs`). Validated on every `apply_operations()` call. Invalid edges cause batch rejection.

### Error Hierarchy

`PipelineError` → `PhaseError` → `GraphError` → `ValidationError` / `OperationLogError`

All implement `std::error::Error` with `source()` for chain traversal. No `anyhow`/`eyre` — typed enums only.

**Detail:** `claudedocs/current_state/type_system.md`

---

## 4. Interfaces and APIs

<!-- metadata: CLI, Unix socket IPC, Python-Rust bridge, storage schemas, security interfaces -->

### CLI — `aegis` binary

**Key common flags:**
```bash
aegis [--preset quick|thorough|paranoid|benchmark] --target <URL>
      [--output <PATH>] [--report-format developer|security|executive]
      [--source-dir <PATH>] [--verbose]
```

**ScanPreset:**
| Preset | Iterations | Convergence | Stealth | LLM |
|--------|-----------|-------------|---------|-----|
| `quick` | 1 | default | default | off |
| `thorough` | 3 | 2 | default | on |
| `paranoid` | 5 | 3 | paranoid | on |
| `benchmark` | 1 | default | default | on |

**Major option groups (all under `ScanConfig`):** `StealthOptions`, `PipelineOptions`, `LlmOptions`, `AuditOptions`, `ScopeOptions`, `AuthOptions`, `DistributedOptions`.

**Subcommands (manual dispatch before clap):**
- `aegis recon --source-dir <PATH>` — standalone dependency scan
- `aegis attest [args]` — Ed25519 scope attestation generation
- `aegis update-db --source-dir <PATH> --db-path <PATH>` — OSV vulnerability DB sync

### Python-Rust IPC

**Transport:** Unix domain socket at `/tmp/aegis-hypothesis-{pid}-{timestamp}.sock`
**Framing:** 4-byte little-endian u32 length prefix + JSON payload. Max frame: 64 MiB.
**Handshake:** 10s timeout. Request timeout: 120s.
**Cleanup:** Socket file deleted on `HypothesisBridge` drop (RAII). 2s grace → SIGKILL.

`BridgeRequest` variants (Rust → Python): `GenerateHypotheses | CompilePayloads | EvasionGenerate | Shutdown`
`BridgeResponse` variants (Python → Rust): `Ready | Hypotheses | CompiledPayloads | EvasionPayloads | Error`

Both use serde internally-tagged with `"type"` field. Pydantic models in `hypothesis-engine/src/hypothesis_engine/ipc_types.py` must stay in sync.

**Detail:** `claudedocs/current_state/interfaces.md`

---

## 5. Data Models

<!-- metadata: graph model, SARIF, audit log binary format, SQLite schemas, IPC types, certificates -->

### Knowledge Graph

Directed property graph: nodes (entities) + edges (28-triple semantic relationships) + findings (vulnerabilities).
- **NodeData:** `id: u64, node_type: NodeType, properties: HashMap<String, String>`
- **EdgeData:** `id, source_node_id, target_node_id, label: EdgeLabel, weight: f64, provenance_module, provenance_sequence`
- **FindingData:** see type_system.md; key: `severity: f64 [0..10], confidence: FindingConfidence`

**Graph persistence (`--graph-db`):** JSON bundle `{nodes, edges, findings, metadata}`. Operation log NOT persisted (starts fresh on load).

### Audit Log Binary Format

```
[seq: u64 LE][SHA3-256 hash: 32 bytes][payload_len: u32 LE][CBOR payload: N bytes][HMAC: 32 bytes]
```
Hash chain: `SHA3-256(prev_hash || payload)`. HMAC key stored separately (`aegis-audit.key`).

### Vulnerability Database SQLite (`~/.aegis/vuln.db`)

```sql
CREATE TABLE vulnerabilities (
    cve_id TEXT NOT NULL, package_name TEXT NOT NULL, ecosystem TEXT NOT NULL,
    vulnerable_version_start TEXT NOT NULL, vulnerable_version_end TEXT NOT NULL,
    severity REAL NOT NULL DEFAULT 0.0, description TEXT NOT NULL DEFAULT ''
);
-- "999999.0.0" in vulnerable_version_end = vulnerability still unfixed
```

### Scan History SQLite (`--history-db`)

```sql
CREATE TABLE scan_history (
    endpoint_pattern TEXT NOT NULL, vulnerability_class TEXT NOT NULL,
    payload TEXT NOT NULL, anomaly_score REAL NOT NULL,
    is_true_positive INTEGER NOT NULL, timestamp_unix_ms INTEGER NOT NULL,
    target_app_hash TEXT NOT NULL  -- prevents cross-app contamination
);
```

**Detail:** `claudedocs/current_state/data_models.md`

---

## 6. Workflows and Control Flow

<!-- metadata: startup sequence, scan phases, fuzz loop, convergence, checkpoint, LLM bridge, subcommands -->

### Startup (23-step sequence in `run_scan()`)

1. Validate stealth level + report format (fail-fast)
2. Load scope attestation (if `--scope-attestation`)
3. `validate_target_with_override()` — localhost check OR attestation OR `--i-am-authorized`
4. Load + verify signed config (if `--signed-config`)
5. Create `AuditLogWriter` (random 32-byte HMAC key, saved to sidecar `.key` file)
6. `load_or_create_graph()` — load from `--graph-db` or create fresh
7. Load checkpoint if `--resume`
8. `CapabilityManager::new()` + register 5 module permission policies
9. Load auth flow (if `--auth-flow`)
10. Spawn interactive stdin reader thread (if `--interactive`)
11. Build `ScanContext` → call `run_scan_phases()`

### Pipeline Phase Sequence

```
1. RECON      — lock file parsing, OSV vuln DB lookup → AddNode(Dependency) ops
2. CRAWL      — BFS/headless browser → AddNode(Endpoint) ops [CURRENTLY STUB]
3. FINGERPRINT — WAF/rate-limit/bot detection + OpenAPI/GraphQL/source endpoint discovery
4. FUZZ:N     — for N in 0..max_iterations:
     a. FuzzScheduler dequeues FuzzTargets (UCB1 BinaryHeap)
     b. Mutator generates TaggedPayload[] (5 origins + LLM payloads)
     c. EvasionTransport.send() → counterfactual oracle → anomalies → AddFinding ops
     d. HypothesisBridge: build_hypothesis_context() → Unix socket → Python LLM
        → hypotheses + payloads → ctx.llm_payloads for next iteration
5. ANALYZE:N  — AttackGraph construction, path analysis, mitigation ranking
     Convergence: if fuzz+analyze both zero N times → break loop
6. DOM_VERIFY — XSS verification via browser DOM execution (feature=browser)
7. REPORT     — risk scoring, SARIF generation, optional DOT/D3 graph export
```

### Checkpoint Resume

`ScanCheckpoint` saved after each phase. Stores `completed_phases: Vec<String>`, `current_iteration`, `total_operations`, `total_findings`, `consecutive_zero_findings`. Written atomically (`.tmp` → rename). Deleted on successful completion.

Resume: `--resume --graph-db <PATH>`. Loads checkpoint, skips already-completed phases. Without `--graph-db`, issues warning and proceeds as fresh scan.

**Detail:** `claudedocs/current_state/workflows.md`, `claudedocs/current_state/code_analysis/call_traces.md`

---

## 7. Per-Crate Summaries

<!-- metadata: all 17 crates, purpose, key types, usage context -->
*For full API details see `claudedocs/current_state/crate_docs/{crate-name}.md`*

### Foundation

**aegis-protocol** — Shared type contracts for all 17 crates. Zero internal dependencies (the DAG root). Defines: `VulnerabilityClass` (34 variants), `NodeType` (9), `EdgeLabel` (8), `EDGE_WHITELIST` (28 valid triples), `FindingData`/`FindingConfidence`/`Confidence`, `GraphOperation`, `OperationLogEntry`, `FuzzRequest`/`FuzzResponse`, `BridgeRequest`/`BridgeResponse` IPC, `ScanEvent`, `AuditEventType` (6 variants), scope attestation/signed config types. All changes here ripple across all 17 crates.

### Core Storage

**aegis-knowledge-graph** — Thread-safe property graph engine. `KnowledgeGraph` wraps `parking_lot::RwLock<Inner>`. Atomic validate-then-apply via `RwLockUpgradableReadGuard`. Enforces 28-triple edge whitelist, weight/severity/confidence bounds, no duplicate edges, sequence integrity. `GraphStore` trait enables test injection. Stores: `NodeStore`, `EdgeStore`, `FindingStore` (all arena-style Vec with HashMap indices). Algorithms: A* shortest path, BFS reachability, priority-bounded DFS (cap 100K), Brandes betweenness centrality, Tarjan cut vertices.

**aegis-audit-log** — SHA3-256 hash-chained, HMAC-signed append-only audit log. Binary wire format: 8+32+4+N+32 bytes per entry. `AuditWriter` trait: `AuditLogWriter` (persists to CBOR) vs `NoOpAuditLogWriter` (for `--no-audit`). Event sourcing: `replay_from_entries()`, `diff_snapshots()`, `compute_scan_timeline()`. Mandatory by default — scan fails if log cannot be created.

### Scanning Pipeline

**aegis-passive-recon** — Dependency lock file parsing (Cargo.lock, Gemfile.lock, package-lock.json, requirements.txt, go.sum). OSV vulnerability database lookup via SQLite. `FileClassification` with 9 variants and priority-ordered rules. 10 directories skipped during walk. `vuln_lookup()` third arg is `Option<&Path>` for DB path; `None` falls back to `~/.aegis/vuln.db`.

**aegis-enumeration** — Route discovery from 5 source code frameworks (Flask, Express, Spring, FastAPI, Rails), OpenAPI 3.x spec parsing (including body parameters), GraphQL introspection/fallback. `AuthorizationMatrix` anomaly detection: symmetric 200 = anomaly (correctly flagged). GraphQL fallback: 21 COMMON_QUERY_FIELDS, 13 COMMON_MUTATION_FIELDS. Multi-step auth flow engine with `{{variable}}` template rendering.

**aegis-fuzzing** — Priority scheduler (UCB1 BinaryHeap), payload mutation (5 `MutationOrigin` strategies), counterfactual anomaly oracle (paired control/treatment requests). Defense detection: WAF fingerprinting, rate-limit probing, bot detection (merged from defense-fingerprinting). Specialized testers for CORS, GraphQL, IDOR, mass assignment, race conditions, cloud misconfigs, subdomain takeover, security headers. UCB1 payload bandit for adaptive payload selection. `FuzzScheduler` clamps NaN/Inf priority to 0.0.

**aegis-evasion-engine** — Persona-based HTTP transport (10 `PersonaId` variants). `EvasionTransport` enforces localhost validation on every request. Header transforms, timing jitter (`JitterDistribution`: Uniform/Exponential/Normal), session rotation. TLS fingerprint abstraction: `TlsFingerprint` (6 variants), Chrome120 and Edge120 share identical JA3 hashes. Future: swap reqwest → rquest for JA3/JA4 control.

**aegis-chain-synthesis** — Attack graph construction (`petgraph DiGraph`) from knowledge graph findings. 4 `AttackNodeType` variants: EntryPoint, SecurityBoundary, Vulnerability, Asset. Algorithms: A* shortest path, priority-bounded DFS (MAX_TOTAL_PATHS=100K, lowest difficulty first), betweenness centrality, defense gap analysis. DOT and D3.js JSON export. `estimated_mitigation_impact()` is structural estimate — NOT causal claim. **Note:** `AttackGraph` type is self-contained but crate does have `aegis-protocol` and `aegis-knowledge-graph` as Cargo deps.

**aegis-reporting** — SARIF 2.1.0 generation with CWE + ATT&CK enrichment. Multi-factor risk scorer with defense adjustments: authentication -30%, rate-limiting -20%, WAF -40% (WAF-category-specific for Security format). `score_with_defense()` undo-then-reapply pattern. CBOR v2 evidence certificates (6 `CertificateType` variants). 3 `ReportFormat` variants: Developer (SARIF), Security (ATT&CK-enriched), Executive (summary JSON).

### Auxiliary Capabilities

**aegis-crawler** — BFS web crawler with `PageFetcher` trait. `browser` feature gate enables `BrowserFetcher` (chromiumoxide CDP) for JS-heavy SPAs. `DomVerifier`: injects `window.__aegis_*` markers for XSS verification. `CrawlResult::default()` returns empty — crawler not yet wired into main scan pipeline.

**aegis-supervisor** — Capability token management (HMAC-SHA3-256, `subtle::ct_eq` timing-safe validation, 1-hour TTL). `ProcessManager` is a **pure state machine** — it does NOT spawn subprocesses. 5 module permission policies: `PassiveRecon(ReadFilesystem+WriteGraph)`, `Enumeration(ReadGraph+WriteGraph+ExecuteRequests)`, `Fuzzing(ReadGraph+WriteGraph+ExecuteRequests)`, `ChainSynthesis(ReadGraph+WriteGraph)`, `HypothesisEngine(ReadGraph)`.

**aegis-compliance** — CVSS v3.1 scoring (FIRST spec formula, all 34 `VulnerabilityClass` variants mapped). OWASP Top 10 2021 + API Security 2023 + PCI-DSS compliance mapping. Pentest report generator. **Warning:** `compliance_mapper` matches on `Display` strings not enum variants — new variants silently miss compliance mappings. **Dev-only** (not in production binary).

**aegis-discovery** — Directory brute-forcing (2,013 paths), JS endpoint extraction (7 regex patterns), technology fingerprinting, parameter discovery (67 params), virtual host discovery (31 prefixes), backup file scanning (40 sensitive paths), sitemap/robots.txt parsing. `discovered_params_to_operations()` emits `NodeType::Config` (not `Endpoint`) for parameters. All modules enforce localhost via `validate_target_is_localhost()`. **Dev-only.**

**aegis-exploiter** — Tool wrapper framework (`ToolWrapper` trait): SQLMap, Nuclei, NmapWrapper, SubfinderWrapper, OastWrapper. Native `JwtTester` (no subprocess, `is_available()` always returns `true`). `check_tool_installed` shells out to `which` (platform-dependent). **Dev-only.**

### Infrastructure

**aegis-orchestrator** — CLI binary + full pipeline orchestration. 30+ modules. `ScanConfig` (clap derive), `ScanContext`, `HypothesisBridge` (Unix socket subprocess), `RefutedTracker` (monotonic refuted hypothesis set), `PipelineDefinition` (topological sort via Kahn's algorithm). Key gap: `WORKSPACE_CRATE_COUNT = 11` constant is outdated (actual: 17).

**aegis-proxy** — Hyper-based HTTP recording proxy with `preserve_header_case(true)`. Request repeater. 4-mode `Intruder` (Sniper/BatteringRam/Pitchfork/ClusterBomb). Result sort: non-200 first, then descending body length. Knowledge graph sync. **Standalone** — no production binary dependency.

**aegis-test-support** — `TestServer` (in-process axum), `MockGraphStore` (no locks, no validation), `MockFuzzTransport` (can simulate WAF/rate-limit behavior), `VulnerableAppBuilder` (16 vuln types + ground truth), `TempWorkspace`. Used as dev-dependency by passive-recon and enumeration.

---

## 8. Dependencies

<!-- metadata: external dependencies, categories, rationale -->

### By Category

| Category | Key Libraries | Version |
|---------|--------------|---------|
| **Async runtime** | tokio (full) | 1.49 |
| **Serialization** | serde (derive), serde_json, ciborium (CBOR) | 1.0, 1.0, 0.2 |
| **HTTP client** | reqwest (json, blocking for update-db) | 0.12 |
| **HTTP server** | hyper, hyper-util (proxy), axum (tests) | 1.8, 1.8, 0.8 |
| **Database** | rusqlite (bundled — no system dep) | 0.32 |
| **CLI** | clap (derive) | 4 |
| **Logging** | tracing, tracing-subscriber (env-filter) | 0.1, 0.3 |
| **Cryptography** | sha3, hmac, sha2, ed25519-dalek (rand_core) | 0.10, 0.12, 0.10, 2 |
| **Security** | subtle (timing-safe comparison) | latest |
| **Graph** | petgraph (DiGraph, astar, BFS) | 0.7 |
| **Parsers** | openapiv3, graphql-parser, cargo-lock, semver | 2, 0.4, 10, 1 |
| **SARIF** | sarif_rust | 0.3 |
| **Browser** | chromiumoxide (browser feature only) | latest |
| **Utilities** | rand, uuid (v4), regex, url, base64 | 0.9, 1, 1, 2, 0.22 |
| **Concurrency** | parking_lot (upgradable RwLock) | latest |
| **Testing** | proptest, tempfile, wiremock | dev only |

**No workspace feature flags** — all dependencies are unconditionally compiled.

**Notable choices:** `rusqlite` with `bundled` (zero system deps); `parking_lot` over `std::sync` (upgradable read locks, no poisoning); `sha3` not SHA2 for hash chains (Keccak vs Merkle-Damgård diversity); `sarif_rust` for SARIF schema compliance.

**Detail:** `claudedocs/current_state/dependencies.md`

---

## 9. Module Tree Summary

<!-- metadata: top-level modules, crate structure -->

| Crate | Module Count | Top-Level Modules |
|-------|-------------|-------------------|
| protocol | 14 | audit, capability, defense_context, edge, finding, hypothesis_ipc, ipc, node, operation, request, scan_event, scope_attestation, signed_config, target_validation |
| knowledge-graph | 7 | edge_store, finding_store, graph, graph_store, node_store, operation_log, query/{path_queries,reachability} |
| audit-log | 5 | event_store, hash_chain, hmac_signer, log_verifier, log_writer |
| supervisor | 2 | capability_manager, process_manager |
| passive-recon | 3 | dependency_parser, filesystem_walker, vuln_database |
| enumeration | 5 | auth_flow, auth_matrix, graphql_discovery, introspection, route_parser |
| fuzzing | 21 | scheduler, mutator, executor, oracle, stealth_config, defense_profile, waf_fingerprinter, rate_limit_detector, bot_detection_probe, payload_selector, streaming_fuzzer, request_patterns, confirmation, cors_detector, graphql_tester, header_analyzer, idor_tester, mass_assignment_tester, race_tester, cloud_detector, subdomain_takeover |
| chain-synthesis | 3 | attack_graph, graph_export, path_analysis |
| reporting | 5 | certificate_serializer, narrative, report_format, risk_scorer, sarif_emitter |
| evasion-engine | 7 | encoding_transformer, header_transformer, persona, session_manager, timing_controller, tls_config, transport |
| orchestrator | 30+ | actor, attest, auth_session, benchmark, calibration, checkpoint, convergence, distributed, distributed_transport, endpoint_similarity, graph_persistence, hypothesis_bridge, idor_analyzer, interactive, phase_{analyze,crawl,dom_verify,error,fingerprint,fuzz,recon,report}, pipeline, pipeline_composer, scan_config, scan_history, scan_strategy, telemetry, update_db, util |
| crawler | 6 | crawler, error, page_fetcher, types, browser_fetcher*, dom_verifier* (*feature=browser) |
| compliance | 5 | class_mapper, compliance_mapper, context_adjuster, cvss_scorer, report_generator |
| discovery | 9 | backup_scanner, brute_forcer, graph_ops, js_extractor, param_discoverer, sitemap_parser, tech_fingerprinter, vhost_discoverer, wordlist |
| exploiter | 11 | checker, error, jwt_tester, nmap_wrapper, nuclei_wrapper, oast_wrapper, runner, selector, sqlmap_wrapper, subfinder_wrapper, wrapper |
| proxy | 5 | graph_sync, intruder, proxy, repeater, types |
| test-support | 7 | assertions, fixture_data, fixture_server, mock_graph, mock_transport, temp_workspace, vulnerable_app |

**Total: 149 modules across 17 crates**

**Detail:** `claudedocs/current_state/code_analysis/module_tree.md`

---

## 10. Known Gaps

<!-- metadata: documentation gaps, areas for further investigation, analysis limitations -->

### Partially Documented Areas

1. **Fuzzing specialized testers** (9 modules) — `cors_detector`, `idor_tester`, `race_tester`, `graphql_tester`, `header_analyzer`, `mass_assignment_tester`, `cloud_detector`, `subdomain_takeover`, `confirmation` — modules discovered but internal probe functions not fully documented.

2. **5 orchestrator modules** — `auth_session`, `distributed_transport`, `idor_analyzer`, `scan_strategy`, `distributed_transport` added to module tree but their full API was not read.

3. **`ScanActor` implementations** — `ReconActor`, `FingerprintActor`, `FuzzActor<T>`, `AnalyzeActor`, `ReportActor`, `ConvergenceActor` listed but method signatures not verified.

4. **Docker Tier 2 tests** — 34 tests exist in `crates/orchestrator/tests/docker_integration.rs` covering Express, Flask, GraphQL defense stacks, but specific test scenarios were not read.

5. **Python hypothesis-engine internals** — `calibration.py` temperature scaling, `generator.py` self-consistency rounds, `uncertainty.py` structural vs speculative patterns — documented from CLAUDE.md not source.

6. **`phase_dom_verify.rs`** — DOM verification phase exists in pipeline but source was not read; interaction with crawler's `dom_verifier` module not traced.

### Known Inconsistencies (See `inconsistencies.md`)

10 documented issues, none critical. Most important:
- `compliance_mapper` matches `Display` strings → new `VulnerabilityClass` variants silently miss compliance mappings
- `WORKSPACE_CRATE_COUNT = 11` constant in `pipeline.rs:1705` is outdated (actual: 17)
- `CrawlResult::default()` in `run_crawl_phase()` — crawler not yet wired into live scan

### Critical Pitfalls (See `index.md` for full list of 19)

1. Adding `NodeType`/`EdgeLabel` variants → must update `EDGE_WHITELIST` AND `protocol_test.rs`
2. `FindingData.confidence` is `FindingConfidence` NOT `f64` — access via `.confidence.composite.value()`
3. `ProcessManager` is a pure state machine — does NOT call `Command::spawn()`
4. `compliance_mapper` matches Display strings → new variants silently miss mappings
5. LLM IPC uses Unix domain socket, NOT stdin/stdout (despite old code in the same file)
6. `EvidenceLevel::Controlled` has `#[serde(alias = "Counterfactual")]` — do not remove

---

*For the complete knowledge base entry point, see: `claudedocs/current_state/index.md`*
