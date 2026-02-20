# AEGIS — Adversarial Vulnerability Discovery Framework

Localhost-only security testing framework. 11 Rust crates + 1 Python package. 1,267 Rust tests, 187 Python tests.

## Commands

```
cargo test --workspace                                                # 1,267 tests across 11 crates
cargo clippy --workspace -- -D warnings                               # zero warnings policy
cargo fmt --check                                                     # formatting gate
cd hypothesis-engine && uv run pytest src/hypothesis_engine/ -v       # 187 Python tests
```

## Architecture

```
protocol                 Shared types: NodeType, EdgeLabel, VulnerabilityClass, GraphOperation,
    |                    FuzzRequest/FuzzResponse, EvidenceLevel, DefenseContext, target validation
    |
knowledge-graph          In-memory graph engine (arena storage, parking_lot::RwLock<Inner>, batch validation)
    |                    Semantic edge validation, weight/score bounds, duplicate edge detection,
    |                    strict sequence gap detection, JSON persistence (save/load), serde derives
    |
    ├── audit-log              Hash-chained append-only log (SHA3-256 + HMAC + CBOR)
    │     └── supervisor       Process lifecycle + capability tokens
    │
    ├── passive-recon          Lock file parsing (cargo-lock), vuln DB (SQLite), filesystem walking
    ├── enumeration            Route discovery, OpenAPI (openapiv3), GraphQL (graphql-parser), auth matrix
    ├── fuzzing                Priority scheduler (novelty-based), payload mutation (tagged), stealth mode,
    │                          rate-limited execution, anomaly oracle (counterfactual testing),
    │                          WAF detection, rate limit probing, bot detection (merged from defense-fingerprinting)
    ├── chain-synthesis        Attack graph (petgraph DiGraph), shortest paths, centrality analysis (capped),
    │                          causal mitigation impact analysis, priority-bounded DFS path enumeration
    ├── reporting              Risk scoring (defense-aware, confidence-weighted), SARIF 2.1.0 (CWE + ATT&CK),
    │                          CBOR certificates, human-readable narratives, CVE references, mitigation priority
    ├── evasion-engine         Persona-based HTTP transport (10 personas, rotation), header/encoding transforms,
    │                          timing jitter, session rotation, localhost enforcement
    └── orchestrator           CLI binary (clap), concurrent recon+fingerprint, audit logging,
                               iterative scan pipeline: recon → fingerprint → (fuzz → analyze)* → report
                               Per-phase timing, LLM attribution, endpoint filtering, convergence detection

hypothesis-engine        (Python) LLM hypothesis generation via pluggable backends (Bedrock, OpenAI, ollama),
                         chain-of-thought prompting, evasion mode, test compilation, per-class feedback loop,
                         token usage tracking, LlmBackend ABC for backend abstraction
```

## Code Organization

```
crates/
├── protocol/src/           node.rs  edge.rs  finding.rs  operation.rs  audit.rs  capability.rs
│                           ipc.rs  target_validation.rs  request.rs  defense_context.rs
├── knowledge-graph/src/    node_store.rs  edge_store.rs  finding_store.rs  operation_log.rs  graph.rs
│                           query/{path_queries,reachability}.rs
├── audit-log/src/          hash_chain.rs  hmac_signer.rs  log_writer.rs  log_verifier.rs
├── supervisor/src/         process_manager.rs  capability_manager.rs
├── passive-recon/src/      dependency_parser.rs  vuln_database.rs  filesystem_walker.rs
├── enumeration/src/        route_parser.rs  introspection.rs  auth_matrix.rs
├── fuzzing/src/            scheduler.rs  mutator.rs  executor.rs  oracle.rs  stealth_config.rs
│                           defense_profile.rs  waf_fingerprinter.rs  rate_limit_detector.rs  bot_detection_probe.rs
├── chain-synthesis/src/    attack_graph.rs  path_analysis.rs
├── reporting/src/          risk_scorer.rs  sarif_emitter.rs  certificate_serializer.rs  narrative.rs
├── evasion-engine/src/     persona.rs  header_transformer.rs  encoding_transformer.rs  timing_controller.rs
│                           session_manager.rs  transport.rs
└── orchestrator/src/       scan_config.rs  pipeline.rs  phase_recon.rs  phase_fingerprint.rs
                            phase_fuzz.rs  phase_analyze.rs  phase_report.rs  main.rs

hypothesis-engine/src/hypothesis_engine/
    bedrock_client.py  openai_client.py  generator.py  compiler.py  feedback.py  evasion_mode.py
    bypass_examples.json
```

Every source file has an adjacent test file: `{module}_test.rs` for Rust, `test_{module}.py` for Python.

## Key Dependencies

| Crate | Notable Deps |
|---|---|
| protocol | serde, serde_json, sha3 |
| knowledge-graph | parking_lot, serde_json, proptest (dev), tempfile (dev) |
| audit-log | sha3, hmac, ciborium |
| supervisor | tokio, sha3, subtle |
| passive-recon | rusqlite (bundled), semver, cargo-lock |
| enumeration | reqwest, openapiv3, graphql-parser |
| fuzzing | rand, reqwest, uuid, regex, aegis-protocol |
| chain-synthesis | petgraph |
| reporting | sarif_rust, ciborium, sha3, aegis-fuzzing |
| evasion-engine | reqwest, rand, aegis-protocol (no longer depends on aegis-fuzzing) |
| orchestrator | clap, tracing, rand, tempfile (dev), all workspace crates |
| hypothesis-engine | boto3, botocore, pydantic |

Rust edition 2024. Python >= 3.12 via `uv`.

## Key Types

- **VulnerabilityClass** — 16-variant enum. Derives Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize. Implements Display with human-readable names (e.g., "SQL Injection", "Cross-Site Scripting").
- **NodeType** — 9 variants including `Defense`. Implements Display. **EdgeLabel** — 8 variants including `ProtectedBy`. Implements Display.
- **is_valid_edge(source, label, target)** — Semantic validation whitelist for (NodeType, EdgeLabel, NodeType) triples. 28 valid combinations.
- **EvidenceLevel** — 4-variant enum: Statistical, Counterfactual, Confirmed, Chained. Tracks how strongly a finding is supported.
- **GraphOperation** — AddNode, AddEdge, UpdateWeight, AddFinding. Applied via `KnowledgeGraph::apply_operations(&[OperationLogEntry])`. All public methods return `Result<T, GraphError>`.
- **FuzzRequest / FuzzResponse** — Shared HTTP types in protocol crate. Re-exported by fuzzing crate for backwards compatibility.
- **DefenseContext** — Abstract defense posture in protocol crate: has_waf, waf_vendor, waf_blocked_categories, rate_limit_rps, bot_detection_present/evaded.
- **FuzzTarget** — endpoint + method + parameter + vulnerability_class + priority. Scheduler uses BinaryHeap.
- **MutationOrigin** — 5-variant enum: Template, Generative, BitFlip, Boundary, BypassCorpus. Tags payloads with their generation strategy.
- **TaggedPayload** — payload + origin. Returned by `generate_tagged_payloads()`.
- **DefenseProfile** — Optional WAF/rate-limit/bot-detection profiles. Builder pattern with `with_*` methods.
- **StealthConfig** — 4 presets: `default()`, `aggressive()`, `paranoid()`, `benchmark()`. Builder pattern with `with_*` methods.
- **PersonaId** — 10 variants: ChromeDesktop, FirefoxDesktop, SafariDesktop, ChromeMobile, Googlebot, EdgeDesktop, OperaDesktop, SafariMobile, CurlClient, PythonRequests. Persona rotation supported.
- **SarifFinding** — input struct for SARIF emission. Includes optional `defense_context`, `vulnerability_class`, `evidence_level`, `cve_id`, `mitigation_rank`, `confidence_score`.
- **MitigationResult** — Result of causal mitigation impact analysis: removed_findings, findings_remaining, impact_score.
- **FindingOrigin** — 3-variant enum: LlmHypothesis, StaticRule, Mutation. Tags fuzz findings by origin.
- **FuzzPhaseResult** — Wraps PhaseResult + origin_counts + discovered_endpoints.
- **GraphMetadata** — Scan metadata for graph persistence: scan_timestamp_unix_ms, target_url, aegis_version.
- **PhaseTimings / LlmMetrics / ScanMetrics** — Per-phase timing and LLM call tracking in scan pipeline.
- **VarianceReport** — Endpoint response variance measurement: response_codes, body_similarity, is_deterministic.
- **LlmBackend** — (Python) Abstract base class for LLM providers. Implementations: BedrockClient, OpenAiClient.
- **AuditWriter** — Trait with `append_event(&mut self, event) -> Result<(), LogWriterError>` and `sequence_number(&self) -> u64`. Implemented by `AuditLogWriter` (persists to disk) and `NoOpAuditLogWriter` (intentionally discards). Pipeline uses `Box<dyn AuditWriter>`.
- **NoOpAuditLogWriter** — Implements `AuditWriter`; intentionally discards all events. Used when `--no-audit` is set.
- **AuditLogWriter::append_event_full()** — Returns `Result<AuditEntry, LogWriterError>` with full hash chain/HMAC data. Use when caller needs the entry metadata (e.g. verification tests). The trait method `append_event()` delegates to this but discards the entry.
- **CertificateType** — 6 variants: Fuzzing, Taint, Chain, Config, Dependency, Evasion. Envelope versioned (current: v2).
- **BusinessContext** — JSON-loadable business annotations: excluded_endpoints, critical_assets, pii_endpoints, known_issues.
- **TokenUsage** — Pydantic model tracking input_tokens and output_tokens from Bedrock API calls.

## LLM Configuration

- **Backends:** Pluggable via `LlmBackend` ABC and `create_backend()` factory.
  - `bedrock` (default): AWS Bedrock with `global.anthropic.claude-sonnet-4-6`
  - `openai`: OpenAI-compatible API (also works with vLLM, any OpenAI-compatible server)
  - `ollama`: Local ollama via OpenAI-compatible API at `http://localhost:11434/v1`
- **AWS Profile:** `None` (uses default credentials chain — env vars, `~/.aws/credentials`, instance profile). Pass `aws_profile="ziya"` explicitly if needed.
- **SDK:** boto3 (Bedrock), urllib.request (OpenAI/ollama — no extra dependencies)
- **Retry:** exponential backoff, 3 retries (1s/2s/4s). **Timeout:** 120s per call.
- **Token tracking:** `invoke()` returns `(text, TokenUsage)` tuple. `GenerationResult` includes `input_tokens` and `output_tokens`.
- **Chain-of-thought:** System prompt instructs reasoning before JSON output. `reasoning_trace` captured in `GenerationResult`.
- **Feedback loop:** `ScanContext.feedback_summary` enables multi-round hypothesis generation. Per-class confirmation thresholds.

## Conventions

- No inline comments — names must be self-documenting (exception: magic constants documenting domain reasoning)
- `///` doc comments required on public types/functions that encode invariants, contracts, or threat models
- One public type per file (private helpers fine)
- Functions under 40 lines
- Enums over strings
- Builder pattern (`with_*`) for config structs
- `lib.rs` / `__init__.py` contain only re-exports
- Test files adjacent to source, included via `#[path]` attribute
- Private modules with `pub use module::*` re-exports in lib.rs
- Commit format: `[component] verb phrase`

## Design Decisions

- SHA3-256 for hash chain and certificate hashing (not SHA2) — Keccak sponge construction provides structural diversity from SHA2's Merkle-Damgard; defense-in-depth against class-specific attacks
- Arena-style Vec storage with u64 indices for graph stores — O(1) lookup — deterministic layout prevents timing side-channels in node lookup; tradeoff: append-only, no deletion
- petgraph DiGraph for attack graph + path analysis (astar, all_simple_paths, Bfs) — mature library with proven correctness; avoids reimplementing graph algorithms
- sarif_rust types for SARIF 2.1.0 output (not custom structs) — ensures schema compliance; tool interoperability with GitHub, Azure DevOps, VS Code
- openapiv3 for OpenAPI parsing, graphql-parser for GraphQL SDL/introspection — spec-compliant parsers; avoids hand-rolling schema parsers
- cargo-lock crate for Cargo.lock parsing (filters to default registry only) — handles all Cargo.lock format versions; registry filter prevents scanning private registries
- SQLite in-memory for vuln database — zero external deps — full SQL query capability with zero deployment overhead; bundled C library via rusqlite
- CBOR (ciborium) for certificate serialization — compact, binary-safe, versioned envelope — ~40% smaller than JSON, self-describing unlike Protobuf, no schema compilation step
- `let` chains (Rust 2024) for collapsible-if patterns
- parking_lot::RwLock\<Inner\> pattern for KnowledgeGraph facade concurrency — single contention point is acceptable for single-process localhost scope; readers never block each other; parking_lot chosen over std for upgradable read locks (no lock poisoning)
- Atomic validate-then-apply via RwLockUpgradableReadGuard — acquires upgradable read lock for validation, atomically upgrades to write lock for application; eliminates TOCTOU gap between validation and mutation
- reqwest for HTTP (evasion-engine transport designed for future rquest swap) — rquest provides TLS fingerprint control (JA3/JA4) needed for WAF evasion; reqwest sufficient for localhost
- FuzzRequest/FuzzResponse in protocol crate — shared HTTP types avoid backwards dependency from evasion-engine to fuzzing; re-exported by fuzzing for backwards compatibility
- Semantic edge validation via whitelist — 28 valid (NodeType, EdgeLabel, NodeType) triples; nonsensical edges rejected at graph validation time
- Counterfactual anomaly detection — paired control/treatment requests eliminate false positives from broken endpoints
- MAX_TOTAL_PATHS cap (100,000) with priority-bounded DFS — explores lowest-difficulty edges first, ensuring most exploitable paths are found before cap is hit; deterministic via sorted_neighbors
- Concurrent recon + fingerprint phases — tokio::join! overlaps filesystem analysis with HTTP defense probing; graph is thread-safe via RwLock
- Mandatory audit logging by default — scan fails if audit log cannot be created; `--no-audit` flag for explicit opt-out; HMAC key stored separately from audit data via `save_key_to_file()` or `with_derived_key(passphrase)`
- Iterative fuzz→analyze loop — `--max-iterations` (default 1) and `--convergence-threshold` (default 2) control repeated scanning; convergence stops when N consecutive rounds find zero new findings
- Pluggable LLM backends — `LlmBackend` ABC with `BedrockClient` and `OpenAiClient` implementations; `create_backend("bedrock"|"openai"|"ollama")` factory; `HypothesisGenerator` uses composition over inheritance
- Causal mitigation impact — `mitigation_impact(node)` computes which findings become unreachable if a node is fixed; `causal_influence_ranking()` sorts nodes by mitigation value; complements betweenness centrality with actionable prioritization
- Endpoint response variance detection — `measure_endpoint_variance()` sends N identical requests and measures status code/body size variance; high-variance endpoints flagged as non-deterministic to reduce false positives in counterfactual testing
- Continuous confidence scoring — `confidence_score: Option<f64>` on FindingData complements discrete EvidenceLevel; `confidence_from_evidence()` maps EvidenceLevel to base confidence; `effective_confidence()` resolves to score or falls back to evidence-based calculation
- Defense-fingerprinting merged into fuzzing crate — eliminates a leaf crate with no consumers other than orchestrator and reporting; reduces workspace crate count from 12 to 11; WAF/rate-limit/bot-detection types now re-exported from `aegis_fuzzing` root alongside scheduler/mutator types

## Graph Validation Rules

The knowledge graph enforces these constraints during batch validation:
- **Semantic edges**: Only 28 valid (NodeType, EdgeLabel, NodeType) triples accepted (e.g., Endpoint-ProtectedBy-Defense valid, DataStore-Calls-Function invalid)
- **Weight bounds**: Edge weights must be finite and >= 0.0
- **Score bounds**: Finding severity must be 0.0..=10.0, confidence must be 0.0..=1.0
- **Duplicate edges**: Two edges with same (source, target, label) are rejected
- **Sequence gaps**: In strict mode, operation sequences must be consecutive (no gaps). Default is relaxed mode.
- **Lock safety**: All KnowledgeGraph public methods return `Result<T, GraphError>` — parking_lot::RwLock (no poisoning); EdgeStore uses `.get()` instead of direct indexing; upgradable read locks for atomic validate-then-apply

## Safety & Dual-Use Hardening

- **Target validation at 3 layers**: protocol crate (shared validator), evasion-engine transport, fuzzing executor — all enforce localhost/127.0.0.1/::1 only
- **Audit logging**: SHA3-256 hash-chained, HMAC-signed audit events written to CBOR sidecar file; mandatory by default (`--no-audit` for explicit opt-out); HMAC key stored separately via `save_key_to_file()` or derived from passphrase
- **`--no-llm` flag**: Skip hypothesis engine entirely for environments without AWS credentials
- **`--no-audit` flag**: Explicitly opt out of audit logging (default is mandatory)
- **Graceful degradation**: `aws_profile` defaults to `None` (standard credentials chain). Pipeline continues with static fuzzing if Bedrock unavailable. Multiple LLM backends supported (Bedrock, OpenAI, ollama).

## Known Pitfalls

- Gemfile.lock: must track indent level to skip sub-dependencies
- Express handler extraction: strip trailing `)` and `;`
- Auth matrix: symmetric 200 responses are correctly flagged as anomalies
- Pydantic models named `Test*` trigger pytest collection warnings (harmless)
- `cargo fmt` reorders imports alphabetically
- VulnerabilityClass, NodeType, EdgeLabel, EvidenceLevel all implement Display — prefer `{}` over `{:?}` for user-facing output
- sarif_rust fields are `Option<Vec<...>>` — access via `.as_ref().unwrap()`
- Defense-fingerprinting types live in `aegis-fuzzing` (merged) — `use aegis_fuzzing::DefenseProfile` not `aegis_defense_fingerprinting::DefenseProfile`; same wildcard re-export pattern as before
- Evasion-engine modules same pattern — `use aegis_evasion_engine::PersonaId` not `::persona::PersonaId`
- `crates/defense-fingerprinting/` directory still exists on disk but is excluded from workspace members — dead code, safe to delete
- `invoke()` returns `(str, TokenUsage)` tuple — all callers must unpack
- `parse_hypotheses_from_response()` returns `(str, list[Hypothesis])` tuple — reasoning trace is the first element
- KnowledgeGraph methods return `Result` — `GraphError::LockPoisoned` removed (parking_lot doesn't poison); `GraphError::Io` added for persistence errors
- `OperationLog::new()` defaults to relaxed sequencing — use `new_strict()` for gap detection
- Adding new `NodeType` or `EdgeLabel` variants requires updating `is_valid_edge()` whitelist AND the exhaustive coverage test in `protocol_test.rs`
- `FindingData` has `confidence_score: Option<f64>` with `#[serde(default)]` — existing JSON without this field deserializes as None
- `run_fuzz()` returns `FuzzPhaseResult` (not `PhaseResult`) — access phase data via `.phase` field
- `run_report()` takes optional `&ScanMetrics` parameter — pass `None` when metrics not needed
- `HypothesisGenerator` uses composition (not inheritance) — accepts `client: LlmBackend` parameter; `create_backend()` factory for backend selection
- `OpenAiClient` uses `urllib.request` (no openai SDK dependency) — supports custom `base_url` for ollama/vLLM
- `KnowledgeGraph::save_to_file()` takes `&GraphMetadata` — caller provides metadata at save time
- `KnowledgeGraph::load_from_file()` returns fresh `OperationLog` — operation history not persisted, only store state
- Stores (`NodeStore`, `EdgeStore`, `FindingStore`) serialize full struct including index HashMaps — indexes are redundant with Vec data but ensures correctness on restore
- `run_recon_standalone(source_dir)` in `phase_recon.rs` — standalone entry point returning `Vec<OperationLogEntry>` without requiring a `ScanContext`; near-duplicate of `collect_recon_ops` in `pipeline.rs`
- Endpoint filtering is wired via `filter_scheduler_by_endpoints()` in `phase_fuzz.rs` — drains + re-enqueues scheduler; only called on freshly-enqueued targets (attempts=0); do not call after targets have been partially consumed
- `timestamp_ms()` is defined in `util.rs` and imported via `crate::util::timestamp_ms` by all orchestrator phases — do not add duplicate definitions
- Intra-batch duplicate edge detection uses `HashSet<(u64, u64, EdgeLabel)>` in `operation_log.rs` `validate_batch()` — catches duplicates within the same batch, not just against existing store
- `EvasionResult` now has `input_tokens` and `output_tokens` fields — matches `GenerationResult` and `CompilationResult` patterns
- `CapabilityManager::validate_token()` — RESOLVED: now uses `subtle::ConstantTimeEq` (`ct_eq`) for timing-safe token comparison
- `EvasionHypothesisGenerator` and `HypothesisCompiler` — RESOLVED: both now use composition via `LlmBackend`
- `OpenAiClient` 429 handling — RESOLVED: now retries with exponential backoff, same as 5xx
- `CompilationResult` (Python) — RESOLVED: `input_tokens` and `output_tokens` fields added and propagated from `HypothesisCompiler`
- OpenAPI `requestBody` is not extracted in `enumeration` crate — only path/query/header parameters are parsed; POST body parameters are invisible to the fuzzer
- `FuzzScheduler` NaN handling — RESOLVED: `enqueue()` now clamps non-finite `priority_score` to `0.0` before insertion
- `bypass_examples.json` loading — RESOLVED: `_load_bypass_examples()` now checks `corpus_path.exists()` and emits `RuntimeWarning` + returns `{}` if missing
- `cargo fmt --check` — RESOLVED: formatting is now clean workspace-wide; gate is enforced
