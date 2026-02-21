# AEGIS — Adversarial Vulnerability Discovery Framework

Localhost-only security testing framework. 11 Rust crates + 1 Python package. 2,374 Rust tests, 229 Python tests.

## Commands

```
cargo test --workspace                                                # 2,374 tests across 11 crates
cargo clippy --workspace -- -D warnings                               # zero warnings policy
cargo fmt --all --check                                               # formatting gate
cd hypothesis-engine && uv run pytest src/hypothesis_engine/ -v       # 229 Python tests
AEGIS_INTEGRATION_TESTS=1 cargo test -p aegis-orchestrator \
  --test docker_integration -- --test-threads=1                       # 28 Docker Tier 2 tests (requires Docker/Colima)
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
    ├── audit-log              Hash-chained append-only log (SHA3-256 + HMAC + CBOR),
    │     │                    event sourcing (replay, snapshot, diff, timeline)
    │     └── supervisor       Process lifecycle + capability tokens
    │
    ├── passive-recon          Lock file parsing (cargo-lock), vuln DB (SQLite), filesystem walking
    ├── enumeration            Route discovery, OpenAPI (openapiv3), GraphQL (graphql-parser), auth matrix,
    │                          GraphQL fallback discovery (error-based + brute-force), auth flow modeling
    ├── fuzzing                Priority scheduler (novelty-based), payload mutation (tagged), stealth mode,
    │                          rate-limited execution, anomaly oracle (counterfactual testing),
    │                          WAF detection, rate limit probing, bot detection (merged from defense-fingerprinting),
    │                          WebSocket/SSE streaming fuzzer, concurrent request patterns, UCB1 payload selector
    ├── chain-synthesis        Attack graph (petgraph DiGraph), shortest paths, centrality analysis (capped),
    │                          causal mitigation impact analysis, priority-bounded DFS path enumeration,
    │                          DOT export, defense gap analysis
    ├── reporting              Risk scoring (defense-aware, confidence-weighted), SARIF 2.1.0 (CWE + ATT&CK),
    │                          CBOR certificates, human-readable narratives, CVE references, mitigation priority,
    │                          multi-format output (Developer/Security/Executive)
    ├── evasion-engine         Persona-based HTTP transport (10 personas, rotation), header/encoding transforms,
    │                          timing jitter, session rotation, localhost enforcement,
    │                          TLS fingerprint abstraction (JA3 mapping, dual-backend Reqwest/Rquest)
    └── orchestrator           CLI binary (clap), concurrent recon+fingerprint, audit logging,
                               iterative scan pipeline: recon → fingerprint → (fuzz → analyze)* → report
                               Per-phase timing, LLM attribution, endpoint filtering, convergence detection,
                               scan checkpoints/resume, benchmark evaluation, confidence calibration,
                               endpoint similarity (TF-IDF), scan history (SQLite), interactive mode,
                               pipeline composition (topological ordering), distributed coordination,
                               opt-in telemetry

hypothesis-engine        (Python) LLM hypothesis generation via pluggable backends (Bedrock, OpenAI, ollama),
                         chain-of-thought prompting, evasion mode, test compilation, per-class feedback loop,
                         token usage tracking, LlmBackend ABC for backend abstraction,
                         uncertainty quantification (hedging/confidence pattern analysis)
```

## Code Organization

```
crates/
├── protocol/src/           node.rs  edge.rs  finding.rs  operation.rs  audit.rs  capability.rs
│                           ipc.rs  target_validation.rs  request.rs  defense_context.rs
│                           scope_attestation.rs  signed_config.rs  scan_event.rs
├── knowledge-graph/src/    node_store.rs  edge_store.rs  finding_store.rs  operation_log.rs  graph.rs
│                           graph_store.rs  query/{path_queries,reachability}.rs
├── audit-log/src/          hash_chain.rs  hmac_signer.rs  log_writer.rs  log_verifier.rs  event_store.rs
├── supervisor/src/         process_manager.rs  capability_manager.rs
├── passive-recon/src/      dependency_parser.rs  vuln_database.rs  filesystem_walker.rs
├── enumeration/src/        route_parser.rs  introspection.rs  auth_matrix.rs  graphql_discovery.rs
│                           auth_flow.rs
├── fuzzing/src/            scheduler.rs  mutator.rs  executor.rs  oracle.rs  stealth_config.rs
│                           defense_profile.rs  waf_fingerprinter.rs  rate_limit_detector.rs
│                           bot_detection_probe.rs  streaming_fuzzer.rs  request_patterns.rs
│                           payload_selector.rs
├── chain-synthesis/src/    attack_graph.rs  path_analysis.rs  graph_export.rs
├── reporting/src/          risk_scorer.rs  sarif_emitter.rs  certificate_serializer.rs  narrative.rs
│                           report_format.rs
├── evasion-engine/src/     persona.rs  header_transformer.rs  encoding_transformer.rs  timing_controller.rs
│                           session_manager.rs  transport.rs  tls_config.rs
└── orchestrator/src/       scan_config.rs  pipeline.rs  phase_recon.rs  phase_fingerprint.rs
                            phase_fuzz.rs  phase_analyze.rs  phase_report.rs  main.rs  util.rs
                            actor.rs  benchmark.rs  calibration.rs  checkpoint.rs  convergence.rs
                            distributed.rs  endpoint_similarity.rs  graph_persistence.rs
                            interactive.rs  pipeline_composer.rs  scan_history.rs  telemetry.rs

hypothesis-engine/src/hypothesis_engine/
    bedrock_client.py  openai_client.py  generator.py  compiler.py  feedback.py  evasion_mode.py
    uncertainty.py  bypass_examples.json

.github/workflows/
    tier1-tests.yml                 PR/push: cargo fmt, clippy, workspace tests, pytest
    tier2-tests.yml                 Push to main: Docker build + Tier 2 integration tests
    ground-truth-validation.yml     Manual dispatch: validates scanner against ground truth fixtures

scripts/
    validate-ground-truth.sh        Local ground truth validation (builds stacks, runs scanner, checks findings)
```

Every source file has an adjacent test file: `{module}_test.rs` for Rust, `test_{module}.py` for Python.

## Defense Stacks (Docker Fixture Apps)

```
defense-stacks/
├── express-vuln-app/       Express.js app with 17 endpoints covering all 16 VulnerabilityClass variants
│                           Uses better-sqlite3, ejs (SSTI), node-serialize (insecure deser)
│                           Includes openapi.json spec + ground-truth.json (16 findings)
├── flask-vuln-app/         Flask app with 8 endpoints: SQLi, XSS, CmdInj, PathTraversal, SSTI, Misconfig, OpenRedirect
│                           Poetry-managed, ground-truth.json (7 findings), pyyaml 5.3.1 (CVE-2020-14343)
├── graphql-vuln-app/       Apollo/express-graphql with SQLi, XSS, PathTraversal, BrokenAuth, BrokenAuthz, SensitiveData
│                           Introspection toggleable via DISABLE_INTROSPECTION=1, ground-truth.json (8 findings)
├── bot-detection/          Python bot detector: header/UA scoring with configurable BOT_THRESHOLD
│   └── detector/           Flask app on port 5000, scoring formula: ua_score(0.4) + header_score(0.6 * present/3)
├── modsecurity/            ModSecurity CRS override config (modsecurity-override.conf)
└── compose/                Docker Compose stacks + nginx configs
    ├── docker-compose.yml               Express standalone (port 3000)
    ├── docker-compose.modsecurity.yml   Express + ModSecurity WAF (port 8080)
    ├── docker-compose.ratelimit.yml     Express + nginx rate limiting (port 8081)
    ├── docker-compose.botdetect.yml     Express + bot detection proxy (port 8082)
    ├── docker-compose.fulldefense.yml   Express + WAF + rate limit + bot detect (port 8083)
    ├── docker-compose.flask.yml         Flask standalone (port 5001)
    ├── docker-compose.graphql.yml       GraphQL (port 4000) + no-introspection variant (port 4001)
    ├── nginx-ratelimit.conf             10 req/s rate limit with burst=20
    ├── nginx-botdetect.conf             auth_request to bot detector before upstream
    └── nginx-fulldefense.conf           bot detect → WAF → upstream chain
```

### Docker Tier 2 Integration Tests

`crates/orchestrator/tests/docker_integration.rs` — 25 tests gated behind `AEGIS_INTEGRATION_TESTS=1`:
- **7 Express tests**: ground truth validation, OpenAPI-guided scanning, recon-only, ModSecurity bypass, rate limit stealth, bot detect evasion, full defense
- **3 Flask tests**: ground truth, SSTI detection, recon-only
- **3 GraphQL tests**: introspection-based, fallback discovery, auth bypass
- **4 Cross-scan tests**: checkpoint resume, diff-mode SARIF, convergence detection, scan history
- **3 Report format tests**: developer SARIF, security ATT&CK, executive summary
- **3 Stealth mode tests**: aggressive, paranoid, benchmark
- **2 Audit trail tests**: full scan integrity, replay matches scan results

Uses `DockerCompose` RAII struct with Drop-based teardown. Requires Docker or Colima runtime.

## Key Dependencies

| Crate | Notable Deps |
|---|---|
| protocol | serde, serde_json, sha3, ed25519-dalek |
| knowledge-graph | parking_lot, serde_json, proptest (dev), tempfile (dev) |
| audit-log | sha3, hmac, ciborium, serde_json |
| supervisor | tokio, sha3, subtle |
| passive-recon | rusqlite (bundled), semver, cargo-lock |
| enumeration | reqwest, openapiv3, graphql-parser |
| fuzzing | rand, reqwest, uuid, regex, url, aegis-protocol |
| chain-synthesis | petgraph |
| reporting | sarif_rust, ciborium, sha3, aegis-fuzzing |
| evasion-engine | reqwest, rand, aegis-protocol (no longer depends on aegis-fuzzing) |
| orchestrator | clap, tracing, rand, rusqlite (bundled), tempfile (dev), reqwest (dev), all workspace crates |
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
- **MitigationResult** — Result of graph-theoretic mitigation impact estimate: removed_findings, findings_remaining, impact_score.
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
- **ScopeDocument / SignedScopeAttestation** — Ed25519-signed authorization documents binding target + authorized_by + expiry. Verified via `verify_attestation()`.
- **SignableConfig / SignedConfig** — Ed25519-signed scan configuration with SHA3-256 content hash. Tamper detection via `verify_signed_config()`.
- **ScanEvent** — Typed event enum (EndpointDiscovered, HypothesisGenerated, PayloadTested, AnomalyDetected, FindingConfirmed, etc.) for inter-module event bus.
- **GraphStore** — Trait abstracting knowledge graph access (apply_operations, nodes_by_type, findings, save/load). Enables test fakes.
- **EventQuery / ScanSnapshot / SnapshotDiff** — Event sourcing types for audit log replay. `replay_from_entries()` reconstructs scan state; `diff_snapshots()` computes deltas.
- **GraphQlDiscoveryResult** — Fallback GraphQL discovery: extracted query/mutation fields + discovery method (ErrorBased, CommonFieldBrute, Combined).
- **AuthFlow / AuthFlowStep** — Multi-step authentication flow modeling with template rendering, response extraction, and vulnerability detection (session fixation, weak IDs, insecure cookies).
- **StreamProtocol / StreamFuzzTarget / StreamFuzzResult** — WebSocket and SSE streaming fuzzer: protocol-aware payload generation, message analysis, anomaly scoring.
- **BrowsingPattern / RequestBatch / CoverTrafficConfig** — Concurrent request patterns: Sequential, BurstThenPause, ParallelResources, NavigationChain. Cover traffic injection for stealth.
- **PayloadSelector** — UCB1 multi-armed bandit for adaptive payload selection. Balances exploitation of effective payloads with exploration of novel ones.
- **DefenseGapReport** — Unprotected entry points/assets identified by defense gap analysis on the attack graph.
- **ReportFormat** — 3-variant enum: Developer (SARIF), Security (ATT&CK-enriched), Executive (summary JSON).
- **TlsFingerprint** — 6 variants: Chrome120, Firefox121, Safari17, Edge120, Curl, Default. Maps to JA3 hash strings via `ja3_hash()`.
- **HttpClientBackend** — Reqwest (always available) vs Rquest (TLS fingerprint control). **TlsConfig / HttpClientConfig** — Builder-pattern configs.
- **FingerprintMapping** — HashMap\<PersonaId, TlsFingerprint\> ensuring persona-TLS consistency.
- **ScanCheckpoint** — Serializable scan progress for resume: completed phases, iteration count, findings count.
- **GroundTruth / BenchmarkFixture / BenchmarkEvaluation** — Benchmark framework: ground truth entries, precision/recall/F1 computation, per-class metrics.
- **CalibrationReport / CalibrationBin** — Confidence calibration: histogram binning, expected calibration error (ECE), over/underconfidence detection.
- **EndpointSignature / TransferredFinding** — TF-IDF endpoint similarity for cross-endpoint hypothesis transfer.
- **ScanHistoryEntry / ScanHistoryRecord** — SQLite-backed scan history: per-payload outcomes across scans for adaptive selection.
- **RefutedTracker** — Monotonic set of refuted hypotheses preventing re-testing in iterative fuzz loops.
- **InteractiveCommand / InteractiveSession** — Interactive scan control: pause/resume/status/findings/endpoints/priority/skip/quit.
- **PipelineStage / PipelineDefinition / PhaseType** — Declarative pipeline composition with topological ordering (Kahn's algorithm) and execution wave planning.
- **DistributedConfig / CoordinatorState / WorkAssignment** — Distributed scan coordination: worker partitioning (RoundRobin, PriorityBased), heartbeat failure detection, rebalancing.
- **TelemetryConfig / TelemetryCollector** — Opt-in aggregate telemetry: scan duration, finding counts, phase timing. Never raw findings/payloads. Disabled by default.
- **ScanActor** — Trait for pipeline phase actors (name, required capabilities, execute). Implementations: ReconActor, FingerprintActor, FuzzActor\<T\>, AnalyzeActor, ReportActor, ConvergenceActor.

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
- Graph-theoretic mitigation estimation — `estimated_mitigation_impact(node)` computes which findings become unreachable if a node is removed; `graph_influence_ranking()` sorts nodes by estimated mitigation value; complements betweenness centrality with actionable prioritization. These are structural graph estimates, not causal claims.
- Endpoint response variance detection — `measure_endpoint_variance()` sends N identical requests and measures status code/body size variance; high-variance endpoints flagged as non-deterministic to reduce false positives in counterfactual testing
- Continuous confidence scoring — `confidence_score: Option<f64>` on FindingData complements discrete EvidenceLevel; `confidence_from_evidence()` maps EvidenceLevel to base confidence; `effective_confidence()` resolves to score or falls back to evidence-based calculation
- Defense-fingerprinting merged into fuzzing crate — eliminates a leaf crate with no consumers other than orchestrator and reporting; reduces workspace crate count from 12 to 11; WAF/rate-limit/bot-detection types now re-exported from `aegis_fuzzing` root alongside scheduler/mutator types
- Ed25519 (ed25519-dalek) for scope attestation and config signing — asymmetric signatures allow offline verification without shared secrets; SHA3-256 content hash for config integrity
- Event sourcing for audit log — `replay_from_entries()` reconstructs scan state from audit events; `diff_snapshots()` computes deltas between states; enables post-hoc analysis without separate state persistence
- GraphStore trait for knowledge graph abstraction — all pipeline phases operate through trait; tests inject lightweight fakes instead of full KnowledgeGraph; `Send + Sync` bound for async compatibility
- ScanEvent typed event bus — enum-based events (not strings) for compile-time exhaustiveness; enables inter-module communication without direct dependencies
- GraphQL fallback discovery — error-based field extraction + common field brute-force when introspection is disabled; merges results from both strategies
- Multi-step auth flow modeling — template-based request rendering with `{{variable}}` interpolation; response extraction from headers/JSON/cookies/status codes; detects session fixation, weak session IDs, insecure cookies
- WebSocket/SSE streaming fuzzer — protocol-aware payload generation; localhost validation on ws:// and sse:// URLs; anomaly types: UnexpectedClose, ErrorFrame, DataLeak, AuthBypass, StateCorruption, ProtocolViolation
- UCB1 bandit for payload selection — balances exploitation (historically effective payloads) with exploration (untested payloads); novel payloads receive infinite priority; standard C=sqrt(2) exploration constant
- Concurrent request patterns with cover traffic — BrowsingPattern enum controls timing; cover traffic injected into batches to mimic real browsing; MAX_BATCH_SIZE=64 prevents resource exhaustion
- DOT export for attack graphs — Graphviz visualization with node coloring by type, edge coloring by difficulty; defense gap analysis identifies unprotected entry points/assets
- Multi-format reporting — Developer (IDE SARIF), Security (ATT&CK-enriched SARIF), Executive (summary JSON); same findings, different emphasis per audience
- TLS fingerprint abstraction — PersonaId→JA3 hash mapping; HttpClientBackend enum (Reqwest/Rquest) allows future swap without API changes; Chrome120/Edge120 share Chromium JA3 hash
- Scan checkpoints for resume — JSON-serialized progress alongside graph DB; deleted on successful completion; enables interrupted scan recovery
- Benchmark evaluation with ground truth — GroundTruthEntry(endpoint, vulnerability_class) pairs; precision/recall/F1 per class and aggregate; enables regression testing
- Confidence calibration — histogram binning of confidence scores vs actual positive rates; expected calibration error (ECE) metric; identifies over/underconfident score ranges
- TF-IDF endpoint similarity — structural comparison of endpoint signatures (path segments, methods, parameters); transfers confirmed vulnerability hypotheses to similar endpoints
- SQLite scan history — per-payload success/failure records across scans; enables adaptive payload selection and cross-scan learning; rusqlite bundled (zero external deps)
- Refuted hypothesis tracking — monotonic HashSet prevents re-testing failed hypotheses; shrinks search space across iterations; no false negative risk (refuted = tested + no findings)
- Interactive scan mode — command parser with case-insensitive matching; session state tracks paused/running status; does not require async runtime
- Pipeline composition via topological sort — Kahn's algorithm for dependency resolution; execution waves group independent stages; validates no cycles, no missing dependencies
- Distributed scan coordination — worker partitioning strategies (RoundRobin, PriorityBased, VulnerabilityClass); heartbeat-based failure detection; automatic rebalancing on worker failure
- Opt-in telemetry — disabled by default, explicit `TelemetryConfig { enabled: true }` required; aggregate-only (scan duration, finding counts, phase timing); never raw findings, payloads, or endpoint URLs
- Uncertainty quantification (Python) — hedging pattern detection ("might", "possibly", "could be") and confidence pattern detection ("confirms", "clearly") in LLM reasoning traces; adjusts hypothesis confidence scores

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
- OpenAPI `requestBody` IS extracted in `enumeration` crate (`introspection.rs:120-150`) — body parameters parsed with `ParameterLocation::Body`. However, parameter metadata is **not persisted to the knowledge graph** and **not used by the fuzzer**: `FuzzTarget.parameter` is always empty string; `enqueue_targets_for_endpoints()` reads only `path` and `method` from graph node properties
- `FuzzScheduler` NaN handling — RESOLVED: `enqueue()` now clamps non-finite `priority_score` to `0.0` before insertion
- `bypass_examples.json` loading — RESOLVED: `_load_bypass_examples()` now checks `corpus_path.exists()` and emits `RuntimeWarning` + returns `{}` if missing
- `cargo fmt --check` — RESOLVED: formatting is now clean workspace-wide; gate is enforced
- `GraphStore` trait must be `Send + Sync` — required for `ScanContext` across async boundaries; `KnowledgeGraph` implements this via `parking_lot::RwLock`
- `ScopeDocument` / `SignedConfig` use `ed25519-dalek` — signing keys are `SigningKey`, verification uses `VerifyingKey`; hex-encoded in serialized forms
- `event_store::replay_from_entries()` is independent of `AuditLogWriter` — operates on `&[AuditEntry]` slices; does not verify hash chain or HMAC signatures
- `graphql_discovery` COMMON_QUERY_FIELDS (21) and COMMON_MUTATION_FIELDS (13) are hardcoded — extend these arrays when adding new field brute-force targets
- `auth_flow` template rendering uses `{{variable}}` syntax — double curly braces; `render_template()` replaces from HashMap; unresolved variables are left as-is
- `streaming_fuzzer::validate_stream_target()` enforces localhost on ws:// URLs — reuses protocol crate's target validation; SSE uses http:// so standard validation applies
- `PayloadSelector::ucb1_score()` returns `f64::INFINITY` for novel payloads — ensures untested payloads are always selected first
- `request_patterns` MAX_BATCH_SIZE=64 — `build_burst_batch()` and `build_parallel_resources_batch()` clamp at this limit
- `graph_export::export_dot()` escapes labels — uses `dot_escape()` to prevent Graphviz injection from node labels
- `tls_config` Chrome120 and Edge120 JA3 hashes are identical — both are Chromium-based; test `ja3_hash_chrome_and_edge_share_chromium_base` asserts this
- `ScanCheckpoint` deleted on successful scan completion — presence of checkpoint file indicates interrupted scan
- `BenchmarkEvaluation` F1 score is 0.0 when precision + recall = 0 — avoids division by zero
- `CalibrationReport::expected_calibration_error` computed as weighted average of |mean_confidence - actual_positive_rate| per bin
- `EndpointSignature` tokenization splits path on `/`, `_`, `-`, and camelCase boundaries — affects TF-IDF similarity
- `ScanHistoryEntry::target_app_hash` groups history records by target application — prevents cross-app contamination in adaptive selection
- `InteractiveSession::execute_command()` returns `InteractiveResponse` — caller is responsible for rendering; no I/O in the module itself
- `PipelineDefinition::validate()` checks for cycles, missing dependencies, and at least one Source stage — call before `topological_order()`
- `CoordinatorState::detect_failed_workers()` requires caller to provide current timestamp — uses `heartbeat_timeout_ms` from config; returns list of failed `WorkerId`s
- `TelemetryCollector::export_json()` sanitizes error categories — strips stack traces and paths; only category strings like "network_error", "timeout", "parse_failure"
- `--resume` requires `--graph-db` — checkpoint logic is fully wired: saves after each phase, skips completed phases on resume, deletes checkpoint on successful completion. Without `--graph-db`, `--resume` logs a warning and proceeds without checkpointing.
- Docker fixture apps bind to `0.0.0.0` (not `127.0.0.1`) — required for Docker networking; Node Alpine containers use `node -e` healthchecks (not `wget`)
- Bot detector scoring formula: `ua_score(0.4) + header_score(0.6 * present/len(REQUIRED_BROWSER_HEADERS))` — max=1.0; BOT_THRESHOLD default 0.5; requests scoring below threshold are classified as bots
- Flask Dockerfile uses `poetry install --only main --no-root` with `POETRY_VIRTUALENVS_CREATE=false` — Poetry 2.x deprecated `--no-dev`
- Docker Tier 2 tests use RAII `DockerCompose` struct — Drop trait tears down containers; `--test-threads=1` required to avoid port conflicts
- Colima (`colima start --cpu 4 --memory 4`) works as Docker Desktop alternative on macOS — avoids organizational sign-in requirements
