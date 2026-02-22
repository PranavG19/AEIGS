# AEGIS — Adversarial Vulnerability Discovery Framework

Localhost-only security testing framework. 11 Rust crates + 1 Python package. 2,917 Rust tests, 511 Python tests.

## Commands

```
cargo test --workspace                                                # 2,917 tests across 11 crates
cargo clippy --workspace -- -D warnings                               # zero warnings policy
cargo fmt --all --check                                               # formatting gate
cd hypothesis-engine && uv run pytest src/hypothesis_engine/ tests/ -v  # 511 Python tests
AEGIS_INTEGRATION_TESTS=1 cargo test -p aegis-orchestrator \
  --test docker_integration -- --test-threads=1                       # 34 Docker Tier 2 tests (requires Docker/Colima)
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
    ├── passive-recon          Lock file parsing (cargo-lock), vuln DB (SQLite, persistent file or in-memory),
    │                          filesystem walking, ecosystem OSV name mapping
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
                               opt-in telemetry, vulnerability database updater (OSV API)

hypothesis-engine        (Python) LLM hypothesis generation via pluggable backends (Bedrock, OpenAI, ollama),
                         XML-structured prompts with <thinking>/<hypotheses> tags,
                         chain-of-thought prompting, evasion mode, test compilation, per-class feedback loop,
                         token usage tracking, LlmBackend ABC for backend abstraction,
                         confidence calibration (sigmoid temperature scaling, ECE),
                         self-consistency generation (N-round agreement filtering),
                         uncertainty quantification (structural evidence vs speculative pattern analysis),
                         golden fixture evaluation (precision/recall/F1 against ground truth)
```

## Code Organization

```
crates/
├── protocol/src/           node.rs  edge.rs  finding.rs  operation.rs  audit.rs  capability.rs
│                           ipc.rs  hypothesis_ipc.rs  target_validation.rs  request.rs
│                           defense_context.rs  scope_attestation.rs  signed_config.rs
│                           scan_event.rs
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
                            phase_fuzz.rs  phase_analyze.rs  phase_report.rs  phase_error.rs
                            main.rs  util.rs  actor.rs  benchmark.rs  calibration.rs
                            checkpoint.rs  convergence.rs  hypothesis_bridge.rs
                            distributed.rs  endpoint_similarity.rs  graph_persistence.rs
                            interactive.rs  pipeline_composer.rs  scan_history.rs  telemetry.rs
                            update_db.rs

hypothesis-engine/src/hypothesis_engine/
    bedrock_client.py  openai_client.py  generator.py  compiler.py  feedback.py  evasion_mode.py
    uncertainty.py  calibration.py  ipc_types.py  bridge.py  bypass_examples.json

hypothesis-engine/tests/
    test_integration.py  test_evaluation.py  test_prompt_regression.py  test_llm_delta.py
    fixtures/express_app.json  fixtures/flask_app.json  fixtures/graphql_app.json
    fixtures/spring_boot_app.json  fixtures/django_app.json  fixtures/rails_app.json
    fixtures/fastapi_app.json  fixtures/nextjs_app.json  fixtures/php_laravel_app.json
    fixtures/go_gin_app.json  fixtures/express_waf_app.json  fixtures/flask_ratelimit_app.json
    fixtures/graphql_auth_app.json  fixtures/microservices_app.json  fixtures/aspnet_app.json

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

`crates/orchestrator/tests/docker_integration.rs` — 34 tests (28 Docker + 6 ground truth unit tests) gated behind `AEGIS_INTEGRATION_TESTS=1`:
- **8 Express tests**: E2E ground truth, full scan ground truth, OpenAPI discovery, source recon, ModSecurity bypass, rate limit stealth, bot detect evasion, full defense
- **4 Flask tests**: E2E ground truth, full scan ground truth, SSTI detection, source recon
- **4 GraphQL tests**: E2E ground truth, introspection discovery, fallback (no-introspection), auth bypass
- **4 Cross-scan tests**: checkpoint resume, diff-mode SARIF, graph persistence, scan history adaptive selection
- **3 Report format tests**: developer SARIF, security ATT&CK, executive summary
- **3 Stealth mode tests**: default, aggressive, paranoid
- **2 Audit trail tests**: full scan integrity, replay matches scan results
- **6 Ground truth unit tests**: comparison metrics, empty sets, fixture parsing (no Docker required)

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
- **EvidenceLevel** — 4-variant enum: Statistical, Controlled (renamed from Counterfactual, `#[serde(alias = "Counterfactual")]` for backwards compat), Confirmed, Chained. Tracks how strongly a finding is supported.
- **GraphOperation** — AddNode, AddEdge, UpdateWeight, AddFinding. Applied via `KnowledgeGraph::apply_operations(&[OperationLogEntry])`. All public methods return `Result<T, GraphError>`.
- **FuzzRequest / FuzzResponse** — Shared HTTP types in protocol crate. Re-exported by fuzzing crate for backwards compatibility.
- **DefenseContext** — Abstract defense posture in protocol crate: has_waf, waf_vendor, waf_blocked_categories, rate_limit_rps, bot_detection_present/evaded.
- **FuzzTarget** — endpoint + method + parameter + vulnerability_class + priority. Scheduler uses BinaryHeap.
- **MutationOrigin** — 5-variant enum: Template, Generative, BitFlip, Boundary, BypassCorpus. Tags payloads with their generation strategy.
- **TaggedPayload** — payload + origin. Returned by `generate_tagged_payloads()`.
- **DefenseProfile** — Optional WAF/rate-limit/bot-detection profiles. Builder pattern with `with_*` methods.
- **StealthConfig** — 4 presets: `default()`, `aggressive()`, `paranoid()`, `benchmark()`. Builder pattern with `with_*` methods.
- **PersonaId** — 10 variants: ChromeDesktop, FirefoxDesktop, SafariDesktop, ChromeMobile, Googlebot, EdgeDesktop, OperaDesktop, SafariMobile, CurlClient, PythonRequests. Persona rotation supported.
- **Confidence** — Newtype wrapper over `f64` enforcing `[0.0, 1.0]` range and finiteness. `Confidence::new(v)` validates, `Confidence::from_evidence(level)` maps `EvidenceLevel` to default score. Implements `Serialize` (as f64), `Deserialize` (tolerant: invalid→default 0.5), `Display`.
- **FindingConfidence** — Provenance-tracked confidence: `prior` (base rate), `likelihood_ratio` (evidence strength), `methodology_reliability` (test method trustworthiness), `composite: Confidence` (combined score). `FindingConfidence::compute(prior, lr, reliability)` clamps product to [0,1]. `FindingConfidence::from_simple(confidence)` wraps legacy scalar values. `FindingData.confidence` is now `FindingConfidence`, not raw `Confidence`.
- **PhaseError** — Structured error enum for pipeline phases: Graph, Io, Serialization, Checkpoint, ReportFormat, UnknownExportFormat, FilesystemWalk. Implements `std::error::Error` with `source()`. Replaces `Result<T, String>` in all phase functions.
- **ScanPreset** — 4-variant enum: Quick (1 iter, no LLM), Thorough (3 iter, LLM, convergence=2), Paranoid (5 iter, paranoid stealth), Benchmark (1 iter, LLM, auto graph-db). Applied via `--preset` / `-p` flag; explicit CLI flags override preset defaults.
- **SarifFinding** — input struct for SARIF emission. Includes optional `defense_context`, `vulnerability_class`, `evidence_level`, `cve_id`, `mitigation_rank`.
- **MitigationResult** — Result of graph-theoretic mitigation impact estimate: removed_findings, findings_remaining, impact_score.
- **FindingOrigin** — 3-variant enum: LlmHypothesis, StaticRule, Mutation. Tags fuzz findings by origin.
- **FuzzPhaseResult** — Wraps PhaseResult + origin_counts + discovered_endpoints.
- **GraphMetadata** — Scan metadata for graph persistence: scan_timestamp_unix_ms, target_url, aegis_version.
- **PhaseTimings / LlmMetrics / ScanMetrics** — Per-phase timing and LLM call tracking in scan pipeline.
- **VarianceReport** — Endpoint response variance measurement: response_codes, body_similarity, is_deterministic.
- **LlmBackend** — (Python) Abstract base class for LLM providers. Implementations: BedrockClient, OpenAiClient.
- **CalibrationBin / CalibrationReport** — (Python) Confidence calibration in `calibration.py`: histogram binning with `mean_confidence`, `actual_positive_rate`, `calibration_error` per bin. `CalibrationReport` includes bins, ECE, overconfident/underconfident ranges, temperature parameters `(a, b)`.
- **_consistency_key / generate_with_consistency** — (Python) Self-consistency in `generator.py`: `_consistency_key(h)` extracts `(vulnerability_class, endpoint)` tuple; `generate_with_consistency(ctx, rounds, threshold)` runs N generations, filters by agreement ratio, and uses **median confidence** (not max) across agreeing rounds to eliminate upward bias.
- **AuditWriter** — Trait with `append_event_full(&mut self, event) -> Result<AuditEntry, LogWriterError>` (required), `append_event()` (default impl delegates to full and discards entry), and `sequence_number(&self) -> u64`. Implemented by `AuditLogWriter` (persists to disk) and `NoOpAuditLogWriter` (returns synthetic entries with zeroed hashes). Pipeline uses `Box<dyn AuditWriter>`. No downcasting needed to access full entries.
- **NoOpAuditLogWriter** — Implements `AuditWriter`; intentionally discards all events. Used when `--no-audit` is set.
- **AuditLogWriter::append_event_full()** — Returns `Result<AuditEntry, LogWriterError>` with full hash chain/HMAC data. Use when caller needs the entry metadata (e.g. verification tests). The trait method `append_event()` delegates to this but discards the entry.
- **CertificateType** — 6 variants: Fuzzing, Taint, Chain, Config, Dependency, Evasion. Envelope versioned (current: v2).
- **BusinessContext** — JSON-loadable business annotations: excluded_endpoints, critical_assets, pii_endpoints, known_issues.
- **TokenUsage** — Pydantic model tracking input_tokens, output_tokens, and latency_ms from LLM API calls.
- **ScanContextIpc / HypothesisIpc / DefenseContextIpc** — Canonical IPC types in `protocol::hypothesis_ipc` for the Python-Rust bridge boundary. Matching Pydantic models in `hypothesis_engine.ipc_types`. `BridgeRequest` and `BridgeResponse` are serde internally-tagged enums. Orchestrator re-exports as type aliases (`ScanContextJson = ScanContextIpc`, etc.).
- **GenerationResult** — (Python) Extended with `parsing_method: str` ("xml_tags", "bracket_json", "single_object_wrapped", "failed") and `latency_ms: float` for LLM degradation monitoring.
- **should_recalibrate / fit_temperature_scaling_cv** — (Python) Recalibration gate in `calibration.py`: detects model changes, runs cross-validated temperature scaling against ground truth fixtures, computes ECE.
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
- **UpdateDbArgs / UpdateDbSummary / UpdateDbError** — `update-db` CLI subcommand types. Args: `db_path`, `source_dir`, `full_refresh`. Summary: `new_records`, `total_records`, `packages_queried`. Error: MissingArg, Http, Database, Io, NoPackagesFound.
- **OsvBatchResponse / OsvVulnerability / OsvAffected / OsvRange / OsvEvent** — OSV API response deserialization types (private to `update_db` module). Batch response contains per-package vulnerability lists with affected version ranges.

## LLM Configuration

- **Backends:** Pluggable via `LlmBackend` ABC and `create_backend()` factory.
  - `bedrock` (default): AWS Bedrock with `global.anthropic.claude-sonnet-4-6`
  - `openai`: OpenAI-compatible API (also works with vLLM, any OpenAI-compatible server)
  - `ollama`: Local ollama via OpenAI-compatible API at `http://localhost:11434/v1`
- **AWS Profile:** `None` (uses default credentials chain — env vars, `~/.aws/credentials`, instance profile). Pass `aws_profile="ziya"` explicitly if needed.
- **SDK:** boto3 (Bedrock), urllib.request (OpenAI/ollama — no extra dependencies)
- **Retry:** exponential backoff, 3 retries (1s/2s/4s). **Timeout:** 120s per call.
- **Token tracking:** `invoke()` returns `(text, TokenUsage)` tuple. `GenerationResult` includes `input_tokens` and `output_tokens`.
- **XML-structured prompts:** All prompts (generator, compiler, evasion) use XML tags (`<role>`, `<task>`, `<instructions>`, `<constraints>`, `<output_format>`) for semantic boundaries. Responses parsed via `<hypotheses>`, `<test_specs>`, `<evasion_payloads>` tags with bracket-based fallback.
- **Chain-of-thought:** System prompt instructs `<thinking>` tags for step-by-step reasoning before JSON output. `reasoning_trace` captured in `GenerationResult`.
- **Confidence rubric:** 4-tier rubric in system prompt (0.9-1.0 structural evidence, 0.7-0.8 moderate, 0.4-0.6 speculative, 0.1-0.3 low). Enforced by `<constraints>` section.
- **Few-shot examples:** 3 graded examples (high/moderate/low confidence) in hypothesis generation system prompt demonstrating the rubric.
- **Self-consistency:** `generate_with_consistency()` runs N rounds, filters by agreement threshold, keeps highest-confidence version per (vulnerability_class, endpoint) key.
- **Confidence calibration (Python):** `calibration.py` — histogram binning, sigmoid temperature scaling via gradient descent on log loss, ECE computation, overconfident/underconfident range detection.
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
- SQLite for vuln database — persistent file (`~/.aegis/vuln.db`) populated by `update-db` subcommand via OSV API; falls back gracefully when DB doesn't exist; bundled C library via rusqlite
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
- Confidence newtype — `Confidence` wraps `f64` with `[0.0, 1.0]` validation; `FindingData.confidence` is always present (no Option); `Confidence::from_evidence()` maps `EvidenceLevel` to default score; custom `Deserialize` handles legacy `confidence_score` field for backwards compatibility
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
- Dependency-driven OSV vulnerability queries — `update-db` parses lockfiles from `--source-dir` to extract `(package, ecosystem)` tuples, batch-queries `https://api.osv.dev/v1/querybatch` (up to 1000 per request), converts to `VulnerabilityRecord` rows with `INSERT OR IGNORE` deduplication; targeted approach avoids downloading entire vulnerability databases
- Uncertainty quantification (Python) — structural evidence pattern detection ("input flows to", "no validation", "concatenated into sql", "graph shows") vs speculative pattern detection ("commonly vulnerable", "technology stack suggests", "default configuration") in LLM reasoning traces; formula: `structural / (structural + speculative)`; replaces prior hedging/confidence word-counting approach
- XML-structured prompts — all LLM prompts use semantic XML tags (`<role>`, `<task>`, `<constraints>`, `<output_format>`, etc.) to prevent instruction bleed between sections; response extraction tries XML tags first (`<hypotheses>`, `<test_specs>`, `<evasion_payloads>`) with bracket-based JSON fallback for robustness
- Confidence calibration (Python) — `calibration.py` provides sigmoid temperature scaling `sigmoid(a*raw + b)` fit via gradient descent on log loss; `CalibrationReport` with ECE, overconfident/underconfident range detection; complements Rust-side `CalibrationReport` in orchestrator
- Self-consistency generation — `generate_with_consistency()` runs N independent hypothesis rounds and filters by `(vulnerability_class, endpoint)` agreement ratio; keeps highest-confidence version per key; mitigates single-generation sampling variance for high-stakes hypotheses
- Golden fixture evaluation — `tests/fixtures/` contains ground truth scan contexts + golden hypotheses for express/flask/graphql apps; `compute_hypothesis_metrics()` computes precision/recall/F1; enables regression testing of prompt quality without live LLM calls
- Prompt regression tests — `test_prompt_regression.py` validates XML structure, all 16 vulnerability classes present, confidence rubric, constraints, and output format in system prompts; prevents accidental prompt degradation
- LLM delta measurement — `test_llm_delta.py` defines static baseline (vulnerability classes discoverable without LLM) per fixture app; validates golden hypotheses exceed the baseline, quantifying LLM value-add

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
- `parse_hypotheses_from_response()` returns `(str, list[Hypothesis])` tuple — reasoning trace is the first element; tries `<thinking>` + `<hypotheses>` XML tags first, falls back to bracket-based JSON extraction
- KnowledgeGraph methods return `Result` — `GraphError::LockPoisoned` removed (parking_lot doesn't poison); `GraphError::Io` added for persistence errors
- `OperationLog::new()` defaults to relaxed sequencing — use `new_strict()` for gap detection
- Adding new `NodeType` or `EdgeLabel` variants requires updating `is_valid_edge()` whitelist AND the exhaustive coverage test in `protocol_test.rs`
- `FindingData.confidence` is `FindingConfidence` (not raw `f64` or `Confidence`) — access composite score via `.confidence.composite.value()`; provenance components via `.confidence.prior`, `.confidence.likelihood_ratio`, `.confidence.methodology_reliability`; construction via `FindingConfidence::compute(prior, lr, reliability)` or `FindingConfidence::from_simple(confidence)` for legacy wrapping; custom `Deserialize` handles legacy `confidence_score`, scalar `confidence`, and full `FindingConfidence` JSON objects
- `EvidenceLevel::Controlled` (renamed from `Counterfactual`) — `#[serde(alias = "Counterfactual")]` for backwards compat; the anomaly oracle still uses "counterfactual" in method names (e.g., `CounterfactualOrder`) to describe the testing methodology, which is distinct from the evidence level variant name
- `PhaseError` replaces `Result<T, String>` in all phase functions — match on variants: `Graph(GraphError)`, `Io(io::Error)`, `Serialization(serde_json::Error)`, `Checkpoint(CheckpointError)`, `ReportFormat(String)`, `UnknownExportFormat(String)`, `FilesystemWalk(String)`
- `parse_hypotheses_from_response()` now returns 3-tuple `(str, list[Hypothesis], str)` — third element is `parsing_method` ("xml_tags", "bracket_json", "single_object_wrapped", "failed"); emits `RuntimeWarning` on fallback
- `ScanContextJson` (type alias for `ScanContextIpc`) has `class_confirmation_rates: HashMap<String, f64>` and `model_id: Option<String>` — populated from scan history in `build_hypothesis_context()`; injected as `<prior_performance>` XML section in LLM prompts
- `FeedbackManager` accepts optional `historical_rates` parameter — blends 50/50 with `DEFAULT_CLASS_THRESHOLDS`; `from_history()` classmethod maps rates to adjusted thresholds
- Endpoint similarity now uses positional TF-IDF + character trigram Jaccard — final similarity = `0.7 * positional_cosine + 0.3 * trigram_jaccard`; earlier path tokens weighted higher via `1.0 / (1.0 + position)`
- `run_fuzz()` returns `FuzzPhaseResult` (not `PhaseResult`) — access phase data via `.phase` field
- `run_report()` takes optional `&ScanMetrics` parameter — pass `None` when metrics not needed
- `HypothesisGenerator` uses composition (not inheritance) — accepts `client: LlmBackend` parameter; `create_backend()` factory for backend selection
- `OpenAiClient` uses `urllib.request` (no openai SDK dependency) — supports custom `base_url` for ollama/vLLM
- `KnowledgeGraph::save_to_file()` takes `&GraphMetadata` — caller provides metadata at save time
- `KnowledgeGraph::load_from_file()` returns fresh `OperationLog` — operation history not persisted, only store state
- Stores (`NodeStore`, `EdgeStore`, `FindingStore`) serialize full struct including index HashMaps — indexes are redundant with Vec data but ensures correctness on restore
- `run_recon_standalone(source_dir, vuln_db_path)` in `phase_recon.rs` — standalone entry point returning `Vec<OperationLogEntry>` without requiring a `ScanContext`; second arg is `Option<&Path>` for vuln DB (pass `None` to use `~/.aegis/vuln.db` default); near-duplicate of `collect_recon_ops` in `pipeline.rs`
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
- `uncertainty.py` uses `STRUCTURAL_EVIDENCE_PATTERNS` and `SPECULATIVE_PATTERNS` (not the old `HEDGING_PATTERNS`/`CONFIDENCE_PATTERNS`) — tests must use structural evidence language ("input flows to", "no validation") not hedging words ("might", "possibly")
- `generate_with_consistency()` returns a standard `GenerationResult` — token counts are cumulative across all N rounds; `call_count` on backend reflects total invocations
- `calibration.py` `apply_calibration(raw, a, b)` applies `sigmoid(a * raw + b)` — input is raw logit/score not probability; `apply_calibration(0.0, 1.0, 0.0)` gives 0.5 (sigmoid of zero)
- `fit_temperature_scaling()` returns `(1.0, 0.0)` identity when no data in bins — gradient descent only runs with >= 1 total prediction
- Golden fixtures in `tests/fixtures/` contain `scan_context`, `ground_truth`, and `golden_hypotheses` keys — `golden_hypotheses` are hand-crafted ideal outputs, not recorded LLM responses
- `compute_hypothesis_metrics()` matches hypotheses to ground truth via `(endpoint_substring, vulnerability_class)` — hypothesis `condition` must contain the endpoint path as a substring
- Python test suite runs from two directories: `src/hypothesis_engine/` (unit tests) + `tests/` (integration/evaluation) — both must be included in pytest invocation
- `compiler.py` parses `<test_specs>` XML tags first, falls back to bracket JSON — same pattern as generator and evasion_mode
- `evasion_mode.py` parses `<evasion_payloads>` XML tags first, falls back to bracket JSON — `_build_system_prompt()` injects `<bypass_examples>` only when corpus has relevant entries
- `update_db` uses `reqwest::blocking::Client` (not async) — runs before tokio runtime; 3 retries with exponential backoff (2s/4s/8s); 120s timeout per batch request
- `vuln_lookup()` now takes 3 args `(deps, seq, vuln_db_path)` — third arg is `Option<&Path>`; when `None`, falls back to `~/.aegis/vuln.db` if it exists, otherwise returns empty (no findings)
- `Ecosystem` derives `PartialOrd, Ord` — required for sorting `(String, Ecosystem)` tuples in `update_db::run_update_db`; variant order follows enum declaration order
- `--vuln-db` CLI flag on `ScopeOptions` — overrides default `~/.aegis/vuln.db` path; passed through `ctx.config.scope.vuln_db` to `vuln_lookup`
- `update-db` subcommand dispatched before clap parsing — same pattern as `recon` and `attest` subcommands; `if args[1] == "update-db"` in main.rs
- OSV version range sentinel `"999999.0.0"` — used when an `introduced` event has no corresponding `fixed` or `last_affected` event; indicates vulnerability is still unfixed
