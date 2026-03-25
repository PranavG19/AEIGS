# AEGIS — Autonomous Adversarial Intelligence Platform

18 Rust crates + 1 Python package. **1,489 Rust files. ~24,601 tests. 0 clippy warnings.**
200+ attack modules. 105+ evasion techniques. 1,000+ payload templates. LLM-powered autonomous agent brain.

## Commands

```bash
cargo test --workspace                                              # all Rust tests
cargo clippy --workspace -- -D warnings                            # zero warnings
cargo fmt --all --check                                            # formatting gate
cd hypothesis-engine && uv run pytest src/hypothesis_engine/ tests/ -v
AEGIS_INTEGRATION_TESTS=1 cargo test -p aegis-orchestrator \
  --test docker_integration -- --test-threads=1                   # 34 Docker tests (needs Docker/Colima)
```

Subcommands dispatched before clap: `recon`, `attest`, `update-db` (via `args[1]` check in main.rs).
`proxy` subcommand prints redirect message to `aegis-proxy-tui` binary.

## Architecture

```
protocol          shared types: NodeType, EdgeLabel, VulnerabilityClass, GraphOperation,
                  FuzzRequest/Response, EvidenceLevel, DefenseContext, ScanEvent, scope/config signing
knowledge-graph   arena Vec storage + parking_lot::RwLock<Inner>; semantic edge validation,
                  weight/score bounds, dup edge detection, JSON persistence, GraphStore trait
  ├─ audit-log         SHA3-256 hash-chain + HMAC + CBOR; event sourcing (replay/snapshot/diff)
  │    └─ supervisor   process lifecycle + capability tokens
  ├─ passive-recon     cargo-lock parsing, SQLite vuln DB (OSV), filesystem walk
  ├─ enumeration       OpenAPI/GraphQL route discovery, auth matrix, fallback GraphQL, auth flow
  ├─ crawler           BFS web crawler; DiscoveredEndpoint/Form/Parameter extraction;
  │                    optional headless browser (feature="browser"), Katana wrapper (feature="katana"); localhost-only
  ├─ fuzzing           priority scheduler (UCB1), tagged mutation, stealth, WAF/rate-limit/bot detect
  │                    (merged from defense-fingerprinting), streaming fuzzer, counterfactual oracle
  ├─ chain-synthesis   petgraph DiGraph attack graph; paths, centrality, mitigation impact, DOT export
  ├─ reporting         SARIF 2.1.0 (CWE+ATT&CK), CBOR certs, risk scoring, Developer/Security/Executive
  ├─ evasion-engine    10 personas, header/encoding transforms, timing jitter, JA3 TLS fingerprints
  ├─ discovery         dir brute-force (2013 paths), JS extraction, sitemap/robots, backup scanner,
  │                    tech fingerprinting, param discovery (67), vhost discovery (31), SecLists loading
  ├─ exploiter         SQLMap, Nuclei, Nmap, Subfinder, Interactsh, Httpx, Gau, Feroxbuster,
  │                    Trufflehog, Dalfox, Amass wrappers; native JWT tester
  ├─ compliance        CVSS 3.1, OWASP Top10 2021, API Security 2023, PCI-DSS, CWE mapping, report gen
  ├─ proxy             hyper recording proxy, repeater, intruder (Sniper/BatteringRam/Pitchfork/ClusterBomb),
  │                    graph sync, diff, grep, modification, payload, persistence, session, scope
  ├─ proxy-tui         ratatui TUI binary (aegis-proxy-tui); 6 tabs: Proxy/Repeater/Intruder/Scope/
  │                    Payloads/Comparer; graph import, keybinds
  ├─ test-support      shared test infra: MockGraphStore, MockFuzzTransport, VulnerableAppBuilder,
  │                    TestServer, fixture_data, fixture_server, assertions, temp_workspace
  └─ orchestrator      CLI binary; pipeline: recon→crawl→fingerprint→(fuzz→analyze)*→dom_verify→report
                       subcommands: recon, attest, update-db; phases + actors + all coordination
hypothesis-engine (Python) LLM hypothesis gen (Bedrock/OpenAI/ollama), XML prompts, calibration,
                           self-consistency, uncertainty quant, golden fixture eval
```

## Code Organization

```
crates/protocol/src/         node.rs edge.rs finding.rs operation.rs audit.rs capability.rs
                             ipc.rs hypothesis_ipc.rs target_validation.rs request.rs
                             defense_context.rs scope_attestation.rs signed_config.rs scan_event.rs
crates/knowledge-graph/src/  node_store.rs edge_store.rs finding_store.rs operation_log.rs graph.rs
                             graph_store.rs query/{path_queries,reachability}.rs
crates/audit-log/src/        hash_chain.rs hmac_signer.rs log_writer.rs log_verifier.rs event_store.rs
crates/supervisor/src/       process_manager.rs capability_manager.rs
crates/passive-recon/src/    dependency_parser.rs vuln_database.rs filesystem_walker.rs
crates/enumeration/src/      route_parser.rs introspection.rs auth_matrix.rs graphql_discovery.rs auth_flow.rs
crates/crawler/src/          crawler.rs page_fetcher.rs types.rs error.rs
                             browser_fetcher.rs dom_verifier.rs  (feature="browser" only)
                             katana_wrapper.rs  (feature="katana" only)
crates/fuzzing/src/          scheduler.rs mutator.rs executor.rs oracle.rs stealth_config.rs
                             defense_profile.rs waf_fingerprinter.rs rate_limit_detector.rs
                             bot_detection_probe.rs streaming_fuzzer.rs request_patterns.rs payload_selector.rs
crates/chain-synthesis/src/  attack_graph.rs path_analysis.rs graph_export.rs
crates/reporting/src/        risk_scorer.rs sarif_emitter.rs certificate_serializer.rs narrative.rs report_format.rs
crates/evasion-engine/src/   persona.rs header_transformer.rs encoding_transformer.rs
                             timing_controller.rs session_manager.rs transport.rs tls_config.rs
crates/discovery/src/        backup_scanner.rs brute_forcer.rs js_extractor.rs param_discoverer.rs
                             sitemap_parser.rs tech_fingerprinter.rs vhost_discoverer.rs wordlist.rs graph_ops.rs
crates/exploiter/src/        checker.rs jwt_tester.rs nmap_wrapper.rs nuclei_wrapper.rs oast_wrapper.rs
                             runner.rs selector.rs sqlmap_wrapper.rs subfinder_wrapper.rs wrapper.rs
                             httpx_wrapper.rs gau_wrapper.rs feroxbuster_wrapper.rs
                             trufflehog_wrapper.rs dalfox_wrapper.rs amass_wrapper.rs
crates/compliance/src/       class_mapper.rs compliance_mapper.rs context_adjuster.rs
                             cvss_scorer.rs report_generator.rs
crates/proxy/src/            proxy.rs repeater.rs intruder.rs graph_sync.rs diff.rs grep.rs
                             modification.rs payload.rs persistence.rs session.rs scope.rs types.rs
crates/proxy-tui/src/        app.rs graph_import.rs keybinds.rs
                             views/{proxy_log,repeater,intruder,scope,payloads,comparer,response}.rs
                             widgets/{table,status_bar,hex_view,diff_view}.rs
crates/test-support/src/     assertions.rs fixture_data.rs fixture_server.rs mock_graph.rs
                             mock_transport.rs temp_workspace.rs vulnerable_app.rs
crates/orchestrator/src/     scan_config.rs pipeline.rs main.rs util.rs
                             phase_{recon,crawl,fingerprint,fuzz,analyze,dom_verify,report,error}.rs
                             actor.rs benchmark.rs calibration.rs checkpoint.rs convergence.rs
                             hypothesis_bridge.rs distributed.rs distributed_transport.rs
                             endpoint_similarity.rs graph_persistence.rs interactive.rs
                             pipeline_composer.rs scan_history.rs scan_strategy.rs
                             telemetry.rs update_db.rs attest.rs auth_session.rs
                             doctor.rs eval.rs idor_analyzer.rs
hypothesis-engine/src/       bedrock_client.py openai_client.py generator.py compiler.py
                             feedback.py evasion_mode.py uncertainty.py calibration.py
                             ipc_types.py bridge.py bypass_examples.json
hypothesis-engine/tests/     test_integration.py test_evaluation.py test_prompt_regression.py
                             test_llm_delta.py fixtures/{express,flask,graphql,...}_app.json (15 fixtures)
```

Every source file has adjacent test: `{module}_test.rs` / `test_{module}.py`.

## Defense Stacks

```
defense-stacks/
  express-vuln-app/   17 endpoints, 16 VulnerabilityClass variants, openapi.json, ground-truth.json
  flask-vuln-app/     8 endpoints: SQLi/XSS/CmdInj/PathTraversal/SSTI/Misconfig/OpenRedirect
  graphql-vuln-app/   Apollo/express-graphql; DISABLE_INTROSPECTION=1 toggle; ground-truth.json
  bot-detection/      Flask; score = ua_score(0.4) + header_score(0.6*present/3); BOT_THRESHOLD=0.5
  modsecurity/        ModSecurity CRS override conf
  compose/            docker-compose.{yml,modsecurity,ratelimit,botdetect,fulldefense,flask,graphql}.yml
```

Docker Tier 2 tests: 28 Docker + 6 ground-truth unit tests across Express(8)/Flask(4)/GraphQL(4)/Cross-scan(4)/Report(3)/Stealth(3)/Audit(2) categories. RAII `DockerCompose` struct, Drop teardown, `--test-threads=1`.

## Key Types

**protocol**
- `VulnerabilityClass` — 34 variants (16+18). Display via human-readable names.
- `NodeType` — 9 variants incl `Defense`. `EdgeLabel` — 8 variants incl `ProtectedBy`. Both impl Display.
- `is_valid_edge(src,lbl,tgt)` — whitelist of 28 valid (NodeType,EdgeLabel,NodeType) triples.
- `EvidenceLevel` — Statistical|Controlled(alias="Counterfactual")|Confirmed|Chained.
- `GraphOperation` — AddNode|AddEdge|UpdateWeight|AddFinding. Applied via `apply_operations(&[OperationLogEntry])`.
- `FuzzRequest/FuzzResponse` — shared HTTP types; re-exported by fuzzing for compat.
- `DefenseContext` — has_waf, waf_vendor, waf_blocked_categories, rate_limit_rps, bot_detection_present/evaded.
- `ScanEvent` — typed event enum for inter-module bus (EndpointDiscovered, HypothesisGenerated, etc.).
- `ScopeDocument/SignedScopeAttestation` — Ed25519-signed auth docs; verified via `verify_attestation()`.
- `SignableConfig/SignedConfig` — Ed25519-signed scan config with SHA3-256 hash.

**knowledge-graph**
- `KnowledgeGraph` — `parking_lot::RwLock<Inner>`, upgradable read lock for atomic validate→apply.
- `GraphStore` — trait abstracting KG access; `Send+Sync`; tests inject `MockGraphStore`.
- `GraphMetadata` — scan_timestamp_unix_ms, target_url, aegis_version. Required for `save_to_file()`.
- `EventQuery/ScanSnapshot/SnapshotDiff` — event sourcing replay types.

**fuzzing**
- `FuzzTarget` — endpoint+method+parameter+vulnerability_class+priority. Scheduler uses BinaryHeap.
- `TaggedPayload/MutationOrigin` — payload tagged with Template|Generative|BitFlip|Boundary|BypassCorpus.
- `DefenseProfile` — optional WAF/rate-limit/bot-detect. Builder `with_*`.
- `StealthConfig` — 4 presets: default/aggressive/paranoid/benchmark. Builder `with_*`.
- `PayloadSelector` — UCB1 bandit; novel payloads get `f64::INFINITY` priority.
- `StreamProtocol/StreamFuzzTarget/StreamFuzzResult` — WebSocket/SSE streaming fuzzer.
- `BrowsingPattern/RequestBatch/CoverTrafficConfig` — Sequential|BurstThenPause|ParallelResources|NavigationChain. MAX_BATCH_SIZE=64.

**evasion-engine**
- `PersonaId` — 10 variants: ChromeDesktop/FirefoxDesktop/SafariDesktop/ChromeMobile/Googlebot/EdgeDesktop/OperaDesktop/SafariMobile/CurlClient/PythonRequests.
- `TlsFingerprint` — Chrome120|Firefox121|Safari17|Edge120|Curl|Default. Chrome120+Edge120 share Chromium JA3.
- `HttpClientBackend` — Reqwest|Rquest. `TlsConfig/HttpClientConfig` builder pattern.

**orchestrator**
- `ScanConfig` — full CLI config; groups: StealthOptions, PipelineOptions, LlmOptions, AuditOptions, AuthOptions, DistributedOptions, ScopeOptions. Includes `--dalfox-blind-xss`, `--amass-active`.
- `PipelineOptions` includes `--headless-crawl`. `ScopeOptions` includes `--seclists-path`.
- `ScanPreset` — Quick(1iter,no-LLM)|Thorough(3iter,LLM,conv=2)|Paranoid(5iter)|Benchmark. `--preset/-p`.
- `PhaseError` — Graph|Io|Serialization|Checkpoint|ReportFormat|UnknownExportFormat|FilesystemWalk.
- `ScanCheckpoint` — serializable progress for resume; deleted on success; requires `--graph-db`.
- `PipelineStage/PipelineDefinition/PhaseType` — declarative pipeline, topological Kahn sort.
- `DistributedConfig/CoordinatorState/WorkAssignment` — RoundRobin|PriorityBased|VulnerabilityClass partitioning.
- `CoordinatorMessage/WorkerMessage/TransportEnvelope/Coordinator/Worker` — in `distributed_transport.rs` (separate from `distributed.rs`).
- `ScanStrategy/ScanState/StrategyAction/DiscoveryType` — adaptive strategy engine.
- `DomVerifyOutcome` — per-finding DOM verification result with confidence_adjustment.
- `AuthenticatedSession/AuthSessionError` — live auth flow execution; extracts tokens/cookies/headers.
- `DoctorCheck/CheckStatus/DoctorArgs` — system prereqs check (`run_doctor()` → Vec<DoctorCheck>). Checks: feroxbuster, httpx, gau, dalfox, trufflehog, amass, katana.
- `EvalArgs/EvalResult/EvalError` — eval subcommand: runs fixture, compares findings, formats results.
- `AttestArgs/AttestError` — `attest` subcommand for Ed25519 scope attestation file generation.
- `ReportFormat` — Developer(SARIF)|Security(ATT&CK-enriched)|Executive(summary JSON).
- `PhaseTimings/LlmMetrics/ScanMetrics` — per-phase timing + LLM call tracking.
- `GroundTruth/BenchmarkFixture/BenchmarkEvaluation` — ground truth precision/recall/F1.
- `RefutedTracker` — monotonic HashSet; prevents re-testing failed hypotheses across iterations.
- `EndpointSignature` — TF-IDF + char trigram Jaccard; final = 0.7*cosine + 0.3*trigram.
- `ScanHistoryEntry/ScanHistoryRecord` — SQLite per-payload outcomes; cross-scan adaptive selection.
- `TelemetryConfig/TelemetryCollector` — opt-in aggregate only; never raw findings/payloads.
- `InteractiveCommand/InteractiveSession` — pause/resume/status/findings/endpoints/priority/skip/quit. No I/O in module.
- `BusinessContext` — JSON-loadable: excluded_endpoints, critical_assets, pii_endpoints, known_issues.
- `UpdateDbArgs/UpdateDbSummary/UpdateDbError` — OSV batch API vuln DB updater. `--update-wordlists`, `--update-tools` flags.
- `FuzzPhaseResult` — wraps PhaseResult + origin_counts + discovered_endpoints.
- `FindingOrigin` — LlmHypothesis|StaticRule|Mutation.
- `AuditWriter` — trait: `append_event_full()→Result<AuditEntry>`, `append_event()` (discards), `sequence_number()`. `NoOpAuditLogWriter` for `--no-audit`.

**reporting**
- `SarifFinding` — includes optional defense_context, vulnerability_class, evidence_level, cve_id, mitigation_rank.
- `MitigationResult` — removed_findings, findings_remaining, impact_score.
- `CertificateType` — Fuzzing|Taint|Chain|Config|Dependency|Evasion. Envelope v2.

**crawler**
- `Crawler` — BFS; localhost-only; extracts DiscoveredEndpoint/Form/Parameter/DomEventHandler.
- `CrawlConfig` — builder: with_max_depth/max_pages/scope_regex/timeout_secs/wait_after_load_ms.
- `CrawlResult` — discovered_endpoints, forms, intercepted API calls.
- `DiscoverySource/ApiResourceType` — source tagging for crawler findings.

**test-support**
- `MockGraphStore` — in-memory GraphStore impl for tests.
- `MockFuzzTransport` — implements FuzzTransport for unit tests.
- `VulnerableApp/VulnerableAppBuilder/GroundTruth/GroundTruthEntry` — in-process test app with known vulns.
- `TestServer` — wraps fixture_server; exposes test HTTP server.

**compliance**
- CVSS 3.1 (FIRST spec, all 34 classes), OWASP Top10 2021, API Security 2023, PCI-DSS, CWE mapping.

**hypothesis-engine (Python)**
- `LlmBackend` — ABC; `BedrockClient`/`OpenAiClient`; `create_backend("bedrock"|"openai"|"ollama")`.
- `TokenUsage` — input_tokens, output_tokens, latency_ms. `invoke()` returns `(text, TokenUsage)`.
- `GenerationResult` — +parsing_method("xml_tags"|"bracket_json"|"single_object_wrapped"|"failed"), latency_ms.
- `CalibrationBin/CalibrationReport` — histogram bins, ECE, over/underconfident ranges, sigmoid params (a,b).
- `generate_with_consistency(ctx, rounds, threshold)` — N-round agreement filter; median confidence (not max).
- `parse_hypotheses_from_response()` → 3-tuple `(reasoning_trace, hypotheses, parsing_method)`.
- `ScanContextIpc/HypothesisIpc/DefenseContextIpc` — canonical IPC types at Rust-Python boundary.
- Backends: `bedrock`=default(`global.anthropic.claude-sonnet-4-6`); `openai`=OpenAI-compat; `ollama`=localhost:11434.

**confidence**
- `Confidence` — newtype f64 [0,1]; `new(v)` validates; `from_evidence(level)` maps EvidenceLevel→score.
- `FindingConfidence` — prior + likelihood_ratio + methodology_reliability + composite. `compute(p,lr,rel)` or `from_simple(c)`.
- `FindingData.confidence` is `FindingConfidence` (not raw f64). Access composite via `.confidence.composite.value()`.

## Conventions

- No inline comments; names self-document. `///` doc on public types encoding invariants/contracts/threat models.
- One public type per file. Functions ≤40 lines. Enums over strings. Builder `with_*` for configs.
- `lib.rs`/`__init__.py` re-exports only. Test files adjacent: `#[path]` attribute in Rust.
- Commit format: `[component] verb phrase`.

## Design Decisions (key)

- SHA3-256 (not SHA2) for hash chain — structural diversity vs Merkle-Damgard attacks.
- Arena Vec + u64 indices — O(1) lookup, deterministic layout, append-only (no deletion).
- petgraph DiGraph for attack graph — proven correctness, no reimplementation.
- CBOR for certs — ~40% smaller than JSON, self-describing unlike Protobuf.
- defense-fingerprinting merged into fuzzing — eliminated leaf crate with single consumer.
- `FuzzRequest/FuzzResponse` in protocol — avoids backwards dep evasion-engine→fuzzing.
- Counterfactual anomaly oracle — paired control/treatment eliminates false positives from broken endpoints.
- MAX_TOTAL_PATHS=100,000 with priority-bounded DFS — lowest-difficulty edges first, deterministic.
- Concurrent recon+fingerprint via `tokio::join!` — KG thread-safe via RwLock.
- Mandatory audit log by default — scan fails if cannot create; `--no-audit` for explicit opt-out.
- UCB1 bandit for payload selection — C=sqrt(2) exploration; novel payloads = ∞ priority.
- XML-structured prompts — `<role>/<task>/<constraints>/<output_format>`; response parsed via XML first, bracket JSON fallback.
- Self-consistency: `_consistency_key(h)` = `(vulnerability_class, endpoint)`; median confidence across agreeing rounds.
- Confidence calibration: `sigmoid(a*raw + b)` fit via gradient descent on log loss; identity `(1.0, 0.0)` if no data.
- Uncertainty quant: structural_patterns / (structural + speculative); NOT hedging word counting.
- `update-db` batch-queries OSV API from lockfile packages (up to 1000/request); `INSERT OR IGNORE` dedup.
- Endpoint similarity = 0.7 * positional TF-IDF cosine + 0.3 * char trigram Jaccard.
- GraphStore trait — all pipeline phases use trait; enables `MockGraphStore` in tests.
- Atomic validate-then-apply via `RwLockUpgradableReadGuard` — eliminates TOCTOU gap.

## Safety

- Target validation at 3 layers: protocol, evasion-engine transport, fuzzing executor. Localhost/127.0.0.1/::1 only by default.
- `--i-am-authorized` flag for remote scanning; logged to audit trail.
- `--no-llm` flag to skip hypothesis engine (no AWS creds needed).
- AWS profile defaults to `None` (standard credentials chain). Pipeline continues with static fuzzing if Bedrock unavailable.

## Known Pitfalls

- Adding `NodeType`/`EdgeLabel` variants requires updating `is_valid_edge()` whitelist AND exhaustive coverage test in `protocol_test.rs`.
- `FindingData.confidence` is `FindingConfidence` not raw `f64`/`Confidence`. Construct via `compute()` or `from_simple()`.
- `EvidenceLevel::Controlled` (renamed from Counterfactual); `#[serde(alias="Counterfactual")]`. Method names still use "counterfactual" (testing methodology ≠ enum name).
- `PhaseError` replaces `Result<T,String>` in all phase fns — match variants not strings.
- `parse_hypotheses_from_response()` → 3-tuple `(str, list[Hypothesis], str)` — unpack all three.
- `invoke()` → `(str, TokenUsage)` — all callers must unpack both.
- `ScanContextJson` alias for `ScanContextIpc` has `class_confirmation_rates: HashMap<String,f64>` and `model_id: Option<String>`.
- `FeedbackManager` blends 50/50 `historical_rates` with `DEFAULT_CLASS_THRESHOLDS`.
- `run_fuzz()` → `FuzzPhaseResult` not `PhaseResult` — access phase data via `.phase`.
- `run_report()` takes optional `&ScanMetrics` — pass `None` if not needed.
- `KnowledgeGraph::save_to_file()` takes `&GraphMetadata` — caller provides at save time.
- `KnowledgeGraph::load_from_file()` — fresh `OperationLog`; operation history not persisted.
- `OperationLog::new()` = relaxed sequencing; `new_strict()` for gap detection.
- `GraphError::LockPoisoned` removed (parking_lot no poisoning); `GraphError::Io` added.
- `use aegis_fuzzing::DefenseProfile` — not `aegis_defense_fingerprinting` (merged, dir still exists on disk but excluded from workspace).
- `use aegis_evasion_engine::PersonaId` — not `::persona::PersonaId`.
- Intra-batch dup edge detection: `HashSet<(u64,u64,EdgeLabel)>` in `validate_batch()`.
- `FuzzScheduler::enqueue()` clamps non-finite priority to 0.0.
- `sarif_rust` fields are `Option<Vec<...>>` — access via `.as_ref().unwrap()`.
- Chrome120 and Edge120 JA3 hashes are identical (both Chromium).
- `timestamp_ms()` in `util.rs` — import via `crate::util::timestamp_ms`; no duplicates.
- `ScanCheckpoint` requires `--graph-db` for `--resume`; warns + proceeds without checkpointing otherwise.
- Docker fixture apps bind `0.0.0.0` (not 127.0.0.1). Node Alpine healthchecks use `node -e`.
- Flask Dockerfile: `poetry install --only main --no-root` + `POETRY_VIRTUALENVS_CREATE=false` (Poetry 2.x).
- `uncertainty.py` uses `STRUCTURAL_EVIDENCE_PATTERNS`/`SPECULATIVE_PATTERNS` — NOT old `HEDGING_PATTERNS`.
- `apply_calibration(0.0, 1.0, 0.0)` → 0.5 (sigmoid of zero). Input is raw score not probability.
- `compute_hypothesis_metrics()` matches via `(endpoint_substring, vulnerability_class)` — hypothesis `condition` must contain endpoint path.
- `endpoint_filtering` via `filter_scheduler_by_endpoints()` — only call on freshly-enqueued targets (attempts=0).
- `bypass_examples.json` loading: checks `corpus_path.exists()`; emits RuntimeWarning + returns `{}` if missing.
- `--resume` requires `--graph-db`; without it, warns and proceeds without checkpointing.
- `vuln_lookup(deps, seq, vuln_db_path)` — third arg `Option<&Path>`; None → `~/.aegis/vuln.db` fallback.
- `Ecosystem` derives `PartialOrd,Ord` (required for tuple sorting in `update_db`).
- `GraphStore` must be `Send+Sync` for `ScanContext` across async boundaries.
- Gemfile.lock parsing: must track indent level to skip sub-dependencies.
- Express handler extraction: strip trailing `)` and `;`.
- Auth matrix: symmetric 200 responses correctly flagged as anomalies.
- `cargo fmt` reorders imports alphabetically.
- Pydantic models named `Test*` trigger pytest collection warnings (harmless).
- `crates/defense-fingerprinting/` dir still on disk but excluded from workspace members — safe to delete.
- `golden_hypotheses` in `tests/fixtures/` are hand-crafted ideal outputs, not recorded LLM responses.
- Python test suite runs from two dirs: `src/hypothesis_engine/` + `tests/` — both required in pytest invocation.
- `extract_domain()` lives in `subfinder_wrapper.rs` — reused by gau and amass wrappers via `use crate::subfinder_wrapper::extract_domain`.
- Katana wrapper is feature-gated: `#[cfg(feature = "katana")]` in crawler lib.rs and Cargo.toml.
- `KatanaWrapper` is not a `ToolWrapper` impl — it has its own API: `build_command(url, config, headless)`, `parse_output(stdout) → CrawlResult`.
- New exploiter wrappers (httpx/gau/feroxbuster/trufflehog/dalfox/amass) all impl `ToolWrapper` trait from `wrapper.rs`.
- `selector.rs` `preferred_tools()` — order matters: first matching available tool wins. New tools added after existing entries.
