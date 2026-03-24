# AEGIS Workflows and Control Flow

<!-- metadata: scan pipeline, iterative fuzz loop, startup sequence, subcommands, testing strategy, concurrent operations -->

## Startup Sequence

Source: `crates/orchestrator/src/main.rs`

```
1. main() reads std::env::args()
2. Dispatch subcommands BEFORE clap parsing (string matching on args[1]):
   ├── args[1] == "recon"      → run_recon_command() → run_recon_standalone() → exit
   ├── args[1] == "attest"     → run_attest_command() → run_attest() → exit
   └── args[1] == "update-db"  → run_update_db_command() → run_update_db() → exit
3. No special subcommand → ScanConfig::parse_and_apply_preset() (clap parsing)
4. If --verbose: init tracing_subscriber with RUST_LOG env filter
5. run_scan(config).await
6. Print summary or error to stdout/stderr
```

**Note:** Subcommand dispatch uses manual string matching, not clap subcommands. This is by design to run these operations before the tokio runtime is active (recon, update-db use blocking I/O).

---

## Main Scan Pipeline

Source: `crates/orchestrator/src/pipeline.rs::run_scan()`

### Initialization Sequence (run_scan → before phases)

```
1.  Validate stealth level and report format strings (fail fast)
2.  Build TelemetryConfig (enabled only if --telemetry)
3.  Load scope attestation if --scope-attestation
4.  validate_target_with_override() — enforce localhost unless:
    a. scope_attestation.target matches AND not expired
    b. --i-am-authorized flag set (logs warning to audit trail)
5.  Load and verify signed config if --signed-config
    a. Ed25519 signature verify
    b. SHA3-256 content hash verify
    c. Match against actual CLI parameters
6.  Create audit writer:
    a. --no-audit → NoOpAuditLogWriter (discards all events)
    b. default → AuditLogWriter at {output_dir}/aegis-audit.cbor
    c. Generate random 32-byte HMAC key, save to {output_dir}/aegis-audit.key
7.  Emit AuditEventType::ScanStarted
8.  Record telemetry scan_start
9.  If --i-am-authorized: emit audit KeyEvent
10. If --signed-config: emit audit KeyEvent with config hash
11. load_or_create_graph(--graph-db path)
    a. If graph-db exists: KnowledgeGraph::load_from_file() + capture previous findings
    b. Else: KnowledgeGraph::new() (empty graph)
12. Load checkpoint if --resume AND --graph-db
13. Create CapabilityManager with random 32-byte master key
14. Register least-privilege module permission policies (5 modules)
15. Load auth flow if --auth-flow
16. Spawn interactive stdin reader thread if --interactive
17. Build ScanContext (graph, capabilities, refuted tracker, auth flow, etc.)
18. Call run_scan_phases(ctx, ...)
19. save_graph_if_configured (save to --graph-db if configured)
20. delete_checkpoint on success
21. Record and export telemetry
22. Verify audit log integrity (SHA3-256 chain + HMAC check)
23. Return ScanSummary
```

---

### Phase Execution Order (run_scan_phases)

```
Pipeline DAG (declared, then validated via Kahn's topological sort):

 [recon] ─┐
           ├──► [fingerprint] ──► [fuzz:0] ──► [analyze:0] ──► [dom_verify] ──► [report]
 [crawl] ─┘                        │           [dom_verify] ─────────────────────────┘
                                    ▼
                          [analyze:0, analyze:1, ...]
                            (iterations repeat)
```

**IMPORTANT:** The declarative DAG is validated but execution is still sequential. Parallelism is modeled for future use.

**Actual execution order:**

```
1. RECON phase
   - run_recon_standalone(--source-dir, --vuln-db)
   - Parses lock files, queries SQLite vuln DB
   - Produces OperationLogEntry[] → graph.apply_operations()

2. CRAWL phase
   - Currently uses CrawlResult::default() (empty — crawler not wired into live scan)
   - crawl_result_to_operations() converts to graph ops

3. FINGERPRINT phase (skippable via --skip-fingerprint)
   - concurrent sub-steps:
     a. probe_defenses() → DefenseProfile (WAF/rate-limit/bot detection via HTTP probes)
     b. discover_openapi_endpoints_http() → try /openapi.json, /swagger.json, /api-docs
     c. If no OpenAPI: discover_openapi_endpoints_source() from --source-dir
     d. discover_graphql_endpoints_http() → try /graphql, /api/graphql
     e. If still empty: discover_routes_from_source() (regex on source files)
   - apply_stealth_adjustments() based on defense profile
   - Adds Defense node + discovered Endpoint nodes to graph

4. FUZZ→ANALYZE LOOP (0..max_iterations)
   For each iteration:

   4a. FUZZ phase
       - run_fuzz(ctx, transport) → FuzzPhaseResult
       - FuzzScheduler (UCB1/BinaryHeap) dequeues FuzzTargets
       - Generates tagged payloads (Template/Generative/BitFlip/Boundary/BypassCorpus)
       - Executes requests via EvasionTransport (persona rotation, jitter, header transforms)
       - Counterfactual oracle: paired control/treatment requests
       - Anomaly detection → FindingData → graph.apply_operations()

   4b. Record refuted payloads (zero-finding LLM payloads → RefutedTracker)

   4c. LLM HYPOTHESIS STEP (if --no-llm not set)
       - build_hypothesis_context() from graph (tech stack, findings, history rates)
       - bridge.generate_hypotheses(scan_context, feedback_summary)
         → Python subprocess via Unix domain socket (length-prefixed JSON)
       - bridge.compile_payloads(hypotheses)
         → Python subprocess compile
       - dedup_and_filter_payloads() against RefutedTracker
       - Store in ctx.llm_payloads for next fuzz iteration

   4d. ANALYZE phase
       - run_analyze(ctx) → PhaseResult
       - Builds attack graph from knowledge graph (petgraph DiGraph)
       - Runs path analysis, centrality, defense gap analysis
       - Adds chain-synthesis findings back to graph

   4e. CONVERGENCE CHECK
       - If fuzz_findings == 0 AND analyze_findings == 0:
           consecutive_zero_findings++
       - Else: consecutive_zero_findings = 0
       - If consecutive_zero_findings >= convergence_threshold: break loop

   4f. Save checkpoint after each iteration

5. DOM VERIFY phase
   - run_dom_verify(ctx) → PhaseResult
   - Verifies XSS findings via DOM execution

6. REPORT phase
   - run_report_with_previous(ctx, metrics, previous_findings)
   - Risk scoring, SARIF generation, diff against previous scan
   - Optional: export_attack_graph() if --export-graph
```

---

## Checkpoint Resume Flow

Source: `crates/orchestrator/src/checkpoint.rs`

```
On scan start with --resume --graph-db:
  1. load_checkpoint(db_path) → Option<ScanCheckpoint>
  2. ScanCheckpoint contains: completed_phases[], current_iteration, total_ops, total_findings, consecutive_zero_findings

At each phase gate:
  - should_skip_phase(checkpoint, "recon") → true if "recon" in completed_phases

On checkpoint save (try_save_checkpoint):
  - After each phase completion
  - After each fuzz-analyze iteration
  - Serializes ScanCheckpoint to JSON alongside graph-db path

On successful scan completion:
  - delete_checkpoint(db_path) — presence of checkpoint file = interrupted scan
```

---

## Interactive Mode

Source: `crates/orchestrator/src/interactive.rs`, `pipeline.rs`

```
Activation: --interactive flag

Architecture: Dedicated OS thread (not Tokio task) reads stdin
  - Thread name: "interactive-stdin"
  - Reads lines → parse_command() → session.handle_command()
  - Uses std::sync::Mutex<InteractiveSession> (not tokio::Mutex)

At each phase gate (interactive_gate):
  1. Check should_quit() → Err(PipelineError::InteractiveQuit)
  2. Check is_paused() → spin-wait (100ms sleep) until resumed or quit
  3. Check should_skip_phase() → skip current phase
  4. Enter phase: set_current_phase(), set_elapsed_ms()

Available commands:
  pause    → is_paused = true
  resume   → is_paused = false
  status   → StatusReport (phase, elapsed, findings count, endpoint count, iteration)
  findings → FindingsList (id, endpoint, vuln class, severity, confidence)
  endpoints → EndpointsList (all discovered endpoint paths)
  priority <class> → set priority for vuln class in next fuzz iteration
  skip     → skip current phase (sets skip flag, cleared after read)
  quit     → should_quit = true → PipelineError::InteractiveQuit
  help     → list available commands
```

---

## Hypothesis Bridge (LLM Integration)

Source: `crates/orchestrator/src/hypothesis_bridge.rs`

```
Lifecycle:
  1. HypothesisBridge::start(python_cmd)
     - Creates Unix socket at /tmp/aegis-hypothesis-{pid}-{timestamp}.sock
     - Spawns: {python_cmd} -m hypothesis_engine.bridge --socket <path>
     - Waits for BridgeResponse::Ready (10s handshake timeout)

  2. generate_hypotheses(scan_context, target_description, feedback_summary)
     Transport: Unix domain socket, 4-byte LE u32 length prefix + JSON payload (max 64 MiB)
     → write_ipc_frame(BridgeRequest::GenerateHypotheses {request_id, scan_context, ...})
     ← read_ipc_frame() → BridgeResponse::Hypotheses {hypotheses, reasoning_trace, tokens}
     Timeout: 120s per request

  3. compile_payloads(hypotheses)
     → write_ipc_frame(BridgeRequest::CompilePayloads {request_id, hypotheses})
     ← BridgeResponse::CompiledPayloads {payloads, input_tokens, output_tokens}
     Timeout: 120s per request

  4. Drop (RAII):
     - Socket file deleted from /tmp/
     - Python subprocess receives EOF or Shutdown request → exits
     - 2s grace period → SIGKILL if process hasn't exited

ScanContextJson (IPC type):
  - technology_stack: Vec<String>  (from Dependency nodes in graph)
  - findings_summary: Vec<String>  (VulnerabilityClass display names)
  - high_centrality_nodes: Vec<String>  (empty in current impl)
  - defense_posture: serde_json::Value
  - class_confirmation_rates: HashMap<String, f64>  (from scan history DB)
  - model_id: Option<String>
```

---

## Subcommand Workflows

### `aegis recon --source-dir /path`

```
1. parse source dir from args (simple string matching, no clap)
2. run_recon_standalone(source_dir, None)
3. Walks directory → classifies files → parses lock files
4. Queries ~/.aegis/vuln.db for dependency vulnerabilities
5. Returns Vec<OperationLogEntry>
6. Prints count to stdout; errors to stderr + exit(1)
```

### `aegis attest [args]`

Source: `crates/orchestrator/src/attest.rs`

```
1. parse_attest_args(args) → AttestArgs
2. run_attest(attest_args)
   - Generates Ed25519 keypair or loads existing
   - Signs scope document: {target_url, authorized_by, expiry_unix}
   - Writes SignedScopeAttestation JSON to output path
```

### `aegis update-db [args]`

Source: `crates/orchestrator/src/update_db.rs`

```
1. parse_update_db_args(args) → UpdateDbArgs {db_path, source_dir, full_refresh}
2. run_update_db(args)
   a. Walk source_dir → find lock files → extract (package, ecosystem) pairs
   b. Batch-query https://api.osv.dev/v1/querybatch (up to 1000 per request)
      Uses reqwest::blocking::Client (NOT async — runs before tokio runtime)
      Retry: exponential backoff, 3 retries (2s/4s/8s), 120s timeout
   c. Convert OsvVulnerability → VulnerabilityRecord
   d. INSERT OR IGNORE into ~/.aegis/vuln.db (SQLite)
3. Returns UpdateDbSummary {new_records, total_records, packages_queried, db_path}
```

---

## Capability / Permission System

Source: `crates/orchestrator/src/pipeline.rs`, `crates/supervisor/src/capability_manager.rs`

```
CapabilityManager:
  - Initialized with random 32-byte master key
  - register_policy(ModulePermissionPolicy) for each module
  - issue_token(module, timestamp) → CapabilityToken (HMAC-signed)
  - validate_token(token, permission, timestamp) → Result (timing-safe via subtle::ct_eq)

Module permission policies (least-privilege):
  PassiveRecon:    ReadFilesystem + WriteGraph
  Enumeration:     ReadGraph + WriteGraph + ExecuteRequests
  Fuzzing:         ReadGraph + WriteGraph + ExecuteRequests
  ChainSynthesis:  ReadGraph + WriteGraph
  HypothesisEngine: ReadGraph only

At each phase:
  1. issue_phase_token(manager, module_id) → Option<CapabilityToken>
  2. Phase executes (token not passed to phase functions — capability check is advisory)
  3. validate_phase_token() → logs warning on failure (non-blocking)
```

---

## Testing Strategy

### Rust Tests

**Convention:** `{module}_test.rs` adjacent to `{module}.rs`, included via `#[path]` attribute:
```rust
#[cfg(test)]
#[path = "scheduler_test.rs"]
mod scheduler_test;
```

**Integration tests:** Each crate has `tests/integration.rs` (or similar), linked via `[[test]]` in Cargo.toml.

**Test support:** `crates/test-support` provides:
- `TestServer`: in-process axum HTTP server for integration tests
- Audit log test helpers

**Docker Tier 2 tests:** `crates/orchestrator/tests/docker_integration.rs`
- Gated: `AEGIS_INTEGRATION_TESTS=1`
- 34 tests covering Express, Flask, GraphQL defense stacks
- `DockerCompose` RAII struct — Drop trait tears down containers
- Must run with `--test-threads=1` (port conflicts)
- Requires Docker or Colima

**Ground truth tests:** 6 unit tests in `crates/orchestrator/tests/ground_truth.rs` — do NOT require Docker, just fixture parsing.

### Python Tests

Run from project root:
```
cd hypothesis-engine && uv run pytest src/hypothesis_engine/ tests/ -v
```

Two test directories:
- `src/hypothesis_engine/` — unit tests for each module
- `tests/` — integration + evaluation tests (golden fixtures, prompt regression)

Test types:
- `test_integration.py` — end-to-end bridge + generator tests
- `test_evaluation.py` — golden fixture evaluation (precision/recall/F1)
- `test_prompt_regression.py` — validates XML structure, vuln classes present, rubric present
- `test_llm_delta.py` — validates LLM value-add over static baseline

---

## Concurrent Operations Pattern

The scan pipeline is mostly sequential, with these concurrency patterns:

1. **Fingerprint phase sub-tasks** run on separate OS threads (not Tokio tasks):
   - `probe_defenses()` — spawned via `std::thread::spawn`
   - OpenAPI/GraphQL discovery — `run_on_thread()` helper (blocking reqwest in separate thread)
   - Rationale: `reqwest::blocking` creates its own tokio runtime internally — cannot run inside existing runtime

2. **Interactive stdin reader** — dedicated OS thread (not Tokio task), communicates via `Arc<Mutex<InteractiveSession>>`

3. **Hypothesis bridge** — Python subprocess communicating via Unix domain socket (`/tmp/aegis-hypothesis-{pid}-{timestamp}.sock`), 4-byte framed JSON

4. **Main pipeline** — single tokio task chain, `async` propagated through `run_scan` → `run_scan_phases` → `run_fuzz_analyze_loop` → `run_fuzz`

---

## Error Propagation Paths

```
run_scan() → Result<ScanSummary, PipelineError>
  ├── ConfigError (validation failures)
  ├── AuditLog (file creation failure)
  ├── PipelineComposer (invalid DAG)
  └── Phase errors (Recon|Crawl|Fingerprint|Fuzz|Analysis|DomVerify|Report)
       └── each wraps PhaseError:
            ├── Graph(GraphError) — knowledge graph validation failure
            ├── Io(io::Error) — file system errors
            ├── Serialization(serde_json::Error)
            ├── Checkpoint(CheckpointError)
            └── ReportFormat/UnknownExportFormat/FilesystemWalk (String)

PipelineError::InteractiveQuit — special case: user requested quit via interactive mode
  → main() prints "Scan aborted by user." (not an error exit code)

All phase errors propagate immediately via ? operator
No retry logic inside the pipeline itself (EvasionTransport handles request-level retries)
```
