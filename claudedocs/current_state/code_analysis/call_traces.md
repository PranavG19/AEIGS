# AEGIS Key Function Call Traces

<!-- metadata: execution traces, function call chains, data flow paths -->

## Trace 1: Full Scan Execution

```
main() [orchestrator/src/main.rs:8]
  └── run_scan(config) [pipeline.rs:1734]
        ├── parse_stealth_level() [scan_config.rs:435]
        ├── resolve_report_format() [scan_config.rs:493]
        ├── load_attestation() [protocol/scope_attestation.rs]  (if --scope-attestation)
        ├── validate_target_with_override() [protocol/target_validation.rs]
        ├── load_signed_config() + verify_signed_config() (if --signed-config)
        ├── create_audit_writer() → AuditLogWriter::create() [audit-log/log_writer.rs:64]
        │     └── HmacSigner::new() + save_key_to_file()
        ├── load_or_create_graph() [graph_persistence.rs]
        │     └── KnowledgeGraph::load_from_file() or KnowledgeGraph::new()
        ├── CapabilityManager::new() + register_default_policies()
        ├── spawn_interactive_reader() (if --interactive)
        │     └── std::thread::spawn("interactive-stdin")
        └── run_scan_phases(ctx, ...)  [pipeline.rs:1496]
              ├── validate_pipeline(pipeline_def) [pipeline_composer.rs]
              ├── run_recon_phase() [pipeline.rs:811]
              │     └── run_recon_standalone() [phase_recon.rs]
              │           ├── walk_directory() [passive-recon/filesystem_walker.rs]
              │           ├── parse_cargo_lock() [passive-recon/dependency_parser.rs]
              │           └── vuln_lookup() [passive-recon/vuln_database.rs]
              ├── run_crawl_phase() [pipeline.rs:845]
              │     └── crawl_result_to_operations() [phase_crawl.rs] (currently empty)
              ├── run_fingerprint_phase() [pipeline.rs:881]
              │     ├── collect_fingerprint_ops() → probe_defenses() (OS thread)
              │     ├── discover_openapi_endpoints_http() (OS thread)
              │     ├── discover_graphql_endpoints_http() (OS thread)
              │     ├── discover_routes_from_source() (if no HTTP endpoints)
              │     ├── apply_stealth_adjustments()
              │     └── graph.apply_operations(fp_ops + endpoint_ops)
              └── run_fuzz_analyze_loop() [pipeline.rs:1211]
                    ├── build_fuzz_transport() → EvasionTransport::builder().build()
                    ├── HypothesisBridge::start() (if !--no-llm)
                    └── for iteration in 0..max_iterations:
                          ├── run_single_fuzz() [pipeline.rs:1325]
                          │     └── run_fuzz(ctx, transport) [phase_fuzz.rs]
                          ├── run_hypothesis_step() [pipeline.rs:1137]
                          │     ├── build_hypothesis_context() → ScanContextJson
                          │     ├── bridge.generate_hypotheses() → Python IPC
                          │     └── bridge.compile_payloads() → Python IPC
                          ├── run_single_analyze() [pipeline.rs:1351]
                          │     └── run_analyze(ctx) [phase_analyze.rs]
                          │           └── build_attack_graph_from_knowledge_graph()
                          └── update_convergence() → check convergence_threshold
```

---

## Trace 2: Fuzz Phase Execution

```
run_fuzz(ctx, transport) [phase_fuzz.rs]
  ├── filter_scheduler_by_endpoints() (if scope filtering active)
  │     └── drains + re-enqueues FuzzScheduler
  └── while scheduler.dequeue():
        ├── FuzzTarget { endpoint, method, parameter, vulnerability_class, ... }
        ├── PayloadSelector::select_arm() → MutationOrigin
        ├── generate_tagged_payloads(target, origin, config)
        │     └── PayloadMutator::generate(template|mutation|boundary|corpus)
        ├── for payload in tagged_payloads:
        │     ├── FuzzRequest { endpoint, method, parameter, payload, ... }
        │     ├── transport.send(request) [evasion-engine/transport.rs:62]
        │     │     ├── validate_target_with_override()
        │     │     ├── timing.compute_delay_ms() → sleep
        │     │     ├── header_transformer.transform()
        │     │     └── reqwest::Client::execute()
        │     ├── oracle.detect_anomaly(control_resp, treatment_resp)
        │     │     └── counterfactual: compare paired requests
        │     └── if anomaly → create FindingData → OperationLogEntry
        └── ctx.graph.apply_operations(finding_ops)
```

---

## Trace 3: Knowledge Graph Apply Operations

```
KnowledgeGraph::apply_operations(entries) [knowledge-graph/graph.rs:113]
  ├── upgradable_read() → RwLockUpgradableReadGuard
  ├── operation_log.validate_batch(ops, node_store, edge_store)
  │     ├── for each op in batch:
  │     │     ├── AddNode → OK (always valid)
  │     │     ├── AddEdge → is_valid_edge(source, label, target)?
  │     │     │     └── EDGE_WHITELIST linear scan [protocol/edge.rs:74]
  │     │     ├── AddEdge → check weight is finite and >= 0.0
  │     │     ├── AddEdge → check not duplicate (same source+target+label)
  │     │     ├── AddFinding → check severity [0.0, 10.0] and confidence [0.0, 1.0]
  │     │     └── UpdateWeight → check target edge exists and weight is finite
  │     └── intra-batch duplicate check: HashSet<(u64, u64, EdgeLabel)>
  ├── upgrade() → RwLockWriteGuard (atomic upgrade, no other writer can intervene)
  └── operation_log.apply_batch(entries, node_store, edge_store, finding_store)
        ├── for each entry: route to node_store.insert() / edge_store.insert() / finding_store.insert()
        └── increment per-module sequence counters
```

---

## Trace 4: LLM Hypothesis IPC

```
HypothesisBridge::start(python_cmd) [hypothesis_bridge.rs]
  ├── Create socket path: /tmp/aegis-hypothesis-{pid}-{timestamp}.sock
  ├── UnixListener::bind(socket_path)
  ├── std::process::Command::new(python_cmd)
  │     .args(["-m", "hypothesis_engine.bridge", "--socket", socket_path])
  │     .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped())
  │     .spawn()
  └── socket = listener.accept()  (waits for Python to connect, 10s timeout)
      └── read_ipc_frame::<BridgeResponse>() → expect Ready response

HypothesisBridge::generate_hypotheses(scan_context, ...) [hypothesis_bridge.rs]
  ├── BridgeRequest::GenerateHypotheses { request_id, scan_context, ... }
  ├── write_ipc_frame(socket, request)  [hypothesis_bridge.rs:203]
  │     └── [4-byte LE u32 length][JSON payload]  (max 64 MiB)
  ├── read_ipc_frame::<BridgeResponse>(socket)  [120s timeout]
  └── BridgeResponse::Hypotheses { hypotheses, reasoning_trace, ... }

# Python side (hypothesis_engine/bridge.py):
while True:
  line = sys.stdin.readline()
  request = BridgeRequest.parse(line)
  match request.type:
    "GenerateHypotheses" →
      generator.generate(scan_context, feedback_summary)
        └── LlmBackend.invoke(system_prompt, user_prompt)
            └── (BedrockClient | OpenAiClient | OllamaClient).invoke()
      parse_hypotheses_from_response(text)
        └── try <hypotheses> XML tags first
        └── fallback: bracket JSON extraction
      response = BridgeResponse.Hypotheses(hypotheses, reasoning_trace, tokens)
    "CompilePayloads" →
      compiler.compile(hypotheses)
      response = BridgeResponse.CompiledPayloads(payloads, tokens)
  sys.stdout.write(json.dumps(response) + "\n")
  sys.stdout.flush()
```

---

## Trace 5: Audit Log Write

```
emit_event(audit_writer, AuditEventType::ModuleStarted { module })
  └── audit_writer.append_event(event) [audit-log/log_writer.rs:48]
        └── append_event_full(event)
              ├── SystemTime::now() → timestamp_unix_ms
              ├── ciborium::into_writer(event) → payload_cbor
              ├── chain.append(payload_cbor) → entry_hash  [hash_chain.rs]
              │     └── SHA3-256(prev_hash || payload_cbor)
              ├── signer.sign(payload_cbor) → hmac  [hmac_signer.rs]
              │     └── HMAC-SHA3-256(key, payload_cbor)
              └── file.write_all(
                    seq_bytes[8] + entry_hash[32] + payload_len[4] +
                    payload_cbor[N] + hmac[32]
                  )
```

---

## Trace 6: SARIF Report Generation

```
run_report_with_previous(ctx, metrics, previous_findings) [phase_report.rs]
  ├── collect all findings from graph
  ├── compute_new_findings(current, previous) → diff
  ├── RiskScorer::score_findings(findings, defense_profile)
  │     └── CVSS-style scoring with defense context adjustment
  ├── resolve_report_format(ctx.config.report_format)
  ├── SarifEmitter::emit(findings, format) [reporting/sarif_emitter.rs]
  │     ├── For each finding → create sarif::Result with:
  │     │     ├── ruleId: VulnerabilityClass display name
  │     │     ├── level: error|warning based on severity
  │     │     ├── message: NarrativeGenerator::generate(finding)
  │     │     └── properties: { severity, confidence, evidence_level, cve_id, ... }
  │     └── Serialize to JSON (sarif_rust types)
  └── write SARIF JSON to ctx.config.output
```

---

## Trace 7: Scan Resume from Checkpoint

```
run_scan(config) where config.pipeline.resume = true
  └── load_resume_checkpoint(config, graph_db_path)
        └── checkpoint::load_checkpoint(db_path)
              └── read "{db_path}.checkpoint.json"
              └── deserialize ScanCheckpoint { completed_phases, current_iteration, ... }

run_scan_phases(ctx, ..., checkpoint=Some(cp))
  ├── should_skip_phase_from_checkpoint(checkpoint, "recon")
  │     └── true if "recon" ∈ cp.completed_phases → skip
  ├── should_skip_phase_from_checkpoint(checkpoint, "crawl") → skip if done
  ├── should_skip_phase_from_checkpoint(checkpoint, "fingerprint") → skip if done
  └── run_fuzz_analyze_loop(start_iteration = cp.current_iteration)
        └── for iteration in cp.current_iteration..max_iterations:
              ├── should_skip_phase_from_checkpoint(cp, "fuzz:N") → skip if done
              └── should_skip_phase_from_checkpoint(cp, "analyze:N") → skip if done
```
