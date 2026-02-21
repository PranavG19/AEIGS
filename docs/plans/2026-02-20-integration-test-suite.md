# AEGIS Integration Test Suite — Full Plan

**Date**: 2026-02-20
**Goal**: 100% integration coverage across all 11 Rust crates + 1 Python package
**Current state**: 2,016 unit tests (Rust), 214 unit tests (Python), 0 integration tests

---

## Part 1: Infrastructure Setup

### 1.1 Create `test-support` Crate

New workspace member: `crates/test-support/`. Dev-dependency only. Provides:

```
crates/test-support/
├── Cargo.toml          # depends on axum, tokio, tower, serde_json, aegis-protocol
├── src/
│   ├── lib.rs
│   ├── fixture_server.rs    # TestServer wrapper (random port, auto-shutdown)
│   ├── vulnerable_app.rs    # VulnerableEndpoint builder + ground truth
│   ├── mock_transport.rs    # MockFuzzTransport implementing FuzzTransport trait
│   ├── mock_graph.rs        # MockGraphStore implementing GraphStore trait
│   ├── mock_llm.rs          # MockLlmBackend for Python hypothesis-engine testing
│   ├── assertions.rs        # assert_finding!, assert_no_finding!, assert_sarif_valid!
│   ├── fixture_data.rs      # Lock file contents, OpenAPI specs, GraphQL schemas
│   └── temp_workspace.rs    # TempDir helpers with pre-populated source trees
```

**fixture_server.rs** — Core test server:
- `TestServer::new(router) -> Self` — binds to `127.0.0.1:0`, returns assigned port
- `TestServer::url() -> String` — returns `http://127.0.0.1:{port}`
- `TestServer::shutdown()` — graceful shutdown (also via Drop)
- Built on `axum::serve` + `tokio::net::TcpListener`

**vulnerable_app.rs** — Declarative vulnerability fixtures:
- `VulnerableApp::builder()` — fluent API
- `.with_sqli(endpoint)` — adds SQL injection vulnerable endpoint
- `.with_xss(endpoint)` — adds reflected XSS endpoint
- `.with_ssti(endpoint)` — adds template injection endpoint
- `.with_path_traversal(endpoint)` — adds path traversal endpoint
- `.with_command_injection(endpoint)` — adds command injection endpoint
- `.with_ssrf(endpoint)` — adds SSRF endpoint
- `.with_idor(endpoint)` — adds IDOR endpoint
- `.with_open_redirect(endpoint)` — adds open redirect endpoint
- `.with_header_injection(endpoint)` — adds header injection endpoint
- `.with_crlf_injection(endpoint)` — adds CRLF injection endpoint
- `.with_broken_auth(endpoint)` — adds broken auth endpoint
- `.with_sensitive_data(endpoint)` — adds data exposure endpoint
- `.with_openapi_spec(spec)` — serves /openapi.json
- `.with_graphql(schema)` — serves /graphql with introspection
- `.with_graphql_no_introspection(schema)` — serves /graphql WITHOUT introspection (error-based discovery)
- `.with_websocket(endpoint)` — adds WS echo server
- `.with_health()` — adds /health baseline
- `.build() -> (Router, GroundTruth)` — returns axum Router + expected findings

**mock_transport.rs** — Deterministic HTTP transport:
- `MockFuzzTransport::new()` — records all requests
- `.with_response(endpoint, status, body)` — configure responses
- `.with_waf_block(endpoint, vendor)` — simulate WAF blocking
- `.with_rate_limit(rps, status)` — simulate rate limiting
- `.with_latency(endpoint, ms)` — simulate slow responses
- `.requests() -> Vec<FuzzRequest>` — inspect sent requests
- Implements `FuzzTransport` trait from orchestrator

**mock_graph.rs** — Lightweight graph for phase testing:
- Implements `GraphStore` trait
- In-memory Vec storage (no parking_lot needed)
- Records all operations for assertion

**assertions.rs** — Test macros:
- `assert_finding!(findings, class, endpoint)` — assert a finding exists
- `assert_no_finding!(findings, class, endpoint)` — assert no false positive
- `assert_sarif_valid!(json)` — validate SARIF 2.1.0 schema
- `assert_audit_chain_valid!(path, key)` — verify hash chain + HMAC
- `assert_ground_truth!(findings, ground_truth)` — precision/recall check

**fixture_data.rs** — Static test data:
- `CARGO_LOCK_WITH_VULN` — Cargo.lock containing a package with known CVE
- `PACKAGE_LOCK_V2` — npm package-lock.json v2 format
- `POETRY_LOCK` — poetry.lock with known vuln
- `GEMFILE_LOCK` — Gemfile.lock with nested deps
- `GO_SUM` — go.sum with known vuln
- `EXPRESS_SOURCE` — Express.js source with routes
- `FLASK_SOURCE` — Flask source with routes
- `FASTAPI_SOURCE` — FastAPI source with routes
- `DJANGO_SOURCE` — Django urlconf with routes
- `SPRING_SOURCE` — Spring controller with routes
- `OPENAPI_3_SPEC` — OpenAPI 3.0 JSON with 10 endpoints
- `GRAPHQL_INTROSPECTION_RESPONSE` — Full introspection JSON
- `GRAPHQL_SDL` — SDL schema string
- `BUSINESS_CONTEXT_JSON` — BusinessContext fixture

### 1.2 Docker Fixture Applications

```
test-fixtures/
├── express-vuln-app/
│   ├── Dockerfile
│   ├── package.json
│   ├── package-lock.json       # Contains intentionally outdated deps for recon
│   ├── app.js                  # 16 vulnerable endpoints (one per VulnerabilityClass)
│   ├── openapi.json            # Served at /openapi.json
│   └── ground-truth.json       # Machine-readable expected findings
│
├── flask-vuln-app/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── poetry.lock             # Contains intentionally outdated deps
│   ├── app.py                  # SSTI (Jinja2), IDOR, broken auth, data exposure
│   ├── templates/              # Vulnerable Jinja2 templates
│   └── ground-truth.json
│
├── graphql-vuln-app/
│   ├── Dockerfile
│   ├── package.json
│   ├── server.js               # Apollo server: introspection + auth bypass + query depth
│   └── ground-truth.json
│
├── rust-vuln-app/
│   ├── Dockerfile
│   ├── Cargo.toml
│   ├── Cargo.lock              # Contains intentionally outdated deps
│   └── src/main.rs             # Axum app with known vulns
│
├── compose.yml                 # All fixture apps (ports 3001-3004)
├── compose.with-modsecurity.yml  # Apps behind ModSecurity WAF (ports 8001-8004)
├── compose.with-ratelimit.yml    # Apps behind rate limiter
├── compose.with-botdetect.yml    # Apps behind bot detection
└── compose.full-defense.yml      # Apps behind all defense layers
```

### 1.3 CI Configuration

```yaml
# .github/workflows/test.yml
jobs:
  unit-tests:
    # Every PR: cargo test --workspace + pytest
  integration-tier1:
    # Every PR: cargo test --workspace --features integration
    # In-process axum tests, no Docker needed
  integration-tier2:
    # Merge to main only: AEGIS_INTEGRATION_TESTS=1
    # Needs Docker, runs fixture apps + full pipeline
```

---

## Part 2: Tier 1 — In-Process Integration Tests

### 2.1 Protocol Crate Integration Tests

**File**: `crates/protocol/tests/integration.rs`

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 1 | `target_validation_accepts_localhost_variants` | `127.0.0.1`, `localhost`, `::1`, `[::1]`, `http://127.0.0.1:3000/path` all accepted |
| 2 | `target_validation_rejects_non_localhost` | `192.168.1.1`, `10.0.0.1`, `example.com`, `0x7f000001`, `0177.0.0.1` all rejected |
| 3 | `target_validation_rejects_ssrf_obfuscation` | Decimal IP, octal IP, DNS rebinding-like patterns rejected |
| 4 | `scope_attestation_sign_verify_roundtrip` | Sign with Ed25519 key → verify with public key → Ok |
| 5 | `scope_attestation_reject_tampered_document` | Modify document after signing → verify fails with InvalidSignature |
| 6 | `scope_attestation_reject_expired` | Expiry date in past → verify fails with Expired |
| 7 | `scope_attestation_reject_target_mismatch` | Attestation for target A, verify against target B → TargetMismatch |
| 8 | `scope_attestation_file_roundtrip` | Save to tempfile → load → verify matches original |
| 9 | `signed_config_sign_verify_roundtrip` | Sign config → verify → Ok, hash matches |
| 10 | `signed_config_reject_tampered_config` | Modify config field after signing → HashMismatch |
| 11 | `signed_config_reject_invalid_signature` | Corrupt signature bytes → InvalidSignature |
| 12 | `signed_config_file_roundtrip` | Save to tempfile → load → verify matches |
| 13 | `scan_event_serialization_all_variants` | All ScanEvent variants serialize/deserialize through serde_json |
| 14 | `edge_validation_all_28_valid_triples` | Every valid (NodeType, EdgeLabel, NodeType) triple accepted |
| 15 | `edge_validation_reject_invalid_triples` | Sample of invalid triples rejected (at least 20 invalid combos) |
| 16 | `vulnerability_class_display_all_16` | All 16 VulnerabilityClass variants display correctly |
| 17 | `finding_data_confidence_roundtrip` | FindingData with confidence_score serializes/deserializes correctly |
| 18 | `finding_data_missing_confidence_defaults_none` | JSON without confidence_score field deserializes as None |

### 2.2 Knowledge Graph Integration Tests

**File**: `crates/knowledge-graph/tests/integration.rs`

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 19 | `graph_persist_save_load_roundtrip` | Create graph → add nodes/edges/findings → save to tempfile → load → all data matches |
| 20 | `graph_persist_metadata_preserved` | GraphMetadata (timestamp, target_url, aegis_version) roundtrips through save/load |
| 21 | `graph_apply_operations_batch_validates_edges` | Batch with invalid edge triple → rejected; valid batch → applied |
| 22 | `graph_apply_operations_rejects_duplicate_edges` | Two edges with same (source, target, label) in same batch → rejected |
| 23 | `graph_apply_operations_weight_bounds` | Edge weight NaN, -1.0, Infinity → rejected; 0.0, 1.0, 100.0 → accepted |
| 24 | `graph_apply_operations_score_bounds` | Finding severity 11.0, -1.0 → rejected; confidence 1.5 → rejected |
| 25 | `graph_strict_sequence_gap_detection` | OperationLog with gap in sequence numbers → rejected in strict mode |
| 26 | `graph_relaxed_sequence_allows_gaps` | Same gaps → accepted in relaxed mode |
| 27 | `graph_concurrent_read_access` | Spawn 10 readers simultaneously → all succeed without blocking |
| 28 | `graph_store_trait_mock_implementation` | MockGraphStore implements GraphStore correctly, records operations |
| 29 | `graph_path_query_finds_shortest_path` | Add known graph → query path → correct shortest path returned |
| 30 | `graph_path_query_respects_100k_cap` | Dense graph → paths capped at MAX_TOTAL_PATHS |
| 31 | `graph_reachability_from_entry_point` | Add entry point → add connected nodes → verify reachability |

### 2.3 Passive Recon Integration Tests

**File**: `crates/passive-recon/tests/integration.rs`

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 32 | `parse_real_cargo_lock` | Parse actual Cargo.lock (from fixture) → correct deps extracted, registry-only |
| 33 | `parse_real_package_lock_v2` | Parse npm v2 lock → correct deps, node_modules prefix stripped |
| 34 | `parse_real_package_lock_v1_fallback` | Parse npm v1 lock → falls back to dependencies object |
| 35 | `parse_real_poetry_lock` | Parse poetry.lock → correct Python deps |
| 36 | `parse_real_gemfile_lock` | Parse Gemfile.lock → only direct deps (indent tracking works) |
| 37 | `parse_real_go_sum` | Parse go.sum → version stripped, deduped |
| 38 | `vuln_database_lookup_known_cve` | Create in-memory SQLite → insert fixture CVE → lookup by package+version → found |
| 39 | `vuln_database_no_match_returns_empty` | Lookup non-existent package → empty results |
| 40 | `filesystem_walker_finds_lock_files` | Create tempdir tree with Cargo.lock, package-lock.json, etc. → all found |
| 41 | `filesystem_walker_classifies_source_files` | Create tempdir with .rs, .js, .py files → classified correctly |
| 42 | `filesystem_walker_skips_hidden_dirs` | Create .git/ and node_modules/ → skipped |
| 43 | `recon_end_to_end_tempdir` | Create tempdir with Cargo.lock containing vulnerable dep → walk → parse → lookup → finding |

### 2.4 Enumeration Integration Tests

**File**: `crates/enumeration/tests/integration.rs`

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 44 | `openapi_parse_from_live_server` | Boot axum serving fixture OpenAPI spec → parse → correct endpoints extracted |
| 45 | `openapi_extracts_parameters` | Fixture spec with path/query/header params → all parameter types extracted |
| 46 | `openapi_extracts_request_body` | Fixture spec with application/json body → properties extracted |
| 47 | `graphql_introspection_from_live_server` | Boot axum serving introspection response → parse → correct types/fields extracted |
| 48 | `graphql_sdl_parse_from_live_server` | Boot axum serving SDL → parse → correct types extracted |
| 49 | `graphql_fallback_discovery_error_based` | Boot axum returning error messages with field suggestions → fields extracted |
| 50 | `graphql_fallback_discovery_common_fields` | Boot axum with no introspection → brute-force common fields → discovered |
| 51 | `graphql_fallback_combined_strategy` | Both strategies merged → union of discovered fields |
| 52 | `route_parser_express_real_source` | Parse fixture Express source → correct routes with methods and handlers |
| 53 | `route_parser_flask_real_source` | Parse fixture Flask source → correct routes |
| 54 | `route_parser_fastapi_real_source` | Parse fixture FastAPI source → correct routes |
| 55 | `route_parser_django_real_source` | Parse fixture Django urlconf → correct routes |
| 56 | `route_parser_spring_real_source` | Parse fixture Spring controller → correct routes |
| 57 | `auth_matrix_from_live_server` | Boot axum with role-based endpoints → build matrix → anomalies detected |
| 58 | `auth_flow_template_rendering` | Define multi-step auth flow → render templates → variables substituted |
| 59 | `auth_flow_session_fixation_detection` | Auth flow with session that doesn't rotate → detected |
| 60 | `auth_flow_weak_session_id_detection` | Auth flow returning short/predictable session ID → detected |
| 61 | `auth_flow_insecure_cookie_detection` | Auth flow setting cookie without Secure/HttpOnly → detected |

### 2.5 Fuzzing Integration Tests

**File**: `crates/fuzzing/tests/integration.rs`

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 62 | `executor_builds_request_with_headers` | Build FuzzRequest → has User-Agent, Accept, Content-Type headers |
| 63 | `executor_sends_to_live_sqli_endpoint` | Boot axum with SQLi → send payload → response contains SQL error |
| 64 | `executor_sends_to_live_xss_endpoint` | Boot axum with XSS → send payload → payload reflected in body |
| 65 | `executor_localhost_validation` | Attempt to send to non-localhost → rejected |
| 66 | `oracle_detects_status_code_anomaly` | Baseline 200, payload response 500 → StatusCodeAnomaly detected |
| 67 | `oracle_detects_timing_anomaly` | Baseline <50ms, payload with sleep → TimingAnomaly detected |
| 68 | `oracle_detects_content_anomaly` | Baseline clean, payload response has "SQL syntax" → ContentAnomaly detected |
| 69 | `oracle_detects_reflection` | Payload `<script>alert(1)</script>` reflected in body → ReflectionDetected |
| 70 | `oracle_detects_size_anomaly` | Baseline 100 bytes, payload response 10000 bytes → SizeAnomaly detected |
| 71 | `oracle_counterfactual_eliminates_false_positive` | Endpoint always returns 500 → control and treatment both error → no anomaly |
| 72 | `oracle_counterfactual_confirms_true_positive` | Only treatment triggers error → anomaly confirmed |
| 73 | `scheduler_priority_ordering` | Enqueue targets with different priorities → dequeue in priority order |
| 74 | `scheduler_novelty_boosts_priority` | Mark target with high novelty → priority increases on re-enqueue |
| 75 | `scheduler_nan_priority_clamped` | Enqueue with NaN priority → clamped to 0.0, no crash |
| 76 | `mutator_generates_sqli_payloads` | Generate for SqlInjection → at least 8 template payloads |
| 77 | `mutator_generates_xss_payloads` | Generate for XSS → at least 6 template payloads |
| 78 | `mutator_generates_all_16_classes` | For each VulnerabilityClass → generates non-empty payload list |
| 79 | `mutator_tagged_payloads_have_origin` | All generated payloads have correct MutationOrigin tag |
| 80 | `mutator_stealth_rating_correct` | Sleep-based SQLi → high stealth; basic SQLi → low stealth |
| 81 | `mutator_boundary_payloads` | Boundary strategy generates 20 boundary values |
| 82 | `waf_fingerprinter_detects_modsecurity` | Boot axum with `x-powered-by: modsecurity` header → ModSecurity detected |
| 83 | `waf_fingerprinter_detects_cloudflare` | Boot axum with `cf-ray` header → Cloudflare detected |
| 84 | `waf_fingerprinter_detects_aws_waf` | Boot axum with `x-amzn-waf-action` header → AwsWaf detected |
| 85 | `waf_fingerprinter_detects_imperva` | Boot axum with "powered by imperva" body → Imperva detected |
| 86 | `waf_fingerprinter_detects_akamai` | Boot axum with `x-akamai-transformed` header → Akamai detected |
| 87 | `waf_fingerprinter_unknown_when_no_signatures` | Boot plain axum → Unknown or None |
| 88 | `waf_blocked_categories_identified` | Boot axum that 403s on SQLi probes → SqlInjection in blocked_categories |
| 89 | `rate_limit_detector_identifies_threshold` | Boot axum that 429s after 5 req/s → rps detected ~5.0 |
| 90 | `rate_limit_detector_burst_allowance` | Boot axum allowing 10 burst then 429 → burst_allowance ~10 |
| 91 | `rate_limit_detector_window_detection` | Boot axum that recovers after 60s → limit_window ~60 |
| 92 | `bot_detection_detects_captcha` | Boot axum serving recaptcha HTML → Captcha detected |
| 93 | `bot_detection_detects_js_challenge` | Boot axum serving JS challenge → JavaScriptChallenge detected |
| 94 | `bot_detection_detects_header_analysis` | Boot axum that blocks requests without proper User-Agent → HeaderAnalysis detected |
| 95 | `bot_detection_detects_behavioral` | Boot axum that blocks rapid requests → Behavioral detected |
| 96 | `streaming_fuzzer_validates_ws_target` | ws://127.0.0.1:PORT → valid; ws://evil.com → rejected |
| 97 | `streaming_fuzzer_generates_ws_payloads` | Generate WS payloads → includes oversized frames, malformed JSON, injection |
| 98 | `streaming_fuzzer_generates_sse_probes` | Generate SSE probe URLs → includes event-stream Accept header |
| 99 | `streaming_fuzzer_detects_ws_anomalies` | Feed abnormal WS messages → anomalies detected (UnexpectedClose, DataLeak) |
| 100 | `request_patterns_sequential` | Build sequential batch → requests ordered, correct delays |
| 101 | `request_patterns_burst` | Build burst batch → requests grouped, inter-burst delay present |
| 102 | `request_patterns_parallel_resources` | Build parallel batch → subresource URLs generated |
| 103 | `request_patterns_navigation_chain` | Build nav chain → steps in order with referers |
| 104 | `request_patterns_cover_traffic` | Inject cover traffic → batch size increases, cover URLs present |
| 105 | `request_patterns_max_batch_clamp` | Request >64 batch → clamped to MAX_BATCH_SIZE |
| 106 | `payload_selector_ucb1_novel_first` | Unknown payload → score is Infinity → selected first |
| 107 | `payload_selector_ucb1_exploits_effective` | Payload with 80% success rate → higher score than 20% success rate |
| 108 | `payload_selector_ucb1_explores_untested` | Payload with 0 attempts → score is Infinity |
| 109 | `defense_profile_builder` | Build profile with WAF + rate limit + bot detection → all fields set |
| 110 | `variance_measurement_deterministic` | Boot axum always returning same response → is_deterministic = true |
| 111 | `variance_measurement_nondeterministic` | Boot axum returning random body → is_deterministic = false |

### 2.6 Evasion Engine Integration Tests

**File**: `crates/evasion-engine/tests/integration.rs`

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 112 | `transport_sends_to_live_server` | Boot axum → send via EvasionTransport → response received |
| 113 | `transport_applies_persona_headers` | Send with ChromeDesktop persona → request has Chrome UA + Sec-Fetch headers |
| 114 | `transport_rotates_personas` | Send 10 requests with rotation → multiple different User-Agents seen |
| 115 | `transport_localhost_enforcement` | Attempt to send to non-localhost → rejected at transport layer |
| 116 | `persona_catalog_loads_all_10` | Load default catalog → 10 personas, each with correct headers |
| 117 | `persona_chrome_desktop_headers` | ChromeDesktop → correct User-Agent, Accept, Accept-Language, Sec-Fetch-* |
| 118 | `persona_firefox_desktop_headers` | FirefoxDesktop → correct Firefox User-Agent, different header order |
| 119 | `persona_curl_minimal_headers` | CurlClient → curl User-Agent, `Accept: */*`, minimal headers |
| 120 | `persona_googlebot_headers` | Googlebot → Googlebot User-Agent, minimal headers |
| 121 | `header_transformer_applies_transforms` | Transform request → headers match persona expectations |
| 122 | `header_transformer_preserves_custom_headers` | Request with custom header → custom header preserved after transform |
| 123 | `encoding_transformer_url_encodes` | Apply URL encoding → special chars encoded |
| 124 | `encoding_transformer_double_encodes` | Apply double encoding → chars double-encoded |
| 125 | `timing_controller_applies_jitter` | Record 20 request timestamps → intervals fall within persona range |
| 126 | `timing_controller_normal_distribution` | ChromeDesktop (Normal dist) → intervals cluster around mean |
| 127 | `timing_controller_exponential_distribution` | SafariDesktop (Exponential) → intervals skewed toward minimum |
| 128 | `session_manager_rotates_cookies` | Enable rotation → cookies change every N requests |
| 129 | `session_manager_preserves_session_within_window` | Within rotation window → same cookies maintained |
| 130 | `tls_fingerprint_mapping_all_personas` | FingerprintMapping::all_personas() → 10 entries, correct mappings |
| 131 | `tls_chrome_edge_share_ja3` | Chrome120 and Edge120 JA3 hashes identical (Chromium-based) |
| 132 | `tls_firefox_different_ja3` | Firefox121 JA3 hash differs from Chrome120 |
| 133 | `tls_config_builder_chain` | Build TlsConfig with all with_* methods → all fields set |
| 134 | `http_client_config_serialization` | Serialize HttpClientConfig → deserialize → identical |
| 135 | `persona_tls_config_curl_no_http2` | CurlClient persona → enable_http2 = false |
| 136 | `persona_tls_config_browsers_http2` | All browser personas → enable_http2 = true |

### 2.7 Chain Synthesis Integration Tests

**File**: `crates/chain-synthesis/tests/integration.rs`

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 137 | `attack_graph_from_findings` | Feed real FindingData → attack graph built with correct nodes |
| 138 | `shortest_path_through_vulns` | Known graph → shortest path uses lowest-difficulty edges |
| 139 | `all_paths_bounded` | Dense graph → paths capped at limit |
| 140 | `betweenness_centrality_identifies_bottleneck` | Graph with single chokepoint → that node has highest centrality |
| 141 | `mitigation_impact_removes_findings` | Remove node → downstream findings unreachable → correct impact_score |
| 142 | `mitigation_ranking_orders_by_value` | Multiple fix candidates → sorted by mitigation value descending |
| 143 | `defense_gap_finds_unprotected_entries` | Graph with some endpoints lacking ProtectedBy edges → gap report lists them |
| 144 | `defense_gap_all_protected` | All endpoints have Defense neighbor → gap report empty |
| 145 | `dot_export_valid_graphviz` | Export graph → output starts with `digraph`, contains all node labels |
| 146 | `dot_export_escapes_special_chars` | Node with `"` and `<` in label → properly escaped in DOT output |
| 147 | `d3_json_export_structure` | Export to D3 JSON → has `nodes` and `links` arrays with correct IDs |

### 2.8 Reporting Integration Tests

**File**: `crates/reporting/tests/integration.rs`

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 148 | `risk_score_all_16_vuln_classes` | Each VulnerabilityClass → computes a score in [0.0, 10.0] |
| 149 | `risk_score_defense_aware_reduces_score` | Same finding with WAF present → lower score than without WAF |
| 150 | `risk_score_confidence_weighted` | Higher confidence → higher effective score |
| 151 | `sarif_emission_valid_json` | Emit from real findings → valid JSON, has `$schema`, `version` "2.1.0" |
| 152 | `sarif_has_correct_cwe_for_sqli` | SqlInjection finding → CWE-89 in taxa |
| 153 | `sarif_has_correct_cwe_for_xss` | XSS finding → CWE-79 in taxa |
| 154 | `sarif_has_attack_technique` | Finding with ATT&CK mapping → technique ID present |
| 155 | `sarif_has_remediation` | Finding → has `fixes` array with remediation description |
| 156 | `sarif_diff_mode_only_new` | Previous + current findings → diff SARIF contains only new findings |
| 157 | `narrative_generates_for_all_classes` | Each VulnerabilityClass → non-empty narrative string |
| 158 | `narrative_includes_remediation_advice` | Narrative for SqlInjection → mentions parameterized queries |
| 159 | `executive_summary_aggregates` | Multiple findings → summary has counts, top risks, recommendations |
| 160 | `certificate_serialize_deserialize_all_types` | Each CertificateType → CBOR serialize → deserialize → matches |
| 161 | `certificate_hash_deterministic` | Same input → same SHA3-256 hash |
| 162 | `report_format_developer_sarif` | Developer format → produces SARIF output |
| 163 | `report_format_security_enriched` | Security format → SARIF with ATT&CK chains |
| 164 | `report_format_executive_summary` | Executive format → JSON summary with risk ratings |

### 2.9 Audit Log Integration Tests

**File**: `crates/audit-log/tests/integration.rs`

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 165 | `write_read_verify_100_entries` | Write 100 audit events → verify chain → all valid |
| 166 | `write_verify_detects_tampering` | Write entries → corrupt one byte in CBOR file → verify fails |
| 167 | `hmac_verification_correct_key` | Write with key A → verify with key A → passes |
| 168 | `hmac_verification_wrong_key` | Write with key A → verify with key B → fails |
| 169 | `hmac_key_derivation_from_passphrase` | Derive key from passphrase → consistent across calls |
| 170 | `hmac_key_save_load_file` | Save key to tempfile → load → same key |
| 171 | `noop_writer_discards_events` | NoOpAuditLogWriter::append_event → Ok, sequence advances, no file |
| 172 | `event_store_replay_reconstructs_scan` | Write ScanStarted, ModuleStarted, FindingRecorded, ScanCompleted → replay → snapshot matches |
| 173 | `event_store_filter_by_type` | 10 mixed events → filter by "FindingRecorded" → only findings returned |
| 174 | `event_store_filter_by_sequence_range` | 10 events → filter after_sequence=3 before_sequence=7 → events 4,5,6 |
| 175 | `event_store_filter_by_timestamp_range` | Events at different timestamps → filter range → correct subset |
| 176 | `event_store_diff_snapshots` | Snapshot A (2 findings) vs snapshot B (5 findings) → diff has 3 new findings |
| 177 | `event_store_timeline` | 5 events → timeline → 5 (timestamp, description) pairs in order |
| 178 | `event_store_config_change_tracked` | ConfigChange events → snapshot has config_changes with key/old/new values |
| 179 | `genesis_hash_deterministic` | genesis_hash() called twice → same result |
| 180 | `hash_chain_sequential` | compute_next_hash with known inputs → deterministic output |

### 2.10 Supervisor Integration Tests

**File**: `crates/supervisor/tests/integration.rs`

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 181 | `capability_grant_validate_roundtrip` | Grant token → validate → Ok |
| 182 | `capability_reject_invalid_token` | Modify token bytes → validate → fails |
| 183 | `capability_timing_safe_comparison` | Validate uses constant-time comparison (no timing leak) |
| 184 | `capability_revoke_module` | Grant → revoke → validate → fails |
| 185 | `process_manager_lifecycle` | Spawn → update state → get state → terminate |

### 2.11 Orchestrator Integration Tests

**File**: `crates/orchestrator/tests/integration.rs`

**Pipeline tests (boot real axum server, run phases):**

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 186 | `full_pipeline_finds_sqli` | Boot server with SQLi → full pipeline → SqlInjection finding present |
| 187 | `full_pipeline_finds_xss` | Boot server with XSS → full pipeline → XSS finding present |
| 188 | `full_pipeline_finds_command_injection` | Boot server with cmd injection → finding present |
| 189 | `full_pipeline_finds_path_traversal` | Boot server with path traversal → finding present |
| 190 | `full_pipeline_finds_ssrf` | Boot server with SSRF → finding present |
| 191 | `full_pipeline_finds_ssti` | Boot server with SSTI → finding present |
| 192 | `full_pipeline_finds_broken_auth` | Boot server with auth bypass → finding present |
| 193 | `full_pipeline_finds_idor` | Boot server with IDOR → finding present |
| 194 | `full_pipeline_finds_open_redirect` | Boot server with redirect → finding present |
| 195 | `full_pipeline_finds_header_injection` | Boot server with header injection → finding present |
| 196 | `full_pipeline_finds_crlf_injection` | Boot server with CRLF → finding present |
| 197 | `full_pipeline_finds_sensitive_data` | Boot server exposing PII → finding present |
| 198 | `full_pipeline_finds_deserialization` | Boot server with unsafe deserialization → finding present |
| 199 | `full_pipeline_finds_security_misconfig` | Boot server with debug mode / default creds → finding present |
| 200 | `full_pipeline_finds_broken_authz` | Boot server with authz bypass → finding present |
| 201 | `full_pipeline_finds_input_validation` | Boot server with weak validation → finding present |
| 202 | `full_pipeline_all_16_classes_ground_truth` | Boot server with all 16 vuln types → GroundTruth evaluation → precision > 0.8, recall > 0.7 |
| 203 | `full_pipeline_no_false_positives_on_clean_app` | Boot axum with no vulns → zero findings |
| 204 | `full_pipeline_produces_valid_sarif` | Run pipeline → SARIF output validates against schema |
| 205 | `full_pipeline_audit_log_intact` | Run pipeline → verify audit chain → all valid |
| 206 | `full_pipeline_with_source_dir` | Provide tempdir with Cargo.lock → recon finds dependencies + CVEs |

**Phase isolation tests:**

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 207 | `phase_recon_standalone` | run_recon_standalone with tempdir → returns OperationLogEntry list |
| 208 | `phase_recon_populates_graph` | run_recon → MockGraphStore has dependency + vulnerability nodes |
| 209 | `phase_fingerprint_detects_waf` | Boot axum with WAF headers → run_fingerprint → DefenseProfile has WAF |
| 210 | `phase_fingerprint_no_defense` | Boot clean axum → run_fingerprint → no defenses detected |
| 211 | `phase_fuzz_sends_real_requests` | Boot vuln axum → run_fuzz with MockTransport → requests sent, anomalies found |
| 212 | `phase_fuzz_returns_fuzz_phase_result` | run_fuzz → FuzzPhaseResult has origin_counts and discovered_endpoints |
| 213 | `phase_analyze_builds_attack_graph` | Pre-populate graph with findings → run_analyze → attack paths computed |
| 214 | `phase_report_emits_sarif` | Pre-populate findings → run_report → SARIF JSON produced |
| 215 | `phase_report_diff_mode` | run_report_with_previous → only new findings in output |

**Checkpoint/resume tests:**

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 216 | `checkpoint_save_load_roundtrip` | Save checkpoint to tempdir → load → all fields match |
| 217 | `checkpoint_skip_completed_phases` | Checkpoint with ["recon", "fingerprint"] → should_skip_phase("recon") = true |
| 218 | `checkpoint_delete_on_completion` | Save → delete → load returns None |
| 219 | `checkpoint_corrupted_file_error` | Write garbage to checkpoint path → load returns Corrupted error |

**Graph persistence tests:**

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 220 | `graph_persistence_load_or_create_fresh` | No file exists → creates fresh graph, returns 0 ops |
| 221 | `graph_persistence_load_or_create_existing` | Save graph first → load_or_create → loads existing data |
| 222 | `graph_persistence_save_if_configured` | Pass Some(path) → file created; pass None → no file |

**Convergence tests:**

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 223 | `convergence_stops_after_threshold` | 2 consecutive zero-finding rounds → is_converged = true |
| 224 | `convergence_resets_on_new_findings` | Zero → findings → zero → not converged yet (only 1 consecutive) |
| 225 | `refuted_tracker_prevents_retest` | Record refuted → is_refuted = true → hypothesis skipped |

**Benchmark/calibration tests:**

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 226 | `benchmark_perfect_detection` | All ground truth found, no extras → precision=1.0, recall=1.0, F1=1.0 |
| 227 | `benchmark_partial_detection` | Half ground truth found → recall=0.5 |
| 228 | `benchmark_false_positives` | Extra findings beyond ground truth → precision < 1.0 |
| 229 | `benchmark_per_class_metrics` | Findings across 3 classes → per-class precision/recall computed |
| 230 | `calibration_well_calibrated` | Findings at 0.8 confidence, 80% true positive → ECE near 0 |
| 231 | `calibration_overconfident` | Findings at 0.9 confidence, 50% true positive → overconfident_bins > 0 |
| 232 | `calibration_underconfident` | Findings at 0.3 confidence, 90% true positive → underconfident_bins > 0 |

**Endpoint similarity tests:**

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 233 | `similarity_transfer_to_similar_endpoint` | /api/users has SQLi, /api/posts is similar → TransferredFinding generated |
| 234 | `similarity_no_transfer_to_dissimilar` | /api/users and /health → too dissimilar → no transfer |
| 235 | `tokenization_splits_path_segments` | /api/users/profile → tokens include "api", "users", "profile" |

**Scan history tests:**

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 236 | `scan_history_insert_and_query` | Insert 10 entries → query by endpoint → correct results |
| 237 | `scan_history_cross_scan_learning` | Insert from scan A → query from scan B (same app_hash) → history available |
| 238 | `scan_history_isolates_by_app_hash` | Two different app_hash values → queries isolated |

**Pipeline composer tests:**

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 239 | `default_pipeline_valid` | default_pipeline() → validate → Ok |
| 240 | `minimal_pipeline_valid` | minimal_pipeline() → validate → Ok |
| 241 | `custom_pipeline_cycle_rejected` | A depends on B, B depends on A → validate → CycleDetected |
| 242 | `topological_order_correct` | Known DAG → order respects all dependencies |
| 243 | `execution_plan_waves` | Pipeline with parallel stages → execution waves group correctly |

**Interactive mode tests:**

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 244 | `interactive_parse_all_commands` | pause, resume, status, findings, endpoints, priority, skip, quit → all parsed |
| 245 | `interactive_case_insensitive` | "PAUSE", "Pause", "pause" → all parse to Pause |
| 246 | `interactive_session_pause_resume` | Execute pause → status is Paused → execute resume → status is Running |
| 247 | `interactive_session_findings_list` | Add findings to session → execute findings → correct response |

**Distributed coordination tests:**

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 248 | `partition_round_robin` | 10 endpoints, 3 workers → partitions roughly equal |
| 249 | `partition_priority_based` | Endpoints with priorities → higher priority workers get more |
| 250 | `coordinator_register_workers` | Register 3 workers → active_worker_count = 3 |
| 251 | `coordinator_heartbeat_failure` | Worker misses heartbeat → detected as failed |
| 252 | `coordinator_rebalance` | Worker fails → remaining workers get redistributed work |
| 253 | `coordinator_all_complete` | All assignments finished → all_complete = true |

**Telemetry tests:**

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 254 | `telemetry_disabled_by_default` | Default config → enabled = false → record_event returns Ok but discards |
| 255 | `telemetry_enabled_records_events` | Enabled config → record events → export_json has all events |
| 256 | `telemetry_never_contains_raw_findings` | Record scan events → export → no finding details, only counts |
| 257 | `telemetry_sanitizes_errors` | Record error with stack trace → export → only category string |
| 258 | `telemetry_export_to_file` | Export to tempfile → file contains valid JSON |

**Actor tests:**

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 259 | `actor_recon_executes` | ReconActor::execute() with mock context → returns Ok |
| 260 | `actor_fuzz_executes` | FuzzActor::execute() with mock transport → sends requests |
| 261 | `run_actor_pipeline_executes_in_order` | Pipeline of 3 actors → executed in correct order |

**Config tests:**

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 262 | `config_validates_localhost` | Valid localhost URLs → Ok; non-localhost → Err |
| 263 | `config_loads_business_context` | Fixture JSON file → BusinessContext with excluded/critical/pii endpoints |
| 264 | `config_parse_stealth_levels` | "default", "aggressive", "paranoid" → correct StealthLevel variants |
| 265 | `config_resolve_persona_ids` | "chrome", "firefox", "safari" → correct PersonaId variants |

### 2.12 Python Hypothesis Engine Integration Tests

**File**: `hypothesis-engine/tests/test_integration.py`

| # | Test Name | What It Proves |
|---|-----------|---------------|
| 266 | `test_mock_backend_generates_hypotheses` | MockLlmBackend → HypothesisGenerator → returns hypotheses list |
| 267 | `test_mock_backend_compiles_tests` | MockLlmBackend → HypothesisCompiler → returns test code |
| 268 | `test_mock_backend_evasion_tactics` | MockLlmBackend → EvasionHypothesisGenerator → returns tactics |
| 269 | `test_feedback_loop_multi_round` | Generate round 1 → provide feedback → generate round 2 → uses feedback |
| 270 | `test_token_usage_tracked` | Multiple invocations → cumulative token counts correct |
| 271 | `test_uncertainty_hedging_detected` | Response with "might", "possibly" → hedging_score > 0 |
| 272 | `test_uncertainty_confidence_detected` | Response with "confirms", "clearly" → confidence_score > 0 |
| 273 | `test_bypass_corpus_loads_when_present` | Create fixture file → loads → corpus available |
| 274 | `test_bypass_corpus_warns_when_missing` | No file → RuntimeWarning emitted → empty corpus |
| 275 | `test_create_backend_factory` | create_backend("bedrock") → BedrockClient; create_backend("openai") → OpenAiClient |

---

## Part 3: Tier 2 — Docker Integration Tests

Gated behind `AEGIS_INTEGRATION_TESTS=1` environment variable.

### 3.1 Express Vulnerable App Tests

| # | Test Name | Fixture | What It Proves |
|---|-----------|---------|---------------|
| 276 | `express_full_scan_ground_truth` | express-vuln-app | Full pipeline → findings match ground-truth.json |
| 277 | `express_openapi_discovery` | express-vuln-app | /openapi.json parsed → all endpoints discovered |
| 278 | `express_source_recon` | express-vuln-app | Source dir with package-lock.json → CVEs found |
| 279 | `express_behind_modsecurity` | express + ModSecurity | WAF detected, some categories blocked, fewer raw findings |
| 280 | `express_behind_rate_limiter` | express + nginx rate limit | Rate limit detected, no 429 flood |
| 281 | `express_behind_bot_detection` | express + bot detector | Bot detection identified, persona rotation helps |
| 282 | `express_behind_full_defense` | express + all defenses | All defenses fingerprinted, report reflects defense posture |

### 3.2 Flask Vulnerable App Tests

| # | Test Name | Fixture | What It Proves |
|---|-----------|---------|---------------|
| 283 | `flask_full_scan_ground_truth` | flask-vuln-app | Full pipeline → findings match ground-truth.json |
| 284 | `flask_ssti_detected` | flask-vuln-app | Jinja2 SSTI payload triggers finding |
| 285 | `flask_source_recon` | flask-vuln-app | poetry.lock → CVEs found |

### 3.3 GraphQL Vulnerable App Tests

| # | Test Name | Fixture | What It Proves |
|---|-----------|---------|---------------|
| 286 | `graphql_introspection_discovery` | graphql-vuln-app | Introspection enabled → all types discovered |
| 287 | `graphql_no_introspection_fallback` | graphql-vuln-app (introspection disabled) | Fallback discovery → fields found |
| 288 | `graphql_auth_bypass` | graphql-vuln-app | Auth bypass on mutation → finding present |

### 3.4 Cross-Scan Tests

| # | Test Name | Fixture | What It Proves |
|---|-----------|---------|---------------|
| 289 | `graph_persistence_across_scans` | express-vuln-app | Scan 1 → save graph → Scan 2 → loads previous state |
| 290 | `diff_mode_sarif_only_new_findings` | express-vuln-app | Scan 1 → add new vuln → Scan 2 → diff SARIF has only new finding |
| 291 | `scan_history_adaptive_selection` | express-vuln-app | Scan 1 records payload outcomes → Scan 2 uses history for UCB1 |
| 292 | `checkpoint_resume_mid_scan` | express-vuln-app | Interrupt after fingerprint → resume → scan completes normally |

### 3.5 Multi-Format Report Tests

| # | Test Name | Fixture | What It Proves |
|---|-----------|---------|---------------|
| 293 | `developer_report_sarif_with_fixes` | express-vuln-app | Developer format → SARIF with inline fix suggestions |
| 294 | `security_report_attack_chains` | express-vuln-app | Security format → ATT&CK technique IDs, defense gap analysis |
| 295 | `executive_report_summary` | express-vuln-app | Executive format → risk ratings, top-N findings, remediation priority |

### 3.6 Stealth Mode Tests

| # | Test Name | Fixture | What It Proves |
|---|-----------|---------|---------------|
| 296 | `stealth_default_mode` | express + rate limiter | Default stealth → some 429s possible |
| 297 | `stealth_paranoid_mode` | express + rate limiter | Paranoid stealth → zero 429s, slower scan |
| 298 | `stealth_aggressive_mode` | express + rate limiter | Aggressive stealth → faster scan, may trigger limits |

### 3.7 Audit Trail End-to-End Tests

| # | Test Name | Fixture | What It Proves |
|---|-----------|---------|---------------|
| 299 | `audit_trail_full_scan_integrity` | express-vuln-app | Full scan → verify audit log → chain intact, all phases logged |
| 300 | `audit_replay_matches_scan_results` | express-vuln-app | Replay audit → snapshot.findings matches SARIF findings |

---

## Part 4: Test Coverage Matrix

### By Vulnerability Class (16 classes × coverage dimensions)

| VulnerabilityClass | Payload Gen | Anomaly Detection | WAF Blocking | Counterfactual | SARIF CWE | Narrative | Risk Score | Test #s |
|---|---|---|---|---|---|---|---|---|
| SqlInjection | ✓ #76 | ✓ #68 | ✓ #88 | ✓ #72 | ✓ #152 | ✓ #157 | ✓ #148 | 186 |
| CrossSiteScripting | ✓ #77 | ✓ #69 | ✓ #88 | ✓ #72 | ✓ #153 | ✓ #157 | ✓ #148 | 187 |
| CommandInjection | ✓ #78 | ✓ #68 | ✓ #88 | ✓ #72 | ✓ #151 | ✓ #157 | ✓ #148 | 188 |
| PathTraversal | ✓ #78 | ✓ #68 | ✓ #88 | ✓ #72 | ✓ #151 | ✓ #157 | ✓ #148 | 189 |
| ServerSideRequestForgery | ✓ #78 | ✓ #68 | ✓ #88 | ✓ #72 | ✓ #151 | ✓ #157 | ✓ #148 | 190 |
| ServerSideTemplateInjection | ✓ #78 | ✓ #68 | ✓ #88 | ✓ #72 | ✓ #151 | ✓ #157 | ✓ #148 | 191 |
| BrokenAuthentication | ✓ #78 | ✓ #66 | — | ✓ #72 | ✓ #151 | ✓ #157 | ✓ #148 | 192 |
| BrokenAuthorization | ✓ #78 | ✓ #66 | — | ✓ #72 | ✓ #151 | ✓ #157 | ✓ #148 | 200 |
| SecurityMisconfiguration | ✓ #78 | ✓ #66 | — | ✓ #72 | ✓ #151 | ✓ #157 | ✓ #148 | 199 |
| SensitiveDataExposure | ✓ #78 | ✓ #68 | — | ✓ #72 | ✓ #151 | ✓ #157 | ✓ #148 | 197 |
| InsecureDeserialization | ✓ #78 | ✓ #68 | ✓ #88 | ✓ #72 | ✓ #151 | ✓ #157 | ✓ #148 | 198 |
| HeaderInjection | ✓ #78 | ✓ #68 | — | ✓ #72 | ✓ #151 | ✓ #157 | ✓ #148 | 195 |
| OpenRedirect | ✓ #78 | ✓ #66 | — | ✓ #72 | ✓ #151 | ✓ #157 | ✓ #148 | 194 |
| CrlfInjection | ✓ #78 | ✓ #68 | — | ✓ #72 | ✓ #151 | ✓ #157 | ✓ #148 | 196 |
| KnownVulnerableDependency | — | — | — | — | ✓ #151 | ✓ #157 | ✓ #148 | 206 |
| InsufficientInputValidation | ✓ #78 | ✓ #68 | — | ✓ #72 | ✓ #151 | ✓ #157 | ✓ #148 | 201 |

### By Defense Type

| Defense | Detection | Fingerprinting | Evasion Effect | Report Impact | Test #s |
|---|---|---|---|---|---|
| ModSecurity WAF | ✓ #82 | ✓ #88 | ✓ #279 | ✓ #149 | 279, 282 |
| Cloudflare WAF | ✓ #83 | ✓ #88 | — | ✓ #149 | 83 |
| AWS WAF | ✓ #84 | ✓ #88 | — | ✓ #149 | 84 |
| Imperva WAF | ✓ #85 | ✓ #88 | — | ✓ #149 | 85 |
| Akamai WAF | ✓ #86 | ✓ #88 | — | ✓ #149 | 86 |
| Rate Limiting | ✓ #89-91 | — | ✓ #297 | — | 280, 296-298 |
| Bot Detection | ✓ #92-95 | — | ✓ #281 | — | 281 |

### By Persona

| PersonaId | Header Correctness | Timing Jitter | TLS Fingerprint | Session Mgmt | Test #s |
|---|---|---|---|---|---|
| ChromeDesktop | ✓ #117 | ✓ #125,126 | ✓ #131 | ✓ #128 | 113, 117 |
| FirefoxDesktop | ✓ #118 | ✓ #125,126 | ✓ #132 | ✓ #128 | 118 |
| SafariDesktop | ✓ #116 | ✓ #127 | ✓ #130 | ✓ #128 | — |
| ChromeMobile | ✓ #116 | ✓ #125 | ✓ #130 | ✓ #128 | — |
| Googlebot | ✓ #120 | ✓ #125 | ✓ #130 | — | 120 |
| EdgeDesktop | ✓ #116 | ✓ #125 | ✓ #131 | ✓ #128 | — |
| OperaDesktop | ✓ #116 | ✓ #125 | ✓ #130 | ✓ #128 | — |
| SafariMobile | ✓ #116 | ✓ #127 | ✓ #130 | ✓ #128 | — |
| CurlClient | ✓ #119 | ✓ #125 | ✓ #135 | — | 119 |
| PythonRequests | ✓ #116 | ✓ #125 | ✓ #130 | — | — |

### By Lock File Format

| Format | Parsing | CVE Lookup | End-to-End Recon | Test #s |
|---|---|---|---|---|
| Cargo.lock | ✓ #32 | ✓ #38 | ✓ #43 | 206, 278 |
| package-lock.json v2 | ✓ #33 | ✓ #38 | ✓ #43 | 278 |
| package-lock.json v1 | ✓ #34 | ✓ #38 | — | — |
| poetry.lock | ✓ #35 | ✓ #38 | — | 285 |
| Gemfile.lock | ✓ #36 | ✓ #38 | — | — |
| go.sum | ✓ #37 | ✓ #38 | — | — |

### By Framework (Route Discovery)

| Framework | Route Parsing | Live Server | End-to-End | Test #s |
|---|---|---|---|---|
| Express | ✓ #52 | ✓ #44 | ✓ #276 | 52, 276 |
| Flask | ✓ #53 | — | ✓ #283 | 53, 283 |
| FastAPI | ✓ #54 | — | — | 54 |
| Django | ✓ #55 | — | — | 55 |
| Spring | ✓ #56 | — | — | 56 |

---

## Part 5: Implementation Order

### Phase A — Foundation (must be first)
1. Create `test-support` crate with fixture_server, vulnerable_app, assertions
2. Add axum + tower + tokio to workspace dev-dependencies
3. Create basic VulnerableApp with SQLi + XSS + health endpoints

### Phase B — Per-Crate Tier 1 Tests (parallelizable)
4. Protocol integration tests (#1-#18)
5. Knowledge graph integration tests (#19-#31)
6. Passive recon integration tests (#32-#43)
7. Enumeration integration tests (#44-#61)
8. Fuzzing integration tests (#62-#111)
9. Evasion engine integration tests (#112-#136)
10. Chain synthesis integration tests (#137-#147)
11. Reporting integration tests (#148-#164)
12. Audit log integration tests (#165-#180)
13. Supervisor integration tests (#181-#185)
14. Orchestrator integration tests (#186-#265)
15. Python hypothesis engine integration tests (#266-#275)

### Phase C — Docker Fixtures (after Tier 1 stable)
16. Create express-vuln-app Docker fixture
17. Create flask-vuln-app Docker fixture
18. Create graphql-vuln-app Docker fixture
19. Create rust-vuln-app Docker fixture
20. Create compose files (plain + with each defense layer)

### Phase D — Tier 2 Docker Tests
21. Express app integration tests (#276-#282)
22. Flask app integration tests (#283-#285)
23. GraphQL app integration tests (#286-#288)
24. Cross-scan tests (#289-#292)
25. Report format tests (#293-#295)
26. Stealth mode tests (#296-#298)
27. Audit trail end-to-end tests (#299-#300)

### Phase E — CI/CD
28. GitHub Actions workflow for Tier 1 (every PR)
29. GitHub Actions workflow for Tier 2 (merge to main)
30. Ground truth validation script

---

## Total Test Count

| Category | Count |
|---|---|
| Protocol integration | 18 |
| Knowledge graph integration | 13 |
| Passive recon integration | 12 |
| Enumeration integration | 18 |
| Fuzzing integration | 50 |
| Evasion engine integration | 25 |
| Chain synthesis integration | 11 |
| Reporting integration | 17 |
| Audit log integration | 16 |
| Supervisor integration | 5 |
| Orchestrator integration | 80 |
| Python hypothesis engine | 10 |
| **Tier 1 Total** | **275** |
| Docker: Express app | 7 |
| Docker: Flask app | 3 |
| Docker: GraphQL app | 3 |
| Docker: Cross-scan | 4 |
| Docker: Report formats | 3 |
| Docker: Stealth modes | 3 |
| Docker: Audit trail | 2 |
| **Tier 2 Total** | **25** |
| **Grand Total** | **300** |

These 300 integration tests, combined with the existing 2,016 unit tests (Rust) + 214 unit tests (Python), provide complete coverage of all 16 vulnerability classes, 5 WAF vendors, 10 personas, 5 framework parsers, 5 dependency ecosystems, 28 edge triples, 5 anomaly types, 4 evidence levels, 3 report formats, and all cross-crate data flow boundaries.
