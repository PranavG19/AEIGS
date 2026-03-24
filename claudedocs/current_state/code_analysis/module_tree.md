# AEGIS Full Module Tree

<!-- metadata: module hierarchy, file paths, public/private modules, all 17 crates -->

## Convention

All test files follow `{module}_test.rs` adjacent to `{module}.rs` and are included via `#[path]` attribute in `#[cfg(test)]` blocks. They are excluded from this tree for clarity.

Module visibility:
- `pub mod` = public module (exported to crate consumers)
- `mod` + `pub use module::*` = private module re-exported via wildcard
- `mod` (no pub use) = fully private

---

## aegis-protocol

Root: `crates/protocol/src/lib.rs`

```
aegis_protocol
├── pub mod audit           → AuditEventType, AuditEntry
├── pub mod capability      → Permission, CapabilityToken
├── pub mod defense_context → DefenseContext
├── pub mod edge            → EdgeLabel, EdgeData, EDGE_WHITELIST, is_valid_edge(), valid_edge_count()
├── pub mod finding         → Confidence, FindingConfidence, FindingId, EvidenceLevel, VulnerabilityClass, FindingData
├── pub mod hypothesis_ipc  → ScanContextIpc, HypothesisIpc, DefenseContextIpc, BridgeRequest, BridgeResponse
├── pub mod ipc             → IpcMessage, IpcRequest, IpcResponse (general inter-module IPC, distinct from hypothesis_ipc)
├── pub mod node            → NodeType, NodeData
├── pub mod operation       → GraphOperation, ModuleIdentifier, OperationLogEntry
├── pub mod request         → ParameterLocation, FuzzRequest, FuzzResponse
├── pub mod scan_event      → ScanEvent, ScanEventEnvelope
├── pub mod scope_attestation → ScopeDocument, SignedScopeAttestation, verify_attestation(), load_attestation()
├── pub mod signed_config   → SignableConfig, SignedConfig, verify_signed_config(), verify_config_matches()
└── pub mod target_validation → validate_target_with_override(), validate_target_is_localhost()
```

---

## aegis-knowledge-graph

Root: `crates/knowledge-graph/src/lib.rs`

```
aegis_knowledge_graph
├── pub mod graph           → KnowledgeGraph, GraphError, GraphMetadata (re-exported)
├── pub mod graph_store     → GraphStore trait (re-exported)
├── pub mod node_store      → NodeStore (pub via re-export)
├── pub mod edge_store      → EdgeStore (pub via re-export)
├── pub mod finding_store   → FindingStore (pub via re-export)
├── pub mod operation_log   → OperationLog, ValidationError, OperationLogError (pub via re-export)
└── pub mod query
    ├── pub mod path_queries  → find_paths_between(), shortest_path(), PathResult, ShortestPathResult
    └── pub mod reachability  → reachable_from(), cut_vertices(), betweenness_centrality(), nodes_by_type()
```

---

## aegis-audit-log

Root: `crates/audit-log/src/lib.rs`

```
aegis_audit_log
├── pub mod hash_chain      → HashChain, Hash type alias
├── pub mod hmac_signer     → HmacSigner, MacBytes type alias
├── pub mod log_writer      → AuditWriter trait, AuditLogWriter, NoOpAuditLogWriter, LogWriterError
├── pub mod log_verifier    → verify_log(), LogVerificationReport
└── pub mod event_store     → replay_from_entries(), ScanSnapshot, SnapshotDiff, diff_snapshots()
```

---

## aegis-supervisor

Root: `crates/supervisor/src/lib.rs`

```
aegis_supervisor
├── pub mod process_manager   → ProcessManager, ProcessState
└── pub mod capability_manager → CapabilityManager, ModulePermissionPolicy
```

---

## aegis-passive-recon

Root: `crates/passive-recon/src/lib.rs`

```
aegis_passive_recon
├── pub mod dependency_parser  → ParsedDependency, parse_cargo_lock(), (other lock file parsers)
├── pub mod vuln_database      → VulnDatabase, VulnerabilityRecord, VulnerabilityMatch, VulnDatabaseError
└── pub mod filesystem_walker  → WalkResult, FileInfo, FileClassification, walk_directory()
```

---

## aegis-enumeration

Root: `crates/enumeration/src/lib.rs`

```
aegis_enumeration
├── pub mod route_parser      → Framework, HttpMethod, ParsedRoute, parse_routes_from_file()
├── pub mod introspection     → IntrospectedEndpoint, parse_openapi_json(), parse_graphql_introspection()
├── pub mod auth_matrix       → AuthMatrix, auth_matrix_from_graph()
├── pub mod graphql_discovery → GraphQlDiscoveryResult, discover_graphql_fallback()
└── pub mod auth_flow         → AuthFlow, AuthFlowStep, execute_auth_flow()
```

---

## aegis-fuzzing

Root: `crates/fuzzing/src/lib.rs`

```
aegis_fuzzing
├── pub mod scheduler       → FuzzTarget, FuzzScheduler
├── pub mod mutator         → PayloadMutator, MutationOrigin, TaggedPayload, generate_tagged_payloads()
├── pub mod executor        → FuzzExecutor
├── pub mod oracle          → AnomalyOracle, CounterfactualResult
├── pub mod stealth_config  → StealthConfig
├── pub mod defense_profile [pub use *] → DefenseProfile, WafFingerprint, RateLimitProfile, BotDetectionResult
├── pub mod waf_fingerprinter [pub use *] → probe_waf(), WafVendor
├── pub mod rate_limit_detector [pub use *] → probe_rate_limit()
├── pub mod bot_detection_probe [pub use *] → probe_bot_detection()
├── pub mod payload_selector → PayloadSelector (UCB1)
├── pub mod streaming_fuzzer → StreamFuzzTarget, StreamFuzzResult, StreamProtocol
├── pub mod request_patterns → BrowsingPattern, RequestBatch, CoverTrafficConfig
├── pub mod confirmation    → (finding confirmation / retest)
├── pub mod cors_detector [pub use *] → detect_cors_misconfiguration()
├── pub mod graphql_tester [pub use *] → test_graphql_vulnerabilities()
├── pub mod header_analyzer [pub use *] → analyze_security_headers()
├── pub mod idor_tester [pub use *] → test_idor_heuristics()
├── pub mod mass_assignment_tester [pub use *] → test_mass_assignment()
├── pub mod race_tester [pub use *] → test_race_conditions()
├── pub mod cloud_detector [pub use *] → detect_cloud_misconfiguration()
└── pub mod subdomain_takeover [pub use *] → detect_subdomain_takeover()
```

**Note:** The CLAUDE.md lists fewer modules than actually present. Modules added since: `confirmation`, `cors_detector`, `graphql_tester`, `header_analyzer`, `idor_tester`, `mass_assignment_tester`, `race_tester`, `cloud_detector`, `subdomain_takeover`.

---

## aegis-chain-synthesis

Root: `crates/chain-synthesis/src/lib.rs`

```
aegis_chain_synthesis
├── pub mod attack_graph  → AttackGraph, AttackNode, AttackEdge, build_attack_graph()
├── pub mod path_analysis → find_attack_paths(), MitigationResult, DefenseGapReport, graph_influence_ranking()
└── pub mod graph_export  → export_dot(), export_d3json()
```

---

## aegis-reporting

Root: `crates/reporting/src/lib.rs`

```
aegis_reporting
├── pub mod risk_scorer          → RiskScorer, score_finding()
├── pub mod sarif_emitter        → SarifEmitter, SarifFinding, emit_sarif()
├── pub mod certificate_serializer → CertificateType, serialize_certificate(), deserialize_certificate()
├── pub mod narrative            → NarrativeGenerator, generate_narrative()
└── pub mod report_format        → ReportFormat, parse_report_format()
```

---

## aegis-evasion-engine

Root: `crates/evasion-engine/src/lib.rs`

```
aegis_evasion_engine
├── pub use encoding_transformer::* → EncodingTransformer
├── pub use header_transformer::*   → HeaderTransformer
├── pub use persona::*              → Persona, PersonaId, PersonaCatalog, load_persona_catalog()
├── pub use session_manager::*      → SessionManager
├── pub use timing_controller::*    → TimingController
├── pub use tls_config::*           → TlsFingerprint, TlsConfig, HttpClientBackend, FingerprintMapping
└── pub use transport::*            → EvasionTransport, EvasionTransportBuilder, TransportError
```

---

## aegis-crawler

Root: `crates/crawler/src/lib.rs`

```
aegis_crawler
└── (modules to be traced from lib.rs)
    CrawlResult (default = empty), crawler integration
    Uses chromiumoxide for headless Chrome CDP
```

---

## aegis-compliance

Root: `crates/compliance/src/lib.rs`

```
aegis_compliance
├── pub mod class_mapper      → VulnerabilityClass → CWE/OWASP mapping
├── pub mod compliance_mapper → OWASP Top 10 2021, API Security 2023, PCI-DSS mapping
├── pub mod context_adjuster  → Adjusts severity based on business context
├── pub mod cvss_scorer       → CvssScore, compute_cvss_score() (FIRST spec formula)
└── pub mod report_generator  → PentestReportGenerator (executive summary, finding narratives)
```

---

## aegis-discovery

Root: `crates/discovery/src/lib.rs`

```
aegis_discovery
├── pub use backup_scanner::*      → SENSITIVE_PATHS[40], scan_backup_files()
├── pub use brute_forcer::*        → DIRECTORY_WORDLIST[2013], brute_force_paths()
├── pub use graph_ops::*           → discovery_to_operations() (converts discoveries to graph ops)
├── pub use js_extractor::*        → extract_endpoints_from_js() (7 regex patterns)
├── pub use param_discoverer::*    → COMMON_PARAMETERS[67], discover_parameters()
├── pub use sitemap_parser::*      → parse_sitemap(), parse_robots_txt()
├── pub use tech_fingerprinter::*  → fingerprint_technology() (headers/HTML/cookies/paths)
├── pub use vhost_discoverer::*    → VHOST_PREFIXES[31], discover_vhosts()
└── pub use wordlist::*            → wordlist management
```

---

## aegis-exploiter

Root: `crates/exploiter/src/lib.rs`

```
aegis_exploiter
├── pub use wrapper::*         → ToolWrapper trait (subprocess management, timeout)
├── pub use runner::*          → run_tool()
├── pub use selector::*        → ToolSelector (choose appropriate tool for vuln class)
├── pub use checker::*         → pre-flight checks (tool availability)
├── pub use error::*           → ExploiterError
├── pub use jwt_tester::*      → JwtTester (alg:none, weak secret, expired, missing sig — native)
├── pub use sqlmap_wrapper::*  → SqlmapWrapper
├── pub use nuclei_wrapper::*  → NucleiWrapper (CVE template scanner)
├── pub use nmap_wrapper::*    → NmapWrapper (port scanner)
├── pub use subfinder_wrapper::* → SubfinderWrapper (subdomain enumeration)
└── pub use oast_wrapper::*    → OastWrapper (Interactsh blind vulnerability detection)
```

---

## aegis-proxy

Root: `crates/proxy/src/lib.rs`

```
aegis_proxy
├── pub use proxy::*      → RecordingProxy, ProxyConfig
├── pub use repeater::*   → RequestRepeater, RepeaterResult
├── pub use intruder::*   → Intruder, AttackMode (Sniper|BatteringRam|Pitchfork|ClusterBomb)
├── pub use types::*      → ProxyRequest, ProxyResponse, RecordedExchange
└── pub use graph_sync::* → sync_to_knowledge_graph()
```

---

## aegis-test-support

Root: `crates/test-support/src/lib.rs`

```
aegis_test_support
├── pub use assertions::*          → assertion helpers for test verification
├── pub use fixture_server::TestServer  → in-process axum HTTP server
├── pub use mock_graph::MockGraphStore  → fake GraphStore for unit tests (no locking)
├── pub use mock_transport::MockFuzzTransport → fake EvasionTransport for fuzz tests
├── pub use temp_workspace::*      → temporary workspace helpers
└── pub use vulnerable_app::{GroundTruth, GroundTruthEntry, VulnerableApp, VulnerableAppBuilder}
    → programmatic vulnerable application builder for ground truth testing
```

---

## aegis-orchestrator

Root: `crates/orchestrator/src/lib.rs`

```
aegis_orchestrator
├── pub mod actor            → ScanActor trait, phase actor implementations
├── pub mod attest           → Ed25519 scope attestation generation
├── pub mod benchmark        → BenchmarkEvaluation, GroundTruth, BenchmarkFixture
├── pub mod calibration      → confidence calibration from ground truth
├── pub mod checkpoint       → ScanCheckpoint, save/load/delete
├── pub mod convergence      → RefutedTracker
├── pub mod distributed      → DistributedConfig, CoordinatorState, WorkAssignment
├── pub mod distributed_transport → DistributedTransport (separate from distributed.rs)
├── pub mod auth_session     → AuthSession, AuthSessionManager
├── pub mod idor_analyzer    → IdorAnalyzer (heuristic IDOR detection)
├── pub mod scan_strategy    → AdaptiveScanStrategy, StrategyDecision
├── pub mod endpoint_similarity → TF-IDF + trigram similarity
├── pub mod graph_persistence  → load_or_create_graph(), save_graph_if_configured()
├── pub mod hypothesis_bridge  → HypothesisBridge, ScanContextJson, HypothesisJson
├── pub mod interactive      → InteractiveSession, InteractiveCommand, InteractiveResponse
├── pub mod phase_analyze    → run_analyze()
├── pub mod phase_crawl      → crawl_result_to_operations()
├── pub mod phase_dom_verify → run_dom_verify()
├── pub mod phase_error      → PhaseError
├── pub mod phase_fingerprint → probe_defenses(), endpoints_to_operations()
├── pub mod phase_fuzz       → run_fuzz(), FuzzPhaseResult, fuzzable_classes()
├── pub mod phase_recon      → run_recon_standalone()
├── pub mod phase_report     → run_report_with_previous(), export_attack_graph(), compute_new_findings()
├── pub mod pipeline         → run_scan(), ScanContext, ScanSummary, PipelineError
├── pub mod pipeline_composer → PipelineDefinition, PipelineStage, PhaseType (Source|Transform|Sink|Observer), validate_pipeline()
├── pub mod scan_config      → ScanConfig, ScanPreset, StealthOptions, PipelineOptions, ...
├── pub mod scan_history     → ScanHistoryDb, ScanHistoryEntry
├── pub mod telemetry        → TelemetryCollector, TelemetryConfig
├── pub mod update_db        → run_update_db(), UpdateDbArgs, UpdateDbSummary
└── pub mod util             → timestamp_ms()
```
