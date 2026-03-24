# aegis-orchestrator

<!-- metadata: crate purpose, public API, modules, CLI binary, scan pipeline, LLM bridge, checkpoints, convergence, telemetry, distributed, benchmark -->

## Purpose

The integration crate — provides the `aegis` CLI binary and wires all 11 pipeline crates into a coherent scan pipeline. Manages the full scan lifecycle: CLI parsing, target authorization, audit logging setup, scan phases execution (recon → crawl → fingerprint → fuzz*N → analyze*N → dom_verify → report), checkpoint/resume, LLM hypothesis bridge, interactive mode, distributed coordination, telemetry, and graph persistence.

## Crate Type
Library + Binary (`aegis`)

## Dependencies on Workspace Crates (Runtime)
- `aegis-protocol`, `aegis-knowledge-graph`, `aegis-audit-log`, `aegis-supervisor`
- `aegis-passive-recon`, `aegis-enumeration`, `aegis-fuzzing`, `aegis-chain-synthesis`
- `aegis-reporting`, `aegis-evasion-engine`, `aegis-crawler`

## Dependencies (Dev/Test Only)
- `aegis-compliance`, `aegis-discovery`, `aegis-exploiter`

## External Dependencies
- `clap` 4 (derive) — CLI parsing
- `tokio` 1 (full) — async runtime
- `tracing`, `tracing-subscriber` — structured logging
- `rusqlite` 0.32 (bundled) — scan history + checkpoint SQLite
- `reqwest` 0.12 (blocking + json) — update-db + OpenAPI discovery
- `rand` 0.9 — HMAC keys, master key
- `serde`, `serde_json` — config/checkpoint serialization
- `ed25519-dalek` 2 — scope attestation + signed config verification
- `url` 2 — URL validation

## Module Structure

| Module | Description |
|--------|-------------|
| `scan_config` | `ScanConfig` (clap Parser), `ScanPreset`, all CLI option groups, validation functions |
| `pipeline` | `run_scan()`, `ScanContext`, `ScanSummary`, `PipelineError`, all phase orchestration |
| `phase_recon` | Passive recon phase, `run_recon_standalone()` |
| `phase_fingerprint` | Defense fingerprinting + endpoint discovery (OpenAPI/GraphQL/source) |
| `phase_crawl` | Crawler output → knowledge graph operations |
| `phase_fuzz` | Fuzz phase, `run_fuzz()`, `FuzzPhaseResult`, `fuzzable_classes()` |
| `phase_analyze` | Attack graph construction, chain-synthesis phase |
| `phase_dom_verify` | DOM-based XSS verification phase |
| `phase_report` | SARIF generation, diff-mode reporting |
| `phase_error` | `PhaseError` enum (typed phase errors) |
| `checkpoint` | `ScanCheckpoint`, save/load/delete, `should_skip_phase()` |
| `convergence` | `RefutedTracker` (monotonic set of refuted hypotheses) |
| `hypothesis_bridge` | `HypothesisBridge` (Python subprocess IPC) |
| `scan_config` | `ScanConfig`, option groups, preset application |
| `calibration` | Confidence calibration from ground truth |
| `benchmark` | `BenchmarkEvaluation`, ground truth comparison (precision/recall/F1) |
| `interactive` | `InteractiveSession`, command parser, `InteractiveResponse` |
| `pipeline_composer` | `PipelineDefinition`, topological ordering (Kahn's algorithm) |
| `scan_history` | `ScanHistoryDb` (SQLite adaptive payload history) |
| `graph_persistence` | `load_or_create_graph()`, `save_graph_if_configured()` |
| `distributed` | `DistributedConfig`, coordinator/worker mode, heartbeat detection |
| `distributed_transport` | `DistributedTransport` — network layer for distributed coordinator/worker |
| `auth_session` | `AuthSession`, `AuthSessionManager` — manages authenticated scan sessions |
| `idor_analyzer` | `IdorAnalyzer` — heuristic IDOR detection from graph patterns |
| `scan_strategy` | `AdaptiveScanStrategy`, `StrategyDecision` — adaptive scan behavior selection |
| `telemetry` | `TelemetryCollector`, `TelemetryConfig` (opt-in aggregate metrics) |
| `endpoint_similarity` | TF-IDF + character trigram similarity for hypothesis transfer |
| `update_db` | `run_update_db()`, OSV API batch queries, `UpdateDbArgs/Summary` |
| `attest` | Ed25519 scope attestation generation |
| `actor` | `ScanActor` trait, phase actor implementations |
| `util` | `timestamp_ms()` helper |

## Public API Summary

### run_scan (main entry point)

```rust
pub async fn run_scan(config: ScanConfig) -> Result<ScanSummary, PipelineError>
```

Full scan pipeline. Validates config, sets up audit writer, loads/creates graph, runs all phases, saves graph, exports telemetry, verifies audit.

### ScanContext

```rust
pub struct ScanContext {
    pub config: ScanConfig,
    pub graph: Box<dyn GraphStore>,
    pub defense_profile: Option<DefenseProfile>,
    pub capabilities: CapabilityManager,
    pub refuted: RefutedTracker,
    pub scope_attestation: Option<SignedScopeAttestation>,
    pub auth_flow: Option<AuthFlow>,
    pub auth_inputs: HashMap<String, String>,
    pub llm_payloads: Vec<String>,   // LLM-generated payloads for next fuzz iteration
}
```

Threaded through all phase functions. `graph` is `Box<dyn GraphStore>` — enables test injection.

### PipelineError

```rust
pub enum PipelineError {
    Config(ConfigError) | AuditLog(String) | PipelineComposer(ComposerError) |
    Recon(PhaseError) | Crawl(PhaseError) | Fingerprint(PhaseError) |
    Fuzz(PhaseError) | Analysis(PhaseError) | DomVerify(PhaseError) |
    Report(PhaseError) | InteractiveQuit
}
```

### PhaseError

```rust
pub enum PhaseError {
    Graph(GraphError) | Io(io::Error) | Serialization(serde_json::Error) |
    Checkpoint(CheckpointError) | ReportFormat(String) |
    UnknownExportFormat(String) | FilesystemWalk(String)
}
impl std::error::Error for PhaseError  // source() chain implemented
```

### ScanSummary

```rust
pub struct ScanSummary {
    pub total_findings: u64,
    pub total_operations: u64,
    pub phases_completed: u32,
    pub sarif_path: String,
    pub audit_log_path: Option<String>,
    pub hmac_key_path: Option<String>,
    pub metrics: ScanMetrics,
    pub new_findings_count: Option<u64>,     // diff vs previous scan (--graph-db)
    pub previously_known_count: Option<u64>, // findings already known
    pub audit_verified: Option<bool>,        // None if --no-audit
    pub telemetry_path: Option<String>,      // None if --telemetry not set
}
```

### HypothesisBridge

```rust
pub struct HypothesisBridge { /* subprocess handle */ }
impl HypothesisBridge {
    pub fn start(python_cmd: &str) -> Result<Self, BridgeError>
    pub fn generate_hypotheses(
        &mut self,
        scan_context: ScanContextJson,
        vulnerability_class: String,
        feedback_summary: Option<String>,
    ) -> Result<GenerationResultJson, BridgeError>
    pub fn compile_payloads(
        &mut self,
        hypotheses: Vec<HypothesisJson>,
    ) -> Result<CompilationResultJson, BridgeError>
}
```

### RefutedTracker

```rust
pub struct RefutedTracker { /* HashSet<String> */ }
impl RefutedTracker {
    pub fn new() -> Self
    pub fn record_refuted(&mut self, key: String)
    pub fn is_refuted(&self, key: &str) -> bool
    pub fn refuted_count(&self) -> usize
}
```

Monotonic — once refuted, never un-refuted. Used to prevent re-testing payloads that produced zero findings.

## Key Implementation Notes

- **Subcommand dispatch before clap**: `recon`, `attest`, `update-db` use manual `args[1]` matching before clap parsing. This allows pre-runtime execution (no tokio).
- **`update-db` uses reqwest::blocking**: Runs before tokio runtime; has its own thread with 3 retries (2s/4s/8s), 120s timeout.
- **Crawl phase uses `CrawlResult::default()`**: Live crawler invocation is not yet wired into `run_crawl_phase`. The crawl result is empty — endpoints come from fingerprint phase discovery.
- **`--resume` requires `--graph-db`**: Without graph-db, resume logs a warning and proceeds without checkpoint.
- **Interactive mode uses OS thread**: Dedicated `"interactive-stdin"` thread with `std::sync::Mutex` — not a Tokio task. Cannot use `tokio::Mutex` because stdin blocking would starve the runtime.
- **Telemetry is opt-in**: `TelemetryConfig { enabled: false }` by default. When enabled, only exports phase timings, finding counts, LLM call counts — never raw findings, payloads, or endpoint URLs.
- **`WORKSPACE_CRATE_COUNT = 11`** hardcoded constant (outdated — actual workspace has 17 crates).
- **Capability tokens are advisory**: Token validation failures log warnings but don't abort phases.

## Usage Context

This is the only binary crate. All other crates are libraries it composes. Entry point: `crates/orchestrator/src/main.rs`.
