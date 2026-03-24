# AEGIS Interfaces and Boundaries

<!-- metadata: CLI interface, IPC protocol, Python-Rust bridge, configuration, scan events, security interfaces -->

## CLI Interface

Binary: `aegis` (built from `crates/orchestrator/src/main.rs`)

### Usage Patterns

```bash
# Standard scan
aegis --target http://localhost:3000 [OPTIONS]

# Preset-based scan
aegis -p thorough --target http://localhost:3000

# Subcommands (manual dispatch, before clap)
aegis recon --source-dir ./myapp
aegis attest [args]
aegis update-db --db-path ~/.aegis/vuln.db --source-dir ./myapp
```

---

### ScanConfig — Full CLI Argument Reference

Source: `crates/orchestrator/src/scan_config.rs`

#### Common Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--preset`, `-p` | `quick\|thorough\|paranoid\|benchmark` | None | Preset configuration bundle (overrideable by explicit flags) |
| `--target` | String | **required** | Target URL to scan (localhost enforced by default) |
| `--output`, `-o` | Path | `aegis-report.sarif` | SARIF report output path |
| `--report-format`, `-f` | `developer\|security\|executive` | `developer` | Report format |
| `--source-dir` | Path | None | Local source directory for recon and route parsing |
| `--verbose`, `-v` | bool | false | Enable tracing output (uses RUST_LOG env filter) |

#### ScanPreset Values

| Preset | max-iterations | convergence-threshold | stealth-level | LLM |
|--------|---------------|----------------------|---------------|-----|
| `quick` | 1 | default | default | disabled |
| `thorough` | 3 | 2 | default | enabled |
| `paranoid` | 5 | 3 | paranoid | enabled |
| `benchmark` | 1 | default | default | enabled |

#### StealthOptions (`--help-heading: Tuning`)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--persona` | `chrome\|firefox\|safari\|mobile\|googlebot` | `chrome` | HTTP persona for requests |
| `--stealth` | bool | false | Enable stealth mode |
| `--stealth-level` | `default\|aggressive\|paranoid` | `default` | Stealth intensity |
| `--max-rps` | u32 | None (unlimited) | Maximum requests per second |
| `--skip-evasion` | bool | false | Disable timing jitter and header transforms |
| `--accept-self-signed` | bool | false | Accept self-signed TLS certs (safe for localhost) |
| `--persona-catalog` | Path | None | Custom persona catalog JSON |

#### PipelineOptions (`--help-heading: Tuning`)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--max-iterations` | u32 | 1 | Maximum fuzz→analyze iterations |
| `--convergence-threshold` | u32 | 2 | Consecutive zero-finding rounds before stopping |
| `--skip-fingerprint` | bool | false | Skip defense fingerprint phase |
| `--skip-crawl` | bool | false | Skip browser crawl phase |
| `--paranoia-sweep` | bool | false | Enable paranoia sweep mode |
| `--resume` | bool | false | Resume from last checkpoint (requires `--graph-db`) |
| `--interactive` | bool | false | Enable interactive scan control via stdin |

#### LlmOptions (`--help-heading: Advanced`)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--no-llm` | bool | false | Skip hypothesis-engine subprocess entirely |
| `--bypass-corpus` | Path | None | Path to bypass examples JSON corpus |
| `--python-cmd` | String | `python3` | Python interpreter for hypothesis-engine subprocess |

#### AuditOptions (`--help-heading: Advanced`)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--no-audit` | bool | false | Disable audit logging (default: mandatory) |
| `--scope-attestation` | Path | None | Ed25519-signed scope attestation JSON |
| `--signed-config` | Path | None | Ed25519-signed scan configuration JSON |
| `--i-am-authorized` | bool | false | Self-authorize remote scanning (recorded in audit) |

#### ScopeOptions (`--help-heading: Advanced/Tuning`)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--include-endpoints` | Vec<String> | None | Allowlist endpoint paths for fuzzing |
| `--exclude-endpoints` | Vec<String> | None | Denylist endpoint paths |
| `--context-file` | Path | None | JSON BusinessContext file (excluded/critical/pii endpoints, known issues) |
| `--graph-db` | Path | None | Persistent graph database (enables incremental scanning and diff reports) |
| `--history-db` | Path | None | SQLite scan history DB (enables adaptive payload selection) |
| `--export-graph` | `dot\|d3json` | None | Export attack graph format |
| `--vuln-db` | Path | `~/.aegis/vuln.db` | Vulnerability database path |

#### AuthOptions (`--help-heading: Advanced`)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--auth-flow` | Path | None | JSON auth flow definition file |
| `--auth-input` | Vec<KEY=VALUE> | [] | Template variables for auth flow (repeatable) |

#### DistributedOptions (`--help-heading: Distributed`)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--distributed` | bool | false | Enable distributed coordinator mode |
| `--coordinator-addr` | String | `127.0.0.1:9100` | Bind address for coordinator |
| `--workers` | usize | 1 | Number of workers to wait for |
| `--worker-connect` | String | None | Connect to coordinator (worker mode) |
| `--worker-id` | String | `worker-0` | Worker identifier |

#### Other Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--telemetry` | bool | false | Enable opt-in aggregate telemetry (phase timings, counts, LLM usage — never raw findings/payloads) |

---

## Python-Rust IPC Interface

Source: `crates/protocol/src/hypothesis_ipc.rs`, `crates/orchestrator/src/hypothesis_bridge.rs`

**Transport:** Unix domain socket at `/tmp/aegis-hypothesis-{pid}-{timestamp}.sock`
**Framing:** 4-byte little-endian u32 length prefix + JSON payload (max frame: 64 MiB)
**Startup:** Python subprocess spawned with `--socket <path>` arg; 10s handshake timeout; 120s request timeout
**Cleanup:** Socket file deleted on `HypothesisBridge` drop (RAII)

### BridgeRequest (Rust → Python)

Internally tagged with `"type"` field (serde `#[serde(tag = "type")]`):

```json
// GenerateHypotheses
{
  "type": "GenerateHypotheses",
  "request_id": 1,
  "scan_context": {
    "technology_stack": ["express", "better-sqlite3"],
    "findings_summary": ["SQL Injection"],
    "high_centrality_nodes": [],
    "defense_posture": {},
    "class_confirmation_rates": {"SqlInjection": 0.8},
    "model_id": null
  },
  "vulnerability_class": "",
  "feedback_summary": "Fuzzed 5 endpoints..."
}

// CompilePayloads
{
  "type": "CompilePayloads",
  "request_id": 2,
  "hypotheses": [
    {
      "vulnerability_class": "SqlInjection",
      "description": "Login endpoint accepts raw SQL in username param",
      "confidence": 0.85,
      "test_specification": "..."
    }
  ]
}

// EvasionGenerate
{
  "type": "EvasionGenerate",
  "request_id": 3,
  "defense_context": {
    "has_waf": true,
    "waf_vendor": "modsecurity",
    "rate_limit_rps": 10.0,
    "bot_detection_present": false
  }
}

// Shutdown
{"type": "Shutdown"}
```

### BridgeResponse (Python → Rust)

```json
// Ready (sent on startup)
{"type": "Ready"}

// Hypotheses
{
  "type": "Hypotheses",
  "request_id": 1,
  "hypotheses": [...],
  "reasoning_trace": "<thinking>...</thinking>",
  "input_tokens": 1500,
  "output_tokens": 450
}

// CompiledPayloads
{
  "type": "CompiledPayloads",
  "request_id": 2,
  "payloads": ["' OR 1=1 --", "1; DROP TABLE users"],
  "input_tokens": 800,
  "output_tokens": 200
}

// EvasionPayloads
{
  "type": "EvasionPayloads",
  "request_id": 3,
  "payloads": ["..."],
  "input_tokens": 600,
  "output_tokens": 150
}

// Error
{
  "type": "Error",
  "request_id": 1,
  "message": "LLM rate limit exceeded"
}
```

---

## Scan Event Bus

Source: `crates/protocol/src/scan_event.rs`

`ScanEvent` is a typed enum for inter-module event communication. Wrapped in `ScanEventEnvelope` with auto-filled timestamp:

| Event | Payload Fields |
|-------|---------------|
| `EndpointDiscovered` | endpoint, method, source_module |
| `HypothesisGenerated` | vulnerability_class, condition, confidence |
| `PayloadTested` | endpoint, payload_hash, vulnerability_class, anomaly_score |
| `AnomalyDetected` | endpoint, vulnerability_class, anomaly_type, score |
| `FindingConfirmed` | finding_id, vulnerability_class, severity, confidence |
| `PhaseCompleted` | phase_name, operations_applied, findings_count, duration_ms |

**Note:** `ScanEvent` is defined in protocol crate for cross-module use but event bus infrastructure is not yet wired across all pipeline phases. Currently used for audit trail events via `AuditEventType` (a separate type in `protocol/src/audit.rs`).

---

## Security Interfaces

### Scope Attestation

Source: `crates/protocol/src/scope_attestation.rs`

Ed25519-signed authorization documents:

```json
// ScopeDocument
{
  "target_url": "http://example.com:3000",
  "authorized_by": "johndoe@company.com",
  "expiry_unix": 1735689600
}

// SignedScopeAttestation
{
  "document": { ... },
  "signature": "hex-encoded Ed25519 signature",
  "verifying_key": "hex-encoded public key"
}
```

Verification: `verify_attestation(attestation, target)` — checks Ed25519 signature, target URL match, and expiry.

### Signed Config

Source: `crates/protocol/src/signed_config.rs`

```json
// SignedConfig
{
  "config": {
    "target": "http://localhost:3000",
    "stealth_level": "default",
    "max_iterations": 3,
    "convergence_threshold": 2,
    "no_llm": false,
    "include_endpoints": null,
    "exclude_endpoints": null
  },
  "config_hash": "sha3-256-hex",
  "signature": "hex-encoded Ed25519 signature",
  "verifying_key": "hex-encoded public key"
}
```

---

## Storage Interfaces

### Vulnerability Database (`~/.aegis/vuln.db`)

SQLite database populated by `aegis update-db`.

Schema (inferred from passive-recon usage):
```sql
CREATE TABLE vulnerabilities (
  id INTEGER PRIMARY KEY,
  package_name TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  cve_id TEXT,
  severity REAL,
  description TEXT,
  affected_version_range TEXT,
  fixed_version TEXT
);
```
Queries: `SELECT * FROM vulnerabilities WHERE package_name = ? AND ecosystem = ?`
Populated by: OSV API batch queries (`api.osv.dev/v1/querybatch`)

### Scan History Database (`--history-db path`)

SQLite database for cross-scan adaptive payload selection.

Used by: `ScanHistoryDb::open(path)`, `db.success_rates_all_classes()`

### Graph Database (`--graph-db path`)

JSON file — `KnowledgeGraph::save_to_file()` output:

```json
{
  "nodes": { ... },
  "edges": { ... },
  "findings": { ... },
  "metadata": {
    "scan_timestamp_unix_ms": 1704067200000,
    "target_url": "http://localhost:3000",
    "aegis_version": "0.1.0",
    "scan_count": 3
  }
}
```

Adjacent checkpoint file: `{graph_db_path}.checkpoint.json`

---

## BusinessContext Configuration File (`--context-file`)

JSON format, loaded by `load_business_context(path)`:

```json
{
  "excluded_endpoints": ["/admin/debug", "/internal/health"],
  "critical_assets": ["/api/payments", "/api/users"],
  "pii_endpoints": ["/api/users/profile"],
  "known_issues": [
    {
      "endpoint": "/api/search",
      "vulnerability_class": "InsufficientInputValidation"
    }
  ]
}
```

---

## AuthFlow Configuration File (`--auth-flow`)

JSON format, loaded by `load_auth_flow(path)`:

Multi-step authentication flow with `{{variable}}` template interpolation. Used to authenticate the scanner before fuzzing protected endpoints.

---

## Proxy Interface

Source: `crates/proxy/src/lib.rs`

HTTP recording proxy (hyper-based):
- Listens for HTTP traffic
- Records requests/responses
- Supports 4-mode intruder attacks: Sniper, BatteringRam, Pitchfork, ClusterBomb
- Request repeater with modifications
- Sync recorded traffic to knowledge graph (adds Endpoint nodes)

The proxy is a standalone capability — not integrated into the `aegis` binary's scan pipeline. Intended for use as a separate tool in the security testing workflow.
