# AEGIS Data Models

<!-- metadata: domain types, graph model, SQLite schemas, IPC data structures, serialization formats -->

## Knowledge Graph Data Model

The knowledge graph is the central data structure — a directed property graph where:
- **Nodes** represent security-relevant entities
- **Edges** represent semantic relationships between entities (28 valid triples enforced)
- **Findings** represent discovered vulnerabilities linked to graph nodes

### Node Model

```
NodeData {
  id: u64                          Arena index (never reused, append-only)
  node_type: NodeType              Discriminates the entity type
  properties: HashMap<String, String>  Flexible property bag
}
```

**Common properties by NodeType:**

| NodeType | Key Properties |
|---------|---------------|
| `Endpoint` | `path` (URL path), `method` (GET/POST/...) |
| `Function` | `name`, `file_path` |
| `DataStore` | `name`, `store_type` (sql/nosql/file/...) |
| `Role` | `name`, `privilege_level` |
| `Dependency` | `name`, `version`, `ecosystem` |
| `Config` | `key`, `value` |
| `User` | `name`, `role` |
| `Service` | `name`, `host` |
| `Defense` | `has_waf`, `waf_vendor`, `rate_limit_rps`, `bot_detection` |

### Edge Model

```
EdgeData {
  id: u64
  source_node_id: u64
  target_node_id: u64
  label: EdgeLabel                 One of 8 semantic edge types
  weight: f64                      >= 0.0, encodes traversal difficulty
  provenance_module: ModuleIdentifier
  provenance_sequence: u64
}
```

### Finding Model

```
FindingData {
  id: u64
  linked_node_ids: Vec<u64>        Nodes this finding is associated with
  vulnerability_class: VulnerabilityClass
  severity: f64                    CVSS-style [0.0, 10.0]
  confidence: FindingConfidence    Provenance-tracked composite score
  certificate: Vec<u8>            CBOR-serialized evidence blob
  provenance_module: ModuleIdentifier
  timestamp_unix_ms: u64
  evidence_level: EvidenceLevel   Statistical|Controlled|Confirmed|Chained
  stable_id: Option<FindingId>    SHA3-256 hash for cross-scan dedup
}
```

---

## Graph Persistence Format

Saved to `--graph-db` path as JSON:

```json
{
  "metadata": {
    "scan_timestamp_unix_ms": 1704067200000,
    "target_url": "http://localhost:3000",
    "aegis_version": "0.1.0",
    "scan_count": 3
  },
  "nodes": {
    "items": [...],           // Vec<NodeData>
    "by_type": {...},         // HashMap<NodeType, Vec<u64>>
    "count": 42
  },
  "edges": {
    "items": [...],           // Vec<EdgeData>
    "by_source": {...},       // HashMap<u64, Vec<u64>>
    "by_target": {...},       // HashMap<u64, Vec<u64>>
    "count": 87
  },
  "findings": {
    "items": [...],           // Vec<FindingData>
    "by_class": {...},        // HashMap<VulnerabilityClass, Vec<u64>>
    "by_node": {...},         // HashMap<u64, Vec<u64>>
    "count": 12
  }
}
```

**Note:** Operation log is NOT persisted — restored graph starts with fresh OperationLog. Store state (nodes, edges, findings) is fully restored.

---

## Audit Log Format (CBOR)

Each audit log entry binary record:

```
[sequence: u64 LE][entry_hash: 32 bytes SHA3-256][payload_len: u32 LE][payload: CBOR][hmac: 32 bytes HMAC-SHA3]
```

CBOR payload encodes `AuditEventType` (6 variants):
- `ScanStarted { target_description: String }`
- `ModuleStarted { module: ModuleIdentifier }`
- `FindingRecorded { finding_id: u64, vulnerability_class: VulnerabilityClass }`
- `ScanCompleted { total_findings: u64 }`
- `KeyEvent { description: String }`
- `ConfigChange { key: String, old_value: String, new_value: String }`

Sidecar files: `aegis-audit.cbor` (log data) + `aegis-audit.key` (HMAC key, stored separately)

---

## Certificate Format (CBOR)

Source: `crates/reporting/src/certificate_serializer.rs`

CBOR-serialized evidence certificates versioned with envelope v2:

```
CertificateType variants:
  Fuzzing      — HTTP request/response pairs with anomaly evidence
  Taint        — data flow trace from source to sink
  Chain        — multi-step attack path evidence
  Config       — misconfiguration evidence
  Dependency   — known CVE with version match
  Evasion      — WAF/defense bypass evidence
```

---

## SARIF Output Format

Source: `crates/reporting/src/sarif_emitter.rs`

SARIF 2.1.0 (JSON) with AEGIS-specific extensions:

```json
{
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "AEGIS",
        "version": "0.1.0",
        "rules": [...]  // One per VulnerabilityClass with CWE mapping
      }
    },
    "results": [{
      "ruleId": "SQL-INJECTION",
      "level": "error",
      "message": { "text": "..." },
      "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "/api/login" } } }],
      "properties": {
        "severity": 9.0,
        "confidence": 0.85,
        "evidence_level": "Controlled",
        "cve_id": null,
        "mitigation_rank": 1,
        "defense_context": { ... }
      }
    }]
  }]
}
```

**Report Formats:**
- `developer` — Standard SARIF (IDE + GitHub integration)
- `security` — SARIF enriched with ATT&CK technique IDs
- `executive` — Summary JSON (finding counts, risk scores, remediation priority)

---

## IPC Data Structures

### ScanContextIpc (Rust → Python)

```rust
ScanContextIpc {
  technology_stack: Vec<String>,              // Dependency node names from graph
  findings_summary: Vec<String>,              // VulnerabilityClass display names
  high_centrality_nodes: Vec<String>,         // (currently empty in impl)
  defense_posture: serde_json::Value,         // {}
  class_confirmation_rates: HashMap<String, f64>, // from scan history DB
  model_id: Option<String>,                   // (not set in current impl)
}
```

### HypothesisIpc

```rust
HypothesisIpc {
  vulnerability_class: String,    // VulnerabilityClass display name
  description: String,            // LLM-generated natural language description
  confidence: f64,               // [0.0, 1.0]
  test_specification: Option<String>,  // Compiled test spec
}
```

### DefenseContextIpc

```rust
DefenseContextIpc {
  has_waf: bool,
  waf_vendor: Option<String>,
  rate_limit_rps: Option<f64>,
  bot_detection_present: bool,
}
```

---

## Python Hypothesis Engine Data Models

Source: `hypothesis-engine/src/hypothesis_engine/ipc_types.py`

Pydantic models matching the Rust IPC types above (must stay in sync):

```python
class ScanContextIpc(BaseModel):
    technology_stack: list[str]
    findings_summary: list[str]
    high_centrality_nodes: list[str]
    defense_posture: dict
    class_confirmation_rates: dict[str, float] = {}
    model_id: str | None = None

class HypothesisIpc(BaseModel):
    vulnerability_class: str
    description: str
    confidence: float
    test_specification: str | None = None

class TokenUsage(BaseModel):
    input_tokens: int
    output_tokens: int
    latency_ms: float
```

### GenerationResult (Python internal)

```python
class GenerationResult:
    hypotheses: list[HypothesisIpc]
    reasoning_trace: str
    input_tokens: int
    output_tokens: int
    latency_ms: float
    parsing_method: str  # "xml_tags"|"bracket_json"|"single_object_wrapped"|"failed"
    call_count: int      # Number of LLM API calls (>1 for self-consistency)
```

### CalibrationReport (Python)

```python
class CalibrationBin:
    lower_bound: float
    upper_bound: float
    mean_confidence: float
    actual_positive_rate: float
    calibration_error: float
    count: int

class CalibrationReport:
    bins: list[CalibrationBin]
    expected_calibration_error: float  # Weighted average |mean_confidence - actual_rate|
    overconfident_range: tuple[float, float] | None
    underconfident_range: tuple[float, float] | None
    temperature_a: float   # sigmoid(a * raw + b) scaling parameters
    temperature_b: float
```

---

## Vulnerability Database Schema

SQLite at `~/.aegis/vuln.db` (default) or `--vuln-db` path:

```sql
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    package_name TEXT NOT NULL,
    ecosystem TEXT NOT NULL,                 -- "cargo", "npm", "pypi", "rubygems", "maven", etc.
    vulnerable_version_start TEXT NOT NULL,
    vulnerable_version_end TEXT NOT NULL,    -- "999999.0.0" sentinel = vulnerability still unfixed
    severity REAL NOT NULL DEFAULT 0.0,      -- CVSS base score
    description TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_vuln_package ON vulnerabilities(package_name, ecosystem);
CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerabilities(cve_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_vuln_unique ON vulnerabilities(
    cve_id, package_name, ecosystem, vulnerable_version_start, vulnerable_version_end
);

CREATE TABLE IF NOT EXISTS update_metadata (
    ecosystem TEXT PRIMARY KEY,
    last_updated_unix_ms INTEGER NOT NULL
);
```

Populated by: OSV API batch queries — `https://api.osv.dev/v1/querybatch`
Deduplication: `INSERT OR IGNORE` via the unique index
`999999.0.0` sentinel in `vulnerable_version_end` indicates the vulnerability is still unfixed (no patched version released)

---

## DefenseContext (Protocol Type)

```rust
DefenseContext {
  has_waf: bool,
  waf_vendor: Option<String>,
  waf_blocked_categories: Vec<VulnerabilityClass>,
  rate_limit_rps: Option<f64>,
  bot_detection_present: bool,
  bot_detection_evaded: bool,
}
```

Used in: `DefenseProfile` (fuzzing crate), `SarifFinding` (reporting), `DefenseContextIpc` (IPC)

---

## ScanCheckpoint (Resume State)

```rust
ScanCheckpoint {
  completed_phases: Vec<String>,     // e.g. ["recon", "crawl", "fingerprint", "fuzz:0", "analyze:0"]
  current_iteration: u32,
  total_operations: u64,
  total_findings: u64,
  consecutive_zero_findings: u32,
  timestamp_unix_ms: u64,
}
```

Stored as JSON alongside `--graph-db` path: `{graph_db}.checkpoint.json`
Deleted on successful scan completion.

---

## Scan History Database Schema

SQLite at `--history-db` path:

```sql
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_pattern TEXT NOT NULL,
    vulnerability_class TEXT NOT NULL,    -- VulnerabilityClass display string
    payload TEXT NOT NULL,
    anomaly_score REAL NOT NULL,          -- [0.0, 1.0]
    is_true_positive INTEGER NOT NULL,    -- 1 = confirmed finding, 0 = false positive
    timestamp_unix_ms INTEGER NOT NULL,
    target_app_hash TEXT NOT NULL         -- groups records by target app, prevents cross-app contamination
);

CREATE INDEX IF NOT EXISTS idx_scan_history_endpoint
    ON scan_history(endpoint_pattern);
CREATE INDEX IF NOT EXISTS idx_scan_history_vuln_class
    ON scan_history(vulnerability_class);
CREATE INDEX IF NOT EXISTS idx_scan_history_app_hash
    ON scan_history(target_app_hash);
```

Used by:
- `ScanHistoryDb::success_rates_all_classes()` — returns `HashMap<String, f64>` for LLM context injection
- Adaptive payload selection across scans (cross-scan learning)
- TF-IDF endpoint similarity for hypothesis transfer

---

## BusinessContext

```rust
BusinessContext {
  excluded_endpoints: Vec<String>,   // Paths to skip during fuzzing
  critical_assets: Vec<String>,      // Paths requiring special attention
  pii_endpoints: Vec<String>,        // PII data locations (GDPR/compliance)
  known_issues: Vec<KnownIssue>,     // Already-triaged vulnerabilities
}

KnownIssue {
  endpoint: String,
  vulnerability_class: VulnerabilityClass,
}
```

When a finding matches a KnownIssue, the SARIF output adds a suppression annotation.
