# AEGIS Type System

<!-- metadata: traits, enums, structs, error types, design patterns, concurrency model, generics -->

## Core Domain Enums (aegis-protocol)

### `VulnerabilityClass` — 34 variants

`Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize`
Source: `crates/protocol/src/finding.rs`

The central taxonomy of vulnerabilities AEGIS can detect. Implements `Display` with human-readable names.

| Variant | Display Name |
|---------|-------------|
| SqlInjection | SQL Injection |
| CrossSiteScripting | Cross-Site Scripting |
| CommandInjection | Command Injection |
| PathTraversal | Path Traversal |
| ServerSideRequestForgery | Server-Side Request Forgery |
| InsecureDeserialization | Insecure Deserialization |
| BrokenAuthentication | Broken Authentication |
| BrokenAuthorization | Broken Authorization |
| SecurityMisconfiguration | Security Misconfiguration |
| SensitiveDataExposure | Sensitive Data Exposure |
| ServerSideTemplateInjection | Server-Side Template Injection |
| HeaderInjection | Header Injection |
| OpenRedirect | Open Redirect |
| CrlfInjection | CRLF Injection |
| KnownVulnerableDependency | Known Vulnerable Dependency |
| InsufficientInputValidation | Insufficient Input Validation |
| NoSqlInjection | NoSQL Injection |
| XmlExternalEntity | XML External Entity |
| CrossOriginMisconfiguration | Cross-Origin Misconfiguration |
| MissingSecurityHeader | Missing Security Header |
| JwtVulnerability | JWT Vulnerability |
| HttpRequestSmuggling | HTTP Request Smuggling |
| RaceCondition | Race Condition |
| SubdomainTakeover | Subdomain Takeover |
| PrototypePollution | Prototype Pollution |
| GraphQlAbuse | GraphQL Abuse |
| CloudMisconfiguration | Cloud Misconfiguration |
| Clickjacking | Clickjacking |
| CachePoisoning | Cache Poisoning |
| HostHeaderInjection | Host Header Injection |
| InsecureDirectObjectReference | Insecure Direct Object Reference |
| InformationDisclosure | Information Disclosure |
| WeakCryptography | Weak Cryptography |
| MassAssignment | Mass Assignment |

**Pitfall:** When adding a new variant, must also update `is_valid_edge()` whitelist if needed, update CVSS mapping in compliance crate, add to LLM system prompt in hypothesis-engine, and update the 16-variant fixture tests.

---

### `NodeType` — 9 variants

`Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize`
Source: `crates/protocol/src/node.rs`

```
Endpoint | Function | DataStore | Role | Dependency | Config | User | Service | Defense
```

Implements `Display`. Used as vertex labels in the knowledge graph. **Adding a new variant requires updating `is_valid_edge()` whitelist AND the exhaustive coverage test.**

---

### `EdgeLabel` — 8 variants

`Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize`
Source: `crates/protocol/src/edge.rs`

```
Calls | Trusts | Authenticates | Reads | Writes | DependsOn | Exposes | ProtectedBy
```

Implements `Display`. Only 28 of the 72 possible (NodeType, EdgeLabel, NodeType) triples are valid. See `EDGE_WHITELIST` constant for the authoritative list.

---

### `EvidenceLevel` — 4 variants

`Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize`
Source: `crates/protocol/src/finding.rs`

| Variant | Default Confidence | Description |
|---------|-------------------|-------------|
| Statistical | 0.4 | Response pattern analysis |
| Controlled | 0.7 | Counterfactual/paired test (serde alias: `"Counterfactual"` for backwards compat) |
| Confirmed | 0.9 | Verified exploitation |
| Chained | 0.95 | Multi-step attack chain confirmed |

---

### `GraphOperation` — 4 variants

`Debug, Clone, Serialize, Deserialize`
Source: `crates/protocol/src/operation.rs`

```rust
AddNode { node_type: NodeType, properties: Vec<(String, String)> }
AddEdge { source_node_id: u64, target_node_id: u64, label: EdgeLabel, weight: f64 }
UpdateWeight { edge_id: u64, new_weight: f64 }
AddFinding { linked_node_ids: Vec<u64>, vulnerability_class: VulnerabilityClass, severity: f64, confidence: f64, certificate: Vec<u8> }
```

Applied to the knowledge graph via `KnowledgeGraph::apply_operations(&[OperationLogEntry])`.

---

### `ModuleIdentifier` — 7 variants

`Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize`
Source: `crates/protocol/src/operation.rs`

```
PassiveRecon | Enumeration | Fuzzing | HypothesisEngine | ChainSynthesis | Discovery | Proxy
```

Tracks which pipeline module produced each graph operation for provenance.

---

## Core Data Structs (aegis-protocol)

### `NodeData`

```rust
pub struct NodeData {
    pub id: u64,                              // Arena index
    pub node_type: NodeType,
    pub properties: HashMap<String, String>,  // Flexible property bag
}
```

Builder: `NodeData::new(id, node_type).with_property(key, value)`

---

### `EdgeData`

```rust
pub struct EdgeData {
    pub id: u64,
    pub source_node_id: u64,
    pub target_node_id: u64,
    pub label: EdgeLabel,
    pub weight: f64,               // Must be finite and >= 0.0
    pub provenance_module: ModuleIdentifier,
    pub provenance_sequence: u64,
}
```

---

### `FindingData`

```rust
pub struct FindingData {
    pub id: u64,
    pub linked_node_ids: Vec<u64>,
    pub vulnerability_class: VulnerabilityClass,
    pub severity: f64,                    // [0.0, 10.0]
    pub confidence: FindingConfidence,    // Provenance-tracked (NOT raw f64)
    pub certificate: Vec<u8>,            // CBOR-serialized evidence cert
    pub provenance_module: ModuleIdentifier,
    pub timestamp_unix_ms: u64,
    pub evidence_level: EvidenceLevel,
    pub stable_id: Option<FindingId>,    // SHA3-256 content hash for dedup
}
```

**Custom `Deserialize`** handles three legacy formats: full `FindingConfidence` object, legacy `confidence_score: f64`, and scalar `confidence: f64`.

Builder: fluent `with_*` methods: `with_stable_id()`, `with_linked_nodes()`, `with_certificate()`, `with_evidence_level()`, `with_confidence()`, `with_finding_confidence()`.

---

### `FuzzRequest` / `FuzzResponse`

Source: `crates/protocol/src/request.rs`

```rust
pub struct FuzzRequest {
    pub request_id: u64,
    pub endpoint: String,
    pub method: String,
    pub parameter_name: String,
    pub parameter_location: ParameterLocation,  // Query | Path | Header | Cookie | Body
    pub payload: String,
    pub headers: Vec<(String, String)>,
}

pub struct FuzzResponse {
    pub request_id: u64,
    pub status_code: u16,
    pub body: String,
    pub headers: Vec<(String, String)>,
    pub response_time: Duration,
    pub body_size_bytes: usize,
}
```

Defined in protocol crate and re-exported by fuzzing crate for backwards compatibility.

---

### `OperationLogEntry`

```rust
pub struct OperationLogEntry {
    pub sequence_number: u64,
    pub module: ModuleIdentifier,
    pub operation: GraphOperation,
    pub timestamp_unix_ms: u64,
}
```

The unit of graph mutation. Pipeline phases return `Vec<OperationLogEntry>` and pass them to `KnowledgeGraph::apply_operations()`.

---

## Newtype Patterns

### `Confidence` — validated f64 wrapper

Source: `crates/protocol/src/finding.rs`

```rust
pub struct Confidence(f64);  // Always in [0.0, 1.0], always finite
```

- `Confidence::new(f64) -> Result<Self, &'static str>` — rejects non-finite or out-of-range
- `Confidence::from_evidence(EvidenceLevel) -> Self` — maps evidence to default confidence
- `Confidence::value() -> f64` — unwraps the inner value
- Default: `0.5`
- Custom `Serialize` — as `f64`
- Custom `Deserialize` — tolerant: invalid values become `0.5` default

### `FindingId` — content-addressed SHA3-256 hash

```rust
pub struct FindingId { bytes: [u8; 32] }
```

`FindingId::from_parts(endpoint, vulnerability_class, parameter)` — SHA3-256 hash enabling cross-scan deduplication.

---

## Provenance-Tracked Confidence

### `FindingConfidence`

```rust
pub struct FindingConfidence {
    pub prior: f64,                    // Base rate for this vuln class
    pub likelihood_ratio: f64,         // Evidence strength multiplier
    pub methodology_reliability: f64,  // Test method trustworthiness
    pub composite: Confidence,         // = clamp(prior * lr * reliability, 0, 1)
}
```

- `FindingConfidence::compute(prior, lr, reliability)` — computes composite from components
- `FindingConfidence::from_simple(confidence)` — wraps legacy scalar (sets lr = confidence*2, reliability = 1.0)

---

## Public Traits

### `GraphStore` — knowledge graph abstraction

Source: `crates/knowledge-graph/src/graph_store.rs`

```rust
pub trait GraphStore: Send + Sync {
    fn apply_operations(&mut self, ops: &[OperationLogEntry]) -> Result<(), GraphError>;
    fn nodes_by_type(&self, node_type: NodeType) -> Result<Vec<u64>, GraphError>;
    fn get_node(&self, id: u64) -> Result<Option<NodeData>, GraphError>;
    fn total_operations_applied(&self) -> Result<u64, GraphError>;
    fn all_findings(&self) -> Result<Vec<FindingData>, GraphError>;
    fn node_count(&self) -> Result<u64, GraphError>;
    fn findings_by_class(&self, vulnerability_class: VulnerabilityClass) -> Result<Vec<u64>, GraphError>;
    fn get_finding(&self, id: u64) -> Result<Option<FindingData>, GraphError>;
    fn save_to_file(&self, _path: &Path, _metadata: &GraphMetadata) -> Result<(), GraphError> { Ok(()) }  // default: no-op
}
```

**Implementors:** `KnowledgeGraph` (full implementation), test fakes (no-op stubs).
`Send + Sync` bound required — `ScanContext` crosses async boundaries.

---

### `ScanActor` — pipeline phase actor

Source: `crates/orchestrator/src/actor.rs`

```rust
pub trait ScanActor {
    fn name(&self) -> &str
    fn process(&mut self, ctx: &mut ScanContext, events: &[ScanEventEnvelope])
        -> Result<Vec<ScanEventEnvelope>, ActorError>
}
```

**Actor types by role:**
- **Source** (`ReconActor`, `FingerprintActor`) — ignore input events; produce endpoint/defense events
- **Transform** (`FuzzActor<T>`, `AnalyzeActor`) — consume events from previous phase; produce finding events
- **Sink** (`ReportActor`) — consume all events; produce no new events; write to file
- **Observer** (`ConvergenceActor`, telemetry) — read events without modifying state; return empty Vec

`ScanActor::process()` is **synchronous** — blocks until the phase completes.

---

### `AuditEventType` — 6 variants

Source: `crates/protocol/src/audit.rs`

```rust
pub enum AuditEventType {
    ScanStarted { target_description: String },
    ModuleStarted { module: ModuleIdentifier },
    FindingRecorded { finding_id: u64, vulnerability_class: VulnerabilityClass },
    ScanCompleted { total_findings: u64 },
    KeyEvent { description: String },
    ConfigChange { key: String, old_value: String, new_value: String },
}
```

`Serialize, Deserialize` — CBOR-serialized into `AuditEntry.payload_cbor`. All audit events emitted via `audit_writer.append_event(AuditEventType::*)`.

---

### `AuditWriter` — audit event writer

Source: `crates/audit-log/src/log_writer.rs`

```rust
pub trait AuditWriter {
    fn append_event_full(&mut self, event: AuditEventType) -> Result<AuditEntry, LogWriterError>;
    fn append_event(&mut self, event: AuditEventType) -> Result<(), LogWriterError> { ... }  // default delegates to full
    fn sequence_number(&self) -> u64;
}
```

**Implementors:**
- `AuditLogWriter` — SHA3-256 hash chain + HMAC-signed CBOR records to disk
- `NoOpAuditLogWriter` — intentionally discards events (for `--no-audit` mode), returns synthetic entries with zeroed hashes

Pipeline uses `Box<dyn AuditWriter>`.

---

## Key Concrete Types

### `KnowledgeGraph`

Source: `crates/knowledge-graph/src/graph.rs`

```rust
pub struct KnowledgeGraph {
    inner: RwLock<KnowledgeGraphInner>,  // parking_lot RwLock for upgradable read support
}
```

**Concurrency model:** `parking_lot::RwLock<Inner>` — single contention point. Validate-then-apply uses `RwLockUpgradableReadGuard` (acquires upgradable read for validation, atomically upgrades to write for application — eliminates TOCTOU).

**Graph invariants (enforced on every `apply_operations`):**
1. All edges satisfy `is_valid_edge()` — 28 valid semantic triples
2. Edge weights finite and >= 0.0
3. Finding severity in [0.0, 10.0], confidence in [0.0, 1.0]
4. No duplicate edges (same source + target + label)
5. Operation sequences consecutive per module (strict mode only)

**Persistence:** `save_to_file(path, metadata)` — JSON bundle with nodes/edges/findings/metadata. `load_from_file(path)` — restores stores but starts fresh OperationLog.

---

### `ScanConfig` — CLI root struct (clap derive)

Source: `crates/orchestrator/src/scan_config.rs`

Parsed with `ScanConfig::parse_and_apply_preset()`. Groups into sub-structs via `#[command(flatten)]`:

```rust
pub struct ScanConfig {
    pub preset: Option<ScanPreset>,   // quick | thorough | paranoid | benchmark
    pub target: String,               // URL to scan (localhost enforced by default)
    pub output: PathBuf,              // default: aegis-report.sarif
    pub report_format: String,        // developer | security | executive
    pub source_dir: Option<PathBuf>,  // local source for recon
    pub verbose: bool,
    pub stealth: StealthOptions,
    pub pipeline: PipelineOptions,
    pub llm: LlmOptions,
    pub audit: AuditOptions,
    pub scope: ScopeOptions,
    pub auth: AuthOptions,
    pub distributed: DistributedOptions,
    pub telemetry: bool,
}
```

---

## Design Patterns

### Builder Pattern

Used extensively for configuration types. Methods follow `with_*` naming:

- `NodeData::new(id, node_type).with_property(k, v)`
- `FindingData::new(...).with_stable_id(...).with_evidence_level(...).with_certificate(...)`
- `StealthConfig::default().with_max_rps(n).with_jitter_ms(min, max)`
- `DefenseProfile::new().with_waf(...).with_rate_limit(...)`

### Repository/Storage Abstraction

`GraphStore` trait abstracts knowledge graph access. Pipeline phase functions accept `&mut dyn GraphStore` or `&dyn GraphStore`, allowing test injection of fake implementations without constructing a full `KnowledgeGraph` with parking_lot locks.

---

## Additional Domain Types (Fuzzing and Oracle)

### `AnomalyType` — 5 variants

`StatusCodeAnomaly | TimingAnomaly | SizeAnomaly | ContentAnomaly | ReflectionDetected`

Categorizes the type of anomaly detected by the counterfactual oracle when comparing control vs treatment responses.

### `CounterfactualOrder`

`ControlFirst | TreatmentFirst` — determines which request (benign or malicious) is sent first to reduce correlation artifacts.

### `BaselineProfile`

```rust
pub struct BaselineProfile {
    endpoint: String,
    method: String,
    expected_status_codes: Vec<u16>,
    mean_response_time_ms: f64,
    p99_response_time_ms: f64,
    mean_body_size: f64,
    body_size_std_dev: f64,
}
```

Statistical baseline for a given endpoint. Used to establish the "control" response distribution before anomaly testing.

### `JitterDistribution` — in evasion-engine persona

`Uniform | Exponential | Normal` — controls timing jitter distribution shape for request intervals. Set per persona in the persona catalog.

---

### Strategy Pattern (via trait objects and generics)

- `Box<dyn AuditWriter>` — runtime-selectable audit backend (file vs no-op)
- LLM backend in Python: `LlmBackend` ABC with `BedrockClient`, `OpenAiClient`, `OllamaClient` — composition over inheritance

### Command Pattern

`GraphOperation` enum — operations are created by one module, validated by another, then applied to the store. Operation log provides event sourcing.

### Event Sourcing

`OperationLogEntry` records form a replay-able log. `event_store::replay_from_entries()` reconstructs scan state from audit events. `diff_snapshots()` computes deltas between states.

### Newtype for Invariant Enforcement

`Confidence(f64)` — wraps f64 to enforce [0.0, 1.0] and finiteness. Eliminates defensive checks at use sites. Invalid values rejected at construction time.

### Facade Pattern

`KnowledgeGraph` is a facade over `KnowledgeGraphInner` which holds the actual stores. Callers never access stores directly — all mutations go through the graph's public API, which handles locking, validation, and atomicity.

---

## Concurrency Model

**Runtime:** Tokio multi-threaded (default). Single `#[tokio::main]` in `crates/orchestrator/src/main.rs`.

**Shared state:**
- `KnowledgeGraph` — `Arc<KnowledgeGraph>` passed through `ScanContext` — `parking_lot::RwLock<Inner>` for readers-don't-block-each-other semantics
- Audit log — `Box<dyn AuditWriter>` behind `Mutex` in `ScanContext`

**Concurrent phases:** `tokio::join!` is used for concurrent recon + fingerprint phases. The scan pipeline is otherwise sequential (iterative fuzz→analyze loop).

**No channels:** No `mpsc`/`oneshot`/`broadcast` channels used in the main pipeline. Python subprocess IPC uses stdin/stdout (blocking, managed by `hypothesis_bridge`).

---

## Error Types and Handling Strategy

All public APIs return `Result<T, E>` where `E` is a typed enum. No `anyhow` or `eyre` — errors are typed for precise pattern matching.

| Error Type | Source | Key Variants |
|-----------|--------|---------|
| `GraphError` | knowledge-graph | `Validation(ValidationError)`, `OperationLog(OperationLogError)`, `Io(String)` |
| `ValidationError` | knowledge-graph | `DuplicateNodeInBatch(u64)`, `DanglingEdgeSource(u64)`, `DanglingEdgeTarget(u64)`, `EdgeNotFound(u64)`, `NodeNotFoundForFinding(u64)`, `InvalidEdgeSemantics{source_type, label, target_type}`, `DuplicateEdge{source, target, label}`, `InvalidWeight(f64)`, `InvalidSeverity(f64)`, `InvalidConfidence(f64)` |
| `OperationLogError` | knowledge-graph | `SequenceOutOfOrder{module, expected_min, received}`, `SequenceGap{module, expected, actual}`, `NodeNotFound(u64)`, `EdgeNotFound(u64)` |
| `LogWriterError` | audit-log | `IoError(io::Error)`, `SerializationError(String)`, `LogCreationFailed(String)` |
| `CapabilityError` | supervisor | `TokenExpired`, `InsufficientPermissions(Permission)`, `UnknownModule(ModuleIdentifier)`, `InvalidToken` |
| `AttestationError` | protocol | `InvalidSignature`, `Expired(String)`, `TargetMismatch{expected, actual}`, `InvalidPublicKey(String)`, `InvalidFormat(String)` |
| `TransportError` | evasion-engine | `NetworkError(String)`, `Timeout(String)`, `BuildError(String)`, `TargetNotAllowed(String)` |
| `ConfigError` | orchestrator | `InvalidTarget`, `NonLocalhost`, `InvalidStealthLevel`, `InvalidPersona`, `InvalidReportFormat`, `ContextFileRead`, `ContextFileParse`, `AuthFlowFileRead`, `AuthFlowFileParse`, `AuthInputParse`, `InvalidDistributed` |
| `PhaseError` | orchestrator | `Graph(GraphError)`, `Io(io::Error)`, `Serialization(serde_json::Error)`, `Checkpoint(CheckpointError)`, `ReportFormat(String)`, `UnknownExportFormat(String)`, `FilesystemWalk(String)` |

All error types implement `std::error::Error` with `source()` for error chaining. `thiserror` is listed as a workspace dependency but the current implementation uses manual error impls.

---

## Semantic Edge Validation

`is_valid_edge(source: NodeType, label: EdgeLabel, target: NodeType) -> bool`
Source: `crates/protocol/src/edge.rs`

28 valid combinations, grouped by semantic category:

| Category | Valid Triples |
|----------|--------------|
| Execution flow (Calls) | Endpoint→Function, Function→Function, Service→Service, Service→Function |
| Trust (Trusts) | Role→Role, Service→Service, User→Service |
| Authentication (Authenticates) | Role→Endpoint, User→Endpoint, Service→Endpoint |
| Data reads (Reads) | Function→DataStore, Endpoint→DataStore, Service→DataStore |
| Data writes (Writes) | Function→DataStore, Endpoint→DataStore, Service→DataStore |
| Dependencies (DependsOn) | Service→Dependency, Service→Service, Function→Dependency, Endpoint→Dependency |
| Data exposure (Exposes) | Endpoint→DataStore, Function→DataStore, Service→DataStore, Config→DataStore |
| Protection (ProtectedBy) | Endpoint→Defense, DataStore→Defense, Service→Defense, Function→Defense |
