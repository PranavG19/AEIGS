<!-- metadata:
  crate: aegis-protocol
  purpose: Shared type definitions and cross-cutting contracts for all AEGIS crates
  public_api: NodeType, EdgeLabel, VulnerabilityClass, EvidenceLevel, Confidence, FindingConfidence,
              FindingData, FindingId, EdgeData, NodeData, GraphOperation, OperationLogEntry,
              ModuleIdentifier, AuditEntry, AuditEventType, CapabilityToken, Permission,
              FuzzRequest, FuzzResponse, ParameterLocation, DefenseContext,
              IpcMessage, GraphQuery, QueryResult, IpcFrame, IpcFrameDecodeError,
              ScanContextIpc, HypothesisIpc, DefenseContextIpc, BridgeRequest, BridgeResponse,
              ScopeDocument, SignedScopeAttestation, AttestationError,
              SignableConfig, SignedConfig, SignedConfigError,
              ScanEvent, ScanEventEnvelope, TargetValidationError,
              validate_target, validate_target_is_localhost, validate_target_with_override,
              is_valid_edge, EDGE_WHITELIST, valid_edge_count,
              sign_scope_document, verify_attestation, load_attestation,
              sign_config, verify_signed_config, load_signed_config, verify_config_matches
  modules: node, edge, finding, operation, audit, capability, ipc, hypothesis_ipc,
           request, defense_context, scope_attestation, signed_config, scan_event,
           target_validation
  dependencies: serde, serde_json, sha3, url, uuid, ed25519-dalek
-->

# aegis-protocol

## Purpose

`aegis-protocol` is the foundational contract layer for the entire AEGIS system. It defines all
shared types that flow between crates — graph nodes and edges, vulnerability findings, audit events,
IPC messages to the Python hypothesis engine, and authorization documents. Having a single protocol
crate prevents circular dependencies and ensures that changes to shared types produce compile errors
everywhere they matter simultaneously.

## Crate Type

Library

## Dependencies on Workspace Crates

None. This crate has no intra-workspace dependencies, making it the root of the dependency tree.

## External Dependencies

| Dependency | Version | Role |
|---|---|---|
| serde | 1 | Serialization/deserialization derives and traits |
| serde_json | 1 | JSON value handling in FindingData deserializer and IPC types |
| sha3 | 0.10 | SHA3-256 for FindingId content-addressing and config hash |
| url | 2 | URL parsing in target_validation |
| uuid | 1 | UUIDs (used by other crates that re-export these types) |
| ed25519-dalek | 2 | Ed25519 signing/verification for scope attestation and signed config |

## Module Structure

| Module | Responsibility |
|---|---|
| `node` | `NodeType` enum (9 variants), `NodeData` struct with property map |
| `edge` | `EdgeLabel` enum (8 variants), `EdgeData` struct, `EDGE_WHITELIST`, `is_valid_edge()` |
| `finding` | `VulnerabilityClass` (34 variants), `EvidenceLevel`, `Confidence`, `FindingConfidence`, `FindingId`, `FindingData`, `confidence_from_evidence()` |
| `operation` | `GraphOperation` enum, `ModuleIdentifier` enum, `OperationLogEntry` struct |
| `audit` | `AuditEventType` enum, `AuditEntry` struct |
| `capability` | `CapabilityToken` struct, `Permission` enum |
| `ipc` | `IpcMessage`, `GraphQuery`, `QueryResult`, `IpcFrame` (length-prefixed framing) |
| `hypothesis_ipc` | `ScanContextIpc`, `HypothesisIpc`, `DefenseContextIpc`, `BridgeRequest`, `BridgeResponse` (Rust-Python bridge) |
| `request` | `FuzzRequest`, `FuzzResponse`, `ParameterLocation` |
| `defense_context` | `DefenseContext` (abstract defense posture) |
| `scope_attestation` | `ScopeDocument`, `SignedScopeAttestation`, `AttestationError`, `sign_scope_document()`, `verify_attestation()`, `load_attestation()` |
| `signed_config` | `SignableConfig`, `SignedConfig`, `SignedConfigError`, `sign_config()`, `verify_signed_config()`, `load_signed_config()`, `verify_config_matches()` |
| `scan_event` | `ScanEvent` enum, `ScanEventEnvelope` struct |
| `target_validation` | `TargetValidationError`, `validate_target_is_localhost()`, `validate_target()`, `validate_target_with_override()` |

## Public API Summary

### Enums

```rust
pub enum NodeType {
    Endpoint, Function, DataStore, Role, Dependency, Config, User, Service, Defense,
}
impl Display for NodeType { ... }  // "Endpoint", "Data Store", "Configuration", etc.

pub enum EdgeLabel {
    Calls, Trusts, Authenticates, Reads, Writes, DependsOn, Exposes, ProtectedBy,
}
impl Display for EdgeLabel { ... }

pub enum VulnerabilityClass {
    SqlInjection, CrossSiteScripting, CommandInjection, PathTraversal,
    ServerSideRequestForgery, InsecureDeserialization, BrokenAuthentication,
    BrokenAuthorization, SecurityMisconfiguration, SensitiveDataExposure,
    ServerSideTemplateInjection, HeaderInjection, OpenRedirect, CrlfInjection,
    KnownVulnerableDependency, InsufficientInputValidation, NoSqlInjection,
    XmlExternalEntity, CrossOriginMisconfiguration, MissingSecurityHeader,
    JwtVulnerability, HttpRequestSmuggling, RaceCondition, SubdomainTakeover,
    PrototypePollution, GraphQlAbuse, CloudMisconfiguration, Clickjacking,
    CachePoisoning, HostHeaderInjection, InsecureDirectObjectReference,
    InformationDisclosure, WeakCryptography, MassAssignment,
}
// 34 variants. Derives Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize.
// Display gives human-readable names: "SQL Injection", "Cross-Site Scripting", etc.

pub enum EvidenceLevel {
    Statistical,
    #[serde(alias = "Counterfactual")]
    Controlled,
    Confirmed,
    Chained,
}
// Ordered by strength: Statistical < Controlled < Confirmed < Chained.
// Serde alias for backwards compat with old "Counterfactual" serializations.

pub enum GraphOperation {
    AddNode { node_type: NodeType, properties: Vec<(String, String)> },
    AddEdge { source_node_id: u64, target_node_id: u64, label: EdgeLabel, weight: f64 },
    UpdateWeight { edge_id: u64, new_weight: f64 },
    AddFinding {
        linked_node_ids: Vec<u64>,
        vulnerability_class: VulnerabilityClass,
        severity: f64,
        confidence: f64,
        certificate: Vec<u8>,
    },
}

pub enum ModuleIdentifier {
    PassiveRecon, Enumeration, Fuzzing, HypothesisEngine, ChainSynthesis, Discovery, Proxy,
}

pub enum AuditEventType {
    ScanStarted { target_description: String },
    ModuleStarted { module: ModuleIdentifier },
    FindingRecorded { finding_id: u64, vulnerability_class: VulnerabilityClass },
    ScanCompleted { total_findings: u64 },
    KeyEvent { description: String },
    ConfigChange { key: String, old_value: String, new_value: String },
}

pub enum Permission {
    ReadGraph, WriteGraph, ExecuteRequests, ReadFilesystem, WriteAuditLog,
}

pub enum IpcMessage {
    OperationBatch { entries: Vec<OperationLogEntry> },
    QueryRequest { request_id: u64, query: GraphQuery },
    QueryResponse { request_id: u64, result: QueryResult },
    ModuleReady { module: ModuleIdentifier },
    ModuleShutdown { module: ModuleIdentifier },
    Heartbeat { module: ModuleIdentifier, timestamp_unix_ms: u64 },
}

pub enum GraphQuery {
    PathsBetween { from_node_id: u64, to_node_id: u64, max_hops: u32 },
    ReachableFrom { node_id: u64, edge_labels: Vec<EdgeLabel> },
    NodesByType { node_type: NodeType },
    FindingsByClass { vulnerability_class: VulnerabilityClass },
    AllFindings,
    CutVertices,
}

pub enum QueryResult {
    Paths { paths: Vec<Vec<u64>> },
    NodeIds { ids: Vec<u64> },
    Findings { findings: Vec<FindingData> },
    Error { message: String },
}

pub enum ParameterLocation {
    Query (default), Path, Header, Cookie, Body,
}

// Bridge request/response are internally-tagged serde enums (#[serde(tag = "type")])
pub enum BridgeRequest {
    GenerateHypotheses { request_id, scan_context: ScanContextIpc, vulnerability_class, feedback_summary },
    CompilePayloads { request_id, hypotheses: Vec<HypothesisIpc> },
    EvasionGenerate { request_id, defense_context: DefenseContextIpc },
    Shutdown,
}

pub enum BridgeResponse {
    Ready,
    Hypotheses { request_id, hypotheses, reasoning_trace, input_tokens, output_tokens },
    CompiledPayloads { request_id, payloads: Vec<String>, input_tokens, output_tokens },
    EvasionPayloads { request_id, payloads: Vec<String>, input_tokens, output_tokens },
    Error { request_id, message: String },
}

pub enum ScanEvent {
    EndpointDiscovered { endpoint, method, source_module: ModuleIdentifier },
    HypothesisGenerated { vulnerability_class: VulnerabilityClass, condition, confidence: f64 },
    PayloadTested { endpoint, payload_hash, vulnerability_class, anomaly_score: f64 },
    AnomalyDetected { endpoint, vulnerability_class, anomaly_type, score: f64 },
    FindingConfirmed { finding_id, vulnerability_class, severity, confidence: f64 },
    PhaseCompleted { phase_name, operations_applied, findings_count, duration_ms },
}

pub enum TargetValidationError {
    NonLocalhostTarget { host: String },
    InvalidUrl { url: String },
    AttestationFailed { reason: String },
}

pub enum AttestationError {
    InvalidSignature,
    Expired(String),
    TargetMismatch { expected: String, actual: String },
    InvalidPublicKey(String),
    InvalidFormat(String),
}

pub enum SignedConfigError {
    InvalidSignature,
    HashMismatch { expected: String, actual: String },
    InvalidPublicKey(String),
    InvalidFormat(String),
}
```

### Key Structs

```rust
pub struct Confidence(f64);  // newtype, validated [0.0, 1.0]
impl Confidence {
    pub fn new(value: f64) -> Result<Self, &'static str>;
    pub fn from_evidence(level: EvidenceLevel) -> Self;
    pub fn value(&self) -> f64;
}
// Custom Serialize: as f64. Custom Deserialize: invalid/None -> default 0.5.

pub struct FindingConfidence {
    pub prior: f64,
    pub likelihood_ratio: f64,
    pub methodology_reliability: f64,
    pub composite: Confidence,
}
impl FindingConfidence {
    pub fn compute(prior: f64, likelihood_ratio: f64, methodology_reliability: f64) -> Self;
    pub fn from_simple(confidence: Confidence) -> Self;
}
// composite = clamp(prior * likelihood_ratio * methodology_reliability, 0.0, 1.0)

pub struct FindingId { bytes: [u8; 32] }
impl FindingId {
    pub fn from_parts(endpoint: &str, vulnerability_class: VulnerabilityClass, parameter: &str) -> Self;
}
// SHA3-256(endpoint + ":" + vulnerability_class + ":" + parameter)

pub struct FindingData {
    pub id: u64,
    pub linked_node_ids: Vec<u64>,
    pub vulnerability_class: VulnerabilityClass,
    pub severity: f64,
    pub confidence: FindingConfidence,
    pub certificate: Vec<u8>,
    pub provenance_module: ModuleIdentifier,
    pub timestamp_unix_ms: u64,
    pub evidence_level: EvidenceLevel,
    pub stable_id: Option<FindingId>,
}
// Builder methods: with_stable_id(), with_linked_nodes(), with_certificate(),
//                  with_evidence_level(), with_confidence(), with_finding_confidence()
// Custom Deserialize handles 3 legacy formats:
//   - Full FindingConfidence JSON object {"prior": ..., "likelihood_ratio": ...}
//   - Legacy scalar confidence_score field
//   - Legacy confidence JSON number

pub struct NodeData {
    pub id: u64,
    pub node_type: NodeType,
    pub properties: HashMap<String, String>,
}
impl NodeData {
    pub fn new(id: u64, node_type: NodeType) -> Self;
    pub fn with_property(self, key, value) -> Self;
}

pub struct EdgeData {
    pub id: u64,
    pub source_node_id: u64,
    pub target_node_id: u64,
    pub label: EdgeLabel,
    pub weight: f64,
    pub provenance_module: ModuleIdentifier,
    pub provenance_sequence: u64,
}

pub struct OperationLogEntry {
    pub sequence_number: u64,
    pub module: ModuleIdentifier,
    pub operation: GraphOperation,
    pub timestamp_unix_ms: u64,
}

pub struct AuditEntry {
    pub sequence_number: u64,
    pub previous_hash: [u8; 32],
    pub timestamp_unix_ms: u64,
    pub event: AuditEventType,
    pub payload_cbor: Vec<u8>,
    pub hmac: [u8; 32],
}

pub struct CapabilityToken {
    pub module: ModuleIdentifier,
    pub permissions: Vec<Permission>,
    pub expires_at_unix_ms: u64,
    pub token_bytes: Vec<u8>,
}

pub struct FuzzRequest {
    pub request_id: u64,
    pub endpoint: String,
    pub method: String,
    pub parameter_name: String,
    pub parameter_location: ParameterLocation,
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

pub struct DefenseContext {
    pub has_waf: bool,
    pub waf_vendor: Option<String>,
    pub waf_blocked_categories: Vec<VulnerabilityClass>,
    pub rate_limit_rps: Option<f64>,
    pub bot_detection_present: bool,
    pub bot_detection_evaded: bool,
}

pub struct IpcFrame {
    pub message_length: u32,
    pub payload: Vec<u8>,
}
impl IpcFrame {
    pub fn encode(message: &IpcMessage) -> Result<Vec<u8>, serde_json::Error>;
    pub fn decode(data: &[u8]) -> Result<IpcMessage, IpcFrameDecodeError>;
}
// Wire format: 4-byte LE length prefix + JSON payload

pub struct ScanContextIpc {
    pub technology_stack: Vec<String>,
    pub findings_summary: Vec<String>,
    pub high_centrality_nodes: Vec<String>,
    pub defense_posture: serde_json::Value,
    pub class_confirmation_rates: HashMap<String, f64>,
    pub model_id: Option<String>,
}

pub struct HypothesisIpc {
    pub vulnerability_class: String,
    pub description: String,
    pub confidence: f64,
    pub test_specification: Option<String>,
}

pub struct DefenseContextIpc {
    pub has_waf: bool,
    pub waf_vendor: Option<String>,
    pub rate_limit_rps: Option<f64>,
    pub bot_detection_present: bool,
}

pub struct ScanEventEnvelope {
    pub event_id: u64,
    pub timestamp_unix_ms: u64,
    pub source_module: ModuleIdentifier,
    pub event: ScanEvent,
}
impl ScanEventEnvelope {
    pub fn new(event_id: u64, source_module: ModuleIdentifier, event: ScanEvent) -> Self;
    // Auto-fills timestamp from system clock
}

pub struct ScopeDocument {
    pub target: String,
    pub authorized_by: String,
    pub valid_until: String,  // YYYY-MM-DD
    pub scope_id: String,
}

pub struct SignedScopeAttestation {
    pub document: ScopeDocument,
    pub public_key_hex: String,
    pub signature_hex: String,
}

pub struct SignableConfig {
    pub target: String,
    pub stealth_level: String,
    pub max_iterations: u32,
    pub convergence_threshold: u32,
    pub no_llm: bool,
    pub include_endpoints: Option<Vec<String>>,
    pub exclude_endpoints: Option<Vec<String>>,
}

pub struct SignedConfig {
    pub config: SignableConfig,
    pub config_hash: String,  // SHA3-256 hex of canonical JSON
    pub public_key_hex: String,
    pub signature_hex: String,
}
```

### Free Functions

```rust
// Edge semantic validation
pub const EDGE_WHITELIST: &[(NodeType, EdgeLabel, NodeType)];  // 28 valid triples
pub fn is_valid_edge(source: NodeType, label: EdgeLabel, target: NodeType) -> bool;
pub fn valid_edge_count() -> usize;

// Finding helpers
pub fn confidence_from_evidence(evidence: EvidenceLevel) -> Confidence;

// Target validation (enforced at 3 layers: protocol, evasion-engine, fuzzing)
pub fn validate_target_is_localhost(url: &str) -> Result<(), TargetValidationError>;
pub fn validate_target(url: &str, attestation: Option<&SignedScopeAttestation>) -> Result<(), TargetValidationError>;
pub fn validate_target_with_override(
    url: &str,
    attestation: Option<&SignedScopeAttestation>,
    operator_authorized: bool,
) -> Result<(), TargetValidationError>;

// Scope attestation
pub fn sign_scope_document(document: &ScopeDocument, signing_key: &SigningKey) -> SignedScopeAttestation;
pub fn verify_attestation(attestation: &SignedScopeAttestation, target: &str) -> Result<(), AttestationError>;
pub fn load_attestation(path: &Path) -> Result<SignedScopeAttestation, AttestationError>;
pub fn days_to_ymd(days: u64) -> (i32, i32, i32);  // Howard Hinnant civil calendar algorithm

// Signed config
pub fn compute_config_hash(config: &SignableConfig) -> String;
pub fn sign_config(config: &SignableConfig, signing_key: &SigningKey) -> SignedConfig;
pub fn verify_signed_config(signed: &SignedConfig) -> Result<(), SignedConfigError>;
pub fn load_signed_config(path: &Path) -> Result<SignedConfig, SignedConfigError>;
pub fn verify_config_matches(signed: &SignableConfig, actual: &SignableConfig) -> Result<(), String>;
```

## Error Types

Each module defines its own error enum implementing `std::error::Error` and `Display`:

- `TargetValidationError` — NonLocalhostTarget, InvalidUrl, AttestationFailed
- `AttestationError` — InvalidSignature, Expired, TargetMismatch, InvalidPublicKey, InvalidFormat
- `SignedConfigError` — InvalidSignature, HashMismatch, InvalidPublicKey, InvalidFormat
- `IpcFrameDecodeError` — InsufficientData, DeserializeError(serde_json::Error)

`Confidence::new()` returns `Result<Self, &'static str>`.

No standard library error wrapping via `From` chains at this layer — protocol errors are kept flat
and concrete.

## Key Implementation Notes

**Edge whitelist is the security model in code.** The `EDGE_WHITELIST` constant is the single
source of truth for which graph relationships are semantically valid. Adding a new `NodeType` or
`EdgeLabel` variant requires updating both this array and the exhaustive coverage test in
`protocol_test.rs`, which will fail to compile if the match is non-exhaustive.

**FindingData deserializer handles three serialization generations.** The custom `Deserialize`
implementation reads a `Raw` helper struct and upgrades: (1) a full `FindingConfidence` JSON object
with `prior`, `likelihood_ratio`, `methodology_reliability` keys; (2) a legacy `confidence_score`
field (float); (3) a legacy `confidence` JSON number. All upgrade paths produce a valid
`FindingConfidence` without data loss.

**Confidence is always non-None.** `FindingData.confidence` is `FindingConfidence` (not
`Option<FindingConfidence>`). Tolerance in the deserializer (invalid inputs map to default 0.5)
ensures this invariant holds across serialization generations.

**EvidenceLevel::Controlled has a backwards-compat alias.** The variant was renamed from
`Counterfactual` to `Controlled`, but `#[serde(alias = "Counterfactual")]` ensures old audit log
entries and SARIF files still deserialize correctly.

**Target validation rejects obfuscated hosts.** `validate_target_is_localhost` normalizes the URL
via the `url` crate and then compares the raw host text against the normalized host. Encoded forms
like `0x7f000001` resolve to `127.0.0.1` after normalization but fail the raw-vs-normalized check,
blocking SSRF bypass attempts.

**Scope attestation uses canonical JSON for signature input.** Both sign and verify serialize
`ScopeDocument` with `serde_json::to_vec` and sign/verify the resulting bytes directly. URL
matching normalizes schemes to lowercase, strips trailing slashes, and strips default port suffixes
before comparison.

**BridgeRequest/BridgeResponse use `#[serde(tag = "type")]`.** The `"type"` discriminator field
is required in all JSON messages sent over the Unix socket bridge. Python and Rust sides must remain
in sync — adding a variant requires updating both `hypothesis_ipc.rs` and `bridge.py`.

## Usage Context

Every crate in the workspace depends on `aegis-protocol`. The orchestrator uses it at the top level
to construct scan configuration and drive the pipeline. The knowledge graph applies `GraphOperation`
entries. The audit log records `AuditEventType` events. The evasion engine and fuzzer use
`FuzzRequest/FuzzResponse` for HTTP transport. The hypothesis bridge serializes `BridgeRequest` and
deserializes `BridgeResponse` over the Unix socket. Target validation is enforced independently in
three layers (protocol, evasion-engine transport, fuzzing executor) for defense in depth.
