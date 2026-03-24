# Type System Improvements

Generated: 2026-02-23 | Source depth: 2 (source-confirmed for high/critical)

---

### TYPE-001: GraphOperation::AddFinding Uses raw f64 Instead of Confidence Newtype
**Severity:** high
**Effort:** small
**Affected:** aegis-protocol, aegis-orchestrator, aegis-knowledge-graph
**Source confirmed:** yes (`operation.rs:19-26`, `phase_fuzz.rs:436-444`)

`GraphOperation::AddFinding` carries `confidence: f64` instead of `Confidence`. This means:
1. The validated `Confidence` value from `FindingConfidence::compute()` is immediately unwrapped to f64 at the call site (`provenance.composite.value()`)
2. The graph operation log must re-validate bounds in `validate_batch()`
3. Any consumer of `GraphOperation` who constructs `AddFinding` can bypass `Confidence::new()` validation

**Recommendation:** Change `GraphOperation::AddFinding::confidence` from `f64` to `Confidence`. Update all construction sites. The `validate_batch()` check for confidence bounds can then be simplified or removed.

**Code location:** `crates/protocol/src/operation.rs:19-26`

---

### TYPE-002: NodeData Properties Bag (HashMap<String, String>) Loses Type Safety
**Severity:** medium
**Effort:** large
**Affected:** aegis-protocol, all crates that read node properties
**Source confirmed:** yes (`node.rs:35`)

`NodeData::properties: HashMap<String, String>` is an untyped property bag. Code across the codebase uses magic strings like `n.properties.get("path")`, `n.properties.get("method")`, `n.properties.get("name")`, `n.properties.get("version")` to access node-type-specific properties. This is stringly-typed and brittle.

**Recommendation:** Define enum-tagged property types per NodeType:
```rust
pub enum NodeProperties {
    Endpoint { path: String, method: String },
    Dependency { name: String, version: String, ecosystem: String },
    Defense { has_waf: bool, waf_vendor: Option<String>, rate_limit_rps: Option<f64> },
    // ...
}
```
Or at minimum, define strongly-typed property key constants:
```rust
pub mod node_props {
    pub const PATH: &str = "path";
    pub const METHOD: &str = "method";
    pub const NAME: &str = "name";
}
```

**Code location:** `crates/protocol/src/node.rs:35`

---

### TYPE-003: Error Types Contain String Where Structured Variants Would Be Better
**Severity:** medium
**Effort:** medium
**Affected:** aegis-orchestrator, aegis-knowledge-graph
**Source confirmed:** yes

Multiple error types use `String` fields that lose structured context:
- `PhaseError::ReportFormat(String)` and `UnknownExportFormat(String)` — should carry `format: String` with context
- `GraphError::Io(String)` — wraps string instead of `io::Error`, losing error source chain
- `ConfigError::*FileRead(String)`, `*FileParse(String)` — should carry `path: PathBuf, source: io::Error`
- `ValidationError::InvalidEdgeSemantics` could include the attempted triple for debugging

**Recommendation:** Use `thiserror` (already in workspace deps) to derive error types with structured fields:
```rust
#[derive(thiserror::Error, Debug)]
pub enum GraphError {
    #[error("graph validation failed: {0}")]
    Validation(#[from] ValidationError),
    #[error("operation log error: {0}")]
    OperationLog(#[from] OperationLogError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),  // Preserve io::Error instead of String
}
```

**Code location:** `crates/knowledge-graph/src/graph.rs:17-21`, `crates/orchestrator/src/phase_error.rs`

---

### TYPE-004: ScanContextJson Type Alias for ScanContextIpc is Confusing
**Severity:** medium
**Effort:** small
**Affected:** aegis-orchestrator
**Source confirmed:** yes (CLAUDE.md and type_system.md confirm this alias)

`ScanContextJson = ScanContextIpc` is a type alias that adds confusion: the name `Json` implies it's a serialization-specific type, but it's actually the canonical IPC struct. This alias is used throughout the orchestrator but not in the protocol crate where the actual type lives.

**Recommendation:** Remove the alias. Use `ScanContextIpc` directly in orchestrator code, or rename it to `ScanContextIpc` everywhere. The alias adds cognitive overhead with no benefit.

**Code location:** `crates/orchestrator/src/hypothesis_bridge.rs`

---

### TYPE-005: Confidence Newtype Missing Arithmetic Operations
**Severity:** low
**Effort:** small
**Affected:** aegis-protocol
**Source confirmed:** partial

`Confidence(f64)` is a validated newtype but doesn't implement any arithmetic operations. Code that needs to combine or scale confidence values must call `.value()`, perform the operation, then re-create a `Confidence` (with potential loss of invariant protection if done carelessly). Common operations like `confidence.scale(0.8)` or clamped addition would be natural fits.

**Recommendation:** Add methods like `fn clamp_scale(&self, factor: f64) -> Confidence` that perform validated operations and return new `Confidence` values. This prevents the anti-pattern of extracting and re-wrapping.

---

### TYPE-006: StealthLevel Enum Defined but Backed by String in ScanConfig
**Severity:** medium
**Effort:** small
**Affected:** aegis-orchestrator
**Source confirmed:** yes (`scan_config.rs` defines `StealthLevel` enum but `StealthOptions::stealth_level` is `String`)

`StealthLevel` enum exists (`Default | Aggressive | Paranoid`) but `StealthOptions::stealth_level` stores a `String`. The `parse_stealth_level(s: &str)` function converts from String to enum. This means:
1. Invalid stealth levels are only detected at runtime, not compile time
2. The enum variant exists alongside the string field creating inconsistency

**Recommendation:** Change `StealthOptions::stealth_level` to `StealthLevel` (using clap's `ValueEnum` derive). Remove the `parse_stealth_level()` conversion function. This is a clean clap pattern.

**Code location:** `crates/orchestrator/src/scan_config.rs:11-15, 163`

---

### TYPE-007: EvidenceLevel → Confidence Mapping Undocumented Magic Constants
**Severity:** low
**Effort:** small
**Affected:** aegis-protocol
**Source confirmed:** yes (`finding.rs:26-33`)

`Confidence::from_evidence()` maps `EvidenceLevel` to hardcoded scores (0.4, 0.7, 0.9, 0.95). These constants encode domain knowledge (what confidence does "Statistical" evidence deserve?) but are unnamed and undocumented.

**Recommendation:** Name the constants and document the rationale:
```rust
const STATISTICAL_EVIDENCE_CONFIDENCE: f64 = 0.4;  // Pattern correlation only
const CONTROLLED_EVIDENCE_CONFIDENCE: f64 = 0.7;   // Counterfactual test passed
const CONFIRMED_EVIDENCE_CONFIDENCE: f64 = 0.9;    // Verified exploitation
const CHAINED_EVIDENCE_CONFIDENCE: f64 = 0.95;     // Multi-step chain confirmed
```

**Code location:** `crates/protocol/src/finding.rs:26-33`

---

### TYPE-008: VulnerabilityClass 34-Variant Flat Enum — Consider Grouping
**Severity:** low
**Effort:** large
**Affected:** aegis-protocol, compliance, fuzzing
**Source confirmed:** yes

`VulnerabilityClass` has 34 flat variants. Match arms appear in at least 5 crates. Adding new variants requires updating `compliance_mapper`, `class_mapper`, CWE mappings, ATT&CK mappings, LLM prompts, and fixture tests. This creates high maintenance overhead for a commonly extended type.

**Recommendation:** Consider grouping into categories:
```rust
pub enum VulnerabilityClass {
    Injection(InjectionType),      // SqlInjection, CommandInjection, XSS, SSTI, ...
    AuthFlaw(AuthFlawType),        // BrokenAuthentication, BrokenAuthorization, JWT, ...
    Configuration(ConfigType),     // SecurityMisconfiguration, MissingSecurityHeader, ...
    // ...
}
```
This is a large breaking change but would make exhaustive matching more manageable. At minimum, add `fn category(&self) -> &'static str` to group variants for display/filtering purposes.

---

### TYPE-009: ModuleIdentifier Missing Variants for New Modules
**Severity:** low
**Effort:** small
**Affected:** aegis-protocol
**Source confirmed:** yes

`ModuleIdentifier` has 7 variants: `PassiveRecon, Enumeration, Fuzzing, HypothesisEngine, ChainSynthesis, Discovery, Proxy`. There's no `Crawler` or `DomVerify` variant for the newer phases. Operations produced by the crawl and dom_verify phases would need to use one of the existing variants or be added.

**Recommendation:** Add `Crawler` and `DomVerify` variants to `ModuleIdentifier`. This is a small additive change with downstream exhaustive match impacts in `compliance_mapper` and elsewhere.

**Code location:** `crates/protocol/src/operation.rs:28-37`

---

### TYPE-010: FindingData Has pub Fields Without Invariant Protection
**Severity:** low
**Effort:** medium
**Affected:** aegis-protocol
**Source confirmed:** yes (`finding.rs:259-272`)

`FindingData` has all public fields. This means callers can set `severity = 999.0` or `confidence = FindingConfidence { composite: Confidence(2.0) }` directly after construction, bypassing invariant checks. The fluent builder pattern (`with_*` methods) exists but is not enforced.

**Recommendation:** Make fields private and expose them only via accessor methods or via the builder `with_*` pattern. Alternatively, use `#[serde(getter)]` or a similar pattern to allow deserialization while preventing direct field mutation. The most pragmatic fix: add invariant validation to `FindingData::new()` that panics on invalid inputs in debug mode.

---

### TYPE-011: Missing TryFrom Implementations for CLI String Types
**Severity:** low
**Effort:** small
**Affected:** aegis-orchestrator
**Source confirmed:** yes (`scan_config.rs:435-453`)

Functions like `parse_stealth_level(s: &str) -> Result<StealthLevel, ConfigError>` and `resolve_persona_id(s: &str) -> Result<PersonaId, ConfigError>` are standalone functions that should be `TryFrom<&str>` implementations. Using `TryFrom` makes the conversion discoverable via the standard Rust type system.

**Recommendation:**
```rust
impl TryFrom<&str> for StealthLevel {
    type Error = ConfigError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        parse_stealth_level(s)
    }
}
```

**Code location:** `crates/orchestrator/src/scan_config.rs:435-453`

---

### TYPE-012: ParameterLocation Missing `GraphQL` Variant
**Severity:** low
**Effort:** small
**Affected:** aegis-protocol
**Source confirmed:** partial

`ParameterLocation` has `Query | Path | Header | Cookie | Body` but no `GraphQL` variant for GraphQL operation parameters (which have different injection semantics). GraphQL testers likely repurpose `Body`.

**Recommendation:** Add `GraphQL` variant to `ParameterLocation` or document that `Body` covers GraphQL operation injection.

**Code location:** `crates/protocol/src/request.rs:6-13`
