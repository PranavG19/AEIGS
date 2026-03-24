<!-- metadata:
  crate: aegis-reporting
  purpose: Multi-format scan report generation: SARIF 2.1.0 with CWE/ATT&CK, CBOR certificates,
           natural language narratives, and executive summaries
  public_api: RiskInput, RiskScore, ScoredFinding, DefenseScoreContext,
              compute_risk_score(), rank_findings(), top_remediation_targets(),
              score_with_defense(), compute_effective_severity(), sort_by_confidence(),
              SarifFinding, SarifDefenseContext, RelatedLocation, SarifLevel,
              emit_sarif(), sarif_to_json(), cwe_for(), attack_technique_for(), remediation_for(),
              CertificateType, Certificate (and subtypes), CertificateError,
              serialize_certificate(), deserialize_certificate(), certificate_hash(),
              generate_finding_narrative(), generate_executive_summary(), generate_actionable_narrative(),
              translate_centrality_to_narrative(), summarize_attack_paths(),
              describe_defense_impact(), remediation_advice(),
              ActionableNarrative, NarrativeContext,
              ReportFormat, DefenseSummary, ReportMetadata,
              format_report(), parse_report_format()
  modules: risk_scorer, sarif_emitter, certificate_serializer, narrative, report_format
  dependencies: aegis-protocol, aegis-knowledge-graph, aegis-fuzzing, serde, serde_json,
                ciborium, sha3, uuid, sarif_rust
-->

# aegis-reporting

## Purpose

`aegis-reporting` transforms raw scan findings into consumable outputs for three distinct audiences.
It provides a multi-factor risk scorer (exploitability × reachability × blast radius × confidence,
with precise defense adjustments), SARIF 2.1.0 emission with CWE and MITRE ATT&CK taxonomy
references, CBOR-serialized versioned evidence certificates, natural language narrative generation,
and a format dispatcher that selects Developer (IDE-native SARIF with inline fix suggestions),
Security (ATT&CK-enriched SARIF with defense gap analysis and cross-finding correlations), or
Executive (high-level summary JSON with severity counts, top remediation priorities, and defense
posture) output. The reporting crate is the final consumer of scan data in the pipeline.

## Crate Type

Library

## Dependencies on Workspace Crates

- `aegis-protocol` — `VulnerabilityClass`, `FindingData`, `EvidenceLevel`
- `aegis-knowledge-graph` — `GraphStore` trait (for data queries in the report phase)
- `aegis-fuzzing` — `DefenseProfile`, `WafProfile`, `RateLimitProfile`, `BotDetectionProfile`

## External Dependencies

| Dependency | Version | Role |
|---|---|---|
| serde | 1 | Derives on report structs |
| serde_json | 1 | JSON serialization of all report formats; property bags in SARIF |
| ciborium | 0.2 | CBOR serialization for evidence certificates (~40% smaller than JSON) |
| sha3 | 0.10 | SHA3-256 for certificate hashing |
| uuid | 1 | Available for callers |
| sarif_rust | 0.3 | Spec-compliant SARIF 2.1.0 type system; avoids hand-rolling schema |

## Module Structure

| Module | Responsibility |
|---|---|
| `risk_scorer` | Multi-factor risk scoring, defense-adjusted scoring, finding ranking |
| `sarif_emitter` | SARIF 2.1.0 emission with CWE + ATT&CK taxonomy references, per-finding fixes |
| `certificate_serializer` | CBOR-serialized versioned evidence certificates (v2 envelope) |
| `narrative` | Human-readable finding narratives, centrality explanations, executive summaries, actionable narratives |
| `report_format` | Top-level `format_report()` dispatcher; Developer/Security/Executive format logic |

## Public API Summary

### risk_scorer

```rust
pub struct RiskInput {
    pub vulnerability_class: VulnerabilityClass,
    pub cvss_exploitability: f64,  // 0.0–10.0 base CVSS exploitability
    pub is_authenticated: bool,
    pub is_rate_limited: bool,
    pub has_waf: bool,
    pub attack_path_count: u32,
    pub reachable_critical_assets: u32,
    pub asset_pii_weight: f64,     // 0.1–2.0; multiplier for PII-handling assets
    pub confidence: f64,
}

pub struct RiskScore {
    pub exploitability: f64,   // 0.0–10.0
    pub reachability: f64,     // 0.0–10.0; log-scale of attack_path_count
    pub blast_radius: f64,     // 0.0–10.0; critical assets * PII weight
    pub confidence: f64,       // 0.0–1.0
    pub composite: f64,        // 0.0–100.0
}

// composite = clamp((exploitability * reachability * blast_radius * confidence) / 1000 * 100, 0, 100)
// Defense adjustments (multiplicative, on exploitability):
//   is_authenticated: *0.7  (30% reduction — requires valid credentials)
//   is_rate_limited:  *0.8  (20% reduction — slows brute-force, doesn't prevent targeted attacks)
//   has_waf:          *0.6  (40% reduction — significant mitigation, known bypasses exist)
pub fn compute_risk_score(input: &RiskInput) -> RiskScore;

pub fn rank_findings(inputs: &[RiskInput]) -> Vec<(usize, RiskScore)>;
// Sorted by composite descending

pub fn top_remediation_targets(inputs: &[RiskInput], budget: usize) -> Vec<(usize, RiskScore)>;

// Defense-profile-aware scoring. Reverses generic adjustments and applies precise profile factors.
// WAF: if evasion succeeded -> undoes reduction; if category blocked -> *0.3; else -> *0.8
// Rate limit: RPS-based factor (0.6 for <10 rps, 0.95 for >100 rps, linear in between)
// Bot detection: if detected and not evaded -> *0.5
pub fn score_with_defense(
    input: &RiskInput,
    defense: &DefenseProfile,
    evasion_succeeded: bool,
    bypass_technique: Option<String>,
) -> ScoredFinding;

pub fn compute_effective_severity(severity: f64, effective_confidence: f64) -> f64;
// = severity * confidence.clamp(0.0, 1.0)

pub fn sort_by_confidence(findings: &mut [ScoredFinding]);

pub struct DefenseScoreContext {
    pub waf_present: bool,
    pub waf_bypassed: bool,
    pub bypass_technique: Option<String>,
    pub rate_limit_present: bool,
    pub bot_detection_present: bool,
    pub bot_detection_evaded: bool,
}

pub struct ScoredFinding {
    pub finding_id: u64,
    pub composite_score: f64,
    pub exploitability: f64,
    pub reachability: f64,
    pub blast_radius: f64,
    pub confidence: f64,
    pub defense_context: Option<DefenseScoreContext>,
}
```

### sarif_emitter

```rust
pub struct SarifFinding {
    pub rule_id: String,
    pub rule_description: String,
    pub level: SarifLevel,
    pub message: String,
    pub uri: Option<String>,                        // artifact URI (file path or URL)
    pub logical_location_name: Option<String>,
    pub logical_location_kind: Option<String>,      // defaults to "function"
    pub severity: f64,
    pub confidence: f64,
    pub composite_score: f64,
    pub vulnerability_class: Option<VulnerabilityClass>,
    pub related_locations: Vec<RelatedLocation>,
    pub defense_context: Option<SarifDefenseContext>,
    pub evidence_level: Option<String>,
    pub cve_id: Option<String>,   // if set, NVD link added as related location
    pub mitigation_rank: Option<u32>,
    pub suppression_kind: Option<String>,           // "inSource" for risk-accepted findings
    pub suppression_message: Option<String>,
    pub endpoint: Option<String>,
    pub http_method: Option<String>,
    pub parameter_name: Option<String>,
}

pub struct RelatedLocation { pub uri: Option<String>, pub message: String }

pub enum SarifLevel { Error, Warning, Note, None }
impl SarifLevel { pub fn as_str(&self) -> &str; }

pub struct SarifDefenseContext {
    pub waf_vendor: Option<String>,
    pub exploitable_despite_waf: bool,
    pub evasion_technique: Option<String>,
    pub defenses_detected: Vec<String>,
    pub evasion_success_rate: Option<f64>,
    pub stealth_mode_used: bool,
}

// Build a SarifLog from findings. Deduplicates rules by rule_id.
// Adds CWE taxonomy (index 0) and MITRE ATT&CK taxonomy (index 1) to run.taxonomies.
// Each result gets .taxa with CWE + ATT&CK references and .fixes with remediation text.
// run.properties contains aggregate defense info when any finding has defense_context.
pub fn emit_sarif(findings: &[SarifFinding], tool_version: &str) -> SarifLog;

pub fn sarif_to_json(report: &SarifLog) -> Result<String, serde_json::Error>;

// Exhaustive mappings for all 34 VulnerabilityClass variants:
pub fn cwe_for(class: &VulnerabilityClass) -> &'static str;
// Examples: SqlInjection->"CWE-89", CrossSiteScripting->"CWE-79", CommandInjection->"CWE-78"
// Full list: SqlInjection/89, CrossSiteScripting/79, CommandInjection/78, PathTraversal/22,
//   SSRF/918, InsecureDeserialization/502, BrokenAuthentication/287, BrokenAuthorization/863,
//   SecurityMisconfiguration/16, SensitiveDataExposure/200, SSTI/1336, HeaderInjection/113,
//   OpenRedirect/601, CrlfInjection/93, KnownVulnerableDependency/1395,
//   InsufficientInputValidation/20, NoSqlInjection/943, XXE/611, CrossOriginMisconfiguration/942,
//   MissingSecurityHeader/693, JwtVulnerability/347, HttpRequestSmuggling/444, RaceCondition/362,
//   SubdomainTakeover/284, PrototypePollution/1321, GraphQlAbuse/20, CloudMisconfiguration/16,
//   Clickjacking/1021, CachePoisoning/349, HostHeaderInjection/644, IDOR/639,
//   InformationDisclosure/200, WeakCryptography/327, MassAssignment/915

pub fn attack_technique_for(class: &VulnerabilityClass) -> &'static str;
// Examples: SqlInjection->"T1190", CrossSiteScripting->"T1189", CommandInjection->"T1059"

pub fn remediation_for(class: &VulnerabilityClass) -> &'static str;
// One-sentence actionable fix per class; all 34 variants covered
```

### certificate_serializer

```rust
pub enum CertificateType { Fuzzing, Taint, Chain, Config, Dependency, Evasion }

pub enum Certificate {
    Fuzzing(FuzzingCertificate),
    Taint(TaintCertificate),
    Chain(ChainCertificate),
    Config(ConfigCertificate),
    Dependency(DependencyCertificate),
    Evasion(EvasionCertificate),
}

pub struct FuzzingCertificate {
    pub request_method: String, pub request_url: String,
    pub request_headers: Vec<(String, String)>, pub request_body: Vec<u8>,
    pub response_status: u16, pub response_body: Vec<u8>,
    pub anomaly_type: String, pub statistical_significance: f64,
}
pub struct TaintCertificate {
    pub source_location: SourceSinkLocation,
    pub sink_location: SourceSinkLocation,
    pub path_steps: Vec<TaintPathStep>,
}
pub struct SourceSinkLocation { pub file: String, pub line: u32, pub function: String, pub variable: String }
pub struct TaintPathStep { pub file, pub line, pub function, pub variable, pub operation: String }
pub struct ChainCertificate { pub steps: Vec<ChainStep> }
pub struct ChainStep { pub vulnerability_id: u64, pub description: String, pub transition_condition: String }
pub struct ConfigCertificate { pub config_key: String, pub current_value: String, pub expected_value: String }
pub struct DependencyCertificate { pub package_name: String, pub installed_version: String, pub vulnerable_range: String, pub cve_id: String }
pub struct EvasionCertificate {
    pub original_payload: String, pub evasion_payload: String,
    pub defense_vendor: String, pub evasion_technique: String,
    pub block_response_status: u16, pub bypass_response_status: u16,
    pub anomaly_detected: bool,
}

pub enum CertificateError {
    SerializeError(String),
    DeserializeError(String),
    UnsupportedVersion(u16),  // version == 0 or > 2 (current)
}

// Serialize to CBOR with v2 versioned envelope: CBOR({ version: 2, payload: CBOR(Certificate) })
pub fn serialize_certificate(cert: &Certificate) -> Result<Vec<u8>, CertificateError>;

// Deserialize from versioned CBOR envelope; rejects version 0 or > CURRENT_VERSION
pub fn deserialize_certificate(data: &[u8]) -> Result<Certificate, CertificateError>;

// SHA3-256 hash of CBOR bytes (for FindingData.certificate integrity checking)
pub fn certificate_hash(data: &[u8]) -> [u8; 32];
```

### narrative

```rust
// One-sentence finding description with severity label and optional defense context note
pub fn generate_finding_narrative(
    rule_id: &str,
    vulnerability_class: Option<&str>,
    composite_score: f64,
    defense_context: Option<&str>,
) -> String;
// Severity labels: >= 70.0 = "high", >= 40.0 = "medium", else "low"

// Betweenness centrality narrative (3 tiers based on centrality value)
pub fn translate_centrality_to_narrative(node_label: &str, centrality: f64) -> String;
// > 0.7: "critical chokepoint — X% of attack paths pass through it"
// 0.3-0.7: "moderately connected"
// < 0.3: "limited connectivity"

pub fn generate_executive_summary(
    total_findings: usize, critical_count: usize, high_count: usize,
    defenses_detected: &[String],
) -> String;

pub fn summarize_attack_paths(entry_count: usize, asset_count: usize, total_paths: usize) -> String;
pub fn describe_defense_impact(defense_name: &str, score_reduction_pct: f64) -> String;

// Map vulnerability class display name to remediation guidance
pub fn remediation_advice(vulnerability_class: &str) -> &'static str;
// Covers: "SQL Injection", "Cross-Site Scripting", "Command Injection", "Path Traversal",
//         "Server-Side Request Forgery", "Broken Authentication", "Broken Authorization"
// Default for all other classes

pub struct NarrativeContext {
    pub endpoint: String, pub method: String, pub parameter: String,
    pub vulnerability_class: String, pub severity: f64, pub confidence: f64,
    pub is_authenticated: bool, pub accesses_pii: bool,
    pub defense_context: Option<String>, pub calibration_note: Option<String>,
}
pub struct ActionableNarrative {
    pub what: String,            // "{class} in the {param} parameter of {method} {endpoint}"
    pub why_it_matters: String,  // auth status, PII flag, severity, active defense
    pub how_to_fix: String,      // remediation_advice() result
    pub confidence_note: String, // "Confidence: X%." + low-confidence manual-verify warning
}
pub fn generate_actionable_narrative(ctx: &NarrativeContext) -> ActionableNarrative;
```

### report_format

```rust
pub enum ReportFormat { Developer, Security, Executive }

pub struct DefenseSummary {
    pub has_waf: bool, pub waf_vendor: Option<String>,
    pub has_rate_limiting: bool, pub has_bot_detection: bool,
}

pub struct ReportMetadata {
    pub target_url: String, pub total_duration_secs: f64, pub phases_completed: u32,
}

pub fn format_report(
    findings: &[SarifFinding],
    format: ReportFormat,
    tool_version: &str,
    metadata: Option<&ReportMetadata>,
    defense_summary: Option<&DefenseSummary>,
) -> Result<String, String>;
// Developer: emit_sarif() -> pretty JSON
// Security: emit_sarif() -> inject securityAnalysis into run.properties
//           (attackChains, defenseGaps, findingCorrelations grouped by VulnerabilityClass)
// Executive: ExecutiveSummary JSON: total_findings, severity_counts, risk_summary,
//            top_remediation_priorities (top 5 by composite score), defense_posture_summary,
//            scan_metadata

pub fn parse_report_format(s: &str) -> Result<ReportFormat, String>;
// "developer" | "security" | "executive"
```

## Error Types

- `CertificateError` — SerializeError(String), DeserializeError(String), UnsupportedVersion(u16)
- `format_report` returns `Result<String, String>` where the error is a stringified serialization error.
- `sarif_to_json` returns `Result<String, serde_json::Error>`.

All implement `std::error::Error` and `Display`.

## Key Implementation Notes

**Risk scoring uses normalized product form.** The formula is
`(exploitability × reachability × blast_radius × confidence) / 1000 × 100`. The divisor `1000`
normalizes the product of three 0–10 scores to a 0–100 human-readable scale. The `/ 1000 * 100`
is written explicitly in source code comments to document the normalization intent.

**`score_with_defense` reverses generic adjustments then re-applies precise ones.** The generic
`compute_risk_score` path applies blanket multipliers (0.7 auth, 0.8 rate-limit, 0.6 WAF). The
`score_with_defense` function "undoes" those via division (e.g., `/ 0.6` to undo the WAF reduction)
then applies WAF-category-specific factors (0.3 if the vuln class is actively blocked, 0.8 if WAF
is present but not blocking this class). This two-step approach keeps the generic path simple.

**SARIF uses `sarif_rust` types throughout.** The crate does not hand-roll SARIF serialization.
All struct types (`Run`, `Tool`, `ToolComponent`, `ReportingDescriptor`, `Location`, etc.) come
from `sarif_rust`. `sarif_rust` fields are `Option<Vec<...>>` per the SARIF JSON schema — access
via `.as_ref().unwrap()` after construction.

**`cwe_for`, `attack_technique_for`, `remediation_for` are exhaustive over all 34 variants.**
The Rust compiler enforces match exhaustiveness. Adding a new `VulnerabilityClass` variant in
`aegis-protocol` will produce compile errors in all three functions, forcing the reporting crate
to be updated at the same time.

**Certificate envelope is versioned at v2.** The outer CBOR wrapper `{ version: u16, payload: bytes }`
allows future format changes without breaking deserializers. Versions 1 and 2 are accepted on
read; only v2 is written. Version 0 is explicitly rejected with `UnsupportedVersion`. The envelope
version is separate from the `Certificate` enum variant.

**Security format injects properties post-SARIF.** `format_security` calls `emit_sarif`,
converts to `serde_json::Value`, and walks the JSON tree to inject `securityAnalysis` into
`runs[0].properties`. This avoids duplicating SARIF emission logic for the security persona.

**Executive top-remediation list is capped at 5 entries.** The internal `RemediationPriority`
struct is `Serialize` but not public — it serializes directly into the JSON output. The executive
report does not depend on `sarif_rust` at all.

**`narrative.rs::remediation_advice` maps display names, not enum variants.** It takes `&str`
matching the `Display` output of `VulnerabilityClass`. This is distinct from
`sarif_emitter.rs::remediation_for` which takes `&VulnerabilityClass` directly. The narrative
version covers 7 common classes with detailed guidance; the SARIF version covers all 34 with
shorter one-sentence remediations.

## Usage Context

The report phase (`phase_report.rs` in the orchestrator) reads all findings from the knowledge
graph via `all_findings()`, scores them with `compute_risk_score` (or `score_with_defense` when
a `DefenseProfile` is available), constructs `SarifFinding` values, and calls `format_report`
with the requested `ReportFormat`. The orchestrator passes `--report-format developer|security|
executive` (default: developer). Evidence certificates are constructed during the fuzz phase
and stored as CBOR bytes in `FindingData.certificate`; they can be deserialized with
`deserialize_certificate` for display in detailed reports. `generate_actionable_narrative` is
called per-finding to produce the human-readable `message` field in SARIF results.
