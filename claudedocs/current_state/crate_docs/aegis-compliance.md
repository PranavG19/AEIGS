<!-- metadata: crate=aegis-compliance, purpose=CVSS scoring + compliance framework mapping + pentest report generation, type=library, internal_deps=[aegis-protocol], external_deps=[serde, serde_json] -->

# aegis-compliance

## Purpose

Provides CVSS v3.1 base score computation, compliance framework mapping (OWASP Top 10 2021, OWASP API Security 2023, CWE, PCI-DSS 3.2.1), and human-readable pentest report generation for all 34 `VulnerabilityClass` variants.

## Crate Type

Library

## Dependencies on Workspace Crates

- `aegis-protocol` — `VulnerabilityClass` enum (all 34 variants)

## External Dependencies

- `serde`, `serde_json` — serialization of CVSS metrics, report structs

## Module Structure

| Module | Description |
|---|---|
| `cvss_scorer` | CVSS v3.1 base score computation (FIRST spec formula), severity labels, vector string generation |
| `class_mapper` | Maps each `VulnerabilityClass` to default worst-case CVSS metrics |
| `compliance_mapper` | Maps each `VulnerabilityClass` to OWASP Top 10 2021, OWASP API Security 2023, CWE, and PCI-DSS references |
| `report_generator` | Assembles full pentest reports with executive summary, finding narratives, remediation roadmap, and compliance summary |
| `context_adjuster` | (Private) Adjusts CVSS metrics based on deployment context (WAF presence, authentication requirements, etc.) |

## Public API Summary

### `cvss_scorer`

```rust
pub enum AttackVector { Network, Adjacent, Local, Physical }
pub enum AttackComplexity { Low, High }
pub enum PrivilegesRequired { None, Low, High }
pub enum UserInteraction { None, Required }
pub enum Scope { Unchanged, Changed }
pub enum Impact { None, Low, High }

pub enum CvssSeverity { None, Low, Medium, High, Critical }
// implements Display: "None" / "Low" / "Medium" / "High" / "Critical"

pub struct CvssMetrics { attack_vector, attack_complexity, privileges_required,
                          user_interaction, scope, confidentiality, integrity, availability }

pub struct CvssResult { score: f64, vector_string: String, severity_label: CvssSeverity }

/// Computes CVSS v3.1 base score using the exact FIRST spec formula.
/// Applies "round up" (ceil at 1 decimal place) per spec.
pub fn compute_cvss(metrics: &CvssMetrics) -> CvssResult

/// Maps raw score to severity label (0.0=None, <=3.9=Low, <=6.9=Medium, <=8.9=High, >8.9=Critical).
pub fn severity_from_score(score: f64) -> CvssSeverity
```

### `class_mapper`

```rust
/// Maps VulnerabilityClass to default CVSS metrics.
/// Represents typical worst-case context for web application testing.
/// Context adjustments applied separately via context_adjuster.
pub fn default_cvss_for_class(vuln_class: VulnerabilityClass) -> CvssMetrics
```

### `compliance_mapper`

```rust
pub struct ComplianceMapping {
    pub owasp_2021: Option<String>,    // e.g., "A03:2021 Injection"
    pub owasp_api_2023: Option<String>, // e.g., "API2:2023 Broken Auth"
    pub cwe: String,                   // e.g., "CWE-89"
    pub pci_dss: Option<String>,       // e.g., "6.5.1"
}

/// Exhaustive mapping over all 34 VulnerabilityClass variants.
pub fn map_to_compliance(vuln_class: VulnerabilityClass) -> ComplianceMapping

/// Generates a markdown section grouping findings by OWASP 2021 category with counts.
pub fn format_owasp_report_section(mappings: &[ComplianceMapping]) -> String

/// Generates a markdown section grouping findings by PCI-DSS requirement with counts.
pub fn format_pci_dss_section(mappings: &[ComplianceMapping]) -> String
```

### `report_generator`

```rust
pub struct ReportInput { target_url, scan_duration_secs, total_findings,
                          critical_count, high_count, medium_count, low_count,
                          tech_stack: Vec<String>, defenses_detected: Vec<String>,
                          findings: Vec<FindingInput> }

pub struct FindingInput { vulnerability_class: String, endpoint: String,
                           parameter: Option<String>, evidence: String,
                           cvss_score: f64, cvss_vector: String,
                           owasp_category: Option<String>, poc_command: Option<String> }

pub struct FindingNarrative { title, description, impact, proof_of_concept,
                               remediation, references: Vec<String>,
                               cvss_score: f64, cvss_vector: String, owasp_category: Option<String> }

pub struct PentestReport { executive_summary, methodology, findings: Vec<FindingNarrative>,
                            remediation_roadmap, compliance_summary }

/// Assembles the full report from a ReportInput. All sections generated deterministically.
pub fn generate_full_report(input: &ReportInput) -> PentestReport

pub fn generate_executive_summary(input: &ReportInput) -> String
pub fn generate_finding_narrative(finding: &FindingInput) -> FindingNarrative
pub fn generate_remediation_roadmap(findings: &[FindingInput]) -> String
```

## Key Implementation Notes

- **CVSS v3.1 spec fidelity**: `cvss_scorer.rs` implements the FIRST specification exactly, including the `roundup()` function (ceiling at 1 decimal place via `(value * 10.0).ceil() / 10.0`). The `PrivilegesRequired` weight is scope-dependent — `PrivilegesRequired::Low` yields 0.62 when `Scope::Unchanged` but 0.68 when `Scope::Changed` (cvss_scorer.rs:171-178).

- **Exhaustiveness invariant**: Both `default_cvss_for_class` and `map_to_compliance` are exhaustive `match` expressions over all 34 `VulnerabilityClass` variants. Adding a new variant to the protocol crate will cause a compile error here, forcing an update.

- **Report generator uses string-matched vulnerability classes**: `description_for_class`, `remediation_for_class`, and `cwe_for_class` in `report_generator.rs` match on `&str` (`VulnerabilityClass::to_string()` output) rather than the enum directly. This means the `VulnerabilityClass::Display` output must match the strings used in these functions (e.g., "SQL Injection", "Cross-Site Scripting"). The default `_` arms provide fallback output for unknown strings.

- **Remediation roadmap triage**: `generate_remediation_roadmap` classifies findings into Immediate (Critical/High), Short-Term (Medium), and Long-Term (Low/None) buckets based on CVSS severity computed from the provided score (report_generator.rs:121-167).

- **PCI-DSS coverage gaps**: Some classes have no PCI-DSS mapping (`pci_dss: None`): `OpenRedirect`, `RaceCondition`, `SubdomainTakeover`, `PrototypePollution`, `GraphQlAbuse`, `CachePoisoning`. These are noted in `compliance_mapper.rs:150-212`.

## Usage Context

Used by the `aegis-reporting` crate and the `orchestrator` to generate compliance-annotated CVSS scores and human-readable pentest narratives. Called during `phase_report` to produce executive summary sections. Also used standalone when generating SARIF `CvssResult` data for each finding.
