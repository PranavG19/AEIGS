/// Autonomous report generator: produce kill chain narrative reports.
///
/// Generates executive narratives, chronological timelines, evidence chains,
/// impact assessments, and priority-ordered remediation recommendations from
/// kill chain execution data.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An action recorded during the kill chain for timeline generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineAction {
    pub timestamp_ms: u64,
    pub phase: String,
    pub action: String,
    pub target: Option<String>,
    pub result: String,
    pub evidence_ref: Option<String>,
}

/// HTTP request/response pair captured as evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpEvidence {
    pub request_method: String,
    pub request_url: String,
    pub request_headers: HashMap<String, String>,
    pub request_body: Option<String>,
    pub response_status: u16,
    pub response_headers: HashMap<String, String>,
    pub response_body_snippet: String,
}

/// A single link in the evidence chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceLink {
    pub step_number: usize,
    pub description: String,
    pub http_evidence: Option<HttpEvidence>,
    pub finding_id: Option<String>,
    pub critical: bool,
}

/// Data exposed during the kill chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposedData {
    pub data_type: String,
    pub description: String,
    pub record_count: Option<u64>,
    pub sensitivity: DataSensitivity,
}

/// Sensitivity classification for exposed data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataSensitivity {
    Public,
    Internal,
    Confidential,
    Restricted,
    Pii,
}

/// A recommended remediation action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remediation {
    pub priority: u32,
    pub title: String,
    pub description: String,
    pub phase_blocked: String,
    pub effort: RemediationEffort,
    pub cwe_ids: Vec<String>,
}

/// Estimated effort for remediation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemediationEffort {
    Low,
    Medium,
    High,
}

/// Input data for report generation.
#[derive(Debug, Clone)]
pub struct ReportInput {
    pub target_url: String,
    pub objective: String,
    pub objective_achieved: bool,
    pub objective_progress_pct: f64,
    pub final_access_level: String,
    pub timeline: Vec<TimelineAction>,
    pub evidence_chain: Vec<EvidenceLink>,
    pub exposed_data: Vec<ExposedData>,
    pub credentials_obtained: Vec<ReportCredential>,
    pub hosts_compromised: Vec<String>,
    pub vulnerabilities_exploited: Vec<ExploitedVuln>,
}

/// Credential info for reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportCredential {
    pub username: String,
    pub credential_type: String,
    pub source: String,
    pub access_level: String,
}

/// Vulnerability exploited during the kill chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitedVuln {
    pub vulnerability_class: String,
    pub endpoint: String,
    pub severity: f64,
    pub cwe_id: Option<String>,
    pub technique: String,
}

/// The complete auto-generated report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoReport {
    pub executive_narrative: String,
    pub timeline: Vec<TimelineAction>,
    pub evidence_chain: Vec<EvidenceLink>,
    pub impact_assessment: ImpactAssessment,
    pub remediations: Vec<Remediation>,
    pub metadata: ReportMetadata,
}

/// Impact assessment section of the report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactAssessment {
    pub overall_risk: String,
    pub data_exposure_summary: String,
    pub access_achieved: String,
    pub exposed_data: Vec<ExposedData>,
    pub credential_count: usize,
    pub hosts_compromised: usize,
}

/// Report metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub target_url: String,
    pub objective: String,
    pub objective_achieved: bool,
    pub objective_progress_pct: f64,
    pub total_actions: usize,
    pub total_evidence_steps: usize,
    pub total_remediations: usize,
}

/// Generate the complete auto report from input data.
pub fn generate_auto_report(input: &ReportInput) -> AutoReport {
    let narrative = build_executive_narrative(input);
    let impact = build_impact_assessment(input);
    let remediations = build_remediations(input);

    let metadata = ReportMetadata {
        target_url: input.target_url.clone(),
        objective: input.objective.clone(),
        objective_achieved: input.objective_achieved,
        objective_progress_pct: input.objective_progress_pct,
        total_actions: input.timeline.len(),
        total_evidence_steps: input.evidence_chain.len(),
        total_remediations: remediations.len(),
    };

    AutoReport {
        executive_narrative: narrative,
        timeline: input.timeline.clone(),
        evidence_chain: input.evidence_chain.clone(),
        impact_assessment: impact,
        remediations,
        metadata,
    }
}

fn build_executive_narrative(input: &ReportInput) -> String {
    let mut paragraphs = Vec::new();

    let opening = format!(
        "Starting from {}, AEGIS conducted an autonomous penetration test with the objective: \"{}\".",
        input.target_url, input.objective
    );
    paragraphs.push(opening);

    for vuln in &input.vulnerabilities_exploited {
        paragraphs.push(format!(
            "A {} vulnerability (severity {:.1}) was discovered on endpoint {}. \
             Using {}, AEGIS was able to exploit this weakness.",
            vuln.vulnerability_class, vuln.severity, vuln.endpoint, vuln.technique
        ));
    }

    if !input.credentials_obtained.is_empty() {
        let cred_summary = input
            .credentials_obtained
            .iter()
            .map(|c| format!("'{}' ({})", c.username, c.access_level))
            .collect::<Vec<_>>()
            .join(", ");
        paragraphs.push(format!(
            "During the engagement, {} credential(s) were obtained: {}.",
            input.credentials_obtained.len(),
            cred_summary
        ));
    }

    if !input.hosts_compromised.is_empty() {
        paragraphs.push(format!(
            "Lateral movement resulted in {} host(s) being compromised: {}.",
            input.hosts_compromised.len(),
            input.hosts_compromised.join(", ")
        ));
    }

    if !input.exposed_data.is_empty() {
        let data_summary = input
            .exposed_data
            .iter()
            .map(|d| d.data_type.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        paragraphs.push(format!("Sensitive data exposure includes: {data_summary}."));
    }

    let outcome = if input.objective_achieved {
        format!(
            "The objective \"{}\" was fully achieved. Final access level: {}.",
            input.objective, input.final_access_level
        )
    } else {
        format!(
            "The objective \"{}\" was not fully achieved ({:.0}% progress). \
             Final access level: {}.",
            input.objective, input.objective_progress_pct, input.final_access_level
        )
    };
    paragraphs.push(outcome);

    paragraphs.join("\n\n")
}

fn build_impact_assessment(input: &ReportInput) -> ImpactAssessment {
    let max_severity = input
        .vulnerabilities_exploited
        .iter()
        .map(|v| v.severity)
        .fold(0.0_f64, f64::max);

    let overall_risk = if max_severity >= 9.0 || input.objective_achieved {
        "Critical"
    } else if max_severity >= 7.0 {
        "High"
    } else if max_severity >= 4.0 {
        "Medium"
    } else {
        "Low"
    };

    let pii_count = input
        .exposed_data
        .iter()
        .filter(|d| {
            d.sensitivity == DataSensitivity::Pii || d.sensitivity == DataSensitivity::Restricted
        })
        .count();

    let data_summary = if pii_count > 0 {
        format!(
            "{} sensitive dataset(s) exposed including PII/restricted data",
            pii_count
        )
    } else if !input.exposed_data.is_empty() {
        format!("{} dataset(s) exposed", input.exposed_data.len())
    } else {
        "No direct data exposure confirmed".to_string()
    };

    ImpactAssessment {
        overall_risk: overall_risk.to_string(),
        data_exposure_summary: data_summary,
        access_achieved: input.final_access_level.clone(),
        exposed_data: input.exposed_data.clone(),
        credential_count: input.credentials_obtained.len(),
        hosts_compromised: input.hosts_compromised.len(),
    }
}

fn build_remediations(input: &ReportInput) -> Vec<Remediation> {
    let mut remediations = Vec::new();
    let mut priority = 1u32;

    let mut sorted_vulns = input.vulnerabilities_exploited.clone();
    sorted_vulns.sort_by(|a, b| {
        b.severity
            .partial_cmp(&a.severity)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    for vuln in &sorted_vulns {
        let (title, description, effort, cwe) =
            remediation_for_vuln_class(&vuln.vulnerability_class);
        remediations.push(Remediation {
            priority,
            title,
            description: format!("{description} (endpoint: {})", vuln.endpoint),
            phase_blocked: phase_blocked_by(&vuln.vulnerability_class),
            effort,
            cwe_ids: cwe,
        });
        priority += 1;
    }

    if input.credentials_obtained.len() > 1 {
        remediations.push(Remediation {
            priority,
            title: "Implement credential rotation and unique passwords".to_string(),
            description: format!(
                "{} credentials obtained suggests password reuse across systems",
                input.credentials_obtained.len()
            ),
            phase_blocked: "Lateral Movement".to_string(),
            effort: RemediationEffort::Medium,
            cwe_ids: vec!["CWE-521".to_string()],
        });
        priority += 1;
    }

    if input.hosts_compromised.len() > 2 {
        remediations.push(Remediation {
            priority,
            title: "Implement network segmentation".to_string(),
            description: format!(
                "{} hosts compromised via lateral movement indicates insufficient segmentation",
                input.hosts_compromised.len()
            ),
            phase_blocked: "Lateral Movement".to_string(),
            effort: RemediationEffort::High,
            cwe_ids: vec!["CWE-284".to_string()],
        });
    }

    remediations
}

fn remediation_for_vuln_class(class: &str) -> (String, String, RemediationEffort, Vec<String>) {
    let lower = class.to_lowercase();
    if lower.contains("sql injection") {
        (
            "Fix SQL Injection".to_string(),
            "Replace string concatenation with parameterized queries / prepared statements"
                .to_string(),
            RemediationEffort::Medium,
            vec!["CWE-89".to_string()],
        )
    } else if lower.contains("xss") || lower.contains("cross-site scripting") {
        (
            "Fix Cross-Site Scripting".to_string(),
            "Implement context-aware output encoding and deploy Content-Security-Policy"
                .to_string(),
            RemediationEffort::Medium,
            vec!["CWE-79".to_string()],
        )
    } else if lower.contains("ssrf") {
        (
            "Fix Server-Side Request Forgery".to_string(),
            "Validate and allowlist outbound request destinations, block cloud metadata"
                .to_string(),
            RemediationEffort::Medium,
            vec!["CWE-918".to_string()],
        )
    } else if lower.contains("command injection") {
        (
            "Fix Command Injection".to_string(),
            "Avoid OS command execution; use language-native APIs with strict input validation"
                .to_string(),
            RemediationEffort::Medium,
            vec!["CWE-78".to_string()],
        )
    } else if lower.contains("ssti") || lower.contains("template injection") {
        (
            "Fix Server-Side Template Injection".to_string(),
            "Use sandboxed template engines; never pass user input directly to template rendering"
                .to_string(),
            RemediationEffort::Medium,
            vec!["CWE-1336".to_string()],
        )
    } else if lower.contains("auth") || lower.contains("authentication") {
        (
            "Fix Broken Authentication".to_string(),
            "Implement MFA, secure session management, and proper token rotation".to_string(),
            RemediationEffort::High,
            vec!["CWE-287".to_string()],
        )
    } else if lower.contains("deserialization") {
        (
            "Fix Insecure Deserialization".to_string(),
            "Reject untrusted serialized data; use allowlists for deserialization classes"
                .to_string(),
            RemediationEffort::High,
            vec!["CWE-502".to_string()],
        )
    } else if lower.contains("file upload") {
        (
            "Fix File Upload Vulnerability".to_string(),
            "Validate file types, store uploads outside webroot, disable execution in upload dirs"
                .to_string(),
            RemediationEffort::Medium,
            vec!["CWE-434".to_string()],
        )
    } else {
        (
            format!("Remediate {class}"),
            format!("Address {class} per OWASP guidelines and apply defense-in-depth"),
            RemediationEffort::Medium,
            vec![],
        )
    }
}

fn phase_blocked_by(vuln_class: &str) -> String {
    let lower = vuln_class.to_lowercase();
    if lower.contains("sql injection")
        || lower.contains("command injection")
        || lower.contains("ssti")
        || lower.contains("ssrf")
        || lower.contains("deserialization")
        || lower.contains("file upload")
    {
        "Initial Access".to_string()
    } else if lower.contains("auth") {
        "Initial Access / Privilege Escalation".to_string()
    } else if lower.contains("xss") {
        "Collection / Credential Harvest".to_string()
    } else {
        "Multiple Phases".to_string()
    }
}

/// Generate a concise text timeline from actions.
pub fn format_timeline(actions: &[TimelineAction]) -> String {
    actions
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let target = a
                .target
                .as_ref()
                .map(|t| format!(" → {t}"))
                .unwrap_or_default();
            format!(
                "{}. [{}] {}{} — {}",
                i + 1,
                a.phase,
                a.action,
                target,
                a.result
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Generate evidence chain summary.
pub fn format_evidence_chain(chain: &[EvidenceLink]) -> String {
    chain
        .iter()
        .map(|link| {
            let critical_marker = if link.critical { " [CRITICAL]" } else { "" };
            let http = link
                .http_evidence
                .as_ref()
                .map(|e| {
                    format!(
                        "\n    {} {} → {}",
                        e.request_method, e.request_url, e.response_status
                    )
                })
                .unwrap_or_default();
            format!(
                "Step {}: {}{}{}",
                link.step_number, link.description, critical_marker, http
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}
