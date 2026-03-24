use std::collections::HashMap;
use std::fmt::Write;

use aegis_protocol::finding::VulnerabilityClass;

use crate::sarif_emitter::{SarifFinding, cwe_for, remediation_for};

/// Which sections to include in the generated narrative report.
#[derive(Debug, Clone)]
pub struct ReportTemplate {
    pub include_executive_summary: bool,
    pub include_finding_narratives: bool,
    pub include_risk_scoring: bool,
    pub include_attack_chains: bool,
    pub include_trend_analysis: bool,
    pub include_remediation_priority: bool,
    pub include_compliance_mapping: bool,
    pub include_technical_appendix: bool,
    pub max_findings_in_detail: Option<usize>,
    pub custom_header: Option<String>,
    pub custom_footer: Option<String>,
}

impl Default for ReportTemplate {
    fn default() -> Self {
        Self {
            include_executive_summary: true,
            include_finding_narratives: true,
            include_risk_scoring: true,
            include_attack_chains: true,
            include_trend_analysis: true,
            include_remediation_priority: true,
            include_compliance_mapping: true,
            include_technical_appendix: true,
            max_findings_in_detail: None,
            custom_header: None,
            custom_footer: None,
        }
    }
}

impl ReportTemplate {
    pub fn executive_only() -> Self {
        Self {
            include_executive_summary: true,
            include_finding_narratives: false,
            include_risk_scoring: true,
            include_attack_chains: false,
            include_trend_analysis: false,
            include_remediation_priority: true,
            include_compliance_mapping: false,
            include_technical_appendix: false,
            max_findings_in_detail: None,
            custom_header: None,
            custom_footer: None,
        }
    }

    pub fn technical_only() -> Self {
        Self {
            include_executive_summary: false,
            include_finding_narratives: true,
            include_risk_scoring: true,
            include_attack_chains: true,
            include_trend_analysis: false,
            include_remediation_priority: true,
            include_compliance_mapping: true,
            include_technical_appendix: true,
            max_findings_in_detail: None,
            custom_header: None,
            custom_footer: None,
        }
    }
}

/// A node in an attack chain path.
#[derive(Debug, Clone)]
pub struct AttackChainNode {
    pub label: String,
    pub vulnerability_class: Option<VulnerabilityClass>,
    pub endpoint: Option<String>,
}

/// An ordered path through the attack graph.
#[derive(Debug, Clone)]
pub struct AttackChainPath {
    pub nodes: Vec<AttackChainNode>,
    pub total_difficulty: f64,
}

/// Baseline findings from a previous scan for trend comparison.
#[derive(Debug, Clone)]
pub struct BaselineFindings {
    pub total_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub resolved_rule_ids: Vec<String>,
    pub new_rule_ids: Vec<String>,
}

/// Evidence captured for a single finding (request/response pairs).
#[derive(Debug, Clone)]
pub struct FindingEvidence {
    pub rule_id: String,
    pub request_method: String,
    pub request_url: String,
    pub request_headers: Vec<(String, String)>,
    pub request_body: Option<String>,
    pub response_status: u16,
    pub response_headers: Vec<(String, String)>,
    pub response_body_snippet: Option<String>,
}

/// Fully assembled narrative report.
#[derive(Debug, Clone)]
pub struct NarrativeReport {
    pub sections: Vec<ReportSection>,
}

/// A single section of the report.
#[derive(Debug, Clone)]
pub struct ReportSection {
    pub title: String,
    pub body: String,
}

/// Input bundle for report generation.
pub struct NarrativeInput<'a> {
    pub findings: &'a [SarifFinding],
    pub attack_chains: &'a [AttackChainPath],
    pub baseline: Option<&'a BaselineFindings>,
    pub evidence: &'a [FindingEvidence],
    pub target_url: &'a str,
    pub scan_date: &'a str,
}

/// Generate a full narrative report from structured scan data.
pub fn generate_narrative_report(
    input: &NarrativeInput<'_>,
    template: &ReportTemplate,
) -> NarrativeReport {
    let mut sections = Vec::new();

    if let Some(header) = &template.custom_header {
        sections.push(ReportSection {
            title: "Header".to_string(),
            body: header.clone(),
        });
    }

    if template.include_executive_summary {
        sections.push(generate_executive_summary(input));
    }
    if template.include_finding_narratives {
        sections.push(generate_finding_narratives(input, template));
    }
    if template.include_risk_scoring {
        sections.push(generate_risk_scoring_narrative(input));
    }
    if template.include_attack_chains {
        sections.push(generate_attack_chain_stories(input));
    }
    if template.include_trend_analysis {
        sections.push(generate_trend_analysis(input));
    }
    if template.include_remediation_priority {
        sections.push(generate_remediation_priority(input));
    }
    if template.include_compliance_mapping {
        sections.push(generate_compliance_mapping_narrative(input));
    }
    if template.include_technical_appendix {
        sections.push(generate_technical_appendix(input));
    }

    if let Some(footer) = &template.custom_footer {
        sections.push(ReportSection {
            title: "Footer".to_string(),
            body: footer.clone(),
        });
    }

    NarrativeReport { sections }
}

fn severity_label(composite: f64) -> &'static str {
    if composite >= 70.0 {
        "critical"
    } else if composite >= 40.0 {
        "high"
    } else if composite >= 20.0 {
        "medium"
    } else {
        "low"
    }
}

fn count_by_severity(findings: &[SarifFinding]) -> (usize, usize, usize, usize) {
    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;
    for f in findings {
        match severity_label(f.composite_score) {
            "critical" => critical += 1,
            "high" => high += 1,
            "medium" => medium += 1,
            _ => low += 1,
        }
    }
    (critical, high, medium, low)
}

fn generate_executive_summary(input: &NarrativeInput<'_>) -> ReportSection {
    let findings = input.findings;
    let (critical, high, medium, low) = count_by_severity(findings);
    let total = findings.len();

    let mut body = String::new();
    let _ = write!(
        body,
        "Penetration test of {} conducted on {}. ",
        input.target_url, input.scan_date
    );
    let _ = write!(
        body,
        "The assessment identified {} findings: {} critical, {} high, {} medium, and {} low severity. ",
        total, critical, high, medium, low
    );

    if critical > 0 {
        let _ = write!(
            body,
            "The presence of {} critical-severity findings indicates significant risk to business operations \
             and requires immediate remediation. ",
            critical
        );
    } else if high > 0 {
        let _ = write!(
            body,
            "While no critical findings were identified, {} high-severity issues \
             warrant prompt attention to prevent potential exploitation. ",
            high
        );
    } else {
        body.push_str(
            "No critical or high-severity findings were identified, indicating a generally \
             sound security posture. ",
        );
    }

    let defenses: Vec<&str> = findings
        .iter()
        .filter_map(|f| f.defense_context.as_ref())
        .flat_map(|dc| dc.defenses_detected.iter().map(|s| s.as_str()))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    if !defenses.is_empty() {
        let mut sorted = defenses;
        sorted.sort();
        let _ = write!(
            body,
            "Active defenses detected during the scan: {}.",
            sorted.join(", ")
        );
    }

    ReportSection {
        title: "Executive Summary".to_string(),
        body,
    }
}

fn generate_finding_narratives(
    input: &NarrativeInput<'_>,
    template: &ReportTemplate,
) -> ReportSection {
    let mut body = String::new();

    let limit = template
        .max_findings_in_detail
        .unwrap_or(input.findings.len());
    let mut sorted: Vec<&SarifFinding> = input.findings.iter().collect();
    sorted.sort_by(|a, b| {
        b.composite_score
            .partial_cmp(&a.composite_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    for finding in sorted.into_iter().take(limit) {
        let _ = write!(body, "### {}\n\n", finding.rule_id);

        let vuln_name = finding
            .vulnerability_class
            .as_ref()
            .map(|vc| format!("{vc}"))
            .unwrap_or_else(|| "Unknown Vulnerability".to_string());

        let _ = write!(body, "**Description:** {vuln_name}");
        if let Some(ep) = &finding.endpoint {
            let method = finding.http_method.as_deref().unwrap_or("GET");
            let _ = write!(body, " affecting {method} {ep}");
        }
        if let Some(param) = &finding.parameter_name {
            let _ = write!(body, " via the `{param}` parameter");
        }
        let _ = writeln!(body, ".\n");

        let _ = writeln!(body, "**Impact:** {}", impact_description(&vuln_name));

        if let Some(vc) = &finding.vulnerability_class {
            let _ = writeln!(body);
            let _ = writeln!(body, "**Reproduction Steps:**");
            let _ = writeln!(body, "1. Send a crafted request to the affected endpoint.");
            let _ = writeln!(
                body,
                "2. Include a {} payload in the {} input.",
                vuln_name,
                finding.parameter_name.as_deref().unwrap_or("target")
            );
            let _ = writeln!(
                body,
                "3. Observe the application response confirming the vulnerability."
            );

            let _ = writeln!(body);
            let _ = writeln!(body, "**Remediation:** {}\n", remediation_for(vc));
        }
    }

    ReportSection {
        title: "Detailed Findings".to_string(),
        body,
    }
}

fn impact_description(vuln_name: &str) -> &'static str {
    match vuln_name {
        "SQL Injection" => {
            "An attacker could read, modify, or delete database contents, potentially \
             exfiltrating sensitive records or escalating privileges."
        }
        "Cross-Site Scripting" => {
            "An attacker could execute arbitrary JavaScript in victims' browsers, \
             stealing session tokens, credentials, or performing actions on their behalf."
        }
        "Command Injection" => {
            "An attacker could execute arbitrary operating system commands, leading to \
             full server compromise."
        }
        "Path Traversal" => {
            "An attacker could read arbitrary files from the server filesystem, \
             potentially accessing configuration files, credentials, or source code."
        }
        "Server-Side Request Forgery" => {
            "An attacker could make the server issue requests to internal services, \
             accessing resources behind the firewall or cloud metadata endpoints."
        }
        "Broken Authentication" => {
            "An attacker could bypass authentication controls to impersonate \
             legitimate users or access protected resources."
        }
        "Broken Authorization" => {
            "An attacker could access resources or perform actions beyond their \
             intended privilege level."
        }
        "Insecure Direct Object Reference" => {
            "An attacker could access other users' data by manipulating resource \
             identifiers in API requests."
        }
        _ => {
            "This vulnerability could allow an attacker to compromise the confidentiality, \
             integrity, or availability of the application."
        }
    }
}

fn generate_risk_scoring_narrative(input: &NarrativeInput<'_>) -> ReportSection {
    let mut body = String::new();

    body.push_str(
        "Risk scores combine severity, confidence, and contextual factors into a composite \
         0\u{2013}100 scale. ",
    );
    body.push_str(
        "Scores above 70 are classified as critical, 40\u{2013}69 as high, 20\u{2013}39 as medium, \
         and below 20 as low.\n\n",
    );

    let mut sorted: Vec<&SarifFinding> = input.findings.iter().collect();
    sorted.sort_by(|a, b| {
        b.composite_score
            .partial_cmp(&a.composite_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    for finding in &sorted {
        let label = severity_label(finding.composite_score);
        let _ = writeln!(
            body,
            "- **{}**: composite score {:.1}/100 ({}) \u{2014} severity {:.1}, confidence {:.0}%.",
            finding.rule_id,
            finding.composite_score,
            label,
            finding.severity,
            finding.confidence * 100.0
        );
    }

    if !sorted.is_empty() {
        let avg = sorted.iter().map(|f| f.composite_score).sum::<f64>() / sorted.len() as f64;
        let _ = write!(
            body,
            "\nAverage composite score across all findings: {:.1}/100 ({}).",
            avg,
            severity_label(avg)
        );
    }

    ReportSection {
        title: "Risk Scoring Analysis".to_string(),
        body,
    }
}

fn generate_attack_chain_stories(input: &NarrativeInput<'_>) -> ReportSection {
    let mut body = String::new();

    if input.attack_chains.is_empty() {
        body.push_str("No multi-step attack chains were identified during this assessment.");
        return ReportSection {
            title: "Attack Chain Analysis".to_string(),
            body,
        };
    }

    let _ = write!(
        body,
        "The assessment identified {} potential attack chain{}:\n\n",
        input.attack_chains.len(),
        if input.attack_chains.len() == 1 {
            ""
        } else {
            "s"
        }
    );

    for (i, chain) in input.attack_chains.iter().enumerate() {
        let _ = write!(
            body,
            "**Chain {}** (difficulty: {:.1}): ",
            i + 1,
            chain.total_difficulty
        );
        let narrative = chain_to_narrative(chain);
        let _ = writeln!(body, "{narrative}\n");
    }

    ReportSection {
        title: "Attack Chain Analysis".to_string(),
        body,
    }
}

fn chain_to_narrative(chain: &AttackChainPath) -> String {
    let mut parts = Vec::new();

    for (i, node) in chain.nodes.iter().enumerate() {
        let vuln_label = node
            .vulnerability_class
            .as_ref()
            .map(|vc| format!("{vc}"))
            .unwrap_or_else(|| "access".to_string());

        let endpoint_label = node.endpoint.as_deref().unwrap_or("the target");

        let connector = match i {
            0 => "An attacker could exploit",
            _ => "then leverage",
        };

        parts.push(format!("{connector} the {vuln_label} on {endpoint_label}"));
    }

    let mut narrative = parts.join(", ");
    narrative.push('.');
    narrative
}

fn generate_trend_analysis(input: &NarrativeInput<'_>) -> ReportSection {
    let mut body = String::new();

    let Some(baseline) = input.baseline else {
        body.push_str("No baseline scan data available for trend comparison.");
        return ReportSection {
            title: "Trend Analysis".to_string(),
            body,
        };
    };

    let current_total = input.findings.len();
    let (current_critical, current_high, _, _) = count_by_severity(input.findings);

    let delta = current_total as isize - baseline.total_count as isize;
    let direction = match delta.cmp(&0) {
        std::cmp::Ordering::Greater => format!("an increase of {delta} findings"),
        std::cmp::Ordering::Less => format!("a decrease of {} findings", delta.unsigned_abs()),
        std::cmp::Ordering::Equal => "no change in total finding count".to_string(),
    };

    let _ = write!(
        body,
        "Compared to the previous scan ({} findings, {} critical, {} high), \
         the current assessment shows {} ({} total, {} critical, {} high). ",
        baseline.total_count,
        baseline.critical_count,
        baseline.high_count,
        direction,
        current_total,
        current_critical,
        current_high
    );

    if !baseline.resolved_rule_ids.is_empty() {
        let _ = write!(
            body,
            "Resolved since last scan: {}. ",
            baseline.resolved_rule_ids.join(", ")
        );
    }
    if !baseline.new_rule_ids.is_empty() {
        let _ = write!(
            body,
            "Newly identified: {}.",
            baseline.new_rule_ids.join(", ")
        );
    }

    ReportSection {
        title: "Trend Analysis".to_string(),
        body,
    }
}

fn generate_remediation_priority(input: &NarrativeInput<'_>) -> ReportSection {
    let mut body = String::new();

    body.push_str(
        "Remediation priorities are ordered by composite risk score (impact \u{00d7} exploitability).\n\n",
    );

    let mut sorted: Vec<&SarifFinding> = input.findings.iter().collect();
    sorted.sort_by(|a, b| {
        b.composite_score
            .partial_cmp(&a.composite_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    for (rank, finding) in sorted.iter().enumerate() {
        let vuln_name = finding
            .vulnerability_class
            .as_ref()
            .map(|vc| format!("{vc}"))
            .unwrap_or_else(|| "Unknown".to_string());

        let remediation = finding
            .vulnerability_class
            .as_ref()
            .map(|vc| remediation_for(vc))
            .unwrap_or("Review and apply defense-in-depth principles.");

        let _ = writeln!(
            body,
            "{}. **{}** \u{2014} {} (score: {:.1}): {}",
            rank + 1,
            finding.rule_id,
            vuln_name,
            finding.composite_score,
            remediation
        );
    }

    ReportSection {
        title: "Remediation Priority".to_string(),
        body,
    }
}

fn generate_compliance_mapping_narrative(input: &NarrativeInput<'_>) -> ReportSection {
    let mut body = String::new();

    let mut owasp_groups: HashMap<&str, Vec<&SarifFinding>> = HashMap::new();
    let mut pci_findings: Vec<(&SarifFinding, &str)> = Vec::new();

    for finding in input.findings {
        let Some(vc) = &finding.vulnerability_class else {
            continue;
        };
        let cwe = cwe_for(vc);
        let owasp = owasp_category(vc);

        owasp_groups.entry(owasp).or_default().push(finding);
        pci_findings.push((finding, cwe));
    }

    body.push_str("**OWASP Top 10 (2021) Mapping:**\n\n");

    let mut owasp_sorted: Vec<_> = owasp_groups.into_iter().collect();
    owasp_sorted.sort_by_key(|(cat, _)| *cat);

    for (category, findings) in &owasp_sorted {
        let _ = writeln!(
            body,
            "- {}: {} finding{} ({})",
            category,
            findings.len(),
            if findings.len() == 1 { "" } else { "s" },
            findings
                .iter()
                .map(|f| f.rule_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    body.push_str("\n**PCI-DSS Relevance:**\n\n");

    if pci_findings.is_empty() {
        body.push_str("No findings mapped to PCI-DSS requirements.\n");
    } else {
        let _ = write!(
            body,
            "{} finding{} map to PCI-DSS requirements. ",
            pci_findings.len(),
            if pci_findings.len() == 1 { "" } else { "s" }
        );
        body.push_str(
            "Organizations handling cardholder data should prioritize remediation \
             of these issues to maintain compliance.\n",
        );
    }

    ReportSection {
        title: "Compliance Mapping".to_string(),
        body,
    }
}

fn owasp_category(vc: &VulnerabilityClass) -> &'static str {
    match vc {
        VulnerabilityClass::BrokenAuthorization
        | VulnerabilityClass::InsecureDirectObjectReference => "A01:2021 Broken Access Control",

        VulnerabilityClass::WeakCryptography => "A02:2021 Cryptographic Failures",

        VulnerabilityClass::SqlInjection
        | VulnerabilityClass::NoSqlInjection
        | VulnerabilityClass::CrossSiteScripting
        | VulnerabilityClass::CommandInjection
        | VulnerabilityClass::PathTraversal
        | VulnerabilityClass::XmlExternalEntity
        | VulnerabilityClass::ServerSideTemplateInjection
        | VulnerabilityClass::HeaderInjection
        | VulnerabilityClass::CrlfInjection => "A03:2021 Injection",

        VulnerabilityClass::InsecureDeserialization => "A04:2021 Insecure Design",

        VulnerabilityClass::SecurityMisconfiguration
        | VulnerabilityClass::CloudMisconfiguration
        | VulnerabilityClass::MissingSecurityHeader
        | VulnerabilityClass::CrossOriginMisconfiguration => "A05:2021 Security Misconfiguration",

        VulnerabilityClass::KnownVulnerableDependency => {
            "A06:2021 Vulnerable and Outdated Components"
        }

        VulnerabilityClass::BrokenAuthentication | VulnerabilityClass::JwtVulnerability => {
            "A07:2021 Identification and Authentication Failures"
        }

        VulnerabilityClass::SensitiveDataExposure | VulnerabilityClass::InformationDisclosure => {
            "A08:2021 Software and Data Integrity Failures"
        }

        VulnerabilityClass::ServerSideRequestForgery => "A10:2021 SSRF",

        VulnerabilityClass::OpenRedirect
        | VulnerabilityClass::InsufficientInputValidation
        | VulnerabilityClass::HttpRequestSmuggling
        | VulnerabilityClass::RaceCondition
        | VulnerabilityClass::SubdomainTakeover
        | VulnerabilityClass::PrototypePollution
        | VulnerabilityClass::GraphQlAbuse
        | VulnerabilityClass::Clickjacking
        | VulnerabilityClass::CachePoisoning
        | VulnerabilityClass::HostHeaderInjection
        | VulnerabilityClass::MassAssignment => "A03:2021 Injection",
    }
}

fn generate_technical_appendix(input: &NarrativeInput<'_>) -> ReportSection {
    let mut body = String::new();

    if input.evidence.is_empty() {
        body.push_str("No raw request/response evidence was captured during this assessment.");
        return ReportSection {
            title: "Technical Appendix".to_string(),
            body,
        };
    }

    for ev in input.evidence {
        let _ = writeln!(body, "#### Evidence for {}\n", ev.rule_id);
        let _ = writeln!(body, "**Request:**\n```");
        let _ = writeln!(body, "{} {}", ev.request_method, ev.request_url);
        for (name, value) in &ev.request_headers {
            let _ = writeln!(body, "{name}: {value}");
        }
        if let Some(req_body) = &ev.request_body {
            let _ = writeln!(body, "\n{req_body}");
        }
        let _ = writeln!(body, "```\n");

        let _ = writeln!(body, "**Response (status {}):**\n```", ev.response_status);
        for (name, value) in &ev.response_headers {
            let _ = writeln!(body, "{name}: {value}");
        }
        if let Some(resp_body) = &ev.response_body_snippet {
            let _ = writeln!(body, "\n{resp_body}");
        }
        let _ = writeln!(body, "```\n");
    }

    ReportSection {
        title: "Technical Appendix".to_string(),
        body,
    }
}
