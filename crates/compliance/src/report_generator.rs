use serde::{Deserialize, Serialize};

use crate::cvss_scorer::CvssSeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PentestReport {
    pub executive_summary: String,
    pub methodology: String,
    pub findings: Vec<FindingNarrative>,
    pub remediation_roadmap: String,
    pub compliance_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingNarrative {
    pub title: String,
    pub description: String,
    pub impact: String,
    pub proof_of_concept: String,
    pub remediation: String,
    pub references: Vec<String>,
    pub cvss_score: f64,
    pub cvss_vector: String,
    pub owasp_category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportInput {
    pub target_url: String,
    pub scan_duration_secs: u64,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub tech_stack: Vec<String>,
    pub defenses_detected: Vec<String>,
    pub findings: Vec<FindingInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingInput {
    pub vulnerability_class: String,
    pub endpoint: String,
    pub parameter: Option<String>,
    pub evidence: String,
    pub cvss_score: f64,
    pub cvss_vector: String,
    pub owasp_category: Option<String>,
    pub poc_command: Option<String>,
}

pub fn generate_full_report(input: &ReportInput) -> PentestReport {
    let narratives: Vec<FindingNarrative> = input
        .findings
        .iter()
        .map(generate_finding_narrative)
        .collect();

    PentestReport {
        executive_summary: generate_executive_summary(input),
        methodology: generate_methodology(input),
        findings: narratives,
        remediation_roadmap: generate_remediation_roadmap(&input.findings),
        compliance_summary: generate_compliance_summary(input),
    }
}

pub fn generate_executive_summary(input: &ReportInput) -> String {
    let duration = format_duration(input.scan_duration_secs);
    let risk = overall_risk_rating(input);
    let risk_desc = risk_description(input);
    let key_findings = top_findings_summary(&input.findings, 3);
    let recommendations = severity_recommendations(input);

    format!(
        "# Executive Summary\n\n\
         A security assessment was performed against {target} over a period of {duration}. \
         The assessment identified {total} vulnerabilities: {critical} critical, {high} high, \
         {medium} medium, and {low} low severity findings.\n\n\
         ## Risk Rating: {risk}\n\n\
         {risk_desc}\n\n\
         ## Key Findings\n\n\
         {key_findings}\n\n\
         ## Recommendations\n\n\
         {recommendations}",
        target = input.target_url,
        total = input.total_findings,
        critical = input.critical_count,
        high = input.high_count,
        medium = input.medium_count,
        low = input.low_count,
    )
}

pub fn generate_finding_narrative(finding: &FindingInput) -> FindingNarrative {
    let title = format!("{} in {}", finding.vulnerability_class, finding.endpoint);
    let description = description_for_class(
        &finding.vulnerability_class,
        &finding.endpoint,
        &finding.parameter,
    );
    let impact = impact_for_finding(&finding.vulnerability_class, finding.cvss_score);
    let poc = proof_of_concept(finding);
    let remediation = remediation_for_class(&finding.vulnerability_class);
    let references = references_for_class(&finding.vulnerability_class);

    FindingNarrative {
        title,
        description,
        impact,
        proof_of_concept: poc,
        remediation,
        references,
        cvss_score: finding.cvss_score,
        cvss_vector: finding.cvss_vector.clone(),
        owasp_category: finding.owasp_category.clone(),
    }
}

pub fn generate_remediation_roadmap(findings: &[FindingInput]) -> String {
    let mut sorted: Vec<&FindingInput> = findings.iter().collect();
    sorted.sort_by(|a, b| {
        b.cvss_score
            .partial_cmp(&a.cvss_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut immediate = Vec::new();
    let mut short_term = Vec::new();
    let mut long_term = Vec::new();

    for (i, f) in sorted.iter().enumerate() {
        let severity = crate::cvss_scorer::severity_from_score(f.cvss_score);
        let cwe = cwe_for_class(&f.vulnerability_class);
        let line = format!(
            "{}. Fix {} in {} — {}",
            i + 1,
            f.vulnerability_class,
            f.endpoint,
            cwe
        );
        match severity {
            CvssSeverity::Critical | CvssSeverity::High => immediate.push(line),
            CvssSeverity::Medium => short_term.push(line),
            CvssSeverity::Low | CvssSeverity::None => long_term.push(line),
        }
    }

    let mut sections = String::from("## Remediation Roadmap\n");
    append_roadmap_section(
        &mut sections,
        "Immediate (Critical/High \u{2014} This Week)",
        &immediate,
    );
    append_roadmap_section(
        &mut sections,
        "Short-Term (Medium \u{2014} This Month)",
        &short_term,
    );
    append_roadmap_section(
        &mut sections,
        "Long-Term (Low \u{2014} This Quarter)",
        &long_term,
    );
    sections
}

fn append_roadmap_section(out: &mut String, heading: &str, items: &[String]) {
    if items.is_empty() {
        return;
    }
    out.push_str(&format!("\n### {heading}\n\n"));
    for item in items {
        out.push_str(item);
        out.push('\n');
    }
}

fn generate_methodology(input: &ReportInput) -> String {
    let duration = format_duration(input.scan_duration_secs);
    let stack = if input.tech_stack.is_empty() {
        "not explicitly identified".to_string()
    } else {
        input.tech_stack.join(", ")
    };
    let defenses = if input.defenses_detected.is_empty() {
        "No active defenses were detected.".to_string()
    } else {
        format!(
            "Active defenses detected: {}.",
            input.defenses_detected.join(", ")
        )
    };

    format!(
        "## Methodology\n\n\
         The assessment was conducted using automated and semi-automated security testing \
         techniques over a period of {duration}. The target application's technology stack \
         includes: {stack}.\n\n\
         {defenses}\n\n\
         Testing phases included:\n\
         1. Reconnaissance and technology fingerprinting\n\
         2. Endpoint enumeration and API discovery\n\
         3. Automated vulnerability scanning with hypothesis-driven fuzzing\n\
         4. Manual verification of identified vulnerabilities\n\
         5. Attack chain analysis and impact assessment",
    )
}

fn generate_compliance_summary(input: &ReportInput) -> String {
    let risk = overall_risk_rating(input);
    let owasp_cats: Vec<&str> = input
        .findings
        .iter()
        .filter_map(|f| f.owasp_category.as_deref())
        .collect();

    let owasp_section = if owasp_cats.is_empty() {
        "No OWASP Top 10 category mappings were identified.".to_string()
    } else {
        let mut unique: Vec<&str> = owasp_cats.clone();
        unique.sort();
        unique.dedup();
        format!(
            "The following OWASP Top 10 (2021) categories were identified:\n{}",
            unique
                .iter()
                .map(|c| format!("- {c}"))
                .collect::<Vec<_>>()
                .join("\n"),
        )
    };

    format!(
        "## Compliance Summary\n\n\
         Overall risk rating: {risk}\n\n\
         {owasp_section}",
    )
}

fn overall_risk_rating(input: &ReportInput) -> &'static str {
    if input.critical_count > 0 {
        "Critical"
    } else if input.high_count > 0 {
        "High"
    } else if input.medium_count > 0 {
        "Medium"
    } else if input.low_count > 0 {
        "Low"
    } else {
        "Informational"
    }
}

fn risk_description(input: &ReportInput) -> String {
    if input.critical_count > 0 {
        format!(
            "The application has {} critical severity vulnerabilities that require immediate \
             remediation. These findings indicate a high likelihood of exploitation and severe \
             impact to confidentiality, integrity, or availability.",
            input.critical_count,
        )
    } else if input.high_count > 0 {
        format!(
            "The application has {} high severity vulnerabilities that should be addressed \
             promptly. These findings pose significant risk and could lead to data compromise \
             or unauthorized access.",
            input.high_count,
        )
    } else if input.medium_count > 0 {
        format!(
            "The application has {} medium severity vulnerabilities. While not immediately \
             critical, these should be addressed in the short term to reduce overall risk.",
            input.medium_count,
        )
    } else if input.low_count > 0 {
        format!(
            "The application has {} low severity findings. These represent minor issues or \
             informational findings with limited direct impact.",
            input.low_count,
        )
    } else {
        "No vulnerabilities were identified during the assessment.".to_string()
    }
}

fn top_findings_summary(findings: &[FindingInput], max: usize) -> String {
    let mut sorted: Vec<&FindingInput> = findings.iter().collect();
    sorted.sort_by(|a, b| {
        b.cvss_score
            .partial_cmp(&a.cvss_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    sorted
        .iter()
        .take(max)
        .enumerate()
        .map(|(i, f)| {
            format!(
                "{}. **{} in {}** (CVSS {:.1})",
                i + 1,
                f.vulnerability_class,
                f.endpoint,
                f.cvss_score,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn severity_recommendations(input: &ReportInput) -> String {
    let mut sections = Vec::new();

    if input.critical_count > 0 {
        sections.push(format!(
            "**Immediate:** Address all {} critical findings before the next production deployment.",
            input.critical_count,
        ));
    }
    if input.high_count > 0 {
        sections.push(format!(
            "**Short-Term:** Remediate {} high severity findings within the current sprint.",
            input.high_count,
        ));
    }
    if input.medium_count > 0 {
        sections.push(format!(
            "**Medium-Term:** Plan remediation of {} medium severity findings within the month.",
            input.medium_count,
        ));
    }
    if input.low_count > 0 {
        sections.push(format!(
            "**Long-Term:** Review and address {} low severity findings as part of ongoing hardening.",
            input.low_count,
        ));
    }

    if sections.is_empty() {
        "No specific remediation actions required.".to_string()
    } else {
        sections.join("\n")
    }
}

fn format_duration(secs: u64) -> String {
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let remaining_secs = secs % 60;

    if hours > 0 {
        format!("{hours}h {minutes}m {remaining_secs}s")
    } else if minutes > 0 {
        format!("{minutes}m {remaining_secs}s")
    } else {
        format!("{remaining_secs}s")
    }
}

fn description_for_class(vuln_class: &str, endpoint: &str, parameter: &Option<String>) -> String {
    let param_note = match parameter {
        Some(p) => format!(" via the `{p}` parameter"),
        None => String::new(),
    };

    match vuln_class {
        "SQL Injection" => format!(
            "A SQL Injection vulnerability was identified at `{endpoint}`{param_note}. \
             User-supplied input is incorporated into SQL queries without adequate sanitization, \
             allowing an attacker to manipulate database queries."
        ),
        "Cross-Site Scripting" => format!(
            "A Cross-Site Scripting (XSS) vulnerability was identified at `{endpoint}`{param_note}. \
             User input is reflected in the response without proper encoding, enabling execution \
             of arbitrary JavaScript in victim browsers."
        ),
        "Command Injection" => format!(
            "A Command Injection vulnerability was identified at `{endpoint}`{param_note}. \
             User input is passed to system shell commands without sanitization, allowing \
             arbitrary command execution on the server."
        ),
        "Path Traversal" => format!(
            "A Path Traversal vulnerability was identified at `{endpoint}`{param_note}. \
             Insufficient path validation allows an attacker to read files outside the \
             intended directory."
        ),
        "Server-Side Request Forgery" => format!(
            "A Server-Side Request Forgery (SSRF) vulnerability was identified at `{endpoint}`{param_note}. \
             The server can be induced to make HTTP requests to attacker-controlled destinations, \
             potentially accessing internal services."
        ),
        "Insecure Deserialization" => format!(
            "An Insecure Deserialization vulnerability was identified at `{endpoint}`{param_note}. \
             The application deserializes untrusted data, which can lead to remote code execution."
        ),
        "Broken Authentication" => format!(
            "A Broken Authentication vulnerability was identified at `{endpoint}`. \
             Weaknesses in the authentication mechanism allow attackers to compromise \
             credentials, session tokens, or exploit implementation flaws."
        ),
        "Broken Authorization" => format!(
            "A Broken Authorization vulnerability was identified at `{endpoint}`. \
             Access control checks are missing or improperly enforced, allowing \
             unauthorized access to resources or functionality."
        ),
        "Server-Side Template Injection" => format!(
            "A Server-Side Template Injection (SSTI) vulnerability was identified at \
             `{endpoint}`{param_note}. User input is evaluated within a server-side template \
             engine, potentially allowing remote code execution."
        ),
        "Security Misconfiguration" => format!(
            "A Security Misconfiguration was identified at `{endpoint}`. \
             The application or its underlying infrastructure uses insecure default settings \
             or incomplete configuration."
        ),
        "Sensitive Data Exposure" => format!(
            "Sensitive Data Exposure was identified at `{endpoint}`. \
             The application transmits or stores sensitive information without adequate protection."
        ),
        "Open Redirect" => format!(
            "An Open Redirect vulnerability was identified at `{endpoint}`{param_note}. \
             The application redirects users to attacker-controlled URLs, which can be \
             leveraged for phishing attacks."
        ),
        "Known Vulnerable Dependency" => format!(
            "A Known Vulnerable Dependency was identified affecting `{endpoint}`. \
             The application uses a third-party component with publicly disclosed vulnerabilities."
        ),
        _ => format!("A {vuln_class} vulnerability was identified at `{endpoint}`{param_note}."),
    }
}

fn impact_for_finding(vuln_class: &str, cvss_score: f64) -> String {
    let severity = crate::cvss_scorer::severity_from_score(cvss_score);
    let severity_word = match severity {
        CvssSeverity::Critical => "critical",
        CvssSeverity::High => "significant",
        CvssSeverity::Medium => "moderate",
        CvssSeverity::Low => "limited",
        CvssSeverity::None => "minimal",
    };

    let class_impact = match vuln_class {
        "SQL Injection" | "NoSQL Injection" => {
            "unauthorized access to the database, data exfiltration, modification, or deletion"
        }
        "Cross-Site Scripting" => {
            "session hijacking, credential theft, defacement, and malware distribution"
        }
        "Command Injection" | "Server-Side Template Injection" | "Insecure Deserialization" => {
            "remote code execution, full server compromise, and lateral movement"
        }
        "Path Traversal" => "unauthorized file access and potential source code disclosure",
        "Server-Side Request Forgery" => {
            "internal service access, cloud metadata exposure, and network pivoting"
        }
        "Broken Authentication" => {
            "account takeover, unauthorized access, and identity impersonation"
        }
        "Broken Authorization" => {
            "unauthorized data access, privilege escalation, and business logic bypass"
        }
        "Security Misconfiguration" | "Missing Security Header" => {
            "information disclosure and reduced defense-in-depth"
        }
        "Sensitive Data Exposure" | "Information Disclosure" => {
            "exposure of confidential data including credentials or personal information"
        }
        "Open Redirect" => "phishing attacks, credential harvesting, and trust exploitation",
        "Known Vulnerable Dependency" => {
            "exploitation of known vulnerabilities in third-party components"
        }
        _ => "security compromise proportional to the vulnerability severity",
    };

    format!(
        "This finding has {severity_word} impact (CVSS {cvss_score:.1}). \
         Successful exploitation could lead to {class_impact}.",
    )
}

fn proof_of_concept(finding: &FindingInput) -> String {
    if let Some(ref cmd) = finding.poc_command {
        return format!("```\n{cmd}\n```\n\nEvidence: {}", finding.evidence);
    }

    format!(
        "The vulnerability was identified through automated testing.\n\n\
         Evidence: {}",
        finding.evidence,
    )
}

fn remediation_for_class(vuln_class: &str) -> String {
    match vuln_class {
        "SQL Injection" | "NoSQL Injection" => {
            "Use parameterized queries or prepared statements for all database operations. \
             Implement an ORM layer and apply input validation with strict allowlists."
                .to_string()
        }
        "Cross-Site Scripting" => {
            "Encode all user-supplied output using context-appropriate encoding (HTML, URL, \
             JavaScript). Implement Content-Security-Policy headers and use auto-escaping \
             template engines."
                .to_string()
        }
        "Command Injection" => {
            "Avoid passing user input to system commands. If unavoidable, use strict allowlists \
             and parameterized command execution (e.g., subprocess with argument lists, not shell strings)."
                .to_string()
        }
        "Path Traversal" => {
            "Canonicalize and validate all file paths against a known-good base directory. \
             Reject inputs containing path traversal sequences (../) and use chroot or sandboxed \
             file access."
                .to_string()
        }
        "Server-Side Request Forgery" => {
            "Validate and restrict outbound request destinations using allowlists. Block access \
             to internal networks, cloud metadata endpoints (169.254.169.254), and localhost."
                .to_string()
        }
        "Insecure Deserialization" => {
            "Avoid deserializing untrusted data. If required, use safe serialization formats \
             (JSON, Protobuf) and implement integrity checks (HMAC signatures) on serialized data."
                .to_string()
        }
        "Broken Authentication" => {
            "Implement multi-factor authentication, enforce strong password policies, use secure \
             session management with HttpOnly/Secure cookie flags, and implement account lockout \
             after failed attempts."
                .to_string()
        }
        "Broken Authorization" => {
            "Implement centralized access control checks at the server side. Deny access by \
             default and enforce role-based access control (RBAC) on every request."
                .to_string()
        }
        "Server-Side Template Injection" => {
            "Avoid embedding user input directly in template expressions. Use a logic-less \
             template engine or sandbox template execution. Validate and escape all template \
             variables."
                .to_string()
        }
        "Security Misconfiguration" => {
            "Review and harden server configuration. Disable unnecessary features, remove \
             default credentials, restrict error messages, and apply the principle of least \
             privilege."
                .to_string()
        }
        "Sensitive Data Exposure" | "Information Disclosure" => {
            "Encrypt sensitive data in transit (TLS 1.2+) and at rest. Remove sensitive \
             information from error messages, headers, and API responses. Classify data \
             and apply appropriate protection levels."
                .to_string()
        }
        "Open Redirect" => {
            "Validate redirect targets against an allowlist of trusted domains. Avoid using \
             user-supplied input directly in redirect URLs."
                .to_string()
        }
        "Known Vulnerable Dependency" => {
            "Update the affected dependency to the latest patched version. Implement automated \
             dependency scanning in the CI/CD pipeline and subscribe to vulnerability advisories."
                .to_string()
        }
        "Missing Security Header" => {
            "Configure the web server or application to emit recommended security headers: \
             Content-Security-Policy, X-Content-Type-Options, Strict-Transport-Security, \
             X-Frame-Options, and Referrer-Policy."
                .to_string()
        }
        _ => format!(
            "Remediate the {vuln_class} vulnerability by following industry best practices. \
             Consult the relevant CWE entry and OWASP guidance for class-specific mitigation steps.",
        ),
    }
}

fn references_for_class(vuln_class: &str) -> Vec<String> {
    let cwe = cwe_for_class(vuln_class);
    let cwe_id = cwe.strip_prefix("CWE-").unwrap_or("0");

    let mut refs = vec![format!(
        "https://cwe.mitre.org/data/definitions/{cwe_id}.html"
    )];

    if let Some(owasp) = owasp_link_for_class(vuln_class) {
        refs.push(owasp);
    }

    refs
}

fn cwe_for_class(vuln_class: &str) -> &'static str {
    match vuln_class {
        "SQL Injection" => "CWE-89",
        "Cross-Site Scripting" => "CWE-79",
        "Command Injection" => "CWE-78",
        "Path Traversal" => "CWE-22",
        "Server-Side Request Forgery" => "CWE-918",
        "Insecure Deserialization" => "CWE-502",
        "Broken Authentication" => "CWE-287",
        "Broken Authorization" => "CWE-862",
        "Security Misconfiguration" => "CWE-16",
        "Sensitive Data Exposure" => "CWE-200",
        "Server-Side Template Injection" => "CWE-1336",
        "Header Injection" => "CWE-113",
        "Open Redirect" => "CWE-601",
        "CRLF Injection" => "CWE-93",
        "Known Vulnerable Dependency" => "CWE-1035",
        "Insufficient Input Validation" => "CWE-20",
        "NoSQL Injection" => "CWE-943",
        "XML External Entity" => "CWE-611",
        "Cross-Origin Misconfiguration" => "CWE-942",
        "Missing Security Header" => "CWE-693",
        "JWT Vulnerability" => "CWE-345",
        "HTTP Request Smuggling" => "CWE-444",
        "Race Condition" => "CWE-362",
        "Subdomain Takeover" => "CWE-284",
        "Prototype Pollution" => "CWE-1321",
        "GraphQL Abuse" => "CWE-20",
        "Cloud Misconfiguration" => "CWE-16",
        "Clickjacking" => "CWE-1021",
        "Cache Poisoning" => "CWE-349",
        "Host Header Injection" => "CWE-644",
        "Insecure Direct Object Reference" => "CWE-639",
        "Information Disclosure" => "CWE-200",
        "Weak Cryptography" => "CWE-327",
        "Mass Assignment" => "CWE-915",
        _ => "CWE-0",
    }
}

fn owasp_link_for_class(vuln_class: &str) -> Option<String> {
    let slug = match vuln_class {
        "SQL Injection"
        | "NoSQL Injection"
        | "Command Injection"
        | "Server-Side Template Injection"
        | "XML External Entity" => Some("A03_2021-Injection"),
        "Cross-Site Scripting" => Some("A03_2021-Injection"),
        "Broken Authentication" => Some("A07_2021-Identification_and_Authentication_Failures"),
        "Broken Authorization" | "Insecure Direct Object Reference" => {
            Some("A01_2021-Broken_Access_Control")
        }
        "Security Misconfiguration" | "Cloud Misconfiguration" | "Missing Security Header" => {
            Some("A05_2021-Security_Misconfiguration")
        }
        "Sensitive Data Exposure" | "Information Disclosure" | "Weak Cryptography" => {
            Some("A02_2021-Cryptographic_Failures")
        }
        "Known Vulnerable Dependency" => Some("A06_2021-Vulnerable_and_Outdated_Components"),
        "Insecure Deserialization" => Some("A08_2021-Software_and_Data_Integrity_Failures"),
        "Server-Side Request Forgery" => Some("A10_2021-Server-Side_Request_Forgery_(SSRF)"),
        "Path Traversal" | "Open Redirect" => Some("A01_2021-Broken_Access_Control"),
        _ => None,
    };

    slug.map(|s| format!("https://owasp.org/Top10/{s}/"))
}
