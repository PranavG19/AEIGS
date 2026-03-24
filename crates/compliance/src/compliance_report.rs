use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A finding prepared for compliance report generation.
///
/// Carries the vulnerability class as a display string alongside endpoint,
/// severity, and composite confidence score. The `id` field links back to
/// the original finding for evidence tracing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFinding {
    pub id: String,
    pub vulnerability_class: String,
    pub endpoint: String,
    pub severity: String,
    pub composite_score: f64,
}

/// Tri-state-plus-untested status for a single compliance requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceStatus {
    Pass,
    Fail,
    Partial,
    NotTested,
}

/// Result of evaluating a single framework requirement against scan findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequirementResult {
    pub requirement_id: String,
    pub title: String,
    pub status: ComplianceStatus,
    pub findings: Vec<String>,
    pub description: String,
}

/// Aggregated pass/fail/partial/not-tested counts for one compliance framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkReport {
    pub framework_name: String,
    pub framework_version: String,
    pub requirements: Vec<RequirementResult>,
    pub pass_count: usize,
    pub fail_count: usize,
    pub partial_count: usize,
    pub not_tested_count: usize,
    pub coverage_percentage: f64,
}

/// Combined compliance report across all supported frameworks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullComplianceReport {
    pub owasp_top10: FrameworkReport,
    pub pci_dss: FrameworkReport,
    pub nist_800_53: FrameworkReport,
    pub cis_controls: FrameworkReport,
    pub gap_analysis: Vec<GapItem>,
}

/// A single gap: a requirement that received no test coverage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapItem {
    pub framework: String,
    pub requirement_id: String,
    pub title: String,
    pub recommendation: String,
}

pub fn generate_compliance_report(findings: &[ComplianceFinding]) -> FullComplianceReport {
    let owasp_top10 = generate_owasp_report(findings);
    let pci_dss = generate_pci_dss_report(findings);
    let nist_800_53 = generate_nist_report(findings);
    let cis_controls = generate_cis_report(findings);

    let mut report = FullComplianceReport {
        owasp_top10,
        pci_dss,
        nist_800_53,
        cis_controls,
        gap_analysis: Vec::new(),
    };
    report.gap_analysis = identify_gaps(&report);
    report
}

pub fn generate_owasp_report(findings: &[ComplianceFinding]) -> FrameworkReport {
    let requirements = owasp_requirements();
    let mapping = owasp_vuln_mapping();
    build_framework_report("OWASP Top 10", "2021", requirements, &mapping, findings)
}

pub fn generate_pci_dss_report(findings: &[ComplianceFinding]) -> FrameworkReport {
    let requirements = pci_dss_requirements();
    let mapping = pci_dss_vuln_mapping();
    build_framework_report("PCI-DSS", "4.0", requirements, &mapping, findings)
}

pub fn generate_nist_report(findings: &[ComplianceFinding]) -> FrameworkReport {
    let requirements = nist_requirements();
    let mapping = nist_vuln_mapping();
    build_framework_report("NIST 800-53", "Rev 5", requirements, &mapping, findings)
}

pub fn generate_cis_report(findings: &[ComplianceFinding]) -> FrameworkReport {
    let requirements = cis_requirements();
    let mapping = cis_vuln_mapping();
    build_framework_report("CIS Controls", "v8", requirements, &mapping, findings)
}

pub fn identify_gaps(report: &FullComplianceReport) -> Vec<GapItem> {
    let mut gaps = Vec::new();
    let frameworks = [
        (&report.owasp_top10, "OWASP Top 10 2021"),
        (&report.pci_dss, "PCI-DSS 4.0"),
        (&report.nist_800_53, "NIST 800-53 Rev 5"),
        (&report.cis_controls, "CIS Controls v8"),
    ];

    for (fw, name) in &frameworks {
        for req in &fw.requirements {
            if req.status == ComplianceStatus::NotTested {
                gaps.push(GapItem {
                    framework: (*name).to_string(),
                    requirement_id: req.requirement_id.clone(),
                    title: req.title.clone(),
                    recommendation: format!(
                        "Add test coverage for {} ({})",
                        req.requirement_id, req.title
                    ),
                });
            }
        }
    }
    gaps
}

struct RequirementDef {
    id: &'static str,
    title: &'static str,
    description: &'static str,
}

fn build_framework_report(
    name: &str,
    version: &str,
    requirement_defs: Vec<RequirementDef>,
    vuln_mapping: &HashMap<&str, Vec<&str>>,
    findings: &[ComplianceFinding],
) -> FrameworkReport {
    let finding_classes: Vec<&str> = findings
        .iter()
        .map(|f| f.vulnerability_class.as_str())
        .collect();

    let mut requirements = Vec::with_capacity(requirement_defs.len());

    for def in &requirement_defs {
        let mapped_classes: Vec<&&str> = vuln_mapping
            .iter()
            .filter(|(_, req_ids)| req_ids.contains(&def.id))
            .map(|(class, _)| class)
            .collect();

        let matching_findings: Vec<String> = findings
            .iter()
            .filter(|f| {
                mapped_classes
                    .iter()
                    .any(|&&c| c == f.vulnerability_class.as_str())
            })
            .map(|f| f.id.clone())
            .collect();

        let has_relevant_classes = !mapped_classes.is_empty();
        let any_class_present = mapped_classes
            .iter()
            .any(|&&c| finding_classes.contains(&c));

        let status = if !matching_findings.is_empty() {
            ComplianceStatus::Fail
        } else if has_relevant_classes && !any_class_present && !findings.is_empty() {
            ComplianceStatus::Pass
        } else {
            ComplianceStatus::NotTested
        };

        requirements.push(RequirementResult {
            requirement_id: def.id.to_string(),
            title: def.title.to_string(),
            status,
            findings: matching_findings,
            description: def.description.to_string(),
        });
    }

    let pass_count = requirements
        .iter()
        .filter(|r| r.status == ComplianceStatus::Pass)
        .count();
    let fail_count = requirements
        .iter()
        .filter(|r| r.status == ComplianceStatus::Fail)
        .count();
    let partial_count = requirements
        .iter()
        .filter(|r| r.status == ComplianceStatus::Partial)
        .count();
    let not_tested_count = requirements
        .iter()
        .filter(|r| r.status == ComplianceStatus::NotTested)
        .count();

    let total = requirements.len();
    let tested = pass_count + fail_count + partial_count;
    let coverage_percentage = if total > 0 {
        (tested as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    FrameworkReport {
        framework_name: name.to_string(),
        framework_version: version.to_string(),
        requirements,
        pass_count,
        fail_count,
        partial_count,
        not_tested_count,
        coverage_percentage,
    }
}

fn owasp_requirements() -> Vec<RequirementDef> {
    vec![
        RequirementDef {
            id: "A01",
            title: "Broken Access Control",
            description: "Restrictions on authenticated users are not properly enforced",
        },
        RequirementDef {
            id: "A02",
            title: "Cryptographic Failures",
            description: "Failures related to cryptography leading to sensitive data exposure",
        },
        RequirementDef {
            id: "A03",
            title: "Injection",
            description: "User-supplied data is not validated, filtered, or sanitized",
        },
        RequirementDef {
            id: "A04",
            title: "Insecure Design",
            description: "Missing or ineffective control design",
        },
        RequirementDef {
            id: "A05",
            title: "Security Misconfiguration",
            description: "Missing or incorrect security hardening across any part of the stack",
        },
        RequirementDef {
            id: "A06",
            title: "Vulnerable and Outdated Components",
            description: "Components with known vulnerabilities or unsupported software",
        },
        RequirementDef {
            id: "A07",
            title: "Identification and Authentication Failures",
            description: "Identity, authentication, and session management weaknesses",
        },
        RequirementDef {
            id: "A08",
            title: "Software and Data Integrity Failures",
            description: "Code and infrastructure failing to protect against integrity violations",
        },
        RequirementDef {
            id: "A09",
            title: "Security Logging and Monitoring Failures",
            description: "Insufficient logging, detection, monitoring, and active response",
        },
        RequirementDef {
            id: "A10",
            title: "Server-Side Request Forgery",
            description: "SSRF flaws occur when a web application fetches a remote resource without validation",
        },
    ]
}

fn owasp_vuln_mapping() -> HashMap<&'static str, Vec<&'static str>> {
    let mut m = HashMap::new();
    m.insert("Broken Authorization", vec!["A01"]);
    m.insert("Insecure Direct Object Reference", vec!["A01"]);
    m.insert("Mass Assignment", vec!["A01"]);
    m.insert("Open Redirect", vec!["A01"]);
    m.insert("Sensitive Data Exposure", vec!["A02"]);
    m.insert("Information Disclosure", vec!["A02"]);
    m.insert("Weak Cryptography", vec!["A02"]);
    m.insert("SQL Injection", vec!["A03"]);
    m.insert("NoSQL Injection", vec!["A03"]);
    m.insert("Cross-Site Scripting", vec!["A03"]);
    m.insert("Command Injection", vec!["A03"]);
    m.insert("Path Traversal", vec!["A03"]);
    m.insert("XML External Entity", vec!["A03"]);
    m.insert("Server-Side Template Injection", vec!["A03"]);
    m.insert("Header Injection", vec!["A03"]);
    m.insert("CRLF Injection", vec!["A03"]);
    m.insert("Insufficient Input Validation", vec!["A03"]);
    m.insert("Prototype Pollution", vec!["A03"]);
    m.insert("GraphQL Abuse", vec!["A03"]);
    m.insert("Host Header Injection", vec!["A03"]);
    m.insert("Race Condition", vec!["A04"]);
    m.insert("Security Misconfiguration", vec!["A05"]);
    m.insert("Missing Security Header", vec!["A05"]);
    m.insert("Cross-Origin Misconfiguration", vec!["A05"]);
    m.insert("HTTP Request Smuggling", vec!["A05"]);
    m.insert("Subdomain Takeover", vec!["A05"]);
    m.insert("Cloud Misconfiguration", vec!["A05"]);
    m.insert("Clickjacking", vec!["A05"]);
    m.insert("Cache Poisoning", vec!["A05"]);
    m.insert("Known Vulnerable Dependency", vec!["A06"]);
    m.insert("Broken Authentication", vec!["A07"]);
    m.insert("JWT Vulnerability", vec!["A07"]);
    m.insert("Insecure Deserialization", vec!["A08"]);
    m.insert("Server-Side Request Forgery", vec!["A10"]);
    m
}

fn pci_dss_requirements() -> Vec<RequirementDef> {
    vec![
        RequirementDef {
            id: "6.2",
            title: "Custom Software Security",
            description: "Bespoke and custom software is developed securely",
        },
        RequirementDef {
            id: "6.3",
            title: "Security Vulnerabilities",
            description: "Security vulnerabilities are identified and addressed",
        },
        RequirementDef {
            id: "6.4",
            title: "Public-Facing Web App Protection",
            description: "Public-facing web applications are protected against attacks",
        },
        RequirementDef {
            id: "6.5",
            title: "Change Management",
            description: "Changes to all system components are managed securely",
        },
        RequirementDef {
            id: "8.3",
            title: "Strong Authentication",
            description: "Strong authentication for users and administrators is established and managed",
        },
        RequirementDef {
            id: "11.3",
            title: "Vulnerability Management",
            description: "External and internal vulnerabilities are regularly tested",
        },
    ]
}

fn pci_dss_vuln_mapping() -> HashMap<&'static str, Vec<&'static str>> {
    let mut m = HashMap::new();
    m.insert("SQL Injection", vec!["6.2", "6.3", "6.4"]);
    m.insert("NoSQL Injection", vec!["6.2", "6.3", "6.4"]);
    m.insert("Cross-Site Scripting", vec!["6.2", "6.4"]);
    m.insert("Command Injection", vec!["6.2", "6.3"]);
    m.insert("Path Traversal", vec!["6.2", "6.3"]);
    m.insert("XML External Entity", vec!["6.2", "6.3"]);
    m.insert("Server-Side Template Injection", vec!["6.2", "6.3"]);
    m.insert("Server-Side Request Forgery", vec!["6.2", "6.3"]);
    m.insert("Header Injection", vec!["6.2"]);
    m.insert("CRLF Injection", vec!["6.2"]);
    m.insert("Host Header Injection", vec!["6.2"]);
    m.insert("Insecure Deserialization", vec!["6.2"]);
    m.insert("Insufficient Input Validation", vec!["6.2"]);
    m.insert("Prototype Pollution", vec!["6.2"]);
    m.insert("Security Misconfiguration", vec!["6.5"]);
    m.insert("Missing Security Header", vec!["6.5"]);
    m.insert("Cross-Origin Misconfiguration", vec!["6.5"]);
    m.insert("HTTP Request Smuggling", vec!["6.5"]);
    m.insert("Cloud Misconfiguration", vec!["6.5"]);
    m.insert("Clickjacking", vec!["6.5"]);
    m.insert("Broken Authentication", vec!["8.3"]);
    m.insert("JWT Vulnerability", vec!["8.3"]);
    m.insert("Broken Authorization", vec!["8.3"]);
    m.insert("Known Vulnerable Dependency", vec!["6.3", "11.3"]);
    m.insert("Sensitive Data Exposure", vec!["6.2"]);
    m.insert("Information Disclosure", vec!["6.2"]);
    m.insert("Weak Cryptography", vec!["6.2"]);
    m
}

fn nist_requirements() -> Vec<RequirementDef> {
    vec![
        RequirementDef {
            id: "AC",
            title: "Access Control",
            description: "Limit system access to authorized users, processes, and devices",
        },
        RequirementDef {
            id: "AU",
            title: "Audit and Accountability",
            description: "Create, protect, and retain system audit records",
        },
        RequirementDef {
            id: "CA",
            title: "Assessment, Authorization, and Monitoring",
            description: "Assess security controls, authorize systems, and monitor controls",
        },
        RequirementDef {
            id: "CM",
            title: "Configuration Management",
            description: "Establish and maintain baseline configurations and inventories",
        },
        RequirementDef {
            id: "IA",
            title: "Identification and Authentication",
            description: "Identify and authenticate users, devices, and services",
        },
        RequirementDef {
            id: "IR",
            title: "Incident Response",
            description: "Establish an operational incident-handling capability",
        },
        RequirementDef {
            id: "SC",
            title: "System and Communications Protection",
            description: "Protect communications and control information at boundaries",
        },
        RequirementDef {
            id: "SI",
            title: "System and Information Integrity",
            description: "Identify, report, and correct information and system flaws in a timely manner",
        },
    ]
}

fn nist_vuln_mapping() -> HashMap<&'static str, Vec<&'static str>> {
    let mut m = HashMap::new();
    m.insert("Broken Authorization", vec!["AC"]);
    m.insert("Insecure Direct Object Reference", vec!["AC"]);
    m.insert("Mass Assignment", vec!["AC"]);
    m.insert("Open Redirect", vec!["AC"]);
    m.insert("Broken Authentication", vec!["IA"]);
    m.insert("JWT Vulnerability", vec!["IA"]);
    m.insert("Security Misconfiguration", vec!["CM"]);
    m.insert("Missing Security Header", vec!["CM"]);
    m.insert("Cross-Origin Misconfiguration", vec!["CM"]);
    m.insert("Cloud Misconfiguration", vec!["CM"]);
    m.insert("SQL Injection", vec!["SI"]);
    m.insert("NoSQL Injection", vec!["SI"]);
    m.insert("Cross-Site Scripting", vec!["SI"]);
    m.insert("Command Injection", vec!["SI"]);
    m.insert("Path Traversal", vec!["SI"]);
    m.insert("XML External Entity", vec!["SI"]);
    m.insert("Server-Side Template Injection", vec!["SI"]);
    m.insert("Header Injection", vec!["SI"]);
    m.insert("CRLF Injection", vec!["SI"]);
    m.insert("Insufficient Input Validation", vec!["SI"]);
    m.insert("Prototype Pollution", vec!["SI"]);
    m.insert("Host Header Injection", vec!["SI"]);
    m.insert("Insecure Deserialization", vec!["SI"]);
    m.insert("Known Vulnerable Dependency", vec!["SI"]);
    m.insert("Sensitive Data Exposure", vec!["SC"]);
    m.insert("Information Disclosure", vec!["SC"]);
    m.insert("Weak Cryptography", vec!["SC"]);
    m.insert("Server-Side Request Forgery", vec!["SC"]);
    m.insert("HTTP Request Smuggling", vec!["SC"]);
    m.insert("Cache Poisoning", vec!["SC"]);
    m.insert("GraphQL Abuse", vec!["SI"]);
    m.insert("Subdomain Takeover", vec!["CM"]);
    m.insert("Clickjacking", vec!["CM"]);
    m.insert("Race Condition", vec!["SI"]);
    m
}

fn cis_requirements() -> Vec<RequirementDef> {
    vec![
        RequirementDef {
            id: "IG1-4",
            title: "Secure Configuration of Enterprise Assets and Software",
            description: "Establish and maintain secure configuration processes",
        },
        RequirementDef {
            id: "IG1-5",
            title: "Account Management",
            description: "Use processes and tools to assign and manage authorization to credentials",
        },
        RequirementDef {
            id: "IG1-6",
            title: "Access Control Management",
            description: "Use processes and tools to create, assign, manage, and revoke access credentials",
        },
        RequirementDef {
            id: "IG2-7",
            title: "Continuous Vulnerability Management",
            description: "Continuously acquire, assess, and take action on vulnerability information",
        },
        RequirementDef {
            id: "IG2-8",
            title: "Audit Log Management",
            description: "Collect, alert, review, and retain audit logs of events",
        },
        RequirementDef {
            id: "IG2-16",
            title: "Application Software Security",
            description: "Manage the security life cycle of in-house developed, hosted, or acquired software",
        },
        RequirementDef {
            id: "IG3-18",
            title: "Penetration Testing",
            description: "Test the effectiveness and resiliency of enterprise assets through penetration testing",
        },
    ]
}

fn cis_vuln_mapping() -> HashMap<&'static str, Vec<&'static str>> {
    let mut m = HashMap::new();
    m.insert("Security Misconfiguration", vec!["IG1-4"]);
    m.insert("Missing Security Header", vec!["IG1-4"]);
    m.insert("Cross-Origin Misconfiguration", vec!["IG1-4"]);
    m.insert("Cloud Misconfiguration", vec!["IG1-4"]);
    m.insert("Clickjacking", vec!["IG1-4"]);
    m.insert("HTTP Request Smuggling", vec!["IG1-4"]);
    m.insert("Subdomain Takeover", vec!["IG1-4"]);
    m.insert("Cache Poisoning", vec!["IG1-4"]);
    m.insert("Broken Authentication", vec!["IG1-5"]);
    m.insert("JWT Vulnerability", vec!["IG1-5"]);
    m.insert("Broken Authorization", vec!["IG1-6"]);
    m.insert("Insecure Direct Object Reference", vec!["IG1-6"]);
    m.insert("Mass Assignment", vec!["IG1-6"]);
    m.insert("Open Redirect", vec!["IG1-6"]);
    m.insert("Known Vulnerable Dependency", vec!["IG2-7"]);
    m.insert("SQL Injection", vec!["IG2-16"]);
    m.insert("NoSQL Injection", vec!["IG2-16"]);
    m.insert("Cross-Site Scripting", vec!["IG2-16"]);
    m.insert("Command Injection", vec!["IG2-16"]);
    m.insert("Path Traversal", vec!["IG2-16"]);
    m.insert("XML External Entity", vec!["IG2-16"]);
    m.insert("Server-Side Template Injection", vec!["IG2-16"]);
    m.insert("Server-Side Request Forgery", vec!["IG2-16"]);
    m.insert("Header Injection", vec!["IG2-16"]);
    m.insert("CRLF Injection", vec!["IG2-16"]);
    m.insert("Host Header Injection", vec!["IG2-16"]);
    m.insert("Insecure Deserialization", vec!["IG2-16"]);
    m.insert("Insufficient Input Validation", vec!["IG2-16"]);
    m.insert("Prototype Pollution", vec!["IG2-16"]);
    m.insert("GraphQL Abuse", vec!["IG2-16"]);
    m.insert("Sensitive Data Exposure", vec!["IG2-16"]);
    m.insert("Information Disclosure", vec!["IG2-16"]);
    m.insert("Weak Cryptography", vec!["IG2-16"]);
    m.insert("Race Condition", vec!["IG2-16"]);
    m
}
