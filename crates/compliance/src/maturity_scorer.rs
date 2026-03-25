use std::fmt;
use std::fmt::Write;

use aegis_protocol::finding::VulnerabilityClass;
use serde::{Deserialize, Serialize};

/// Security maturity dimensions evaluated during scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MaturityDimension {
    VulnerabilityManagement,
    AccessControl,
    Encryption,
    Monitoring,
    IncidentResponse,
}

impl fmt::Display for MaturityDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MaturityDimension::VulnerabilityManagement => write!(f, "Vulnerability Management"),
            MaturityDimension::AccessControl => write!(f, "Access Control"),
            MaturityDimension::Encryption => write!(f, "Encryption"),
            MaturityDimension::Monitoring => write!(f, "Monitoring"),
            MaturityDimension::IncidentResponse => write!(f, "Incident Response"),
        }
    }
}

/// Maturity level 1-5 following industry-standard capability maturity models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MaturityLevel {
    Initial = 1,
    Developing = 2,
    Defined = 3,
    Managed = 4,
    Optimizing = 5,
}

impl MaturityLevel {
    pub fn score(self) -> u32 {
        self as u32
    }

    fn from_score(score: u32) -> Self {
        match score {
            0..=1 => MaturityLevel::Initial,
            2 => MaturityLevel::Developing,
            3 => MaturityLevel::Defined,
            4 => MaturityLevel::Managed,
            _ => MaturityLevel::Optimizing,
        }
    }
}

impl fmt::Display for MaturityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MaturityLevel::Initial => write!(f, "Level 1 - Initial"),
            MaturityLevel::Developing => write!(f, "Level 2 - Developing"),
            MaturityLevel::Defined => write!(f, "Level 3 - Defined"),
            MaturityLevel::Managed => write!(f, "Level 4 - Managed"),
            MaturityLevel::Optimizing => write!(f, "Level 5 - Optimizing"),
        }
    }
}

/// Observed security control for maturity assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedControl {
    pub dimension: MaturityDimension,
    pub control_name: String,
    pub present: bool,
    pub description: String,
}

/// Evidence collected during a scan that feeds maturity scoring.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MaturityEvidence {
    pub discovered_vulnerabilities: Vec<VulnerabilityClass>,
    pub observed_controls: Vec<ObservedControl>,
    pub has_security_headers: bool,
    pub has_rate_limiting: bool,
    pub has_waf: bool,
    pub has_cors_policy: bool,
    pub has_csp: bool,
    pub has_hsts: bool,
    pub uses_tls: bool,
    pub has_auth_mechanism: bool,
    pub has_audit_logging: bool,
    pub has_error_handling: bool,
    pub dependency_count: usize,
    pub vulnerable_dependency_count: usize,
}

/// Score for a single maturity dimension with rationale.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimensionScore {
    pub dimension: MaturityDimension,
    pub level: MaturityLevel,
    pub findings: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Complete security maturity assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaturityAssessment {
    pub dimension_scores: Vec<DimensionScore>,
    pub overall_level: MaturityLevel,
    pub overall_score: f64,
    pub strengths: Vec<String>,
    pub weaknesses: Vec<String>,
}

/// Scores security maturity across five dimensions based on scan evidence.
///
/// Each dimension is scored Level 1-5 based on observed controls, discovered
/// vulnerabilities, and security posture indicators.
pub fn score_maturity(evidence: &MaturityEvidence) -> MaturityAssessment {
    let vuln_mgmt = score_vulnerability_management(evidence);
    let access = score_access_control(evidence);
    let encryption = score_encryption(evidence);
    let monitoring = score_monitoring(evidence);
    let incident = score_incident_response(evidence);

    let dimension_scores = vec![vuln_mgmt, access, encryption, monitoring, incident];

    let total: u32 = dimension_scores.iter().map(|d| d.level.score()).sum();
    let avg = total as f64 / dimension_scores.len() as f64;
    let overall_level = MaturityLevel::from_score(avg.round() as u32);

    let strengths = dimension_scores
        .iter()
        .filter(|d| d.level.score() >= 4)
        .map(|d| format!("{}: {}", d.dimension, d.level))
        .collect();

    let weaknesses = dimension_scores
        .iter()
        .filter(|d| d.level.score() <= 2)
        .map(|d| format!("{}: {}", d.dimension, d.level))
        .collect();

    MaturityAssessment {
        dimension_scores,
        overall_level,
        overall_score: avg,
        strengths,
        weaknesses,
    }
}

fn score_vulnerability_management(evidence: &MaturityEvidence) -> DimensionScore {
    let mut score: u32 = 3;
    let mut findings = Vec::new();
    let mut recommendations = Vec::new();

    let critical_vulns: Vec<&VulnerabilityClass> = evidence
        .discovered_vulnerabilities
        .iter()
        .filter(is_critical_vuln)
        .collect();

    let high_vulns: Vec<&VulnerabilityClass> = evidence
        .discovered_vulnerabilities
        .iter()
        .filter(is_high_vuln)
        .collect();

    if !critical_vulns.is_empty() {
        score = score.saturating_sub(2);
        findings.push(format!(
            "{} critical vulnerabilities discovered",
            critical_vulns.len()
        ));
        recommendations.push("Immediately remediate critical vulnerabilities".into());
    }

    if !high_vulns.is_empty() {
        score = score.saturating_sub(1);
        findings.push(format!(
            "{} high-severity vulnerabilities discovered",
            high_vulns.len()
        ));
        recommendations.push("Prioritize remediation of high-severity vulnerabilities".into());
    }

    if evidence.vulnerable_dependency_count > 0 {
        score = score.saturating_sub(1);
        findings.push(format!(
            "{} of {} dependencies have known vulnerabilities",
            evidence.vulnerable_dependency_count, evidence.dependency_count
        ));
        recommendations.push("Implement automated dependency scanning in CI/CD".into());
    } else if evidence.dependency_count > 0 {
        score += 1;
        findings.push("No known vulnerable dependencies detected".into());
    }

    if evidence.has_waf {
        score += 1;
        findings.push("Web Application Firewall detected".into());
    } else {
        recommendations.push("Deploy a WAF for defense-in-depth".into());
    }

    DimensionScore {
        dimension: MaturityDimension::VulnerabilityManagement,
        level: MaturityLevel::from_score(score.clamp(1, 5)),
        findings,
        recommendations,
    }
}

fn score_access_control(evidence: &MaturityEvidence) -> DimensionScore {
    let mut score: u32 = 3;
    let mut findings = Vec::new();
    let mut recommendations = Vec::new();

    let has_auth_vuln = evidence.discovered_vulnerabilities.iter().any(|v| {
        matches!(
            v,
            VulnerabilityClass::BrokenAuthentication | VulnerabilityClass::JwtVulnerability
        )
    });

    let has_authz_vuln = evidence.discovered_vulnerabilities.iter().any(|v| {
        matches!(
            v,
            VulnerabilityClass::BrokenAuthorization
                | VulnerabilityClass::InsecureDirectObjectReference
                | VulnerabilityClass::MassAssignment
        )
    });

    if has_auth_vuln {
        score = score.saturating_sub(2);
        findings.push("Authentication vulnerabilities discovered".into());
        recommendations.push("Strengthen authentication mechanisms and implement MFA".into());
    }

    if has_authz_vuln {
        score = score.saturating_sub(1);
        findings.push("Authorization bypass vulnerabilities discovered".into());
        recommendations.push("Implement RBAC and validate authorization on every request".into());
    }

    if evidence.has_auth_mechanism {
        score += 1;
        findings.push("Authentication mechanism present".into());
    } else {
        score = score.saturating_sub(1);
        findings.push("No authentication mechanism detected".into());
        recommendations.push("Implement authentication for all sensitive endpoints".into());
    }

    if evidence.has_cors_policy {
        findings.push("CORS policy configured".into());
    } else {
        recommendations.push("Configure restrictive CORS policy".into());
    }

    DimensionScore {
        dimension: MaturityDimension::AccessControl,
        level: MaturityLevel::from_score(score.clamp(1, 5)),
        findings,
        recommendations,
    }
}

fn score_encryption(evidence: &MaturityEvidence) -> DimensionScore {
    let mut score: u32 = 3;
    let mut findings = Vec::new();
    let mut recommendations = Vec::new();

    if evidence.uses_tls {
        score += 1;
        findings.push("TLS encryption in use".into());
    } else {
        score = score.saturating_sub(2);
        findings.push("TLS not detected".into());
        recommendations.push("Enable TLS for all communications".into());
    }

    if evidence.has_hsts {
        score += 1;
        findings.push("HSTS header present".into());
    } else {
        recommendations.push("Enable HSTS to prevent downgrade attacks".into());
    }

    let has_crypto_vuln = evidence
        .discovered_vulnerabilities
        .contains(&VulnerabilityClass::WeakCryptography);
    if has_crypto_vuln {
        score = score.saturating_sub(2);
        findings.push("Weak cryptography detected".into());
        recommendations.push("Upgrade to strong cipher suites and key lengths".into());
    }

    let has_data_exposure = evidence.discovered_vulnerabilities.iter().any(|v| {
        matches!(
            v,
            VulnerabilityClass::SensitiveDataExposure | VulnerabilityClass::InformationDisclosure
        )
    });
    if has_data_exposure {
        score = score.saturating_sub(1);
        findings.push("Sensitive data exposure detected".into());
        recommendations.push("Encrypt sensitive data at rest and in transit".into());
    }

    DimensionScore {
        dimension: MaturityDimension::Encryption,
        level: MaturityLevel::from_score(score.clamp(1, 5)),
        findings,
        recommendations,
    }
}

fn score_monitoring(evidence: &MaturityEvidence) -> DimensionScore {
    let mut score: u32 = 2;
    let mut findings = Vec::new();
    let mut recommendations = Vec::new();

    if evidence.has_rate_limiting {
        score += 1;
        findings.push("Rate limiting detected".into());
    } else {
        recommendations.push("Implement rate limiting on all endpoints".into());
    }

    if evidence.has_security_headers {
        score += 1;
        findings.push("Security headers present".into());
    } else {
        recommendations.push("Add security headers (CSP, X-Frame-Options, etc.)".into());
    }

    if evidence.has_error_handling {
        score += 1;
        findings.push("Proper error handling observed".into());
    } else {
        findings.push("Verbose error messages may expose internal details".into());
        recommendations.push("Implement generic error responses in production".into());
    }

    if evidence.has_audit_logging {
        score += 1;
        findings.push("Audit logging present".into());
    } else {
        recommendations.push("Implement comprehensive audit logging".into());
    }

    DimensionScore {
        dimension: MaturityDimension::Monitoring,
        level: MaturityLevel::from_score(score.clamp(1, 5)),
        findings,
        recommendations,
    }
}

fn score_incident_response(evidence: &MaturityEvidence) -> DimensionScore {
    let mut score: u32 = 2;
    let mut findings = Vec::new();
    let mut recommendations = Vec::new();

    if evidence.has_audit_logging {
        score += 1;
        findings.push("Audit trail supports incident investigation".into());
    } else {
        recommendations.push("Implement audit logging for incident forensics".into());
    }

    if evidence.has_waf {
        score += 1;
        findings.push("WAF can support automated incident blocking".into());
    }

    let total_vulns = evidence.discovered_vulnerabilities.len();
    if total_vulns == 0 {
        score += 1;
        findings.push("No vulnerabilities found indicates proactive security".into());
    } else if total_vulns > 10 {
        score = score.saturating_sub(1);
        findings.push(format!(
            "{total_vulns} vulnerabilities suggest reactive security posture"
        ));
        recommendations.push("Establish vulnerability SLAs and remediation workflows".into());
    }

    if evidence.has_error_handling {
        findings.push("Error handling prevents information leakage during incidents".into());
    } else {
        recommendations.push("Ensure error handling doesn't leak details during incidents".into());
    }

    DimensionScore {
        dimension: MaturityDimension::IncidentResponse,
        level: MaturityLevel::from_score(score.clamp(1, 5)),
        findings,
        recommendations,
    }
}

fn is_critical_vuln(v: &&VulnerabilityClass) -> bool {
    matches!(
        v,
        VulnerabilityClass::SqlInjection
            | VulnerabilityClass::CommandInjection
            | VulnerabilityClass::InsecureDeserialization
            | VulnerabilityClass::ServerSideRequestForgery
    )
}

fn is_high_vuln(v: &&VulnerabilityClass) -> bool {
    matches!(
        v,
        VulnerabilityClass::BrokenAuthentication
            | VulnerabilityClass::BrokenAuthorization
            | VulnerabilityClass::PathTraversal
            | VulnerabilityClass::ServerSideTemplateInjection
            | VulnerabilityClass::NoSqlInjection
            | VulnerabilityClass::XmlExternalEntity
    )
}

/// Formats a maturity assessment as a human-readable markdown report.
pub fn format_maturity_report(assessment: &MaturityAssessment) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Security Maturity Assessment\n");
    let _ = writeln!(
        out,
        "**Overall Maturity:** {} (Score: {:.1}/5.0)\n",
        assessment.overall_level, assessment.overall_score
    );

    let _ = writeln!(out, "## Dimension Scores\n");
    let _ = writeln!(out, "| Dimension | Level | Score |");
    let _ = writeln!(out, "|-----------|-------|-------|");
    for ds in &assessment.dimension_scores {
        let _ = writeln!(
            out,
            "| {} | {} | {}/5 |",
            ds.dimension,
            ds.level,
            ds.level.score()
        );
    }
    let _ = writeln!(out);

    for ds in &assessment.dimension_scores {
        let _ = writeln!(out, "### {}\n", ds.dimension);
        let _ = writeln!(out, "**Level:** {}\n", ds.level);
        if !ds.findings.is_empty() {
            let _ = writeln!(out, "**Findings:**");
            for f in &ds.findings {
                let _ = writeln!(out, "- {f}");
            }
        }
        if !ds.recommendations.is_empty() {
            let _ = writeln!(out, "\n**Recommendations:**");
            for r in &ds.recommendations {
                let _ = writeln!(out, "- {r}");
            }
        }
        let _ = writeln!(out);
    }

    if !assessment.strengths.is_empty() {
        let _ = writeln!(out, "## Strengths\n");
        for s in &assessment.strengths {
            let _ = writeln!(out, "- {s}");
        }
        let _ = writeln!(out);
    }

    if !assessment.weaknesses.is_empty() {
        let _ = writeln!(out, "## Weaknesses\n");
        for w in &assessment.weaknesses {
            let _ = writeln!(out, "- {w}");
        }
    }

    out
}
