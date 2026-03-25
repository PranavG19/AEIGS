use std::fmt;
use std::fmt::Write;

use aegis_protocol::finding::VulnerabilityClass;
use serde::{Deserialize, Serialize};

/// Type of action recorded in the audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuditActionType {
    ScanStarted,
    ScanCompleted,
    EndpointDiscovered,
    VulnerabilityFound,
    EvidenceCollected,
    FuzzingExecuted,
    AuthenticationTested,
    ComplianceChecked,
    ReportGenerated,
    RemediationRecommended,
    ConfigurationChanged,
    ManualReview,
}

impl fmt::Display for AuditActionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditActionType::ScanStarted => write!(f, "Scan Started"),
            AuditActionType::ScanCompleted => write!(f, "Scan Completed"),
            AuditActionType::EndpointDiscovered => write!(f, "Endpoint Discovered"),
            AuditActionType::VulnerabilityFound => write!(f, "Vulnerability Found"),
            AuditActionType::EvidenceCollected => write!(f, "Evidence Collected"),
            AuditActionType::FuzzingExecuted => write!(f, "Fuzzing Executed"),
            AuditActionType::AuthenticationTested => write!(f, "Authentication Tested"),
            AuditActionType::ComplianceChecked => write!(f, "Compliance Checked"),
            AuditActionType::ReportGenerated => write!(f, "Report Generated"),
            AuditActionType::RemediationRecommended => write!(f, "Remediation Recommended"),
            AuditActionType::ConfigurationChanged => write!(f, "Configuration Changed"),
            AuditActionType::ManualReview => write!(f, "Manual Review"),
        }
    }
}

/// Severity of an audit trail entry for filtering and prioritization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuditSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for AuditSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditSeverity::Info => write!(f, "INFO"),
            AuditSeverity::Low => write!(f, "LOW"),
            AuditSeverity::Medium => write!(f, "MEDIUM"),
            AuditSeverity::High => write!(f, "HIGH"),
            AuditSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A single entry in the compliance audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrailEntry {
    pub sequence: u64,
    pub timestamp_ms: u64,
    pub action_type: AuditActionType,
    pub severity: AuditSeverity,
    pub actor: String,
    pub target: String,
    pub description: String,
    pub evidence: Vec<EvidenceRecord>,
    pub related_vulnerabilities: Vec<VulnerabilityClass>,
    pub remediation: Option<String>,
}

/// Evidence collected during a scan action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub evidence_type: EvidenceType,
    pub description: String,
    pub data_reference: String,
}

/// Type of evidence collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceType {
    HttpRequest,
    HttpResponse,
    Screenshot,
    LogEntry,
    ConfigurationSnapshot,
    NetworkCapture,
    CodeSnippet,
    CertificateInfo,
}

impl fmt::Display for EvidenceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvidenceType::HttpRequest => write!(f, "HTTP Request"),
            EvidenceType::HttpResponse => write!(f, "HTTP Response"),
            EvidenceType::Screenshot => write!(f, "Screenshot"),
            EvidenceType::LogEntry => write!(f, "Log Entry"),
            EvidenceType::ConfigurationSnapshot => write!(f, "Configuration Snapshot"),
            EvidenceType::NetworkCapture => write!(f, "Network Capture"),
            EvidenceType::CodeSnippet => write!(f, "Code Snippet"),
            EvidenceType::CertificateInfo => write!(f, "Certificate Info"),
        }
    }
}

/// Builder for constructing audit trail entries with a running sequence.
#[derive(Debug, Clone)]
pub struct AuditTrailBuilder {
    entries: Vec<AuditTrailEntry>,
    next_sequence: u64,
    scan_target: String,
}

impl AuditTrailBuilder {
    pub fn new(scan_target: &str) -> Self {
        Self {
            entries: Vec::new(),
            next_sequence: 1,
            scan_target: scan_target.to_string(),
        }
    }

    /// Records a scan start event.
    pub fn record_scan_start(&mut self, timestamp_ms: u64, config_summary: &str) {
        let seq = self.next_seq();
        let target = self.scan_target.clone();
        let desc = format!("Security scan initiated against {}", target);
        self.add_entry(AuditTrailEntry {
            sequence: seq,
            timestamp_ms,
            action_type: AuditActionType::ScanStarted,
            severity: AuditSeverity::Info,
            actor: "aegis-scanner".into(),
            target,
            description: desc,
            evidence: vec![EvidenceRecord {
                evidence_type: EvidenceType::ConfigurationSnapshot,
                description: "Scan configuration".into(),
                data_reference: config_summary.into(),
            }],
            related_vulnerabilities: vec![],
            remediation: None,
        });
    }

    /// Records discovery of an endpoint.
    pub fn record_endpoint_discovered(&mut self, timestamp_ms: u64, endpoint: &str, method: &str) {
        let seq = self.next_seq();
        self.add_entry(AuditTrailEntry {
            sequence: seq,
            timestamp_ms,
            action_type: AuditActionType::EndpointDiscovered,
            severity: AuditSeverity::Info,
            actor: "aegis-crawler".into(),
            target: endpoint.into(),
            description: format!("Discovered endpoint: {method} {endpoint}"),
            evidence: vec![],
            related_vulnerabilities: vec![],
            remediation: None,
        });
    }

    /// Records a vulnerability finding.
    pub fn record_vulnerability(
        &mut self,
        timestamp_ms: u64,
        vuln_class: VulnerabilityClass,
        endpoint: &str,
        evidence_desc: &str,
        evidence_data: &str,
        remediation: &str,
    ) {
        let seq = self.next_seq();
        let severity = vuln_to_audit_severity(vuln_class);
        self.add_entry(AuditTrailEntry {
            sequence: seq,
            timestamp_ms,
            action_type: AuditActionType::VulnerabilityFound,
            severity,
            actor: "aegis-fuzzer".into(),
            target: endpoint.into(),
            description: format!("{} discovered at {}", vuln_class, endpoint),
            evidence: vec![EvidenceRecord {
                evidence_type: EvidenceType::HttpResponse,
                description: evidence_desc.into(),
                data_reference: evidence_data.into(),
            }],
            related_vulnerabilities: vec![vuln_class],
            remediation: Some(remediation.into()),
        });
    }

    /// Records a fuzzing execution event.
    pub fn record_fuzzing(&mut self, timestamp_ms: u64, endpoint: &str, payloads_tested: usize) {
        let seq = self.next_seq();
        self.add_entry(AuditTrailEntry {
            sequence: seq,
            timestamp_ms,
            action_type: AuditActionType::FuzzingExecuted,
            severity: AuditSeverity::Info,
            actor: "aegis-fuzzer".into(),
            target: endpoint.into(),
            description: format!("Executed {payloads_tested} fuzz payloads against {endpoint}"),
            evidence: vec![],
            related_vulnerabilities: vec![],
            remediation: None,
        });
    }

    /// Records evidence collection.
    pub fn record_evidence(
        &mut self,
        timestamp_ms: u64,
        target: &str,
        evidence_type: EvidenceType,
        description: &str,
        data_ref: &str,
    ) {
        let seq = self.next_seq();
        self.add_entry(AuditTrailEntry {
            sequence: seq,
            timestamp_ms,
            action_type: AuditActionType::EvidenceCollected,
            severity: AuditSeverity::Info,
            actor: "aegis-scanner".into(),
            target: target.into(),
            description: description.into(),
            evidence: vec![EvidenceRecord {
                evidence_type,
                description: description.into(),
                data_reference: data_ref.into(),
            }],
            related_vulnerabilities: vec![],
            remediation: None,
        });
    }

    /// Records a compliance check result.
    pub fn record_compliance_check(
        &mut self,
        timestamp_ms: u64,
        framework: &str,
        compliance_pct: f64,
    ) {
        let seq = self.next_seq();
        self.add_entry(AuditTrailEntry {
            sequence: seq,
            timestamp_ms,
            action_type: AuditActionType::ComplianceChecked,
            severity: if compliance_pct < 50.0 {
                AuditSeverity::High
            } else if compliance_pct < 80.0 {
                AuditSeverity::Medium
            } else {
                AuditSeverity::Info
            },
            actor: "aegis-compliance".into(),
            target: framework.into(),
            description: format!("{framework} compliance check: {compliance_pct:.1}% compliant"),
            evidence: vec![],
            related_vulnerabilities: vec![],
            remediation: None,
        });
    }

    /// Records a remediation recommendation.
    pub fn record_remediation(
        &mut self,
        timestamp_ms: u64,
        target: &str,
        vuln_class: VulnerabilityClass,
        recommendation: &str,
    ) {
        let seq = self.next_seq();
        self.add_entry(AuditTrailEntry {
            sequence: seq,
            timestamp_ms,
            action_type: AuditActionType::RemediationRecommended,
            severity: vuln_to_audit_severity(vuln_class),
            actor: "aegis-compliance".into(),
            target: target.into(),
            description: format!("Remediation recommended for {} at {}", vuln_class, target),
            evidence: vec![],
            related_vulnerabilities: vec![vuln_class],
            remediation: Some(recommendation.into()),
        });
    }

    /// Records scan completion.
    pub fn record_scan_complete(
        &mut self,
        timestamp_ms: u64,
        findings_count: usize,
        endpoints_tested: usize,
    ) {
        let seq = self.next_seq();
        let target = self.scan_target.clone();
        self.add_entry(AuditTrailEntry {
            sequence: seq,
            timestamp_ms,
            action_type: AuditActionType::ScanCompleted,
            severity: AuditSeverity::Info,
            actor: "aegis-scanner".into(),
            target,
            description: format!(
                "Scan completed: {findings_count} findings across {endpoints_tested} endpoints"
            ),
            evidence: vec![],
            related_vulnerabilities: vec![],
            remediation: None,
        });
    }

    /// Produces the finalized audit trail.
    pub fn build(self) -> AuditTrail {
        AuditTrail {
            scan_target: self.scan_target,
            entries: self.entries,
        }
    }

    fn next_seq(&mut self) -> u64 {
        let seq = self.next_sequence;
        self.next_sequence += 1;
        seq
    }

    fn add_entry(&mut self, entry: AuditTrailEntry) {
        self.entries.push(entry);
    }
}

/// Complete compliance audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrail {
    pub scan_target: String,
    pub entries: Vec<AuditTrailEntry>,
}

impl AuditTrail {
    /// Returns entries filtered by severity at or above the given level.
    pub fn filter_by_severity(&self, min_severity: AuditSeverity) -> Vec<&AuditTrailEntry> {
        self.entries
            .iter()
            .filter(|e| e.severity >= min_severity)
            .collect()
    }

    /// Returns entries filtered by action type.
    pub fn filter_by_action(&self, action: AuditActionType) -> Vec<&AuditTrailEntry> {
        self.entries
            .iter()
            .filter(|e| e.action_type == action)
            .collect()
    }

    /// Returns all entries with associated vulnerabilities.
    pub fn vulnerability_entries(&self) -> Vec<&AuditTrailEntry> {
        self.entries
            .iter()
            .filter(|e| !e.related_vulnerabilities.is_empty())
            .collect()
    }

    /// Returns all entries with remediation recommendations.
    pub fn remediation_entries(&self) -> Vec<&AuditTrailEntry> {
        self.entries
            .iter()
            .filter(|e| e.remediation.is_some())
            .collect()
    }

    /// Returns total entry count.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

fn vuln_to_audit_severity(vuln: VulnerabilityClass) -> AuditSeverity {
    match vuln {
        VulnerabilityClass::SqlInjection
        | VulnerabilityClass::CommandInjection
        | VulnerabilityClass::InsecureDeserialization
        | VulnerabilityClass::ServerSideRequestForgery => AuditSeverity::Critical,
        VulnerabilityClass::BrokenAuthentication
        | VulnerabilityClass::BrokenAuthorization
        | VulnerabilityClass::PathTraversal
        | VulnerabilityClass::ServerSideTemplateInjection
        | VulnerabilityClass::NoSqlInjection
        | VulnerabilityClass::XmlExternalEntity => AuditSeverity::High,
        VulnerabilityClass::CrossSiteScripting
        | VulnerabilityClass::JwtVulnerability
        | VulnerabilityClass::InsecureDirectObjectReference
        | VulnerabilityClass::MassAssignment
        | VulnerabilityClass::SensitiveDataExposure
        | VulnerabilityClass::WeakCryptography
        | VulnerabilityClass::KnownVulnerableDependency => AuditSeverity::Medium,
        VulnerabilityClass::SecurityMisconfiguration
        | VulnerabilityClass::MissingSecurityHeader
        | VulnerabilityClass::CrossOriginMisconfiguration
        | VulnerabilityClass::InformationDisclosure
        | VulnerabilityClass::CloudMisconfiguration => AuditSeverity::Low,
        _ => AuditSeverity::Info,
    }
}

/// Formats an audit trail as a human-readable markdown report suitable for auditor review.
pub fn format_audit_trail(trail: &AuditTrail) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Compliance Audit Trail\n");
    let _ = writeln!(out, "**Target:** {}\n", trail.scan_target);
    let _ = writeln!(out, "**Total Entries:** {}\n", trail.entries.len());

    let vuln_count = trail.vulnerability_entries().len();
    let remediation_count = trail.remediation_entries().len();
    let _ = writeln!(out, "**Vulnerability Findings:** {vuln_count}");
    let _ = writeln!(
        out,
        "**Remediation Recommendations:** {remediation_count}\n"
    );

    let _ = writeln!(out, "## Timeline\n");
    let _ = writeln!(
        out,
        "| # | Timestamp (ms) | Severity | Action | Target | Description |"
    );
    let _ = writeln!(
        out,
        "|---|----------------|----------|--------|--------|-------------|"
    );

    for entry in &trail.entries {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} |",
            entry.sequence,
            entry.timestamp_ms,
            entry.severity,
            entry.action_type,
            entry.target,
            entry.description,
        );
    }
    let _ = writeln!(out);

    let critical_entries = trail.filter_by_severity(AuditSeverity::High);
    if !critical_entries.is_empty() {
        let _ = writeln!(out, "## High/Critical Findings\n");
        for entry in critical_entries {
            let _ = writeln!(
                out,
                "### [{}/{}] {} \u{2014} {}\n",
                entry.sequence, entry.severity, entry.action_type, entry.target
            );
            let _ = writeln!(out, "{}\n", entry.description);

            if !entry.evidence.is_empty() {
                let _ = writeln!(out, "**Evidence:**");
                for ev in &entry.evidence {
                    let _ = writeln!(
                        out,
                        "- {} ({}): {}",
                        ev.evidence_type, ev.description, ev.data_reference
                    );
                }
            }

            if let Some(ref rem) = entry.remediation {
                let _ = writeln!(out, "\n**Remediation:** {rem}");
            }
            let _ = writeln!(out);
        }
    }

    let remediation_entries = trail.remediation_entries();
    if !remediation_entries.is_empty() {
        let _ = writeln!(out, "## Remediation Summary\n");
        for entry in remediation_entries {
            if let Some(ref rem) = entry.remediation {
                let _ = writeln!(out, "- **{}** ({}): {}", entry.target, entry.severity, rem);
            }
        }
    }

    out
}
