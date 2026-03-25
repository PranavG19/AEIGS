/// Email infrastructure analysis: MX topology, gateway detection, open relay
/// indicators, and spoof feasibility scoring.
///
/// Operates entirely on pre-fetched DNS records, SMTP banners, and email headers.
/// No network calls. Imports `SpfQualifier` and `DmarcPolicy` from `dns_security`
/// to avoid duplicating email authentication primitives.
use std::fmt;

use super::dns_security::{DmarcPolicy, SpfQualifier};

#[derive(Debug, Clone, PartialEq)]
pub struct MxRecord {
    pub priority: u16,
    pub hostname: String,
    pub ip_addresses: Vec<String>,
}

/// Known commercial email security gateways identifiable from MX records and
/// mail headers. `Generic` captures unrecognized vendors with a freeform label.
#[derive(Debug, Clone, PartialEq)]
pub enum EmailGateway {
    Proofpoint,
    Mimecast,
    Barracuda,
    IronPort,
    MessageLabs,
    Fortimail,
    Microsoft365,
    GoogleWorkspace,
    Generic(String),
}

impl fmt::Display for EmailGateway {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Proofpoint => write!(f, "Proofpoint"),
            Self::Mimecast => write!(f, "Mimecast"),
            Self::Barracuda => write!(f, "Barracuda"),
            Self::IronPort => write!(f, "Cisco IronPort"),
            Self::MessageLabs => write!(f, "Symantec MessageLabs"),
            Self::Fortimail => write!(f, "Fortinet FortiMail"),
            Self::Microsoft365 => write!(f, "Microsoft 365"),
            Self::GoogleWorkspace => write!(f, "Google Workspace"),
            Self::Generic(name) => write!(f, "{}", name),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EmailGatewayDetection {
    pub gateway: EmailGateway,
    pub confidence: f64,
    pub evidence: Vec<String>,
}

/// Indicates whether a given MX host appears to permit open relay behavior
/// based on SMTP banner analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenRelayIndicator {
    pub hostname: String,
    pub allows_relay: bool,
    pub evidence: String,
}

/// Composite spoof feasibility assessment. `score` ranges from 0.0 (hardened)
/// to 1.0 (trivially spoofable). Factors are weighted contributors; the final
/// `overall_risk` is a categorical bucketing of the score.
#[derive(Debug, Clone, PartialEq)]
pub struct SpoofFeasibility {
    pub score: f64,
    pub factors: Vec<SpoofFactor>,
    pub overall_risk: SpoofRisk,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpoofFactor {
    pub name: String,
    pub weight: f64,
    pub present: bool,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SpoofRisk {
    Minimal,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for SpoofRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "Critical"),
            Self::High => write!(f, "High"),
            Self::Medium => write!(f, "Medium"),
            Self::Low => write!(f, "Low"),
            Self::Minimal => write!(f, "Minimal"),
        }
    }
}

/// Full email infrastructure report aggregating MX topology, gateway detection,
/// relay indicators, spoof risk, and actionable findings.
#[derive(Debug, Clone, PartialEq)]
pub struct EmailInfraReport {
    pub domain: String,
    pub mx_records: Vec<MxRecord>,
    pub gateways: Vec<EmailGatewayDetection>,
    pub open_relay_indicators: Vec<OpenRelayIndicator>,
    pub spoof_feasibility: SpoofFeasibility,
    pub findings: Vec<EmailInfraFinding>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EmailInfraFinding {
    pub severity: EmailInfraSeverity,
    pub title: String,
    pub description: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EmailInfraSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for EmailInfraSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "Info"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

pub fn parse_mx_records(raw_records: &[(&str, u16, &[&str])]) -> Vec<MxRecord> {
    let mut records: Vec<MxRecord> = raw_records
        .iter()
        .map(|(hostname, priority, ips)| MxRecord {
            priority: *priority,
            hostname: hostname.to_lowercase(),
            ip_addresses: ips.iter().map(|ip| ip.to_string()).collect(),
        })
        .collect();
    records.sort_by_key(|r| r.priority);
    records
}

pub fn detect_email_gateway(
    mx_records: &[MxRecord],
    headers: &[(&str, &str)],
) -> Vec<EmailGatewayDetection> {
    let mut detections: Vec<EmailGatewayDetection> = Vec::new();
    detect_gateways_from_mx(mx_records, &mut detections);
    detect_gateways_from_headers(headers, &mut detections);
    deduplicate_detections(&mut detections);
    detections
}

fn detect_gateways_from_mx(mx_records: &[MxRecord], detections: &mut Vec<EmailGatewayDetection>) {
    for mx in mx_records {
        let host = mx.hostname.as_str();
        if let Some(detection) = match_mx_pattern(host) {
            detections.push(detection);
        }
    }
}

fn match_mx_pattern(host: &str) -> Option<EmailGatewayDetection> {
    let (gateway, confidence) = if host.ends_with(".pphosted.com") {
        (EmailGateway::Proofpoint, 0.95)
    } else if host.ends_with(".mimecast.com") {
        (EmailGateway::Mimecast, 0.95)
    } else if host.contains("barracuda") {
        (EmailGateway::Barracuda, 0.90)
    } else if host.ends_with(".iphmx.com") {
        (EmailGateway::IronPort, 0.95)
    } else if host.ends_with(".messagelabs.com") {
        (EmailGateway::MessageLabs, 0.95)
    } else if host.contains(".fortimail.") {
        (EmailGateway::Fortimail, 0.90)
    } else if host.ends_with(".mail.protection.outlook.com") {
        (EmailGateway::Microsoft365, 0.95)
    } else if host.contains("google")
        || host.contains("smtp.google.com")
        || host == "aspmx.l.google.com"
    {
        (EmailGateway::GoogleWorkspace, 0.90)
    } else {
        return None;
    };

    Some(EmailGatewayDetection {
        gateway,
        confidence,
        evidence: vec![format!("MX hostname: {}", host)],
    })
}

fn detect_gateways_from_headers(
    headers: &[(&str, &str)],
    detections: &mut Vec<EmailGatewayDetection>,
) {
    for (name, value) in headers {
        let lower_name = name.to_lowercase();
        let lower_value = value.to_lowercase();
        if let Some(detection) = match_header_pattern(&lower_name, &lower_value) {
            detections.push(detection);
        }
    }
}

fn match_header_pattern(name: &str, value: &str) -> Option<EmailGatewayDetection> {
    let evidence_line = format!("Header {}: {}", name, value);

    if name == "x-proofpoint-virus-version" || name == "x-proofpoint-spam-details" {
        return Some(build_header_detection(
            EmailGateway::Proofpoint,
            0.98,
            evidence_line,
        ));
    }
    if name == "x-mimecast-spam-score" || name == "x-mimecast-originator" {
        return Some(build_header_detection(
            EmailGateway::Mimecast,
            0.98,
            evidence_line,
        ));
    }
    if name == "x-barracuda-spam-score" || name == "x-barracuda-spam-status" {
        return Some(build_header_detection(
            EmailGateway::Barracuda,
            0.98,
            evidence_line,
        ));
    }
    if name == "x-ironport-anti-spam-filtered" || value.contains("ironport") {
        return Some(build_header_detection(
            EmailGateway::IronPort,
            0.95,
            evidence_line,
        ));
    }
    if value.contains("messagelabs") {
        return Some(build_header_detection(
            EmailGateway::MessageLabs,
            0.90,
            evidence_line,
        ));
    }
    if value.contains("fortimail") {
        return Some(build_header_detection(
            EmailGateway::Fortimail,
            0.90,
            evidence_line,
        ));
    }
    if name == "x-ms-exchange-organization-authas"
        || name == "x-ms-exchange-organization-authsource"
    {
        return Some(build_header_detection(
            EmailGateway::Microsoft365,
            0.92,
            evidence_line,
        ));
    }
    if name == "x-google-dkim-signature" || name == "x-gm-message-state" {
        return Some(build_header_detection(
            EmailGateway::GoogleWorkspace,
            0.92,
            evidence_line,
        ));
    }
    None
}

fn build_header_detection(
    gateway: EmailGateway,
    confidence: f64,
    evidence: String,
) -> EmailGatewayDetection {
    EmailGatewayDetection {
        gateway,
        confidence,
        evidence: vec![evidence],
    }
}

fn deduplicate_detections(detections: &mut Vec<EmailGatewayDetection>) {
    let mut seen = std::collections::HashMap::<String, usize>::new();
    let mut merged: Vec<EmailGatewayDetection> = Vec::new();

    for detection in detections.drain(..) {
        let key = format!("{}", detection.gateway);
        if let Some(&idx) = seen.get(&key) {
            let existing = &mut merged[idx];
            if detection.confidence > existing.confidence {
                existing.confidence = detection.confidence;
            }
            existing.evidence.extend(detection.evidence);
        } else {
            seen.insert(key, merged.len());
            merged.push(detection);
        }
    }
    *detections = merged;
}

const RELAY_POSITIVE_PATTERNS: &[&str] = &[
    "relay access permitted",
    "relaying allowed",
    "250 ok",
    "relay ok",
];

const RELAY_NEGATIVE_PATTERNS: &[&str] = &[
    "relay access denied",
    "relay not permitted",
    "relaying denied",
    "550",
    "553",
    "554",
];

pub fn assess_open_relay(
    mx_records: &[MxRecord],
    banner_responses: &[(&str, &str)],
) -> Vec<OpenRelayIndicator> {
    let mx_hosts: std::collections::HashSet<&str> =
        mx_records.iter().map(|mx| mx.hostname.as_str()).collect();

    banner_responses
        .iter()
        .filter(|(host, _)| mx_hosts.contains(&host.to_lowercase().as_str()) || mx_hosts.is_empty())
        .map(|(host, banner)| classify_relay_banner(host, banner))
        .collect()
}

fn classify_relay_banner(host: &str, banner: &str) -> OpenRelayIndicator {
    let lower_banner = banner.to_lowercase();

    let allows_relay = RELAY_POSITIVE_PATTERNS
        .iter()
        .any(|pat| lower_banner.contains(pat))
        && !RELAY_NEGATIVE_PATTERNS
            .iter()
            .any(|pat| lower_banner.contains(pat));

    let evidence = if allows_relay {
        format!("SMTP banner indicates open relay: {}", banner)
    } else {
        format!("SMTP banner shows relay controls: {}", banner)
    };

    OpenRelayIndicator {
        hostname: host.to_string(),
        allows_relay,
        evidence,
    }
}

pub fn calculate_spoof_feasibility(
    spf_qualifier: Option<SpfQualifier>,
    dmarc_policy: Option<DmarcPolicy>,
    dkim_present: bool,
    gateway_detected: bool,
) -> SpoofFeasibility {
    let mut factors = Vec::new();
    let mut score = 0.0_f64;

    let (spf_weight, spf_present, spf_desc) = evaluate_spf_factor(spf_qualifier);
    factors.push(SpoofFactor {
        name: "SPF Policy".to_string(),
        weight: spf_weight,
        present: spf_present,
        description: spf_desc,
    });
    if spf_present {
        score += spf_weight;
    }

    let (dmarc_weight, dmarc_present, dmarc_desc) = evaluate_dmarc_factor(dmarc_policy);
    factors.push(SpoofFactor {
        name: "DMARC Policy".to_string(),
        weight: dmarc_weight,
        present: dmarc_present,
        description: dmarc_desc,
    });
    if dmarc_present {
        score += dmarc_weight;
    }

    factors.push(SpoofFactor {
        name: "DKIM Signing".to_string(),
        weight: 0.2,
        present: !dkim_present,
        description: if dkim_present {
            "DKIM signing configured".to_string()
        } else {
            "No DKIM signing detected".to_string()
        },
    });
    if !dkim_present {
        score += 0.2;
    }

    factors.push(SpoofFactor {
        name: "Email Gateway".to_string(),
        weight: 0.15,
        present: !gateway_detected,
        description: if gateway_detected {
            "Email gateway detected".to_string()
        } else {
            "No email gateway detected".to_string()
        },
    });
    if !gateway_detected {
        score += 0.15;
    }

    score = score.clamp(0.0, 1.0);
    let overall_risk = spoof_risk_from_score(score);

    SpoofFeasibility {
        score,
        factors,
        overall_risk,
    }
}

fn evaluate_spf_factor(qualifier: Option<SpfQualifier>) -> (f64, bool, String) {
    match qualifier {
        None => (0.3, true, "No SPF record published".to_string()),
        Some(SpfQualifier::Pass) => (
            0.3,
            true,
            "SPF uses +all which permits any sender".to_string(),
        ),
        Some(SpfQualifier::SoftFail) => (
            0.1,
            true,
            "SPF uses ~all (softfail) which may still deliver spoofed mail".to_string(),
        ),
        Some(SpfQualifier::Neutral) => (
            0.15,
            true,
            "SPF uses ?all (neutral) providing no assertion".to_string(),
        ),
        Some(SpfQualifier::Fail) => (
            0.3,
            false,
            "SPF uses -all which rejects unauthorized senders".to_string(),
        ),
        Some(SpfQualifier::None) => (0.3, true, "No SPF all-mechanism found".to_string()),
    }
}

fn evaluate_dmarc_factor(policy: Option<DmarcPolicy>) -> (f64, bool, String) {
    match policy {
        None | Some(DmarcPolicy::Missing) => (0.25, true, "No DMARC policy published".to_string()),
        Some(DmarcPolicy::None) => (
            0.25,
            true,
            "DMARC policy set to none (monitor only)".to_string(),
        ),
        Some(DmarcPolicy::Quarantine) => {
            (0.25, false, "DMARC policy set to quarantine".to_string())
        }
        Some(DmarcPolicy::Reject) => (0.25, false, "DMARC policy set to reject".to_string()),
    }
}

fn spoof_risk_from_score(score: f64) -> SpoofRisk {
    if score >= 0.8 {
        SpoofRisk::Critical
    } else if score >= 0.6 {
        SpoofRisk::High
    } else if score >= 0.4 {
        SpoofRisk::Medium
    } else if score >= 0.2 {
        SpoofRisk::Low
    } else {
        SpoofRisk::Minimal
    }
}

pub fn analyze_email_infrastructure(
    domain: &str,
    mx_raw: &[(&str, u16, &[&str])],
    headers: &[(&str, &str)],
    banners: &[(&str, &str)],
    spf_qualifier: Option<SpfQualifier>,
    dmarc_policy: Option<DmarcPolicy>,
    dkim_present: bool,
) -> EmailInfraReport {
    let mx_records = parse_mx_records(mx_raw);
    let gateways = detect_email_gateway(&mx_records, headers);
    let open_relay_indicators = assess_open_relay(&mx_records, banners);
    let gateway_detected = !gateways.is_empty();
    let spoof_feasibility =
        calculate_spoof_feasibility(spf_qualifier, dmarc_policy, dkim_present, gateway_detected);

    let mut report = EmailInfraReport {
        domain: domain.to_string(),
        mx_records,
        gateways,
        open_relay_indicators,
        spoof_feasibility,
        findings: Vec::new(),
    };

    report.findings = generate_email_findings(&report);
    report
}

pub fn generate_email_findings(report: &EmailInfraReport) -> Vec<EmailInfraFinding> {
    let mut findings = Vec::new();
    generate_mx_findings(report, &mut findings);
    generate_relay_findings(report, &mut findings);
    generate_spoof_findings(report, &mut findings);
    generate_gateway_findings(report, &mut findings);
    findings
}

fn generate_mx_findings(report: &EmailInfraReport, findings: &mut Vec<EmailInfraFinding>) {
    if report.mx_records.is_empty() {
        findings.push(EmailInfraFinding {
            severity: EmailInfraSeverity::High,
            title: "No MX records found".to_string(),
            description: format!(
                "Domain {} has no MX records, which may indicate misconfiguration or that the domain does not receive email",
                report.domain
            ),
            remediation: "Verify MX record configuration if the domain should receive email".to_string(),
        });
        return;
    }

    let single_ip_mx: Vec<&MxRecord> = report
        .mx_records
        .iter()
        .filter(|mx| mx.ip_addresses.len() <= 1)
        .collect();

    if single_ip_mx.len() == report.mx_records.len() && !report.mx_records.is_empty() {
        findings.push(EmailInfraFinding {
            severity: EmailInfraSeverity::Medium,
            title: "No MX redundancy".to_string(),
            description: "All MX records resolve to single IP addresses with no failover"
                .to_string(),
            remediation: "Add secondary MX records pointing to backup mail servers".to_string(),
        });
    }
}

fn generate_relay_findings(report: &EmailInfraReport, findings: &mut Vec<EmailInfraFinding>) {
    for indicator in &report.open_relay_indicators {
        if indicator.allows_relay {
            findings.push(EmailInfraFinding {
                severity: EmailInfraSeverity::Critical,
                title: format!("Potential open relay: {}", indicator.hostname),
                description: format!(
                    "Mail server {} appears to allow unauthorized relay. {}",
                    indicator.hostname, indicator.evidence
                ),
                remediation: "Restrict SMTP relay to authenticated and authorized senders only"
                    .to_string(),
            });
        }
    }
}

fn generate_spoof_findings(report: &EmailInfraReport, findings: &mut Vec<EmailInfraFinding>) {
    let severity = match report.spoof_feasibility.overall_risk {
        SpoofRisk::Critical => EmailInfraSeverity::Critical,
        SpoofRisk::High => EmailInfraSeverity::High,
        SpoofRisk::Medium => EmailInfraSeverity::Medium,
        SpoofRisk::Low => EmailInfraSeverity::Low,
        SpoofRisk::Minimal => EmailInfraSeverity::Info,
    };

    let weak_factors: Vec<&SpoofFactor> = report
        .spoof_feasibility
        .factors
        .iter()
        .filter(|f| f.present)
        .collect();

    if weak_factors.is_empty() {
        return;
    }

    let descriptions: Vec<String> = weak_factors.iter().map(|f| f.description.clone()).collect();

    findings.push(EmailInfraFinding {
        severity,
        title: format!(
            "Email spoofing risk: {}",
            report.spoof_feasibility.overall_risk
        ),
        description: format!(
            "Spoof feasibility score {:.2}/1.00. Weak factors: {}",
            report.spoof_feasibility.score,
            descriptions.join("; ")
        ),
        remediation: "Deploy SPF with -all, DMARC with p=reject, and enable DKIM signing"
            .to_string(),
    });
}

fn generate_gateway_findings(report: &EmailInfraReport, findings: &mut Vec<EmailInfraFinding>) {
    if report.gateways.is_empty() && !report.mx_records.is_empty() {
        findings.push(EmailInfraFinding {
            severity: EmailInfraSeverity::Low,
            title: "No email security gateway detected".to_string(),
            description:
                "No recognized email security gateway was identified from MX records or headers"
                    .to_string(),
            remediation:
                "Consider deploying an email security gateway for phishing and malware filtering"
                    .to_string(),
        });
        return;
    }

    for detection in &report.gateways {
        findings.push(EmailInfraFinding {
            severity: EmailInfraSeverity::Info,
            title: format!("Email gateway detected: {}", detection.gateway),
            description: format!(
                "{} identified with {:.0}% confidence. Evidence: {}",
                detection.gateway,
                detection.confidence * 100.0,
                detection.evidence.join(", ")
            ),
            remediation: "Verify gateway configuration follows vendor hardening guidelines"
                .to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mx_records_sorts_by_priority() {
        let ips_backup: Vec<&str> = vec!["10.0.0.2"];
        let ips_primary: Vec<&str> = vec!["10.0.0.1"];
        let raw = vec![
            ("backup.example.com", 20u16, ips_backup.as_slice()),
            ("primary.example.com", 10u16, ips_primary.as_slice()),
        ];
        let records = parse_mx_records(&raw);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].priority, 10);
        assert_eq!(records[0].hostname, "primary.example.com");
        assert_eq!(records[1].priority, 20);
    }

    #[test]
    fn parse_mx_records_lowercases_hostnames() {
        let ips: Vec<&str> = vec!["10.0.0.1"];
        let raw = vec![("MX.EXAMPLE.COM", 10u16, ips.as_slice())];
        let records = parse_mx_records(&raw);
        assert_eq!(records[0].hostname, "mx.example.com");
    }

    #[test]
    fn parse_mx_records_empty_input() {
        let records = parse_mx_records(&[]);
        assert!(records.is_empty());
    }

    #[test]
    fn detect_gateway_proofpoint_from_mx() {
        let mx = vec![MxRecord {
            priority: 10,
            hostname: "mx1.pphosted.com".to_string(),
            ip_addresses: vec!["1.2.3.4".to_string()],
        }];
        let detections = detect_email_gateway(&mx, &[]);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].gateway, EmailGateway::Proofpoint);
        assert!(detections[0].confidence >= 0.9);
    }

    #[test]
    fn detect_gateway_microsoft365_from_mx() {
        let mx = vec![MxRecord {
            priority: 10,
            hostname: "contoso-com.mail.protection.outlook.com".to_string(),
            ip_addresses: vec![],
        }];
        let detections = detect_email_gateway(&mx, &[]);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].gateway, EmailGateway::Microsoft365);
    }

    #[test]
    fn detect_gateway_google_from_mx() {
        let mx = vec![MxRecord {
            priority: 10,
            hostname: "aspmx.l.google.com".to_string(),
            ip_addresses: vec![],
        }];
        let detections = detect_email_gateway(&mx, &[]);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].gateway, EmailGateway::GoogleWorkspace);
    }

    #[test]
    fn detect_gateway_from_headers() {
        let mx: Vec<MxRecord> = vec![];
        let headers = vec![("X-Proofpoint-Virus-Version", "vendor=abc")];
        let detections = detect_email_gateway(&mx, &headers);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].gateway, EmailGateway::Proofpoint);
        assert!(detections[0].confidence >= 0.95);
    }

    #[test]
    fn detect_gateway_deduplicates_mx_and_header() {
        let mx = vec![MxRecord {
            priority: 10,
            hostname: "mx1.pphosted.com".to_string(),
            ip_addresses: vec![],
        }];
        let headers = vec![("X-Proofpoint-Spam-Details", "rule=notspam")];
        let detections = detect_email_gateway(&mx, &headers);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].gateway, EmailGateway::Proofpoint);
        assert_eq!(detections[0].evidence.len(), 2);
    }

    #[test]
    fn detect_gateway_mimecast_from_mx() {
        let mx = vec![MxRecord {
            priority: 10,
            hostname: "us-smtp-inbound-1.mimecast.com".to_string(),
            ip_addresses: vec![],
        }];
        let detections = detect_email_gateway(&mx, &[]);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].gateway, EmailGateway::Mimecast);
    }

    #[test]
    fn detect_gateway_barracuda_from_mx() {
        let mx = vec![MxRecord {
            priority: 10,
            hostname: "mail.barracuda.example.com".to_string(),
            ip_addresses: vec![],
        }];
        let detections = detect_email_gateway(&mx, &[]);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].gateway, EmailGateway::Barracuda);
    }

    #[test]
    fn detect_gateway_ironport_from_mx() {
        let mx = vec![MxRecord {
            priority: 10,
            hostname: "mail.iphmx.com".to_string(),
            ip_addresses: vec![],
        }];
        let detections = detect_email_gateway(&mx, &[]);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].gateway, EmailGateway::IronPort);
    }

    #[test]
    fn detect_gateway_messagelabs_from_mx() {
        let mx = vec![MxRecord {
            priority: 10,
            hostname: "cluster1.us.messagelabs.com".to_string(),
            ip_addresses: vec![],
        }];
        let detections = detect_email_gateway(&mx, &[]);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].gateway, EmailGateway::MessageLabs);
    }

    #[test]
    fn detect_gateway_fortimail_from_mx() {
        let mx = vec![MxRecord {
            priority: 10,
            hostname: "gw.fortimail.example.com".to_string(),
            ip_addresses: vec![],
        }];
        let detections = detect_email_gateway(&mx, &[]);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].gateway, EmailGateway::Fortimail);
    }

    #[test]
    fn detect_gateway_none_for_unknown_mx() {
        let mx = vec![MxRecord {
            priority: 10,
            hostname: "mail.custom-corp.example.org".to_string(),
            ip_addresses: vec![],
        }];
        let detections = detect_email_gateway(&mx, &[]);
        assert!(detections.is_empty());
    }

    #[test]
    fn assess_open_relay_positive() {
        let mx = vec![MxRecord {
            priority: 10,
            hostname: "mail.example.com".to_string(),
            ip_addresses: vec![],
        }];
        let banners = vec![(
            "mail.example.com",
            "220 mail.example.com ESMTP - relay access permitted",
        )];
        let indicators = assess_open_relay(&mx, &banners);
        assert_eq!(indicators.len(), 1);
        assert!(indicators[0].allows_relay);
    }

    #[test]
    fn assess_open_relay_negative() {
        let mx = vec![MxRecord {
            priority: 10,
            hostname: "mail.example.com".to_string(),
            ip_addresses: vec![],
        }];
        let banners = vec![("mail.example.com", "550 relay access denied")];
        let indicators = assess_open_relay(&mx, &banners);
        assert_eq!(indicators.len(), 1);
        assert!(!indicators[0].allows_relay);
    }

    #[test]
    fn assess_open_relay_empty_banners() {
        let mx = vec![MxRecord {
            priority: 10,
            hostname: "mail.example.com".to_string(),
            ip_addresses: vec![],
        }];
        let indicators = assess_open_relay(&mx, &[]);
        assert!(indicators.is_empty());
    }

    #[test]
    fn spoof_feasibility_no_protections() {
        let result = calculate_spoof_feasibility(None, None, false, false);
        assert!(result.score >= 0.85);
        assert_eq!(result.overall_risk, SpoofRisk::Critical);
    }

    #[test]
    fn spoof_feasibility_full_protections() {
        let result = calculate_spoof_feasibility(
            Some(SpfQualifier::Fail),
            Some(DmarcPolicy::Reject),
            true,
            true,
        );
        assert!(result.score < 0.01);
        assert_eq!(result.overall_risk, SpoofRisk::Minimal);
    }

    #[test]
    fn spoof_feasibility_spf_pass_means_permissive() {
        let result = calculate_spoof_feasibility(Some(SpfQualifier::Pass), None, true, true);
        assert!(result.score >= 0.3);
    }

    #[test]
    fn spoof_feasibility_softfail_adds_partial_score() {
        let result = calculate_spoof_feasibility(
            Some(SpfQualifier::SoftFail),
            Some(DmarcPolicy::Reject),
            true,
            true,
        );
        assert!((result.score - 0.1).abs() < f64::EPSILON);
        assert_eq!(result.overall_risk, SpoofRisk::Minimal);
    }

    #[test]
    fn spoof_feasibility_dmarc_none_is_weak() {
        let result = calculate_spoof_feasibility(
            Some(SpfQualifier::Fail),
            Some(DmarcPolicy::None),
            true,
            true,
        );
        assert!(result.score >= 0.2);
    }

    #[test]
    fn spoof_risk_boundary_values() {
        assert_eq!(spoof_risk_from_score(0.0), SpoofRisk::Minimal);
        assert_eq!(spoof_risk_from_score(0.19), SpoofRisk::Minimal);
        assert_eq!(spoof_risk_from_score(0.2), SpoofRisk::Low);
        assert_eq!(spoof_risk_from_score(0.4), SpoofRisk::Medium);
        assert_eq!(spoof_risk_from_score(0.6), SpoofRisk::High);
        assert_eq!(spoof_risk_from_score(0.8), SpoofRisk::Critical);
        assert_eq!(spoof_risk_from_score(1.0), SpoofRisk::Critical);
    }

    #[test]
    fn analyze_email_infrastructure_full_pipeline() {
        let ips_mx1: Vec<&str> = vec!["1.2.3.4", "5.6.7.8"];
        let ips_mx2: Vec<&str> = vec!["9.10.11.12"];
        let mx_raw = vec![
            ("mx1.pphosted.com", 10u16, ips_mx1.as_slice()),
            ("mx2.pphosted.com", 20u16, ips_mx2.as_slice()),
        ];
        let headers = vec![("X-Proofpoint-Virus-Version", "vendor=abc")];
        let banners: Vec<(&str, &str)> = vec![];

        let report = analyze_email_infrastructure(
            "example.com",
            &mx_raw,
            &headers,
            &banners,
            Some(SpfQualifier::Fail),
            Some(DmarcPolicy::Reject),
            true,
        );

        assert_eq!(report.domain, "example.com");
        assert_eq!(report.mx_records.len(), 2);
        assert_eq!(report.mx_records[0].priority, 10);
        assert!(!report.gateways.is_empty());
        assert_eq!(report.gateways[0].gateway, EmailGateway::Proofpoint);
        assert!(report.spoof_feasibility.score < 0.01);
        assert!(!report.findings.is_empty());
    }

    #[test]
    fn analyze_email_infrastructure_no_mx() {
        let report =
            analyze_email_infrastructure("no-mail.example.com", &[], &[], &[], None, None, false);

        assert!(report.mx_records.is_empty());
        let has_no_mx_finding = report
            .findings
            .iter()
            .any(|f| f.title.contains("No MX records"));
        assert!(has_no_mx_finding);
    }

    #[test]
    fn generate_findings_open_relay() {
        let report = EmailInfraReport {
            domain: "example.com".to_string(),
            mx_records: vec![MxRecord {
                priority: 10,
                hostname: "mail.example.com".to_string(),
                ip_addresses: vec![],
            }],
            gateways: vec![],
            open_relay_indicators: vec![OpenRelayIndicator {
                hostname: "mail.example.com".to_string(),
                allows_relay: true,
                evidence: "Banner says relay allowed".to_string(),
            }],
            spoof_feasibility: SpoofFeasibility {
                score: 0.0,
                factors: vec![],
                overall_risk: SpoofRisk::Minimal,
            },
            findings: vec![],
        };

        let findings = generate_email_findings(&report);
        let relay_finding = findings.iter().find(|f| f.title.contains("open relay"));
        assert!(relay_finding.is_some());
        assert_eq!(
            relay_finding.unwrap().severity,
            EmailInfraSeverity::Critical
        );
    }

    #[test]
    fn generate_findings_no_gateway() {
        let report = EmailInfraReport {
            domain: "example.com".to_string(),
            mx_records: vec![MxRecord {
                priority: 10,
                hostname: "mail.example.com".to_string(),
                ip_addresses: vec![],
            }],
            gateways: vec![],
            open_relay_indicators: vec![],
            spoof_feasibility: SpoofFeasibility {
                score: 0.0,
                factors: vec![],
                overall_risk: SpoofRisk::Minimal,
            },
            findings: vec![],
        };

        let findings = generate_email_findings(&report);
        let gw_finding = findings
            .iter()
            .find(|f| f.title.contains("No email security gateway"));
        assert!(gw_finding.is_some());
        assert_eq!(gw_finding.unwrap().severity, EmailInfraSeverity::Low);
    }

    #[test]
    fn email_infra_severity_display() {
        assert_eq!(EmailInfraSeverity::Critical.to_string(), "Critical");
        assert_eq!(EmailInfraSeverity::High.to_string(), "High");
        assert_eq!(EmailInfraSeverity::Medium.to_string(), "Medium");
        assert_eq!(EmailInfraSeverity::Low.to_string(), "Low");
        assert_eq!(EmailInfraSeverity::Info.to_string(), "Info");
    }

    #[test]
    fn email_gateway_display() {
        assert_eq!(EmailGateway::Proofpoint.to_string(), "Proofpoint");
        assert_eq!(EmailGateway::Microsoft365.to_string(), "Microsoft 365");
        assert_eq!(
            EmailGateway::Generic("Custom".to_string()).to_string(),
            "Custom"
        );
    }

    #[test]
    fn spoof_risk_display() {
        assert_eq!(SpoofRisk::Critical.to_string(), "Critical");
        assert_eq!(SpoofRisk::Minimal.to_string(), "Minimal");
    }

    #[test]
    fn spoof_feasibility_score_clamped() {
        let result = calculate_spoof_feasibility(
            Some(SpfQualifier::Pass),
            Some(DmarcPolicy::Missing),
            false,
            false,
        );
        assert!(result.score <= 1.0);
        assert!(result.score >= 0.0);
    }

    #[test]
    fn generate_findings_spoof_risk_medium() {
        let report = EmailInfraReport {
            domain: "example.com".to_string(),
            mx_records: vec![MxRecord {
                priority: 10,
                hostname: "mail.example.com".to_string(),
                ip_addresses: vec![],
            }],
            gateways: vec![EmailGatewayDetection {
                gateway: EmailGateway::Proofpoint,
                confidence: 0.95,
                evidence: vec!["MX hostname".to_string()],
            }],
            open_relay_indicators: vec![],
            spoof_feasibility: SpoofFeasibility {
                score: 0.45,
                factors: vec![SpoofFactor {
                    name: "DMARC Policy".to_string(),
                    weight: 0.25,
                    present: true,
                    description: "DMARC set to none".to_string(),
                }],
                overall_risk: SpoofRisk::Medium,
            },
            findings: vec![],
        };

        let findings = generate_email_findings(&report);
        let spoof_finding = findings.iter().find(|f| f.title.contains("spoofing risk"));
        assert!(spoof_finding.is_some());
        assert_eq!(spoof_finding.unwrap().severity, EmailInfraSeverity::Medium);
    }

    #[test]
    fn mx_redundancy_finding_all_single_ip() {
        let report = EmailInfraReport {
            domain: "example.com".to_string(),
            mx_records: vec![
                MxRecord {
                    priority: 10,
                    hostname: "mx1.example.com".to_string(),
                    ip_addresses: vec!["10.0.0.1".to_string()],
                },
                MxRecord {
                    priority: 20,
                    hostname: "mx2.example.com".to_string(),
                    ip_addresses: vec!["10.0.0.2".to_string()],
                },
            ],
            gateways: vec![],
            open_relay_indicators: vec![],
            spoof_feasibility: SpoofFeasibility {
                score: 0.0,
                factors: vec![],
                overall_risk: SpoofRisk::Minimal,
            },
            findings: vec![],
        };

        let findings = generate_email_findings(&report);
        let redundancy_finding = findings
            .iter()
            .find(|f| f.title.contains("No MX redundancy"));
        assert!(redundancy_finding.is_some());
    }
}
