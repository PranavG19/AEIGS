use std::process::Command;

use aegis_protocol::finding::{Confidence, VulnerabilityClass};
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::util::timestamp_ms;

#[derive(Debug, Clone, PartialEq)]
pub enum EmailIssue {
    MissingSpf,
    WeakSpf,
    MissingDmarc,
    WeakDmarc,
    MissingDkim,
}

impl std::fmt::Display for EmailIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmailIssue::MissingSpf => write!(f, "missing_spf"),
            EmailIssue::WeakSpf => write!(f, "weak_spf"),
            EmailIssue::MissingDmarc => write!(f, "missing_dmarc"),
            EmailIssue::WeakDmarc => write!(f, "weak_dmarc"),
            EmailIssue::MissingDkim => write!(f, "missing_dkim"),
        }
    }
}

pub fn check_email_security(target: &str) -> Vec<EmailIssue> {
    let domain = match aegis_exploiter::extract_domain(target) {
        Some(d) => d,
        None => return Vec::new(),
    };
    if domain == "localhost" || domain == "127.0.0.1" || domain == "::1" {
        return Vec::new();
    }

    let mut issues = Vec::new();
    let txt_records = query_txt(&domain);
    issues.extend(check_spf_issues(&txt_records));

    let dmarc_records = query_txt(&format!("_dmarc.{domain}"));
    issues.extend(check_dmarc_issues(&dmarc_records));

    let dkim_records = query_txt(&format!("default._domainkey.{domain}"));
    if dkim_records.is_empty() {
        issues.push(EmailIssue::MissingDkim);
    }

    issues
}

fn query_txt(domain: &str) -> Vec<String> {
    let output = Command::new("dig")
        .args(["+short", "+time=3", "+tries=1", domain, "TXT"])
        .output();
    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|l| l.trim().trim_matches('"').to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

pub(crate) fn check_spf_issues(txt_records: &[String]) -> Vec<EmailIssue> {
    let spf = txt_records.iter().find(|r| r.starts_with("v=spf1"));
    match spf {
        None => vec![EmailIssue::MissingSpf],
        Some(record) if record.contains("+all") || record.contains("?all") => {
            vec![EmailIssue::WeakSpf]
        }
        Some(_) => vec![],
    }
}

pub(crate) fn check_dmarc_issues(txt_records: &[String]) -> Vec<EmailIssue> {
    let dmarc = txt_records.iter().find(|r| r.starts_with("v=DMARC1"));
    match dmarc {
        None => vec![EmailIssue::MissingDmarc],
        Some(record) if record.contains("p=none") => vec![EmailIssue::WeakDmarc],
        Some(_) => vec![],
    }
}

pub(crate) fn email_severity(issue: &EmailIssue) -> f64 {
    match issue {
        EmailIssue::WeakSpf => 5.0,
        EmailIssue::WeakDmarc => 4.5,
        EmailIssue::MissingSpf => 4.0,
        EmailIssue::MissingDmarc => 3.5,
        EmailIssue::MissingDkim => 3.0,
    }
}

pub fn email_findings_to_operations(
    issues: &[EmailIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddFinding {
                    linked_node_ids: vec![],
                    vulnerability_class: VulnerabilityClass::SecurityMisconfiguration,
                    severity: email_severity(issue),
                    confidence: Confidence::new(0.9).unwrap(),
                    certificate: Vec::new(),
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}
