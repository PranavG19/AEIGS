use std::process::Command;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

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
    let Some(domain) = recon_client::validated_domain(target) else {
        return Vec::new();
    };

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

pub fn check_spf_issues(txt_records: &[String]) -> Vec<EmailIssue> {
    let spf = txt_records.iter().find(|r| r.starts_with("v=spf1"));
    match spf {
        None => vec![EmailIssue::MissingSpf],
        Some(record) if record.contains("+all") || record.contains("?all") => {
            vec![EmailIssue::WeakSpf]
        }
        Some(_) => vec![],
    }
}

pub fn check_dmarc_issues(txt_records: &[String]) -> Vec<EmailIssue> {
    let dmarc = txt_records.iter().find(|r| r.starts_with("v=DMARC1"));
    match dmarc {
        None => vec![EmailIssue::MissingDmarc],
        Some(record) if record.contains("p=none") => vec![EmailIssue::WeakDmarc],
        Some(_) => vec![],
    }
}

pub fn email_severity(issue: &EmailIssue) -> f64 {
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
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                email_severity(issue),
                0.9,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum EmailSecurityIssue {
    MissingSpf,
    WeakSpf { record: String },
    SpfTooManyLookups { count: usize },
    SpfAllMechanism { mechanism: String },
    MissingDmarc,
    WeakDmarc { policy: String },
    DmarcNoReporting,
    DmarcSubdomainWeak { policy: String },
    MissingDkim,
    MultipleDkimSelectors { count: usize },
    MissingMtaSts,
    MissingTlsRpt,
}

impl std::fmt::Display for EmailSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmailSecurityIssue::MissingSpf => write!(f, "missing_spf"),
            EmailSecurityIssue::WeakSpf { record } => write!(f, "weak_spf: {}", record),
            EmailSecurityIssue::SpfTooManyLookups { count } => {
                write!(f, "spf_too_many_lookups: {}", count)
            }
            EmailSecurityIssue::SpfAllMechanism { mechanism } => {
                write!(f, "spf_all_mechanism: {}", mechanism)
            }
            EmailSecurityIssue::MissingDmarc => write!(f, "missing_dmarc"),
            EmailSecurityIssue::WeakDmarc { policy } => write!(f, "weak_dmarc: {}", policy),
            EmailSecurityIssue::DmarcNoReporting => write!(f, "dmarc_no_reporting"),
            EmailSecurityIssue::DmarcSubdomainWeak { policy } => {
                write!(f, "dmarc_subdomain_weak: {}", policy)
            }
            EmailSecurityIssue::MissingDkim => write!(f, "missing_dkim"),
            EmailSecurityIssue::MultipleDkimSelectors { count } => {
                write!(f, "multiple_dkim_selectors: {}", count)
            }
            EmailSecurityIssue::MissingMtaSts => write!(f, "missing_mta_sts"),
            EmailSecurityIssue::MissingTlsRpt => write!(f, "missing_tls_rpt"),
        }
    }
}

pub fn email_security_severity(issue: &EmailSecurityIssue) -> f64 {
    match issue {
        EmailSecurityIssue::SpfAllMechanism { mechanism } => {
            if mechanism == "+all" {
                7.0
            } else {
                5.5
            }
        }
        EmailSecurityIssue::WeakDmarc { .. } => 5.5,
        EmailSecurityIssue::WeakSpf { .. } => 5.0,
        EmailSecurityIssue::DmarcSubdomainWeak { .. } => 5.0,
        EmailSecurityIssue::MissingSpf => 4.5,
        EmailSecurityIssue::MissingDmarc => 4.0,
        EmailSecurityIssue::DmarcNoReporting => 3.5,
        EmailSecurityIssue::SpfTooManyLookups { .. } => 3.5,
        EmailSecurityIssue::MissingDkim => 3.0,
        EmailSecurityIssue::MissingMtaSts => 2.5,
        EmailSecurityIssue::MultipleDkimSelectors { .. } => 2.0,
        EmailSecurityIssue::MissingTlsRpt => 2.0,
    }
}

pub fn analyze_email_records(
    txt_records: &[String],
    dmarc_records: &[String],
    dkim_records: &[String],
) -> Vec<EmailSecurityIssue> {
    let mut issues = Vec::new();

    let spf = txt_records.iter().find(|r| r.starts_with("v=spf1"));
    match spf {
        None => issues.push(EmailSecurityIssue::MissingSpf),
        Some(record) => {
            if record.contains("+all") {
                issues.push(EmailSecurityIssue::SpfAllMechanism {
                    mechanism: "+all".to_string(),
                });
                issues.push(EmailSecurityIssue::WeakSpf {
                    record: record.clone(),
                });
            } else if record.contains("?all") {
                issues.push(EmailSecurityIssue::SpfAllMechanism {
                    mechanism: "?all".to_string(),
                });
                issues.push(EmailSecurityIssue::WeakSpf {
                    record: record.clone(),
                });
            } else if record.contains("~all") {
                issues.push(EmailSecurityIssue::WeakSpf {
                    record: record.clone(),
                });
            }
            let lookup_count = record.matches("include:").count()
                + record.matches("a:").count()
                + record.matches("mx:").count()
                + record.matches("redirect=").count();
            if lookup_count > 10 {
                issues.push(EmailSecurityIssue::SpfTooManyLookups {
                    count: lookup_count,
                });
            }
        }
    }

    let dmarc = dmarc_records.iter().find(|r| r.starts_with("v=DMARC1"));
    match dmarc {
        None => issues.push(EmailSecurityIssue::MissingDmarc),
        Some(record) => {
            if record.contains("p=none") {
                issues.push(EmailSecurityIssue::WeakDmarc {
                    policy: "none".to_string(),
                });
            }
            if !record.contains("rua=") && !record.contains("ruf=") {
                issues.push(EmailSecurityIssue::DmarcNoReporting);
            }
            if record.contains("sp=none") {
                issues.push(EmailSecurityIssue::DmarcSubdomainWeak {
                    policy: "none".to_string(),
                });
            }
        }
    }

    if dkim_records.is_empty() {
        issues.push(EmailSecurityIssue::MissingDkim);
    } else if dkim_records.len() > 1 {
        issues.push(EmailSecurityIssue::MultipleDkimSelectors {
            count: dkim_records.len(),
        });
    }

    let has_mta_sts = txt_records.iter().any(|r| r.starts_with("v=STSv1"));
    if !has_mta_sts {
        issues.push(EmailSecurityIssue::MissingMtaSts);
    }

    let has_tls_rpt = txt_records.iter().any(|r| r.starts_with("v=TLSRPTv1"));
    if !has_tls_rpt {
        issues.push(EmailSecurityIssue::MissingTlsRpt);
    }

    issues
}

pub fn email_security_to_operations(
    issues: &[EmailSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                email_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
