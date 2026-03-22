use std::time::Duration;

use aegis_protocol::finding::{Confidence, VulnerabilityClass};
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::util::timestamp_ms;

const TLS_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct TlsFinding {
    pub issue: TlsIssue,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TlsIssue {
    NoHttps,
    MissingHsts,
    ShortHstsMaxAge,
    InsecureRedirect,
}

pub fn scan_tls(target: &str) -> Vec<TlsFinding> {
    let domain = match aegis_exploiter::extract_domain(target) {
        Some(d) => d,
        None => return Vec::new(),
    };
    if domain == "localhost" || domain == "127.0.0.1" || domain == "::1" {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let https_url = format!("https://{domain}");
    let client = match reqwest::blocking::Client::builder()
        .timeout(TLS_CHECK_TIMEOUT)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(_) => return findings,
    };

    // Check HTTPS availability
    let resp = match client.get(&https_url).send() {
        Ok(r) => r,
        Err(_) => {
            findings.push(TlsFinding {
                issue: TlsIssue::NoHttps,
                detail: format!("{domain} does not respond on HTTPS"),
            });
            return findings;
        }
    };

    // Check HSTS header
    let hsts = resp
        .headers()
        .get("strict-transport-security")
        .and_then(|v| v.to_str().ok().map(String::from));
    match &hsts {
        None => {
            findings.push(TlsFinding {
                issue: TlsIssue::MissingHsts,
                detail: format!("{domain} does not set Strict-Transport-Security"),
            });
        }
        Some(val) => {
            if let Some(max_age) = parse_hsts_max_age(val)
                && max_age < 31_536_000
            {
                findings.push(TlsFinding {
                    issue: TlsIssue::ShortHstsMaxAge,
                    detail: format!("{domain} HSTS max-age={max_age} (recommended: >=31536000)"),
                });
            }
        }
    }

    // Check HTTP→HTTPS redirect
    let http_url = format!("http://{domain}");
    if let Ok(http_resp) = client.get(&http_url).send() {
        let status = http_resp.status().as_u16();
        if !(300..400).contains(&status) {
            findings.push(TlsFinding {
                issue: TlsIssue::InsecureRedirect,
                detail: format!("{domain} HTTP does not redirect to HTTPS (status {status})"),
            });
        } else if let Some(location) = http_resp.headers().get("location")
            && let Ok(loc) = location.to_str()
            && !loc.starts_with("https://")
        {
            findings.push(TlsFinding {
                issue: TlsIssue::InsecureRedirect,
                detail: format!("{domain} HTTP redirects to non-HTTPS: {loc}"),
            });
        }
    }

    findings
}

pub(crate) fn parse_hsts_max_age(header: &str) -> Option<u64> {
    for part in header.split(';') {
        let trimmed = part.trim().to_lowercase();
        if let Some(val) = trimmed.strip_prefix("max-age=") {
            return val.trim().parse().ok();
        }
    }
    None
}

pub fn tls_findings_to_operations(
    findings: &[TlsFinding],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    findings
        .iter()
        .map(|f| {
            *seq += 1;
            let (vuln_class, severity, confidence) = match f.issue {
                TlsIssue::NoHttps => (VulnerabilityClass::WeakCryptography, 7.0, 0.95),
                TlsIssue::MissingHsts => (VulnerabilityClass::MissingSecurityHeader, 5.0, 0.9),
                TlsIssue::ShortHstsMaxAge => (VulnerabilityClass::MissingSecurityHeader, 3.0, 0.85),
                TlsIssue::InsecureRedirect => {
                    (VulnerabilityClass::SecurityMisconfiguration, 5.0, 0.9)
                }
            };
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddFinding {
                    linked_node_ids: vec![],
                    vulnerability_class: vuln_class,
                    severity,
                    confidence: Confidence::new(confidence).unwrap(),
                    certificate: Vec::new(),
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}
