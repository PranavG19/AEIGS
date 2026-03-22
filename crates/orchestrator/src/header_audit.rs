use std::time::Duration;

use aegis_protocol::finding::{Confidence, VulnerabilityClass};
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::util::timestamp_ms;

const HEADER_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) const SECURITY_HEADERS: &[(&str, f64)] = &[
    ("content-security-policy", 6.0),
    ("x-frame-options", 4.0),
    ("x-content-type-options", 3.0),
    ("referrer-policy", 2.0),
    ("permissions-policy", 2.0),
];

#[derive(Debug, Clone)]
pub struct MissingHeader {
    pub header: String,
    pub severity: f64,
}

pub fn audit_security_headers(target: &str) -> Vec<MissingHeader> {
    let domain = match aegis_exploiter::extract_domain(target) {
        Some(d) => d,
        None => return Vec::new(),
    };
    if domain == "localhost" || domain == "127.0.0.1" || domain == "::1" {
        return Vec::new();
    }

    let client = match reqwest::blocking::Client::builder()
        .timeout(HEADER_CHECK_TIMEOUT)
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let resp = match client.get(target).send() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let headers = resp.headers();
    SECURITY_HEADERS
        .iter()
        .filter(|(name, _)| headers.get(*name).is_none())
        .map(|(name, severity)| MissingHeader {
            header: name.to_string(),
            severity: *severity,
        })
        .collect()
}

pub fn header_findings_to_operations(
    findings: &[MissingHeader],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    findings
        .iter()
        .map(|f| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddFinding {
                    linked_node_ids: vec![],
                    vulnerability_class: VulnerabilityClass::MissingSecurityHeader,
                    severity: f.severity,
                    confidence: Confidence::new(0.95).unwrap(),
                    certificate: Vec::new(),
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}
