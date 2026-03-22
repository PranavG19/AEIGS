use std::time::Duration;

use aegis_protocol::finding::{Confidence, VulnerabilityClass};
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::util::timestamp_ms;

const INFO_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) const DISCLOSURE_HEADERS: &[&str] = &[
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-varnish",
    "x-debug-token",
    "x-runtime",
];

#[derive(Debug, Clone)]
pub struct DisclosedHeader {
    pub header: String,
    pub value: String,
}

pub fn scan_info_disclosure(target: &str) -> Vec<DisclosedHeader> {
    let domain = match aegis_exploiter::extract_domain(target) {
        Some(d) => d,
        None => return Vec::new(),
    };
    if domain == "localhost" || domain == "127.0.0.1" || domain == "::1" {
        return Vec::new();
    }

    let client = match reqwest::blocking::Client::builder()
        .timeout(INFO_TIMEOUT)
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
    DISCLOSURE_HEADERS
        .iter()
        .filter_map(|name| {
            headers
                .get(*name)
                .and_then(|v| v.to_str().ok())
                .map(|v| DisclosedHeader {
                    header: name.to_string(),
                    value: v.to_string(),
                })
        })
        .collect()
}

pub(crate) fn disclosure_severity(header: &str) -> f64 {
    match header {
        "x-debug-token" => 5.0,
        "x-aspnet-version" | "x-aspnetmvc-version" => 3.5,
        "x-powered-by" | "x-generator" => 3.0,
        "server" => 2.0,
        _ => 2.0,
    }
}

pub fn disclosure_findings_to_operations(
    findings: &[DisclosedHeader],
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
                    vulnerability_class: VulnerabilityClass::InformationDisclosure,
                    severity: disclosure_severity(&f.header),
                    confidence: Confidence::new(0.95).unwrap(),
                    certificate: Vec::new(),
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}
