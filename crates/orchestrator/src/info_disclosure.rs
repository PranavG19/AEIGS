use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

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
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
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
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                disclosure_severity(&f.header),
                0.95,
            )
        })
        .collect()
}
