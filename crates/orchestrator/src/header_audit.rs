use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

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

    check_missing_headers(resp.headers())
}

pub(crate) fn check_missing_headers(headers: &reqwest::header::HeaderMap) -> Vec<MissingHeader> {
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
            recon_client::finding_entry(
                seq,
                aegis_protocol::finding::VulnerabilityClass::MissingSecurityHeader,
                f.severity,
                0.95,
            )
        })
        .collect()
}
