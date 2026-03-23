use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone)]
pub struct SourceMapHeaderIssue {
    pub url: String,
}

pub fn audit_sourcemap_header(target: &str) -> Vec<SourceMapHeaderIssue> {
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

    let sm_value = resp
        .headers()
        .get("sourcemap")
        .or_else(|| resp.headers().get("x-sourcemap"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    analyze_sourcemap_header(sm_value.as_deref())
}

pub(crate) fn analyze_sourcemap_header(value: Option<&str>) -> Vec<SourceMapHeaderIssue> {
    let Some(url) = value else {
        return Vec::new();
    };
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    vec![SourceMapHeaderIssue {
        url: trimmed.to_string(),
    }]
}

pub fn sourcemap_header_to_operations(
    issues: &[SourceMapHeaderIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::InformationDisclosure,
        5.0,
        0.95,
    )]
}
