use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

const DANGEROUS_METHODS: &[&str] = &["PUT", "DELETE", "TRACE", "CONNECT"];

#[derive(Debug, Clone)]
pub struct MethodResult {
    pub allowed_methods: Vec<String>,
    pub dangerous_methods: Vec<String>,
}

pub fn scan_methods(target: &str) -> Option<MethodResult> {
    recon_client::validated_domain(target)?;
    let client = recon_client::default_client()?;

    let resp = client
        .request(reqwest::Method::OPTIONS, target)
        .send()
        .ok()?;

    let allow_header = resp.headers().get("allow").and_then(|v| v.to_str().ok())?;

    Some(parse_allow_header(allow_header))
}

pub(crate) fn parse_allow_header(header: &str) -> MethodResult {
    let allowed: Vec<String> = header
        .split(',')
        .map(|m| m.trim().to_uppercase())
        .filter(|m| !m.is_empty())
        .collect();
    let dangerous: Vec<String> = allowed
        .iter()
        .filter(|m| DANGEROUS_METHODS.contains(&m.as_str()))
        .cloned()
        .collect();
    MethodResult {
        allowed_methods: allowed,
        dangerous_methods: dangerous,
    }
}

pub fn method_findings_to_operations(
    result: &MethodResult,
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if result.dangerous_methods.is_empty() {
        return Vec::new();
    }
    let severity = result
        .dangerous_methods
        .iter()
        .map(|m| match m.as_str() {
            "TRACE" => 5.0,
            "PUT" => 4.5,
            "DELETE" => 4.5,
            "CONNECT" => 4.0,
            _ => 3.0,
        })
        .fold(0.0_f64, f64::max);
    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::SecurityMisconfiguration,
        severity,
        0.8,
    )]
}
