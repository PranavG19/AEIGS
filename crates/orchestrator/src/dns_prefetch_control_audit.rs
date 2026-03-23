use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone)]
pub struct DnsPrefetchControlIssue {
    pub value: String,
    pub severity: f64,
}

pub fn audit_dns_prefetch_control(target: &str) -> Vec<DnsPrefetchControlIssue> {
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

    let value = resp
        .headers()
        .get("x-dns-prefetch-control")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    analyze_dns_prefetch_control(value.as_deref())
}

pub(crate) fn analyze_dns_prefetch_control(value: Option<&str>) -> Vec<DnsPrefetchControlIssue> {
    let Some(val) = value else {
        return Vec::new();
    };

    let lower = val.trim().to_ascii_lowercase();

    if lower == "on" {
        return vec![DnsPrefetchControlIssue {
            value: val.to_string(),
            severity: 2.5,
        }];
    }

    if lower != "off" && lower != "on" {
        return vec![DnsPrefetchControlIssue {
            value: val.to_string(),
            severity: 1.5,
        }];
    }

    Vec::new()
}

pub fn dns_prefetch_control_to_operations(
    issues: &[DnsPrefetchControlIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let max_severity = issues
        .iter()
        .map(|i| i.severity)
        .fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::SecurityMisconfiguration,
        max_severity,
        0.9,
    )]
}
