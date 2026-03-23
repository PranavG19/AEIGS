use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

const SENSITIVE_HEADERS: &[(&str, f64)] = &[
    ("authorization", 7.0),
    ("x-api-key", 6.5),
    ("x-auth-token", 6.5),
    ("set-cookie", 6.0),
    ("x-csrf-token", 5.0),
    ("x-request-id", 3.0),
    ("x-trace-id", 3.5),
    ("x-amzn-requestid", 3.0),
    ("x-debug-token", 5.0),
    ("server-timing", 3.5),
];

#[derive(Debug, Clone)]
pub struct ExposedHeaderIssue {
    pub header: String,
    pub severity: f64,
}

pub fn audit_expose_headers(target: &str) -> Vec<ExposedHeaderIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) =
        recon_client::build_client_limited_redirect(std::time::Duration::from_secs(10), 3)
    else {
        return Vec::new();
    };
    let resp = match client
        .get(target)
        .header("Origin", "https://evil.example.com")
        .send()
    {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let value = resp
        .headers()
        .get("access-control-expose-headers")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    analyze_expose_headers(value.as_deref())
}

pub(crate) fn analyze_expose_headers(value: Option<&str>) -> Vec<ExposedHeaderIssue> {
    let Some(v) = value else {
        return Vec::new();
    };

    let exposed: Vec<&str> = v.split(',').map(|s| s.trim()).collect();

    if exposed.contains(&"*") {
        return vec![ExposedHeaderIssue {
            header: "*".to_string(),
            severity: 5.0,
        }];
    }

    exposed
        .iter()
        .filter_map(|h| {
            let lower = h.to_ascii_lowercase();
            SENSITIVE_HEADERS
                .iter()
                .find(|(name, _)| *name == lower)
                .map(|(_, severity)| ExposedHeaderIssue {
                    header: h.to_string(),
                    severity: *severity,
                })
        })
        .collect()
}

pub fn expose_headers_to_operations(
    issues: &[ExposedHeaderIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let max_severity = issues.iter().map(|i| i.severity).fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::SecurityMisconfiguration,
        max_severity,
        0.85,
    )]
}
