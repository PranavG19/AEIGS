use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

const DEPRECATED_HEADERS: &[(&str, &str, f64)] = &[
    (
        "expect-ct",
        "Expect-CT is deprecated; Chrome enforces CT by default since 2021",
        1.5,
    ),
    (
        "feature-policy",
        "Feature-Policy is deprecated; use Permissions-Policy instead",
        2.0,
    ),
    (
        "public-key-pins",
        "HPKP is removed from all browsers; causes denial-of-service risk",
        3.0,
    ),
    (
        "public-key-pins-report-only",
        "HPKP-Report-Only is deprecated along with HPKP",
        2.0,
    ),
    (
        "x-xss-protection",
        "X-XSS-Protection is deprecated; causes vulnerabilities in older browsers",
        2.5,
    ),
];

#[derive(Debug, Clone)]
pub struct DeprecatedHeaderIssue {
    pub header: String,
    pub reason: String,
    pub severity: f64,
}

pub fn audit_deprecated_headers(target: &str) -> Vec<DeprecatedHeaderIssue> {
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
    analyze_deprecated_headers(|name| headers.get(name).is_some())
}

pub(crate) fn analyze_deprecated_headers(
    has_header: impl Fn(&str) -> bool,
) -> Vec<DeprecatedHeaderIssue> {
    DEPRECATED_HEADERS
        .iter()
        .filter(|(name, _, _)| has_header(name))
        .map(|(name, reason, severity)| DeprecatedHeaderIssue {
            header: name.to_string(),
            reason: reason.to_string(),
            severity: *severity,
        })
        .collect()
}

pub fn deprecated_header_to_operations(
    issues: &[DeprecatedHeaderIssue],
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
        0.95,
    )]
}
