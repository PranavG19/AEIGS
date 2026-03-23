use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ProxyHeaderIssueKind {
    ViaProxyLeak,
    AgePresent,
    XCacheHit,
    XForwardedFor,
}

#[derive(Debug, Clone)]
pub struct ProxyHeaderIssue {
    pub kind: ProxyHeaderIssueKind,
    pub detail: String,
    pub severity: f64,
}

const PROXY_HEADERS: &[(&str, ProxyHeaderIssueKind, f64)] = &[
    ("x-cache", ProxyHeaderIssueKind::XCacheHit, 2.0),
    (
        "x-forwarded-for",
        ProxyHeaderIssueKind::XForwardedFor,
        3.0,
    ),
];

pub fn audit_proxy_headers(target: &str) -> Vec<ProxyHeaderIssue> {
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

    let via_values: Vec<String> = resp
        .headers()
        .get_all("via")
        .iter()
        .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
        .collect();

    let has_age = resp.headers().get("age").is_some();

    let extra_headers: Vec<(String, String)> = PROXY_HEADERS
        .iter()
        .filter_map(|(name, _, _)| {
            resp.headers()
                .get(*name)
                .and_then(|v| v.to_str().ok())
                .map(|v| (name.to_string(), v.to_string()))
        })
        .collect();

    analyze_proxy_headers(&via_values, has_age, &extra_headers)
}

pub(crate) fn analyze_proxy_headers(
    via_values: &[String],
    has_age: bool,
    extra_headers: &[(String, String)],
) -> Vec<ProxyHeaderIssue> {
    let mut issues = Vec::new();

    for via in via_values {
        issues.push(ProxyHeaderIssue {
            kind: ProxyHeaderIssueKind::ViaProxyLeak,
            detail: format!("Via header reveals proxy chain: {}", truncate(via, 80)),
            severity: 3.0,
        });
    }

    if has_age {
        issues.push(ProxyHeaderIssue {
            kind: ProxyHeaderIssueKind::AgePresent,
            detail: "Age header reveals caching layer presence and cache timing".into(),
            severity: 1.5,
        });
    }

    for (name, value) in extra_headers {
        let kind = PROXY_HEADERS
            .iter()
            .find(|(n, _, _)| *n == name)
            .map(|(_, k, _)| k.clone())
            .unwrap_or(ProxyHeaderIssueKind::XCacheHit);
        let severity = PROXY_HEADERS
            .iter()
            .find(|(n, _, _)| *n == name)
            .map(|(_, _, s)| *s)
            .unwrap_or(2.0);
        issues.push(ProxyHeaderIssue {
            kind,
            detail: format!("{name}: {}", truncate(value, 60)),
            severity,
        });
    }

    issues
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max.saturating_sub(3)])
    } else {
        s.to_string()
    }
}

pub fn proxy_header_to_operations(
    issues: &[ProxyHeaderIssue],
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
        VulnerabilityClass::InformationDisclosure,
        max_severity,
        0.9,
    )]
}
