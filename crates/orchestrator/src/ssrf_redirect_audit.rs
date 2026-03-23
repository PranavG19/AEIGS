use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum SsrfRedirectIssue {
    RedirectToPrivateIp { location: String },
    RedirectToLocalhost { location: String },
    RedirectToMetadata { location: String },
}

impl std::fmt::Display for SsrfRedirectIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RedirectToPrivateIp { location } => {
                write!(f, "ssrf_redirect_private_ip:{location}")
            }
            Self::RedirectToLocalhost { location } => {
                write!(f, "ssrf_redirect_localhost:{location}")
            }
            Self::RedirectToMetadata { location } => {
                write!(f, "ssrf_redirect_metadata:{location}")
            }
        }
    }
}

const REDIRECT_TEST_PARAMS: &[&str] = &["url", "redirect", "next", "return", "dest", "uri"];
const SSRF_TARGETS: &[(&str, SsrfTargetKind)] = &[
    ("http://127.0.0.1/", SsrfTargetKind::Localhost),
    ("http://localhost/", SsrfTargetKind::Localhost),
    ("http://[::1]/", SsrfTargetKind::Localhost),
    ("http://169.254.169.254/latest/meta-data/", SsrfTargetKind::Metadata),
    ("http://metadata.google.internal/", SsrfTargetKind::Metadata),
    ("http://10.0.0.1/", SsrfTargetKind::PrivateIp),
    ("http://192.168.1.1/", SsrfTargetKind::PrivateIp),
    ("http://172.16.0.1/", SsrfTargetKind::PrivateIp),
];

#[derive(Debug, Clone, Copy, PartialEq)]
enum SsrfTargetKind {
    Localhost,
    Metadata,
    PrivateIp,
}

pub fn audit_ssrf_redirect(target: &str) -> Vec<SsrfRedirectIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client_no_redirect() else {
        return Vec::new();
    };

    let base = target.trim_end_matches('/');
    let mut issues = Vec::new();

    for param in REDIRECT_TEST_PARAMS {
        for (ssrf_url, kind) in SSRF_TARGETS {
            let separator = if base.contains('?') { '&' } else { '?' };
            let url = format!("{base}{separator}{param}={ssrf_url}");

            if let Ok(resp) = client.get(&url).send() {
                let status = resp.status().as_u16();
                if !(300..400).contains(&status) {
                    continue;
                }
                if let Some(location) = resp
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    && let Some(issue) = classify_redirect(location, *kind)
                {
                    issues.push(issue);
                    break;
                }
            }
        }
    }

    issues
}

fn classify_redirect(location: &str, kind: SsrfTargetKind) -> Option<SsrfRedirectIssue> {
    let loc = location.to_string();
    if !is_internal_target(location) {
        return None;
    }
    match kind {
        SsrfTargetKind::Localhost => Some(SsrfRedirectIssue::RedirectToLocalhost { location: loc }),
        SsrfTargetKind::Metadata => Some(SsrfRedirectIssue::RedirectToMetadata { location: loc }),
        SsrfTargetKind::PrivateIp => {
            Some(SsrfRedirectIssue::RedirectToPrivateIp { location: loc })
        }
    }
}

pub(crate) fn is_internal_target(location: &str) -> bool {
    let lower = location.to_ascii_lowercase();
    lower.contains("127.0.0.1")
        || lower.contains("localhost")
        || lower.contains("[::1]")
        || lower.contains("169.254.169.254")
        || lower.contains("metadata.google.internal")
        || lower.contains("10.0.0.")
        || lower.contains("192.168.")
        || lower.contains("172.16.")
}

#[cfg(test)]
pub(crate) fn analyze_redirect_location(
    location: &str,
    kind_str: &str,
) -> Option<SsrfRedirectIssue> {
    let kind = match kind_str {
        "localhost" => SsrfTargetKind::Localhost,
        "metadata" => SsrfTargetKind::Metadata,
        "private" => SsrfTargetKind::PrivateIp,
        _ => return None,
    };
    classify_redirect(location, kind)
}

pub(crate) fn ssrf_redirect_severity(issue: &SsrfRedirectIssue) -> f64 {
    match issue {
        SsrfRedirectIssue::RedirectToMetadata { .. } => 9.5,
        SsrfRedirectIssue::RedirectToLocalhost { .. } => 8.0,
        SsrfRedirectIssue::RedirectToPrivateIp { .. } => 7.5,
    }
}

pub fn ssrf_redirect_to_operations(
    issues: &[SsrfRedirectIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::ServerSideRequestForgery,
                ssrf_redirect_severity(issue),
                0.85,
            )
        })
        .collect()
}
