use std::fmt;
use std::time::Duration;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

const REDIRECT_TIMEOUT: Duration = Duration::from_secs(10);

pub const REDIRECT_PARAMS: &[&str] = &[
    "url",
    "redirect",
    "next",
    "return",
    "redir",
    "return_to",
    "redirect_uri",
    "continue",
    "dest",
    "destination",
    "go",
    "target",
    "out",
    "view",
    "login",
    "link",
    "forward",
];

pub const CANARY_URL: &str = "https://evil.example.com";

#[derive(Debug, Clone, PartialEq)]
pub enum RedirectIssue {
    OpenRedirect { param: String, location: String },
    JavascriptRedirect { param: String },
    DataUriRedirect { param: String },
    MetaRefreshRedirect { url: String },
    DoubleEncodedRedirect { param: String },
    RelativePathBypass { param: String, location: String },
    FragmentRedirect { param: String, location: String },
    HttpToHttpsDowngrade { param: String, location: String },
    RedirectChain { param: String, hops: usize },
    HeaderInjection { param: String },
}

impl fmt::Display for RedirectIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenRedirect { param, location } => {
                write!(f, "open_redirect: param={param} location={location}")
            }
            Self::JavascriptRedirect { param } => {
                write!(f, "javascript_redirect: param={param}")
            }
            Self::DataUriRedirect { param } => {
                write!(f, "data_uri_redirect: param={param}")
            }
            Self::MetaRefreshRedirect { url } => {
                write!(f, "meta_refresh_redirect: url={url}")
            }
            Self::DoubleEncodedRedirect { param } => {
                write!(f, "double_encoded_redirect: param={param}")
            }
            Self::RelativePathBypass { param, location } => {
                write!(f, "relative_path_bypass: param={param} location={location}")
            }
            Self::FragmentRedirect { param, location } => {
                write!(f, "fragment_redirect: param={param} location={location}")
            }
            Self::HttpToHttpsDowngrade { param, location } => {
                write!(
                    f,
                    "http_to_https_downgrade: param={param} location={location}"
                )
            }
            Self::RedirectChain { param, hops } => {
                write!(f, "redirect_chain: param={param} hops={hops}")
            }
            Self::HeaderInjection { param } => {
                write!(f, "header_injection: param={param}")
            }
        }
    }
}

pub fn redirect_severity(issue: &RedirectIssue) -> f64 {
    match issue {
        RedirectIssue::OpenRedirect { .. } => 7.0,
        RedirectIssue::JavascriptRedirect { .. } => 8.0,
        RedirectIssue::DataUriRedirect { .. } => 6.0,
        RedirectIssue::MetaRefreshRedirect { .. } => 4.0,
        RedirectIssue::DoubleEncodedRedirect { .. } => 6.5,
        RedirectIssue::RelativePathBypass { .. } => 5.5,
        RedirectIssue::FragmentRedirect { .. } => 4.0,
        RedirectIssue::HttpToHttpsDowngrade { .. } => 3.5,
        RedirectIssue::RedirectChain { .. } => 3.0,
        RedirectIssue::HeaderInjection { .. } => 8.5,
    }
}

pub fn analyze_redirect_location(location: &str, param: &str) -> Vec<RedirectIssue> {
    let mut issues = Vec::new();

    if location.is_empty() {
        return issues;
    }

    let lower = location.to_ascii_lowercase();

    if lower.starts_with("javascript:") {
        issues.push(RedirectIssue::JavascriptRedirect {
            param: param.to_string(),
        });
    }

    if lower.starts_with("data:") {
        issues.push(RedirectIssue::DataUriRedirect {
            param: param.to_string(),
        });
    }

    if lower.contains("%252f") || lower.contains("%2f%2f") {
        issues.push(RedirectIssue::DoubleEncodedRedirect {
            param: param.to_string(),
        });
    }

    if location.starts_with("/\\") || location.starts_with("\\/") {
        issues.push(RedirectIssue::RelativePathBypass {
            param: param.to_string(),
            location: location.to_string(),
        });
    }

    if let Some(fragment) = location.split_once('#').map(|(_, frag)| frag) {
        let frag_lower = fragment.to_ascii_lowercase();
        if frag_lower.starts_with("http://")
            || frag_lower.starts_with("https://")
            || frag_lower.starts_with("//")
        {
            issues.push(RedirectIssue::FragmentRedirect {
                param: param.to_string(),
                location: location.to_string(),
            });
        }
    }

    if lower.starts_with("http://") {
        issues.push(RedirectIssue::HttpToHttpsDowngrade {
            param: param.to_string(),
            location: location.to_string(),
        });
    }

    if is_external_redirect(location) {
        issues.push(RedirectIssue::OpenRedirect {
            param: param.to_string(),
            location: location.to_string(),
        });
    }

    issues
}

pub fn is_external_redirect(location: &str) -> bool {
    location.starts_with("https://evil.example.com")
        || location.starts_with("http://evil.example.com")
        || location.starts_with("//evil.example.com")
}

pub fn scan_redirects(target: &str) -> Vec<RedirectIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::build_client_no_redirect(REDIRECT_TIMEOUT) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    for param in REDIRECT_PARAMS {
        findings.extend(check_redirect_param(&client, target, param));
    }
    findings
}

fn check_redirect_param(
    client: &reqwest::blocking::Client,
    target: &str,
    param: &str,
) -> Vec<RedirectIssue> {
    let separator = if target.contains('?') { '&' } else { '?' };
    let url = format!("{target}{separator}{param}={CANARY_URL}");
    let Ok(resp) = client.get(&url).send() else {
        return Vec::new();
    };
    let status = resp.status().as_u16();
    if !(300..400).contains(&status) {
        return Vec::new();
    }
    let Some(location) = resp.headers().get("location").and_then(|v| v.to_str().ok()) else {
        return Vec::new();
    };
    analyze_redirect_location(location, param)
}

pub fn redirect_findings_to_operations(
    findings: &[RedirectIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    findings
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::OpenRedirect,
                redirect_severity(issue),
                0.5,
            )
        })
        .collect()
}
