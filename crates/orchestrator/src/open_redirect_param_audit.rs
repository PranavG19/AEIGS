use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum OpenRedirectIssue {
    RedirectToExternal { param: String, destination: String },
    RedirectNoValidation { param: String },
    JavascriptSchemeRedirect { param: String },
}

impl std::fmt::Display for OpenRedirectIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RedirectToExternal { param, destination } => {
                write!(f, "open_redirect_external:{param}->{destination}")
            }
            Self::RedirectNoValidation { param } => {
                write!(f, "open_redirect_no_validation:{param}")
            }
            Self::JavascriptSchemeRedirect { param } => {
                write!(f, "javascript_scheme_redirect:{param}")
            }
        }
    }
}

const REDIRECT_PARAMS: &[&str] = &[
    "url",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "next",
    "return",
    "return_to",
    "returnTo",
    "returnUrl",
    "return_url",
    "goto",
    "target",
    "dest",
    "destination",
    "rurl",
    "continue",
    "forward",
    "out",
    "ref",
    "callback",
];

const CANARY_DOMAIN: &str = "https://evil.example.com";
const JS_PAYLOAD: &str = "javascript:alert(1)";

pub fn audit_open_redirect_params(target: &str) -> Vec<OpenRedirectIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) =
        recon_client::build_client_limited_redirect(std::time::Duration::from_secs(10), 0)
    else {
        return Vec::new();
    };

    let mut issues = Vec::new();
    let base = target.trim_end_matches('/');

    for &param in REDIRECT_PARAMS {
        let test_url = format!("{base}?{param}={CANARY_DOMAIN}");
        if let Ok(resp) = client.get(&test_url).send()
            && (300..400).contains(&resp.status().as_u16())
            && let Some(location) = resp.headers().get("location").and_then(|v| v.to_str().ok())
        {
            let loc_lower = location.to_ascii_lowercase();
            if loc_lower.contains("evil.example.com") {
                issues.push(OpenRedirectIssue::RedirectToExternal {
                    param: param.to_string(),
                    destination: location.to_string(),
                });
            }
        }

        let js_url = format!("{base}?{param}={JS_PAYLOAD}");
        if let Ok(resp) = client.get(&js_url).send()
            && let Some(location) = resp.headers().get("location").and_then(|v| v.to_str().ok())
            && location.to_ascii_lowercase().starts_with("javascript:")
        {
            issues.push(OpenRedirectIssue::JavascriptSchemeRedirect {
                param: param.to_string(),
            });
        }
    }

    issues
}

pub fn analyze_redirect_response(
    param: &str,
    status: u16,
    location: Option<&str>,
) -> Vec<OpenRedirectIssue> {
    let mut issues = Vec::new();

    if !(300..400).contains(&status) {
        return issues;
    }

    let Some(loc) = location else {
        return issues;
    };

    let loc_lower = loc.to_ascii_lowercase();

    if loc_lower.contains("evil.example.com") {
        issues.push(OpenRedirectIssue::RedirectToExternal {
            param: param.to_string(),
            destination: loc.to_string(),
        });
    }

    if loc_lower.starts_with("javascript:") {
        issues.push(OpenRedirectIssue::JavascriptSchemeRedirect {
            param: param.to_string(),
        });
    }

    if (loc_lower.starts_with("//")
        || loc_lower.starts_with("http://")
        || loc_lower.starts_with("https://"))
        && !loc_lower.contains("evil.example.com")
    {
        issues.push(OpenRedirectIssue::RedirectNoValidation {
            param: param.to_string(),
        });
    }

    issues
}

pub(crate) fn open_redirect_severity(issue: &OpenRedirectIssue) -> f64 {
    match issue {
        OpenRedirectIssue::JavascriptSchemeRedirect { .. } => 8.0,
        OpenRedirectIssue::RedirectToExternal { .. } => 7.0,
        OpenRedirectIssue::RedirectNoValidation { .. } => 5.0,
    }
}

pub fn open_redirect_to_operations(
    issues: &[OpenRedirectIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::OpenRedirect,
                open_redirect_severity(issue),
                0.9,
            )
        })
        .collect()
}
