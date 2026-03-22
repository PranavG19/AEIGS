use std::time::Duration;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

const REDIRECT_TIMEOUT: Duration = Duration::from_secs(10);

const REDIRECT_PARAMS: &[&str] = &[
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

const CANARY_URL: &str = "https://evil.example.com";

#[derive(Debug, Clone)]
pub struct OpenRedirect {
    pub param: String,
    pub redirected_to: String,
}

pub fn scan_redirects(target: &str) -> Vec<OpenRedirect> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::build_client_no_redirect(REDIRECT_TIMEOUT) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    for param in REDIRECT_PARAMS {
        if let Some(redirect) = check_redirect_param(&client, target, param) {
            findings.push(redirect);
        }
    }
    findings
}

fn check_redirect_param(
    client: &reqwest::blocking::Client,
    target: &str,
    param: &str,
) -> Option<OpenRedirect> {
    let separator = if target.contains('?') { '&' } else { '?' };
    let url = format!("{target}{separator}{param}={CANARY_URL}");
    let resp = client.get(&url).send().ok()?;
    let status = resp.status().as_u16();
    if !(300..400).contains(&status) {
        return None;
    }
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())?;
    if is_external_redirect(location) {
        Some(OpenRedirect {
            param: param.to_string(),
            redirected_to: location.to_string(),
        })
    } else {
        None
    }
}

pub(crate) fn is_external_redirect(location: &str) -> bool {
    location.starts_with("https://evil.example.com")
        || location.starts_with("http://evil.example.com")
        || location.starts_with("//evil.example.com")
}

pub fn redirect_findings_to_operations(
    findings: &[OpenRedirect],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    findings
        .iter()
        .map(|_f| recon_client::finding_entry(seq, VulnerabilityClass::OpenRedirect, 5.0, 0.9))
        .collect()
}
