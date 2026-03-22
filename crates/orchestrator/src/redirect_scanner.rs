use std::time::Duration;

use aegis_protocol::finding::{Confidence, VulnerabilityClass};
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::util::timestamp_ms;

const REDIRECT_TIMEOUT: Duration = Duration::from_secs(10);

const REDIRECT_PARAMS: &[&str] = &[
    "url", "redirect", "next", "return", "redir", "return_to", "redirect_uri", "continue", "dest",
    "destination", "go", "target", "out", "view", "login", "link", "forward",
];

const CANARY_URL: &str = "https://evil.example.com";

#[derive(Debug, Clone)]
pub struct OpenRedirect {
    pub param: String,
    pub redirected_to: String,
}

pub fn scan_redirects(target: &str) -> Vec<OpenRedirect> {
    let domain = match aegis_exploiter::extract_domain(target) {
        Some(d) => d,
        None => return Vec::new(),
    };
    if domain == "localhost" || domain == "127.0.0.1" || domain == "::1" {
        return Vec::new();
    }

    let client = match reqwest::blocking::Client::builder()
        .timeout(REDIRECT_TIMEOUT)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
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
        .map(|_f| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddFinding {
                    linked_node_ids: vec![],
                    vulnerability_class: VulnerabilityClass::OpenRedirect,
                    severity: 5.0,
                    confidence: Confidence::new(0.9).unwrap(),
                    certificate: Vec::new(),
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}
