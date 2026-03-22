use std::time::Duration;

use aegis_protocol::finding::{Confidence, VulnerabilityClass};
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::util::timestamp_ms;

const CORS_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct CorsFinding {
    pub issue: CorsIssue,
    pub acao_value: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CorsIssue {
    WildcardOrigin,
    NullOrigin,
    ReflectedOrigin,
    ArbitrarySubdomain,
}

impl std::fmt::Display for CorsIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CorsIssue::WildcardOrigin => write!(f, "wildcard_origin"),
            CorsIssue::NullOrigin => write!(f, "null_origin"),
            CorsIssue::ReflectedOrigin => write!(f, "reflected_origin"),
            CorsIssue::ArbitrarySubdomain => write!(f, "arbitrary_subdomain"),
        }
    }
}

pub fn scan_cors(target: &str) -> Vec<CorsFinding> {
    let domain = match aegis_exploiter::extract_domain(target) {
        Some(d) => d,
        None => return Vec::new(),
    };
    if domain == "localhost" || domain == "127.0.0.1" || domain == "::1" {
        return Vec::new();
    }

    let client = match reqwest::blocking::Client::builder()
        .timeout(CORS_TIMEOUT)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut findings = Vec::new();

    if let Some(acao) = fetch_acao(&client, target, None)
        && acao == "*"
    {
        findings.push(CorsFinding {
            issue: CorsIssue::WildcardOrigin,
            acao_value: acao,
        });
    }

    if let Some(acao) = fetch_acao(&client, target, Some("null"))
        && acao == "null"
    {
        findings.push(CorsFinding {
            issue: CorsIssue::NullOrigin,
            acao_value: acao,
        });
    }

    let evil_origin = "https://evil.example.com";
    if let Some(acao) = fetch_acao(&client, target, Some(evil_origin))
        && acao == evil_origin
    {
        findings.push(CorsFinding {
            issue: CorsIssue::ReflectedOrigin,
            acao_value: acao,
        });
    }

    let subdomain_origin = format!("https://evil.{domain}");
    if let Some(acao) = fetch_acao(&client, target, Some(&subdomain_origin))
        && acao == subdomain_origin
    {
        findings.push(CorsFinding {
            issue: CorsIssue::ArbitrarySubdomain,
            acao_value: acao,
        });
    }

    findings
}

fn fetch_acao(
    client: &reqwest::blocking::Client,
    target: &str,
    origin: Option<&str>,
) -> Option<String> {
    let mut req = client.get(target);
    if let Some(o) = origin {
        req = req.header("Origin", o);
    }
    let resp = req.send().ok()?;
    resp.headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
}

pub(crate) fn cors_severity(issue: &CorsIssue) -> f64 {
    match issue {
        CorsIssue::ReflectedOrigin => 7.0,
        CorsIssue::NullOrigin => 6.0,
        CorsIssue::ArbitrarySubdomain => 5.5,
        CorsIssue::WildcardOrigin => 4.0,
    }
}

pub fn cors_findings_to_operations(
    findings: &[CorsFinding],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    findings
        .iter()
        .map(|f| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddFinding {
                    linked_node_ids: vec![],
                    vulnerability_class: VulnerabilityClass::SecurityMisconfiguration,
                    severity: cors_severity(&f.issue),
                    confidence: Confidence::new(0.9).unwrap(),
                    certificate: Vec::new(),
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}
