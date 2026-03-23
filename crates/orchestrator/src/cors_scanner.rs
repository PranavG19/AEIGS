use std::time::Duration;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

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
    CredentialsWithReflection,
}

impl std::fmt::Display for CorsIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CorsIssue::WildcardOrigin => write!(f, "wildcard_origin"),
            CorsIssue::NullOrigin => write!(f, "null_origin"),
            CorsIssue::ReflectedOrigin => write!(f, "reflected_origin"),
            CorsIssue::ArbitrarySubdomain => write!(f, "arbitrary_subdomain"),
            CorsIssue::CredentialsWithReflection => write!(f, "credentials_with_reflection"),
        }
    }
}

pub fn scan_cors(target: &str) -> Vec<CorsFinding> {
    let Some(domain) = recon_client::validated_domain(target) else {
        return Vec::new();
    };
    let Some(client) = recon_client::build_client_limited_redirect(CORS_TIMEOUT, 3) else {
        return Vec::new();
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
    if let Some((acao, acac)) = fetch_acao_with_creds(&client, target, Some(evil_origin))
        && acao == evil_origin
    {
        findings.push(CorsFinding {
            issue: CorsIssue::ReflectedOrigin,
            acao_value: acao.clone(),
        });
        if acac {
            findings.push(CorsFinding {
                issue: CorsIssue::CredentialsWithReflection,
                acao_value: acao,
            });
        }
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
    fetch_acao_with_creds(client, target, origin).map(|(acao, _)| acao)
}

fn fetch_acao_with_creds(
    client: &reqwest::blocking::Client,
    target: &str,
    origin: Option<&str>,
) -> Option<(String, bool)> {
    let mut req = client.get(target);
    if let Some(o) = origin {
        req = req.header("Origin", o);
    }
    let resp = req.send().ok()?;
    let acao = resp
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())?;
    let acac = resp
        .headers()
        .get("access-control-allow-credentials")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    Some((acao, acac))
}

pub(crate) fn cors_severity(issue: &CorsIssue) -> f64 {
    match issue {
        CorsIssue::CredentialsWithReflection => 8.0,
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
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                cors_severity(&f.issue),
                0.9,
            )
        })
        .collect()
}
