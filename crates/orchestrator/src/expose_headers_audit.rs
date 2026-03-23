use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ExposeHeaderIssue {
    WildcardExpose,
    AuthorizationExposed,
    ApiKeyExposed { header: String },
    AuthTokenExposed { header: String },
    SetCookieExposed,
    CsrfTokenExposed,
    RequestIdExposed { header: String },
    TraceIdExposed { header: String },
    DebugTokenExposed,
    ServerTimingExposed,
    InternalHeaderExposed { header: String },
    ExcessiveExposure { count: usize },
    CredentialHeaderExposed { header: String },
}

impl std::fmt::Display for ExposeHeaderIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExposeHeaderIssue::WildcardExpose => write!(f, "wildcard_expose"),
            ExposeHeaderIssue::AuthorizationExposed => write!(f, "authorization_exposed"),
            ExposeHeaderIssue::ApiKeyExposed { .. } => write!(f, "api_key_exposed"),
            ExposeHeaderIssue::AuthTokenExposed { .. } => write!(f, "auth_token_exposed"),
            ExposeHeaderIssue::SetCookieExposed => write!(f, "set_cookie_exposed"),
            ExposeHeaderIssue::CsrfTokenExposed => write!(f, "csrf_token_exposed"),
            ExposeHeaderIssue::RequestIdExposed { .. } => write!(f, "request_id_exposed"),
            ExposeHeaderIssue::TraceIdExposed { .. } => write!(f, "trace_id_exposed"),
            ExposeHeaderIssue::DebugTokenExposed => write!(f, "debug_token_exposed"),
            ExposeHeaderIssue::ServerTimingExposed => write!(f, "server_timing_exposed"),
            ExposeHeaderIssue::InternalHeaderExposed { .. } => write!(f, "internal_header_exposed"),
            ExposeHeaderIssue::ExcessiveExposure { .. } => write!(f, "excessive_exposure"),
            ExposeHeaderIssue::CredentialHeaderExposed { .. } => {
                write!(f, "credential_header_exposed")
            }
        }
    }
}

pub fn expose_header_severity(issue: &ExposeHeaderIssue) -> f64 {
    match issue {
        ExposeHeaderIssue::WildcardExpose => 5.0,
        ExposeHeaderIssue::AuthorizationExposed => 7.0,
        ExposeHeaderIssue::ApiKeyExposed { .. } => 6.5,
        ExposeHeaderIssue::AuthTokenExposed { .. } => 6.5,
        ExposeHeaderIssue::SetCookieExposed => 6.0,
        ExposeHeaderIssue::CsrfTokenExposed => 5.0,
        ExposeHeaderIssue::RequestIdExposed { .. } => 3.0,
        ExposeHeaderIssue::TraceIdExposed { .. } => 3.5,
        ExposeHeaderIssue::DebugTokenExposed => 5.0,
        ExposeHeaderIssue::ServerTimingExposed => 3.5,
        ExposeHeaderIssue::InternalHeaderExposed { .. } => 4.0,
        ExposeHeaderIssue::ExcessiveExposure { .. } => 4.5,
        ExposeHeaderIssue::CredentialHeaderExposed { .. } => 6.0,
    }
}

pub fn audit_expose_headers(target: &str) -> Vec<ExposeHeaderIssue> {
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

pub(crate) fn analyze_expose_headers(value: Option<&str>) -> Vec<ExposeHeaderIssue> {
    let Some(v) = value else {
        return Vec::new();
    };

    let exposed: Vec<&str> = v
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    if exposed.is_empty() {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if exposed.contains(&"*") {
        issues.push(ExposeHeaderIssue::WildcardExpose);
        return issues;
    }

    for h in &exposed {
        let lower = h.to_ascii_lowercase();
        match lower.as_str() {
            "authorization" => issues.push(ExposeHeaderIssue::AuthorizationExposed),
            "x-api-key" | "api-key" | "apikey" => {
                issues.push(ExposeHeaderIssue::ApiKeyExposed {
                    header: h.to_string(),
                });
            }
            "x-auth-token" | "x-access-token" => {
                issues.push(ExposeHeaderIssue::AuthTokenExposed {
                    header: h.to_string(),
                });
            }
            "set-cookie" => issues.push(ExposeHeaderIssue::SetCookieExposed),
            "x-csrf-token" => issues.push(ExposeHeaderIssue::CsrfTokenExposed),
            "x-request-id" | "x-amzn-requestid" => {
                issues.push(ExposeHeaderIssue::RequestIdExposed {
                    header: h.to_string(),
                });
            }
            "x-trace-id" => {
                issues.push(ExposeHeaderIssue::TraceIdExposed {
                    header: h.to_string(),
                });
            }
            "x-debug-token" => issues.push(ExposeHeaderIssue::DebugTokenExposed),
            "server-timing" => issues.push(ExposeHeaderIssue::ServerTimingExposed),
            "cookie" | "proxy-authorization" | "www-authenticate" => {
                issues.push(ExposeHeaderIssue::CredentialHeaderExposed {
                    header: h.to_string(),
                });
            }
            _ => {
                if lower.starts_with("x-internal-")
                    || lower.starts_with("x-backend-")
                    || lower.starts_with("x-upstream-")
                {
                    issues.push(ExposeHeaderIssue::InternalHeaderExposed {
                        header: h.to_string(),
                    });
                }
            }
        }
    }

    if exposed.len() >= 10 {
        issues.push(ExposeHeaderIssue::ExcessiveExposure {
            count: exposed.len(),
        });
    }

    issues
}

pub fn expose_headers_to_operations(
    issues: &[ExposeHeaderIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                expose_header_severity(issue),
                0.5,
            )
        })
        .collect()
}
