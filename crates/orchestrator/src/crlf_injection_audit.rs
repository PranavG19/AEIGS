use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum CrlfIssue {
    HeaderInjection { parameter: String },
    ResponseSplitting { parameter: String },
    EncodedCrlf { parameter: String, encoding: String },
    UnicodeCrlf { parameter: String },
    SetCookieInjection { parameter: String },
    LocationHeaderInjection { parameter: String },
    ContentTypeInjection { parameter: String },
    CrlfInUserAgent,
    PartialHeaderInjection { parameter: String },
}

impl std::fmt::Display for CrlfIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeaderInjection { parameter } => {
                write!(f, "crlf_header_injection:{parameter}")
            }
            Self::ResponseSplitting { parameter } => {
                write!(f, "crlf_response_splitting:{parameter}")
            }
            Self::EncodedCrlf {
                parameter,
                encoding,
            } => {
                write!(f, "crlf_encoded:{parameter}:{encoding}")
            }
            Self::UnicodeCrlf { parameter } => {
                write!(f, "crlf_unicode:{parameter}")
            }
            Self::SetCookieInjection { parameter } => {
                write!(f, "crlf_set_cookie_injection:{parameter}")
            }
            Self::LocationHeaderInjection { parameter } => {
                write!(f, "crlf_location_header_injection:{parameter}")
            }
            Self::ContentTypeInjection { parameter } => {
                write!(f, "crlf_content_type_injection:{parameter}")
            }
            Self::CrlfInUserAgent => {
                write!(f, "crlf_in_user_agent")
            }
            Self::PartialHeaderInjection { parameter } => {
                write!(f, "crlf_partial_header_injection:{parameter}")
            }
        }
    }
}

const CRLF_CANARY_HEADER: &str = "X-Aegis-Crlf-Test";
const CRLF_CANARY_VALUE: &str = "canary123";

const CRLF_PAYLOADS: &[&str] = &[
    "%0d%0aX-Aegis-Crlf-Test:canary123",
    "%0aX-Aegis-Crlf-Test:canary123",
    "\r\nX-Aegis-Crlf-Test:canary123",
    "%E5%98%8A%E5%98%8DX-Aegis-Crlf-Test:canary123",
];

const TEST_PARAMS: &[&str] = &["url", "redirect", "next", "return", "path", "q"];

pub fn audit_crlf(target: &str) -> Vec<CrlfIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client_no_redirect() else {
        return Vec::new();
    };

    let mut issues = Vec::new();

    for param in TEST_PARAMS {
        for payload in CRLF_PAYLOADS {
            let test_url = format!("{target}?{param}={payload}");
            if let Ok(resp) = client.get(&test_url).send() {
                let found = resp
                    .headers()
                    .get(CRLF_CANARY_HEADER)
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.contains(CRLF_CANARY_VALUE))
                    .unwrap_or(false);
                if found {
                    issues.push(CrlfIssue::HeaderInjection {
                        parameter: param.to_string(),
                    });
                    break;
                }
                if let Ok(body) = resp.text()
                    && body.contains(&format!("{CRLF_CANARY_HEADER}:{CRLF_CANARY_VALUE}"))
                {
                    issues.push(CrlfIssue::ResponseSplitting {
                        parameter: param.to_string(),
                    });
                    break;
                }
            }
        }
    }

    issues
}

pub fn analyze_crlf_response(
    resp_headers: &[(String, String)],
    body: &str,
    parameter: &str,
) -> Vec<CrlfIssue> {
    let mut issues = Vec::new();

    let mut has_canary_header = false;
    for (name, value) in resp_headers {
        if name.eq_ignore_ascii_case(CRLF_CANARY_HEADER) && value.contains(CRLF_CANARY_VALUE) {
            has_canary_header = true;
            issues.push(CrlfIssue::HeaderInjection {
                parameter: parameter.to_string(),
            });
            break;
        }
    }

    if !has_canary_header
        && body.contains(&format!("{CRLF_CANARY_HEADER}:{CRLF_CANARY_VALUE}"))
    {
        issues.push(CrlfIssue::ResponseSplitting {
            parameter: parameter.to_string(),
        });
    }

    for (name, value) in resp_headers {
        if name.eq_ignore_ascii_case("set-cookie") && value.contains(CRLF_CANARY_VALUE) {
            issues.push(CrlfIssue::SetCookieInjection {
                parameter: parameter.to_string(),
            });
            break;
        }
    }

    for (name, value) in resp_headers {
        if name.eq_ignore_ascii_case("location") && value.contains(CRLF_CANARY_VALUE) {
            issues.push(CrlfIssue::LocationHeaderInjection {
                parameter: parameter.to_string(),
            });
            break;
        }
    }

    let has_injected_content_type = resp_headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type") && value.contains(CRLF_CANARY_VALUE)
    });
    if has_injected_content_type {
        issues.push(CrlfIssue::ContentTypeInjection {
            parameter: parameter.to_string(),
        });
    }

    if issues.is_empty() {
        let has_partial = body.contains("\r\n")
            && body.contains(CRLF_CANARY_VALUE)
            || body.contains("%0d%0a")
                && body.contains(CRLF_CANARY_VALUE);
        if has_partial {
            issues.push(CrlfIssue::PartialHeaderInjection {
                parameter: parameter.to_string(),
            });
        }
    }

    issues
}

pub fn crlf_severity(issue: &CrlfIssue) -> f64 {
    match issue {
        CrlfIssue::HeaderInjection { .. } => 7.5,
        CrlfIssue::ResponseSplitting { .. } => 8.5,
        CrlfIssue::EncodedCrlf { .. } => 7.0,
        CrlfIssue::UnicodeCrlf { .. } => 7.0,
        CrlfIssue::SetCookieInjection { .. } => 8.0,
        CrlfIssue::LocationHeaderInjection { .. } => 7.5,
        CrlfIssue::ContentTypeInjection { .. } => 6.5,
        CrlfIssue::CrlfInUserAgent => 5.0,
        CrlfIssue::PartialHeaderInjection { .. } => 4.0,
    }
}

pub fn crlf_to_operations(issues: &[CrlfIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                crlf_severity(issue),
                0.5,
            )
        })
        .collect()
}
