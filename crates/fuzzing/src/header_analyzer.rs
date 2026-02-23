const ONE_YEAR_SECONDS: u64 = 31_536_000;

const VALID_REFERRER_POLICIES: &[&str] = &[
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
];

#[derive(Debug, Clone)]
pub struct HeaderFinding {
    pub header_name: String,
    pub issue: HeaderIssue,
    pub severity: f64,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HeaderIssue {
    Missing,
    Weak(String),
}

pub struct SecurityHeaderAnalyzer;

impl SecurityHeaderAnalyzer {
    pub fn analyze_response_headers(headers: &[(String, String)]) -> Vec<HeaderFinding> {
        let lookup = |name: &str| -> Option<&str> {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };

        let mut findings = Vec::new();
        Self::check_hsts(lookup("strict-transport-security"), &mut findings);
        Self::check_csp(lookup("content-security-policy"), &mut findings);
        Self::check_x_frame_options(lookup("x-frame-options"), &mut findings);
        Self::check_x_content_type_options(lookup("x-content-type-options"), &mut findings);
        Self::check_referrer_policy(lookup("referrer-policy"), &mut findings);
        Self::check_permissions_policy(lookup("permissions-policy"), &mut findings);
        findings
    }

    pub fn analyze_cookies(set_cookie_headers: &[String]) -> Vec<HeaderFinding> {
        let mut findings = Vec::new();
        for raw in set_cookie_headers {
            let lower = raw.to_ascii_lowercase();
            let cookie_name = raw
                .split(';')
                .next()
                .unwrap_or(raw)
                .split('=')
                .next()
                .unwrap_or("unknown");

            if !lower.contains("secure") {
                findings.push(HeaderFinding {
                    header_name: "Set-Cookie".to_string(),
                    issue: HeaderIssue::Weak(format!("cookie '{cookie_name}' missing Secure flag")),
                    severity: 4.0,
                    description: format!("Cookie '{cookie_name}' lacks the Secure flag and may be sent over unencrypted HTTP"),
                });
            }
            if !lower.contains("httponly") {
                findings.push(HeaderFinding {
                    header_name: "Set-Cookie".to_string(),
                    issue: HeaderIssue::Weak(format!("cookie '{cookie_name}' missing HttpOnly flag")),
                    severity: 3.0,
                    description: format!("Cookie '{cookie_name}' lacks HttpOnly and is accessible to JavaScript via document.cookie"),
                });
            }
            if !lower.contains("samesite") {
                findings.push(HeaderFinding {
                    header_name: "Set-Cookie".to_string(),
                    issue: HeaderIssue::Weak(format!("cookie '{cookie_name}' missing SameSite attribute")),
                    severity: 2.0,
                    description: format!("Cookie '{cookie_name}' lacks a SameSite attribute, enabling potential CSRF attacks"),
                });
            }
        }
        findings
    }

    pub fn analyze_info_disclosure(headers: &[(String, String)]) -> Vec<HeaderFinding> {
        let mut findings = Vec::new();
        for (name, value) in headers {
            let lower_name = name.to_ascii_lowercase();
            match lower_name.as_str() {
                "server" if Self::has_version(value) => {
                    findings.push(HeaderFinding {
                        header_name: "Server".to_string(),
                        issue: HeaderIssue::Weak(format!("exposes version: {value}")),
                        severity: 1.0,
                        description: format!("Server header discloses software version: {value}"),
                    });
                }
                "x-powered-by" => {
                    findings.push(HeaderFinding {
                        header_name: "X-Powered-By".to_string(),
                        issue: HeaderIssue::Weak(format!("exposes technology: {value}")),
                        severity: 1.0,
                        description: format!(
                            "X-Powered-By header discloses technology stack: {value}"
                        ),
                    });
                }
                "x-aspnet-version" => {
                    findings.push(HeaderFinding {
                        header_name: "X-AspNet-Version".to_string(),
                        issue: HeaderIssue::Weak(format!("exposes version: {value}")),
                        severity: 1.0,
                        description: format!(
                            "X-AspNet-Version header discloses framework version: {value}"
                        ),
                    });
                }
                "x-debug-token" => {
                    findings.push(HeaderFinding {
                        header_name: "X-Debug-Token".to_string(),
                        issue: HeaderIssue::Weak(format!("debug token exposed: {value}")),
                        severity: 5.0,
                        description: "X-Debug-Token header present, indicating debug mode may be active in production".to_string(),
                    });
                }
                _ => {}
            }
        }
        findings
    }

    pub fn analyze_all(
        headers: &[(String, String)],
        set_cookie_headers: &[String],
    ) -> Vec<HeaderFinding> {
        let mut findings = Self::analyze_response_headers(headers);
        findings.extend(Self::analyze_cookies(set_cookie_headers));
        findings.extend(Self::analyze_info_disclosure(headers));
        findings
    }

    fn check_hsts(value: Option<&str>, findings: &mut Vec<HeaderFinding>) {
        match value {
            None => findings.push(HeaderFinding {
                header_name: "Strict-Transport-Security".to_string(),
                issue: HeaderIssue::Missing,
                severity: 5.0,
                description: "Strict-Transport-Security header is missing; site may be accessed over plain HTTP".to_string(),
            }),
            Some(v) => {
                if let Some(max_age) = Self::parse_max_age(v) {
                    if max_age < ONE_YEAR_SECONDS {
                        findings.push(HeaderFinding {
                            header_name: "Strict-Transport-Security".to_string(),
                            issue: HeaderIssue::Weak(format!("max-age={max_age} is less than {ONE_YEAR_SECONDS}")),
                            severity: 3.0,
                            description: format!("HSTS max-age of {max_age}s is below the recommended minimum of {ONE_YEAR_SECONDS}s (1 year)"),
                        });
                    }
                }
            }
        }
    }

    fn check_csp(value: Option<&str>, findings: &mut Vec<HeaderFinding>) {
        match value {
            None => findings.push(HeaderFinding {
                header_name: "Content-Security-Policy".to_string(),
                issue: HeaderIssue::Missing,
                severity: 5.0,
                description: "Content-Security-Policy header is missing; no browser-side injection mitigations".to_string(),
            }),
            Some(v) => {
                let lower = v.to_ascii_lowercase();
                if lower.contains("unsafe-inline") {
                    findings.push(HeaderFinding {
                        header_name: "Content-Security-Policy".to_string(),
                        issue: HeaderIssue::Weak("contains 'unsafe-inline'".to_string()),
                        severity: 4.0,
                        description: "CSP allows 'unsafe-inline', weakening protection against XSS".to_string(),
                    });
                }
                if lower.contains("unsafe-eval") {
                    findings.push(HeaderFinding {
                        header_name: "Content-Security-Policy".to_string(),
                        issue: HeaderIssue::Weak("contains 'unsafe-eval'".to_string()),
                        severity: 4.0,
                        description: "CSP allows 'unsafe-eval', enabling dynamic code execution".to_string(),
                    });
                }
            }
        }
    }

    fn check_x_frame_options(value: Option<&str>, findings: &mut Vec<HeaderFinding>) {
        match value {
            None => findings.push(HeaderFinding {
                header_name: "X-Frame-Options".to_string(),
                issue: HeaderIssue::Missing,
                severity: 3.0,
                description: "X-Frame-Options header is missing; page may be embedded in iframes (clickjacking)".to_string(),
            }),
            Some(v) => {
                let upper = v.to_ascii_uppercase();
                if upper != "DENY" && upper != "SAMEORIGIN" {
                    findings.push(HeaderFinding {
                        header_name: "X-Frame-Options".to_string(),
                        issue: HeaderIssue::Weak(format!("invalid value: {v}")),
                        severity: 3.0,
                        description: format!("X-Frame-Options has unrecognized value '{v}'; must be DENY or SAMEORIGIN"),
                    });
                }
            }
        }
    }

    fn check_x_content_type_options(value: Option<&str>, findings: &mut Vec<HeaderFinding>) {
        match value {
            None => findings.push(HeaderFinding {
                header_name: "X-Content-Type-Options".to_string(),
                issue: HeaderIssue::Missing,
                severity: 2.0,
                description:
                    "X-Content-Type-Options header is missing; browser may MIME-sniff responses"
                        .to_string(),
            }),
            Some(v) if !v.eq_ignore_ascii_case("nosniff") => {
                findings.push(HeaderFinding {
                    header_name: "X-Content-Type-Options".to_string(),
                    issue: HeaderIssue::Weak(format!("invalid value: {v}")),
                    severity: 2.0,
                    description: format!(
                        "X-Content-Type-Options has invalid value '{v}'; must be 'nosniff'"
                    ),
                });
            }
            _ => {}
        }
    }

    fn check_referrer_policy(value: Option<&str>, findings: &mut Vec<HeaderFinding>) {
        match value {
            None => findings.push(HeaderFinding {
                header_name: "Referrer-Policy".to_string(),
                issue: HeaderIssue::Missing,
                severity: 2.0,
                description:
                    "Referrer-Policy header is missing; sensitive URLs may leak via Referer header"
                        .to_string(),
            }),
            Some(v) => {
                let lower = v.to_ascii_lowercase();
                if !VALID_REFERRER_POLICIES.contains(&lower.as_str()) {
                    findings.push(HeaderFinding {
                        header_name: "Referrer-Policy".to_string(),
                        issue: HeaderIssue::Weak(format!("permissive value: {v}")),
                        severity: 2.0,
                        description: format!(
                            "Referrer-Policy value '{v}' may leak URL information to third parties"
                        ),
                    });
                }
            }
        }
    }

    fn check_permissions_policy(value: Option<&str>, findings: &mut Vec<HeaderFinding>) {
        if value.is_none() {
            findings.push(HeaderFinding {
                header_name: "Permissions-Policy".to_string(),
                issue: HeaderIssue::Missing,
                severity: 1.0,
                description:
                    "Permissions-Policy header is missing; browser features are not restricted"
                        .to_string(),
            });
        }
    }

    fn parse_max_age(hsts_value: &str) -> Option<u64> {
        hsts_value
            .split(';')
            .map(str::trim)
            .find(|part| part.to_ascii_lowercase().starts_with("max-age"))
            .and_then(|part| part.split('=').nth(1))
            .and_then(|val| val.trim().parse().ok())
    }

    fn has_version(server_value: &str) -> bool {
        server_value.contains('/')
            && server_value.split('/').nth(1).is_some_and(|after_slash| {
                after_slash
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_digit())
            })
    }
}

#[cfg(test)]
#[path = "header_analyzer_test.rs"]
mod header_analyzer_test;
