use std::time::Duration;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

const TLS_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct TlsFinding {
    pub issue: TlsIssue,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TlsIssue {
    NoHttps,
    MissingHsts,
    ShortHstsMaxAge,
    InsecureRedirect,
}

pub fn scan_tls(target: &str) -> Vec<TlsFinding> {
    let Some(domain) = recon_client::validated_domain(target) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    let https_url = format!("https://{domain}");
    let Some(client) = recon_client::build_client_no_redirect(TLS_CHECK_TIMEOUT) else {
        return findings;
    };

    // Check HTTPS availability
    let resp = match client.get(&https_url).send() {
        Ok(r) => r,
        Err(_) => {
            findings.push(TlsFinding {
                issue: TlsIssue::NoHttps,
                detail: format!("{domain} does not respond on HTTPS"),
            });
            return findings;
        }
    };

    // Check HSTS header
    let hsts = resp
        .headers()
        .get("strict-transport-security")
        .and_then(|v| v.to_str().ok().map(String::from));
    match &hsts {
        None => {
            findings.push(TlsFinding {
                issue: TlsIssue::MissingHsts,
                detail: format!("{domain} does not set Strict-Transport-Security"),
            });
        }
        Some(val) => {
            if let Some(max_age) = parse_hsts_max_age(val)
                && max_age < 31_536_000
            {
                findings.push(TlsFinding {
                    issue: TlsIssue::ShortHstsMaxAge,
                    detail: format!("{domain} HSTS max-age={max_age} (recommended: >=31536000)"),
                });
            }
        }
    }

    // Check HTTP→HTTPS redirect
    let http_url = format!("http://{domain}");
    if let Ok(http_resp) = client.get(&http_url).send() {
        let status = http_resp.status().as_u16();
        if !(300..400).contains(&status) {
            findings.push(TlsFinding {
                issue: TlsIssue::InsecureRedirect,
                detail: format!("{domain} HTTP does not redirect to HTTPS (status {status})"),
            });
        } else if let Some(location) = http_resp.headers().get("location")
            && let Ok(loc) = location.to_str()
            && !loc.starts_with("https://")
        {
            findings.push(TlsFinding {
                issue: TlsIssue::InsecureRedirect,
                detail: format!("{domain} HTTP redirects to non-HTTPS: {loc}"),
            });
        }
    }

    findings
}

pub fn parse_hsts_max_age(header: &str) -> Option<u64> {
    for part in header.split(';') {
        let trimmed = part.trim().to_lowercase();
        if let Some(val) = trimmed.strip_prefix("max-age=") {
            return val.trim().parse().ok();
        }
    }
    None
}

pub fn tls_findings_to_operations(
    findings: &[TlsFinding],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    findings
        .iter()
        .map(|f| {
            let (vuln_class, severity, confidence) = match f.issue {
                TlsIssue::NoHttps => (VulnerabilityClass::WeakCryptography, 7.0, 0.95),
                TlsIssue::MissingHsts => (VulnerabilityClass::MissingSecurityHeader, 5.0, 0.9),
                TlsIssue::ShortHstsMaxAge => (VulnerabilityClass::MissingSecurityHeader, 3.0, 0.85),
                TlsIssue::InsecureRedirect => {
                    (VulnerabilityClass::SecurityMisconfiguration, 5.0, 0.9)
                }
            };
            recon_client::finding_entry(seq, vuln_class, severity, confidence)
        })
        .collect()
}

// New TLS Security Analysis Types and Functions

#[derive(Debug, Clone, PartialEq)]
pub enum TlsSecurityIssue {
    MissingStrictTransport,
    ShortMaxAge,
    MissingIncludeSubDomains,
    MissingPreload,
    InsecureUpgradeInsecureRequests,
    MixedContentRisk,
    WeakCipherIndication,
    CertificateTransparency,
    MissingPublicKeyPins,
    InsecureCookieTransmission,
}

impl std::fmt::Display for TlsSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingStrictTransport => write!(f, "Missing Strict-Transport-Security header"),
            Self::ShortMaxAge => write!(f, "HSTS max-age below recommended threshold"),
            Self::MissingIncludeSubDomains => {
                write!(f, "HSTS missing includeSubDomains directive")
            }
            Self::MissingPreload => write!(f, "HSTS missing preload directive"),
            Self::InsecureUpgradeInsecureRequests => {
                write!(f, "Missing upgrade-insecure-requests directive")
            }
            Self::MixedContentRisk => {
                write!(f, "Content-Security-Policy missing block-all-mixed-content")
            }
            Self::WeakCipherIndication => write!(f, "Server header indicates weak cipher suite"),
            Self::CertificateTransparency => write!(f, "Missing Expect-CT header"),
            Self::MissingPublicKeyPins => {
                write!(
                    f,
                    "Missing Public-Key-Pins header (deprecated but informational)"
                )
            }
            Self::InsecureCookieTransmission => {
                write!(f, "Set-Cookie without Secure flag in response")
            }
        }
    }
}

pub fn analyze_tls_headers(headers: &[(&str, &str)]) -> Vec<TlsSecurityIssue> {
    let mut issues = Vec::new();
    let mut has_hsts = false;
    let mut hsts_value = None;
    let mut has_upgrade_insecure = false;
    let mut has_csp_mixed_content = false;
    let mut has_expect_ct = false;
    let mut has_pkp = false;
    let mut has_insecure_cookie = false;

    for (name, value) in headers {
        let name_lower = name.to_lowercase();
        match name_lower.as_str() {
            "strict-transport-security" => {
                has_hsts = true;
                hsts_value = Some(*value);
            }
            "content-security-policy" => {
                if value.to_lowercase().contains("upgrade-insecure-requests") {
                    has_upgrade_insecure = true;
                }
                if value.to_lowercase().contains("block-all-mixed-content") {
                    has_csp_mixed_content = true;
                }
            }
            "expect-ct" => {
                has_expect_ct = true;
            }
            "public-key-pins" | "public-key-pins-report-only" => {
                has_pkp = true;
            }
            "set-cookie" => {
                if !value.to_lowercase().contains("secure") {
                    has_insecure_cookie = true;
                }
            }
            "server" => {
                let val_lower = value.to_lowercase();
                if val_lower.contains("rc4")
                    || val_lower.contains("des")
                    || val_lower.contains("md5")
                    || val_lower.contains("ssl")
                    || val_lower.contains("tls1.0")
                    || val_lower.contains("tls1.1")
                {
                    issues.push(TlsSecurityIssue::WeakCipherIndication);
                }
            }
            _ => {}
        }
    }

    if !has_hsts {
        issues.push(TlsSecurityIssue::MissingStrictTransport);
    } else if let Some(hsts) = hsts_value {
        if let Some(max_age) = parse_hsts_max_age(hsts)
            && max_age < 31_536_000
        {
            issues.push(TlsSecurityIssue::ShortMaxAge);
        }
        let hsts_lower = hsts.to_lowercase();
        if !hsts_lower.contains("includesubdomains") {
            issues.push(TlsSecurityIssue::MissingIncludeSubDomains);
        }
        if !hsts_lower.contains("preload") {
            issues.push(TlsSecurityIssue::MissingPreload);
        }
    }

    if !has_upgrade_insecure {
        issues.push(TlsSecurityIssue::InsecureUpgradeInsecureRequests);
    }

    if !has_csp_mixed_content {
        issues.push(TlsSecurityIssue::MixedContentRisk);
    }

    if !has_expect_ct {
        issues.push(TlsSecurityIssue::CertificateTransparency);
    }

    if !has_pkp {
        issues.push(TlsSecurityIssue::MissingPublicKeyPins);
    }

    if has_insecure_cookie {
        issues.push(TlsSecurityIssue::InsecureCookieTransmission);
    }

    issues
}

pub fn tls_security_severity(issue: &TlsSecurityIssue) -> f64 {
    match issue {
        TlsSecurityIssue::MissingStrictTransport => 6.0,
        TlsSecurityIssue::ShortMaxAge => 4.0,
        TlsSecurityIssue::MissingIncludeSubDomains => 3.0,
        TlsSecurityIssue::MissingPreload => 2.0,
        TlsSecurityIssue::InsecureUpgradeInsecureRequests => 5.0,
        TlsSecurityIssue::MixedContentRisk => 5.5,
        TlsSecurityIssue::WeakCipherIndication => 7.0,
        TlsSecurityIssue::CertificateTransparency => 3.5,
        TlsSecurityIssue::MissingPublicKeyPins => 2.0,
        TlsSecurityIssue::InsecureCookieTransmission => 6.5,
    }
}

pub fn tls_security_to_operations(
    issues: &[TlsSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            let severity = tls_security_severity(issue);
            recon_client::finding_entry(seq, VulnerabilityClass::WeakCryptography, severity, 0.5)
        })
        .collect()
}
