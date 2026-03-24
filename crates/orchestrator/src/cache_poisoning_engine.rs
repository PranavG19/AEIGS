/// Web cache poisoning discovery engine.
///
/// Automates the full chain: cache-key analysis, unkeyed header discovery,
/// cache probing (hit/miss/TTL), payload delivery verification, fat GET
/// attacks, and parameter cloaking detection.
use std::collections::HashMap;

/// Headers commonly excluded from cache keys by CDNs and reverse proxies.
pub const UNKEYED_HEADERS: &[&str] = &[
    "X-Forwarded-Host",
    "X-Forwarded-Scheme",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Forwarded-For",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Method-Override",
    "X-Forwarded-Proto",
    "X-Custom-IP-Authorization",
    "X-Original-Host",
    "X-Proxy-URL",
    "X-Real-IP",
    "X-Client-IP",
    "True-Client-IP",
    "Forwarded",
];

/// Known CDN/proxy cache status header names.
const CACHE_STATUS_HEADERS: &[&str] = &[
    "x-cache",
    "x-cache-status",
    "cf-cache-status",
    "x-varnish",
    "x-drupal-cache",
    "x-proxy-cache",
    "x-rack-cache",
    "fastly-cache-status",
    "akamai-cache-status",
    "x-iinfo",
    "x-nc",
    "x-hits",
    "x-served-by",
    "x-timer",
    "cdn-cache-control",
    "age",
];

/// Header values that indicate a cache hit.
const HIT_INDICATORS: &[&str] = &[
    "hit",
    "hit, hit",
    "tcp_hit",
    "tcp_mem_hit",
    "tcp_refresh_hit",
    "mem_hit",
    "fresh",
    "stale",
    "revalidated",
];

/// Header values that indicate a cache miss.
const MISS_INDICATORS: &[&str] = &[
    "miss",
    "miss, miss",
    "tcp_miss",
    "tcp_refresh_miss",
    "expired",
    "dynamic",
    "bypass",
    "none",
];

#[derive(Debug, Clone, PartialEq)]
pub enum CacheStatus {
    Hit,
    Miss,
    Unknown,
}

impl std::fmt::Display for CacheStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hit => write!(f, "HIT"),
            Self::Miss => write!(f, "MISS"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Result of probing a single response for cache behaviour.
#[derive(Debug, Clone, PartialEq)]
pub struct CacheProbeResult {
    pub status: CacheStatus,
    pub age_seconds: Option<u64>,
    pub ttl_seconds: Option<u64>,
    pub cache_header: Option<String>,
    pub cache_value: Option<String>,
    pub vary_headers: Vec<String>,
}

/// A header discovered to be outside the cache key that influences the response.
#[derive(Debug, Clone, PartialEq)]
pub struct UnkeyedHeader {
    pub name: String,
    pub reflected_in: ReflectionTarget,
    pub payload_delivered: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReflectionTarget {
    Body,
    Header { name: String },
    StatusCode,
}

impl std::fmt::Display for ReflectionTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Body => write!(f, "body"),
            Self::Header { name } => write!(f, "header:{name}"),
            Self::StatusCode => write!(f, "status_code"),
        }
    }
}

/// Fat GET test result: whether query parameters in a GET body are honoured.
#[derive(Debug, Clone, PartialEq)]
pub struct FatGetResult {
    pub parameter: String,
    pub reflected: bool,
    pub cached: bool,
}

/// Parameter cloaking result: normalization differences between cache and origin.
#[derive(Debug, Clone, PartialEq)]
pub struct ParameterCloakResult {
    pub technique: CloakTechnique,
    pub parameter: String,
    pub smuggled_value: String,
    pub confirmed: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CloakTechnique {
    SemicolonSeparator,
    DuplicateParam,
    UrlEncodedAmpersand,
    TrailingDot,
    PathParameterInjection,
}

impl std::fmt::Display for CloakTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SemicolonSeparator => write!(f, "semicolon_separator"),
            Self::DuplicateParam => write!(f, "duplicate_param"),
            Self::UrlEncodedAmpersand => write!(f, "url_encoded_ampersand"),
            Self::TrailingDot => write!(f, "trailing_dot"),
            Self::PathParameterInjection => write!(f, "path_param_injection"),
        }
    }
}

/// Complete cache poisoning scan result.
#[derive(Debug, Clone)]
pub struct CachePoisoningScanResult {
    pub target_url: String,
    pub probe: CacheProbeResult,
    pub unkeyed_headers: Vec<UnkeyedHeader>,
    pub fat_get_results: Vec<FatGetResult>,
    pub cloak_results: Vec<ParameterCloakResult>,
    pub cache_buster_used: String,
}

/// Generates a unique cache buster query parameter value for A/B testing.
pub fn generate_cache_buster(prefix: &str, index: u32) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{prefix}_{ts}_{index}")
}

/// Generates a deterministic cache buster from a seed for reproducible tests.
pub fn generate_cache_buster_seeded(prefix: &str, seed: u64) -> String {
    format!("{prefix}_{seed}")
}

/// Detect cache status from response headers.
pub fn detect_cache_status(headers: &HashMap<String, String>) -> CacheProbeResult {
    let mut status = CacheStatus::Unknown;
    let mut age_seconds: Option<u64> = None;
    let mut ttl_seconds: Option<u64> = None;
    let mut cache_header: Option<String> = None;
    let mut cache_value: Option<String> = None;
    let mut vary_headers = Vec::new();

    for (key, value) in headers {
        let lower_key = key.to_ascii_lowercase();
        let lower_value = value.to_ascii_lowercase();

        if lower_key == "age" {
            age_seconds = lower_value.trim().parse::<u64>().ok();
            if age_seconds.is_some() && status == CacheStatus::Unknown {
                status = CacheStatus::Hit;
                cache_header = Some(key.clone());
                cache_value = Some(value.clone());
            }
        }

        if CACHE_STATUS_HEADERS.contains(&lower_key.as_str()) {
            let trimmed = lower_value.trim();
            if HIT_INDICATORS.iter().any(|h| trimmed.starts_with(h)) {
                status = CacheStatus::Hit;
                cache_header = Some(key.clone());
                cache_value = Some(value.clone());
            } else if MISS_INDICATORS.iter().any(|m| trimmed.starts_with(m))
                && status != CacheStatus::Hit
            {
                status = CacheStatus::Miss;
                cache_header = Some(key.clone());
                cache_value = Some(value.clone());
            }
        }

        if lower_key == "vary" {
            vary_headers = value
                .split(',')
                .map(|v| v.trim().to_ascii_lowercase())
                .filter(|v| !v.is_empty())
                .collect();
        }

        if lower_key == "cache-control" {
            ttl_seconds = extract_max_age(&lower_value);
        }
    }

    CacheProbeResult {
        status,
        age_seconds,
        ttl_seconds,
        cache_header,
        cache_value,
        vary_headers,
    }
}

/// Extract max-age value from a Cache-Control header. Prefers s-maxage over max-age.
fn extract_max_age(cache_control: &str) -> Option<u64> {
    let mut max_age_val: Option<u64> = None;
    let mut s_maxage_val: Option<u64> = None;

    for directive in cache_control.split(',') {
        let trimmed = directive.trim();
        if let Some(rest) = trimmed.strip_prefix("s-maxage=") {
            s_maxage_val = rest.trim().parse::<u64>().ok();
        } else if let Some(rest) = trimmed.strip_prefix("max-age=") {
            max_age_val = rest.trim().parse::<u64>().ok();
        }
    }

    s_maxage_val.or(max_age_val)
}

/// Analyze a response body and headers for reflection of a canary value.
pub fn detect_reflection(
    canary: &str,
    response_body: &str,
    response_headers: &HashMap<String, String>,
    status_code: u16,
) -> Option<ReflectionTarget> {
    if response_body.contains(canary) {
        return Some(ReflectionTarget::Body);
    }

    for (name, value) in response_headers {
        if value.contains(canary) {
            return Some(ReflectionTarget::Header { name: name.clone() });
        }
    }

    let canary_status: u16 = canary.parse().unwrap_or(0);
    if canary_status != 0 && status_code == canary_status {
        return Some(ReflectionTarget::StatusCode);
    }

    None
}

/// Test whether a specific header is excluded from the cache key.
///
/// Compares two responses: one baseline and one with the header set to a
/// canary. If the response differs (canary reflected) while cache status
/// doesn't change, the header is unkeyed.
pub fn test_unkeyed_header(
    header_name: &str,
    canary: &str,
    baseline_body: &str,
    baseline_headers: &HashMap<String, String>,
    probed_body: &str,
    probed_headers: &HashMap<String, String>,
    probed_status: u16,
) -> Option<UnkeyedHeader> {
    if baseline_body == probed_body && baseline_headers == probed_headers {
        return None;
    }

    let reflection = detect_reflection(canary, probed_body, probed_headers, probed_status)?;

    Some(UnkeyedHeader {
        name: header_name.to_string(),
        reflected_in: reflection,
        payload_delivered: canary.to_string(),
    })
}

/// Analyze fat GET behaviour: whether a body parameter in a GET request
/// is treated as a query parameter by the origin but ignored by the cache.
pub fn analyze_fat_get(
    parameter: &str,
    canary: &str,
    fat_get_body: &str,
    fat_get_headers: &HashMap<String, String>,
    fat_get_status: u16,
    second_get_body: &str,
) -> FatGetResult {
    let reflected =
        detect_reflection(canary, fat_get_body, fat_get_headers, fat_get_status).is_some();
    let cached = second_get_body.contains(canary);

    FatGetResult {
        parameter: parameter.to_string(),
        reflected,
        cached,
    }
}

/// Test a parameter cloaking technique by comparing a smuggled parameter
/// against a baseline.
pub fn test_parameter_cloak(
    technique: CloakTechnique,
    parameter: &str,
    smuggled_value: &str,
    response_body: &str,
    response_headers: &HashMap<String, String>,
) -> ParameterCloakResult {
    let confirmed = response_body.contains(smuggled_value)
        || response_headers
            .values()
            .any(|v| v.contains(smuggled_value));

    ParameterCloakResult {
        technique,
        parameter: parameter.to_string(),
        smuggled_value: smuggled_value.to_string(),
        confirmed,
    }
}

/// Build a smuggled URL for parameter cloaking using the given technique.
pub fn build_cloak_url(
    base_url: &str,
    parameter: &str,
    value: &str,
    technique: &CloakTechnique,
) -> String {
    let separator = if base_url.contains('?') { '&' } else { '?' };

    match technique {
        CloakTechnique::SemicolonSeparator => {
            format!("{base_url}{separator}cachebust=1;{parameter}={value}")
        }
        CloakTechnique::DuplicateParam => {
            format!("{base_url}{separator}{parameter}=benign&{parameter}={value}")
        }
        CloakTechnique::UrlEncodedAmpersand => {
            format!("{base_url}{separator}cachebust=1%26{parameter}={value}")
        }
        CloakTechnique::TrailingDot => {
            format!("{base_url}.{separator}{parameter}={value}")
        }
        CloakTechnique::PathParameterInjection => {
            format!("{base_url};{parameter}={value}")
        }
    }
}

/// Compute severity score for a cache poisoning finding.
pub fn severity_score(
    unkeyed_count: usize,
    has_fat_get: bool,
    has_cloak: bool,
    ttl: Option<u64>,
) -> f64 {
    let mut score = 0.0_f64;

    score += (unkeyed_count as f64).min(5.0) * 1.5;

    if has_fat_get {
        score += 2.0;
    }
    if has_cloak {
        score += 2.5;
    }

    if let Some(ttl_val) = ttl
        && ttl_val > 3600
    {
        score += 1.0;
    }

    score.min(10.0)
}

/// Return all commonly-unkeyed header names (full list ≥16).
pub fn commonly_unkeyed_headers() -> &'static [&'static str] {
    UNKEYED_HEADERS
}

/// Return all known cache status header names.
pub fn cache_status_header_names() -> &'static [&'static str] {
    CACHE_STATUS_HEADERS
}

/// Determine if a set of Vary headers covers the given header name.
pub fn vary_covers(vary_headers: &[String], header_name: &str) -> bool {
    let lower = header_name.to_ascii_lowercase();
    vary_headers.iter().any(|v| v == &lower || v == "*")
}

/// Detect if a response indicates the server is behind a CDN.
pub fn detect_cdn_presence(headers: &HashMap<String, String>) -> Option<String> {
    let cdn_fingerprints: &[(&str, &str)] = &[
        ("cf-ray", "Cloudflare"),
        ("x-amz-cf-id", "CloudFront"),
        ("x-served-by", "Fastly"),
        ("x-akamai-request-id", "Akamai"),
        ("x-cdn", "Generic CDN"),
        ("x-cache", "Reverse Proxy/CDN"),
        ("x-varnish", "Varnish"),
    ];

    for (header, cdn_name) in cdn_fingerprints {
        if headers.contains_key(*header) {
            return Some(cdn_name.to_string());
        }
    }
    None
}

/// Build a summary of all cache poisoning findings for reporting.
pub fn summarize_findings(result: &CachePoisoningScanResult) -> Vec<String> {
    let mut findings = Vec::new();

    match &result.probe.status {
        CacheStatus::Hit => findings.push("Cache detected: responses are being cached".into()),
        CacheStatus::Miss => findings.push("Cache detected: responses marked as miss".into()),
        CacheStatus::Unknown => findings.push("Cache status: could not determine".into()),
    }

    if let Some(ttl) = result.probe.ttl_seconds {
        findings.push(format!("Cache TTL: {ttl} seconds"));
    }

    for uh in &result.unkeyed_headers {
        findings.push(format!(
            "Unkeyed header '{}' reflected in {} with payload '{}'",
            uh.name, uh.reflected_in, uh.payload_delivered
        ));
    }

    for fg in &result.fat_get_results {
        if fg.reflected && fg.cached {
            findings.push(format!(
                "Fat GET attack: parameter '{}' cached from request body",
                fg.parameter
            ));
        } else if fg.reflected {
            findings.push(format!(
                "Fat GET: parameter '{}' reflected but not confirmed cached",
                fg.parameter
            ));
        }
    }

    for cloak in &result.cloak_results {
        if cloak.confirmed {
            findings.push(format!(
                "Parameter cloak via {}: '{}' smuggled with value '{}'",
                cloak.technique, cloak.parameter, cloak.smuggled_value
            ));
        }
    }

    findings
}
