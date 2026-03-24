use std::collections::HashMap;
use std::fmt;

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;

/// IP spoofing header names used by proxies and CDNs.
/// Different rate limiters trust different headers, so rotating across
/// all known variants maximizes bypass probability.
const IP_ROTATION_HEADERS: &[&str] = &[
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Originating-IP",
    "True-Client-IP",
    "CF-Connecting-IP",
    "X-Client-IP",
    "Forwarded",
    "X-Cluster-Client-IP",
];

const CONTENT_TYPES: &[&str] = &[
    "application/json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
    "application/xml",
    "application/json; charset=utf-8",
];

const METHOD_VARIANTS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

const REFERER_TEMPLATES: &[&str] = &[
    "https://www.google.com/search?q=",
    "https://www.bing.com/search?q=",
    "https://duckduckgo.com/?q=",
    "https://t.co/redirect?url=",
    "https://www.reddit.com/r/",
    "https://news.ycombinator.com/item?id=",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BypassTechnique {
    IpRotation,
    ApiKeyMultiplexing,
    EndpointAliasing,
    HttpMethodSwitching,
    UnicodePathNormalization,
    Http2Multiplexing,
    DistributedTiming,
    CaseVariation,
    ContentTypeSwitching,
    RefererManipulation,
}

impl fmt::Display for BypassTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IpRotation => write!(f, "IP Rotation Headers"),
            Self::ApiKeyMultiplexing => write!(f, "API Key Multiplexing"),
            Self::EndpointAliasing => write!(f, "Endpoint Aliasing"),
            Self::HttpMethodSwitching => write!(f, "HTTP Method Switching"),
            Self::UnicodePathNormalization => write!(f, "Unicode Path Normalization"),
            Self::Http2Multiplexing => write!(f, "HTTP/2 Connection Multiplexing"),
            Self::DistributedTiming => write!(f, "Distributed Timing Jitter"),
            Self::CaseVariation => write!(f, "Case Variation"),
            Self::ContentTypeSwitching => write!(f, "Content-Type Switching"),
            Self::RefererManipulation => write!(f, "Referer/Origin Manipulation"),
        }
    }
}

impl BypassTechnique {
    pub fn all() -> &'static [BypassTechnique] {
        &[
            Self::IpRotation,
            Self::ApiKeyMultiplexing,
            Self::EndpointAliasing,
            Self::HttpMethodSwitching,
            Self::UnicodePathNormalization,
            Self::Http2Multiplexing,
            Self::DistributedTiming,
            Self::CaseVariation,
            Self::ContentTypeSwitching,
            Self::RefererManipulation,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitterShape {
    Uniform,
    Normal,
    Exponential,
}

/// Encapsulates a mutated request produced by a bypass technique.
#[derive(Debug, Clone)]
pub struct BypassRequest {
    pub technique: BypassTechnique,
    pub path: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub delay_ms: u64,
}

/// Configuration for the rate limit bypass engine.
#[derive(Debug, Clone)]
pub struct RateLimitBypassConfig {
    pub ip_pool: Vec<String>,
    pub api_keys: Vec<String>,
    pub jitter_shape: JitterShape,
    pub min_delay_ms: u64,
    pub max_delay_ms: u64,
    pub enabled_techniques: Vec<BypassTechnique>,
    pub h2_max_streams: u32,
}

impl Default for RateLimitBypassConfig {
    fn default() -> Self {
        Self {
            ip_pool: default_ip_pool(),
            api_keys: Vec::new(),
            jitter_shape: JitterShape::Uniform,
            min_delay_ms: 50,
            max_delay_ms: 500,
            enabled_techniques: BypassTechnique::all().to_vec(),
            h2_max_streams: 100,
        }
    }
}

/// Builder for `RateLimitBypassConfig`.
pub struct RateLimitBypassConfigBuilder {
    config: RateLimitBypassConfig,
}

impl RateLimitBypassConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: RateLimitBypassConfig::default(),
        }
    }

    pub fn with_ip_pool(mut self, ips: Vec<String>) -> Self {
        self.config.ip_pool = ips;
        self
    }

    pub fn with_api_keys(mut self, keys: Vec<String>) -> Self {
        self.config.api_keys = keys;
        self
    }

    pub fn with_jitter_shape(mut self, shape: JitterShape) -> Self {
        self.config.jitter_shape = shape;
        self
    }

    pub fn with_delay_range(mut self, min_ms: u64, max_ms: u64) -> Self {
        self.config.min_delay_ms = min_ms;
        self.config.max_delay_ms = max_ms;
        self
    }

    pub fn with_techniques(mut self, techniques: Vec<BypassTechnique>) -> Self {
        self.config.enabled_techniques = techniques;
        self
    }

    pub fn with_h2_max_streams(mut self, max: u32) -> Self {
        self.config.h2_max_streams = max;
        self
    }

    pub fn build(self) -> RateLimitBypassConfig {
        self.config
    }
}

impl Default for RateLimitBypassConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Core engine that produces mutated requests using rate limit bypass techniques.
pub struct RateLimitBypassEngine {
    config: RateLimitBypassConfig,
    rng: StdRng,
    ip_cursor: usize,
    api_key_cursor: usize,
    h2_stream_counter: u32,
}

impl RateLimitBypassEngine {
    pub fn new(config: RateLimitBypassConfig, seed: u64) -> Self {
        Self {
            config,
            rng: StdRng::seed_from_u64(seed),
            ip_cursor: 0,
            api_key_cursor: 0,
            h2_stream_counter: 0,
        }
    }

    pub fn config(&self) -> &RateLimitBypassConfig {
        &self.config
    }

    pub fn generate_bypass(&mut self, path: &str, method: &str) -> Vec<BypassRequest> {
        let mut results = Vec::new();
        for technique in &self.config.enabled_techniques.clone() {
            match technique {
                BypassTechnique::IpRotation => {
                    results.push(self.apply_ip_rotation(path, method));
                }
                BypassTechnique::ApiKeyMultiplexing => {
                    if let Some(req) = self.apply_api_key_multiplex(path, method) {
                        results.push(req);
                    }
                }
                BypassTechnique::EndpointAliasing => {
                    results.extend(self.apply_endpoint_aliasing(path, method));
                }
                BypassTechnique::HttpMethodSwitching => {
                    results.extend(self.apply_method_switching(path, method));
                }
                BypassTechnique::UnicodePathNormalization => {
                    results.extend(self.apply_unicode_normalization(path, method));
                }
                BypassTechnique::Http2Multiplexing => {
                    results.push(self.apply_h2_multiplex(path, method));
                }
                BypassTechnique::DistributedTiming => {
                    results.push(self.apply_distributed_timing(path, method));
                }
                BypassTechnique::CaseVariation => {
                    results.extend(self.apply_case_variation(path, method));
                }
                BypassTechnique::ContentTypeSwitching => {
                    results.extend(self.apply_content_type_switching(path, method));
                }
                BypassTechnique::RefererManipulation => {
                    results.extend(self.apply_referer_manipulation(path, method));
                }
            }
        }
        results
    }

    pub fn next_ip_header(&mut self) -> (String, String) {
        let header_idx = self.ip_cursor % IP_ROTATION_HEADERS.len();
        let ip_idx = self.ip_cursor % self.config.ip_pool.len().max(1);
        let header_name = IP_ROTATION_HEADERS[header_idx].to_string();
        let ip = if self.config.ip_pool.is_empty() {
            generate_random_ip(&mut self.rng)
        } else {
            self.config.ip_pool[ip_idx].clone()
        };
        self.ip_cursor = self.ip_cursor.wrapping_add(1);
        (header_name, ip)
    }

    pub fn compute_jitter_ms(&mut self) -> u64 {
        let min = self.config.min_delay_ms;
        let max = self.config.max_delay_ms;
        if min >= max {
            return min;
        }
        match self.config.jitter_shape {
            JitterShape::Uniform => self.rng.random_range(min..=max),
            JitterShape::Normal => {
                let mean = (min + max) as f64 / 2.0;
                let stddev = (max - min) as f64 / 4.0;
                let u1: f64 = self.rng.random_range(0.0001f64..1.0);
                let u2: f64 = self.rng.random_range(0.0001f64..1.0);
                let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
                let sample = mean + stddev * z;
                sample.round().max(min as f64).min(max as f64) as u64
            }
            JitterShape::Exponential => {
                let range = max - min;
                let lambda = 1.0 / range as f64;
                let u: f64 = self.rng.random_range(0.0001f64..1.0);
                let sample = -u.ln() / lambda;
                let delay = min as f64 + sample;
                delay.round().min(max as f64) as u64
            }
        }
    }

    fn apply_ip_rotation(&mut self, path: &str, method: &str) -> BypassRequest {
        let (header_name, ip) = self.next_ip_header();
        BypassRequest {
            technique: BypassTechnique::IpRotation,
            path: path.to_string(),
            method: method.to_string(),
            headers: vec![(header_name, ip)],
            delay_ms: 0,
        }
    }

    fn apply_api_key_multiplex(&mut self, path: &str, method: &str) -> Option<BypassRequest> {
        if self.config.api_keys.is_empty() {
            return None;
        }
        let idx = self.api_key_cursor % self.config.api_keys.len();
        let key = self.config.api_keys[idx].clone();
        self.api_key_cursor = self.api_key_cursor.wrapping_add(1);
        Some(BypassRequest {
            technique: BypassTechnique::ApiKeyMultiplexing,
            path: path.to_string(),
            method: method.to_string(),
            headers: vec![("Authorization".to_string(), format!("Bearer {key}"))],
            delay_ms: 0,
        })
    }

    fn apply_endpoint_aliasing(&self, path: &str, method: &str) -> Vec<BypassRequest> {
        generate_path_aliases(path)
            .into_iter()
            .map(|aliased| BypassRequest {
                technique: BypassTechnique::EndpointAliasing,
                path: aliased,
                method: method.to_string(),
                headers: Vec::new(),
                delay_ms: 0,
            })
            .collect()
    }

    fn apply_method_switching(&self, path: &str, current_method: &str) -> Vec<BypassRequest> {
        METHOD_VARIANTS
            .iter()
            .filter(|m| !m.eq_ignore_ascii_case(current_method))
            .map(|m| BypassRequest {
                technique: BypassTechnique::HttpMethodSwitching,
                path: path.to_string(),
                method: m.to_string(),
                headers: Vec::new(),
                delay_ms: 0,
            })
            .collect()
    }

    fn apply_unicode_normalization(&self, path: &str, method: &str) -> Vec<BypassRequest> {
        generate_unicode_variants(path)
            .into_iter()
            .map(|encoded| BypassRequest {
                technique: BypassTechnique::UnicodePathNormalization,
                path: encoded,
                method: method.to_string(),
                headers: Vec::new(),
                delay_ms: 0,
            })
            .collect()
    }

    fn apply_h2_multiplex(&mut self, path: &str, method: &str) -> BypassRequest {
        self.h2_stream_counter = (self.h2_stream_counter + 1) % self.config.h2_max_streams;
        BypassRequest {
            technique: BypassTechnique::Http2Multiplexing,
            path: path.to_string(),
            method: method.to_string(),
            headers: vec![
                (
                    "X-H2-Stream-Id".to_string(),
                    self.h2_stream_counter.to_string(),
                ),
                ("Connection".to_string(), "keep-alive".to_string()),
            ],
            delay_ms: 0,
        }
    }

    fn apply_distributed_timing(&mut self, path: &str, method: &str) -> BypassRequest {
        let delay = self.compute_jitter_ms();
        BypassRequest {
            technique: BypassTechnique::DistributedTiming,
            path: path.to_string(),
            method: method.to_string(),
            headers: Vec::new(),
            delay_ms: delay,
        }
    }

    fn apply_case_variation(&self, path: &str, method: &str) -> Vec<BypassRequest> {
        generate_case_variants(path)
            .into_iter()
            .map(|variant| BypassRequest {
                technique: BypassTechnique::CaseVariation,
                path: variant,
                method: method.to_string(),
                headers: Vec::new(),
                delay_ms: 0,
            })
            .collect()
    }

    fn apply_content_type_switching(&self, path: &str, method: &str) -> Vec<BypassRequest> {
        CONTENT_TYPES
            .iter()
            .map(|ct| BypassRequest {
                technique: BypassTechnique::ContentTypeSwitching,
                path: path.to_string(),
                method: method.to_string(),
                headers: vec![("Content-Type".to_string(), ct.to_string())],
                delay_ms: 0,
            })
            .collect()
    }

    fn apply_referer_manipulation(&mut self, path: &str, method: &str) -> Vec<BypassRequest> {
        let domain = extract_path_domain(path);
        REFERER_TEMPLATES
            .iter()
            .map(|tmpl| {
                let referer = format!("{tmpl}{domain}");
                let origin = tmpl
                    .split("//")
                    .nth(1)
                    .and_then(|s| s.split('/').next())
                    .unwrap_or("unknown");
                BypassRequest {
                    technique: BypassTechnique::RefererManipulation,
                    path: path.to_string(),
                    method: method.to_string(),
                    headers: vec![
                        ("Referer".to_string(), referer),
                        ("Origin".to_string(), format!("https://{origin}")),
                    ],
                    delay_ms: 0,
                }
            })
            .collect()
    }
}

/// Generate path aliases that web servers often normalize to the same handler.
pub fn generate_path_aliases(path: &str) -> Vec<String> {
    let mut aliases = Vec::new();

    let trailing = if path.ends_with('/') {
        path.trim_end_matches('/').to_string()
    } else {
        format!("{path}/")
    };
    aliases.push(trailing);

    if let Some(pos) = path.rfind('/') {
        let prefix = &path[..=pos];
        let suffix = &path[pos + 1..];
        aliases.push(format!("{prefix}/{suffix}"));
    }

    aliases.push(format!("/.{}", path.trim_start_matches('/')));

    let with_param = if path.contains('?') {
        format!("{path}&_={}", 1)
    } else {
        format!("{path}?_={}", 1)
    };
    aliases.push(with_param);

    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() > 2 {
        let mut dotdot_path = String::new();
        for (i, seg) in segments.iter().enumerate() {
            if i == segments.len() - 1 {
                dotdot_path.push_str("dummy/../");
                dotdot_path.push_str(seg);
            } else {
                dotdot_path.push_str(seg);
                if i < segments.len() - 2 {
                    dotdot_path.push('/');
                }
            }
        }
        aliases.push(dotdot_path);
    }

    aliases
}

/// Generate percent-encoded and unicode variations of a path.
/// These resolve to the same endpoint on normalizing servers but
/// appear as distinct strings to path-based rate limiters.
pub fn generate_unicode_variants(path: &str) -> Vec<String> {
    let mut variants = Vec::new();

    let mut encoded = String::new();
    for ch in path.chars() {
        if ch.is_ascii_alphanumeric() {
            encoded.push_str(&format!("%{:02X}", ch as u8));
        } else {
            encoded.push(ch);
        }
    }
    variants.push(encoded);

    let mut partial = String::new();
    for (i, ch) in path.chars().enumerate() {
        if ch.is_ascii_lowercase() && i % 3 == 0 {
            partial.push_str(&format!("%{:02X}", ch as u8));
        } else {
            partial.push(ch);
        }
    }
    variants.push(partial);

    let double_encoded = path.replace('%', "%25");
    if double_encoded != path {
        variants.push(double_encoded);
    }

    let mut mixed_slash = path.replace('/', "%2F");
    if mixed_slash == path {
        mixed_slash = path.replace('/', "%2f");
    }
    variants.push(mixed_slash);

    let utf8_dot = path.replace('.', "\u{FF0E}");
    if utf8_dot != path {
        variants.push(utf8_dot);
    }

    let null_byte_injected = format!("{path}%00");
    variants.push(null_byte_injected);

    let fullwidth = path
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() {
                char::from_u32(0xFF21 + (c as u32 - b'a' as u32)).unwrap_or(c)
            } else {
                c
            }
        })
        .collect::<String>();
    variants.push(fullwidth);

    variants
}

/// Generate case-varied paths that exploit case-insensitive routing
/// with case-sensitive rate limit keys.
pub fn generate_case_variants(path: &str) -> Vec<String> {
    let mut variants = Vec::new();

    variants.push(path.to_uppercase());
    variants.push(path.to_lowercase());

    let alternating: String = path
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_uppercase().next().unwrap_or(c)
            } else {
                c.to_lowercase().next().unwrap_or(c)
            }
        })
        .collect();
    variants.push(alternating);

    let segments: Vec<&str> = path.split('/').collect();
    let capitalized: String = segments
        .iter()
        .map(|seg| {
            let mut chars = seg.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => {
                    let upper: String = first.to_uppercase().collect();
                    upper + &chars.as_str().to_lowercase()
                }
            }
        })
        .collect::<Vec<_>>()
        .join("/");
    variants.push(capitalized);

    variants
}

fn default_ip_pool() -> Vec<String> {
    vec![
        "127.0.0.1".to_string(),
        "10.0.0.1".to_string(),
        "192.168.1.1".to_string(),
        "172.16.0.1".to_string(),
        "10.10.10.1".to_string(),
        "192.168.0.100".to_string(),
        "10.255.255.1".to_string(),
        "172.31.255.1".to_string(),
    ]
}

fn generate_random_ip(rng: &mut StdRng) -> String {
    format!(
        "{}.{}.{}.{}",
        rng.random_range(1u8..=254),
        rng.random_range(0u8..=255),
        rng.random_range(0u8..=255),
        rng.random_range(1u8..=254),
    )
}

fn extract_path_domain(path: &str) -> String {
    let stripped = path
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    stripped
        .split('/')
        .next()
        .unwrap_or("example.com")
        .to_string()
}

/// Count how many distinct IP rotation header names are available.
pub fn ip_header_variant_count() -> usize {
    IP_ROTATION_HEADERS.len()
}

/// Returns all available IP rotation header names.
pub fn ip_rotation_header_names() -> Vec<&'static str> {
    IP_ROTATION_HEADERS.to_vec()
}

/// Summarize which techniques are enabled in a config, keyed by technique.
pub fn technique_summary(config: &RateLimitBypassConfig) -> HashMap<BypassTechnique, bool> {
    let mut map = HashMap::new();
    for t in BypassTechnique::all() {
        map.insert(*t, config.enabled_techniques.contains(t));
    }
    map
}

#[cfg(test)]
#[path = "rate_limit_bypass_test.rs"]
mod rate_limit_bypass_test;
