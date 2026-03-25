use std::collections::HashMap;
use std::fmt;

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

/// Cloud CDN provider for domain fronting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CdnFrontDomain {
    GoogleApis,
    CloudFront,
    AzureCdn,
    Fastly,
    Cloudflare,
    Akamai,
}

impl CdnFrontDomain {
    /// Returns the SNI hostname that will appear on the wire.
    pub fn sni_hostname(&self) -> &'static str {
        match self {
            Self::GoogleApis => "www.googleapis.com",
            Self::CloudFront => "d1234abcde.cloudfront.net",
            Self::AzureCdn => "az-cdn.azureedge.net",
            Self::Fastly => "global.ssl.fastly.net",
            Self::Cloudflare => "cdn.cloudflare.com",
            Self::Akamai => "e9876.dscg.akamaiedge.net",
        }
    }

    /// Returns the Host header that will be sent inside the TLS tunnel.
    pub fn host_header_template(&self) -> &'static str {
        match self {
            Self::GoogleApis => "storage.googleapis.com",
            Self::CloudFront => "d1234abcde.cloudfront.net",
            Self::AzureCdn => "az-cdn.azureedge.net",
            Self::Fastly => "global.ssl.fastly.net",
            Self::Cloudflare => "cdn.cloudflare.com",
            Self::Akamai => "e9876.dscg.akamaiedge.net",
        }
    }
}

impl fmt::Display for CdnFrontDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.sni_hostname())
    }
}

/// Protocol mimicry target for making scan traffic resemble known protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MimicProtocol {
    Https,
    DnsOverHttps,
    Ntp,
    Quic,
    WebSocket,
}

impl fmt::Display for MimicProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Https => write!(f, "HTTPS"),
            Self::DnsOverHttps => write!(f, "DoH"),
            Self::Ntp => write!(f, "NTP"),
            Self::Quic => write!(f, "QUIC"),
            Self::WebSocket => write!(f, "WebSocket"),
        }
    }
}

/// Traffic distribution model for shaping request patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrafficDistribution {
    Pareto,
    LogNormal,
    Uniform,
    Exponential,
}

/// Encrypted SNI/ECH mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SniMode {
    Plaintext,
    Esni,
    Ech,
}

impl fmt::Display for SniMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plaintext => write!(f, "plaintext"),
            Self::Esni => write!(f, "ESNI"),
            Self::Ech => write!(f, "ECH"),
        }
    }
}

/// A domain-fronted request that hides the real target behind a CDN.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontedRequest {
    pub sni_hostname: String,
    pub actual_host: String,
    pub path: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub cdn: CdnFrontDomain,
}

/// Cover traffic entry mixed alongside scan traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverTrafficEntry {
    pub url: String,
    pub referer: Option<String>,
    pub delay_ms: u64,
    pub is_cover: bool,
}

/// Payload embedding strategy for hiding scan payloads inside benign traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EmbeddingStrategy {
    Base64InQueryParam,
    JsonFieldInjection,
    MultipartBoundary,
    ChunkedTransferEncoding,
    CookieValue,
}

impl fmt::Display for EmbeddingStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base64InQueryParam => write!(f, "base64-query"),
            Self::JsonFieldInjection => write!(f, "json-field"),
            Self::MultipartBoundary => write!(f, "multipart"),
            Self::ChunkedTransferEncoding => write!(f, "chunked"),
            Self::CookieValue => write!(f, "cookie"),
        }
    }
}

/// An embedded payload wrapped in a benign-looking request.
#[derive(Debug, Clone)]
pub struct EmbeddedPayload {
    pub strategy: EmbeddingStrategy,
    pub outer_url: String,
    pub outer_content_type: String,
    pub encoded_payload: String,
    pub original_payload: String,
}

/// Bandwidth profile for shaping traffic to match normal user patterns.
#[derive(Debug, Clone)]
pub struct BandwidthProfile {
    pub max_bytes_per_second: u64,
    pub burst_allowance_bytes: u64,
    pub current_window_bytes: u64,
}

impl BandwidthProfile {
    pub fn new(max_bps: u64) -> Self {
        Self {
            max_bytes_per_second: max_bps,
            burst_allowance_bytes: max_bps / 5,
            current_window_bytes: 0,
        }
    }

    /// Returns whether sending `bytes` would exceed the bandwidth limit.
    pub fn would_exceed(&self, bytes: u64) -> bool {
        self.current_window_bytes + bytes > self.max_bytes_per_second + self.burst_allowance_bytes
    }

    /// Records bytes sent in the current window.
    pub fn record_sent(&mut self, bytes: u64) {
        self.current_window_bytes += bytes;
    }

    /// Resets the window (called on each new second).
    pub fn reset_window(&mut self) {
        self.current_window_bytes = 0;
    }

    /// Returns utilization ratio 0.0..=1.0+.
    pub fn utilization(&self) -> f64 {
        if self.max_bytes_per_second == 0 {
            return 0.0;
        }
        self.current_window_bytes as f64 / self.max_bytes_per_second as f64
    }
}

/// Configuration for the traffic camouflage engine.
#[derive(Debug, Clone)]
pub struct CamouflageConfig {
    pub domain_fronting_enabled: bool,
    pub preferred_cdn: CdnFrontDomain,
    pub sni_mode: SniMode,
    pub traffic_distribution: TrafficDistribution,
    pub cover_traffic_ratio: f64,
    pub max_bandwidth_bps: u64,
    pub mimic_protocol: MimicProtocol,
    pub embedding_strategy: EmbeddingStrategy,
}

impl Default for CamouflageConfig {
    fn default() -> Self {
        Self {
            domain_fronting_enabled: true,
            preferred_cdn: CdnFrontDomain::CloudFront,
            sni_mode: SniMode::Ech,
            traffic_distribution: TrafficDistribution::Pareto,
            cover_traffic_ratio: 0.7,
            max_bandwidth_bps: 1_000_000,
            mimic_protocol: MimicProtocol::Https,
            embedding_strategy: EmbeddingStrategy::Base64InQueryParam,
        }
    }
}

impl CamouflageConfig {
    pub fn with_cdn(mut self, cdn: CdnFrontDomain) -> Self {
        self.preferred_cdn = cdn;
        self
    }

    pub fn with_sni_mode(mut self, mode: SniMode) -> Self {
        self.sni_mode = mode;
        self
    }

    pub fn with_cover_ratio(mut self, ratio: f64) -> Self {
        self.cover_traffic_ratio = ratio.clamp(0.0, 1.0);
        self
    }

    pub fn with_distribution(mut self, dist: TrafficDistribution) -> Self {
        self.traffic_distribution = dist;
        self
    }

    pub fn with_max_bandwidth(mut self, bps: u64) -> Self {
        self.max_bandwidth_bps = bps;
        self
    }

    pub fn with_mimic(mut self, protocol: MimicProtocol) -> Self {
        self.mimic_protocol = protocol;
        self
    }

    pub fn with_embedding(mut self, strategy: EmbeddingStrategy) -> Self {
        self.embedding_strategy = strategy;
        self
    }
}

/// Popular sites for cover traffic generation.
const COVER_SITES: &[&str] = &[
    "https://www.google.com/search?q=weather",
    "https://www.youtube.com/",
    "https://www.reddit.com/r/popular",
    "https://www.wikipedia.org/",
    "https://news.ycombinator.com/",
    "https://www.amazon.com/",
    "https://twitter.com/home",
    "https://www.github.com/",
    "https://stackoverflow.com/",
    "https://www.linkedin.com/feed/",
];

/// Traffic camouflage engine that makes scan traffic indistinguishable
/// from normal browsing patterns through domain fronting, cover traffic,
/// payload embedding, protocol mimicry, and bandwidth shaping.
pub struct TrafficCamouflageEngine {
    config: CamouflageConfig,
    bandwidth: BandwidthProfile,
    rng: StdRng,
    requests_sent: u64,
    cover_requests_sent: u64,
    scan_requests_sent: u64,
    cover_site_index: usize,
}

impl TrafficCamouflageEngine {
    pub fn new(config: CamouflageConfig) -> Self {
        let bps = config.max_bandwidth_bps;
        Self {
            config,
            bandwidth: BandwidthProfile::new(bps),
            rng: StdRng::from_os_rng(),
            requests_sent: 0,
            cover_requests_sent: 0,
            scan_requests_sent: 0,
            cover_site_index: 0,
        }
    }

    pub fn with_seed(config: CamouflageConfig, seed: u64) -> Self {
        let bps = config.max_bandwidth_bps;
        Self {
            config,
            bandwidth: BandwidthProfile::new(bps),
            rng: StdRng::seed_from_u64(seed),
            requests_sent: 0,
            cover_requests_sent: 0,
            scan_requests_sent: 0,
            cover_site_index: 0,
        }
    }

    /// Creates a domain-fronted request that hides the real target behind a CDN domain.
    pub fn create_fronted_request(
        &self,
        actual_target: &str,
        path: &str,
        method: &str,
        body: Option<&[u8]>,
    ) -> FrontedRequest {
        let cdn = self.config.preferred_cdn;
        let mut headers = HashMap::new();
        headers.insert("Host".to_string(), actual_target.to_string());
        headers.insert(
            "User-Agent".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
        );
        headers.insert(
            "Accept".to_string(),
            "text/html,application/json".to_string(),
        );
        headers.insert("Accept-Language".to_string(), "en-US,en;q=0.9".to_string());

        FrontedRequest {
            sni_hostname: cdn.sni_hostname().to_string(),
            actual_host: actual_target.to_string(),
            path: path.to_string(),
            method: method.to_string(),
            headers,
            body: body.map(|b| b.to_vec()),
            cdn,
        }
    }

    /// Generates cover traffic entries mixed with scan traffic to mask scan patterns.
    /// Returns a mixed schedule of cover and scan requests.
    pub fn generate_traffic_schedule(&mut self, scan_urls: &[&str]) -> Vec<CoverTrafficEntry> {
        let mut schedule: Vec<CoverTrafficEntry> = Vec::new();

        for url in scan_urls {
            let cover_count = (self.config.cover_traffic_ratio * 3.0).ceil() as usize;
            for _ in 0..cover_count {
                let cover_url = COVER_SITES[self.cover_site_index % COVER_SITES.len()];
                self.cover_site_index += 1;
                let delay = self.shaped_delay();
                schedule.push(CoverTrafficEntry {
                    url: cover_url.to_string(),
                    referer: Some("https://www.google.com/".to_string()),
                    delay_ms: delay,
                    is_cover: true,
                });
                self.cover_requests_sent += 1;
            }

            let delay = self.shaped_delay();
            schedule.push(CoverTrafficEntry {
                url: url.to_string(),
                referer: Some(COVER_SITES[self.rng.random_range(0..COVER_SITES.len())].to_string()),
                delay_ms: delay,
                is_cover: false,
            });
            self.scan_requests_sent += 1;
        }

        self.requests_sent += schedule.len() as u64;
        schedule
    }

    /// Embeds a scan payload inside a benign-looking request.
    pub fn embed_payload(&self, payload: &str, target_url: &str) -> EmbeddedPayload {
        match self.config.embedding_strategy {
            EmbeddingStrategy::Base64InQueryParam => {
                let encoded = base64_encode(payload.as_bytes());
                EmbeddedPayload {
                    strategy: EmbeddingStrategy::Base64InQueryParam,
                    outer_url: format!("{target_url}?q={encoded}&lang=en"),
                    outer_content_type: "text/html".to_string(),
                    encoded_payload: encoded,
                    original_payload: payload.to_string(),
                }
            }
            EmbeddingStrategy::JsonFieldInjection => {
                let encoded = base64_encode(payload.as_bytes());
                EmbeddedPayload {
                    strategy: EmbeddingStrategy::JsonFieldInjection,
                    outer_url: target_url.to_string(),
                    outer_content_type: "application/json".to_string(),
                    encoded_payload: format!(
                        r#"{{"preferences":{{"theme":"dark","locale":"en","data":"{encoded}"}}}}"#
                    ),
                    original_payload: payload.to_string(),
                }
            }
            EmbeddingStrategy::MultipartBoundary => {
                let boundary = "----WebKitFormBoundaryABC123";
                let encoded = base64_encode(payload.as_bytes());
                EmbeddedPayload {
                    strategy: EmbeddingStrategy::MultipartBoundary,
                    outer_url: target_url.to_string(),
                    outer_content_type: format!("multipart/form-data; boundary={boundary}"),
                    encoded_payload: format!(
                        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"photo.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n{encoded}\r\n--{boundary}--"
                    ),
                    original_payload: payload.to_string(),
                }
            }
            EmbeddingStrategy::ChunkedTransferEncoding => {
                let encoded = base64_encode(payload.as_bytes());
                let chunk_len = encoded.len();
                EmbeddedPayload {
                    strategy: EmbeddingStrategy::ChunkedTransferEncoding,
                    outer_url: target_url.to_string(),
                    outer_content_type: "text/html".to_string(),
                    encoded_payload: format!("{chunk_len:x}\r\n{encoded}\r\n0\r\n\r\n"),
                    original_payload: payload.to_string(),
                }
            }
            EmbeddingStrategy::CookieValue => {
                let encoded = base64_encode(payload.as_bytes());
                EmbeddedPayload {
                    strategy: EmbeddingStrategy::CookieValue,
                    outer_url: target_url.to_string(),
                    outer_content_type: "text/html".to_string(),
                    encoded_payload: format!("session={encoded}; Path=/; HttpOnly"),
                    original_payload: payload.to_string(),
                }
            }
        }
    }

    /// Returns protocol mimicry headers for the configured protocol.
    pub fn mimic_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        match self.config.mimic_protocol {
            MimicProtocol::Https => {
                headers.insert(
                    "Accept".to_string(),
                    "text/html,application/xhtml+xml".to_string(),
                );
                headers.insert(
                    "Accept-Encoding".to_string(),
                    "gzip, deflate, br".to_string(),
                );
                headers.insert("Connection".to_string(), "keep-alive".to_string());
                headers.insert("Upgrade-Insecure-Requests".to_string(), "1".to_string());
            }
            MimicProtocol::DnsOverHttps => {
                headers.insert("Accept".to_string(), "application/dns-message".to_string());
                headers.insert(
                    "Content-Type".to_string(),
                    "application/dns-message".to_string(),
                );
            }
            MimicProtocol::Ntp => {
                headers.insert("X-NTP-Mode".to_string(), "client".to_string());
                headers.insert(
                    "Content-Type".to_string(),
                    "application/octet-stream".to_string(),
                );
            }
            MimicProtocol::Quic => {
                headers.insert("Alt-Svc".to_string(), "h3=\":443\"".to_string());
                headers.insert("Accept".to_string(), "text/html".to_string());
            }
            MimicProtocol::WebSocket => {
                headers.insert("Upgrade".to_string(), "websocket".to_string());
                headers.insert("Connection".to_string(), "Upgrade".to_string());
                headers.insert("Sec-WebSocket-Version".to_string(), "13".to_string());
                headers.insert(
                    "Sec-WebSocket-Key".to_string(),
                    "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
                );
            }
        }
        headers
    }

    /// Returns current bandwidth utilization ratio.
    pub fn bandwidth_utilization(&self) -> f64 {
        self.bandwidth.utilization()
    }

    /// Checks if sending `bytes` would exceed bandwidth limits.
    pub fn would_exceed_bandwidth(&self, bytes: u64) -> bool {
        self.bandwidth.would_exceed(bytes)
    }

    /// Records bytes sent for bandwidth tracking.
    pub fn record_bytes_sent(&mut self, bytes: u64) {
        self.bandwidth.record_sent(bytes);
    }

    /// Resets the bandwidth window (call once per second).
    pub fn reset_bandwidth_window(&mut self) {
        self.bandwidth.reset_window();
    }

    /// Returns total requests sent (cover + scan).
    pub fn total_requests(&self) -> u64 {
        self.requests_sent
    }

    /// Returns cover-to-scan request ratio.
    pub fn cover_scan_ratio(&self) -> f64 {
        if self.scan_requests_sent == 0 {
            return 0.0;
        }
        self.cover_requests_sent as f64 / self.scan_requests_sent as f64
    }

    /// Returns the configured SNI mode.
    pub fn sni_mode(&self) -> SniMode {
        self.config.sni_mode
    }

    fn shaped_delay(&mut self) -> u64 {
        match self.config.traffic_distribution {
            TrafficDistribution::Pareto => {
                let alpha = 1.5_f64;
                let u: f64 = self.rng.random_range(0.01..1.0);
                let pareto = 100.0 / u.powf(1.0 / alpha);
                pareto.min(10000.0) as u64
            }
            TrafficDistribution::LogNormal => {
                let mu = 5.5_f64;
                let sigma = 1.0_f64;
                let u1: f64 = self.rng.random_range(0.01..1.0);
                let u2: f64 = self.rng.random_range(0.01..1.0);
                let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
                let val = (mu + sigma * z).exp();
                val.min(10000.0) as u64
            }
            TrafficDistribution::Uniform => self.rng.random_range(100..2000),
            TrafficDistribution::Exponential => {
                let lambda = 0.005;
                let u: f64 = self.rng.random_range(0.01..1.0);
                let val = -u.ln() / lambda;
                val.min(10000.0) as u64
            }
        }
    }
}

/// Simple base64 encoding without external dependency.
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() {
            data[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < data.len() {
            data[i + 2] as u32
        } else {
            0
        };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if i + 1 < data.len() {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if i + 2 < data.len() {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        i += 3;
    }
    result
}
