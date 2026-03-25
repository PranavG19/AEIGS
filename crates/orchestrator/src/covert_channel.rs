use std::fmt;

use serde::{Deserialize, Serialize};

/// Types of covert communication channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChannelType {
    DnsTunnel,
    HttpsTunnel,
    Steganography,
    DomainFronting,
    DeadDrop,
    TimingChannel,
}

impl fmt::Display for ChannelType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::DnsTunnel => "DNS Tunnel",
            Self::HttpsTunnel => "HTTPS Tunnel",
            Self::Steganography => "Steganography",
            Self::DomainFronting => "Domain Fronting",
            Self::DeadDrop => "Dead Drop",
            Self::TimingChannel => "Timing Channel",
        };
        write!(f, "{label}")
    }
}

/// Detection difficulty rating for a covert channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DetectionDifficulty {
    Low,
    Medium,
    High,
    VeryHigh,
}

impl fmt::Display for DetectionDifficulty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::VeryHigh => "Very High",
        };
        write!(f, "{label}")
    }
}

/// Specification for a covert communication channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelSpec {
    pub channel_type: ChannelType,
    pub description: String,
    pub capacity_bytes_per_sec: f64,
    pub detection_difficulty: DetectionDifficulty,
    pub reliability: f64,
    pub latency_ms: u64,
    pub requires_infrastructure: bool,
    pub infrastructure_details: Vec<String>,
    pub countermeasures: Vec<String>,
}

/// DNS tunnel configuration for encoding data in DNS queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsTunnelConfig {
    pub nameserver: String,
    pub base_domain: String,
    pub encoding: DnsEncoding,
    pub max_label_length: usize,
    pub query_type: DnsQueryType,
    pub jitter_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsEncoding {
    Base32,
    Base64,
    Hex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsQueryType {
    A,
    AAAA,
    TXT,
    CNAME,
    MX,
}

impl Default for DnsTunnelConfig {
    fn default() -> Self {
        Self {
            nameserver: String::new(),
            base_domain: String::new(),
            encoding: DnsEncoding::Base32,
            max_label_length: 63,
            query_type: DnsQueryType::TXT,
            jitter_ms: 500,
        }
    }
}

/// Encode data for DNS tunnel transport using base32-like encoding.
pub fn dns_tunnel_encode(data: &[u8], base_domain: &str, max_label_len: usize) -> Vec<String> {
    let effective_label_len = max_label_len.min(63).max(1);
    let encoded = base32_encode(data);
    let mut queries = Vec::new();
    let mut offset = 0;
    let mut seq = 0u32;

    while offset < encoded.len() {
        let prefix = format!("{seq:04x}.");
        let available = effective_label_len.saturating_sub(prefix.len());
        if available == 0 {
            break;
        }
        let chunk_end = (offset + available).min(encoded.len());
        let chunk = &encoded[offset..chunk_end];
        let query = format!("{prefix}{chunk}.{base_domain}");
        queries.push(query);
        offset = chunk_end;
        seq += 1;
    }
    queries
}

/// Decode DNS tunnel queries back to original data.
pub fn dns_tunnel_decode(queries: &[String], base_domain: &str) -> Option<Vec<u8>> {
    let suffix = format!(".{base_domain}");
    let mut parts: Vec<(u32, String)> = Vec::new();

    for query in queries {
        let stripped = query.strip_suffix(&suffix)?;
        let dot_pos = stripped.find('.')?;
        let seq_str = &stripped[..dot_pos];
        let seq = u32::from_str_radix(seq_str, 16).ok()?;
        let data_part = &stripped[dot_pos + 1..];
        parts.push((seq, data_part.to_string()));
    }
    parts.sort_by_key(|(seq, _)| *seq);

    let encoded: String = parts.into_iter().map(|(_, d)| d).collect();
    base32_decode(&encoded)
}

fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            result.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        result.push(ALPHABET[idx] as char);
    }
    result
}

fn base32_decode(encoded: &str) -> Option<Vec<u8>> {
    let mut buffer: u64 = 0;
    let mut bits = 0;
    let mut result = Vec::new();

    for ch in encoded.chars() {
        let val = match ch {
            'a'..='z' => (ch as u8 - b'a') as u64,
            '2'..='7' => (ch as u8 - b'2' + 26) as u64,
            _ => return None,
        };
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
        }
    }
    Some(result)
}

/// HTTPS tunnel configuration using CDN relays.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpsTunnelConfig {
    pub relay_type: CdnRelay,
    pub relay_url: String,
    pub encryption: TunnelEncryption,
    pub max_payload_bytes: usize,
    pub polling_interval_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CdnRelay {
    CloudflareWorker,
    AwsLambda,
    AzureFunction,
    GcpCloudRun,
    VercelEdge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelEncryption {
    Aes256Gcm,
    ChaCha20Poly1305,
    XSalsa20Poly1305,
}

/// Steganography configuration for hiding data in images.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteganographyConfig {
    pub method: StegoMethod,
    pub bits_per_pixel: u8,
    pub carrier_format: ImageFormat,
    pub max_payload_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StegoMethod {
    LsbReplacement,
    LsbMatching,
    DctCoefficient,
    SpreadSpectrum,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageFormat {
    Png,
    Bmp,
    Tiff,
}

/// Encode data into LSB of pixel bytes (simplified model).
pub fn lsb_encode(carrier: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
    let required_bits = payload.len() * 8 + 32;
    if carrier.len() < required_bits {
        return None;
    }
    let mut output = carrier.to_vec();
    let len_bytes = (payload.len() as u32).to_be_bytes();
    let all_bytes: Vec<u8> = len_bytes.iter().chain(payload.iter()).copied().collect();

    let mut bit_idx = 0;
    for byte in &all_bytes {
        for bit_pos in (0..8).rev() {
            let bit = (byte >> bit_pos) & 1;
            output[bit_idx] = (output[bit_idx] & 0xFE) | bit;
            bit_idx += 1;
        }
    }
    Some(output)
}

/// Decode data from LSB of pixel bytes.
pub fn lsb_decode(stego_data: &[u8]) -> Option<Vec<u8>> {
    if stego_data.len() < 32 {
        return None;
    }
    let mut len_bits = [0u8; 4];
    for (i, byte) in len_bits.iter_mut().enumerate() {
        for bit_pos in (0..8).rev() {
            let bit_idx = i * 8 + (7 - bit_pos);
            *byte |= (stego_data[bit_idx] & 1) << bit_pos;
        }
    }
    let payload_len = u32::from_be_bytes(len_bits) as usize;
    let required = 32 + payload_len * 8;
    if stego_data.len() < required {
        return None;
    }
    let mut payload = vec![0u8; payload_len];
    for (i, byte) in payload.iter_mut().enumerate() {
        for bit_pos in (0..8).rev() {
            let bit_idx = 32 + i * 8 + (7 - bit_pos);
            *byte |= (stego_data[bit_idx] & 1) << bit_pos;
        }
    }
    Some(payload)
}

/// Domain fronting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainFrontingConfig {
    pub front_domain: String,
    pub actual_host: String,
    pub sni_domain: String,
    pub path_prefix: String,
}

/// Known CDN providers that support (or historically supported) domain fronting.
pub fn domain_fronting_candidates() -> Vec<DomainFrontingConfig> {
    vec![
        DomainFrontingConfig {
            front_domain: "cdn.example-cdn.net".to_string(),
            actual_host: "c2.attacker.com".to_string(),
            sni_domain: "cdn.example-cdn.net".to_string(),
            path_prefix: "/api/v1/".to_string(),
        },
        DomainFrontingConfig {
            front_domain: "static.example-cloud.com".to_string(),
            actual_host: "c2.attacker.com".to_string(),
            sni_domain: "static.example-cloud.com".to_string(),
            path_prefix: "/content/".to_string(),
        },
    ]
}

/// Dead drop configuration using public services as message relays.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadDropConfig {
    pub service: DeadDropService,
    pub identifier: String,
    pub encoding: DeadDropEncoding,
    pub polling_interval_ms: u64,
    pub max_message_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DeadDropService {
    GithubIssue,
    Pastebin,
    DiscordWebhook,
    TelegramChannel,
    RedditPost,
}

impl fmt::Display for DeadDropService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::GithubIssue => "GitHub Issue",
            Self::Pastebin => "Pastebin",
            Self::DiscordWebhook => "Discord Webhook",
            Self::TelegramChannel => "Telegram Channel",
            Self::RedditPost => "Reddit Post",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeadDropEncoding {
    Base64,
    Hex,
    Steganographic,
    NaturalLanguage,
}

/// Timing channel configuration for encoding data in request timing patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingChannelConfig {
    pub bit_duration_ms: u64,
    pub zero_delay_ms: u64,
    pub one_delay_ms: u64,
    pub sync_pattern: Vec<bool>,
    pub error_correction: bool,
}

impl Default for TimingChannelConfig {
    fn default() -> Self {
        Self {
            bit_duration_ms: 100,
            zero_delay_ms: 50,
            one_delay_ms: 150,
            sync_pattern: vec![true, false, true, false, true, true],
            error_correction: true,
        }
    }
}

/// Encode data into timing delays for a timing channel.
pub fn timing_channel_encode(data: &[u8], config: &TimingChannelConfig) -> Vec<u64> {
    let mut delays = Vec::new();
    for bit in &config.sync_pattern {
        delays.push(if *bit {
            config.one_delay_ms
        } else {
            config.zero_delay_ms
        });
    }
    for byte in data {
        for bit_pos in (0..8).rev() {
            let bit = (byte >> bit_pos) & 1;
            delays.push(if bit == 1 {
                config.one_delay_ms
            } else {
                config.zero_delay_ms
            });
        }
    }
    delays
}

/// Decode timing delays back to data bytes.
pub fn timing_channel_decode(delays: &[u64], config: &TimingChannelConfig) -> Option<Vec<u8>> {
    let sync_len = config.sync_pattern.len();
    if delays.len() < sync_len {
        return None;
    }
    let threshold = (config.zero_delay_ms + config.one_delay_ms) / 2;
    let data_delays = &delays[sync_len..];
    let bit_count = data_delays.len();
    let byte_count = bit_count / 8;
    let mut result = vec![0u8; byte_count];

    for (i, delay) in data_delays.iter().enumerate().take(byte_count * 8) {
        let byte_idx = i / 8;
        let bit_pos = 7 - (i % 8);
        if *delay > threshold {
            result[byte_idx] |= 1 << bit_pos;
        }
    }
    Some(result)
}

/// Build a complete channel specification for a given channel type.
pub fn build_channel_spec(channel_type: ChannelType) -> ChannelSpec {
    match channel_type {
        ChannelType::DnsTunnel => ChannelSpec {
            channel_type,
            description: "Encode exfiltrated data in DNS queries to an attacker-controlled \
                          nameserver. Data hidden in subdomain labels using base32 encoding."
                .to_string(),
            capacity_bytes_per_sec: 15.0,
            detection_difficulty: DetectionDifficulty::Medium,
            reliability: 0.95,
            latency_ms: 200,
            requires_infrastructure: true,
            infrastructure_details: vec![
                "Attacker-controlled authoritative nameserver".to_string(),
                "Registered domain with NS records pointing to attacker NS".to_string(),
            ],
            countermeasures: vec![
                "DNS traffic analysis for unusual query patterns".to_string(),
                "DNS query length anomaly detection".to_string(),
                "Block external DNS resolvers".to_string(),
            ],
        },
        ChannelType::HttpsTunnel => ChannelSpec {
            channel_type,
            description: "Tunnel data through HTTPS connections to legitimate CDN endpoints. \
                          Data encrypted and embedded in normal-looking API calls."
                .to_string(),
            capacity_bytes_per_sec: 10240.0,
            detection_difficulty: DetectionDifficulty::High,
            reliability: 0.99,
            latency_ms: 100,
            requires_infrastructure: true,
            infrastructure_details: vec![
                "CDN worker/function endpoint (Cloudflare Worker, AWS Lambda)".to_string(),
                "Proxy relay logic deployed to CDN edge".to_string(),
            ],
            countermeasures: vec![
                "Deep packet inspection of TLS metadata".to_string(),
                "CDN usage anomaly detection".to_string(),
                "Certificate transparency monitoring".to_string(),
            ],
        },
        ChannelType::Steganography => ChannelSpec {
            channel_type,
            description: "Hide data in least significant bits of image pixels. Images posted to \
                          public platforms appear normal to humans and automated scanners."
                .to_string(),
            capacity_bytes_per_sec: 1.0,
            detection_difficulty: DetectionDifficulty::VeryHigh,
            reliability: 0.85,
            latency_ms: 5000,
            requires_infrastructure: false,
            infrastructure_details: vec!["Public image hosting platform account".to_string()],
            countermeasures: vec![
                "Statistical steganalysis on uploaded images".to_string(),
                "Chi-square analysis of LSB distributions".to_string(),
            ],
        },
        ChannelType::DomainFronting => ChannelSpec {
            channel_type,
            description: "Use high-reputation CDN domains in TLS SNI while routing to actual \
                          C2 via HTTP Host header. Appears as traffic to trusted services."
                .to_string(),
            capacity_bytes_per_sec: 5120.0,
            detection_difficulty: DetectionDifficulty::High,
            reliability: 0.70,
            latency_ms: 150,
            requires_infrastructure: true,
            infrastructure_details: vec![
                "CDN account with the same provider as front domain".to_string(),
                "Backend server accessible through CDN".to_string(),
            ],
            countermeasures: vec![
                "Compare TLS SNI with HTTP Host header".to_string(),
                "Block known domain fronting CDN providers".to_string(),
            ],
        },
        ChannelType::DeadDrop => ChannelSpec {
            channel_type,
            description: "Use public services (GitHub issues, Pastebin, Discord webhooks) as \
                          asynchronous message relays. Data encoded to blend with normal content."
                .to_string(),
            capacity_bytes_per_sec: 5.0,
            detection_difficulty: DetectionDifficulty::High,
            reliability: 0.90,
            latency_ms: 10000,
            requires_infrastructure: false,
            infrastructure_details: vec!["Account on chosen public service".to_string()],
            countermeasures: vec![
                "Monitor for unusual API access patterns to public services".to_string(),
                "Content analysis of posts for encoded data".to_string(),
            ],
        },
        ChannelType::TimingChannel => ChannelSpec {
            channel_type,
            description: "Encode data in the timing patterns of otherwise normal HTTP requests. \
                          Bits represented by inter-request delays."
                .to_string(),
            capacity_bytes_per_sec: 0.5,
            detection_difficulty: DetectionDifficulty::VeryHigh,
            reliability: 0.70,
            latency_ms: 20000,
            requires_infrastructure: false,
            infrastructure_details: vec![
                "Target must be accessible for repeated requests".to_string()
            ],
            countermeasures: vec![
                "Statistical analysis of request timing distributions".to_string(),
                "Request rate normalization".to_string(),
            ],
        },
    }
}

/// Rank all channel types by a combined score of capacity, stealth, and reliability.
pub fn rank_channels() -> Vec<(ChannelType, f64)> {
    let channels = [
        ChannelType::DnsTunnel,
        ChannelType::HttpsTunnel,
        ChannelType::Steganography,
        ChannelType::DomainFronting,
        ChannelType::DeadDrop,
        ChannelType::TimingChannel,
    ];
    let mut ranked: Vec<(ChannelType, f64)> = channels
        .iter()
        .map(|ct| {
            let spec = build_channel_spec(*ct);
            let stealth_score = match spec.detection_difficulty {
                DetectionDifficulty::Low => 0.2,
                DetectionDifficulty::Medium => 0.5,
                DetectionDifficulty::High => 0.8,
                DetectionDifficulty::VeryHigh => 1.0,
            };
            let capacity_score = (spec.capacity_bytes_per_sec.ln() / 10.0).clamp(0.0, 1.0);
            let combined = 0.4 * stealth_score + 0.3 * capacity_score + 0.3 * spec.reliability;
            (*ct, combined)
        })
        .collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    ranked
}

#[cfg(test)]
#[path = "covert_channel_test.rs"]
mod tests;
