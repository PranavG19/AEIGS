use aegis_protocol::finding::VulnerabilityClass;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::mutator::{MutationOrigin, TaggedPayload};

/// Protocol type for streaming endpoint fuzzing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamProtocol {
    WebSocket,
    ServerSentEvents,
}

impl std::fmt::Display for StreamProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WebSocket => write!(f, "WebSocket"),
            Self::ServerSentEvents => write!(f, "Server-Sent Events"),
        }
    }
}

/// Direction of a message in a streaming connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageDirection {
    Sent,
    Received,
}

impl std::fmt::Display for MessageDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sent => write!(f, "Sent"),
            Self::Received => write!(f, "Received"),
        }
    }
}

/// Type of a message in a streaming connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamMessageType {
    Text,
    Binary,
    Ping,
    Pong,
    Event,
}

impl std::fmt::Display for StreamMessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text => write!(f, "Text"),
            Self::Binary => write!(f, "Binary"),
            Self::Ping => write!(f, "Ping"),
            Self::Pong => write!(f, "Pong"),
            Self::Event => write!(f, "Event"),
        }
    }
}

/// A single message captured during a streaming fuzzing session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamMessage {
    pub sequence: u64,
    pub direction: MessageDirection,
    pub payload: String,
    pub timestamp_ms: u64,
    pub message_type: StreamMessageType,
}

/// A target for streaming protocol fuzzing.
#[derive(Debug, Clone)]
pub struct StreamFuzzTarget {
    pub endpoint: String,
    pub protocol: StreamProtocol,
    pub vulnerability_class: VulnerabilityClass,
    pub priority_score: f64,
    pub handshake_headers: Vec<(String, String)>,
}

/// Anomaly types specific to streaming protocol analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StreamAnomalyType {
    UnexpectedClose,
    ErrorMessage,
    ReflectionDetected,
    TimingAnomaly,
    ProtocolViolation,
    InformationLeak,
}

impl std::fmt::Display for StreamAnomalyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedClose => write!(f, "Unexpected Close"),
            Self::ErrorMessage => write!(f, "Error Message"),
            Self::ReflectionDetected => write!(f, "Reflection Detected"),
            Self::TimingAnomaly => write!(f, "Timing Anomaly"),
            Self::ProtocolViolation => write!(f, "Protocol Violation"),
            Self::InformationLeak => write!(f, "Information Leak"),
        }
    }
}

/// An anomaly detected during streaming protocol fuzzing.
#[derive(Debug, Clone)]
pub struct StreamAnomaly {
    pub target: StreamFuzzTarget,
    pub anomaly_type: StreamAnomalyType,
    pub score: f64,
    pub trigger_message: StreamMessage,
    pub evidence_messages: Vec<StreamMessage>,
    pub description: String,
}

/// Result of a streaming fuzzing session against a single target.
#[derive(Debug, Clone)]
pub struct StreamFuzzResult {
    pub target: StreamFuzzTarget,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub anomalies: Vec<StreamAnomaly>,
    pub connection_duration_ms: u64,
    pub protocol: StreamProtocol,
}

/// Errors that can occur during streaming protocol fuzzing.
#[derive(Debug)]
pub enum StreamFuzzError {
    ConnectionFailed(String),
    HandshakeFailed(String),
    TargetNotAllowed(String),
    Timeout(String),
    ProtocolError(String),
}

impl std::fmt::Display for StreamFuzzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionFailed(msg) => write!(f, "connection failed: {msg}"),
            Self::HandshakeFailed(msg) => write!(f, "handshake failed: {msg}"),
            Self::TargetNotAllowed(msg) => write!(f, "target not allowed: {msg}"),
            Self::Timeout(msg) => write!(f, "timeout: {msg}"),
            Self::ProtocolError(msg) => write!(f, "protocol error: {msg}"),
        }
    }
}

impl std::error::Error for StreamFuzzError {}

/// Validates a streaming target URL is localhost and detects the protocol.
///
/// Accepts `ws://`, `wss://` (WebSocket) and `http://`, `https://` (SSE).
/// Rejects any non-localhost host.
pub fn validate_stream_target(endpoint: &str) -> Result<StreamProtocol, StreamFuzzError> {
    let parsed =
        Url::parse(endpoint).map_err(|e| StreamFuzzError::TargetNotAllowed(e.to_string()))?;

    let host = parsed
        .host_str()
        .ok_or_else(|| StreamFuzzError::TargetNotAllowed("missing host".to_string()))?;

    if !is_localhost(host) {
        return Err(StreamFuzzError::TargetNotAllowed(format!(
            "host is not localhost: {host}"
        )));
    }

    match parsed.scheme() {
        "ws" | "wss" => Ok(StreamProtocol::WebSocket),
        "http" | "https" => Ok(StreamProtocol::ServerSentEvents),
        other => Err(StreamFuzzError::TargetNotAllowed(format!(
            "unsupported scheme: {other}"
        ))),
    }
}

fn is_localhost(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    matches!(lower.as_str(), "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

/// Generates WebSocket-specific payloads for a given vulnerability class.
///
/// Payloads are JSON-wrapped where appropriate for WebSocket message framing.
/// Returns at most `count` payloads, all tagged with `MutationOrigin::Template`.
pub fn generate_ws_payloads(class: VulnerabilityClass, count: usize) -> Vec<TaggedPayload> {
    let mut templates = class_specific_ws_templates(class);
    templates.extend(universal_ws_templates());

    templates
        .into_iter()
        .take(count)
        .map(|payload| TaggedPayload {
            payload,
            origin: MutationOrigin::Template,
        })
        .collect()
}

fn class_specific_ws_templates(class: VulnerabilityClass) -> Vec<String> {
    match class {
        VulnerabilityClass::CrossSiteScripting => vec![
            "<img src=x onerror=alert(1)>".to_string(),
            r#"{"msg":"<script>alert(1)</script>"}"#.to_string(),
            r#"{"content":"<svg onload=alert(1)>"}"#.to_string(),
            r#"{"text":"'\"><script>alert(1)</script>"}"#.to_string(),
        ],
        VulnerabilityClass::SqlInjection => vec![
            r#"{"query":"' OR 1=1--"}"#.to_string(),
            r#"{"id":"1 UNION SELECT null,null--"}"#.to_string(),
            r#"{"search":"'; DROP TABLE users;--"}"#.to_string(),
            r#"{"filter":"1' AND SLEEP(5)--"}"#.to_string(),
        ],
        VulnerabilityClass::CommandInjection => vec![
            r#"{"cmd":"$(whoami)"}"#.to_string(),
            r#"{"path":"; ls -la"}"#.to_string(),
            r#"{"input":"| cat /etc/passwd"}"#.to_string(),
            r#"{"exec":"`id`"}"#.to_string(),
        ],
        VulnerabilityClass::PathTraversal => vec![
            r#"{"file":"../../../etc/passwd"}"#.to_string(),
            r#"{"path":"..\\..\\..\\windows\\system32"}"#.to_string(),
        ],
        VulnerabilityClass::ServerSideTemplateInjection => vec![
            r#"{"template":"{{7*7}}"}"#.to_string(),
            r#"{"input":"${7*7}"}"#.to_string(),
        ],
        _ => vec![r#"{"input":"FUZZ"}"#.to_string()],
    }
}

fn universal_ws_templates() -> Vec<String> {
    vec![
        "A".repeat(65536),
        r#"{"key": "value""#.to_string(),
        "null\0byte\0injection".to_string(),
        "\u{FEFF}\u{202E}unicode_direction_override".to_string(),
    ]
}

/// Generates SSE-specific probe URLs from a base endpoint.
///
/// Appends common SSE path variations and query parameter injection vectors.
pub fn generate_sse_probe_urls(base_endpoint: &str) -> Vec<String> {
    let base = base_endpoint.trim_end_matches('/');
    let path_suffixes = ["/events", "/stream", "/sse", "/subscribe", "/feed"];

    let mut urls: Vec<String> = path_suffixes
        .iter()
        .map(|suffix| format!("{base}{suffix}"))
        .collect();

    urls.push(format!("{base}?event=<script>alert(1)</script>"));
    urls.push(format!("{base}?channel=../../../etc/passwd"));
    urls
}

/// Analyzes a stream of messages for anomalies triggered by a specific payload.
///
/// Returns a list of detected anomaly types based on message content and patterns.
pub fn analyze_stream_messages(
    messages: &[StreamMessage],
    payload: &str,
) -> Vec<StreamAnomalyType> {
    let mut anomalies = Vec::new();

    let received: Vec<&StreamMessage> = messages
        .iter()
        .filter(|m| m.direction == MessageDirection::Received)
        .collect();

    if has_reflection(&received, payload) {
        anomalies.push(StreamAnomalyType::ReflectionDetected);
    }
    if has_error_message(&received) {
        anomalies.push(StreamAnomalyType::ErrorMessage);
    }
    if has_information_leak(&received) {
        anomalies.push(StreamAnomalyType::InformationLeak);
    }
    if has_unexpected_close(messages) {
        anomalies.push(StreamAnomalyType::UnexpectedClose);
    }
    if has_protocol_violation(messages) {
        anomalies.push(StreamAnomalyType::ProtocolViolation);
    }

    anomalies
}

fn has_reflection(received: &[&StreamMessage], payload: &str) -> bool {
    payload.len() >= 4 && received.iter().any(|m| m.payload.contains(payload))
}

fn has_error_message(received: &[&StreamMessage]) -> bool {
    let error_keywords = ["error", "exception", "stack trace", "internal server"];
    received.iter().any(|m| {
        let lower = m.payload.to_lowercase();
        error_keywords.iter().any(|kw| lower.contains(kw))
    })
}

fn has_information_leak(received: &[&StreamMessage]) -> bool {
    let leak_patterns = [
        "/usr/",
        "/var/",
        "/home/",
        "C:\\",
        "at java.",
        "at org.",
        "SQLSTATE",
        "Traceback",
    ];
    received.iter().any(|m| {
        leak_patterns
            .iter()
            .any(|pattern| m.payload.contains(pattern))
    })
}

fn has_unexpected_close(messages: &[StreamMessage]) -> bool {
    if let Some(last) = messages.last()
        && last.direction == MessageDirection::Sent
        && last.message_type == StreamMessageType::Ping
    {
        let has_pong_after = messages.iter().any(|m| {
            m.sequence > last.sequence
                && m.direction == MessageDirection::Received
                && m.message_type == StreamMessageType::Pong
        });
        return !has_pong_after;
    }
    false
}

fn has_protocol_violation(messages: &[StreamMessage]) -> bool {
    let sent_types: Vec<StreamMessageType> = messages
        .iter()
        .filter(|m| m.direction == MessageDirection::Sent)
        .map(|m| m.message_type)
        .collect();

    let expected_response_type = if sent_types.iter().all(|t| *t == StreamMessageType::Text) {
        Some(StreamMessageType::Text)
    } else if sent_types.iter().all(|t| *t == StreamMessageType::Binary) {
        Some(StreamMessageType::Binary)
    } else {
        None
    };

    if let Some(expected) = expected_response_type {
        let violation_type = match expected {
            StreamMessageType::Text => StreamMessageType::Binary,
            StreamMessageType::Binary => StreamMessageType::Text,
            _ => return false,
        };

        return messages.iter().any(|m| {
            m.direction == MessageDirection::Received && m.message_type == violation_type
        });
    }

    false
}

/// Returns a confidence score for a given stream anomaly type.
pub fn score_stream_anomaly(anomaly_type: &StreamAnomalyType) -> f64 {
    match anomaly_type {
        StreamAnomalyType::ReflectionDetected => 0.9,
        StreamAnomalyType::InformationLeak => 0.85,
        StreamAnomalyType::ErrorMessage => 0.7,
        StreamAnomalyType::UnexpectedClose => 0.6,
        StreamAnomalyType::TimingAnomaly => 0.5,
        StreamAnomalyType::ProtocolViolation => 0.4,
    }
}

/// Builds a `StreamFuzzResult` from collected messages and anomalies.
pub fn build_stream_fuzz_result(
    target: &StreamFuzzTarget,
    messages: &[StreamMessage],
    anomalies: Vec<StreamAnomaly>,
    duration_ms: u64,
) -> StreamFuzzResult {
    let messages_sent = messages
        .iter()
        .filter(|m| m.direction == MessageDirection::Sent)
        .count() as u64;
    let messages_received = messages
        .iter()
        .filter(|m| m.direction == MessageDirection::Received)
        .count() as u64;

    StreamFuzzResult {
        target: target.clone(),
        messages_sent,
        messages_received,
        anomalies,
        connection_duration_ms: duration_ms,
        protocol: target.protocol,
    }
}

#[cfg(test)]
#[path = "streaming_fuzzer_test.rs"]
mod streaming_fuzzer_test;
