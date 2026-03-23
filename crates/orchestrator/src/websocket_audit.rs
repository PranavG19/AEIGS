use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WebSocketIssue {
    InsecureWsScheme { endpoint: String },
    WsEndpointDiscovered { endpoint: String },
    MissingOriginValidation { endpoint: String },
    WsInHtmlSource { url: String },
}

impl std::fmt::Display for WebSocketIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsecureWsScheme { endpoint } => write!(f, "insecure_ws:{endpoint}"),
            Self::WsEndpointDiscovered { endpoint } => write!(f, "ws_endpoint:{endpoint}"),
            Self::MissingOriginValidation { endpoint } => {
                write!(f, "ws_no_origin_check:{endpoint}")
            }
            Self::WsInHtmlSource { url } => write!(f, "ws_in_html:{url}"),
        }
    }
}

const WS_PATHS: &[&str] = &[
    "/ws",
    "/websocket",
    "/socket",
    "/socket.io/",
    "/sockjs/",
    "/realtime",
    "/live",
    "/stream",
    "/cable",
    "/hub",
];

pub fn audit_websockets(target: &str) -> Vec<WebSocketIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };

    let mut issues = Vec::new();

    if let Ok(resp) = client.get(target).send() {
        let body = resp.text().unwrap_or_default();
        issues.extend(analyze_html_for_websockets(&body));
    }

    for path in WS_PATHS {
        let url = format!("{}{}", target.trim_end_matches('/'), path);
        if let Ok(resp) = client
            .get(&url)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .send()
        {
            let status = resp.status().as_u16();
            if status == 101 || status == 200 {
                let upgrade = resp
                    .headers()
                    .get("upgrade")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if status == 101 || upgrade.contains("websocket") {
                    issues.push(WebSocketIssue::WsEndpointDiscovered {
                        endpoint: path.to_string(),
                    });
                    if !target.starts_with("https://") {
                        issues.push(WebSocketIssue::InsecureWsScheme {
                            endpoint: path.to_string(),
                        });
                    }
                }
            }
        }

        let evil_origin = "https://evil.example.com";
        if let Ok(resp) = client
            .get(&url)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Origin", evil_origin)
            .send()
            && (resp.status().as_u16() == 101 || resp.status().as_u16() == 200)
        {
            let upgrade = resp
                .headers()
                .get("upgrade")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_ascii_lowercase();
            if resp.status().as_u16() == 101 || upgrade.contains("websocket") {
                issues.push(WebSocketIssue::MissingOriginValidation {
                    endpoint: path.to_string(),
                });
            }
        }
    }

    issues
}

pub fn analyze_html_for_websockets(body: &str) -> Vec<WebSocketIssue> {
    let mut issues = Vec::new();

    for (idx, _) in body.match_indices("ws://").chain(body.match_indices("wss://")) {
        let rest = &body[idx..];
        let end = rest
            .find(['"', '\'', ')', ' ', '<'])
            .unwrap_or(rest.len());
        let url = &rest[..end];

        if url.starts_with("ws://") {
            issues.push(WebSocketIssue::InsecureWsScheme {
                endpoint: url.to_string(),
            });
        }
        issues.push(WebSocketIssue::WsInHtmlSource {
            url: url.to_string(),
        });
    }

    issues
}

pub fn websocket_severity(issue: &WebSocketIssue) -> f64 {
    match issue {
        WebSocketIssue::MissingOriginValidation { .. } => 7.0,
        WebSocketIssue::InsecureWsScheme { .. } => 5.5,
        WebSocketIssue::WsEndpointDiscovered { .. } => 3.0,
        WebSocketIssue::WsInHtmlSource { .. } => 2.5,
    }
}

pub fn websocket_to_operations(
    issues: &[WebSocketIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                websocket_severity(issue),
                0.75,
            )
        })
        .collect()
}
