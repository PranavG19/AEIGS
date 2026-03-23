use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum WebSocketIssue {
    ApiDetected,
    InsecureProtocol,
    MissingOriginValidation,
    MessageInjectionRisk,
    SensitiveDataExposure,
    UnlimitedReconnect,
}

impl std::fmt::Display for WebSocketIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::InsecureProtocol => write!(f, "insecure_protocol"),
            Self::MissingOriginValidation => write!(f, "missing_origin_validation"),
            Self::MessageInjectionRisk => write!(f, "message_injection_risk"),
            Self::SensitiveDataExposure => write!(f, "sensitive_data_exposure"),
            Self::UnlimitedReconnect => write!(f, "unlimited_reconnect"),
        }
    }
}

pub fn websocket_severity(issue: &WebSocketIssue) -> f64 {
    match issue {
        WebSocketIssue::ApiDetected => 2.0,
        WebSocketIssue::InsecureProtocol => 6.5,
        WebSocketIssue::MissingOriginValidation => 7.5,
        WebSocketIssue::MessageInjectionRisk => 8.0,
        WebSocketIssue::SensitiveDataExposure => 7.0,
        WebSocketIssue::UnlimitedReconnect => 5.0,
    }
}

pub fn audit_websocket(target: &str) -> Vec<WebSocketIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send() {
        Ok(r) => r.text().unwrap_or_default(),
        Err(_) => return Vec::new(),
    };
    analyze_websocket(&body)
}

pub fn analyze_websocket(body: &str) -> Vec<WebSocketIssue> {
    let mut issues = Vec::new();

    let has_websocket = body.contains("new WebSocket")
        || body.contains("WebSocket(")
        || body.contains("ws://")
        || body.contains("wss://");

    if has_websocket {
        issues.push(WebSocketIssue::ApiDetected);
    }

    if body.contains("ws://") {
        issues.push(WebSocketIssue::InsecureProtocol);
    }

    let has_origin_check = body.contains(".origin")
        || body.contains("checkOrigin")
        || body.contains("verifyOrigin")
        || body.contains("allowedOrigins");

    if has_websocket && !has_origin_check {
        issues.push(WebSocketIssue::MissingOriginValidation);
    }

    let has_inner_html = body.contains(".innerHTML") && body.contains(".data");
    let has_eval = body.contains("eval(") && body.contains(".data");
    let has_doc_write = body.contains("document.write") && body.contains(".data");
    let has_function_constructor = body.contains("Function(") && body.contains(".data");

    if has_inner_html || has_eval || has_doc_write || has_function_constructor {
        issues.push(WebSocketIssue::MessageInjectionRisk);
    }

    let ws_context_present =
        body.contains("WebSocket") || body.contains("ws://") || body.contains("wss://");
    let has_password = body.contains("password");
    let has_token = body.contains("token");
    let has_secret = body.contains("secret");
    let has_credential = body.contains("credential");
    let has_api_key = body.contains("apiKey") || body.contains("api_key");

    if ws_context_present
        && (has_password || has_token || has_secret || has_credential || has_api_key)
    {
        issues.push(WebSocketIssue::SensitiveDataExposure);
    }

    let has_reconnect = body.contains("reconnect") || body.contains("retry");
    let has_backoff = body.contains("backoff") || body.contains("exponential");
    let has_max_retry = body.contains("maxRetries")
        || body.contains("max_retries")
        || body.contains("maxReconnect");

    if has_websocket && has_reconnect && !has_backoff && !has_max_retry {
        issues.push(WebSocketIssue::UnlimitedReconnect);
    }

    issues
}

pub fn websocket_to_operations(issues: &[WebSocketIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                websocket_severity(issue),
                0.5,
            )
        })
        .collect()
}
