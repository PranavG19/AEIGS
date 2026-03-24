use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum SseIssue {
    SseEndpointExposed { url: String },
    SseNoAuth { url: String },
    SseWithUserInput,
    EventSourceInsecure { url: String },
}

impl std::fmt::Display for SseIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SseEndpointExposed { url } => write!(f, "sse_endpoint:{url}"),
            Self::SseNoAuth { url } => write!(f, "sse_no_auth:{url}"),
            Self::SseWithUserInput => write!(f, "sse_user_input"),
            Self::EventSourceInsecure { url } => write!(f, "eventsource_http:{url}"),
        }
    }
}

const SSE_PATH_PATTERNS: &[&str] = &[
    "/events",
    "/sse",
    "/stream",
    "/subscribe",
    "/notifications",
    "/updates",
    "/feed",
    "/realtime",
    "/push",
    "/live",
];

pub fn audit_sse(target: &str) -> Vec<SseIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send().and_then(|r| r.text()) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    analyze_sse_usage(&body)
}

pub fn analyze_sse_usage(body: &str) -> Vec<SseIssue> {
    let mut issues = Vec::new();

    find_eventsource_constructors(body, &mut issues);
    find_sse_path_references(body, &mut issues);

    if has_user_input_in_sse(body) {
        issues.push(SseIssue::SseWithUserInput);
    }

    issues
}

fn find_eventsource_constructors(body: &str, issues: &mut Vec<SseIssue>) {
    for prefix in [
        "new EventSource(\"",
        "new EventSource('",
        "new EventSource(`",
    ] {
        let mut pos = 0;
        while let Some(idx) = body[pos..].find(prefix) {
            let abs = pos + idx + prefix.len();
            let quote = prefix.as_bytes()[prefix.len() - 1] as char;
            if let Some(end) = body[abs..].find(quote) {
                let url = &body[abs..abs + end];
                if url.starts_with("http://") {
                    issues.push(SseIssue::EventSourceInsecure {
                        url: url.to_string(),
                    });
                }
                issues.push(SseIssue::SseEndpointExposed {
                    url: url.to_string(),
                });
            }
            pos = abs + 1;
        }
    }
}

fn find_sse_path_references(body: &str, issues: &mut Vec<SseIssue>) {
    let lower = body.to_ascii_lowercase();

    if !lower.contains("eventsource") && !lower.contains("text/event-stream") {
        return;
    }

    for &path in SSE_PATH_PATTERNS {
        for delim in ["\"", "'", "`"] {
            let search = format!("{delim}{path}");
            if lower.contains(&search) {
                issues.push(SseIssue::SseNoAuth {
                    url: path.to_string(),
                });
                break;
            }
        }
    }
}

fn has_user_input_in_sse(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    if !lower.contains("eventsource") {
        return false;
    }

    let user_input_patterns = [
        "location.search",
        "location.hash",
        "URLSearchParams",
        "window.location",
        "document.location",
        "url.searchParams",
    ];

    let has_input = user_input_patterns.iter().any(|p| body.contains(p));
    let has_concat = body.contains("+ ") || body.contains("${") || body.contains("concat(");

    has_input && has_concat
}

pub fn sse_severity(issue: &SseIssue) -> f64 {
    match issue {
        SseIssue::SseWithUserInput => 6.5,
        SseIssue::EventSourceInsecure { .. } => 6.0,
        SseIssue::SseNoAuth { .. } => 4.5,
        SseIssue::SseEndpointExposed { .. } => 3.5,
    }
}

pub fn sse_to_operations(issues: &[SseIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                sse_severity(issue),
                0.7,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum SseSecurityIssue {
    SseDataExfiltration,
    SseSensitiveDataExposure,
    SseWithoutAuthentication,
    SseReconnectionAbuse,
    SseCrossOriginConnection,
    SseInjectionVector,
    SseDenialOfService,
    SseDataPersistence,
    SseWithoutEncryption,
    SseEventSpoofing,
}

impl std::fmt::Display for SseSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SseDataExfiltration => write!(f, "sse_data_exfiltration"),
            Self::SseSensitiveDataExposure => write!(f, "sse_sensitive_data_exposure"),
            Self::SseWithoutAuthentication => write!(f, "sse_without_authentication"),
            Self::SseReconnectionAbuse => write!(f, "sse_reconnection_abuse"),
            Self::SseCrossOriginConnection => write!(f, "sse_cross_origin_connection"),
            Self::SseInjectionVector => write!(f, "sse_injection_vector"),
            Self::SseDenialOfService => write!(f, "sse_denial_of_service"),
            Self::SseDataPersistence => write!(f, "sse_data_persistence"),
            Self::SseWithoutEncryption => write!(f, "sse_without_encryption"),
            Self::SseEventSpoofing => write!(f, "sse_event_spoofing"),
        }
    }
}

pub fn analyze_sse_security(body: &str) -> Vec<SseSecurityIssue> {
    let lower = body.to_ascii_lowercase();

    if !lower.contains("eventsource") && !lower.contains("text/event-stream") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    // SseDataExfiltration: SSE + outbound data sending
    if has_sse_data_exfiltration(body) {
        issues.push(SseSecurityIssue::SseDataExfiltration);
    }

    // SseSensitiveDataExposure: PII keywords in SSE context
    if has_sensitive_data_exposure(body) {
        issues.push(SseSecurityIssue::SseSensitiveDataExposure);
    }

    // SseWithoutAuthentication: EventSource without auth
    if has_sse_without_auth(body) {
        issues.push(SseSecurityIssue::SseWithoutAuthentication);
    }

    // SseReconnectionAbuse: very low retry intervals
    if has_reconnection_abuse(body) {
        issues.push(SseSecurityIssue::SseReconnectionAbuse);
    }

    // SseCrossOriginConnection: different origin
    if has_cross_origin_connection(body) {
        issues.push(SseSecurityIssue::SseCrossOriginConnection);
    }

    // SseInjectionVector: SSE data into DOM
    if has_injection_vector(body) {
        issues.push(SseSecurityIssue::SseInjectionVector);
    }

    // SseDenialOfService: no cleanup
    if has_denial_of_service(body) {
        issues.push(SseSecurityIssue::SseDenialOfService);
    }

    // SseDataPersistence: SSE to storage
    if has_data_persistence(body) {
        issues.push(SseSecurityIssue::SseDataPersistence);
    }

    // SseWithoutEncryption: http:// URLs
    if has_unencrypted_connection(body) {
        issues.push(SseSecurityIssue::SseWithoutEncryption);
    }

    // SseEventSpoofing: custom event types
    if has_event_spoofing(body) {
        issues.push(SseSecurityIssue::SseEventSpoofing);
    }

    issues
}

fn has_sse_data_exfiltration(body: &str) -> bool {
    let has_sse = body.contains("EventSource") || body.contains("event-stream");
    let has_fetch =
        body.contains("fetch(") || body.contains("XMLHttpRequest") || body.contains("sendBeacon");
    has_sse && has_fetch
}

fn has_sensitive_data_exposure(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    let has_sse = lower.contains("eventsource") || lower.contains("event-stream");
    let sensitive_keywords = ["email", "password", "ssn", "creditcard", "credit_card"];
    let has_sensitive = sensitive_keywords.iter().any(|k| lower.contains(k));
    has_sse && has_sensitive
}

fn has_sse_without_auth(body: &str) -> bool {
    if !body.contains("EventSource") {
        return false;
    }

    let has_auth = body.contains("Authorization")
        || body.contains("Bearer")
        || body.contains("token")
        || body.contains("headers:");

    !has_auth
}

fn has_reconnection_abuse(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    if !lower.contains("eventsource") {
        return false;
    }

    // Look for retry patterns with values < 1000ms
    for pattern in ["retry:", "reconnectinterval", "reconnect_interval"] {
        if let Some(pos) = lower.find(pattern) {
            let after = &body[pos..];
            // Extract numeric value
            if let Some(num_start) = after.find(|c: char| c.is_ascii_digit()) {
                let num_str: String = after[num_start..]
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                if let Ok(val) = num_str.parse::<u32>()
                    && val < 1000
                {
                    return true;
                }
            }
        }
    }
    false
}

fn has_cross_origin_connection(body: &str) -> bool {
    if !body.contains("EventSource") {
        return false;
    }

    // Look for different domains or external URLs
    body.contains("://") && (body.contains("http://") || body.contains("https://"))
}

fn has_injection_vector(body: &str) -> bool {
    let has_sse = body.contains("EventSource") || body.contains("event-stream");
    let has_dom_manipulation =
        body.contains("innerHTML") || body.contains("document.write") || body.contains("outerHTML");
    has_sse && has_dom_manipulation
}

fn has_denial_of_service(body: &str) -> bool {
    if !body.contains("EventSource") {
        return false;
    }

    let has_listener = body.contains("addEventListener")
        || body.contains(".onmessage")
        || body.contains(".onerror");
    let has_cleanup = body.contains("removeEventListener") || body.contains(".close()");

    has_listener && !has_cleanup
}

fn has_data_persistence(body: &str) -> bool {
    let has_sse = body.contains("EventSource") || body.contains("event-stream");
    let has_storage = body.contains("localStorage")
        || body.contains("sessionStorage")
        || body.contains("indexedDB");
    has_sse && has_storage
}

fn has_unencrypted_connection(body: &str) -> bool {
    if !body.contains("EventSource") {
        return false;
    }

    body.contains("http://") && !body.contains("https://")
}

fn has_event_spoofing(body: &str) -> bool {
    if !body.contains("EventSource") {
        return false;
    }

    // Look for custom event types that might conflict with system events
    let system_events = ["error", "message", "open"];
    for event in system_events {
        let pattern = format!("addEventListener(\"{}\"", event);
        if body.contains(&pattern) || body.contains(&format!("addEventListener('{}\'", event)) {
            return true;
        }
    }
    false
}

pub fn sse_security_severity(issue: &SseSecurityIssue) -> f64 {
    match issue {
        SseSecurityIssue::SseDataExfiltration => 7.5,
        SseSecurityIssue::SseSensitiveDataExposure => 8.0,
        SseSecurityIssue::SseWithoutAuthentication => 6.5,
        SseSecurityIssue::SseReconnectionAbuse => 5.0,
        SseSecurityIssue::SseCrossOriginConnection => 6.0,
        SseSecurityIssue::SseInjectionVector => 7.0,
        SseSecurityIssue::SseDenialOfService => 5.5,
        SseSecurityIssue::SseDataPersistence => 6.0,
        SseSecurityIssue::SseWithoutEncryption => 7.0,
        SseSecurityIssue::SseEventSpoofing => 5.0,
    }
}

pub fn sse_security_to_operations(
    issues: &[SseSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                sse_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
