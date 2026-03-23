use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;
use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum EventSourceIssue {
    ApiDetected,
    SensitiveDataStream,
    CrossOriginStream,
    NoReconnectLimit,
    InjectionViaMessage,
}

impl std::fmt::Display for EventSourceIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::SensitiveDataStream => write!(f, "sensitive_data_stream"),
            Self::CrossOriginStream => write!(f, "cross_origin_stream"),
            Self::NoReconnectLimit => write!(f, "no_reconnect_limit"),
            Self::InjectionViaMessage => write!(f, "injection_via_message"),
        }
    }
}

pub fn event_source_severity(issue: &EventSourceIssue) -> f64 {
    match issue {
        EventSourceIssue::ApiDetected => 2.0,
        EventSourceIssue::SensitiveDataStream => 7.5,
        EventSourceIssue::CrossOriginStream => 6.5,
        EventSourceIssue::NoReconnectLimit => 5.5,
        EventSourceIssue::InjectionViaMessage => 7.0,
    }
}

pub fn audit_event_source(target: &str) -> Vec<EventSourceIssue> {
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
    analyze_event_source(&body)
}

pub fn analyze_event_source(body: &str) -> Vec<EventSourceIssue> {
    let mut issues = Vec::new();

    let has_api = body.contains("EventSource")
        || body.contains("new EventSource")
        || body.contains("eventsource");

    if has_api {
        issues.push(EventSourceIssue::ApiDetected);
    }

    if has_api
        && (body.contains("password")
            || body.contains("token")
            || body.contains("secret")
            || body.contains("credential")
            || body.contains("apiKey")
            || body.contains("sessionId"))
    {
        issues.push(EventSourceIssue::SensitiveDataStream);
    }

    if has_api
        && (body.contains("http://") || body.contains("https://"))
        && !(body.contains("location.origin")
            || body.contains("same-origin")
            || body.contains("withCredentials: false"))
    {
        issues.push(EventSourceIssue::CrossOriginStream);
    }

    if has_api
        && (body.contains("onopen") || body.contains("onerror"))
        && !(body.contains("close()")
            || body.contains("maxRetries")
            || body.contains("retryCount")
            || body.contains("limit"))
    {
        issues.push(EventSourceIssue::NoReconnectLimit);
    }

    if has_api
        && (body.contains("onmessage") || body.contains("addEventListener"))
        && (body.contains("innerHTML")
            || body.contains("document.write")
            || body.contains("eval"))
    {
        issues.push(EventSourceIssue::InjectionViaMessage);
    }

    issues
}

pub fn event_source_to_operations(
    issues: &[EventSourceIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                event_source_severity(issue),
                0.5,
            )
        })
        .collect()
}
