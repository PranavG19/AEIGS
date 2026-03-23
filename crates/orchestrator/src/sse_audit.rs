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
