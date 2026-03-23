use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::html_parser::{self, TagIter};
use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum MixedContentKind {
    Script,
    Stylesheet,
    Image,
    Iframe,
    Form,
    Audio,
    Video,
    Source,
    Object,
    Embed,
}

impl std::fmt::Display for MixedContentKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MixedContentKind::Script => write!(f, "script"),
            MixedContentKind::Stylesheet => write!(f, "stylesheet"),
            MixedContentKind::Image => write!(f, "image"),
            MixedContentKind::Iframe => write!(f, "iframe"),
            MixedContentKind::Form => write!(f, "form"),
            MixedContentKind::Audio => write!(f, "audio"),
            MixedContentKind::Video => write!(f, "video"),
            MixedContentKind::Source => write!(f, "source"),
            MixedContentKind::Object => write!(f, "object"),
            MixedContentKind::Embed => write!(f, "embed"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MixedContentIssue {
    pub kind: MixedContentKind,
    pub url: String,
}

pub fn check_mixed_content(target: &str) -> Vec<MixedContentIssue> {
    if !target.starts_with("https://") {
        return Vec::new();
    }
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
    find_mixed_content(&body)
}

const TAG_ATTRS: &[(&str, &str, MixedContentKind)] = &[
    ("script", "src", MixedContentKind::Script),
    ("link", "href", MixedContentKind::Stylesheet),
    ("img", "src", MixedContentKind::Image),
    ("iframe", "src", MixedContentKind::Iframe),
    ("form", "action", MixedContentKind::Form),
    ("audio", "src", MixedContentKind::Audio),
    ("video", "src", MixedContentKind::Video),
    ("source", "src", MixedContentKind::Source),
    ("object", "data", MixedContentKind::Object),
    ("embed", "src", MixedContentKind::Embed),
];

pub fn find_mixed_content(html: &str) -> Vec<MixedContentIssue> {
    let mut issues = Vec::new();

    for (tag_name, attr, kind) in TAG_ATTRS {
        for tag in TagIter::new(html, tag_name) {
            if let Some(url) = html_parser::extract_attr(tag.original, &tag.lower, attr)
                && url.starts_with("http://")
            {
                issues.push(MixedContentIssue {
                    kind: kind.clone(),
                    url,
                });
            }
        }
    }

    issues
}

pub fn mixed_content_to_operations(
    issues: &[MixedContentIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let has_active = issues.iter().any(|i| {
        matches!(
            i.kind,
            MixedContentKind::Script | MixedContentKind::Stylesheet | MixedContentKind::Iframe
        )
    });
    let severity = if has_active { 6.0 } else { 3.0 };

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::SecurityMisconfiguration,
        severity,
        0.95,
    )]
}

#[derive(Debug, Clone, PartialEq)]
pub enum MixedContentSecurityIssue {
    ActiveMixedContent { tag: String, url: String },
    PassiveMixedContent { tag: String, url: String },
    WebSocketDowngrade { url: String },
    EventSourceHttp { url: String },
    FetchHttpEndpoint { url: String },
    XhrHttpEndpoint { url: String },
    CssImportHttp { url: String },
    FontLoadHttp { url: String },
    ServiceWorkerHttp { url: String },
    PreconnectHttp { url: String },
}

impl std::fmt::Display for MixedContentSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MixedContentSecurityIssue::ActiveMixedContent { tag, url } => {
                write!(f, "active mixed content in {} tag: {}", tag, url)
            }
            MixedContentSecurityIssue::PassiveMixedContent { tag, url } => {
                write!(f, "passive mixed content in {} tag: {}", tag, url)
            }
            MixedContentSecurityIssue::WebSocketDowngrade { url } => {
                write!(f, "insecure WebSocket connection: {}", url)
            }
            MixedContentSecurityIssue::EventSourceHttp { url } => {
                write!(f, "EventSource over HTTP: {}", url)
            }
            MixedContentSecurityIssue::FetchHttpEndpoint { url } => {
                write!(f, "fetch() to HTTP endpoint: {}", url)
            }
            MixedContentSecurityIssue::XhrHttpEndpoint { url } => {
                write!(f, "XMLHttpRequest to HTTP endpoint: {}", url)
            }
            MixedContentSecurityIssue::CssImportHttp { url } => {
                write!(f, "CSS @import over HTTP: {}", url)
            }
            MixedContentSecurityIssue::FontLoadHttp { url } => {
                write!(f, "font loaded over HTTP: {}", url)
            }
            MixedContentSecurityIssue::ServiceWorkerHttp { url } => {
                write!(f, "service worker registered over HTTP: {}", url)
            }
            MixedContentSecurityIssue::PreconnectHttp { url } => {
                write!(f, "preconnect hint to HTTP: {}", url)
            }
        }
    }
}

pub fn analyze_mixed_content_security(html: &str) -> Vec<MixedContentSecurityIssue> {
    let mut issues = Vec::new();

    // Wrap existing mixed content detection results
    let mixed_content = find_mixed_content(html);
    for item in mixed_content {
        match item.kind {
            MixedContentKind::Script | MixedContentKind::Stylesheet | MixedContentKind::Iframe => {
                issues.push(MixedContentSecurityIssue::ActiveMixedContent {
                    tag: item.kind.to_string(),
                    url: item.url,
                });
            }
            MixedContentKind::Image | MixedContentKind::Audio | MixedContentKind::Video => {
                issues.push(MixedContentSecurityIssue::PassiveMixedContent {
                    tag: item.kind.to_string(),
                    url: item.url,
                });
            }
            _ => {}
        }
    }

    // WebSocket downgrade: ws:// without wss://
    if html.contains("ws://")
        && !html.contains("wss://")
        && let Some(start) = html.find("ws://")
    {
        let remaining = &html[start..];
        if let Some(end) = remaining.find(['"', '\'', ' ', '\t', '\n']) {
            issues.push(MixedContentSecurityIssue::WebSocketDowngrade {
                url: remaining[..end].to_string(),
            });
        }
    }

    // EventSource over HTTP
    if (html.contains("EventSource(\"http://") || html.contains("EventSource('http://"))
        && let Some(start) = html
            .find("EventSource(\"http://")
            .or_else(|| html.find("EventSource('http://"))
    {
        let remaining = &html[start + 20..];
        if let Some(end) = remaining.find(['"', '\'']) {
            issues.push(MixedContentSecurityIssue::EventSourceHttp {
                url: format!("http://{}", &remaining[..end]),
            });
        }
    }

    // fetch() to HTTP
    if (html.contains("fetch(\"http://") || html.contains("fetch('http://"))
        && let Some(start) = html
            .find("fetch(\"http://")
            .or_else(|| html.find("fetch('http://"))
    {
        let remaining = &html[start + 14..];
        if let Some(end) = remaining.find(['"', '\'']) {
            issues.push(MixedContentSecurityIssue::FetchHttpEndpoint {
                url: format!("http://{}", &remaining[..end]),
            });
        }
    }

    // XHR to HTTP (simple proximity check)
    if html.contains(".open(")
        && html.contains("\"http://")
        && let Some(start) = html.find("\"http://")
    {
        let remaining = &html[start + 1..];
        if let Some(end) = remaining.find('"') {
            issues.push(MixedContentSecurityIssue::XhrHttpEndpoint {
                url: remaining[..end].to_string(),
            });
        }
    }

    // CSS @import over HTTP
    if html.contains("@import")
        && (html.contains("url(http://")
            || html.contains("@import \"http://")
            || html.contains("@import 'http://"))
        && let Some(start) = html
            .find("url(http://")
            .or_else(|| html.find("@import \"http://"))
            .or_else(|| html.find("@import 'http://"))
    {
        let offset = if html[start..].starts_with("url(") {
            4
        } else {
            9
        };
        let remaining = &html[start + offset..];
        if let Some(end) = remaining.find([')', '"', '\'']) {
            issues.push(MixedContentSecurityIssue::CssImportHttp {
                url: remaining[..end].to_string(),
            });
        }
    }

    // Font over HTTP
    if html.contains("@font-face")
        && html.contains("http://")
        && let Some(start) = html.find("@font-face")
        && let Some(http_pos) = html[start..].find("http://")
    {
        let url_start = &html[start + http_pos..];
        if let Some(end) = url_start.find([')', '"', '\'', ' ', '\t', '\n']) {
            issues.push(MixedContentSecurityIssue::FontLoadHttp {
                url: url_start[..end].to_string(),
            });
        }
    }

    // Service Worker over HTTP
    if html.contains("navigator.serviceWorker.register")
        && html.contains("http://")
        && let Some(start) = html.find("navigator.serviceWorker.register")
        && let Some(http_pos) = html[start..].find("http://")
    {
        let url_start = &html[start + http_pos..];
        if let Some(end) = url_start.find(['"', '\'']) {
            issues.push(MixedContentSecurityIssue::ServiceWorkerHttp {
                url: url_start[..end].to_string(),
            });
        }
    }

    // Preconnect to HTTP
    if (html.contains("rel=\"preconnect\"") || html.contains("rel='preconnect'"))
        && (html.contains("href=\"http://") || html.contains("href='http://"))
        && let Some(start) = html
            .find("href=\"http://")
            .or_else(|| html.find("href='http://"))
    {
        let remaining = &html[start + 6..];
        if let Some(end) = remaining.find(['"', '\'']) {
            issues.push(MixedContentSecurityIssue::PreconnectHttp {
                url: remaining[..end].to_string(),
            });
        }
    }

    issues
}

pub fn mixed_content_security_severity(issue: &MixedContentSecurityIssue) -> f64 {
    match issue {
        MixedContentSecurityIssue::ServiceWorkerHttp { .. } => 9.0,
        MixedContentSecurityIssue::ActiveMixedContent { .. } => 7.5,
        MixedContentSecurityIssue::FetchHttpEndpoint { .. } => 7.0,
        MixedContentSecurityIssue::XhrHttpEndpoint { .. } => 7.0,
        MixedContentSecurityIssue::WebSocketDowngrade { .. } => 6.5,
        MixedContentSecurityIssue::EventSourceHttp { .. } => 6.5,
        MixedContentSecurityIssue::CssImportHttp { .. } => 6.0,
        MixedContentSecurityIssue::FontLoadHttp { .. } => 5.5,
        MixedContentSecurityIssue::PreconnectHttp { .. } => 4.0,
        MixedContentSecurityIssue::PassiveMixedContent { .. } => 3.0,
    }
}

pub fn mixed_content_security_to_operations(
    issues: &[MixedContentSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            let severity = mixed_content_security_severity(issue);
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                severity,
                0.95,
            )
        })
        .collect()
}
