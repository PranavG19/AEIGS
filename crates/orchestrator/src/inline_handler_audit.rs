use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::html_parser::TagIter;
use crate::recon_client;

const INLINE_EVENT_HANDLERS: &[&str] = &[
    "onclick=",
    "onerror=",
    "onload=",
    "onmouseover=",
    "onfocus=",
    "onblur=",
    "onsubmit=",
    "onchange=",
    "onkeyup=",
    "onkeydown=",
    "onmouseout=",
    "onunload=",
    "onbeforeunload=",
];

const RISKY_TAGS: &[&str] = &[
    "div", "span", "a", "img", "input", "button", "form", "body", "p", "td", "li",
];

const JAVASCRIPT_URI_ATTRS: &[&str] = &["href=", "action=", "src="];

const UNSAFE_EVAL_PATTERNS: &[&str] = &["eval(", "function(", "settimeout("];

const DOM_MANIPULATION_PATTERNS: &[&str] = &["innerhtml", "outerhtml", "document.write"];

const HIGH_DENSITY_THRESHOLD: usize = 10;

#[derive(Debug, Clone, PartialEq)]
pub enum InlineHandlerIssue {
    EventHandler { tag: String, handler: String },
    JavascriptUri { tag: String },
    DataUri { tag: String },
    UnsafeEvalInHandler { tag: String, handler: String },
    DomManipulationInHandler { tag: String, handler: String },
    HighDensityHandlers { count: usize },
}

impl std::fmt::Display for InlineHandlerIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EventHandler { .. } => write!(f, "event_handler"),
            Self::JavascriptUri { .. } => write!(f, "javascript_uri"),
            Self::DataUri { .. } => write!(f, "data_uri"),
            Self::UnsafeEvalInHandler { .. } => write!(f, "unsafe_eval_in_handler"),
            Self::DomManipulationInHandler { .. } => write!(f, "dom_manipulation_in_handler"),
            Self::HighDensityHandlers { .. } => write!(f, "high_density_handlers"),
        }
    }
}

pub fn inline_handler_severity(issue: &InlineHandlerIssue) -> f64 {
    match issue {
        InlineHandlerIssue::EventHandler { .. } => 2.5,
        InlineHandlerIssue::JavascriptUri { .. } => 7.0,
        InlineHandlerIssue::DataUri { .. } => 5.0,
        InlineHandlerIssue::UnsafeEvalInHandler { .. } => 8.0,
        InlineHandlerIssue::DomManipulationInHandler { .. } => 6.0,
        InlineHandlerIssue::HighDensityHandlers { .. } => 4.0,
    }
}

pub fn audit_inline_handlers(target: &str) -> Vec<InlineHandlerIssue> {
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
    find_inline_handlers(&body)
}

pub fn find_inline_handlers(html: &str) -> Vec<InlineHandlerIssue> {
    let mut issues = Vec::new();
    let mut event_handler_count: usize = 0;

    for tag_name in RISKY_TAGS {
        for tag in TagIter::new(html, tag_name) {
            detect_event_handlers(&tag.lower, tag_name, &mut issues, &mut event_handler_count);
            detect_javascript_uris(&tag.lower, tag_name, &mut issues);
            detect_data_uris(&tag.lower, tag_name, &mut issues);
        }
    }

    if event_handler_count > HIGH_DENSITY_THRESHOLD {
        issues.push(InlineHandlerIssue::HighDensityHandlers {
            count: event_handler_count,
        });
    }

    issues
}

fn detect_event_handlers(
    tag_lower: &str,
    tag_name: &str,
    issues: &mut Vec<InlineHandlerIssue>,
    event_handler_count: &mut usize,
) {
    for handler in INLINE_EVENT_HANDLERS {
        if !tag_lower.contains(handler) {
            continue;
        }
        let handler_name = handler.trim_end_matches('=');
        *event_handler_count += 1;

        let handler_value = extract_handler_value(tag_lower, handler);

        if has_unsafe_eval(&handler_value) {
            issues.push(InlineHandlerIssue::UnsafeEvalInHandler {
                tag: tag_name.to_string(),
                handler: handler_name.to_string(),
            });
        } else if has_dom_manipulation(&handler_value) {
            issues.push(InlineHandlerIssue::DomManipulationInHandler {
                tag: tag_name.to_string(),
                handler: handler_name.to_string(),
            });
        } else {
            issues.push(InlineHandlerIssue::EventHandler {
                tag: tag_name.to_string(),
                handler: handler_name.to_string(),
            });
        }

        break;
    }
}

fn detect_javascript_uris(tag_lower: &str, tag_name: &str, issues: &mut Vec<InlineHandlerIssue>) {
    for attr in JAVASCRIPT_URI_ATTRS {
        let Some(value) = extract_attr_value(tag_lower, attr) else {
            continue;
        };
        let trimmed = value.trim();
        if trimmed.starts_with("javascript:") {
            issues.push(InlineHandlerIssue::JavascriptUri {
                tag: tag_name.to_string(),
            });
            return;
        }
    }
}

fn detect_data_uris(tag_lower: &str, tag_name: &str, issues: &mut Vec<InlineHandlerIssue>) {
    let Some(value) = extract_attr_value(tag_lower, "src=") else {
        return;
    };
    let trimmed = value.trim();
    if trimmed.starts_with("data:") {
        issues.push(InlineHandlerIssue::DataUri {
            tag: tag_name.to_string(),
        });
    }
}

fn extract_handler_value(tag_lower: &str, handler_attr: &str) -> String {
    let Some(pos) = tag_lower.find(handler_attr) else {
        return String::new();
    };
    let rest = &tag_lower[pos + handler_attr.len()..];
    extract_quoted_or_unquoted(rest)
}

fn extract_attr_value(tag_lower: &str, attr: &str) -> Option<String> {
    let pos = tag_lower.find(attr)?;
    let rest = &tag_lower[pos + attr.len()..];
    let value = extract_quoted_or_unquoted(rest);
    if value.is_empty() {
        return None;
    }
    Some(value)
}

fn extract_quoted_or_unquoted(rest: &str) -> String {
    let trimmed = rest.trim_start();
    if let Some(stripped) = trimmed.strip_prefix('"') {
        let end = stripped.find('"').unwrap_or(stripped.len());
        stripped[..end].to_string()
    } else if let Some(stripped) = trimmed.strip_prefix('\'') {
        let end = stripped.find('\'').unwrap_or(stripped.len());
        stripped[..end].to_string()
    } else {
        let end = trimmed
            .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
            .unwrap_or(trimmed.len());
        trimmed[..end].to_string()
    }
}

fn has_unsafe_eval(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    UNSAFE_EVAL_PATTERNS
        .iter()
        .any(|pattern| lower.contains(pattern))
}

fn has_dom_manipulation(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    DOM_MANIPULATION_PATTERNS
        .iter()
        .any(|pattern| lower.contains(pattern))
}

pub fn inline_handler_to_operations(
    issues: &[InlineHandlerIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::CrossSiteScripting,
                inline_handler_severity(issue),
                0.5,
            )
        })
        .collect()
}
