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

#[derive(Debug, Clone)]
pub struct InlineHandlerIssue {
    pub tag: String,
    pub handler: String,
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

pub(crate) fn find_inline_handlers(html: &str) -> Vec<InlineHandlerIssue> {
    let mut issues = Vec::new();

    for tag_name in RISKY_TAGS {
        for tag in TagIter::new(html, tag_name) {
            for handler in INLINE_EVENT_HANDLERS {
                if tag.lower.contains(handler) {
                    let handler_name = handler.trim_end_matches('=');
                    issues.push(InlineHandlerIssue {
                        tag: tag_name.to_string(),
                        handler: handler_name.to_string(),
                    });
                    break;
                }
            }
        }
    }

    issues
}

pub fn inline_handler_to_operations(
    issues: &[InlineHandlerIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let severity = if issues.len() > 5 { 4.0 } else { 2.5 };

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::CrossSiteScripting,
        severity,
        0.6,
    )]
}
