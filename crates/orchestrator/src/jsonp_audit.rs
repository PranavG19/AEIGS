use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::html_parser::{self, TagIter};
use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum JsonpIssueKind {
    CallbackParam,
    JsonpEndpoint,
}

#[derive(Debug, Clone)]
pub struct JsonpIssue {
    pub kind: JsonpIssueKind,
    pub url: String,
    pub severity: f64,
}

pub fn audit_jsonp(target: &str) -> Vec<JsonpIssue> {
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
    find_jsonp_endpoints(&body)
}

const CALLBACK_PARAMS: &[&str] = &[
    "callback=",
    "jsonp=",
    "cb=",
    "jsonpcallback=",
    "jsoncallback=",
    "_callback=",
];

pub(crate) fn find_jsonp_endpoints(html: &str) -> Vec<JsonpIssue> {
    let mut issues = Vec::new();

    for tag in TagIter::new(html, "script") {
        let Some(src) = html_parser::extract_attr(tag.original, &tag.lower, "src") else {
            continue;
        };
        let src_lower = src.to_ascii_lowercase();
        let truncated = recon_client::truncate(&src, 100);
        for param in CALLBACK_PARAMS {
            if src_lower.contains(param) {
                issues.push(JsonpIssue {
                    kind: JsonpIssueKind::CallbackParam,
                    url: truncated.clone(),
                    severity: 5.5,
                });
                break;
            }
        }
        if (src_lower.contains("jsonp") || src_lower.ends_with(".jsonp"))
            && !issues.iter().any(|i| i.url == truncated)
        {
            issues.push(JsonpIssue {
                kind: JsonpIssueKind::JsonpEndpoint,
                url: truncated,
                severity: 4.5,
            });
        }
    }

    issues
}

pub fn jsonp_to_operations(
    issues: &[JsonpIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let max_severity = issues
        .iter()
        .map(|i| i.severity)
        .fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::CrossSiteScripting,
        max_severity,
        0.75,
    )]
}
