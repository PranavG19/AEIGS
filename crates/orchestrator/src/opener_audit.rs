use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::html_parser::{self, TagIter};
use crate::recon_client;

#[derive(Debug, Clone)]
pub struct OpenerIssue {
    pub href: String,
}

pub fn audit_opener(target: &str) -> Vec<OpenerIssue> {
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
    find_opener_issues(&body)
}

pub(crate) fn find_opener_issues(html: &str) -> Vec<OpenerIssue> {
    let mut issues = Vec::new();

    for tag in TagIter::new(html, "a") {
        let target_attr =
            html_parser::extract_attr_lower(&tag.lower, "target").unwrap_or_default();
        if target_attr != "_blank" {
            continue;
        }

        let rel = html_parser::extract_attr_lower(&tag.lower, "rel").unwrap_or_default();
        if rel.contains("noopener") || rel.contains("noreferrer") {
            continue;
        }

        let href = html_parser::extract_attr(tag.original, &tag.lower, "href").unwrap_or_default();
        if !href.starts_with("http://") && !href.starts_with("https://") {
            continue;
        }

        issues.push(OpenerIssue { href });
    }

    issues
}

pub fn opener_to_operations(
    issues: &[OpenerIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::SecurityMisconfiguration,
        3.0,
        0.9,
    )]
}
