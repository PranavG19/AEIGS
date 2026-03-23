use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::html_parser::{TagIter, extract_attr, extract_attr_lower};
use crate::recon_client;

#[derive(Debug, Clone)]
pub struct PreconnectIssue {
    pub href: String,
    pub rel: String,
    pub kind: PreconnectIssueKind,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PreconnectIssueKind {
    HttpOrigin,
    MissingCrossorigin,
    ExcessivePreconnects,
}

impl std::fmt::Display for PreconnectIssueKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HttpOrigin => write!(f, "preconnect/prefetch uses HTTP"),
            Self::MissingCrossorigin => {
                write!(f, "cross-origin preconnect missing crossorigin attribute")
            }
            Self::ExcessivePreconnects => {
                write!(f, "excessive preconnect hints (>6) degrade performance")
            }
        }
    }
}

const MAX_PRECONNECTS: usize = 6;

pub fn audit_preconnects(target: &str) -> Vec<PreconnectIssue> {
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
    analyze_preconnects(&body)
}

pub(crate) fn analyze_preconnects(html: &str) -> Vec<PreconnectIssue> {
    let mut issues = Vec::new();
    let mut preconnect_count = 0usize;

    for tag in TagIter::new(html, "link") {
        let Some(rel) = extract_attr_lower(&tag.lower, "rel") else {
            continue;
        };
        let is_preconnect = rel == "preconnect";
        let is_prefetch = rel == "dns-prefetch";
        if !is_preconnect && !is_prefetch {
            continue;
        }

        preconnect_count += 1;

        let href = extract_attr(tag.original, &tag.lower, "href").unwrap_or_default();
        if href.is_empty() {
            continue;
        }

        if href.starts_with("http://") {
            issues.push(PreconnectIssue {
                href: href.clone(),
                rel: rel.clone(),
                kind: PreconnectIssueKind::HttpOrigin,
            });
        }

        if is_preconnect && href.starts_with("http") && !tag.lower.contains("crossorigin") {
            issues.push(PreconnectIssue {
                href,
                rel,
                kind: PreconnectIssueKind::MissingCrossorigin,
            });
        }
    }

    if preconnect_count > MAX_PRECONNECTS {
        issues.push(PreconnectIssue {
            href: String::new(),
            rel: String::new(),
            kind: PreconnectIssueKind::ExcessivePreconnects,
        });
    }

    issues
}

pub fn preconnect_to_operations(
    issues: &[PreconnectIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let has_http = issues
        .iter()
        .any(|i| i.kind == PreconnectIssueKind::HttpOrigin);

    let max_severity = if has_http { 4.0 } else { 2.0 };

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::SecurityMisconfiguration,
        max_severity,
        0.7,
    )]
}
