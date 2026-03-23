use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::html_parser::{self, TagIter};
use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum BaseTagIssue {
    ExternalBaseHref,
    HttpBaseHref,
    MultipleBaseTags,
}

impl std::fmt::Display for BaseTagIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BaseTagIssue::ExternalBaseHref => write!(f, "external_base_href"),
            BaseTagIssue::HttpBaseHref => write!(f, "http_base_href"),
            BaseTagIssue::MultipleBaseTags => write!(f, "multiple_base_tags"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BaseTagFinding {
    pub issue: BaseTagIssue,
    pub href: String,
}

pub fn audit_base_tags(target: &str) -> Vec<BaseTagFinding> {
    let Some(domain) = recon_client::validated_domain(target) else {
        return Vec::new();
    };
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send().and_then(|r| r.text()) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    analyze_base_tags(&body, &domain)
}

pub(crate) fn analyze_base_tags(html: &str, domain: &str) -> Vec<BaseTagFinding> {
    let mut findings = Vec::new();
    let tags: Vec<_> = TagIter::new(html, "base").collect();

    if tags.len() > 1 {
        findings.push(BaseTagFinding {
            issue: BaseTagIssue::MultipleBaseTags,
            href: String::new(),
        });
    }

    for tag in &tags {
        let Some(href) = html_parser::extract_attr(tag.original, &tag.lower, "href") else {
            continue;
        };

        if href.starts_with("http://") {
            findings.push(BaseTagFinding {
                issue: BaseTagIssue::HttpBaseHref,
                href: href.clone(),
            });
        }

        if recon_client::is_external(&href, domain) {
            findings.push(BaseTagFinding {
                issue: BaseTagIssue::ExternalBaseHref,
                href,
            });
        }
    }

    findings
}

pub fn base_tag_to_operations(
    findings: &[BaseTagFinding],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if findings.is_empty() {
        return Vec::new();
    }

    let has_external = findings
        .iter()
        .any(|f| f.issue == BaseTagIssue::ExternalBaseHref);
    let severity = if has_external { 7.0 } else { 3.5 };

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::SecurityMisconfiguration,
        severity,
        0.9,
    )]
}
