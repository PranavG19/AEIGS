use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::html_parser::{self, TagIter};
use crate::recon_client;

const DISCLOSURE_META_NAMES: &[&str] = &[
    "generator",
    "author",
    "powered-by",
    "built-with",
    "cms",
    "framework",
];

#[derive(Debug, Clone, PartialEq)]
pub enum MetaIssue {
    GeneratorDisclosure(String),
    SensitiveMetaTag(String),
    NoindexOnPublicPage,
}

impl std::fmt::Display for MetaIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetaIssue::GeneratorDisclosure(v) => write!(f, "generator_disclosure:{v}"),
            MetaIssue::SensitiveMetaTag(v) => write!(f, "sensitive_meta:{v}"),
            MetaIssue::NoindexOnPublicPage => write!(f, "noindex_on_public"),
        }
    }
}

pub fn audit_meta_tags(target: &str) -> Vec<MetaIssue> {
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
    analyze_meta_tags(&body)
}

pub(crate) fn analyze_meta_tags(html: &str) -> Vec<MetaIssue> {
    let mut issues = Vec::new();

    for tag in TagIter::new(html, "meta") {
        if let Some(name) = html_parser::extract_attr_lower(&tag.lower, "name") {
            if let Some(content) = html_parser::extract_attr(tag.original, &tag.lower, "content")
                && DISCLOSURE_META_NAMES.iter().any(|d| name.contains(d))
                && !content.is_empty()
            {
                issues.push(MetaIssue::GeneratorDisclosure(content));
            }

            if name == "robots"
                && let Some(content) = html_parser::extract_attr_lower(&tag.lower, "content")
                && content.contains("noindex")
            {
                issues.push(MetaIssue::NoindexOnPublicPage);
            }
        }

        if let Some(equiv) = html_parser::extract_attr_lower(&tag.lower, "http-equiv")
            && equiv == "set-cookie"
        {
            issues.push(MetaIssue::SensitiveMetaTag("set-cookie".to_string()));
        }
    }

    issues
}

pub fn meta_findings_to_operations(issues: &[MetaIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let has_sensitive = issues
        .iter()
        .any(|i| matches!(i, MetaIssue::SensitiveMetaTag(_)));
    let severity = if has_sensitive { 5.0 } else { 2.5 };

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::InformationDisclosure,
        severity,
        0.85,
    )]
}
