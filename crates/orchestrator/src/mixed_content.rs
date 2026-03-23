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
}

impl std::fmt::Display for MixedContentKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MixedContentKind::Script => write!(f, "script"),
            MixedContentKind::Stylesheet => write!(f, "stylesheet"),
            MixedContentKind::Image => write!(f, "image"),
            MixedContentKind::Iframe => write!(f, "iframe"),
            MixedContentKind::Form => write!(f, "form"),
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
];

pub(crate) fn find_mixed_content(html: &str) -> Vec<MixedContentIssue> {
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
