use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

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
    let lower = html.to_ascii_lowercase();

    for (tag_name, attr, kind) in TAG_ATTRS {
        let pattern = format!("<{tag_name}");
        let attr_pattern = format!("{attr}=");
        let mut search_from = 0;

        while let Some(start) = lower[search_from..].find(&pattern) {
            let abs_start = search_from + start;
            let Some(end) = lower[abs_start..].find('>') else {
                break;
            };
            let tag = &html[abs_start..abs_start + end + 1];
            let tag_lower = &lower[abs_start..abs_start + end + 1];
            search_from = abs_start + end + 1;

            let Some(pos) = tag_lower.find(&attr_pattern) else {
                continue;
            };
            let rest = &tag[pos + attr_pattern.len()..];
            let url = extract_quoted_value(rest);
            if url.starts_with("http://") {
                issues.push(MixedContentIssue {
                    kind: kind.clone(),
                    url,
                });
            }
        }
    }

    issues
}

fn extract_quoted_value(s: &str) -> String {
    let trimmed = s.trim_start();
    if let Some(stripped) = trimmed.strip_prefix('"') {
        stripped
            .find('"')
            .map(|end| stripped[..end].to_string())
            .unwrap_or_default()
    } else if let Some(stripped) = trimmed.strip_prefix('\'') {
        stripped
            .find('\'')
            .map(|end| stripped[..end].to_string())
            .unwrap_or_default()
    } else {
        let end = trimmed
            .find(|c: char| c.is_whitespace() || c == '>')
            .unwrap_or(trimmed.len());
        trimmed[..end].to_string()
    }
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
