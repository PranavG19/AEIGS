use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

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
    let lower = html.to_ascii_lowercase();
    let mut search_from = 0;

    while let Some(start) = lower[search_from..].find("<meta") {
        let abs_start = search_from + start;
        let Some(end) = lower[abs_start..].find('>') else {
            break;
        };
        let tag = &html[abs_start..abs_start + end + 1];
        let tag_lower = &lower[abs_start..abs_start + end + 1];
        search_from = abs_start + end + 1;

        if let Some(name) = extract_attr_value(tag_lower, "name") {
            if let Some(content) = extract_attr_value(tag, "content")
                && DISCLOSURE_META_NAMES.iter().any(|d| name.contains(d))
                && !content.is_empty()
            {
                issues.push(MetaIssue::GeneratorDisclosure(content));
            }

            if name == "robots"
                && let Some(content) = extract_attr_value(tag_lower, "content")
                && content.contains("noindex")
            {
                issues.push(MetaIssue::NoindexOnPublicPage);
            }
        }

        if let Some(equiv) = extract_attr_value(tag_lower, "http-equiv")
            && equiv == "set-cookie"
        {
            issues.push(MetaIssue::SensitiveMetaTag("set-cookie".to_string()));
        }
    }

    issues
}

fn extract_attr_value(tag: &str, attr_name: &str) -> Option<String> {
    let pattern = format!("{attr_name}=");
    let pos = tag.find(&pattern)?;
    let rest = &tag[pos + pattern.len()..];
    let trimmed = rest.trim_start();
    if let Some(stripped) = trimmed.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(stripped[..end].to_string())
    } else if let Some(stripped) = trimmed.strip_prefix('\'') {
        let end = stripped.find('\'')?;
        Some(stripped[..end].to_string())
    } else {
        let end = trimmed
            .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
            .unwrap_or(trimmed.len());
        Some(trimmed[..end].to_string())
    }
}

pub fn meta_findings_to_operations(
    issues: &[MetaIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
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
