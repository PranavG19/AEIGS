use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::html_parser::{self, TagIter};
use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum BaseTagIssue {
    ExternalBaseHref { href: String },
    HttpBaseHref { href: String },
    MultipleBaseTags { count: usize },
    DataUriBaseHref,
    JavascriptUriBaseHref,
    BaseTargetBlank,
    DynamicBaseHref,
    BaseHrefInBody,
    EmptyBaseHref,
}

impl std::fmt::Display for BaseTagIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BaseTagIssue::ExternalBaseHref { .. } => write!(f, "external_base_href"),
            BaseTagIssue::HttpBaseHref { .. } => write!(f, "http_base_href"),
            BaseTagIssue::MultipleBaseTags { .. } => write!(f, "multiple_base_tags"),
            BaseTagIssue::DataUriBaseHref => write!(f, "data_uri_base_href"),
            BaseTagIssue::JavascriptUriBaseHref => write!(f, "javascript_uri_base_href"),
            BaseTagIssue::BaseTargetBlank => write!(f, "base_target_blank"),
            BaseTagIssue::DynamicBaseHref => write!(f, "dynamic_base_href"),
            BaseTagIssue::BaseHrefInBody => write!(f, "base_href_in_body"),
            BaseTagIssue::EmptyBaseHref => write!(f, "empty_base_href"),
        }
    }
}

pub fn base_tag_severity(issue: &BaseTagIssue) -> f64 {
    match issue {
        BaseTagIssue::ExternalBaseHref { .. } => 7.0,
        BaseTagIssue::HttpBaseHref { .. } => 3.5,
        BaseTagIssue::MultipleBaseTags { .. } => 5.0,
        BaseTagIssue::DataUriBaseHref => 8.0,
        BaseTagIssue::JavascriptUriBaseHref => 9.0,
        BaseTagIssue::BaseTargetBlank => 2.0,
        BaseTagIssue::DynamicBaseHref => 6.0,
        BaseTagIssue::BaseHrefInBody => 4.0,
        BaseTagIssue::EmptyBaseHref => 1.5,
    }
}

pub fn audit_base_tags(target: &str) -> Vec<BaseTagIssue> {
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

pub fn analyze_base_tags(html: &str, domain: &str) -> Vec<BaseTagIssue> {
    let mut issues = Vec::new();
    let tags: Vec<_> = TagIter::new(html, "base").collect();

    if tags.len() > 1 {
        issues.push(BaseTagIssue::MultipleBaseTags { count: tags.len() });
    }

    let lower_html = html.to_ascii_lowercase();
    let body_start = lower_html.find("<body");

    for tag in &tags {
        if let Some(body_pos) = body_start {
            let tag_pos = html.as_ptr() as usize;
            let orig_ptr = tag.original.as_ptr() as usize;
            let offset = orig_ptr - tag_pos;
            if offset >= body_pos {
                issues.push(BaseTagIssue::BaseHrefInBody);
            }
        }

        if let Some(target_val) = html_parser::extract_attr(tag.original, &tag.lower, "target")
            && target_val.eq_ignore_ascii_case("_blank")
        {
            issues.push(BaseTagIssue::BaseTargetBlank);
        }

        let Some(href) = html_parser::extract_attr(tag.original, &tag.lower, "href") else {
            continue;
        };

        if href.is_empty() {
            issues.push(BaseTagIssue::EmptyBaseHref);
            continue;
        }

        let href_lower = href.to_ascii_lowercase();

        if href_lower.starts_with("data:") {
            issues.push(BaseTagIssue::DataUriBaseHref);
            continue;
        }

        if href_lower.starts_with("javascript:") {
            issues.push(BaseTagIssue::JavascriptUriBaseHref);
            continue;
        }

        if href.contains("${") || href.contains("{{") {
            issues.push(BaseTagIssue::DynamicBaseHref);
            continue;
        }

        if href_lower.starts_with("http://") {
            issues.push(BaseTagIssue::HttpBaseHref { href: href.clone() });
        }

        if recon_client::is_external(&href, domain) {
            issues.push(BaseTagIssue::ExternalBaseHref { href });
        }
    }

    issues
}

pub fn base_tag_to_operations(issues: &[BaseTagIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                base_tag_severity(issue),
                0.5,
            )
        })
        .collect()
}
