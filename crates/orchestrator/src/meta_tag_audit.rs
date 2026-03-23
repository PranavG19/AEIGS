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
    CspViaMetaTag(String),
    RefreshRedirect { url: String, delay: u32 },
    ReferrerPolicyInsecure(String),
    OpenGraphInfoLeak(String),
    ViewportManipulation(String),
    BaseUriInMeta(String),
    DnsPrefetchControl(String),
    HttpEquivXssProtection(String),
    ContentSecurityPolicyReportUri(String),
    ThemeColorExposure(String),
}

impl std::fmt::Display for MetaIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetaIssue::GeneratorDisclosure(v) => write!(f, "generator_disclosure:{v}"),
            MetaIssue::SensitiveMetaTag(v) => write!(f, "sensitive_meta:{v}"),
            MetaIssue::NoindexOnPublicPage => write!(f, "noindex_on_public"),
            MetaIssue::CspViaMetaTag(v) => write!(f, "csp_via_meta:{v}"),
            MetaIssue::RefreshRedirect { url, delay } => {
                write!(f, "refresh_redirect:url={url},delay={delay}")
            }
            MetaIssue::ReferrerPolicyInsecure(v) => write!(f, "referrer_policy_insecure:{v}"),
            MetaIssue::OpenGraphInfoLeak(v) => write!(f, "opengraph_info_leak:{v}"),
            MetaIssue::ViewportManipulation(v) => write!(f, "viewport_manipulation:{v}"),
            MetaIssue::BaseUriInMeta(v) => write!(f, "base_uri_in_meta:{v}"),
            MetaIssue::DnsPrefetchControl(v) => write!(f, "dns_prefetch_control:{v}"),
            MetaIssue::HttpEquivXssProtection(v) => write!(f, "http_equiv_xss_protection:{v}"),
            MetaIssue::ContentSecurityPolicyReportUri(v) => {
                write!(f, "csp_report_uri_in_meta:{v}")
            }
            MetaIssue::ThemeColorExposure(v) => write!(f, "theme_color_exposure:{v}"),
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

pub fn analyze_meta_tags(html: &str) -> Vec<MetaIssue> {
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

pub fn analyze_meta_tags_security(html: &str) -> Vec<MetaIssue> {
    let mut issues = Vec::new();

    for tag in TagIter::new(html, "meta") {
        if let Some(equiv) = html_parser::extract_attr_lower(&tag.lower, "http-equiv") {
            if equiv == "content-security-policy" {
                if let Some(content) =
                    html_parser::extract_attr(tag.original, &tag.lower, "content")
                {
                    if content.contains("report-uri") {
                        issues.push(MetaIssue::ContentSecurityPolicyReportUri(content.clone()));
                    }
                    issues.push(MetaIssue::CspViaMetaTag(content));
                }
            } else if equiv == "refresh" {
                if let Some(content) =
                    html_parser::extract_attr(tag.original, &tag.lower, "content")
                    && (content.contains("url=") || content.contains("URL="))
                {
                    let parts: Vec<&str> = content.splitn(2, ';').collect();
                    let delay = parts[0].trim().parse::<u32>().unwrap_or(0);
                    let url = if parts.len() > 1 {
                        parts[1]
                            .trim()
                            .trim_start_matches("url=")
                            .trim_start_matches("URL=")
                            .to_string()
                    } else {
                        String::new()
                    };
                    if !url.is_empty() {
                        issues.push(MetaIssue::RefreshRedirect { url, delay });
                    }
                }
            } else if equiv == "x-dns-prefetch-control" {
                if let Some(content) = html_parser::extract_attr_lower(&tag.lower, "content")
                    && content == "on"
                {
                    issues.push(MetaIssue::DnsPrefetchControl(content));
                }
            } else if equiv == "x-xss-protection" {
                if let Some(content) =
                    html_parser::extract_attr(tag.original, &tag.lower, "content")
                    && content.contains('0')
                {
                    issues.push(MetaIssue::HttpEquivXssProtection(content));
                }
            } else if equiv.contains("base")
                && let Some(content) =
                    html_parser::extract_attr(tag.original, &tag.lower, "content")
            {
                issues.push(MetaIssue::BaseUriInMeta(content));
            }
        }

        if let Some(name) = html_parser::extract_attr_lower(&tag.lower, "name") {
            if name == "referrer"
                && let Some(content) =
                    html_parser::extract_attr(tag.original, &tag.lower, "content")
            {
                let content_lower = content.to_lowercase();
                if content_lower == "no-referrer-when-downgrade"
                    || content_lower == "unsafe-url"
                    || content_lower == "origin"
                {
                    issues.push(MetaIssue::ReferrerPolicyInsecure(content));
                }
            } else if name == "viewport"
                && let Some(content) = html_parser::extract_attr_lower(&tag.lower, "content")
                && (content.contains("user-scalable=no") || content.contains("maximum-scale=1"))
            {
                issues.push(MetaIssue::ViewportManipulation(content));
            } else if name == "theme-color"
                && let Some(content) =
                    html_parser::extract_attr(tag.original, &tag.lower, "content")
                && !content.is_empty()
            {
                issues.push(MetaIssue::ThemeColorExposure(content));
            }
        }

        if let Some(property) = html_parser::extract_attr_lower(&tag.lower, "property")
            && property.starts_with("og:")
            && let Some(content) = html_parser::extract_attr(tag.original, &tag.lower, "content")
        {
            let content_lower = content.to_lowercase();
            if content_lower.contains("@")
                || content_lower.contains("localhost")
                || content_lower.contains("127.0.0.1")
                || content_lower.contains("192.168.")
                || content_lower.contains("10.")
                || content_lower
                    .matches(char::is_numeric)
                    .collect::<String>()
                    .len()
                    >= 10
            {
                issues.push(MetaIssue::OpenGraphInfoLeak(content));
            }
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
