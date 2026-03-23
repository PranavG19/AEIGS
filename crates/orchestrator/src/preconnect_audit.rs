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

pub fn analyze_preconnects(html: &str) -> Vec<PreconnectIssue> {
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

#[derive(Debug, Clone, PartialEq)]
pub enum PreconnectSecurityIssue {
    HttpPreconnect { href: String },
    ThirdPartyPreconnect { href: String },
    ExcessiveResourceHints { count: usize },
    TrackingPixelPreconnect { href: String },
    MissingCrossoriginAttribute { href: String },
    PreconnectToSuspiciousTld { href: String, tld: String },
    DnsPrefetchToExternal { href: String },
    PreloadWithoutIntegrity { href: String },
    PrerenderExternalUrl { href: String },
    DuplicateResourceHint { href: String },
}

impl std::fmt::Display for PreconnectSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HttpPreconnect { href } => {
                write!(f, "preconnect to HTTP origin: {}", href)
            }
            Self::ThirdPartyPreconnect { href } => {
                write!(f, "preconnect to unknown third-party domain: {}", href)
            }
            Self::ExcessiveResourceHints { count } => {
                write!(
                    f,
                    "excessive resource hints ({} total) degrade performance",
                    count
                )
            }
            Self::TrackingPixelPreconnect { href } => {
                write!(f, "preconnect to known tracking domain: {}", href)
            }
            Self::MissingCrossoriginAttribute { href } => {
                write!(
                    f,
                    "cross-origin preconnect missing crossorigin attribute: {}",
                    href
                )
            }
            Self::PreconnectToSuspiciousTld { href, tld } => {
                write!(f, "preconnect to suspicious TLD ({}): {}", tld, href)
            }
            Self::DnsPrefetchToExternal { href } => {
                write!(f, "dns-prefetch pointing to external domain: {}", href)
            }
            Self::PreloadWithoutIntegrity { href } => {
                write!(f, "preload of script/style without integrity: {}", href)
            }
            Self::PrerenderExternalUrl { href } => {
                write!(f, "prerender hint pointing to external URL: {}", href)
            }
            Self::DuplicateResourceHint { href } => {
                write!(f, "duplicate resource hint for URL: {}", href)
            }
        }
    }
}

const TRACKING_DOMAINS: &[&str] = &[
    "google-analytics.com",
    "googletagmanager.com",
    "facebook.com",
    "facebook.net",
    "doubleclick.net",
    "scorecardresearch.com",
    "hotjar.com",
    "mouseflow.com",
    "amplitude.com",
    "segment.com",
    "mixpanel.com",
];

const SUSPICIOUS_TLDS: &[&str] = &[
    ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc", ".top", ".xyz", ".work",
];

const MAX_RESOURCE_HINTS: usize = 10;

pub fn analyze_preconnect_security(html: &str) -> Vec<PreconnectSecurityIssue> {
    let mut issues = Vec::new();
    let mut seen_urls = std::collections::HashSet::new();
    let mut resource_hint_count = 0usize;

    for tag in TagIter::new(html, "link") {
        let Some(rel) = extract_attr_lower(&tag.lower, "rel") else {
            continue;
        };

        let is_preconnect = rel == "preconnect";
        let is_prefetch = rel == "dns-prefetch";
        let is_preload = rel == "preload";
        let is_prerender = rel == "prerender";

        if !is_preconnect && !is_prefetch && !is_preload && !is_prerender {
            continue;
        }

        resource_hint_count += 1;

        let href = extract_attr(tag.original, &tag.lower, "href").unwrap_or_default();
        if href.is_empty() {
            continue;
        }

        if !seen_urls.insert(href.clone()) {
            issues.push(PreconnectSecurityIssue::DuplicateResourceHint { href: href.clone() });
        }

        if href.starts_with("http://") {
            issues.push(PreconnectSecurityIssue::HttpPreconnect { href: href.clone() });
        }

        if is_preconnect
            && (href.starts_with("http") || href.starts_with("//"))
            && !tag.lower.contains("crossorigin")
        {
            issues
                .push(PreconnectSecurityIssue::MissingCrossoriginAttribute { href: href.clone() });
        }

        if let Some(domain) = extract_domain_from_url(&href) {
            if TRACKING_DOMAINS.iter().any(|&td| domain.contains(td)) {
                issues
                    .push(PreconnectSecurityIssue::TrackingPixelPreconnect { href: href.clone() });
            }

            for &tld in SUSPICIOUS_TLDS {
                if domain.ends_with(tld) {
                    issues.push(PreconnectSecurityIssue::PreconnectToSuspiciousTld {
                        href: href.clone(),
                        tld: tld.to_string(),
                    });
                    break;
                }
            }

            if is_preconnect && is_third_party_domain(&domain) {
                issues.push(PreconnectSecurityIssue::ThirdPartyPreconnect { href: href.clone() });
            }

            if is_prefetch && is_external_domain(&domain) {
                issues.push(PreconnectSecurityIssue::DnsPrefetchToExternal { href: href.clone() });
            }
        }

        if is_preload {
            let as_attr = extract_attr_lower(&tag.lower, "as").unwrap_or_default();
            if (as_attr == "script" || as_attr == "style") && !tag.lower.contains("integrity") {
                issues
                    .push(PreconnectSecurityIssue::PreloadWithoutIntegrity { href: href.clone() });
            }
        }

        if is_prerender && is_external_url(&href) {
            issues.push(PreconnectSecurityIssue::PrerenderExternalUrl { href: href.clone() });
        }
    }

    if resource_hint_count > MAX_RESOURCE_HINTS {
        issues.push(PreconnectSecurityIssue::ExcessiveResourceHints {
            count: resource_hint_count,
        });
    }

    issues
}

fn extract_domain_from_url(url: &str) -> Option<String> {
    if let Some(start) = url.find("://") {
        let after_protocol = &url[start + 3..];
        if let Some(end) = after_protocol.find('/') {
            Some(after_protocol[..end].to_lowercase())
        } else {
            Some(after_protocol.to_lowercase())
        }
    } else if let Some(after_slashes) = url.strip_prefix("//") {
        if let Some(end) = after_slashes.find('/') {
            Some(after_slashes[..end].to_lowercase())
        } else {
            Some(after_slashes.to_lowercase())
        }
    } else {
        None
    }
}

fn is_third_party_domain(domain: &str) -> bool {
    !domain.contains("localhost")
        && !domain.starts_with("127.0.0.1")
        && !domain.starts_with("::1")
        && !domain.contains("example.com")
        && !domain.contains("test.com")
}

fn is_external_domain(domain: &str) -> bool {
    !domain.contains("localhost") && !domain.starts_with("127.0.0.1") && !domain.starts_with("::1")
}

fn is_external_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://") || url.starts_with("//")
}

pub fn preconnect_security_severity(issue: &PreconnectSecurityIssue) -> f64 {
    match issue {
        PreconnectSecurityIssue::HttpPreconnect { .. } => 6.0,
        PreconnectSecurityIssue::PreloadWithoutIntegrity { .. } => 5.5,
        PreconnectSecurityIssue::PreconnectToSuspiciousTld { .. } => 5.0,
        PreconnectSecurityIssue::TrackingPixelPreconnect { .. } => 4.0,
        PreconnectSecurityIssue::PrerenderExternalUrl { .. } => 3.5,
        PreconnectSecurityIssue::MissingCrossoriginAttribute { .. } => 3.0,
        PreconnectSecurityIssue::ThirdPartyPreconnect { .. } => 2.5,
        PreconnectSecurityIssue::DnsPrefetchToExternal { .. } => 2.0,
        PreconnectSecurityIssue::ExcessiveResourceHints { .. } => 2.0,
        PreconnectSecurityIssue::DuplicateResourceHint { .. } => 1.5,
    }
}

pub fn preconnect_security_to_operations(
    issues: &[PreconnectSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            let severity = preconnect_security_severity(issue);
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                severity,
                0.5,
            )
        })
        .collect()
}
