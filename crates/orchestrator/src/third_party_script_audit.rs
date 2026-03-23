use std::collections::HashSet;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::html_parser::{self, TagIter};
use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ThirdPartyScriptIssue {
    TrackerScript { domain: String },
    UnknownCdnScript { domain: String },
    HttpScript { url: String },
    ExcessiveThirdParty { count: usize },
    NoSubresourceIntegrity { domain: String },
}

impl std::fmt::Display for ThirdPartyScriptIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TrackerScript { domain } => write!(f, "tracker_script:{domain}"),
            Self::UnknownCdnScript { domain } => write!(f, "unknown_cdn:{domain}"),
            Self::HttpScript { url } => write!(f, "http_script:{url}"),
            Self::ExcessiveThirdParty { count } => {
                write!(f, "excessive_third_party:{count}")
            }
            Self::NoSubresourceIntegrity { domain } => write!(f, "no_sri:{domain}"),
        }
    }
}

const KNOWN_TRACKERS: &[&str] = &[
    "google-analytics.com",
    "googletagmanager.com",
    "facebook.net",
    "connect.facebook.net",
    "analytics.tiktok.com",
    "snap.licdn.com",
    "bat.bing.com",
    "clarity.ms",
    "hotjar.com",
    "mouseflow.com",
    "fullstory.com",
    "segment.com",
    "mixpanel.com",
    "amplitude.com",
    "heap.io",
    "heapanalytics.com",
    "plausible.io",
    "matomo.cloud",
    "crazyegg.com",
    "luckyorange.com",
    "newrelic.com",
    "nr-data.net",
    "sentry.io",
    "cdn.ravenjs.com",
];

const TRUSTED_CDNS: &[&str] = &[
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "ajax.googleapis.com",
    "code.jquery.com",
    "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com",
    "cdn.bootcdn.net",
    "fonts.googleapis.com",
    "use.fontawesome.com",
];

const EXCESSIVE_THRESHOLD: usize = 10;

pub fn audit_third_party_scripts(target: &str) -> Vec<ThirdPartyScriptIssue> {
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
    let target_domain = recon_client::validated_domain(target).unwrap_or_default();
    analyze_third_party_scripts(&body, &target_domain)
}

pub fn analyze_third_party_scripts(html: &str, site_domain: &str) -> Vec<ThirdPartyScriptIssue> {
    let mut issues = Vec::new();
    let mut third_party_domains = HashSet::new();
    let site_lower = site_domain.to_ascii_lowercase();

    for tag in TagIter::new(html, "script") {
        let Some(src) = html_parser::extract_attr(tag.original, &tag.lower, "src") else {
            continue;
        };

        let Some(domain) = extract_script_domain(&src) else {
            continue;
        };

        let domain_lower = domain.to_ascii_lowercase();

        if is_same_site(&domain_lower, &site_lower) {
            continue;
        }

        third_party_domains.insert(domain_lower.clone());

        if src.starts_with("http://") {
            issues.push(ThirdPartyScriptIssue::HttpScript { url: src.clone() });
        }

        if is_tracker(&domain_lower) {
            issues.push(ThirdPartyScriptIssue::TrackerScript {
                domain: domain.clone(),
            });
        } else if !is_trusted_cdn(&domain_lower) {
            issues.push(ThirdPartyScriptIssue::UnknownCdnScript {
                domain: domain.clone(),
            });
        }

        if !tag.lower.contains("integrity") {
            issues.push(ThirdPartyScriptIssue::NoSubresourceIntegrity { domain });
        }
    }

    if third_party_domains.len() > EXCESSIVE_THRESHOLD {
        issues.push(ThirdPartyScriptIssue::ExcessiveThirdParty {
            count: third_party_domains.len(),
        });
    }

    issues
}

fn extract_script_domain(src: &str) -> Option<String> {
    let url = if src.starts_with("//") {
        format!("https:{src}")
    } else if src.starts_with("http://") || src.starts_with("https://") {
        src.to_string()
    } else {
        return None;
    };

    let after_scheme = url.split("//").nth(1)?;
    let domain = after_scheme.split('/').next()?;
    let domain = domain.split(':').next()?;
    if domain.is_empty() || !domain.contains('.') {
        return None;
    }
    Some(domain.to_string())
}

fn is_same_site(script_domain: &str, site_domain: &str) -> bool {
    script_domain == site_domain
        || script_domain.ends_with(&format!(".{site_domain}"))
}

fn is_tracker(domain: &str) -> bool {
    KNOWN_TRACKERS
        .iter()
        .any(|t| domain == *t || domain.ends_with(&format!(".{t}")))
}

fn is_trusted_cdn(domain: &str) -> bool {
    TRUSTED_CDNS
        .iter()
        .any(|c| domain == *c || domain.ends_with(&format!(".{c}")))
}

pub fn third_party_script_severity(issue: &ThirdPartyScriptIssue) -> f64 {
    match issue {
        ThirdPartyScriptIssue::HttpScript { .. } => 7.0,
        ThirdPartyScriptIssue::UnknownCdnScript { .. } => 5.0,
        ThirdPartyScriptIssue::ExcessiveThirdParty { .. } => 4.5,
        ThirdPartyScriptIssue::TrackerScript { .. } => 3.5,
        ThirdPartyScriptIssue::NoSubresourceIntegrity { .. } => 4.0,
    }
}

pub fn third_party_script_to_operations(
    issues: &[ThirdPartyScriptIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                third_party_script_severity(issue),
                0.85,
            )
        })
        .collect()
}
