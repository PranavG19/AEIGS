use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum LinkIssueKind {
    ExternalPreload,
    HttpResource,
    DnsPrefetchExternal,
}

#[derive(Debug, Clone)]
pub struct LinkHeaderIssue {
    pub kind: LinkIssueKind,
    pub url: String,
    pub severity: f64,
}

pub fn audit_link_header(target: &str) -> Vec<LinkHeaderIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let resp = match client.get(target).send() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let values: Vec<String> = resp
        .headers()
        .get_all("link")
        .iter()
        .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
        .collect();

    let target_domain = recon_client::validated_domain(target);
    analyze_link_headers(&values, target_domain.as_deref())
}

pub fn analyze_link_headers(
    values: &[String],
    target_domain: Option<&str>,
) -> Vec<LinkHeaderIssue> {
    let mut issues = Vec::new();

    for value in values {
        for entry in value.split(',') {
            let entry = entry.trim();
            let Some(url) = extract_link_url(entry) else {
                continue;
            };
            let rel = extract_rel(entry).unwrap_or_default();
            let lower_rel = rel.to_ascii_lowercase();

            if url.starts_with("http://") {
                issues.push(LinkHeaderIssue {
                    kind: LinkIssueKind::HttpResource,
                    url: recon_client::truncate(&url, 80),
                    severity: 4.5,
                });
            }

            let is_preload = lower_rel.contains("preload")
                || lower_rel.contains("prefetch")
                || lower_rel.contains("prerender")
                || lower_rel.contains("modulepreload");
            let is_dns = lower_rel.contains("dns-prefetch");

            if let Some(domain) = target_domain
                && (is_preload || is_dns)
                && recon_client::is_external(&url, domain)
            {
                let kind = if is_dns {
                    LinkIssueKind::DnsPrefetchExternal
                } else {
                    LinkIssueKind::ExternalPreload
                };
                let severity = if is_preload { 5.0 } else { 3.0 };
                issues.push(LinkHeaderIssue {
                    kind,
                    url: recon_client::truncate(&url, 80),
                    severity,
                });
            }
        }
    }

    issues
}

pub fn extract_link_url(entry: &str) -> Option<String> {
    let start = entry.find('<')? + 1;
    let end = entry[start..].find('>')? + start;
    let url = entry[start..end].trim();
    if url.is_empty() {
        return None;
    }
    Some(url.to_string())
}

pub fn extract_rel(entry: &str) -> Option<String> {
    let lower = entry.to_ascii_lowercase();
    let pos = lower.find("rel=")?;
    let after = &entry[pos + 4..];
    let after = after.trim_start_matches('"').trim_start_matches('\'');
    let end = after.find(['"', '\'', ';', ',']).unwrap_or(after.len());
    Some(after[..end].trim().to_string())
}

pub fn link_header_to_operations(
    issues: &[LinkHeaderIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let max_severity = issues.iter().map(|i| i.severity).fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::SecurityMisconfiguration,
        max_severity,
        0.85,
    )]
}

#[derive(Debug, Clone, PartialEq)]
pub enum LinkSecurityIssue {
    CrossOriginPreload,
    HttpPreload,
    UntrustedCdnPreload,
    ExcessivePreloads,
    SensitiveResourcePreload,
    ModulePreloadExternalOrigin,
    DnsPrefetchExternal,
    PreconnectWithoutCrossorigin,
    PrerenderExternalPage,
    MissingIntegrityAttribute,
}

impl std::fmt::Display for LinkSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkSecurityIssue::CrossOriginPreload => write!(f, "Cross-origin preload detected"),
            LinkSecurityIssue::HttpPreload => write!(f, "Insecure HTTP preload"),
            LinkSecurityIssue::UntrustedCdnPreload => {
                write!(f, "Untrusted CDN preload without integrity")
            }
            LinkSecurityIssue::ExcessivePreloads => write!(f, "Excessive preload/prefetch links"),
            LinkSecurityIssue::SensitiveResourcePreload => {
                write!(f, "Sensitive resource preload detected")
            }
            LinkSecurityIssue::ModulePreloadExternalOrigin => {
                write!(f, "Module preload from external origin")
            }
            LinkSecurityIssue::DnsPrefetchExternal => write!(f, "DNS prefetch for external domain"),
            LinkSecurityIssue::PreconnectWithoutCrossorigin => {
                write!(f, "Preconnect missing crossorigin attribute")
            }
            LinkSecurityIssue::PrerenderExternalPage => write!(f, "Prerender to external page"),
            LinkSecurityIssue::MissingIntegrityAttribute => {
                write!(f, "Missing integrity attribute on preloaded script/style")
            }
        }
    }
}

pub fn analyze_link_security(
    values: &[String],
    target_domain: Option<&str>,
) -> Vec<LinkSecurityIssue> {
    let mut issues = Vec::new();
    let mut preload_count = 0;

    let trusted_cdns = [
        "cdn.jsdelivr.net",
        "cdnjs.cloudflare.com",
        "unpkg.com",
        "cdn.skypack.dev",
    ];

    for value in values {
        for entry in value.split(',') {
            let entry = entry.trim();
            let Some(url) = extract_link_url(entry) else {
                continue;
            };
            let rel = extract_rel(entry).unwrap_or_default();
            let lower_rel = rel.to_ascii_lowercase();
            let lower_entry = entry.to_ascii_lowercase();

            let is_preload = lower_rel.contains("preload");
            let is_prefetch = lower_rel.contains("prefetch");
            let is_modulepreload = lower_rel.contains("modulepreload");
            let is_prerender = lower_rel.contains("prerender");
            let is_preconnect = lower_rel.contains("preconnect");
            let is_dns_prefetch = lower_rel.contains("dns-prefetch");

            if is_preload || is_prefetch {
                preload_count += 1;
            }

            if url.starts_with("http://") && (is_preload || is_prefetch || is_modulepreload) {
                issues.push(LinkSecurityIssue::HttpPreload);
            }

            if let Some(domain) = target_domain {
                let is_external = recon_client::is_external(&url, domain);

                if is_external && (is_preload || is_prefetch) {
                    issues.push(LinkSecurityIssue::CrossOriginPreload);
                }

                if is_external && is_modulepreload {
                    issues.push(LinkSecurityIssue::ModulePreloadExternalOrigin);
                }

                if is_external && is_prerender {
                    issues.push(LinkSecurityIssue::PrerenderExternalPage);
                }

                if is_external && is_dns_prefetch {
                    issues.push(LinkSecurityIssue::DnsPrefetchExternal);
                }

                if is_external && (is_preload || is_prefetch || is_modulepreload) {
                    let url_lower = url.to_ascii_lowercase();
                    let is_trusted = trusted_cdns.iter().any(|cdn| url_lower.contains(cdn));

                    if !is_trusted && !has_integrity_attribute(&lower_entry) {
                        issues.push(LinkSecurityIssue::UntrustedCdnPreload);
                    }
                }
            }

            if is_preconnect && !has_crossorigin_attribute(&lower_entry) {
                issues.push(LinkSecurityIssue::PreconnectWithoutCrossorigin);
            }

            let url_lower = url.to_ascii_lowercase();
            if (is_preload || is_prefetch)
                && (url_lower.contains("/auth")
                    || url_lower.contains("/admin")
                    || url_lower.contains("/api/"))
            {
                issues.push(LinkSecurityIssue::SensitiveResourcePreload);
            }

            if (is_preload || is_prefetch || is_modulepreload)
                && (url_lower.ends_with(".js") || url_lower.ends_with(".css"))
                && !has_integrity_attribute(&lower_entry)
            {
                issues.push(LinkSecurityIssue::MissingIntegrityAttribute);
            }
        }
    }

    if preload_count > 10 {
        issues.push(LinkSecurityIssue::ExcessivePreloads);
    }

    issues
}

fn has_integrity_attribute(entry: &str) -> bool {
    entry.contains("integrity=")
}

fn has_crossorigin_attribute(entry: &str) -> bool {
    entry.contains("crossorigin")
}

pub fn link_security_severity(issue: &LinkSecurityIssue) -> f64 {
    match issue {
        LinkSecurityIssue::HttpPreload => 6.0,
        LinkSecurityIssue::ModulePreloadExternalOrigin => 5.5,
        LinkSecurityIssue::CrossOriginPreload => 5.0,
        LinkSecurityIssue::UntrustedCdnPreload => 5.0,
        LinkSecurityIssue::PrerenderExternalPage => 4.5,
        LinkSecurityIssue::SensitiveResourcePreload => 4.5,
        LinkSecurityIssue::MissingIntegrityAttribute => 4.0,
        LinkSecurityIssue::PreconnectWithoutCrossorigin => 3.5,
        LinkSecurityIssue::DnsPrefetchExternal => 3.0,
        LinkSecurityIssue::ExcessivePreloads => 2.5,
    }
}

pub fn link_security_to_operations(
    issues: &[LinkSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let max_severity = issues
        .iter()
        .map(link_security_severity)
        .fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::SecurityMisconfiguration,
        max_severity,
        0.5,
    )]
}
