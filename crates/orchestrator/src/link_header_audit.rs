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

pub(crate) fn analyze_link_headers(
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

fn extract_link_url(entry: &str) -> Option<String> {
    let start = entry.find('<')? + 1;
    let end = entry[start..].find('>')? + start;
    let url = entry[start..end].trim();
    if url.is_empty() {
        return None;
    }
    Some(url.to_string())
}

fn extract_rel(entry: &str) -> Option<String> {
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
