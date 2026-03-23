use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ClearSiteDataIssueKind {
    WildcardOnGet,
    CookieClearOnGet,
    StorageClearOnGet,
    CacheClearOnGet,
    HttpNotHttps,
}

#[derive(Debug, Clone)]
pub struct ClearSiteDataIssue {
    pub kind: ClearSiteDataIssueKind,
    pub detail: String,
    pub severity: f64,
}

pub fn audit_clear_site_data(target: &str) -> Vec<ClearSiteDataIssue> {
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

    let is_https = target.starts_with("https://");
    let value = resp
        .headers()
        .get("clear-site-data")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    analyze_clear_site_data(value.as_deref(), is_https)
}

pub(crate) fn analyze_clear_site_data(
    value: Option<&str>,
    is_https: bool,
) -> Vec<ClearSiteDataIssue> {
    let Some(val) = value else {
        return Vec::new();
    };

    let mut issues = Vec::new();

    if !is_https {
        issues.push(ClearSiteDataIssue {
            kind: ClearSiteDataIssueKind::HttpNotHttps,
            detail: "Clear-Site-Data over HTTP has no effect (requires HTTPS)".into(),
            severity: 2.0,
        });
    }

    let lower = val.to_ascii_lowercase();
    let directives: Vec<&str> = lower
        .split(',')
        .map(|s| s.trim().trim_matches('"'))
        .collect();

    if directives.contains(&"*") {
        issues.push(ClearSiteDataIssue {
            kind: ClearSiteDataIssueKind::WildcardOnGet,
            detail: "Clear-Site-Data: \"*\" on GET clears all browser state".into(),
            severity: 5.5,
        });
        return issues;
    }

    if directives.contains(&"cookies") {
        issues.push(ClearSiteDataIssue {
            kind: ClearSiteDataIssueKind::CookieClearOnGet,
            detail: "Clear-Site-Data clears cookies on GET — may log users out".into(),
            severity: 4.5,
        });
    }

    if directives.contains(&"storage") {
        issues.push(ClearSiteDataIssue {
            kind: ClearSiteDataIssueKind::StorageClearOnGet,
            detail: "Clear-Site-Data clears storage on GET — destroys client state".into(),
            severity: 4.0,
        });
    }

    if directives.contains(&"cache") {
        issues.push(ClearSiteDataIssue {
            kind: ClearSiteDataIssueKind::CacheClearOnGet,
            detail: "Clear-Site-Data clears cache on GET — forces full re-download".into(),
            severity: 3.0,
        });
    }

    issues
}

pub fn clear_site_data_to_operations(
    issues: &[ClearSiteDataIssue],
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
        0.9,
    )]
}
