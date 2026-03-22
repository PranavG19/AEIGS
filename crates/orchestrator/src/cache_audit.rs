use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone)]
pub struct CacheIssue {
    pub kind: CacheIssueKind,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub enum CacheIssueKind {
    MissingCacheControl,
    PublicWithoutRevalidation,
    NoNoStore,
}

pub fn audit_cache_headers(target: &str) -> Vec<CacheIssue> {
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

    let cache_control = resp
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase());

    let pragma = resp
        .headers()
        .get("pragma")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase());

    analyze_cache_headers(cache_control.as_deref(), pragma.as_deref())
}

pub(crate) fn analyze_cache_headers(
    cache_control: Option<&str>,
    pragma: Option<&str>,
) -> Vec<CacheIssue> {
    let mut issues = Vec::new();

    let Some(cc) = cache_control else {
        if pragma.is_none() {
            issues.push(CacheIssue {
                kind: CacheIssueKind::MissingCacheControl,
                detail: "No Cache-Control or Pragma header present".to_string(),
            });
        }
        return issues;
    };

    if cc.contains("public") && !cc.contains("no-cache") && !cc.contains("must-revalidate") {
        issues.push(CacheIssue {
            kind: CacheIssueKind::PublicWithoutRevalidation,
            detail: "Cache-Control: public without no-cache or must-revalidate".to_string(),
        });
    }

    if !cc.contains("no-store") && !cc.contains("private") {
        issues.push(CacheIssue {
            kind: CacheIssueKind::NoNoStore,
            detail: "Cache-Control missing no-store and private directives".to_string(),
        });
    }

    issues
}

fn issue_severity(issue: &CacheIssue) -> f64 {
    match issue.kind {
        CacheIssueKind::MissingCacheControl => 2.5,
        CacheIssueKind::PublicWithoutRevalidation => 3.5,
        CacheIssueKind::NoNoStore => 2.0,
    }
}

pub fn cache_findings_to_operations(
    issues: &[CacheIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let is_missing = issues
        .iter()
        .any(|i| matches!(i.kind, CacheIssueKind::MissingCacheControl));

    let vuln_class = if is_missing {
        VulnerabilityClass::MissingSecurityHeader
    } else {
        VulnerabilityClass::SecurityMisconfiguration
    };

    let max_severity = issues.iter().map(issue_severity).fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        vuln_class,
        max_severity,
        0.85,
    )]
}
