use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum EtagIssueKind {
    InodeLeak,
    WeakEtag,
    LongEtag,
}

#[derive(Debug, Clone)]
pub struct EtagIssue {
    pub kind: EtagIssueKind,
    pub detail: String,
    pub severity: f64,
}

pub fn audit_etag(target: &str) -> Vec<EtagIssue> {
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

    let value = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    analyze_etag(value.as_deref())
}

pub(crate) fn analyze_etag(value: Option<&str>) -> Vec<EtagIssue> {
    let Some(raw) = value else {
        return Vec::new();
    };

    let mut issues = Vec::new();
    let etag = raw.trim().trim_matches('"');

    if is_apache_inode_etag(etag) {
        issues.push(EtagIssue {
            kind: EtagIssueKind::InodeLeak,
            detail: format!("ETag appears to contain inode number (Apache default): {raw}"),
            severity: 4.0,
        });
    }

    if raw.trim().starts_with("W/") {
        issues.push(EtagIssue {
            kind: EtagIssueKind::WeakEtag,
            detail: "Weak ETag (W/) reduces cache integrity guarantees".into(),
            severity: 1.5,
        });
    }

    if etag.len() > 64 {
        issues.push(EtagIssue {
            kind: EtagIssueKind::LongEtag,
            detail: format!("Unusually long ETag ({} chars) may leak internal state", etag.len()),
            severity: 2.5,
        });
    }

    issues
}

fn is_apache_inode_etag(etag: &str) -> bool {
    let parts: Vec<&str> = etag.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    parts
        .iter()
        .all(|p| !p.is_empty() && p.len() <= 16 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

pub fn etag_to_operations(
    issues: &[EtagIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let max_severity = issues
        .iter()
        .map(|i| i.severity)
        .fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::InformationDisclosure,
        max_severity,
        0.8,
    )]
}
