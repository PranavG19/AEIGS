use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ObjectUrlIssue {
    CreateObjectUrl,
    BlobUrlInScript,
    BlobUrlInIframe,
    DataUrlInScript,
    DataUrlInIframe,
    RevokeNotCalled,
}

impl std::fmt::Display for ObjectUrlIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CreateObjectUrl => write!(f, "create_object_url"),
            Self::BlobUrlInScript => write!(f, "blob_url_script"),
            Self::BlobUrlInIframe => write!(f, "blob_url_iframe"),
            Self::DataUrlInScript => write!(f, "data_url_script"),
            Self::DataUrlInIframe => write!(f, "data_url_iframe"),
            Self::RevokeNotCalled => write!(f, "revoke_not_called"),
        }
    }
}

pub fn audit_object_urls(target: &str) -> Vec<ObjectUrlIssue> {
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
    analyze_object_urls(&body)
}

pub fn analyze_object_urls(body: &str) -> Vec<ObjectUrlIssue> {
    let has_create = body.contains("createObjectURL");
    let needs_lowercase =
        body.contains("blob:") || body.contains("data:") || body.contains("<iframe");
    if !has_create && !needs_lowercase {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if has_create {
        issues.push(ObjectUrlIssue::CreateObjectUrl);
        if !body.contains("revokeObjectURL") {
            issues.push(ObjectUrlIssue::RevokeNotCalled);
        }
    }

    if !needs_lowercase {
        return issues;
    }

    let lower = body.to_ascii_lowercase();

    if has_src_prefix(&lower, "blob:") {
        issues.push(ObjectUrlIssue::BlobUrlInScript);
    }
    if iframe_has_src_prefix(&lower, "blob:") {
        issues.push(ObjectUrlIssue::BlobUrlInIframe);
    }
    if has_src_prefix(&lower, "data:") {
        issues.push(ObjectUrlIssue::DataUrlInScript);
    }
    if iframe_has_src_prefix(&lower, "data:") {
        issues.push(ObjectUrlIssue::DataUrlInIframe);
    }

    issues
}

fn has_src_prefix(lower: &str, prefix: &str) -> bool {
    lower.contains(&format!("src=\"{prefix}"))
        || lower.contains(&format!("src='{prefix}"))
        || lower.contains(&format!("src={prefix}"))
}

fn iframe_has_src_prefix(lower: &str, prefix: &str) -> bool {
    if !lower.contains("<iframe") {
        return false;
    }
    let dq = format!("src=\"{prefix}");
    let sq = format!("src='{prefix}");
    let mut pos = 0;
    while let Some(idx) = lower[pos..].find("<iframe") {
        let abs = pos + idx;
        let tag_end = lower[abs..].find('>').unwrap_or(lower.len() - abs);
        let tag = &lower[abs..abs + tag_end];
        if tag.contains(dq.as_str()) || tag.contains(sq.as_str()) {
            return true;
        }
        pos = abs + tag_end;
    }
    false
}

pub fn object_url_severity(issue: &ObjectUrlIssue) -> f64 {
    match issue {
        ObjectUrlIssue::BlobUrlInScript => 7.0,
        ObjectUrlIssue::DataUrlInScript => 7.0,
        ObjectUrlIssue::BlobUrlInIframe => 6.5,
        ObjectUrlIssue::DataUrlInIframe => 6.5,
        ObjectUrlIssue::RevokeNotCalled => 4.0,
        ObjectUrlIssue::CreateObjectUrl => 3.0,
    }
}

pub fn object_url_to_operations(
    issues: &[ObjectUrlIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::CrossSiteScripting,
                object_url_severity(issue),
                0.75,
            )
        })
        .collect()
}
