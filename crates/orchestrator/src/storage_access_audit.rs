use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum StorageAccessIssue {
    HasStorageAccess,
    RequestStorageAccess,
    RequestStorageAccessFor,
    NoUserGesture,
    IframeContext,
    AutoGrant,
}

impl std::fmt::Display for StorageAccessIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HasStorageAccess => write!(f, "has_storage_access"),
            Self::RequestStorageAccess => write!(f, "request_storage_access"),
            Self::RequestStorageAccessFor => write!(f, "request_storage_access_for"),
            Self::NoUserGesture => write!(f, "no_user_gesture"),
            Self::IframeContext => write!(f, "iframe_context"),
            Self::AutoGrant => write!(f, "auto_grant"),
        }
    }
}

pub fn audit_storage_access(target: &str) -> Vec<StorageAccessIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send() {
        Ok(r) => r.text().unwrap_or_default(),
        Err(_) => return Vec::new(),
    };
    analyze_storage_access(&body)
}

pub fn analyze_storage_access(body: &str) -> Vec<StorageAccessIssue> {
    let has_api = body.contains("hasStorageAccess")
        || body.contains("requestStorageAccess");
    if !has_api {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("hasStorageAccess") {
        issues.push(StorageAccessIssue::HasStorageAccess);
    }

    if body.contains("requestStorageAccess()")
        || (body.contains("requestStorageAccess") && !body.contains("requestStorageAccessFor"))
    {
        issues.push(StorageAccessIssue::RequestStorageAccess);
    }

    if body.contains("requestStorageAccessFor") {
        issues.push(StorageAccessIssue::RequestStorageAccessFor);
    }

    let has_request = body.contains("requestStorageAccess");
    if has_request && !body.contains("click") && !body.contains("pointerdown")
        && !body.contains("touchstart") && !body.contains("keydown")
    {
        issues.push(StorageAccessIssue::NoUserGesture);
    }

    if body.contains("iframe") && has_request {
        issues.push(StorageAccessIssue::IframeContext);
    }

    if has_request && body.contains(".then(") && !body.contains("catch") {
        issues.push(StorageAccessIssue::AutoGrant);
    }

    issues
}

pub fn storage_access_severity(issue: &StorageAccessIssue) -> f64 {
    match issue {
        StorageAccessIssue::RequestStorageAccessFor => 6.0,
        StorageAccessIssue::NoUserGesture => 5.5,
        StorageAccessIssue::AutoGrant => 5.0,
        StorageAccessIssue::IframeContext => 4.5,
        StorageAccessIssue::RequestStorageAccess => 4.0,
        StorageAccessIssue::HasStorageAccess => 3.0,
    }
}

pub fn storage_access_to_operations(
    issues: &[StorageAccessIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                storage_access_severity(issue),
                0.6,
            )
        })
        .collect()
}
