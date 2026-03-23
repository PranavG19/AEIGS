use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum StorageBucketIssue {
    ApiDetected,
    PersistentStorage,
    UnboundedQuota,
    CrossOriginLeak,
    DataExfiltration,
}

impl std::fmt::Display for StorageBucketIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::PersistentStorage => write!(f, "persistent_storage"),
            Self::UnboundedQuota => write!(f, "unbounded_quota"),
            Self::CrossOriginLeak => write!(f, "cross_origin_leak"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
        }
    }
}

pub fn audit_storage_bucket(target: &str) -> Vec<StorageBucketIssue> {
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
    analyze_storage_bucket(&body)
}

pub fn analyze_storage_bucket(body: &str) -> Vec<StorageBucketIssue> {
    let has_api = body.contains("storageBuckets")
        || body.contains("StorageBucket")
        || body.contains("navigator.storageBuckets");

    if !has_api {
        return Vec::new();
    }

    let mut issues = vec![StorageBucketIssue::ApiDetected];

    let has_persist = body.contains("persisted") || body.contains("persist");
    let has_consent = body.contains("Notification.permission")
        || body.contains("permission")
        || body.contains("consent");
    if has_persist && !has_consent {
        issues.push(StorageBucketIssue::PersistentStorage);
    }

    let has_quota_call = body.contains("open(") || body.contains("quota");
    let has_quota_limit =
        body.contains("quota:") || body.contains("maxSize") || body.contains("limit");
    if has_quota_call && !has_quota_limit {
        issues.push(StorageBucketIssue::UnboundedQuota);
    }

    let has_storage_access =
        body.contains("indexedDB") || body.contains("caches") || body.contains("getDirectory");
    let has_cross_origin = body.contains("postMessage")
        || body.contains("SharedWorker")
        || body.contains("BroadcastChannel");
    if has_storage_access && has_cross_origin {
        issues.push(StorageBucketIssue::CrossOriginLeak);
    }

    let has_data_read =
        body.contains("keys()") || body.contains("getAll") || body.contains("entries");
    let has_external_send =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_data_read && has_external_send {
        issues.push(StorageBucketIssue::DataExfiltration);
    }

    issues
}

pub fn storage_bucket_severity(issue: &StorageBucketIssue) -> f64 {
    match issue {
        StorageBucketIssue::ApiDetected => 2.0,
        StorageBucketIssue::PersistentStorage => 6.5,
        StorageBucketIssue::UnboundedQuota => 6.0,
        StorageBucketIssue::CrossOriginLeak => 7.0,
        StorageBucketIssue::DataExfiltration => 7.5,
    }
}

pub fn storage_bucket_to_operations(
    issues: &[StorageBucketIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                storage_bucket_severity(issue),
                0.5,
            )
        })
        .collect()
}
