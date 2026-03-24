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

#[derive(Debug, Clone, PartialEq)]
pub enum StorageBucketSecurityIssue {
    BucketDataExfiltration,
    BucketSensitiveData,
    BucketNoExpiration,
    BucketCrossOrigin,
    BucketEnumeration,
    BucketOverQuota,
    BucketInBackground,
    BucketFingerprinting,
    BucketWithoutPermission,
    BucketPersistentTracking,
}

impl std::fmt::Display for StorageBucketSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BucketDataExfiltration => write!(f, "bucket_data_exfiltration"),
            Self::BucketSensitiveData => write!(f, "bucket_sensitive_data"),
            Self::BucketNoExpiration => write!(f, "bucket_no_expiration"),
            Self::BucketCrossOrigin => write!(f, "bucket_cross_origin"),
            Self::BucketEnumeration => write!(f, "bucket_enumeration"),
            Self::BucketOverQuota => write!(f, "bucket_over_quota"),
            Self::BucketInBackground => write!(f, "bucket_in_background"),
            Self::BucketFingerprinting => write!(f, "bucket_fingerprinting"),
            Self::BucketWithoutPermission => write!(f, "bucket_without_permission"),
            Self::BucketPersistentTracking => write!(f, "bucket_persistent_tracking"),
        }
    }
}

pub fn analyze_storage_bucket_security(body: &str) -> Vec<StorageBucketSecurityIssue> {
    let has_api = body.contains("storageBuckets") || body.contains("StorageBucket");

    if !has_api {
        return Vec::new();
    }

    let mut issues = Vec::new();

    let has_storage_access = body.contains("indexedDB")
        || body.contains("caches")
        || body.contains("getDirectory")
        || body.contains("open(");
    let has_external_send =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_storage_access && has_external_send {
        issues.push(StorageBucketSecurityIssue::BucketDataExfiltration);
    }

    let has_pii = body.contains("email")
        || body.contains("password")
        || body.contains("ssn")
        || body.contains("creditCard")
        || body.contains("token");
    if has_storage_access && has_pii {
        issues.push(StorageBucketSecurityIssue::BucketSensitiveData);
    }

    let has_persist = body.contains("persist()") || body.contains("persisted()");
    let has_expiration =
        body.contains("ttl") || body.contains("expiration") || body.contains("expires");
    if has_persist && !has_expiration {
        issues.push(StorageBucketSecurityIssue::BucketNoExpiration);
    }

    let has_post_message = body.contains("postMessage");
    if has_storage_access && has_post_message {
        issues.push(StorageBucketSecurityIssue::BucketCrossOrigin);
    }

    let has_enumeration =
        body.contains("storageBuckets.keys()") || body.contains("keys()") || body.contains("list");
    if has_enumeration {
        issues.push(StorageBucketSecurityIssue::BucketEnumeration);
    }

    let has_quota_error = body.contains("QuotaExceededError") || body.contains("catch");
    if has_storage_access && !has_quota_error {
        issues.push(StorageBucketSecurityIssue::BucketOverQuota);
    }

    let has_visibility = body.contains("visibilitychange") || body.contains("hidden");
    if has_storage_access && has_visibility {
        issues.push(StorageBucketSecurityIssue::BucketInBackground);
    }

    let has_fingerprint = body.contains("userAgent") || body.contains("navigator.");
    if has_storage_access && has_fingerprint {
        issues.push(StorageBucketSecurityIssue::BucketFingerprinting);
    }

    let has_permission_check = body.contains("permissions.query") || body.contains("permission");
    if has_storage_access && !has_permission_check {
        issues.push(StorageBucketSecurityIssue::BucketWithoutPermission);
    }

    let has_unique_id = body.contains("uuid")
        || body.contains("sessionId")
        || body.contains("userId")
        || body.contains("deviceId");
    if has_persist && has_unique_id {
        issues.push(StorageBucketSecurityIssue::BucketPersistentTracking);
    }

    issues
}

pub fn storage_bucket_security_severity(issue: &StorageBucketSecurityIssue) -> f64 {
    match issue {
        StorageBucketSecurityIssue::BucketDataExfiltration => 8.5,
        StorageBucketSecurityIssue::BucketSensitiveData => 9.0,
        StorageBucketSecurityIssue::BucketNoExpiration => 5.5,
        StorageBucketSecurityIssue::BucketCrossOrigin => 7.5,
        StorageBucketSecurityIssue::BucketEnumeration => 6.0,
        StorageBucketSecurityIssue::BucketOverQuota => 5.0,
        StorageBucketSecurityIssue::BucketInBackground => 6.5,
        StorageBucketSecurityIssue::BucketFingerprinting => 7.0,
        StorageBucketSecurityIssue::BucketWithoutPermission => 6.0,
        StorageBucketSecurityIssue::BucketPersistentTracking => 8.0,
    }
}

pub fn storage_bucket_security_to_operations(
    issues: &[StorageBucketSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                storage_bucket_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
