use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum StorageAccessIssue {
    ApiDetected,
    ThirdPartyCookieAccess,
    CrossSiteTracking,
    MissingPermissionCheck,
    SensitiveDataAccess,
    NoUserGesture,
    IframeWithoutSandbox,
}

impl std::fmt::Display for StorageAccessIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::ThirdPartyCookieAccess => write!(f, "third_party_cookie_access"),
            Self::CrossSiteTracking => write!(f, "cross_site_tracking"),
            Self::MissingPermissionCheck => write!(f, "missing_permission_check"),
            Self::SensitiveDataAccess => write!(f, "sensitive_data_access"),
            Self::NoUserGesture => write!(f, "no_user_gesture"),
            Self::IframeWithoutSandbox => write!(f, "iframe_without_sandbox"),
        }
    }
}

pub fn storage_access_severity(issue: &StorageAccessIssue) -> f64 {
    match issue {
        StorageAccessIssue::SensitiveDataAccess => 7.5,
        StorageAccessIssue::ThirdPartyCookieAccess => 6.5,
        StorageAccessIssue::CrossSiteTracking => 6.0,
        StorageAccessIssue::NoUserGesture => 5.5,
        StorageAccessIssue::MissingPermissionCheck => 5.0,
        StorageAccessIssue::IframeWithoutSandbox => 4.5,
        StorageAccessIssue::ApiDetected => 3.0,
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
    let has_storage_access_api = body.contains("document.requestStorageAccess")
        || body.contains("document.hasStorageAccess")
        || body.contains("requestStorageAccess(")
        || body.contains("hasStorageAccess(");

    if !has_storage_access_api {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(StorageAccessIssue::ApiDetected);

    if has_iframe_context(body) && body.contains("requestStorageAccess") {
        if !has_user_gesture_handler(body) {
            issues.push(StorageAccessIssue::NoUserGesture);
        }

        if !has_sandbox_attribute(body) {
            issues.push(StorageAccessIssue::IframeWithoutSandbox);
        }

        issues.push(StorageAccessIssue::ThirdPartyCookieAccess);
    }

    if has_tracking_keywords(body) && body.contains("requestStorageAccess") {
        issues.push(StorageAccessIssue::CrossSiteTracking);
    }

    if !has_permission_check(body) && body.contains("requestStorageAccess") {
        issues.push(StorageAccessIssue::MissingPermissionCheck);
    }

    if has_sensitive_data_patterns(body) && body.contains("requestStorageAccess") {
        issues.push(StorageAccessIssue::SensitiveDataAccess);
    }

    issues
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
                0.5,
            )
        })
        .collect()
}

fn has_iframe_context(body: &str) -> bool {
    body.contains("<iframe") || body.contains("window.parent") || body.contains("window.top")
}

fn has_user_gesture_handler(body: &str) -> bool {
    body.contains("addEventListener(\"click\"")
        || body.contains("addEventListener('click'")
        || body.contains(".onclick")
        || body.contains("addEventListener(\"pointerdown\"")
        || body.contains("addEventListener('pointerdown'")
        || body.contains("addEventListener(\"touchstart\"")
        || body.contains("addEventListener('touchstart'")
        || body.contains("addEventListener(\"keydown\"")
        || body.contains("addEventListener('keydown'")
}

fn has_sandbox_attribute(body: &str) -> bool {
    body.contains("sandbox=") && body.contains("allow-storage-access-by-user-activation")
}

fn has_tracking_keywords(body: &str) -> bool {
    body.contains("analytics")
        || body.contains("tracking")
        || body.contains("pixel")
        || body.contains("tracker")
        || body.contains("facebook")
        || body.contains("google-analytics")
        || body.contains("gtag")
        || body.contains("fbq")
}

fn has_permission_check(body: &str) -> bool {
    body.contains("navigator.permissions.query")
        || body.contains("Permissions API")
        || body.contains("permission.state")
}

fn has_sensitive_data_patterns(body: &str) -> bool {
    let has_sensitive_keywords = body.contains("password")
        || body.contains("token")
        || body.contains("secret")
        || body.contains("apiKey")
        || body.contains("api_key")
        || body.contains("bearer")
        || body.contains("credentials");

    let has_storage_access = body.contains("localStorage.getItem")
        || body.contains("sessionStorage.getItem")
        || body.contains("document.cookie");

    has_sensitive_keywords && has_storage_access
}
