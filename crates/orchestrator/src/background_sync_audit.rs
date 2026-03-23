use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum BackgroundSyncIssue {
    SyncRegisterDetected,
    PeriodicSyncDetected,
    ShortMinInterval,
    ExcessiveSyncTags,
    SyncWithFetch,
    NoPermissionCheck,
    SyncDataExfiltration,
    SyncWithGeolocation,
    SyncCrossOrigin,
    SyncWithCrypto,
    PeriodicSyncAbuseRisk,
    SyncInServiceWorker,
    SyncWithIndexedDb,
    SyncRetryLoop,
    SyncWithNotifications,
    SyncWithoutUserActivation,
}

impl std::fmt::Display for BackgroundSyncIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SyncRegisterDetected => write!(f, "sync_register_detected"),
            Self::PeriodicSyncDetected => write!(f, "periodic_sync_detected"),
            Self::ShortMinInterval => write!(f, "short_min_interval"),
            Self::ExcessiveSyncTags => write!(f, "excessive_sync_tags"),
            Self::SyncWithFetch => write!(f, "sync_with_fetch"),
            Self::NoPermissionCheck => write!(f, "no_permission_check"),
            Self::SyncDataExfiltration => write!(f, "sync_data_exfiltration"),
            Self::SyncWithGeolocation => write!(f, "sync_with_geolocation"),
            Self::SyncCrossOrigin => write!(f, "sync_cross_origin"),
            Self::SyncWithCrypto => write!(f, "sync_with_crypto"),
            Self::PeriodicSyncAbuseRisk => write!(f, "periodic_sync_abuse_risk"),
            Self::SyncInServiceWorker => write!(f, "sync_in_service_worker"),
            Self::SyncWithIndexedDb => write!(f, "sync_with_indexed_db"),
            Self::SyncRetryLoop => write!(f, "sync_retry_loop"),
            Self::SyncWithNotifications => write!(f, "sync_with_notifications"),
            Self::SyncWithoutUserActivation => write!(f, "sync_without_user_activation"),
        }
    }
}

pub fn audit_background_sync(target: &str) -> Vec<BackgroundSyncIssue> {
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
    analyze_background_sync(&body)
}

pub fn analyze_background_sync(body: &str) -> Vec<BackgroundSyncIssue> {
    let has_sync = body.contains("sync.register");
    let has_periodic = body.contains("periodicSync");
    if !has_sync && !has_periodic {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if has_sync {
        issues.push(BackgroundSyncIssue::SyncRegisterDetected);

        let tag_count = count_sync_tags(body);
        if tag_count > 5 {
            issues.push(BackgroundSyncIssue::ExcessiveSyncTags);
        }
    }

    if has_periodic {
        issues.push(BackgroundSyncIssue::PeriodicSyncDetected);

        if has_short_interval(body) {
            issues.push(BackgroundSyncIssue::ShortMinInterval);
        }

        if !body.contains("permissions") && !body.contains("Notification.permission") {
            issues.push(BackgroundSyncIssue::NoPermissionCheck);
        }
    }

    if (has_sync || has_periodic) && body.contains("fetch(") {
        issues.push(BackgroundSyncIssue::SyncWithFetch);
    }

    issues
}

fn count_sync_tags(body: &str) -> usize {
    let mut names = std::collections::HashSet::new();
    let marker = "sync.register(";
    let mut search_from = 0;
    while let Some(pos) = body[search_from..].find(marker) {
        let start = search_from + pos + marker.len();
        if start >= body.len() {
            break;
        }
        let rest = &body[start..];
        let name = if let Some(stripped) = rest.strip_prefix('"') {
            stripped.split('"').next()
        } else if let Some(stripped) = rest.strip_prefix('\'') {
            stripped.split('\'').next()
        } else {
            None
        };
        if let Some(n) = name {
            names.insert(n);
        }
        search_from = start;
    }
    names.len()
}

fn has_short_interval(body: &str) -> bool {
    if let Some(pos) = body.find("minInterval") {
        let rest = &body[pos..];
        if let Some(colon) = rest.find(':') {
            let after_colon = rest[colon + 1..].trim_start();
            let num_str: String = after_colon
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(val) = num_str.parse::<u64>() {
                return val < 60_000;
            }
        }
    }
    false
}

pub fn analyze_background_sync_security(body: &str) -> Vec<BackgroundSyncIssue> {
    let has_sync = body.contains("sync.register");
    let has_periodic = body.contains("periodicSync");

    if !has_sync && !has_periodic {
        return Vec::new();
    }

    let has_sync_api = has_sync || has_periodic;
    let mut issues = Vec::new();

    if has_sync_api
        && (body.contains("sendBeacon")
            || body.contains("XMLHttpRequest")
            || body.contains("navigator.sendBeacon"))
    {
        issues.push(BackgroundSyncIssue::SyncDataExfiltration);
    }

    if has_sync_api
        && (body.contains("getCurrentPosition")
            || body.contains("watchPosition")
            || body.contains("geolocation"))
    {
        issues.push(BackgroundSyncIssue::SyncWithGeolocation);
    }

    if has_sync_api
        && (body.contains("postMessage")
            || body.contains("cross-origin")
            || body.contains("iframe"))
    {
        issues.push(BackgroundSyncIssue::SyncCrossOrigin);
    }

    if has_sync_api
        && (body.contains("crypto.subtle")
            || body.contains("CryptoKey")
            || body.contains("encrypt")
            || body.contains("decrypt"))
    {
        issues.push(BackgroundSyncIssue::SyncWithCrypto);
    }

    if has_periodic
        && (body.contains("mine")
            || body.contains("miner")
            || body.contains("crypto")
            || body.contains("blockchain"))
    {
        issues.push(BackgroundSyncIssue::PeriodicSyncAbuseRisk);
    }

    if has_sync_api
        && (body.contains("serviceWorker")
            || body.contains("ServiceWorkerRegistration")
            || body.contains("self.addEventListener"))
    {
        issues.push(BackgroundSyncIssue::SyncInServiceWorker);
    }

    if has_sync_api
        && (body.contains("indexedDB")
            || body.contains("IDBTransaction")
            || body.contains("objectStore"))
    {
        issues.push(BackgroundSyncIssue::SyncWithIndexedDb);
    }

    if has_sync_api
        && (body.contains("retry")
            || body.contains("retryCount")
            || body.contains("maxRetries")
            || body.contains("backoff"))
    {
        issues.push(BackgroundSyncIssue::SyncRetryLoop);
    }

    if has_sync_api
        && (body.contains("Notification")
            || body.contains("showNotification")
            || body.contains("PushManager"))
    {
        issues.push(BackgroundSyncIssue::SyncWithNotifications);
    }

    if has_sync_api
        && !body.contains("click")
        && !body.contains("onclick")
        && !body.contains("addEventListener")
        && !body.contains("user-activation")
    {
        issues.push(BackgroundSyncIssue::SyncWithoutUserActivation);
    }

    issues
}

pub fn background_sync_severity(issue: &BackgroundSyncIssue) -> f64 {
    match issue {
        BackgroundSyncIssue::PeriodicSyncAbuseRisk => 8.0,
        BackgroundSyncIssue::SyncDataExfiltration => 7.5,
        BackgroundSyncIssue::SyncWithGeolocation => 7.0,
        BackgroundSyncIssue::SyncWithCrypto => 7.0,
        BackgroundSyncIssue::SyncCrossOrigin => 6.5,
        BackgroundSyncIssue::PeriodicSyncDetected => 6.0,
        BackgroundSyncIssue::SyncWithIndexedDb => 5.5,
        BackgroundSyncIssue::SyncWithNotifications => 5.5,
        BackgroundSyncIssue::ShortMinInterval => 5.5,
        BackgroundSyncIssue::SyncInServiceWorker => 5.0,
        BackgroundSyncIssue::SyncWithFetch => 5.0,
        BackgroundSyncIssue::SyncRetryLoop => 4.5,
        BackgroundSyncIssue::ExcessiveSyncTags => 4.5,
        BackgroundSyncIssue::NoPermissionCheck => 4.0,
        BackgroundSyncIssue::SyncWithoutUserActivation => 4.0,
        BackgroundSyncIssue::SyncRegisterDetected => 3.5,
    }
}

pub fn background_sync_to_operations(
    issues: &[BackgroundSyncIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                background_sync_severity(issue),
                0.7,
            )
        })
        .collect()
}

pub fn background_sync_security_to_operations(
    issues: &[BackgroundSyncIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                background_sync_severity(issue),
                0.7,
            )
        })
        .collect()
}
