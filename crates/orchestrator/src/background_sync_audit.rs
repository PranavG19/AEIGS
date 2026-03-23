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

pub fn background_sync_severity(issue: &BackgroundSyncIssue) -> f64 {
    match issue {
        BackgroundSyncIssue::PeriodicSyncDetected => 6.0,
        BackgroundSyncIssue::ShortMinInterval => 5.5,
        BackgroundSyncIssue::SyncWithFetch => 5.0,
        BackgroundSyncIssue::ExcessiveSyncTags => 4.5,
        BackgroundSyncIssue::NoPermissionCheck => 4.0,
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
