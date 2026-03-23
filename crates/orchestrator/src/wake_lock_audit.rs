use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WakeLockIssue {
    WakeLockRequested,
    ScreenWakeLock,
    NoRelease,
    NoVisibilityCheck,
    PersistentLock,
}

impl std::fmt::Display for WakeLockIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WakeLockRequested => write!(f, "wake_lock_requested"),
            Self::ScreenWakeLock => write!(f, "screen_wake_lock"),
            Self::NoRelease => write!(f, "no_release"),
            Self::NoVisibilityCheck => write!(f, "no_visibility_check"),
            Self::PersistentLock => write!(f, "persistent_lock"),
        }
    }
}

pub fn audit_wake_lock(target: &str) -> Vec<WakeLockIssue> {
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
    analyze_wake_lock(&body)
}

pub fn analyze_wake_lock(body: &str) -> Vec<WakeLockIssue> {
    if !body.contains("wakeLock") && !body.contains("WakeLock") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("navigator.wakeLock.request") {
        issues.push(WakeLockIssue::WakeLockRequested);

        if body.contains("\"screen\"") || body.contains("'screen'") {
            issues.push(WakeLockIssue::ScreenWakeLock);
        }

        if !body.contains(".release()") {
            issues.push(WakeLockIssue::NoRelease);
        }

        if !body.contains("visibilitychange") && !body.contains("document.hidden") {
            issues.push(WakeLockIssue::NoVisibilityCheck);
        }

        if body.contains("setInterval") || body.contains("while") {
            issues.push(WakeLockIssue::PersistentLock);
        }
    }

    issues
}

pub fn wake_lock_severity(issue: &WakeLockIssue) -> f64 {
    match issue {
        WakeLockIssue::PersistentLock => 5.5,
        WakeLockIssue::NoRelease => 5.0,
        WakeLockIssue::NoVisibilityCheck => 4.5,
        WakeLockIssue::ScreenWakeLock => 4.0,
        WakeLockIssue::WakeLockRequested => 3.0,
    }
}

pub fn wake_lock_to_operations(
    issues: &[WakeLockIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                wake_lock_severity(issue),
                0.6,
            )
        })
        .collect()
}
