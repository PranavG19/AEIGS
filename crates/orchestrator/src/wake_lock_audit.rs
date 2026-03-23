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
    WakeLockInBackground,
    WakeLockWithTracking,
    WakeLockBatteryDrain,
    WakeLockWithGeolocation,
    WakeLockCrossOrigin,
    WakeLockInServiceWorker,
    WakeLockWithAudio,
    WakeLockDenialOfService,
    WakeLockWithWebSocket,
    WakeLockWithoutPermissionCheck,
}

impl std::fmt::Display for WakeLockIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WakeLockRequested => write!(f, "wake_lock_requested"),
            Self::ScreenWakeLock => write!(f, "screen_wake_lock"),
            Self::NoRelease => write!(f, "no_release"),
            Self::NoVisibilityCheck => write!(f, "no_visibility_check"),
            Self::PersistentLock => write!(f, "persistent_lock"),
            Self::WakeLockInBackground => write!(f, "wake_lock_in_background"),
            Self::WakeLockWithTracking => write!(f, "wake_lock_with_tracking"),
            Self::WakeLockBatteryDrain => write!(f, "wake_lock_battery_drain"),
            Self::WakeLockWithGeolocation => write!(f, "wake_lock_with_geolocation"),
            Self::WakeLockCrossOrigin => write!(f, "wake_lock_cross_origin"),
            Self::WakeLockInServiceWorker => write!(f, "wake_lock_in_service_worker"),
            Self::WakeLockWithAudio => write!(f, "wake_lock_with_audio"),
            Self::WakeLockDenialOfService => write!(f, "wake_lock_denial_of_service"),
            Self::WakeLockWithWebSocket => write!(f, "wake_lock_with_web_socket"),
            Self::WakeLockWithoutPermissionCheck => write!(f, "wake_lock_without_permission_check"),
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
        WakeLockIssue::WakeLockDenialOfService => 8.0,
        WakeLockIssue::WakeLockWithGeolocation => 7.5,
        WakeLockIssue::WakeLockWithTracking => 7.0,
        WakeLockIssue::WakeLockCrossOrigin => 6.5,
        WakeLockIssue::WakeLockInBackground => 6.0,
        WakeLockIssue::WakeLockInServiceWorker => 6.0,
        WakeLockIssue::WakeLockBatteryDrain => 5.5,
        WakeLockIssue::WakeLockWithWebSocket => 5.5,
        WakeLockIssue::WakeLockWithAudio => 5.0,
        WakeLockIssue::WakeLockWithoutPermissionCheck => 4.0,
    }
}

pub fn wake_lock_to_operations(issues: &[WakeLockIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
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

pub fn analyze_wake_lock_security(body: &str) -> Vec<WakeLockIssue> {
    if !body.contains("wakeLock") && !body.contains("WakeLock") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if (body.contains("background") || body.contains("hidden") || body.contains("pagehide"))
        && body.contains("request")
    {
        issues.push(WakeLockIssue::WakeLockInBackground);
    }

    if body.contains("fetch(")
        || body.contains("sendBeacon")
        || body.contains("XMLHttpRequest")
        || body.contains("navigator.sendBeacon")
    {
        issues.push(WakeLockIssue::WakeLockWithTracking);
    }

    if body.contains("getBattery") || body.contains("BatteryManager") || body.contains("battery") {
        issues.push(WakeLockIssue::WakeLockBatteryDrain);
    }

    if body.contains("getCurrentPosition")
        || body.contains("watchPosition")
        || body.contains("geolocation")
    {
        issues.push(WakeLockIssue::WakeLockWithGeolocation);
    }

    if body.contains("postMessage") || body.contains("cross-origin") || body.contains("iframe") {
        issues.push(WakeLockIssue::WakeLockCrossOrigin);
    }

    if body.contains("serviceWorker") || body.contains("ServiceWorker") {
        issues.push(WakeLockIssue::WakeLockInServiceWorker);
    }

    if body.contains("AudioContext") || body.contains("new Audio") || body.contains("MediaStream") {
        issues.push(WakeLockIssue::WakeLockWithAudio);
    }

    if body.contains("while(true)")
        || body.contains("while (true)")
        || body.contains("for(;;)")
        || body.contains("infinite")
    {
        issues.push(WakeLockIssue::WakeLockDenialOfService);
    }

    if body.contains("WebSocket") || body.contains("new WebSocket") || body.contains("ws://") {
        issues.push(WakeLockIssue::WakeLockWithWebSocket);
    }

    if !body.contains("Permissions")
        && !body.contains("navigator.permissions")
        && !body.contains("query(")
    {
        issues.push(WakeLockIssue::WakeLockWithoutPermissionCheck);
    }

    issues
}

pub fn wake_lock_security_to_operations(
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
                0.7,
            )
        })
        .collect()
}
