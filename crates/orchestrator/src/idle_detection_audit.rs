use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum IdleDetectionIssue {
    IdleDetectorUsage,
    IdleStateExfiltration,
    IdleChangeTracking,
    ScreenStateMonitoring,
    ContinuousIdlePolling,
}

impl std::fmt::Display for IdleDetectionIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IdleDetectorUsage => write!(f, "idle_detector_usage"),
            Self::IdleStateExfiltration => write!(f, "idle_state_exfiltration"),
            Self::IdleChangeTracking => write!(f, "idle_change_tracking"),
            Self::ScreenStateMonitoring => write!(f, "screen_state_monitoring"),
            Self::ContinuousIdlePolling => write!(f, "continuous_idle_polling"),
        }
    }
}

pub fn audit_idle_detection(target: &str) -> Vec<IdleDetectionIssue> {
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
    analyze_idle_detection(&body)
}

pub fn analyze_idle_detection(body: &str) -> Vec<IdleDetectionIssue> {
    if !body.contains("IdleDetector") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    issues.push(IdleDetectionIssue::IdleDetectorUsage);

    if body.contains("userState") || body.contains("screenState") {
        let sends = body.contains("fetch(")
            || body.contains("XMLHttpRequest")
            || body.contains(".send(")
            || body.contains("sendBeacon");
        if sends {
            issues.push(IdleDetectionIssue::IdleStateExfiltration);
        }
    }

    if body.contains("onchange") || body.contains("addEventListener") {
        issues.push(IdleDetectionIssue::IdleChangeTracking);
    }

    if body.contains("screenState") {
        issues.push(IdleDetectionIssue::ScreenStateMonitoring);
    }

    if body.contains("setInterval") || body.contains("requestAnimationFrame") {
        issues.push(IdleDetectionIssue::ContinuousIdlePolling);
    }

    issues
}

pub fn idle_detection_severity(issue: &IdleDetectionIssue) -> f64 {
    match issue {
        IdleDetectionIssue::IdleStateExfiltration => 7.5,
        IdleDetectionIssue::ScreenStateMonitoring => 7.0,
        IdleDetectionIssue::ContinuousIdlePolling => 6.5,
        IdleDetectionIssue::IdleChangeTracking => 6.0,
        IdleDetectionIssue::IdleDetectorUsage => 5.0,
    }
}

pub fn idle_detection_to_operations(
    issues: &[IdleDetectionIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                idle_detection_severity(issue),
                0.7,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum IdleDetectionSecurityIssue {
    DetectorWithoutPermission,
    IdleStatePersistence,
    CrossOriginIdleLeak,
    WorkerBasedDetection,
    UserPresenceFingerprint,
    UnencryptedIdleData,
    AbsenceTimingAttack,
    ScreenLockDetection,
    ThirdPartyIdleSharing,
    AutoStartDetection,
}

impl std::fmt::Display for IdleDetectionSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DetectorWithoutPermission => write!(f, "detector_without_permission"),
            Self::IdleStatePersistence => write!(f, "idle_state_persistence"),
            Self::CrossOriginIdleLeak => write!(f, "cross_origin_idle_leak"),
            Self::WorkerBasedDetection => write!(f, "worker_based_detection"),
            Self::UserPresenceFingerprint => write!(f, "user_presence_fingerprint"),
            Self::UnencryptedIdleData => write!(f, "unencrypted_idle_data"),
            Self::AbsenceTimingAttack => write!(f, "absence_timing_attack"),
            Self::ScreenLockDetection => write!(f, "screen_lock_detection"),
            Self::ThirdPartyIdleSharing => write!(f, "third_party_idle_sharing"),
            Self::AutoStartDetection => write!(f, "auto_start_detection"),
        }
    }
}

pub fn analyze_idle_detection_security(body: &str) -> Vec<IdleDetectionSecurityIssue> {
    if !body.contains("IdleDetector") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    // DetectorWithoutPermission - IdleDetector used without permission.request check
    if (body.contains("new IdleDetector()") || body.contains("new IdleDetector("))
        && !body.contains("permission")
        && !body.contains("requestPermission")
    {
        issues.push(IdleDetectionSecurityIssue::DetectorWithoutPermission);
    }

    // IdleStatePersistence - idle state stored in localStorage/IndexedDB
    if (body.contains("userState") || body.contains("screenState"))
        && (body.contains("localStorage")
            || body.contains("indexedDB")
            || body.contains("IndexedDB")
            || body.contains("sessionStorage"))
    {
        issues.push(IdleDetectionSecurityIssue::IdleStatePersistence);
    }

    // CrossOriginIdleLeak - idle state shared via postMessage
    if (body.contains("userState") || body.contains("screenState")) && body.contains("postMessage")
    {
        issues.push(IdleDetectionSecurityIssue::CrossOriginIdleLeak);
    }

    // WorkerBasedDetection - IdleDetector used inside Worker/ServiceWorker
    if body.contains("IdleDetector")
        && (body.contains("new Worker(")
            || body.contains("ServiceWorker")
            || body.contains("self.addEventListener")
            || body.contains("onmessage"))
    {
        issues.push(IdleDetectionSecurityIssue::WorkerBasedDetection);
    }

    // UserPresenceFingerprint - idle data combined with other APIs for fingerprinting
    if body.contains("IdleDetector")
        && (body.contains("navigator.userAgent")
            || body.contains("screen.width")
            || body.contains("canvas.toDataURL")
            || body.contains("AudioContext")
            || body.contains("WebGL")
            || body.contains("webgl"))
    {
        issues.push(IdleDetectionSecurityIssue::UserPresenceFingerprint);
    }

    // UnencryptedIdleData - idle state sent via http://
    if (body.contains("userState") || body.contains("screenState"))
        && (body.contains("fetch(") || body.contains("XMLHttpRequest"))
        && body.contains("http://")
    {
        issues.push(IdleDetectionSecurityIssue::UnencryptedIdleData);
    }

    // AbsenceTimingAttack - idle duration used to time user absence
    if body.contains("IdleDetector")
        && (body.contains("Date.now()")
            || body.contains("performance.now()")
            || body.contains("timestamp"))
        && (body.contains("userState") || body.contains("idle"))
    {
        issues.push(IdleDetectionSecurityIssue::AbsenceTimingAttack);
    }

    // ScreenLockDetection - screenState used to detect screen lock
    if body.contains("screenState") && (body.contains("locked") || body.contains("unlocked")) {
        issues.push(IdleDetectionSecurityIssue::ScreenLockDetection);
    }

    // ThirdPartyIdleSharing - idle data sent to external domains
    if (body.contains("userState") || body.contains("screenState"))
        && (body.contains("fetch(") || body.contains("XMLHttpRequest"))
        && (body.contains(".com") || body.contains(".net") || body.contains(".org"))
    {
        issues.push(IdleDetectionSecurityIssue::ThirdPartyIdleSharing);
    }

    // AutoStartDetection - IdleDetector.start() called without user gesture
    if body.contains("IdleDetector")
        && body.contains(".start(")
        && !body.contains("addEventListener('click'")
        && !body.contains("addEventListener('touchstart'")
        && !body.contains("onclick")
    {
        issues.push(IdleDetectionSecurityIssue::AutoStartDetection);
    }

    issues
}

pub fn idle_detection_security_severity(issue: &IdleDetectionSecurityIssue) -> f64 {
    match issue {
        IdleDetectionSecurityIssue::UnencryptedIdleData => 8.5,
        IdleDetectionSecurityIssue::ThirdPartyIdleSharing => 8.0,
        IdleDetectionSecurityIssue::CrossOriginIdleLeak => 7.8,
        IdleDetectionSecurityIssue::AbsenceTimingAttack => 7.5,
        IdleDetectionSecurityIssue::UserPresenceFingerprint => 7.2,
        IdleDetectionSecurityIssue::IdleStatePersistence => 6.8,
        IdleDetectionSecurityIssue::ScreenLockDetection => 6.5,
        IdleDetectionSecurityIssue::WorkerBasedDetection => 6.0,
        IdleDetectionSecurityIssue::DetectorWithoutPermission => 5.5,
        IdleDetectionSecurityIssue::AutoStartDetection => 5.0,
    }
}

pub fn idle_detection_security_to_operations(
    issues: &[IdleDetectionSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                idle_detection_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
