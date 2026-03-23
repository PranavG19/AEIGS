use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum VibrationIssue {
    ApiDetected,
    NoUserActivation,
    ExcessiveDuration,
    ContinuousVibration,
    CovertChannel,
}

impl std::fmt::Display for VibrationIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::NoUserActivation => write!(f, "no_user_activation"),
            Self::ExcessiveDuration => write!(f, "excessive_duration"),
            Self::ContinuousVibration => write!(f, "continuous_vibration"),
            Self::CovertChannel => write!(f, "covert_channel"),
        }
    }
}

pub fn audit_vibration(target: &str) -> Vec<VibrationIssue> {
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
    analyze_vibration(&body)
}

pub fn analyze_vibration(body: &str) -> Vec<VibrationIssue> {
    if !body.contains("navigator.vibrate") && !body.contains(".vibrate(") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(VibrationIssue::ApiDetected);

    if !body.contains("click") && !body.contains("keydown") && !body.contains("pointerdown") {
        issues.push(VibrationIssue::NoUserActivation);
    }

    if body.contains("[") && body.contains("vibrate(") {
        issues.push(VibrationIssue::ExcessiveDuration);
    }

    if body.contains("setInterval") || body.contains("while(") || body.contains("while ") {
        issues.push(VibrationIssue::ContinuousVibration);
    }

    if body.contains("vibrate(")
        && (body.contains("WebSocket")
            || body.contains("BroadcastChannel")
            || body.contains("postMessage"))
    {
        issues.push(VibrationIssue::CovertChannel);
    }

    issues
}

pub fn vibration_severity(issue: &VibrationIssue) -> f64 {
    match issue {
        VibrationIssue::CovertChannel => 6.5,
        VibrationIssue::ContinuousVibration => 5.5,
        VibrationIssue::ExcessiveDuration => 5.0,
        VibrationIssue::NoUserActivation => 4.5,
        VibrationIssue::ApiDetected => 2.0,
    }
}

pub fn vibration_to_operations(issues: &[VibrationIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                vibration_severity(issue),
                0.5,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum VibrationSecurityIssue {
    VibrationDataExfiltration,
    VibrationFingerprinting,
    VibrationInBackground,
    VibrationDenialOfService,
    VibrationWithoutUserGesture,
    VibrationCrossOrigin,
    VibrationPatternEncoding,
    VibrationWithNotification,
    VibrationTimingAttack,
    ExcessiveVibrationDuration,
}

impl std::fmt::Display for VibrationSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VibrationDataExfiltration => write!(f, "vibration_data_exfiltration"),
            Self::VibrationFingerprinting => write!(f, "vibration_fingerprinting"),
            Self::VibrationInBackground => write!(f, "vibration_in_background"),
            Self::VibrationDenialOfService => write!(f, "vibration_denial_of_service"),
            Self::VibrationWithoutUserGesture => write!(f, "vibration_without_user_gesture"),
            Self::VibrationCrossOrigin => write!(f, "vibration_cross_origin"),
            Self::VibrationPatternEncoding => write!(f, "vibration_pattern_encoding"),
            Self::VibrationWithNotification => write!(f, "vibration_with_notification"),
            Self::VibrationTimingAttack => write!(f, "vibration_timing_attack"),
            Self::ExcessiveVibrationDuration => write!(f, "excessive_vibration_duration"),
        }
    }
}

pub fn analyze_vibration_security(body: &str) -> Vec<VibrationSecurityIssue> {
    if !body.contains("navigator.vibrate") && !body.contains(".vibrate(") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    // VibrationDataExfiltration: encoding data via vibration patterns
    if body.contains("vibrate(")
        && (body.contains("fetch(") || body.contains("XMLHttpRequest"))
        && (body.contains("encode") || body.contains("btoa") || body.contains("JSON.stringify"))
    {
        issues.push(VibrationSecurityIssue::VibrationDataExfiltration);
    }

    // VibrationFingerprinting: using vibration API for device fingerprinting
    if body.contains("vibrate(")
        && (body.contains("userAgent")
            || body.contains("platform")
            || body.contains("hardwareConcurrency")
            || body.contains("deviceMemory")
            || body.contains("maxTouchPoints"))
    {
        issues.push(VibrationSecurityIssue::VibrationFingerprinting);
    }

    // VibrationInBackground: triggering vibration when page hidden
    if body.contains("vibrate(")
        && (body.contains("visibilitychange")
            || body.contains("document.hidden")
            || body.contains("document.visibilityState"))
    {
        issues.push(VibrationSecurityIssue::VibrationInBackground);
    }

    // VibrationDenialOfService: continuous vibration draining battery
    if body.contains("vibrate(")
        && (body.contains("setInterval")
            || body.contains("requestAnimationFrame")
            || body.contains("while(true)")
            || body.contains("for(;;)"))
    {
        issues.push(VibrationSecurityIssue::VibrationDenialOfService);
    }

    // VibrationWithoutUserGesture: triggering vibration without user action
    if body.contains("vibrate(")
        && !body.contains("click")
        && !body.contains("keydown")
        && !body.contains("pointerdown")
        && !body.contains("touchstart")
        && !body.contains("mousedown")
    {
        issues.push(VibrationSecurityIssue::VibrationWithoutUserGesture);
    }

    // VibrationCrossOrigin: vibration triggered from cross-origin iframe
    if body.contains("vibrate(")
        && (body.contains("iframe")
            || body.contains("contentWindow")
            || body.contains("postMessage")
            || body.contains("parent."))
    {
        issues.push(VibrationSecurityIssue::VibrationCrossOrigin);
    }

    // VibrationPatternEncoding: using patterns to encode covert data
    if body.contains("vibrate([")
        && (body.contains("map(")
            || body.contains("reduce(")
            || body.contains("charCodeAt")
            || body.contains("split("))
    {
        issues.push(VibrationSecurityIssue::VibrationPatternEncoding);
    }

    // VibrationWithNotification: combining vibration with notification abuse
    if body.contains("vibrate(")
        && (body.contains("Notification")
            || body.contains("showNotification")
            || body.contains("navigator.permissions"))
    {
        issues.push(VibrationSecurityIssue::VibrationWithNotification);
    }

    // VibrationTimingAttack: using vibration timing for side channels
    if body.contains("vibrate(")
        && (body.contains("performance.now()")
            || body.contains("Date.now()")
            || body.contains("performance.timing")
            || body.contains("performance.measure"))
    {
        issues.push(VibrationSecurityIssue::VibrationTimingAttack);
    }

    // ExcessiveVibrationDuration: very long vibration durations
    if body.contains("vibrate(")
        && let Some(regex) = regex::Regex::new(r"vibrate\((\d+)\)").ok()
    {
        for cap in regex.captures_iter(body) {
            if let Some(duration_str) = cap.get(1)
                && let Ok(duration) = duration_str.as_str().parse::<u32>()
                && duration > 5000
            {
                issues.push(VibrationSecurityIssue::ExcessiveVibrationDuration);
                break;
            }
        }
    }

    issues
}

pub fn vibration_security_severity(issue: &VibrationSecurityIssue) -> f64 {
    match issue {
        VibrationSecurityIssue::VibrationDataExfiltration => 8.0,
        VibrationSecurityIssue::VibrationTimingAttack => 7.5,
        VibrationSecurityIssue::VibrationPatternEncoding => 7.0,
        VibrationSecurityIssue::VibrationFingerprinting => 6.5,
        VibrationSecurityIssue::VibrationDenialOfService => 6.0,
        VibrationSecurityIssue::VibrationCrossOrigin => 5.5,
        VibrationSecurityIssue::VibrationInBackground => 5.0,
        VibrationSecurityIssue::VibrationWithNotification => 4.5,
        VibrationSecurityIssue::VibrationWithoutUserGesture => 4.0,
        VibrationSecurityIssue::ExcessiveVibrationDuration => 3.5,
    }
}

pub fn vibration_security_to_operations(
    issues: &[VibrationSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                vibration_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
