use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum BadgingIssue {
    ApiDetected,
    MisleadingBadge,
    ContinuousUpdate,
    NoUserActivation,
    SpoofedUrgency,
    BadgingInServiceWorker,
    BadgingWithNotification,
    BadgingPhishingIndicator,
    BadgingPersistence,
    BadgingCrossOrigin,
    BadgingWithPushApi,
    BadgingExcessiveValue,
    BadgingWithoutClearLogic,
    BadgingTimingAttack,
    BadgingInBackground,
}

impl std::fmt::Display for BadgingIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::MisleadingBadge => write!(f, "misleading_badge"),
            Self::ContinuousUpdate => write!(f, "continuous_update"),
            Self::NoUserActivation => write!(f, "no_user_activation"),
            Self::SpoofedUrgency => write!(f, "spoofed_urgency"),
            Self::BadgingInServiceWorker => write!(f, "badging_in_service_worker"),
            Self::BadgingWithNotification => write!(f, "badging_with_notification"),
            Self::BadgingPhishingIndicator => write!(f, "badging_phishing_indicator"),
            Self::BadgingPersistence => write!(f, "badging_persistence"),
            Self::BadgingCrossOrigin => write!(f, "badging_cross_origin"),
            Self::BadgingWithPushApi => write!(f, "badging_with_push_api"),
            Self::BadgingExcessiveValue => write!(f, "badging_excessive_value"),
            Self::BadgingWithoutClearLogic => write!(f, "badging_without_clear_logic"),
            Self::BadgingTimingAttack => write!(f, "badging_timing_attack"),
            Self::BadgingInBackground => write!(f, "badging_in_background"),
        }
    }
}

pub fn audit_badging(target: &str) -> Vec<BadgingIssue> {
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
    analyze_badging(&body)
}

pub fn analyze_badging(body: &str) -> Vec<BadgingIssue> {
    if !body.contains("setAppBadge") && !body.contains("clearAppBadge") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(BadgingIssue::ApiDetected);

    if body.contains("setAppBadge(")
        && !body.contains("click")
        && !body.contains("pointerdown")
        && !body.contains("submit")
    {
        issues.push(BadgingIssue::NoUserActivation);
    }

    if body.contains("setInterval") || body.contains("setTimeout") && body.contains("setAppBadge") {
        issues.push(BadgingIssue::ContinuousUpdate);
    }

    if body.contains("setAppBadge(")
        && (body.contains("999") || body.contains("9999") || body.contains("Math.random"))
    {
        issues.push(BadgingIssue::MisleadingBadge);
    }

    if body.contains("setAppBadge(")
        && (body.contains("urgent")
            || body.contains("alert")
            || body.contains("warning")
            || body.contains("security"))
    {
        issues.push(BadgingIssue::SpoofedUrgency);
    }

    issues
}

pub fn analyze_badging_security(body: &str) -> Vec<BadgingIssue> {
    if !body.contains("setAppBadge") && !body.contains("clearAppBadge") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("serviceWorker")
        || body.contains("ServiceWorker")
        || body.contains("self.registration")
    {
        issues.push(BadgingIssue::BadgingInServiceWorker);
    }

    if body.contains("Notification")
        || body.contains("showNotification")
        || body.contains("PushManager")
    {
        issues.push(BadgingIssue::BadgingWithNotification);
    }

    if body.contains("login")
        || body.contains("password")
        || body.contains("verify")
        || body.contains("account")
        || body.contains("bank")
    {
        issues.push(BadgingIssue::BadgingPhishingIndicator);
    }

    if body.contains("localStorage")
        || body.contains("sessionStorage")
        || body.contains("indexedDB")
    {
        issues.push(BadgingIssue::BadgingPersistence);
    }

    if body.contains("postMessage") || body.contains("cross-origin") || body.contains("iframe") {
        issues.push(BadgingIssue::BadgingCrossOrigin);
    }

    if body.contains("PushManager") || body.contains("pushManager") || body.contains("subscribe") {
        issues.push(BadgingIssue::BadgingWithPushApi);
    }

    if let Some(pos) = body.find("setAppBadge(")
        && let Some(end) = body[pos + 12..].find(')')
    {
        let arg = body[pos + 12..][..end].trim();
        if let Ok(val) = arg.parse::<i32>()
            && val > 100
        {
            issues.push(BadgingIssue::BadgingExcessiveValue);
        }
    }

    if body.contains("setAppBadge") && !body.contains("clearAppBadge") {
        issues.push(BadgingIssue::BadgingWithoutClearLogic);
    }

    if body.contains("performance.now") || body.contains("Date.now") {
        issues.push(BadgingIssue::BadgingTimingAttack);
    }

    if body.contains("visibilitychange") || body.contains("hidden") || body.contains("background") {
        issues.push(BadgingIssue::BadgingInBackground);
    }

    issues
}

pub fn badging_severity(issue: &BadgingIssue) -> f64 {
    match issue {
        BadgingIssue::SpoofedUrgency => 6.0,
        BadgingIssue::MisleadingBadge => 5.5,
        BadgingIssue::ContinuousUpdate => 4.5,
        BadgingIssue::NoUserActivation => 4.0,
        BadgingIssue::ApiDetected => 2.0,
        BadgingIssue::BadgingPhishingIndicator => 7.5,
        BadgingIssue::BadgingCrossOrigin => 6.0,
        BadgingIssue::BadgingWithNotification => 5.5,
        BadgingIssue::BadgingWithPushApi => 5.5,
        BadgingIssue::BadgingInServiceWorker => 5.0,
        BadgingIssue::BadgingTimingAttack => 5.0,
        BadgingIssue::BadgingPersistence => 4.5,
        BadgingIssue::BadgingInBackground => 4.5,
        BadgingIssue::BadgingExcessiveValue => 4.0,
        BadgingIssue::BadgingWithoutClearLogic => 3.5,
    }
}

pub fn badging_to_operations(issues: &[BadgingIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                badging_severity(issue),
                0.5,
            )
        })
        .collect()
}

pub fn badging_security_to_operations(
    issues: &[BadgingIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                badging_severity(issue),
                0.6,
            )
        })
        .collect()
}
