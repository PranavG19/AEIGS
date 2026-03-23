use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum NotificationIssue {
    ApiDetected,
    PermissionSpam,
    PhishingContent,
    SensitiveDataLeak,
    ClickHijacking,
    PushAbuseNoConsent,
}

impl std::fmt::Display for NotificationIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::PermissionSpam => write!(f, "permission_spam"),
            Self::PhishingContent => write!(f, "phishing_content"),
            Self::SensitiveDataLeak => write!(f, "sensitive_data_leak"),
            Self::ClickHijacking => write!(f, "click_hijacking"),
            Self::PushAbuseNoConsent => write!(f, "push_abuse_no_consent"),
        }
    }
}

pub fn notification_severity(issue: &NotificationIssue) -> f64 {
    match issue {
        NotificationIssue::SensitiveDataLeak => 8.0,
        NotificationIssue::PhishingContent => 7.5,
        NotificationIssue::ClickHijacking => 7.0,
        NotificationIssue::PermissionSpam => 6.0,
        NotificationIssue::PushAbuseNoConsent => 5.5,
        NotificationIssue::ApiDetected => 3.0,
    }
}

pub fn audit_notification(target: &str) -> Vec<NotificationIssue> {
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
    let is_https = target.starts_with("https://");
    analyze_notification(&body, is_https)
}

pub fn analyze_notification(body: &str, _is_https: bool) -> Vec<NotificationIssue> {
    let has_notification_api = body.contains("Notification")
        || body.contains("notification")
        || body.contains("PushManager")
        || body.contains("pushManager");

    let has_notification_handler = body.contains("notificationclick") || body.contains(".onclick");

    if !has_notification_api && !has_notification_handler {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("Notification.requestPermission")
        || body.contains("new Notification(")
        || body.contains("showNotification(")
    {
        issues.push(NotificationIssue::ApiDetected);
    }

    if body.contains("Notification.requestPermission") && !has_user_gesture_check(body) {
        issues.push(NotificationIssue::PermissionSpam);
    }

    if has_phishing_indicators(body) {
        issues.push(NotificationIssue::PhishingContent);
    }

    if has_sensitive_data_in_notification(body) {
        issues.push(NotificationIssue::SensitiveDataLeak);
    }

    if has_click_hijacking(body) {
        issues.push(NotificationIssue::ClickHijacking);
    }

    if (body.contains("PushManager.subscribe") || body.contains("pushManager.subscribe"))
        && !has_consent_flow(body)
    {
        issues.push(NotificationIssue::PushAbuseNoConsent);
    }

    issues
}

pub fn notification_to_operations(
    issues: &[NotificationIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                notification_severity(issue),
                0.5,
            )
        })
        .collect()
}

fn has_user_gesture_check(body: &str) -> bool {
    (body.contains("addEventListener") && body.contains("click"))
        || (body.contains("button") && body.contains("click"))
        || body.contains(".click()")
}

fn has_phishing_indicators(body: &str) -> bool {
    let notification_context =
        body.contains("new Notification(") || body.contains("showNotification(");
    if !notification_context {
        return false;
    }

    let phishing_keywords = [
        "login", "verify", "confirm", "update", "password", "account",
    ];
    let has_keyword = phishing_keywords.iter().any(|&kw| body.contains(kw));

    let url_patterns = ["http://", "https://", "www.", ".com", ".net"];
    let has_url = url_patterns.iter().any(|&pat| body.contains(pat));

    has_keyword && has_url
}

fn has_sensitive_data_in_notification(body: &str) -> bool {
    let notification_context =
        body.contains("new Notification(") || body.contains("showNotification(");
    if !notification_context {
        return false;
    }

    let sensitive_keywords = [
        "password",
        "token",
        "secret",
        "credential",
        "api_key",
        "apikey",
        "authToken",
    ];
    sensitive_keywords.iter().any(|&kw| body.contains(kw))
}

fn has_click_hijacking(body: &str) -> bool {
    let has_click_handler = body.contains("onclick") || body.contains("notificationclick");
    if !has_click_handler {
        return false;
    }

    let external_navigation = [
        "window.open(",
        "window.location",
        "location.href",
        "clients.openWindow(",
    ];
    let has_navigation = external_navigation.iter().any(|&pat| body.contains(pat));

    has_click_handler && has_navigation
}

fn has_consent_flow(body: &str) -> bool {
    body.contains("confirm")
        || body.contains("accept")
        || body.contains("Accept")
        || body.contains("agree")
        || body.contains("Agree")
}
