use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum NotificationIssue {
    NotificationApiUsed,
    PermissionRequested,
    PushManagerSubscription,
    NotificationOverHttp,
    NotificationWithLink,
    ServiceWorkerPush,
}

impl std::fmt::Display for NotificationIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotificationApiUsed => write!(f, "notification_api"),
            Self::PermissionRequested => write!(f, "permission_requested"),
            Self::PushManagerSubscription => write!(f, "push_subscription"),
            Self::NotificationOverHttp => write!(f, "notification_over_http"),
            Self::NotificationWithLink => write!(f, "notification_link"),
            Self::ServiceWorkerPush => write!(f, "sw_push"),
        }
    }
}

pub fn audit_notifications(target: &str) -> Vec<NotificationIssue> {
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
    analyze_notifications(&body, target.starts_with("https://"))
}

pub fn analyze_notifications(body: &str, is_https: bool) -> Vec<NotificationIssue> {
    if !body.contains("Notification") && !body.contains("PushManager") && !body.contains("pushManager") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("new Notification(") || body.contains("showNotification(") {
        issues.push(NotificationIssue::NotificationApiUsed);

        if !is_https {
            issues.push(NotificationIssue::NotificationOverHttp);
        }
    }

    if body.contains("Notification.requestPermission") {
        issues.push(NotificationIssue::PermissionRequested);
    }

    if body.contains("pushManager.subscribe") || body.contains("PushManager") {
        issues.push(NotificationIssue::PushManagerSubscription);
    }

    if (body.contains("new Notification(") || body.contains("showNotification("))
        && (body.contains("onclick") || body.contains("data:") || body.contains("actions:"))
    {
        issues.push(NotificationIssue::NotificationWithLink);
    }

    if body.contains("self.addEventListener")
        && body.contains("push")
        && body.contains("showNotification")
    {
        issues.push(NotificationIssue::ServiceWorkerPush);
    }

    issues
}

pub fn notification_severity(issue: &NotificationIssue) -> f64 {
    match issue {
        NotificationIssue::NotificationOverHttp => 6.0,
        NotificationIssue::NotificationWithLink => 5.0,
        NotificationIssue::ServiceWorkerPush => 4.5,
        NotificationIssue::PushManagerSubscription => 4.0,
        NotificationIssue::PermissionRequested => 3.5,
        NotificationIssue::NotificationApiUsed => 3.0,
    }
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
                0.7,
            )
        })
        .collect()
}
