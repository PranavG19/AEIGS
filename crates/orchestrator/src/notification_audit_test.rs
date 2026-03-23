use crate::notification_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_notifications("", true);
    assert!(issues.is_empty());
}

#[test]
fn no_notification_no_issues() {
    let body = "var x = document.title;";
    let issues = analyze_notifications(body, true);
    assert!(issues.is_empty());
}

#[test]
fn detects_new_notification() {
    let body = "new Notification('Hello');";
    let issues = analyze_notifications(body, true);
    assert!(issues.contains(&NotificationIssue::NotificationApiUsed));
}

#[test]
fn detects_show_notification() {
    let body = "registration.showNotification('Hello');";
    let issues = analyze_notifications(body, true);
    assert!(issues.contains(&NotificationIssue::NotificationApiUsed));
}

#[test]
fn detects_permission_request() {
    let body = "Notification.requestPermission().then(p => {});";
    let issues = analyze_notifications(body, true);
    assert!(issues.contains(&NotificationIssue::PermissionRequested));
}

#[test]
fn detects_push_manager() {
    let body = "registration.pushManager.subscribe({userVisibleOnly: true});";
    let issues = analyze_notifications(body, true);
    assert!(issues.contains(&NotificationIssue::PushManagerSubscription));
}

#[test]
fn detects_notification_over_http() {
    let body = "new Notification('Hello');";
    let issues = analyze_notifications(body, false);
    assert!(issues.contains(&NotificationIssue::NotificationOverHttp));
}

#[test]
fn https_no_http_issue() {
    let body = "new Notification('Hello');";
    let issues = analyze_notifications(body, true);
    assert!(!issues.contains(&NotificationIssue::NotificationOverHttp));
}

#[test]
fn detects_notification_with_onclick() {
    let body = r#"
        var n = new Notification('Click me');
        n.onclick = function() { window.open('https://evil.com'); };
    "#;
    let issues = analyze_notifications(body, true);
    assert!(issues.contains(&NotificationIssue::NotificationWithLink));
}

#[test]
fn detects_notification_with_actions() {
    let body = r#"
        registration.showNotification('Update', {
            actions: [{action: 'open', title: 'Open'}]
        });
    "#;
    let issues = analyze_notifications(body, true);
    assert!(issues.contains(&NotificationIssue::NotificationWithLink));
}

#[test]
fn detects_service_worker_push() {
    let body = r#"
        self.addEventListener('push', function(event) {
            event.waitUntil(
                self.registration.showNotification('New message')
            );
        });
    "#;
    let issues = analyze_notifications(body, true);
    assert!(issues.contains(&NotificationIssue::ServiceWorkerPush));
}

#[test]
fn severity_http_highest() {
    assert_eq!(
        notification_severity(&NotificationIssue::NotificationOverHttp),
        6.0
    );
}

#[test]
fn severity_api_lowest() {
    assert_eq!(
        notification_severity(&NotificationIssue::NotificationApiUsed),
        3.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        NotificationIssue::NotificationApiUsed,
        NotificationIssue::PermissionRequested,
    ];
    let mut seq = 0;
    let ops = notification_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(NotificationIssue::NotificationApiUsed.to_string(), "notification_api");
    assert_eq!(
        NotificationIssue::PermissionRequested.to_string(),
        "permission_requested"
    );
    assert_eq!(
        NotificationIssue::PushManagerSubscription.to_string(),
        "push_subscription"
    );
    assert_eq!(
        NotificationIssue::NotificationOverHttp.to_string(),
        "notification_over_http"
    );
    assert_eq!(
        NotificationIssue::NotificationWithLink.to_string(),
        "notification_link"
    );
    assert_eq!(NotificationIssue::ServiceWorkerPush.to_string(), "sw_push");
}
