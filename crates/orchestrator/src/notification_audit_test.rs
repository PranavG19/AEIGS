use crate::notification_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_notification("", true);
    assert!(issues.is_empty());
}

#[test]
fn no_notification_keywords_no_issues() {
    let body = "var x = document.title; console.log('test');";
    let issues = analyze_notification(body, true);
    assert!(issues.is_empty());
}

#[test]
fn detects_api_new_notification() {
    let body = "new Notification('Hello');";
    let issues = analyze_notification(body, true);
    assert!(issues.contains(&NotificationIssue::ApiDetected));
}

#[test]
fn detects_api_show_notification() {
    let body = "registration.showNotification('Hello');";
    let issues = analyze_notification(body, true);
    assert!(issues.contains(&NotificationIssue::ApiDetected));
}

#[test]
fn detects_api_request_permission() {
    let body = "Notification.requestPermission().then(p => {});";
    let issues = analyze_notification(body, true);
    assert!(issues.contains(&NotificationIssue::ApiDetected));
}

#[test]
fn detects_permission_spam_without_gesture() {
    let body = "Notification.requestPermission();";
    let issues = analyze_notification(body, true);
    assert!(issues.contains(&NotificationIssue::PermissionSpam));
}

#[test]
fn no_permission_spam_with_click_handler() {
    let body = r#"
        button.addEventListener('click', function() {
            Notification.requestPermission();
        });
    "#;
    let issues = analyze_notification(body, true);
    assert!(!issues.contains(&NotificationIssue::PermissionSpam));
}

#[test]
fn no_permission_spam_with_onclick() {
    let body = r#"
        button.onclick = function() {
            Notification.requestPermission();
        };
    "#;
    let issues = analyze_notification(body, true);
    assert!(!issues.contains(&NotificationIssue::PermissionSpam));
}

#[test]
fn detects_phishing_login_with_url() {
    let body = r#"
        new Notification('Please login at https://evil.com');
    "#;
    let issues = analyze_notification(body, true);
    assert!(issues.contains(&NotificationIssue::PhishingContent));
}

#[test]
fn detects_phishing_verify_with_url() {
    let body = r#"
        showNotification('Verify your account at www.phishing.net');
    "#;
    let issues = analyze_notification(body, true);
    assert!(issues.contains(&NotificationIssue::PhishingContent));
}

#[test]
fn detects_phishing_confirm_with_url() {
    let body = r#"
        new Notification('Confirm password at login.example.com');
    "#;
    let issues = analyze_notification(body, true);
    assert!(issues.contains(&NotificationIssue::PhishingContent));
}

#[test]
fn no_phishing_without_url() {
    let body = "new Notification('Please login');";
    let issues = analyze_notification(body, true);
    assert!(!issues.contains(&NotificationIssue::PhishingContent));
}

#[test]
fn no_phishing_without_keyword() {
    let body = "new Notification('Visit https://example.com');";
    let issues = analyze_notification(body, true);
    assert!(!issues.contains(&NotificationIssue::PhishingContent));
}

#[test]
fn detects_sensitive_data_password() {
    let body = r#"
        new Notification('Your password is: ' + pwd);
    "#;
    let issues = analyze_notification(body, true);
    assert!(issues.contains(&NotificationIssue::SensitiveDataLeak));
}

#[test]
fn detects_sensitive_data_token() {
    let body = r#"
        showNotification('Token: ' + authToken);
    "#;
    let issues = analyze_notification(body, true);
    assert!(issues.contains(&NotificationIssue::SensitiveDataLeak));
}

#[test]
fn detects_sensitive_data_secret() {
    let body = r#"
        new Notification(title, {body: 'secret=' + secret});
    "#;
    let issues = analyze_notification(body, true);
    assert!(issues.contains(&NotificationIssue::SensitiveDataLeak));
}

#[test]
fn detects_sensitive_data_credential() {
    let body = r#"
        showNotification('credential: ' + cred);
    "#;
    let issues = analyze_notification(body, true);
    assert!(issues.contains(&NotificationIssue::SensitiveDataLeak));
}

#[test]
fn detects_click_hijacking_window_open() {
    let body = r#"
        var n = new Notification('Click me');
        n.onclick = function() { window.open('https://evil.com'); };
    "#;
    let issues = analyze_notification(body, true);
    assert!(issues.contains(&NotificationIssue::ClickHijacking));
}

#[test]
fn detects_click_hijacking_window_location() {
    let body = r#"
        notification.onclick = () => { window.location = 'https://malicious.com'; };
    "#;
    let issues = analyze_notification(body, true);
    assert!(issues.contains(&NotificationIssue::ClickHijacking));
}

#[test]
fn detects_click_hijacking_location_href() {
    let body = r#"
        n.onclick = function() { location.href = 'https://bad.com'; };
    "#;
    let issues = analyze_notification(body, true);
    assert!(issues.contains(&NotificationIssue::ClickHijacking));
}

#[test]
fn detects_click_hijacking_clients_open_window() {
    let body = r#"
        self.addEventListener('notificationclick', function(event) {
            clients.openWindow('https://attacker.com');
        });
    "#;
    let issues = analyze_notification(body, true);
    assert!(issues.contains(&NotificationIssue::ClickHijacking));
}

#[test]
fn detects_push_abuse_without_consent() {
    let body = r#"
        registration.pushManager.subscribe({userVisibleOnly: true});
    "#;
    let issues = analyze_notification(body, true);
    assert!(issues.contains(&NotificationIssue::PushAbuseNoConsent));
}

#[test]
fn no_push_abuse_with_consent() {
    let body = r#"
        if (confirm('Allow notifications?')) {
            PushManager.subscribe({userVisibleOnly: true});
        }
    "#;
    let issues = analyze_notification(body, true);
    assert!(!issues.contains(&NotificationIssue::PushAbuseNoConsent));
}

#[test]
fn no_push_abuse_with_accept() {
    let body = r#"
        if (userAccepted) {
            PushManager.subscribe();
        }
    "#;
    let issues = analyze_notification(body, true);
    assert!(!issues.contains(&NotificationIssue::PushAbuseNoConsent));
}

#[test]
fn severity_sensitive_data_highest() {
    assert_eq!(
        notification_severity(&NotificationIssue::SensitiveDataLeak),
        8.0
    );
}

#[test]
fn severity_phishing_high() {
    assert_eq!(
        notification_severity(&NotificationIssue::PhishingContent),
        7.5
    );
}

#[test]
fn severity_api_lowest() {
    assert_eq!(notification_severity(&NotificationIssue::ApiDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        NotificationIssue::ApiDetected,
        NotificationIssue::PermissionSpam,
    ];
    let mut seq = 0u64;
    let ops = notification_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn to_operations_empty_issues() {
    let issues = vec![];
    let mut seq = 0u64;
    let ops = notification_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn display_api_detected() {
    assert_eq!(NotificationIssue::ApiDetected.to_string(), "api_detected");
}

#[test]
fn display_permission_spam() {
    assert_eq!(
        NotificationIssue::PermissionSpam.to_string(),
        "permission_spam"
    );
}

#[test]
fn display_phishing_content() {
    assert_eq!(
        NotificationIssue::PhishingContent.to_string(),
        "phishing_content"
    );
}

#[test]
fn display_sensitive_data_leak() {
    assert_eq!(
        NotificationIssue::SensitiveDataLeak.to_string(),
        "sensitive_data_leak"
    );
}

#[test]
fn display_click_hijacking() {
    assert_eq!(
        NotificationIssue::ClickHijacking.to_string(),
        "click_hijacking"
    );
}

#[test]
fn display_push_abuse_no_consent() {
    assert_eq!(
        NotificationIssue::PushAbuseNoConsent.to_string(),
        "push_abuse_no_consent"
    );
}

#[test]
fn complex_scenario_multiple_issues() {
    let body = r#"
        Notification.requestPermission();
        new Notification('Verify your password at https://phishing.com');
        notification.onclick = function() {
            window.open('https://evil.com');
        };
        PushManager.subscribe({});
    "#;
    let issues = analyze_notification(body, true);
    assert!(issues.contains(&NotificationIssue::ApiDetected));
    assert!(issues.contains(&NotificationIssue::PermissionSpam));
    assert!(issues.contains(&NotificationIssue::PhishingContent));
    assert!(issues.contains(&NotificationIssue::ClickHijacking));
    assert!(issues.contains(&NotificationIssue::PushAbuseNoConsent));
}

#[test]
fn real_world_service_worker_push() {
    let body = r#"
        self.addEventListener('push', function(event) {
            const data = event.data.json();
            event.waitUntil(
                self.registration.showNotification(data.title, {
                    body: data.body,
                    icon: data.icon
                })
            );
        });

        self.addEventListener('notificationclick', function(event) {
            event.notification.close();
            clients.openWindow(event.notification.data.url);
        });
    "#;
    let issues = analyze_notification(body, true);
    assert!(issues.contains(&NotificationIssue::ApiDetected));
    assert!(issues.contains(&NotificationIssue::ClickHijacking));
}
