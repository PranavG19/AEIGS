use crate::badging_audit::*;

#[test]
fn no_badging_no_issues() {
    assert!(analyze_badging("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_set_badge() {
    let body = r#"<script>navigator.setAppBadge(5);</script>"#;
    let issues = analyze_badging(body);
    assert!(issues.contains(&BadgingIssue::ApiDetected));
}

#[test]
fn detects_api_clear_badge() {
    let body = r#"<script>navigator.clearAppBadge();</script>"#;
    let issues = analyze_badging(body);
    assert!(issues.contains(&BadgingIssue::ApiDetected));
}

#[test]
fn detects_no_user_activation() {
    let body = r#"<script>navigator.setAppBadge(10);</script>"#;
    let issues = analyze_badging(body);
    assert!(issues.contains(&BadgingIssue::NoUserActivation));
}

#[test]
fn no_activation_issue_with_click() {
    let body = r#"<script>
        btn.addEventListener("click", () => navigator.setAppBadge(1));
    </script>"#;
    let issues = analyze_badging(body);
    assert!(!issues.contains(&BadgingIssue::NoUserActivation));
}

#[test]
fn detects_continuous_update() {
    let body = r#"<script>
        setInterval(() => navigator.setAppBadge(count++), 1000);
    </script>"#;
    let issues = analyze_badging(body);
    assert!(issues.contains(&BadgingIssue::ContinuousUpdate));
}

#[test]
fn detects_misleading_badge() {
    let body = r#"<script>navigator.setAppBadge(9999);</script>"#;
    let issues = analyze_badging(body);
    assert!(issues.contains(&BadgingIssue::MisleadingBadge));
}

#[test]
fn no_misleading_with_normal_count() {
    let body = r#"<script>navigator.setAppBadge(3);</script>"#;
    let issues = analyze_badging(body);
    assert!(!issues.contains(&BadgingIssue::MisleadingBadge));
}

#[test]
fn detects_spoofed_urgency() {
    let body = r#"<script>
        navigator.setAppBadge(1);
        showNotification("security alert: verify your account");
    </script>"#;
    let issues = analyze_badging(body);
    assert!(issues.contains(&BadgingIssue::SpoofedUrgency));
}

#[test]
fn no_urgency_without_keywords() {
    let body = r#"<script>
        navigator.setAppBadge(1);
        console.log("badge set");
    </script>"#;
    let issues = analyze_badging(body);
    assert!(!issues.contains(&BadgingIssue::SpoofedUrgency));
}

#[test]
fn severity_urgency_highest() {
    assert_eq!(badging_severity(&BadgingIssue::SpoofedUrgency), 6.0);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(badging_severity(&BadgingIssue::ApiDetected), 2.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![BadgingIssue::ApiDetected, BadgingIssue::MisleadingBadge];
    let mut seq = 0;
    let ops = badging_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(BadgingIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        BadgingIssue::MisleadingBadge.to_string(),
        "misleading_badge"
    );
    assert_eq!(
        BadgingIssue::ContinuousUpdate.to_string(),
        "continuous_update"
    );
    assert_eq!(
        BadgingIssue::NoUserActivation.to_string(),
        "no_user_activation"
    );
    assert_eq!(BadgingIssue::SpoofedUrgency.to_string(), "spoofed_urgency");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_badging("").is_empty());
}

#[test]
fn security_no_badge_api_returns_empty() {
    let body = "<html><body>no badge here</body></html>";
    assert!(analyze_badging_security(body).is_empty());
}

#[test]
fn security_detects_service_worker_lowercase() {
    let body = r#"
        navigator.serviceWorker.register('/sw.js');
        navigator.setAppBadge(5);
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingInServiceWorker));
}

#[test]
fn security_detects_service_worker_camelcase() {
    let body = r#"
        ServiceWorkerRegistration.badge.set(3);
        navigator.setAppBadge(3);
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingInServiceWorker));
}

#[test]
fn security_detects_service_worker_self_registration() {
    let body = r#"
        self.registration.setAppBadge(1);
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingInServiceWorker));
}

#[test]
fn security_detects_notification_capital() {
    let body = r#"
        new Notification("Hello");
        navigator.setAppBadge(2);
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingWithNotification));
}

#[test]
fn security_detects_show_notification() {
    let body = r#"
        registration.showNotification("Alert");
        setAppBadge(10);
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingWithNotification));
}

#[test]
fn security_detects_push_manager() {
    let body = r#"
        PushManager.subscribe();
        setAppBadge(1);
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingWithNotification));
}

#[test]
fn security_detects_phishing_login() {
    let body = r#"
        function login() { setAppBadge(1); }
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingPhishingIndicator));
}

#[test]
fn security_detects_phishing_password() {
    let body = r#"
        const password = input.value;
        navigator.setAppBadge(1);
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingPhishingIndicator));
}

#[test]
fn security_detects_phishing_verify() {
    let body = r#"
        verify your account
        setAppBadge(5);
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingPhishingIndicator));
}

#[test]
fn security_detects_phishing_account() {
    let body = r#"
        account settings
        navigator.setAppBadge(2);
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingPhishingIndicator));
}

#[test]
fn security_detects_phishing_bank() {
    let body = r#"
        bank transfer complete
        setAppBadge(1);
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingPhishingIndicator));
}

#[test]
fn security_detects_persistence_local_storage() {
    let body = r#"
        localStorage.setItem('badge', count);
        navigator.setAppBadge(count);
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingPersistence));
}

#[test]
fn security_detects_persistence_session_storage() {
    let body = r#"
        sessionStorage.setItem('badge', 5);
        setAppBadge(5);
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingPersistence));
}

#[test]
fn security_detects_persistence_indexeddb() {
    let body = r#"
        indexedDB.open('badge-db');
        navigator.setAppBadge(3);
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingPersistence));
}

#[test]
fn security_detects_cross_origin_post_message() {
    let body = r#"
        window.postMessage({badge: 5}, '*');
        setAppBadge(5);
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingCrossOrigin));
}

#[test]
fn security_detects_cross_origin_keyword() {
    let body = r#"
        // cross-origin badge sync
        navigator.setAppBadge(1);
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingCrossOrigin));
}

#[test]
fn security_detects_cross_origin_iframe() {
    let body = r#"
        iframe.contentWindow.setAppBadge(2);
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingCrossOrigin));
}

#[test]
fn security_detects_push_api_push_manager() {
    let body = r#"
        PushManager.getSubscription();
        setAppBadge(1);
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingWithPushApi));
}

#[test]
fn security_detects_push_api_lowercase() {
    let body = r#"
        registration.pushManager.subscribe({});
        navigator.setAppBadge(5);
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingWithPushApi));
}

#[test]
fn security_detects_push_api_subscribe() {
    let body = r#"
        push.subscribe();
        setAppBadge(1);
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingWithPushApi));
}

#[test]
fn security_detects_excessive_value_101() {
    let body = r#"navigator.setAppBadge(101);"#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingExcessiveValue));
}

#[test]
fn security_detects_excessive_value_999() {
    let body = r#"setAppBadge(999);"#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingExcessiveValue));
}

#[test]
fn security_no_excessive_value_100() {
    let body = r#"navigator.setAppBadge(100);"#;
    let issues = analyze_badging_security(body);
    assert!(!issues.contains(&BadgingIssue::BadgingExcessiveValue));
}

#[test]
fn security_no_excessive_value_50() {
    let body = r#"setAppBadge(50);"#;
    let issues = analyze_badging_security(body);
    assert!(!issues.contains(&BadgingIssue::BadgingExcessiveValue));
}

#[test]
fn security_detects_without_clear_logic() {
    let body = r#"navigator.setAppBadge(5);"#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingWithoutClearLogic));
}

#[test]
fn security_no_without_clear_when_present() {
    let body = r#"
        navigator.setAppBadge(5);
        navigator.clearAppBadge();
    "#;
    let issues = analyze_badging_security(body);
    assert!(!issues.contains(&BadgingIssue::BadgingWithoutClearLogic));
}

#[test]
fn security_detects_timing_attack_performance() {
    let body = r#"
        const start = performance.now();
        setAppBadge(1);
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingTimingAttack));
}

#[test]
fn security_detects_timing_attack_date() {
    let body = r#"
        const time = Date.now();
        navigator.setAppBadge(2);
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingTimingAttack));
}

#[test]
fn security_detects_background_visibility_change() {
    let body = r#"
        document.addEventListener('visibilitychange', () => {
            setAppBadge(1);
        });
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingInBackground));
}

#[test]
fn security_detects_background_hidden() {
    let body = r#"
        if (document.hidden) {
            navigator.setAppBadge(5);
        }
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingInBackground));
}

#[test]
fn security_detects_background_keyword() {
    let body = r#"
        // background badge update
        setAppBadge(1);
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingInBackground));
}

#[test]
fn security_multiple_issues_detected() {
    let body = r#"
        navigator.serviceWorker.register('/sw.js');
        localStorage.setItem('count', 5);
        if (document.hidden) {
            navigator.setAppBadge(150);
        }
    "#;
    let issues = analyze_badging_security(body);
    assert!(issues.contains(&BadgingIssue::BadgingInServiceWorker));
    assert!(issues.contains(&BadgingIssue::BadgingPersistence));
    assert!(issues.contains(&BadgingIssue::BadgingInBackground));
    assert!(issues.contains(&BadgingIssue::BadgingExcessiveValue));
}

#[test]
fn security_severity_phishing_highest() {
    assert_eq!(
        badging_severity(&BadgingIssue::BadgingPhishingIndicator),
        7.5
    );
}

#[test]
fn security_severity_cross_origin() {
    assert_eq!(badging_severity(&BadgingIssue::BadgingCrossOrigin), 6.0);
}

#[test]
fn security_severity_notification() {
    assert_eq!(
        badging_severity(&BadgingIssue::BadgingWithNotification),
        5.5
    );
}

#[test]
fn security_severity_push_api() {
    assert_eq!(badging_severity(&BadgingIssue::BadgingWithPushApi), 5.5);
}

#[test]
fn security_severity_service_worker() {
    assert_eq!(badging_severity(&BadgingIssue::BadgingInServiceWorker), 5.0);
}

#[test]
fn security_severity_timing_attack() {
    assert_eq!(badging_severity(&BadgingIssue::BadgingTimingAttack), 5.0);
}

#[test]
fn security_severity_persistence() {
    assert_eq!(badging_severity(&BadgingIssue::BadgingPersistence), 4.5);
}

#[test]
fn security_severity_background() {
    assert_eq!(badging_severity(&BadgingIssue::BadgingInBackground), 4.5);
}

#[test]
fn security_severity_excessive_value() {
    assert_eq!(badging_severity(&BadgingIssue::BadgingExcessiveValue), 4.0);
}

#[test]
fn security_severity_without_clear() {
    assert_eq!(
        badging_severity(&BadgingIssue::BadgingWithoutClearLogic),
        3.5
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        BadgingIssue::BadgingInServiceWorker,
        BadgingIssue::BadgingPhishingIndicator,
    ];
    let mut seq = 0;
    let ops = badging_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_to_operations_empty() {
    let issues = vec![];
    let mut seq = 0;
    let ops = badging_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 0);
    assert_eq!(seq, 0);
}

#[test]
fn display_new_variants() {
    assert_eq!(
        BadgingIssue::BadgingInServiceWorker.to_string(),
        "badging_in_service_worker"
    );
    assert_eq!(
        BadgingIssue::BadgingWithNotification.to_string(),
        "badging_with_notification"
    );
    assert_eq!(
        BadgingIssue::BadgingPhishingIndicator.to_string(),
        "badging_phishing_indicator"
    );
    assert_eq!(
        BadgingIssue::BadgingPersistence.to_string(),
        "badging_persistence"
    );
    assert_eq!(
        BadgingIssue::BadgingCrossOrigin.to_string(),
        "badging_cross_origin"
    );
    assert_eq!(
        BadgingIssue::BadgingWithPushApi.to_string(),
        "badging_with_push_api"
    );
    assert_eq!(
        BadgingIssue::BadgingExcessiveValue.to_string(),
        "badging_excessive_value"
    );
    assert_eq!(
        BadgingIssue::BadgingWithoutClearLogic.to_string(),
        "badging_without_clear_logic"
    );
    assert_eq!(
        BadgingIssue::BadgingTimingAttack.to_string(),
        "badging_timing_attack"
    );
    assert_eq!(
        BadgingIssue::BadgingInBackground.to_string(),
        "badging_in_background"
    );
}
