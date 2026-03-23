use crate::navigator_login_audit::*;

#[test]
fn test_no_api_detected() {
    let body = "<html><body>Normal page</body></html>";
    let issues = analyze_navigator_login(body);
    assert!(issues.is_empty());
}

#[test]
fn test_api_detected_navigator_login() {
    let body = "if (navigator.login) { console.log('FedCM'); }";
    let issues = analyze_navigator_login(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], NavigatorLoginIssue::ApiDetected);
}

#[test]
fn test_api_detected_navigator_login_interface() {
    let body = "interface NavigatorLogin { isLoggedIn(): boolean; }";
    let issues = analyze_navigator_login(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], NavigatorLoginIssue::ApiDetected);
}

#[test]
fn test_api_detected_set_logged_in() {
    let body = "if (navigator.login.isLoggedIn()) { show(); }";
    let issues = analyze_navigator_login(body);
    assert!(issues.contains(&NavigatorLoginIssue::ApiDetected));
    assert!(!issues.contains(&NavigatorLoginIssue::SessionFixation));
}

#[test]
fn test_api_detected_set_logged_out() {
    let body = "await navigator.login.setLoggedOut(); validate(token);";
    let issues = analyze_navigator_login(body);
    assert!(issues.contains(&NavigatorLoginIssue::ApiDetected));
    assert!(!issues.contains(&NavigatorLoginIssue::SessionFixation));
}

#[test]
fn test_api_detected_is_logged_in() {
    let body = "const status = await navigator.login.isLoggedIn();";
    let issues = analyze_navigator_login(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], NavigatorLoginIssue::ApiDetected);
}

#[test]
fn test_login_status_leak_postmessage() {
    let body = r#"
        const status = await navigator.login.isLoggedIn();
        window.parent.postMessage({ logged_in: status }, '*');
    "#;
    let issues = analyze_navigator_login(body);
    assert!(issues.contains(&NavigatorLoginIssue::ApiDetected));
    assert!(issues.contains(&NavigatorLoginIssue::LoginStatusLeak));
}

#[test]
fn test_login_status_leak_iframe() {
    let body = r#"
        navigator.login.setLoggedIn();
        const iframe = document.createElement('iframe');
    "#;
    let issues = analyze_navigator_login(body);
    assert!(issues.contains(&NavigatorLoginIssue::ApiDetected));
    assert!(issues.contains(&NavigatorLoginIssue::LoginStatusLeak));
}

#[test]
fn test_phishing_risk_modal() {
    let body = r#"
        await navigator.login.setLoggedIn();
        document.getElementById('modal').style.display = 'block';
    "#;
    let issues = analyze_navigator_login(body);
    assert!(issues.contains(&NavigatorLoginIssue::ApiDetected));
    assert!(issues.contains(&NavigatorLoginIssue::PhishingRisk));
}

#[test]
fn test_phishing_risk_dialog() {
    let body = r#"
        navigator.login.setLoggedIn();
        <dialog id="fake-login">Enter password</dialog>
    "#;
    let issues = analyze_navigator_login(body);
    assert!(issues.contains(&NavigatorLoginIssue::ApiDetected));
    assert!(issues.contains(&NavigatorLoginIssue::PhishingRisk));
}

#[test]
fn test_session_fixation_no_validation() {
    let body = r#"
        function login() {
            navigator.login.setLoggedIn();
        }
    "#;
    let issues = analyze_navigator_login(body);
    assert!(issues.contains(&NavigatorLoginIssue::ApiDetected));
    assert!(issues.contains(&NavigatorLoginIssue::SessionFixation));
}

#[test]
fn test_session_fixation_prevented_with_validation() {
    let body = r#"
        async function login(token) {
            if (await validate(token)) {
                navigator.login.setLoggedIn();
            }
        }
    "#;
    let issues = analyze_navigator_login(body);
    assert!(issues.contains(&NavigatorLoginIssue::ApiDetected));
    assert!(!issues.contains(&NavigatorLoginIssue::SessionFixation));
}

#[test]
fn test_tracking_via_login_analytics() {
    let body = r#"
        const logged_in = await navigator.login.isLoggedIn();
        analytics.track('user_status', { logged_in });
    "#;
    let issues = analyze_navigator_login(body);
    assert!(issues.contains(&NavigatorLoginIssue::ApiDetected));
    assert!(issues.contains(&NavigatorLoginIssue::TrackingViaLogin));
}

#[test]
fn test_tracking_via_login_beacon() {
    let body = r#"
        if (await navigator.login.isLoggedIn()) {
            navigator.sendBeacon('/track', data);
        }
    "#;
    let issues = analyze_navigator_login(body);
    assert!(issues.contains(&NavigatorLoginIssue::ApiDetected));
    assert!(issues.contains(&NavigatorLoginIssue::TrackingViaLogin));
}

#[test]
fn test_multiple_issues() {
    let body = r#"
        const status = await navigator.login.isLoggedIn();
        window.parent.postMessage({ status }, '*');
        analytics.track('login_check', { status });
        if (status) {
            showModal('Welcome!');
        }
    "#;
    let issues = analyze_navigator_login(body);
    assert_eq!(issues.len(), 3);
    assert!(issues.contains(&NavigatorLoginIssue::ApiDetected));
    assert!(issues.contains(&NavigatorLoginIssue::LoginStatusLeak));
    assert!(issues.contains(&NavigatorLoginIssue::TrackingViaLogin));
}

#[test]
fn test_severity_values() {
    assert_eq!(
        navigator_login_severity(&NavigatorLoginIssue::ApiDetected),
        2.0
    );
    assert_eq!(
        navigator_login_severity(&NavigatorLoginIssue::LoginStatusLeak),
        7.0
    );
    assert_eq!(
        navigator_login_severity(&NavigatorLoginIssue::PhishingRisk),
        7.5
    );
    assert_eq!(
        navigator_login_severity(&NavigatorLoginIssue::SessionFixation),
        6.5
    );
    assert_eq!(
        navigator_login_severity(&NavigatorLoginIssue::TrackingViaLogin),
        6.0
    );
}

#[test]
fn test_display_format() {
    assert_eq!(NavigatorLoginIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        NavigatorLoginIssue::LoginStatusLeak.to_string(),
        "login_status_leak"
    );
    assert_eq!(
        NavigatorLoginIssue::PhishingRisk.to_string(),
        "phishing_risk"
    );
    assert_eq!(
        NavigatorLoginIssue::SessionFixation.to_string(),
        "session_fixation"
    );
    assert_eq!(
        NavigatorLoginIssue::TrackingViaLogin.to_string(),
        "tracking_via_login"
    );
}

#[test]
fn test_to_operations() {
    let issues = vec![
        NavigatorLoginIssue::ApiDetected,
        NavigatorLoginIssue::PhishingRisk,
    ];
    let mut seq = 100;
    let ops = navigator_login_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 102);
}
