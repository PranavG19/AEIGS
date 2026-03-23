use crate::abort_controller_audit::*;

#[test]
fn test_api_detected_abort_controller() {
    let body = "<script>const controller = new AbortController();</script>";
    let issues = analyze_abort_controller(body);
    assert!(issues.contains(&AbortControllerIssue::ApiDetected));
}

#[test]
fn test_api_detected_abort_signal() {
    let body = "<script>function check(signal: AbortSignal) {}</script>";
    let issues = analyze_abort_controller(body);
    assert!(issues.contains(&AbortControllerIssue::ApiDetected));
}

#[test]
fn test_api_detected_signal_aborted() {
    let body = "<script>if (signal.aborted) return;</script>";
    let issues = analyze_abort_controller(body);
    assert!(issues.contains(&AbortControllerIssue::ApiDetected));
}

#[test]
fn test_denial_of_service_no_cleanup() {
    let body = r#"
        <script>
        const c = new AbortController();
        setInterval(() => {}, 100);
        c.abort();
        </script>
    "#;
    let issues = analyze_abort_controller(body);
    assert!(issues.contains(&AbortControllerIssue::DenialOfService));
}

#[test]
fn test_denial_of_service_with_cleanup() {
    let body = r#"
        <script>
        const c = new AbortController();
        const id = setInterval(() => {}, 100);
        clearInterval(id);
        c.abort();
        </script>
    "#;
    let issues = analyze_abort_controller(body);
    assert!(!issues.contains(&AbortControllerIssue::DenialOfService));
}

#[test]
fn test_security_bypass_csrf() {
    let body = r#"
        <script>
        const c = new AbortController();
        c.abort();
        const csrf = getToken();
        </script>
    "#;
    let issues = analyze_abort_controller(body);
    assert!(issues.contains(&AbortControllerIssue::SecurityBypass));
}

#[test]
fn test_security_bypass_auth() {
    let body = r#"
        <script>
        const signal = new AbortController().signal;
        signal.abort();
        const auth = verify();
        </script>
    "#;
    let issues = analyze_abort_controller(body);
    assert!(issues.contains(&AbortControllerIssue::SecurityBypass));
}

#[test]
fn test_race_condition_promise_race() {
    let body = r#"
        <script>
        const c = new AbortController();
        Promise.race([fetch('/api')]);
        c.abort();
        </script>
    "#;
    let issues = analyze_abort_controller(body);
    assert!(issues.contains(&AbortControllerIssue::RaceCondition));
}

#[test]
fn test_race_condition_xhr() {
    let body = r#"
        <script>
        const c = new AbortController();
        setTimeout(() => c.abort(), 100);
        const xhr = new XMLHttpRequest();
        </script>
    "#;
    let issues = analyze_abort_controller(body);
    assert!(issues.contains(&AbortControllerIssue::RaceCondition));
}

#[test]
fn test_resource_leak_no_cleanup() {
    let body = "<script>const c = new AbortController();</script>";
    let issues = analyze_abort_controller(body);
    assert!(issues.contains(&AbortControllerIssue::ResourceLeak));
}

#[test]
fn test_resource_leak_with_abort() {
    let body = r#"
        <script>
        const c = new AbortController();
        c.abort();
        </script>
    "#;
    let issues = analyze_abort_controller(body);
    assert!(!issues.contains(&AbortControllerIssue::ResourceLeak));
}

#[test]
fn test_resource_leak_with_finally() {
    let body = r#"
        <script>
        const c = new AbortController();
        fetch('/api').finally(() => {});
        </script>
    "#;
    let issues = analyze_abort_controller(body);
    assert!(!issues.contains(&AbortControllerIssue::ResourceLeak));
}

#[test]
fn test_no_issues_without_api() {
    let body = "<html><body>Hello World</body></html>";
    let issues = analyze_abort_controller(body);
    assert!(issues.is_empty());
}

#[test]
fn test_severity_mapping() {
    assert_eq!(
        abort_controller_severity(&AbortControllerIssue::ApiDetected),
        2.0
    );
    assert_eq!(
        abort_controller_severity(&AbortControllerIssue::DenialOfService),
        7.0
    );
    assert_eq!(
        abort_controller_severity(&AbortControllerIssue::SecurityBypass),
        7.5
    );
    assert_eq!(
        abort_controller_severity(&AbortControllerIssue::RaceCondition),
        6.5
    );
    assert_eq!(
        abort_controller_severity(&AbortControllerIssue::ResourceLeak),
        5.5
    );
}

#[test]
fn test_to_operations() {
    let issues = vec![
        AbortControllerIssue::ApiDetected,
        AbortControllerIssue::SecurityBypass,
    ];
    let mut seq = 1;
    let ops = abort_controller_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 3);
}

#[test]
fn test_display_trait() {
    assert_eq!(
        AbortControllerIssue::ApiDetected.to_string(),
        "api_detected"
    );
    assert_eq!(
        AbortControllerIssue::DenialOfService.to_string(),
        "denial_of_service"
    );
    assert_eq!(
        AbortControllerIssue::SecurityBypass.to_string(),
        "security_bypass"
    );
    assert_eq!(
        AbortControllerIssue::RaceCondition.to_string(),
        "race_condition"
    );
    assert_eq!(
        AbortControllerIssue::ResourceLeak.to_string(),
        "resource_leak"
    );
}
