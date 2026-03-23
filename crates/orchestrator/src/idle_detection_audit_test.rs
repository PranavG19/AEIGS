use crate::idle_detection_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_idle_detection("");
    assert!(issues.is_empty());
}

#[test]
fn no_idle_api_no_issues() {
    let body = "<html><body>Hello</body></html>";
    let issues = analyze_idle_detection(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_idle_detector_usage() {
    let body = "const detector = new IdleDetector();";
    let issues = analyze_idle_detection(body);
    assert!(issues.contains(&IdleDetectionIssue::IdleDetectorUsage));
}

#[test]
fn detects_idle_state_exfiltration() {
    let body = r#"
        const detector = new IdleDetector();
        detector.addEventListener('change', () => {
            fetch('/track?state=' + detector.userState);
        });
    "#;
    let issues = analyze_idle_detection(body);
    assert!(issues.contains(&IdleDetectionIssue::IdleStateExfiltration));
}

#[test]
fn no_exfiltration_without_send() {
    let body = r#"
        const detector = new IdleDetector();
        console.log(detector.userState);
    "#;
    let issues = analyze_idle_detection(body);
    assert!(!issues.contains(&IdleDetectionIssue::IdleStateExfiltration));
}

#[test]
fn detects_idle_change_tracking() {
    let body = r#"
        const detector = new IdleDetector();
        detector.addEventListener('change', handler);
    "#;
    let issues = analyze_idle_detection(body);
    assert!(issues.contains(&IdleDetectionIssue::IdleChangeTracking));
}

#[test]
fn detects_onchange_tracking() {
    let body = r#"
        const detector = new IdleDetector();
        detector.onchange = handler;
    "#;
    let issues = analyze_idle_detection(body);
    assert!(issues.contains(&IdleDetectionIssue::IdleChangeTracking));
}

#[test]
fn detects_screen_state_monitoring() {
    let body = r#"
        const detector = new IdleDetector();
        console.log(detector.screenState);
    "#;
    let issues = analyze_idle_detection(body);
    assert!(issues.contains(&IdleDetectionIssue::ScreenStateMonitoring));
}

#[test]
fn detects_continuous_idle_polling() {
    let body = r#"
        const detector = new IdleDetector();
        setInterval(() => { check(detector); }, 1000);
    "#;
    let issues = analyze_idle_detection(body);
    assert!(issues.contains(&IdleDetectionIssue::ContinuousIdlePolling));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        idle_detection_severity(&IdleDetectionIssue::IdleStateExfiltration),
        7.5
    );
}

#[test]
fn severity_usage_lowest() {
    assert_eq!(
        idle_detection_severity(&IdleDetectionIssue::IdleDetectorUsage),
        5.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        IdleDetectionIssue::IdleDetectorUsage,
        IdleDetectionIssue::ScreenStateMonitoring,
    ];
    let mut seq = 0;
    let ops = idle_detection_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        IdleDetectionIssue::IdleDetectorUsage.to_string(),
        "idle_detector_usage"
    );
    assert_eq!(
        IdleDetectionIssue::IdleStateExfiltration.to_string(),
        "idle_state_exfiltration"
    );
    assert_eq!(
        IdleDetectionIssue::ScreenStateMonitoring.to_string(),
        "screen_state_monitoring"
    );
    assert_eq!(
        IdleDetectionIssue::ContinuousIdlePolling.to_string(),
        "continuous_idle_polling"
    );
}
