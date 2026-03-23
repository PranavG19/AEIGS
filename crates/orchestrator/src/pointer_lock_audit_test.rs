use crate::pointer_lock_audit::*;

#[test]
fn empty_body() {
    let issues = analyze_pointer_lock("");
    assert!(issues.is_empty());
}

#[test]
fn no_api() {
    let body = "<html><body><script>console.log('hello');</script></body></html>";
    let issues = analyze_pointer_lock(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_request_pointer_lock() {
    let body = "<script>element.requestPointerLock();</script>";
    let issues = analyze_pointer_lock(body);
    assert!(issues.iter().any(|i| *i == PointerLockIssue::ApiDetected));
}

#[test]
fn detects_pointer_lock_element() {
    let body = "<script>var el = document.pointerLockElement; el.exitPointerLock();</script>";
    let issues = analyze_pointer_lock(body);
    assert!(issues.iter().any(|i| *i == PointerLockIssue::ApiDetected));
}

#[test]
fn detects_clickjacking() {
    let body = concat!(
        "<script>",
        "element.requestPointerLock();",
        "document.fullscreen;",
        "element.innerHTML = payload;",
        "</script>",
    );
    let issues = analyze_pointer_lock(body);
    assert!(issues.iter().any(|i| *i == PointerLockIssue::ClickjackingRisk));
}

#[test]
fn no_clickjacking_without_injection() {
    let body = concat!(
        "<script>",
        "element.requestPointerLock();",
        "document.fullscreen;",
        "console.log('safe');",
        "</script>",
    );
    let issues = analyze_pointer_lock(body);
    assert!(!issues.iter().any(|i| *i == PointerLockIssue::ClickjackingRisk));
}

#[test]
fn detects_ui_spoofing() {
    let body = concat!(
        "<script>element.requestPointerLock();</script>",
        "<style>body { cursor: none; position: fixed; }</style>",
    );
    let issues = analyze_pointer_lock(body);
    assert!(issues.iter().any(|i| *i == PointerLockIssue::UiSpoofing));
}

#[test]
fn no_spoofing_without_positioning() {
    let body = concat!(
        "<script>element.requestPointerLock();</script>",
        "<style>body { cursor: none; }</style>",
    );
    let issues = analyze_pointer_lock(body);
    assert!(!issues.iter().any(|i| *i == PointerLockIssue::UiSpoofing));
}

#[test]
fn detects_input_hijacking() {
    let body = concat!(
        "<script>",
        "if (document.pointerLockElement) {",
        "  document.addEventListener('mousemove', handler);",
        "}",
        "</script>",
    );
    let issues = analyze_pointer_lock(body);
    assert!(issues.iter().any(|i| *i == PointerLockIssue::InputHijacking));
}

#[test]
fn no_hijacking_with_exit() {
    let body = concat!(
        "<script>",
        "if (document.pointerLockElement) {",
        "  document.addEventListener('mousemove', handler);",
        "}",
        "document.exitPointerLock();",
        "</script>",
    );
    let issues = analyze_pointer_lock(body);
    assert!(!issues.iter().any(|i| *i == PointerLockIssue::InputHijacking));
}

#[test]
fn detects_escape_bypass() {
    let body = concat!(
        "<script>",
        "element.requestPointerLock({ unadjustedMovement: true });",
        "</script>",
    );
    let issues = analyze_pointer_lock(body);
    assert!(issues.iter().any(|i| *i == PointerLockIssue::EscapeBypass));
}

#[test]
fn no_escape_bypass_with_error_handler() {
    let body = concat!(
        "<script>",
        "element.requestPointerLock({ unadjustedMovement: true });",
        "document.addEventListener('pointerlockerror', handleErr);",
        "</script>",
    );
    let issues = analyze_pointer_lock(body);
    assert!(!issues.iter().any(|i| *i == PointerLockIssue::EscapeBypass));
}

#[test]
fn all_issues_detected() {
    let body = concat!(
        "<script>",
        "element.requestPointerLock({ unadjustedMovement: true });",
        "if (document.pointerLockElement) {",
        "  document.addEventListener('mousemove', handler);",
        "}",
        "document.requestFullscreen();",
        "element.innerHTML = payload;",
        "</script>",
        "<style>body { cursor: none; position: fixed; }</style>",
    );
    let issues = analyze_pointer_lock(body);
    assert!(issues.iter().any(|i| *i == PointerLockIssue::ApiDetected));
    assert!(issues.iter().any(|i| *i == PointerLockIssue::ClickjackingRisk));
    assert!(issues.iter().any(|i| *i == PointerLockIssue::UiSpoofing));
    assert!(issues.iter().any(|i| *i == PointerLockIssue::EscapeBypass));
}

#[test]
fn severity_values_correct() {
    assert!((pointer_lock_severity(&PointerLockIssue::ApiDetected) - 2.0).abs() < f64::EPSILON);
    assert!((pointer_lock_severity(&PointerLockIssue::ClickjackingRisk) - 7.0).abs() < f64::EPSILON);
    assert!((pointer_lock_severity(&PointerLockIssue::UiSpoofing) - 6.5).abs() < f64::EPSILON);
    assert!((pointer_lock_severity(&PointerLockIssue::InputHijacking) - 6.0).abs() < f64::EPSILON);
    assert!((pointer_lock_severity(&PointerLockIssue::EscapeBypass) - 5.5).abs() < f64::EPSILON);
}

#[test]
fn display_impl_works() {
    assert_eq!(PointerLockIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(PointerLockIssue::ClickjackingRisk.to_string(), "clickjacking_risk");
    assert_eq!(PointerLockIssue::UiSpoofing.to_string(), "ui_spoofing");
    assert_eq!(PointerLockIssue::InputHijacking.to_string(), "input_hijacking");
    assert_eq!(PointerLockIssue::EscapeBypass.to_string(), "escape_bypass");
}

#[test]
fn operations_generated_correctly() {
    let issues = vec![PointerLockIssue::ClickjackingRisk];
    let mut seq = 0;
    let ops = pointer_lock_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn operations_increment_sequence() {
    let issues = vec![
        PointerLockIssue::ApiDetected,
        PointerLockIssue::ClickjackingRisk,
        PointerLockIssue::UiSpoofing,
    ];
    let mut seq = 5;
    let ops = pointer_lock_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 8);
}

#[test]
fn detects_exit_pointer_lock_api() {
    let body = "<script>document.exitPointerLock();</script>";
    let issues = analyze_pointer_lock(body);
    assert!(issues.iter().any(|i| *i == PointerLockIssue::ApiDetected));
}
