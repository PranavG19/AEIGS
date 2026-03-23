use crate::vibration_audit::*;

#[test]
fn no_vibration_no_issues() {
    assert!(analyze_vibration("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_navigator() {
    let body = r#"<script>navigator.vibrate(200);</script>"#;
    let issues = analyze_vibration(body);
    assert!(issues.contains(&VibrationIssue::ApiDetected));
}

#[test]
fn detects_api_method() {
    let body = r#"<script>device.vibrate(100);</script>"#;
    let issues = analyze_vibration(body);
    assert!(issues.contains(&VibrationIssue::ApiDetected));
}

#[test]
fn detects_no_user_activation() {
    let body = r#"<script>navigator.vibrate(200);</script>"#;
    let issues = analyze_vibration(body);
    assert!(issues.contains(&VibrationIssue::NoUserActivation));
}

#[test]
fn no_activation_issue_with_click() {
    let body = r#"<script>
        btn.addEventListener("click", () => navigator.vibrate(200));
    </script>"#;
    let issues = analyze_vibration(body);
    assert!(!issues.contains(&VibrationIssue::NoUserActivation));
}

#[test]
fn detects_excessive_duration() {
    let body = r#"<script>navigator.vibrate([200, 100, 200, 100, 200]);</script>"#;
    let issues = analyze_vibration(body);
    assert!(issues.contains(&VibrationIssue::ExcessiveDuration));
}

#[test]
fn no_excessive_without_pattern() {
    let body = r#"<script>navigator.vibrate(200);</script>"#;
    let issues = analyze_vibration(body);
    assert!(!issues.contains(&VibrationIssue::ExcessiveDuration));
}

#[test]
fn detects_continuous_vibration() {
    let body = r#"<script>
        setInterval(() => navigator.vibrate(100), 500);
    </script>"#;
    let issues = analyze_vibration(body);
    assert!(issues.contains(&VibrationIssue::ContinuousVibration));
}

#[test]
fn detects_covert_channel() {
    let body = r#"<script>
        const ws = new WebSocket("ws://evil.com");
        ws.onmessage = (e) => navigator.vibrate(JSON.parse(e.data));
    </script>"#;
    let issues = analyze_vibration(body);
    assert!(issues.contains(&VibrationIssue::CovertChannel));
}

#[test]
fn no_covert_without_channel() {
    let body = r#"<script>
        btn.addEventListener("click", () => navigator.vibrate(200));
    </script>"#;
    let issues = analyze_vibration(body);
    assert!(!issues.contains(&VibrationIssue::CovertChannel));
}

#[test]
fn severity_covert_highest() {
    assert_eq!(vibration_severity(&VibrationIssue::CovertChannel), 6.5);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(vibration_severity(&VibrationIssue::ApiDetected), 2.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![VibrationIssue::ApiDetected, VibrationIssue::CovertChannel];
    let mut seq = 0;
    let ops = vibration_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(VibrationIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        VibrationIssue::NoUserActivation.to_string(),
        "no_user_activation"
    );
    assert_eq!(
        VibrationIssue::ExcessiveDuration.to_string(),
        "excessive_duration"
    );
    assert_eq!(
        VibrationIssue::ContinuousVibration.to_string(),
        "continuous_vibration"
    );
    assert_eq!(VibrationIssue::CovertChannel.to_string(), "covert_channel");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_vibration("").is_empty());
}
