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
