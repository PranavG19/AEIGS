use crate::priority_hints_audit::*;

#[test]
fn test_no_priority_hints() {
    let body = "<html><head><title>Test</title></head><body></body></html>";
    let issues = analyze_priority_hints(body);
    assert!(issues.is_empty());
}

#[test]
fn test_api_detected_fetchpriority() {
    let body = r#"<img src="test.jpg" fetchpriority="high">"#;
    let issues = analyze_priority_hints(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], PriorityHintsIssue::ApiDetected);
}

#[test]
fn test_api_detected_fetchpriority_camel() {
    let body = r#"<script>img.fetchPriority = "low";</script>"#;
    let issues = analyze_priority_hints(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], PriorityHintsIssue::ApiDetected);
}

#[test]
fn test_api_detected_importance() {
    let body = r#"<link rel="preload" importance="high">"#;
    let issues = analyze_priority_hints(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], PriorityHintsIssue::ApiDetected);
}

#[test]
fn test_high_priority_tracker_analytics() {
    let body = r#"<script src="analytics.js" fetchpriority="high"></script>"#;
    let issues = analyze_priority_hints(body);
    assert!(issues.contains(&PriorityHintsIssue::ApiDetected));
    assert!(issues.contains(&PriorityHintsIssue::HighPriorityTracker));
}

#[test]
fn test_high_priority_tracker_beacon() {
    let body = r#"<img src="beacon.gif" fetchpriority="high">"#;
    let issues = analyze_priority_hints(body);
    assert!(issues.contains(&PriorityHintsIssue::HighPriorityTracker));
}

#[test]
fn test_high_priority_tracker_fetchpriority_camel() {
    let body = r#"<script>img.fetchPriority = "high"; analytics.send();</script>"#;
    let issues = analyze_priority_hints(body);
    assert!(issues.contains(&PriorityHintsIssue::HighPriorityTracker));
}

#[test]
fn test_low_priority_csp_report() {
    let body = r#"<link rel="csp-report" fetchpriority="low">"#;
    let issues = analyze_priority_hints(body);
    assert!(issues.contains(&PriorityHintsIssue::LowPriorityCSP));
}

#[test]
fn test_low_priority_security() {
    let body = r#"<script src="security.js" fetchpriority="low" integrity="sha256-..."></script>"#;
    let issues = analyze_priority_hints(body);
    assert!(issues.contains(&PriorityHintsIssue::LowPriorityCSP));
}

#[test]
fn test_resource_priority_spoofing() {
    let body = r#"
        <script>
        const img = document.createElement("img");
        img.fetchPriority = "high";
        img.setAttribute("src", url);
        </script>
    "#;
    let issues = analyze_priority_hints(body);
    assert!(issues.contains(&PriorityHintsIssue::ResourcePrioritySpoofing));
}

#[test]
fn test_no_spoofing_with_static() {
    let body = r#"
        <script>
        const img = document.createElement("img");
        img.fetchPriority = "high";
        const static = true;
        </script>
    "#;
    let issues = analyze_priority_hints(body);
    assert!(!issues.contains(&PriorityHintsIssue::ResourcePrioritySpoofing));
}

#[test]
fn test_preload_abuse_script() {
    let body = r#"<link rel="preload" as="script" href="app.js" fetchpriority="high">"#;
    let issues = analyze_priority_hints(body);
    assert!(issues.contains(&PriorityHintsIssue::PreloadAbuse));
}

#[test]
fn test_preload_abuse_style() {
    let body = r#"<link rel="prefetch" as="style" href="app.css" fetchpriority="high">"#;
    let issues = analyze_priority_hints(body);
    assert!(issues.contains(&PriorityHintsIssue::PreloadAbuse));
}

#[test]
fn test_multiple_issues() {
    let body = r#"
        <link rel="preload" as="script" href="analytics.js" fetchpriority="high">
        <script src="tracking.js" fetchpriority="high"></script>
        <link rel="csp-report" fetchpriority="low">
        <script>
        img.fetchPriority = "high";
        img.setAttribute("src", url);
        </script>
    "#;
    let issues = analyze_priority_hints(body);
    assert!(issues.contains(&PriorityHintsIssue::ApiDetected));
    assert!(issues.contains(&PriorityHintsIssue::HighPriorityTracker));
    assert!(issues.contains(&PriorityHintsIssue::LowPriorityCSP));
    assert!(issues.contains(&PriorityHintsIssue::ResourcePrioritySpoofing));
    assert!(issues.contains(&PriorityHintsIssue::PreloadAbuse));
}

#[test]
fn test_severity_values() {
    assert_eq!(
        priority_hints_severity(&PriorityHintsIssue::ApiDetected),
        2.0
    );
    assert_eq!(
        priority_hints_severity(&PriorityHintsIssue::HighPriorityTracker),
        6.5
    );
    assert_eq!(
        priority_hints_severity(&PriorityHintsIssue::LowPriorityCSP),
        7.0
    );
    assert_eq!(
        priority_hints_severity(&PriorityHintsIssue::ResourcePrioritySpoofing),
        5.5
    );
    assert_eq!(
        priority_hints_severity(&PriorityHintsIssue::PreloadAbuse),
        6.0
    );
}

#[test]
fn test_to_operations() {
    let issues = vec![
        PriorityHintsIssue::ApiDetected,
        PriorityHintsIssue::HighPriorityTracker,
    ];
    let mut seq = 100;
    let ops = priority_hints_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 102);
}

#[test]
fn test_display_trait() {
    assert_eq!(PriorityHintsIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        PriorityHintsIssue::HighPriorityTracker.to_string(),
        "high_priority_tracker"
    );
    assert_eq!(
        PriorityHintsIssue::LowPriorityCSP.to_string(),
        "low_priority_csp"
    );
    assert_eq!(
        PriorityHintsIssue::ResourcePrioritySpoofing.to_string(),
        "resource_priority_spoofing"
    );
    assert_eq!(
        PriorityHintsIssue::PreloadAbuse.to_string(),
        "preload_abuse"
    );
}
