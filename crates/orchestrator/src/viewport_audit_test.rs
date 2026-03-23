use crate::viewport_audit::*;

#[test]
fn empty_body_viewport_missing() {
    let issues = analyze_viewport("");
    assert!(issues.contains(&ViewportIssue::ViewportMissing));
}

#[test]
fn no_viewport_meta_reports_missing() {
    let body = "<html><head><meta charset='utf-8'></head></html>";
    let issues = analyze_viewport(body);
    assert!(issues.contains(&ViewportIssue::ViewportMissing));
}

#[test]
fn proper_viewport_no_issues() {
    let body = r#"<meta name="viewport" content="width=device-width, initial-scale=1.0">"#;
    let issues = analyze_viewport(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_zoom_disabled() {
    let body = r#"<meta name="viewport" content="width=device-width, user-scalable=no">"#;
    let issues = analyze_viewport(body);
    assert!(issues.contains(&ViewportIssue::ZoomDisabled));
}

#[test]
fn detects_zoom_disabled_zero() {
    let body = r#"<meta name="viewport" content="width=device-width, user-scalable=0">"#;
    let issues = analyze_viewport(body);
    assert!(issues.contains(&ViewportIssue::ZoomDisabled));
}

#[test]
fn detects_maximum_scale_one() {
    let body = r#"<meta name="viewport" content="width=device-width, maximum-scale=1.0">"#;
    let issues = analyze_viewport(body);
    assert!(issues.contains(&ViewportIssue::MaximumScaleOne));
}

#[test]
fn maximum_scale_two_ok() {
    let body = r#"<meta name="viewport" content="width=device-width, maximum-scale=2.0">"#;
    let issues = analyze_viewport(body);
    assert!(!issues.contains(&ViewportIssue::MaximumScaleOne));
}

#[test]
fn detects_minimal_initial_scale() {
    let body = r#"<meta name="viewport" content="width=device-width, initial-scale=0.1">"#;
    let issues = analyze_viewport(body);
    assert!(issues.contains(&ViewportIssue::MinimalInitialScale));
}

#[test]
fn initial_scale_one_ok() {
    let body = r#"<meta name="viewport" content="width=device-width, initial-scale=1.0">"#;
    let issues = analyze_viewport(body);
    assert!(!issues.contains(&ViewportIssue::MinimalInitialScale));
}

#[test]
fn detects_fixed_width_viewport() {
    let body = r#"<meta name="viewport" content="width=320">"#;
    let issues = analyze_viewport(body);
    assert!(issues.contains(&ViewportIssue::FixedWidthViewport));
}

#[test]
fn device_width_not_fixed() {
    let body = r#"<meta name="viewport" content="width=device-width">"#;
    let issues = analyze_viewport(body);
    assert!(!issues.contains(&ViewportIssue::FixedWidthViewport));
}

#[test]
fn detects_shrink_to_fit_disabled() {
    let body = r#"<meta name="viewport" content="width=device-width, shrink-to-fit=no">"#;
    let issues = analyze_viewport(body);
    assert!(issues.contains(&ViewportIssue::ShrinkToFitDisabled));
}

#[test]
fn severity_zoom_disabled_highest() {
    assert_eq!(viewport_severity(&ViewportIssue::ZoomDisabled), 5.5);
}

#[test]
fn severity_viewport_missing_lowest() {
    assert_eq!(viewport_severity(&ViewportIssue::ViewportMissing), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![ViewportIssue::ZoomDisabled, ViewportIssue::ViewportMissing];
    let mut seq = 0;
    let ops = viewport_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(ViewportIssue::ZoomDisabled.to_string(), "zoom_disabled");
    assert_eq!(
        ViewportIssue::MaximumScaleOne.to_string(),
        "maximum_scale_one"
    );
    assert_eq!(
        ViewportIssue::ViewportMissing.to_string(),
        "viewport_missing"
    );
    assert_eq!(
        ViewportIssue::FixedWidthViewport.to_string(),
        "fixed_width_viewport"
    );
    assert_eq!(
        ViewportIssue::ShrinkToFitDisabled.to_string(),
        "shrink_to_fit_disabled"
    );
}
