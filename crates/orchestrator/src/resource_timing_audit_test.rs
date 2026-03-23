use crate::resource_timing_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_resource_timing("", "");
    assert!(issues.is_empty());
}

#[test]
fn no_timing_indicators_no_issues() {
    let body = "<html><body>Hello world</body></html>";
    let issues = analyze_resource_timing(body, "");
    assert!(issues.is_empty());
}

#[test]
fn detects_get_entries_by_type() {
    let body = "performance.getEntriesByType('resource')";
    let issues = analyze_resource_timing(body, "");
    assert!(issues.contains(&ResourceTimingIssue::TimingApiUsed));
}

#[test]
fn detects_get_entries_by_name() {
    let body = "performance.getEntriesByName('/api/data')";
    let issues = analyze_resource_timing(body, "");
    assert!(issues.contains(&ResourceTimingIssue::TimingApiUsed));
}

#[test]
fn detects_transfer_size_leak() {
    let body = "entry.transferSize > 0";
    let issues = analyze_resource_timing(body, "");
    assert!(issues.contains(&ResourceTimingIssue::CrossOriginSizeLeak));
}

#[test]
fn detects_encoded_body_size() {
    let body = "entry.encodedBodySize";
    let issues = analyze_resource_timing(body, "");
    assert!(issues.contains(&ResourceTimingIssue::CrossOriginSizeLeak));
}

#[test]
fn detects_decoded_body_size() {
    let body = "entry.decodedBodySize";
    let issues = analyze_resource_timing(body, "");
    assert!(issues.contains(&ResourceTimingIssue::CrossOriginSizeLeak));
}

#[test]
fn detects_performance_observer() {
    let body = "new PerformanceObserver((list) => {})";
    let issues = analyze_resource_timing(body, "");
    assert!(issues.contains(&ResourceTimingIssue::PerformanceObserverUsed));
}

#[test]
fn detects_performance_now() {
    let body = "var t = performance.now();";
    let issues = analyze_resource_timing(body, "");
    assert!(issues.contains(&ResourceTimingIssue::HighResTimestamp));
}

#[test]
fn detects_time_origin() {
    let body = "performance.timeOrigin";
    let issues = analyze_resource_timing(body, "");
    assert!(issues.contains(&ResourceTimingIssue::HighResTimestamp));
}

#[test]
fn detects_navigation_timing() {
    let body = "performance.timing.navigationStart";
    let issues = analyze_resource_timing(body, "");
    assert!(issues.contains(&ResourceTimingIssue::NavigationTimingLeak));
}

#[test]
fn detects_performance_navigation() {
    let body = "performance.navigation.type";
    let issues = analyze_resource_timing(body, "");
    assert!(issues.contains(&ResourceTimingIssue::NavigationTimingLeak));
}

#[test]
fn missing_tao_when_timing_used() {
    let body = "performance.getEntriesByType('resource')";
    let issues = analyze_resource_timing(body, "");
    assert!(issues.contains(&ResourceTimingIssue::MissingTimingAllowOrigin));
}

#[test]
fn tao_present_no_missing_issue() {
    let body = "performance.getEntriesByType('resource')";
    let issues = analyze_resource_timing(body, "*");
    assert!(!issues.contains(&ResourceTimingIssue::MissingTimingAllowOrigin));
}

#[test]
fn tao_specific_origin_no_missing_issue() {
    let body = "performance.getEntriesByType('resource')";
    let issues = analyze_resource_timing(body, "https://example.com");
    assert!(!issues.contains(&ResourceTimingIssue::MissingTimingAllowOrigin));
}

#[test]
fn severity_cross_origin_size_high() {
    assert_eq!(
        resource_timing_severity(&ResourceTimingIssue::CrossOriginSizeLeak),
        6.0
    );
}

#[test]
fn severity_navigation_timing() {
    assert_eq!(
        resource_timing_severity(&ResourceTimingIssue::NavigationTimingLeak),
        5.5
    );
}

#[test]
fn severity_missing_tao_low() {
    assert_eq!(
        resource_timing_severity(&ResourceTimingIssue::MissingTimingAllowOrigin),
        3.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        ResourceTimingIssue::TimingApiUsed,
        ResourceTimingIssue::CrossOriginSizeLeak,
    ];
    let mut seq = 0;
    let ops = resource_timing_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        ResourceTimingIssue::TimingApiUsed.to_string(),
        "timing_api_used"
    );
    assert_eq!(
        ResourceTimingIssue::CrossOriginSizeLeak.to_string(),
        "cross_origin_size_leak"
    );
    assert_eq!(
        ResourceTimingIssue::PerformanceObserverUsed.to_string(),
        "performance_observer"
    );
    assert_eq!(
        ResourceTimingIssue::HighResTimestamp.to_string(),
        "high_res_timestamp"
    );
    assert_eq!(
        ResourceTimingIssue::NavigationTimingLeak.to_string(),
        "navigation_timing_leak"
    );
    assert_eq!(
        ResourceTimingIssue::MissingTimingAllowOrigin.to_string(),
        "missing_timing_allow_origin"
    );
}

#[test]
fn combined_timing_issues() {
    let body = r#"
        var observer = new PerformanceObserver((list) => {
            list.getEntries().forEach(entry => {
                console.log(entry.transferSize);
            });
        });
        performance.getEntriesByType('resource');
    "#;
    let issues = analyze_resource_timing(body, "");
    assert!(issues.contains(&ResourceTimingIssue::TimingApiUsed));
    assert!(issues.contains(&ResourceTimingIssue::CrossOriginSizeLeak));
    assert!(issues.contains(&ResourceTimingIssue::PerformanceObserverUsed));
}

#[test]
fn response_timing_differential() {
    let body = "var dur = entry.responseStart - entry.requestStart;";
    let issues = analyze_resource_timing(body, "");
    assert!(issues.contains(&ResourceTimingIssue::CrossOriginSizeLeak));
}
