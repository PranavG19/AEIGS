use crate::perf_observer_audit::*;

#[test]
fn no_perf_api_no_issues() {
    assert!(analyze_perf_observer("<html></html>").is_empty());
}

#[test]
fn detects_observer() {
    let body = r#"<script>new PerformanceObserver(cb).observe({type: "resource"})</script>"#;
    let issues = analyze_perf_observer(body);
    assert!(issues.contains(&PerfObserverIssue::ObserverDetected));
}

#[test]
fn detects_resource_timing() {
    let body = r#"<script>new PerformanceObserver(cb).observe({type: "resource"})</script>"#;
    let issues = analyze_perf_observer(body);
    assert!(issues.contains(&PerfObserverIssue::ResourceTimingObserved));
}

#[test]
fn detects_navigation_timing() {
    let body = r#"<script>new PerformanceObserver(cb).observe({type: "navigation"})</script>"#;
    let issues = analyze_perf_observer(body);
    assert!(issues.contains(&PerfObserverIssue::NavigationTimingObserved));
}

#[test]
fn detects_longtask() {
    let body = r#"<script>new PerformanceObserver(cb).observe({type: "longtask"})</script>"#;
    let issues = analyze_perf_observer(body);
    assert!(issues.contains(&PerfObserverIssue::LongTaskObserved));
}

#[test]
fn detects_buffered_flag() {
    let body = r#"<script>new PerformanceObserver(cb).observe({type: "resource", buffered: true})</script>"#;
    let issues = analyze_perf_observer(body);
    assert!(issues.contains(&PerfObserverIssue::BufferedFlag));
}

#[test]
fn detects_get_entries_by_type() {
    let body = r#"<script>performance.getEntriesByType("resource")</script>"#;
    let issues = analyze_perf_observer(body);
    assert!(issues.contains(&PerfObserverIssue::GetEntriesByType));
}

#[test]
fn detects_get_entries_by_name() {
    let body = r#"<script>performance.getEntriesByName("https://example.com/api")</script>"#;
    let issues = analyze_perf_observer(body);
    assert!(issues.contains(&PerfObserverIssue::GetEntriesByType));
}

#[test]
fn detects_get_entries_bare() {
    let body = r#"<script>performance.getEntries().forEach(e => send(e))</script>"#;
    let issues = analyze_perf_observer(body);
    assert!(issues.contains(&PerfObserverIssue::GetEntriesByType));
}

#[test]
fn detects_excessive_types() {
    let body = r#"<script>
        new PerformanceObserver(cb).observe({
            entryTypes: ["resource", "navigation", "longtask", "paint"]
        });
    </script>"#;
    let issues = analyze_perf_observer(body);
    assert!(issues.contains(&PerfObserverIssue::ExcessiveEntryTypes));
}

#[test]
fn no_excessive_with_few_types() {
    let body = r#"<script>new PerformanceObserver(cb).observe({type: "resource"})</script>"#;
    let issues = analyze_perf_observer(body);
    assert!(!issues.contains(&PerfObserverIssue::ExcessiveEntryTypes));
}

#[test]
fn severity_resource_highest() {
    assert_eq!(
        perf_observer_severity(&PerfObserverIssue::ResourceTimingObserved),
        5.5
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(
        perf_observer_severity(&PerfObserverIssue::ObserverDetected),
        3.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        PerfObserverIssue::ObserverDetected,
        PerfObserverIssue::ResourceTimingObserved,
    ];
    let mut seq = 0;
    let ops = perf_observer_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        PerfObserverIssue::ObserverDetected.to_string(),
        "observer_detected"
    );
    assert_eq!(
        PerfObserverIssue::ResourceTimingObserved.to_string(),
        "resource_timing_observed"
    );
    assert_eq!(
        PerfObserverIssue::NavigationTimingObserved.to_string(),
        "navigation_timing_observed"
    );
    assert_eq!(
        PerfObserverIssue::LongTaskObserved.to_string(),
        "long_task_observed"
    );
    assert_eq!(
        PerfObserverIssue::GetEntriesByType.to_string(),
        "get_entries_by_type"
    );
    assert_eq!(PerfObserverIssue::BufferedFlag.to_string(), "buffered_flag");
    assert_eq!(
        PerfObserverIssue::ExcessiveEntryTypes.to_string(),
        "excessive_entry_types"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_perf_observer("").is_empty());
}

#[test]
fn single_quoted_types_detected() {
    let body = r#"<script>new PerformanceObserver(cb).observe({type: 'resource'})</script>"#;
    let issues = analyze_perf_observer(body);
    assert!(issues.contains(&PerfObserverIssue::ResourceTimingObserved));
}
