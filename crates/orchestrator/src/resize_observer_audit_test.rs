use crate::resize_observer_audit::*;

#[test]
fn no_observer_no_issues() {
    assert!(analyze_resize_observer("<html></html>").is_empty());
}

#[test]
fn detects_observer() {
    let body = r#"<script>new ResizeObserver(cb).observe(el)</script>"#;
    let issues = analyze_resize_observer(body);
    assert!(issues.contains(&ResizeObserverIssue::ObserverDetected));
}

#[test]
fn detects_content_rect() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            const rect = entries[0].contentRect;
            console.log(rect.width, rect.height);
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer(body);
    assert!(issues.contains(&ResizeObserverIssue::ContentRectAccess));
}

#[test]
fn detects_border_box_size() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            const size = entries[0].borderBoxSize[0];
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer(body);
    assert!(issues.contains(&ResizeObserverIssue::BorderBoxSize));
}

#[test]
fn detects_device_pixel_content_box() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            const s = entries[0].devicePixelContentBoxSize;
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer(body);
    assert!(issues.contains(&ResizeObserverIssue::BorderBoxSize));
}

#[test]
fn detects_multiple_targets() {
    let body = r#"<script>
        const ro = new ResizeObserver(cb);
        ro.observe(el1);
        ro.observe(el2);
        ro.observe(el3);
        ro.observe(el4);
    </script>"#;
    let issues = analyze_resize_observer(body);
    assert!(issues.contains(&ResizeObserverIssue::MultipleTargets));
}

#[test]
fn no_multiple_with_few_targets() {
    let body = r#"<script>
        const ro = new ResizeObserver(cb);
        ro.observe(el1);
        ro.observe(el2);
    </script>"#;
    let issues = analyze_resize_observer(body);
    assert!(!issues.contains(&ResizeObserverIssue::MultipleTargets));
}

#[test]
fn detects_data_exfiltration_fetch() {
    let body = r#"<script>
        new ResizeObserver((entries) => {
            fetch("/track", {body: JSON.stringify(entries[0].contentRect)});
        }).observe(el);
    </script>"#;
    let issues = analyze_resize_observer(body);
    assert!(issues.contains(&ResizeObserverIssue::DataExfiltration));
}

#[test]
fn detects_continuous_tracking() {
    let body = r#"<script>
        new ResizeObserver(cb).observe(el);
        requestAnimationFrame(loop);
    </script>"#;
    let issues = analyze_resize_observer(body);
    assert!(issues.contains(&ResizeObserverIssue::ContinuousTracking));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(resize_observer_severity(&ResizeObserverIssue::DataExfiltration), 5.5);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(resize_observer_severity(&ResizeObserverIssue::ObserverDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        ResizeObserverIssue::ObserverDetected,
        ResizeObserverIssue::DataExfiltration,
    ];
    let mut seq = 0;
    let ops = resize_observer_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(ResizeObserverIssue::ObserverDetected.to_string(), "observer_detected");
    assert_eq!(ResizeObserverIssue::ContentRectAccess.to_string(), "content_rect_access");
    assert_eq!(ResizeObserverIssue::BorderBoxSize.to_string(), "border_box_size");
    assert_eq!(ResizeObserverIssue::MultipleTargets.to_string(), "multiple_targets");
    assert_eq!(ResizeObserverIssue::DataExfiltration.to_string(), "data_exfiltration");
    assert_eq!(ResizeObserverIssue::ContinuousTracking.to_string(), "continuous_tracking");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_resize_observer("").is_empty());
}
