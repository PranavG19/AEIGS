use crate::intersection_observer_audit::*;

#[test]
fn no_observer_no_issues() {
    assert!(analyze_intersection_observer("<html></html>").is_empty());
}

#[test]
fn detects_observer() {
    let body = r#"<script>new IntersectionObserver(cb).observe(el)</script>"#;
    let issues = analyze_intersection_observer(body);
    assert!(issues.contains(&IntersectionObserverIssue::ObserverDetected));
}

#[test]
fn detects_visibility_tracking_fetch() {
    let body = r#"<script>
        new IntersectionObserver((entries) => {
            entries.forEach(e => {
                if (e.isIntersecting) fetch("/track?visible=true");
            });
        }).observe(el);
    </script>"#;
    let issues = analyze_intersection_observer(body);
    assert!(issues.contains(&IntersectionObserverIssue::VisibilityTracking));
}

#[test]
fn detects_visibility_tracking_beacon() {
    let body = r#"<script>
        new IntersectionObserver((entries) => {
            if (entries[0].isIntersecting) navigator.sendBeacon("/view");
        }).observe(el);
    </script>"#;
    let issues = analyze_intersection_observer(body);
    assert!(issues.contains(&IntersectionObserverIssue::VisibilityTracking));
}

#[test]
fn no_tracking_without_fetch() {
    let body = r#"<script>
        new IntersectionObserver((entries) => {
            if (entries[0].isIntersecting) lazyLoad();
        }).observe(el);
    </script>"#;
    let issues = analyze_intersection_observer(body);
    assert!(!issues.contains(&IntersectionObserverIssue::VisibilityTracking));
}

#[test]
fn detects_multiple_thresholds() {
    let body = r#"<script>
        new IntersectionObserver(cb, {
            threshold: [0, 0.1, 0.2, 0.3, 0.4, 0.5]
        });
    </script>"#;
    let issues = analyze_intersection_observer(body);
    assert!(issues.contains(&IntersectionObserverIssue::MultipleThresholds));
}

#[test]
fn no_multiple_with_few_thresholds() {
    let body = r#"<script>
        new IntersectionObserver(cb, {threshold: [0, 1]});
    </script>"#;
    let issues = analyze_intersection_observer(body);
    assert!(!issues.contains(&IntersectionObserverIssue::MultipleThresholds));
}

#[test]
fn detects_cross_origin_target() {
    let body = r#"<script>
        const iframe = document.querySelector("iframe");
        new IntersectionObserver(cb).observe(iframe);
    </script>"#;
    let issues = analyze_intersection_observer(body);
    assert!(issues.contains(&IntersectionObserverIssue::CrossOriginTarget));
}

#[test]
fn detects_scroll_jacking() {
    let body = r#"<script>
        new IntersectionObserver((entries) => {
            el.scrollIntoView({behavior: "smooth"});
        }).observe(el);
    </script>"#;
    let issues = analyze_intersection_observer(body);
    assert!(issues.contains(&IntersectionObserverIssue::ScrollJacking));
}

#[test]
fn detects_ad_visibility() {
    let body = r#"<script>
        const ad = document.querySelector(".ad-banner");
        new IntersectionObserver((entries) => {
            if (entries[0].isIntersecting) trackAdView();
        }).observe(ad);
    </script>"#;
    let issues = analyze_intersection_observer(body);
    assert!(issues.contains(&IntersectionObserverIssue::AdVisibilityCheck));
}

#[test]
fn severity_tracking_highest() {
    assert_eq!(
        intersection_observer_severity(&IntersectionObserverIssue::VisibilityTracking),
        5.5
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(
        intersection_observer_severity(&IntersectionObserverIssue::ObserverDetected),
        3.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        IntersectionObserverIssue::ObserverDetected,
        IntersectionObserverIssue::VisibilityTracking,
    ];
    let mut seq = 0;
    let ops = intersection_observer_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        IntersectionObserverIssue::ObserverDetected.to_string(),
        "observer_detected"
    );
    assert_eq!(
        IntersectionObserverIssue::VisibilityTracking.to_string(),
        "visibility_tracking"
    );
    assert_eq!(
        IntersectionObserverIssue::MultipleThresholds.to_string(),
        "multiple_thresholds"
    );
    assert_eq!(
        IntersectionObserverIssue::CrossOriginTarget.to_string(),
        "cross_origin_target"
    );
    assert_eq!(
        IntersectionObserverIssue::ScrollJacking.to_string(),
        "scroll_jacking"
    );
    assert_eq!(
        IntersectionObserverIssue::AdVisibilityCheck.to_string(),
        "ad_visibility_check"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_intersection_observer("").is_empty());
}
