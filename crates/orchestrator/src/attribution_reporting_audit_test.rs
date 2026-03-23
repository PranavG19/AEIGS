use crate::attribution_reporting_audit::*;

#[test]
fn no_attribution_no_issues() {
    assert!(analyze_attribution_reporting("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_attributionsrc_attribute() {
    let body = r#"<a href="https://shop.example" attributionsrc>Buy now</a>"#;
    let issues = analyze_attribution_reporting(body);
    assert!(issues.contains(&AttributionReportingIssue::ApiDetected));
}

#[test]
fn detects_attribution_reporting_js() {
    let body = r#"<script>
        fetch(url, {attributionReporting: {eventSourceEligible: true}});
    </script>"#;
    let issues = analyze_attribution_reporting(body);
    assert!(issues.contains(&AttributionReportingIssue::ApiDetected));
}

#[test]
fn detects_attribution_reporting_header() {
    let body = r#"Attribution-Reporting-Eligible: event-source, trigger"#;
    let issues = analyze_attribution_reporting(body);
    assert!(issues.contains(&AttributionReportingIssue::ApiDetected));
}

#[test]
fn detects_cross_site_tracking() {
    let body = r#"<a attributionsrc>Link</a>
    <script>
        const config = {
            source_event_id: "12345",
            destination: "https://advertiser.example",
            trigger_data: "7"
        };
    </script>"#;
    let issues = analyze_attribution_reporting(body);
    assert!(issues.contains(&AttributionReportingIssue::CrossSiteTracking));
}

#[test]
fn no_tracking_without_trigger() {
    let body = r#"<a attributionsrc>Link</a>
    <script>const config = { source_event_id: "12345" };</script>"#;
    let issues = analyze_attribution_reporting(body);
    assert!(!issues.contains(&AttributionReportingIssue::CrossSiteTracking));
}

#[test]
fn detects_external_report_url() {
    let body = r#"<img attributionsrc="https://tracker.example.com/pixel" src="ad.png">"#;
    let issues = analyze_attribution_reporting(body);
    assert!(issues.contains(&AttributionReportingIssue::ExternalReportUrl));
}

#[test]
fn no_external_without_url() {
    let body = r#"<a attributionsrc>Link</a>"#;
    let issues = analyze_attribution_reporting(body);
    assert!(!issues.contains(&AttributionReportingIssue::ExternalReportUrl));
}

#[test]
fn detects_event_level_fingerprint() {
    let body = r#"<a attributionsrc>Link</a>
    <script>
        const trigger = {
            event_trigger_data: [{trigger_data: "3", priority: "10"}]
        };
    </script>"#;
    let issues = analyze_attribution_reporting(body);
    assert!(issues.contains(&AttributionReportingIssue::EventLevelFingerprint));
}

#[test]
fn no_fingerprint_without_event_data() {
    let body = r#"<a attributionsrc>Link</a>
    <script>const cfg = { trigger_data: "1" };</script>"#;
    let issues = analyze_attribution_reporting(body);
    assert!(!issues.contains(&AttributionReportingIssue::EventLevelFingerprint));
}

#[test]
fn detects_debug_key_leak() {
    let body = r#"<a attributionsrc>Link</a>
    <script>const src = { debug_key: "user_12345" };</script>"#;
    let issues = analyze_attribution_reporting(body);
    assert!(issues.contains(&AttributionReportingIssue::DebugKeyLeak));
}

#[test]
fn detects_debug_reporting_flag() {
    let body = r#"Attribution-Reporting-Eligible: event-source
    <script>const cfg = { debug_reporting: true };</script>"#;
    let issues = analyze_attribution_reporting(body);
    assert!(issues.contains(&AttributionReportingIssue::DebugKeyLeak));
}

#[test]
fn no_debug_without_flag() {
    let body = r#"<a attributionsrc>Link</a>"#;
    let issues = analyze_attribution_reporting(body);
    assert!(!issues.contains(&AttributionReportingIssue::DebugKeyLeak));
}

#[test]
fn severity_tracking_highest() {
    assert_eq!(
        attribution_reporting_severity(&AttributionReportingIssue::CrossSiteTracking),
        7.0
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(
        attribution_reporting_severity(&AttributionReportingIssue::ApiDetected),
        2.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        AttributionReportingIssue::ApiDetected,
        AttributionReportingIssue::DebugKeyLeak,
    ];
    let mut seq = 0;
    let ops = attribution_reporting_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        AttributionReportingIssue::ApiDetected.to_string(),
        "api_detected"
    );
    assert_eq!(
        AttributionReportingIssue::CrossSiteTracking.to_string(),
        "cross_site_tracking"
    );
    assert_eq!(
        AttributionReportingIssue::ExternalReportUrl.to_string(),
        "external_report_url"
    );
    assert_eq!(
        AttributionReportingIssue::EventLevelFingerprint.to_string(),
        "event_level_fingerprint"
    );
    assert_eq!(
        AttributionReportingIssue::DebugKeyLeak.to_string(),
        "debug_key_leak"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_attribution_reporting("").is_empty());
}
