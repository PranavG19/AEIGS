use crate::topics_api_audit::*;

#[test]
fn no_topics_no_issues() {
    assert!(analyze_topics_api("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_browsing_topics() {
    let body = r#"<script>const topics = await document.browsingTopics();</script>"#;
    let issues = analyze_topics_api(body);
    assert!(issues.contains(&TopicsApiIssue::ApiDetected));
}

#[test]
fn detects_api_header_variant() {
    let body = r#"<script>fetch("/api", {browsingTopics: true});</script>"#;
    let issues = analyze_topics_api(body);
    assert!(issues.contains(&TopicsApiIssue::ApiDetected));
}

#[test]
fn detects_interest_tracking() {
    let body = r#"<script>const t = await document.browsingTopics();</script>"#;
    let issues = analyze_topics_api(body);
    assert!(issues.contains(&TopicsApiIssue::InterestTracking));
}

#[test]
fn detects_cross_site_correlation() {
    let body = r#"<script>
        const t = await document.browsingTopics();
        fetch("/track", {body: JSON.stringify(t)});
    </script>"#;
    let issues = analyze_topics_api(body);
    assert!(issues.contains(&TopicsApiIssue::CrossSiteCorrelation));
}

#[test]
fn no_correlation_without_fetch() {
    let body = r#"<script>const t = await document.browsingTopics();</script>"#;
    let issues = analyze_topics_api(body);
    assert!(!issues.contains(&TopicsApiIssue::CrossSiteCorrelation));
}

#[test]
fn detects_no_permission_policy() {
    let body = r#"<script>const t = await document.browsingTopics();</script>"#;
    let issues = analyze_topics_api(body);
    assert!(issues.contains(&TopicsApiIssue::NoPermissionPolicy));
}

#[test]
fn no_policy_issue_with_header() {
    let body = r#"<meta http-equiv="Permissions-Policy" content="browsing-topics=()">
    <script>const t = await document.browsingTopics();</script>"#;
    let issues = analyze_topics_api(body);
    assert!(!issues.contains(&TopicsApiIssue::NoPermissionPolicy));
}

#[test]
fn detects_third_party_access() {
    let body = r#"<iframe src="https://ads.example.com">
    <script>const t = await document.browsingTopics();</script>"#;
    let issues = analyze_topics_api(body);
    assert!(issues.contains(&TopicsApiIssue::ThirdPartyAccess));
}

#[test]
fn no_third_party_without_iframe() {
    let body = r#"<script>const t = await document.browsingTopics();</script>"#;
    let issues = analyze_topics_api(body);
    assert!(!issues.contains(&TopicsApiIssue::ThirdPartyAccess));
}

#[test]
fn detects_silent_observation() {
    let body = r#"<script>
        fetch("/api", {browsingTopics: true, observe: true});
    </script>"#;
    let issues = analyze_topics_api(body);
    assert!(issues.contains(&TopicsApiIssue::SilentObservation));
}

#[test]
fn no_silent_without_observe() {
    let body = r#"<script>
        fetch("/api", {browsingTopics: true});
    </script>"#;
    let issues = analyze_topics_api(body);
    assert!(!issues.contains(&TopicsApiIssue::SilentObservation));
}

#[test]
fn severity_correlation_highest() {
    assert_eq!(topics_api_severity(&TopicsApiIssue::CrossSiteCorrelation), 7.0);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(topics_api_severity(&TopicsApiIssue::ApiDetected), 2.5);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![TopicsApiIssue::ApiDetected, TopicsApiIssue::InterestTracking];
    let mut seq = 0;
    let ops = topics_api_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(TopicsApiIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(TopicsApiIssue::InterestTracking.to_string(), "interest_tracking");
    assert_eq!(TopicsApiIssue::CrossSiteCorrelation.to_string(), "cross_site_correlation");
    assert_eq!(TopicsApiIssue::NoPermissionPolicy.to_string(), "no_permission_policy");
    assert_eq!(TopicsApiIssue::ThirdPartyAccess.to_string(), "third_party_access");
    assert_eq!(TopicsApiIssue::SilentObservation.to_string(), "silent_observation");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_topics_api("").is_empty());
}
