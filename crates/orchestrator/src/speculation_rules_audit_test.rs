use crate::speculation_rules_audit::*;

#[test]
fn no_speculation_no_issues() {
    assert!(analyze_speculation_rules("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_speculation_rules_script() {
    let body = r#"<script type="speculationrules">
        {"prefetch": [{"urls": ["/page2"]}]}
    </script>"#;
    let issues = analyze_speculation_rules(body);
    assert!(issues.contains(&SpeculationRulesIssue::ApiDetected));
}

#[test]
fn detects_single_quote_type() {
    let body = r#"<script type='speculationrules'>
        {"prerender": [{"urls": ["/next"]}]}
    </script>"#;
    let issues = analyze_speculation_rules(body);
    assert!(issues.contains(&SpeculationRulesIssue::ApiDetected));
}

#[test]
fn no_detection_without_type() {
    let body = r#"<script>// speculationrules mention in comment</script>"#;
    let issues = analyze_speculation_rules(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_external_prefetch() {
    let body = r#"<script type="speculationrules">
        {"prefetch": [{"urls": ["https://cdn.example.com/page"]}]}
    </script>"#;
    let issues = analyze_speculation_rules(body);
    assert!(issues.contains(&SpeculationRulesIssue::ExternalPrefetch));
}

#[test]
fn no_external_with_local_urls() {
    let body = r#"<script type="speculationrules">
        {"prefetch": [{"urls": ["/page2", "/page3"]}]}
    </script>"#;
    let issues = analyze_speculation_rules(body);
    assert!(!issues.contains(&SpeculationRulesIssue::ExternalPrefetch));
}

#[test]
fn detects_aggressive_prerender() {
    let body = r#"<script type="speculationrules">
        {"prerender": [{"where": {"href_matches": "/*"}, "eagerness": "eager"}]}
    </script>"#;
    let issues = analyze_speculation_rules(body);
    assert!(issues.contains(&SpeculationRulesIssue::AggressivePrerender));
}

#[test]
fn no_aggressive_without_eager() {
    let body = r#"<script type="speculationrules">
        {"prerender": [{"urls": ["/next"], "eagerness": "moderate"}]}
    </script>"#;
    let issues = analyze_speculation_rules(body);
    assert!(!issues.contains(&SpeculationRulesIssue::AggressivePrerender));
}

#[test]
fn detects_tracking_via_prefetch() {
    let body = r#"<script type="speculationrules">
        {"prefetch": [{"urls": ["/page?utm_source=test&tracking=1"]}]}
    </script>"#;
    let issues = analyze_speculation_rules(body);
    assert!(issues.contains(&SpeculationRulesIssue::TrackingViaPrefetch));
}

#[test]
fn detects_tracking_analytics() {
    let body = r#"<script type="speculationrules">
        {"prerender": [{"urls": ["/analytics/collect"]}]}
    </script>"#;
    let issues = analyze_speculation_rules(body);
    assert!(issues.contains(&SpeculationRulesIssue::TrackingViaPrefetch));
}

#[test]
fn no_tracking_with_clean_urls() {
    let body = r#"<script type="speculationrules">
        {"prefetch": [{"urls": ["/page2", "/about"]}]}
    </script>"#;
    let issues = analyze_speculation_rules(body);
    assert!(!issues.contains(&SpeculationRulesIssue::TrackingViaPrefetch));
}

#[test]
fn detects_wildcard_rules() {
    let body = r#"<script type="speculationrules">
        {"prefetch": [{"where": {"href_matches": "*"}}]}
    </script>"#;
    let issues = analyze_speculation_rules(body);
    assert!(issues.contains(&SpeculationRulesIssue::WildcardRules));
}

#[test]
fn no_wildcard_with_specific_rules() {
    let body = r#"<script type="speculationrules">
        {"prefetch": [{"where": {"href_matches": "/products/*"}}]}
    </script>"#;
    let issues = analyze_speculation_rules(body);
    assert!(!issues.contains(&SpeculationRulesIssue::WildcardRules));
}

#[test]
fn severity_external_highest() {
    assert_eq!(
        speculation_rules_severity(&SpeculationRulesIssue::ExternalPrefetch),
        6.5
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(
        speculation_rules_severity(&SpeculationRulesIssue::ApiDetected),
        2.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        SpeculationRulesIssue::ApiDetected,
        SpeculationRulesIssue::WildcardRules,
    ];
    let mut seq = 0;
    let ops = speculation_rules_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(SpeculationRulesIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(SpeculationRulesIssue::ExternalPrefetch.to_string(), "external_prefetch");
    assert_eq!(
        SpeculationRulesIssue::AggressivePrerender.to_string(),
        "aggressive_prerender"
    );
    assert_eq!(
        SpeculationRulesIssue::TrackingViaPrefetch.to_string(),
        "tracking_via_prefetch"
    );
    assert_eq!(SpeculationRulesIssue::WildcardRules.to_string(), "wildcard_rules");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_speculation_rules("").is_empty());
}
