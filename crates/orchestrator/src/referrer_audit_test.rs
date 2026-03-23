use crate::referrer_audit::{
    ReferrerIssueKind, ReferrerSecurityIssue, analyze_referrer_policy, analyze_referrer_security,
    referrer_security_severity, referrer_security_to_operations, referrer_to_operations,
};

#[test]
fn safe_strict_origin() {
    let issues = analyze_referrer_policy("strict-origin");
    assert!(issues.is_empty());
}

#[test]
fn safe_no_referrer() {
    let issues = analyze_referrer_policy("no-referrer");
    assert!(issues.is_empty());
}

#[test]
fn safe_same_origin() {
    let issues = analyze_referrer_policy("same-origin");
    assert!(issues.is_empty());
}

#[test]
fn safe_strict_origin_when_cross_origin() {
    let issues = analyze_referrer_policy("strict-origin-when-cross-origin");
    assert!(issues.is_empty());
}

#[test]
fn unsafe_url_detected() {
    let issues = analyze_referrer_policy("unsafe-url");
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, ReferrerIssueKind::UnsafePolicy);
    assert_eq!(issues[0].severity, 5.0);
}

#[test]
fn no_referrer_when_downgrade_detected() {
    let issues = analyze_referrer_policy("no-referrer-when-downgrade");
    assert!(
        issues
            .iter()
            .any(|i| i.kind == ReferrerIssueKind::UnsafePolicy)
    );
}

#[test]
fn origin_when_cross_origin_detected() {
    let issues = analyze_referrer_policy("origin-when-cross-origin");
    assert!(
        issues
            .iter()
            .any(|i| i.kind == ReferrerIssueKind::UnsafePolicy)
    );
}

#[test]
fn multiple_policies_flagged() {
    let issues = analyze_referrer_policy("no-referrer, unsafe-url");
    assert!(
        issues
            .iter()
            .any(|i| i.kind == ReferrerIssueKind::MultiplePolicies)
    );
    assert!(
        issues
            .iter()
            .any(|i| i.kind == ReferrerIssueKind::UnsafePolicy)
    );
}

#[test]
fn invalid_policy_flagged() {
    let issues = analyze_referrer_policy("not-a-real-policy");
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, ReferrerIssueKind::InvalidPolicy);
}

#[test]
fn case_insensitive() {
    let issues = analyze_referrer_policy("Strict-Origin");
    assert!(issues.is_empty());
}

#[test]
fn whitespace_trimmed() {
    let issues = analyze_referrer_policy("  strict-origin  ");
    assert!(issues.is_empty());
}

#[test]
fn empty_string_no_issues() {
    let issues = analyze_referrer_policy("");
    assert!(issues.is_empty());
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = referrer_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_for_issues() {
    let issues = analyze_referrer_policy("unsafe-url");
    let mut seq = 0;
    let ops = referrer_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn display_variants() {
    assert!(!format!("{}", ReferrerIssueKind::UnsafePolicy).is_empty());
    assert!(!format!("{}", ReferrerIssueKind::MultiplePolicies).is_empty());
    assert!(!format!("{}", ReferrerIssueKind::InvalidPolicy).is_empty());
}

#[test]
fn security_unsafe_url_policy_detected() {
    let html = "<html><body></body></html>";
    let issues = analyze_referrer_security(Some("unsafe-url"), html);
    assert!(issues.contains(&ReferrerSecurityIssue::UnsafeUrlPolicy));
}

#[test]
fn security_no_referrer_when_downgrade_detected() {
    let html = "<html><body></body></html>";
    let issues = analyze_referrer_security(Some("no-referrer-when-downgrade"), html);
    assert!(issues.contains(&ReferrerSecurityIssue::NoReferrerWhenDowngrade));
}

#[test]
fn security_origin_cross_origin_detected() {
    let html = "<html><body></body></html>";
    let issues = analyze_referrer_security(Some("origin-when-cross-origin"), html);
    assert!(issues.contains(&ReferrerSecurityIssue::OriginCrossOrigin));
}

#[test]
fn security_missing_referrer_policy() {
    let html = "<html><body></body></html>";
    let issues = analyze_referrer_security(None, html);
    assert!(issues.contains(&ReferrerSecurityIssue::MissingReferrerPolicy));
}

#[test]
fn security_conflicting_policies() {
    let html = r#"<html><head><meta name="referrer" content="no-referrer"></head></html>"#;
    let issues = analyze_referrer_security(Some("unsafe-url"), html);
    assert!(issues.contains(&ReferrerSecurityIssue::ConflictingPolicies));
}

#[test]
fn security_referrer_in_meta_tag() {
    let html = r#"<html><head><meta name="referrer" content="no-referrer"></head></html>"#;
    let issues = analyze_referrer_security(Some("no-referrer"), html);
    assert!(issues.contains(&ReferrerSecurityIssue::ReferrerInMetaTag));
}

#[test]
fn security_link_with_noreferrer_selective() {
    let html = r#"<html><body><a href="https://example.com" rel="noreferrer">Link1</a><a href="https://other.com">Link2</a></body></html>"#;
    let issues = analyze_referrer_security(Some("no-referrer-when-downgrade"), html);
    assert!(issues.contains(&ReferrerSecurityIssue::LinkWithNoReferrer));
}

#[test]
fn security_form_without_referrer() {
    let html = r#"<html><body><form action="/submit" method="post"></form></body></html>"#;
    let issues = analyze_referrer_security(Some("no-referrer"), html);
    assert!(issues.contains(&ReferrerSecurityIssue::FormWithoutReferrer));
}

#[test]
fn security_cross_origin_link_leak() {
    let html = r#"<html><body><a href="https://external.com">Link</a></body></html>"#;
    let issues = analyze_referrer_security(Some("unsafe-url"), html);
    assert!(issues.contains(&ReferrerSecurityIssue::CrossOriginLinkLeak));
}

#[test]
fn security_token_in_referrer() {
    let html = r#"<html><body><a href="/page?token=abc123">Link</a></body></html>"#;
    let issues = analyze_referrer_security(Some("unsafe-url"), html);
    assert!(issues.contains(&ReferrerSecurityIssue::TokenInReferrer));
}

#[test]
fn security_severity_unsafe_url_highest() {
    let sev = referrer_security_severity(&ReferrerSecurityIssue::UnsafeUrlPolicy);
    assert_eq!(sev, 5.0);
}

#[test]
fn security_severity_token_in_referrer_highest() {
    let sev = referrer_security_severity(&ReferrerSecurityIssue::TokenInReferrer);
    assert_eq!(sev, 5.0);
}

#[test]
fn security_severity_downgrade_high() {
    let sev = referrer_security_severity(&ReferrerSecurityIssue::NoReferrerWhenDowngrade);
    assert_eq!(sev, 4.0);
}

#[test]
fn security_severity_cross_origin_leak_moderate() {
    let sev = referrer_security_severity(&ReferrerSecurityIssue::CrossOriginLinkLeak);
    assert_eq!(sev, 3.5);
}

#[test]
fn security_severity_origin_cross_origin_moderate() {
    let sev = referrer_security_severity(&ReferrerSecurityIssue::OriginCrossOrigin);
    assert_eq!(sev, 3.0);
}

#[test]
fn security_severity_missing_policy_medium() {
    let sev = referrer_security_severity(&ReferrerSecurityIssue::MissingReferrerPolicy);
    assert_eq!(sev, 2.5);
}

#[test]
fn security_severity_conflicting_medium() {
    let sev = referrer_security_severity(&ReferrerSecurityIssue::ConflictingPolicies);
    assert_eq!(sev, 2.5);
}

#[test]
fn security_severity_form_without_medium() {
    let sev = referrer_security_severity(&ReferrerSecurityIssue::FormWithoutReferrer);
    assert_eq!(sev, 2.5);
}

#[test]
fn security_severity_meta_tag_low() {
    let sev = referrer_security_severity(&ReferrerSecurityIssue::ReferrerInMetaTag);
    assert_eq!(sev, 2.0);
}

#[test]
fn security_severity_link_noreferrer_lowest() {
    let sev = referrer_security_severity(&ReferrerSecurityIssue::LinkWithNoReferrer);
    assert_eq!(sev, 1.5);
}

#[test]
fn security_operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = referrer_security_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn security_operations_produced_for_issues() {
    let issues = vec![ReferrerSecurityIssue::UnsafeUrlPolicy];
    let mut seq = 0;
    let ops = referrer_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn security_operations_max_severity() {
    let issues = vec![
        ReferrerSecurityIssue::LinkWithNoReferrer,
        ReferrerSecurityIssue::TokenInReferrer,
        ReferrerSecurityIssue::MissingReferrerPolicy,
    ];
    let mut seq = 0;
    referrer_security_to_operations(&issues, &mut seq);
    assert_eq!(seq, 1);
}

#[test]
fn security_display_unsafe_url() {
    let msg = format!("{}", ReferrerSecurityIssue::UnsafeUrlPolicy);
    assert!(msg.contains("unsafe-url"));
}

#[test]
fn security_display_downgrade() {
    let msg = format!("{}", ReferrerSecurityIssue::NoReferrerWhenDowngrade);
    assert!(msg.contains("downgrade"));
}

#[test]
fn security_display_origin_cross() {
    let msg = format!("{}", ReferrerSecurityIssue::OriginCrossOrigin);
    assert!(msg.contains("origin-when-cross-origin"));
}

#[test]
fn security_display_missing() {
    let msg = format!("{}", ReferrerSecurityIssue::MissingReferrerPolicy);
    assert!(msg.contains("missing"));
}

#[test]
fn security_display_conflicting() {
    let msg = format!("{}", ReferrerSecurityIssue::ConflictingPolicies);
    assert!(msg.contains("conflict"));
}

#[test]
fn security_display_meta_tag() {
    let msg = format!("{}", ReferrerSecurityIssue::ReferrerInMetaTag);
    assert!(msg.contains("meta tag"));
}

#[test]
fn security_display_link_noreferrer() {
    let msg = format!("{}", ReferrerSecurityIssue::LinkWithNoReferrer);
    assert!(msg.contains("noreferrer"));
}

#[test]
fn security_display_form() {
    let msg = format!("{}", ReferrerSecurityIssue::FormWithoutReferrer);
    assert!(msg.contains("form"));
}

#[test]
fn security_display_cross_origin_leak() {
    let msg = format!("{}", ReferrerSecurityIssue::CrossOriginLinkLeak);
    assert!(msg.contains("external"));
}

#[test]
fn security_display_token() {
    let msg = format!("{}", ReferrerSecurityIssue::TokenInReferrer);
    assert!(msg.contains("token"));
}

#[test]
fn security_safe_policy_no_issues() {
    let html = "<html><body></body></html>";
    let issues = analyze_referrer_security(Some("strict-origin"), html);
    assert!(!issues.contains(&ReferrerSecurityIssue::UnsafeUrlPolicy));
    assert!(!issues.contains(&ReferrerSecurityIssue::NoReferrerWhenDowngrade));
}

#[test]
fn security_meta_policy_extraction() {
    let html = r#"<html><head><meta name="referrer" content="no-referrer"></head></html>"#;
    let issues = analyze_referrer_security(None, html);
    assert!(!issues.contains(&ReferrerSecurityIssue::MissingReferrerPolicy));
}

#[test]
fn security_multiple_forms() {
    let html = r#"<html><body><form></form><form></form></body></html>"#;
    let issues = analyze_referrer_security(Some("no-referrer"), html);
    assert!(issues.contains(&ReferrerSecurityIssue::FormWithoutReferrer));
}

#[test]
fn security_form_with_policy_attribute() {
    let html = r#"<html><body><form referrerpolicy="no-referrer"></form></body></html>"#;
    let issues = analyze_referrer_security(Some("no-referrer"), html);
    assert!(!issues.contains(&ReferrerSecurityIssue::FormWithoutReferrer));
}

#[test]
fn security_token_api_key_pattern() {
    let html = r#"<a href="/api?api_key=secret">API</a>"#;
    let issues = analyze_referrer_security(Some("unsafe-url"), html);
    assert!(issues.contains(&ReferrerSecurityIssue::TokenInReferrer));
}

#[test]
fn security_token_apikey_pattern() {
    let html = r#"<a href="/api?apikey=secret">API</a>"#;
    let issues = analyze_referrer_security(Some("unsafe-url"), html);
    assert!(issues.contains(&ReferrerSecurityIssue::TokenInReferrer));
}

#[test]
fn security_token_key_pattern() {
    let html = r#"<a href="/api?key=secret">API</a>"#;
    let issues = analyze_referrer_security(Some("unsafe-url"), html);
    assert!(issues.contains(&ReferrerSecurityIssue::TokenInReferrer));
}

#[test]
fn security_token_secret_pattern() {
    let html = r#"<a href="/api?secret=abc123">API</a>"#;
    let issues = analyze_referrer_security(Some("unsafe-url"), html);
    assert!(issues.contains(&ReferrerSecurityIssue::TokenInReferrer));
}

#[test]
fn security_token_auth_pattern() {
    let html = r#"<a href="/api?auth=token123">API</a>"#;
    let issues = analyze_referrer_security(Some("unsafe-url"), html);
    assert!(issues.contains(&ReferrerSecurityIssue::TokenInReferrer));
}

#[test]
fn security_no_external_links_no_leak() {
    let html = r#"<html><body><a href="/local">Local</a></body></html>"#;
    let issues = analyze_referrer_security(Some("unsafe-url"), html);
    assert!(!issues.contains(&ReferrerSecurityIssue::CrossOriginLinkLeak));
}

#[test]
fn security_external_link_with_safe_policy_no_leak() {
    let html = r#"<html><body><a href="https://example.com">External</a></body></html>"#;
    let issues = analyze_referrer_security(Some("no-referrer"), html);
    assert!(!issues.contains(&ReferrerSecurityIssue::CrossOriginLinkLeak));
}

#[test]
fn security_external_link_with_noreferrer_no_leak() {
    let html =
        r#"<html><body><a href="https://example.com" rel="noreferrer">External</a></body></html>"#;
    let issues = analyze_referrer_security(Some("unsafe-url"), html);
    assert!(!issues.contains(&ReferrerSecurityIssue::CrossOriginLinkLeak));
}

#[test]
fn security_case_insensitive_policy() {
    let html = "<html><body></body></html>";
    let issues = analyze_referrer_security(Some("UNSAFE-URL"), html);
    assert!(issues.contains(&ReferrerSecurityIssue::UnsafeUrlPolicy));
}

#[test]
fn security_meta_tag_case_insensitive() {
    let html = r#"<html><head><META NAME="referrer" CONTENT="no-referrer"></head></html>"#;
    let issues = analyze_referrer_security(None, html);
    assert!(!issues.contains(&ReferrerSecurityIssue::MissingReferrerPolicy));
}

#[test]
fn security_single_quote_noreferrer() {
    let html =
        r#"<html><body><a href='https://example.com' rel='noreferrer'>Link</a></body></html>"#;
    let issues = analyze_referrer_security(Some("unsafe-url"), html);
    assert!(!issues.contains(&ReferrerSecurityIssue::CrossOriginLinkLeak));
}
