use crate::clickjack_audit::*;

#[test]
fn no_protection_at_all() {
    let issues = analyze_frame_protection(None, None);
    assert!(
        issues
            .iter()
            .any(|i| *i == ClickjackIssue::NoFrameProtection)
    );
}

#[test]
fn xfo_only_flagged() {
    let issues = analyze_frame_protection(Some("DENY"), None);
    assert!(
        issues
            .iter()
            .any(|i| *i == ClickjackIssue::XfoOnlyNoFrameAncestors)
    );
}

#[test]
fn xfo_sameorigin_only_flagged() {
    let issues = analyze_frame_protection(Some("SAMEORIGIN"), None);
    assert!(
        issues
            .iter()
            .any(|i| *i == ClickjackIssue::XfoOnlyNoFrameAncestors)
    );
}

#[test]
fn frame_ancestors_self_ok() {
    let issues = analyze_frame_protection(None, Some("frame-ancestors 'self'"));
    assert!(issues.is_empty());
}

#[test]
fn frame_ancestors_none_detected() {
    let issues = analyze_frame_protection(None, Some("frame-ancestors 'none'"));
    assert!(
        issues
            .iter()
            .any(|i| *i == ClickjackIssue::FrameAncestorsNone)
    );
}

#[test]
fn frame_ancestors_wildcard_detected() {
    let issues = analyze_frame_protection(None, Some("frame-ancestors *"));
    assert!(
        issues
            .iter()
            .any(|i| *i == ClickjackIssue::FrameAncestorsWildcard)
    );
}

#[test]
fn conflicting_deny_with_allow() {
    let issues =
        analyze_frame_protection(Some("DENY"), Some("frame-ancestors https://example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ClickjackIssue::ConflictingPolicies { .. }))
    );
}

#[test]
fn conflicting_sameorigin_with_none() {
    let issues = analyze_frame_protection(Some("SAMEORIGIN"), Some("frame-ancestors 'none'"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ClickjackIssue::ConflictingPolicies { .. }))
    );
}

#[test]
fn consistent_deny_and_none() {
    let issues = analyze_frame_protection(Some("DENY"), Some("frame-ancestors 'none'"));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ClickjackIssue::ConflictingPolicies { .. }))
    );
}

#[test]
fn consistent_sameorigin_and_self() {
    let issues = analyze_frame_protection(Some("SAMEORIGIN"), Some("frame-ancestors 'self'"));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ClickjackIssue::ConflictingPolicies { .. }))
    );
}

#[test]
fn csp_with_multiple_directives() {
    let csp = "default-src 'self'; frame-ancestors 'none'; script-src 'unsafe-inline'";
    let issues = analyze_frame_protection(None, Some(csp));
    assert!(
        issues
            .iter()
            .any(|i| *i == ClickjackIssue::FrameAncestorsNone)
    );
}

#[test]
fn csp_without_frame_ancestors() {
    let csp = "default-src 'self'; script-src 'unsafe-inline'";
    let issues = analyze_frame_protection(None, Some(csp));
    assert!(
        issues
            .iter()
            .any(|i| *i == ClickjackIssue::NoFrameProtection)
    );
}

#[test]
fn severity_no_protection_highest() {
    assert!(
        clickjack_severity(&ClickjackIssue::NoFrameProtection)
            > clickjack_severity(&ClickjackIssue::XfoOnlyNoFrameAncestors)
    );
}

#[test]
fn severity_wildcard_higher_than_conflict() {
    assert!(
        clickjack_severity(&ClickjackIssue::FrameAncestorsWildcard)
            > clickjack_severity(&ClickjackIssue::ConflictingPolicies {
                xfo: "x".to_string(),
                csp_fa: "y".to_string()
            })
    );
}

#[test]
fn operations_filter_low_severity() {
    let issues = vec![ClickjackIssue::FrameAncestorsNone];
    let mut seq = 0;
    let ops = clickjack_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_include_high_severity() {
    let issues = vec![ClickjackIssue::NoFrameProtection];
    let mut seq = 0;
    let ops = clickjack_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = clickjack_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn display_variants() {
    assert_eq!(
        ClickjackIssue::NoFrameProtection.to_string(),
        "no_frame_protection"
    );
    assert_eq!(
        ClickjackIssue::XfoOnlyNoFrameAncestors.to_string(),
        "xfo_only_no_frame_ancestors"
    );
    assert_eq!(
        ClickjackIssue::FrameAncestorsWildcard.to_string(),
        "frame_ancestors_wildcard"
    );
    assert_eq!(
        ClickjackIssue::FrameAncestorsNone.to_string(),
        "frame_ancestors_none"
    );
    assert_eq!(
        ClickjackIssue::ConflictingPolicies {
            xfo: "DENY".to_string(),
            csp_fa: "*".to_string()
        }
        .to_string(),
        "conflicting_policies:DENY|*"
    );
}

#[test]
fn audit_skips_localhost() {
    let issues = audit_clickjacking("http://localhost:8080");
    assert!(issues.is_empty());
}

#[test]
fn audit_skips_loopback() {
    let issues = audit_clickjacking("http://127.0.0.1");
    assert!(issues.is_empty());
}
