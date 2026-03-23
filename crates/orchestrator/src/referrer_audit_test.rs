use crate::referrer_audit::{ReferrerIssueKind, analyze_referrer_policy, referrer_to_operations};

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
