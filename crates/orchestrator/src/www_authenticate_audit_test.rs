use crate::www_authenticate_audit::{
    WwwAuthIssueKind, analyze_www_authenticate, www_authenticate_to_operations,
};

#[test]
fn no_header_no_issues() {
    let issues = analyze_www_authenticate(&[], true);
    assert!(issues.is_empty());
}

#[test]
fn basic_over_http_high_severity() {
    let vals = vec!["Basic realm=\"Login\"".to_string()];
    let issues = analyze_www_authenticate(&vals, false);
    let basic = issues
        .iter()
        .find(|i| i.kind == WwwAuthIssueKind::BasicAuth)
        .unwrap();
    assert!(basic.severity >= 7.0);
}

#[test]
fn basic_over_https_lower_severity() {
    let vals = vec!["Basic realm=\"Login\"".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    let basic = issues
        .iter()
        .find(|i| i.kind == WwwAuthIssueKind::BasicAuth)
        .unwrap();
    assert!(basic.severity < 7.0);
}

#[test]
fn digest_without_qop_flagged() {
    let vals = vec!["Digest realm=\"test\", nonce=\"abc123\", algorithm=MD5".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == WwwAuthIssueKind::DigestWithoutQop)
    );
}

#[test]
fn digest_with_qop_ok() {
    let vals =
        vec!["Digest realm=\"test\", nonce=\"abc\", qop=\"auth\", algorithm=MD5".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(
        !issues
            .iter()
            .any(|i| i.kind == WwwAuthIssueKind::DigestWithoutQop)
    );
}

#[test]
fn realm_with_admin_leaks_info() {
    let vals = vec!["Basic realm=\"Admin Panel\"".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(issues.iter().any(|i| i.kind == WwwAuthIssueKind::RealmLeak));
}

#[test]
fn realm_with_staging_leaks_info() {
    let vals = vec!["Basic realm=\"staging-api\"".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(issues.iter().any(|i| i.kind == WwwAuthIssueKind::RealmLeak));
}

#[test]
fn generic_realm_ok() {
    let vals = vec!["Basic realm=\"Restricted\"".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(!issues.iter().any(|i| i.kind == WwwAuthIssueKind::RealmLeak));
}

#[test]
fn bearer_no_issues() {
    let vals = vec!["Bearer".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    assert!(issues.is_empty());
}

#[test]
fn multiple_challenges() {
    let vals = vec![
        "Basic realm=\"internal-admin\"".to_string(),
        "Digest realm=\"api\", nonce=\"xyz\"".to_string(),
    ];
    let issues = analyze_www_authenticate(&vals, false);
    assert!(issues.iter().any(|i| i.kind == WwwAuthIssueKind::BasicAuth));
    assert!(
        issues
            .iter()
            .any(|i| i.kind == WwwAuthIssueKind::DigestWithoutQop)
    );
    assert!(issues.iter().any(|i| i.kind == WwwAuthIssueKind::RealmLeak));
}

#[test]
fn operations_empty_on_no_issues() {
    let mut seq = 0;
    let ops = www_authenticate_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_produced_on_issues() {
    let vals = vec!["Basic realm=\"Login\"".to_string()];
    let issues = analyze_www_authenticate(&vals, true);
    let mut seq = 5;
    let ops = www_authenticate_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 6);
}
