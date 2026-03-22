use crate::cache_audit::*;

#[test]
fn audit_cache_headers_skips_localhost() {
    let result = audit_cache_headers("http://localhost:8080");
    assert!(result.is_empty());
}

#[test]
fn audit_cache_headers_skips_loopback() {
    let result = audit_cache_headers("http://127.0.0.1");
    assert!(result.is_empty());
}

#[test]
fn analyze_missing_both_headers() {
    let issues = analyze_cache_headers(None, None);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0].kind,
        CacheIssueKind::MissingCacheControl
    ));
}

#[test]
fn analyze_pragma_present_no_cache_control() {
    let issues = analyze_cache_headers(None, Some("no-cache"));
    assert!(issues.is_empty());
}

#[test]
fn analyze_public_without_revalidation() {
    let issues = analyze_cache_headers(Some("public, max-age=3600"), None);
    let public_issues: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i.kind, CacheIssueKind::PublicWithoutRevalidation))
        .collect();
    assert_eq!(public_issues.len(), 1);
}

#[test]
fn analyze_public_with_must_revalidate_ok() {
    let issues = analyze_cache_headers(Some("public, must-revalidate"), None);
    let public_issues: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i.kind, CacheIssueKind::PublicWithoutRevalidation))
        .collect();
    assert!(public_issues.is_empty());
}

#[test]
fn analyze_no_store_is_clean() {
    let issues = analyze_cache_headers(Some("no-store, no-cache"), None);
    assert!(issues.is_empty());
}

#[test]
fn analyze_private_is_clean() {
    let issues = analyze_cache_headers(Some("private, max-age=0"), None);
    assert!(issues.is_empty());
}

#[test]
fn cache_findings_to_operations_missing() {
    let issues = vec![CacheIssue {
        kind: CacheIssueKind::MissingCacheControl,
        detail: "missing".to_string(),
    }];
    let mut seq = 0;
    let ops = cache_findings_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::MissingSecurityHeader
            );
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn cache_findings_empty_returns_no_ops() {
    let mut seq = 0;
    let ops = cache_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}
