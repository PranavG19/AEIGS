use crate::cache_poison_audit::*;

#[test]
fn no_issues_when_not_cached() {
    let issues = analyze_cache_headers(false, "", "", false);
    assert!(issues.is_empty());
}

#[test]
fn cached_without_vary() {
    let issues = analyze_cache_headers(true, "", "", false);
    assert!(issues
        .iter()
        .any(|i| *i == CachePoisonIssue::CachedWithoutVary));
}

#[test]
fn vary_missing_origin() {
    let issues = analyze_cache_headers(true, "Accept-Encoding", "", false);
    assert!(issues.iter().any(|i| matches!(
        i,
        CachePoisonIssue::VaryMissingSensitiveHeader { missing } if missing == "origin"
    )));
}

#[test]
fn vary_missing_cookie() {
    let issues = analyze_cache_headers(true, "Origin", "", false);
    assert!(issues.iter().any(|i| matches!(
        i,
        CachePoisonIssue::VaryMissingSensitiveHeader { missing } if missing == "cookie"
    )));
}

#[test]
fn vary_has_all_sensitive() {
    let issues = analyze_cache_headers(true, "Origin, Cookie, Authorization", "", false);
    assert!(!issues
        .iter()
        .any(|i| matches!(i, CachePoisonIssue::VaryMissingSensitiveHeader { .. })));
    assert!(!issues
        .iter()
        .any(|i| *i == CachePoisonIssue::CachedWithoutVary));
}

#[test]
fn public_cache_with_auth() {
    let issues = analyze_cache_headers(true, "Origin", "public, max-age=3600", true);
    assert!(issues
        .iter()
        .any(|i| *i == CachePoisonIssue::CacheControlPublicWithAuth));
}

#[test]
fn public_cache_without_auth_ok() {
    let issues = analyze_cache_headers(true, "Origin", "public, max-age=3600", false);
    assert!(!issues
        .iter()
        .any(|i| *i == CachePoisonIssue::CacheControlPublicWithAuth));
}

#[test]
fn private_cache_with_auth_ok() {
    let issues = analyze_cache_headers(true, "Origin", "private, no-store", true);
    assert!(!issues
        .iter()
        .any(|i| *i == CachePoisonIssue::CacheControlPublicWithAuth));
}

#[test]
fn severity_unkeyed_highest() {
    assert!(
        cache_poison_severity(&CachePoisonIssue::UnkeyedHeaderReflected {
            header: "x".to_string()
        }) > cache_poison_severity(&CachePoisonIssue::CacheControlPublicWithAuth)
    );
}

#[test]
fn severity_public_auth_higher_than_missing_vary() {
    assert!(
        cache_poison_severity(&CachePoisonIssue::CacheControlPublicWithAuth)
            > cache_poison_severity(&CachePoisonIssue::CachedWithoutVary)
    );
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = cache_poison_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_created_for_issues() {
    let issues = vec![
        CachePoisonIssue::CachedWithoutVary,
        CachePoisonIssue::UnkeyedHeaderReflected {
            header: "X-Forwarded-Host".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = cache_poison_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        CachePoisonIssue::CachedWithoutVary.to_string(),
        "cached_without_vary"
    );
    assert_eq!(
        CachePoisonIssue::VaryMissingSensitiveHeader {
            missing: "origin".to_string()
        }
        .to_string(),
        "vary_missing:origin"
    );
    assert_eq!(
        CachePoisonIssue::CacheControlPublicWithAuth.to_string(),
        "cache_public_with_auth"
    );
    assert_eq!(
        CachePoisonIssue::UnkeyedHeaderReflected {
            header: "X-Forwarded-Host".to_string()
        }
        .to_string(),
        "unkeyed_header_reflected:X-Forwarded-Host"
    );
}

#[test]
fn audit_skips_localhost() {
    let issues = audit_cache_poison("http://localhost:8080");
    assert!(issues.is_empty());
}

#[test]
fn audit_skips_loopback() {
    let issues = audit_cache_poison("http://127.0.0.1");
    assert!(issues.is_empty());
}

#[test]
fn vary_case_insensitive() {
    let issues = analyze_cache_headers(true, "ORIGIN, COOKIE, AUTHORIZATION", "", false);
    assert!(!issues
        .iter()
        .any(|i| matches!(i, CachePoisonIssue::VaryMissingSensitiveHeader { .. })));
}

#[test]
fn multiple_issues_combined() {
    let issues = analyze_cache_headers(true, "", "public", true);
    assert!(issues.len() >= 2);
}
