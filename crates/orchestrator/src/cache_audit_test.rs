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
fn no_headers_yields_missing_cache_control() {
    let issues = analyze_cache_security(&[]);
    assert_eq!(issues.len(), 1);
    assert!(matches!(issues[0], CacheIssue::MissingCacheControl));
}

#[test]
fn pragma_no_cache_only_suppresses_missing() {
    let issues = analyze_cache_security(&[("pragma", "no-cache")]);
    assert!(issues.is_empty());
}

#[test]
fn public_without_revalidation() {
    let headers = [
        ("cache-control", "public, max-age=3600"),
        ("vary", "Accept-Encoding"),
    ];
    let issues = analyze_cache_security(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CacheIssue::PublicWithoutRevalidation))
    );
}

#[test]
fn public_with_must_revalidate_is_safe() {
    let headers = [
        ("cache-control", "public, must-revalidate"),
        ("vary", "Accept-Encoding"),
    ];
    let issues = analyze_cache_security(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CacheIssue::PublicWithoutRevalidation))
    );
}

#[test]
fn public_with_no_cache_is_safe() {
    let headers = [
        ("cache-control", "public, no-cache"),
        ("vary", "Accept-Encoding"),
    ];
    let issues = analyze_cache_security(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CacheIssue::PublicWithoutRevalidation))
    );
}

#[test]
fn no_store_is_clean() {
    let headers = [
        ("cache-control", "no-store, no-cache"),
        ("pragma", "no-cache"),
        ("vary", "Accept-Encoding"),
    ];
    let issues = analyze_cache_security(&headers);
    assert!(!issues.iter().any(|i| matches!(i, CacheIssue::NoNoStore)));
}

#[test]
fn private_is_clean() {
    let headers = [
        ("cache-control", "private, max-age=0"),
        ("pragma", "no-cache"),
        ("vary", "Accept-Encoding"),
    ];
    let issues = analyze_cache_security(&headers);
    assert!(!issues.iter().any(|i| matches!(i, CacheIssue::NoNoStore)));
}

#[test]
fn long_max_age_detected() {
    let headers = [
        ("cache-control", "public, max-age=63072000"),
        ("vary", "Accept-Encoding"),
    ];
    let issues = analyze_cache_security(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CacheIssue::LongMaxAge { seconds } if *seconds == 63_072_000))
    );
}

#[test]
fn normal_max_age_no_issue() {
    let headers = [
        ("cache-control", "public, max-age=3600"),
        ("vary", "Accept-Encoding"),
    ];
    let issues = analyze_cache_security(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CacheIssue::LongMaxAge { .. }))
    );
}

#[test]
fn stale_while_revalidate_large() {
    let headers = [
        ("cache-control", "public, stale-while-revalidate=604800"),
        ("vary", "Accept-Encoding"),
    ];
    let issues = analyze_cache_security(&headers);
    assert!(
        issues.iter().any(
            |i| matches!(i, CacheIssue::StaleWhileRevalidate { seconds } if *seconds == 604_800)
        )
    );
}

#[test]
fn stale_while_revalidate_small_no_issue() {
    let headers = [
        ("cache-control", "public, stale-while-revalidate=60"),
        ("vary", "Accept-Encoding"),
    ];
    let issues = analyze_cache_security(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CacheIssue::StaleWhileRevalidate { .. }))
    );
}

#[test]
fn vary_missing_detected() {
    let headers = [("cache-control", "public, max-age=300")];
    let issues = analyze_cache_security(&headers);
    assert!(issues.iter().any(|i| matches!(i, CacheIssue::VaryMissing)));
}

#[test]
fn vary_wildcard_detected() {
    let headers = [("cache-control", "public, max-age=300"), ("vary", "*")];
    let issues = analyze_cache_security(&headers);
    assert!(issues.iter().any(|i| matches!(i, CacheIssue::VaryWildcard)));
    assert!(!issues.iter().any(|i| matches!(i, CacheIssue::VaryMissing)));
}

#[test]
fn vary_accept_encoding_is_safe() {
    let headers = [
        ("cache-control", "public, max-age=300"),
        ("vary", "Accept-Encoding"),
    ];
    let issues = analyze_cache_security(&headers);
    assert!(!issues.iter().any(|i| matches!(i, CacheIssue::VaryMissing)));
    assert!(!issues.iter().any(|i| matches!(i, CacheIssue::VaryWildcard)));
}

#[test]
fn weak_etag_detected() {
    let headers = [
        ("cache-control", "no-store"),
        ("etag", "W/\"abc123\""),
        ("pragma", "no-cache"),
        ("vary", "Accept-Encoding"),
    ];
    let issues = analyze_cache_security(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CacheIssue::EtagWeakHash { .. }))
    );
}

#[test]
fn strong_etag_no_issue() {
    let headers = [
        ("cache-control", "no-store"),
        ("etag", "\"abc123\""),
        ("pragma", "no-cache"),
        ("vary", "Accept-Encoding"),
    ];
    let issues = analyze_cache_security(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CacheIssue::EtagWeakHash { .. }))
    );
}

#[test]
fn conflicting_public_private() {
    let headers = [
        ("cache-control", "public, private"),
        ("pragma", "no-cache"),
        ("vary", "Accept-Encoding"),
    ];
    let issues = analyze_cache_security(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CacheIssue::CacheControlConflict { .. }))
    );
}

#[test]
fn conflicting_no_cache_with_max_age() {
    let headers = [
        ("cache-control", "no-cache, max-age=3600"),
        ("pragma", "no-cache"),
        ("vary", "Accept-Encoding"),
    ];
    let issues = analyze_cache_security(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CacheIssue::CacheControlConflict { .. }))
    );
}

#[test]
fn no_conflict_without_contradictions() {
    let headers = [
        ("cache-control", "private, no-cache"),
        ("pragma", "no-cache"),
        ("vary", "Accept-Encoding"),
    ];
    let issues = analyze_cache_security(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CacheIssue::CacheControlConflict { .. }))
    );
}

#[test]
fn set_cookie_with_public_cache() {
    let headers = [
        ("cache-control", "public, max-age=300"),
        ("set-cookie", "session=abc123"),
        ("vary", "Accept-Encoding"),
    ];
    let issues = analyze_cache_security(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CacheIssue::SensitiveHeaderCached))
    );
}

#[test]
fn set_cookie_without_public_no_issue() {
    let headers = [
        ("cache-control", "private, max-age=300"),
        ("set-cookie", "session=abc123"),
        ("pragma", "no-cache"),
        ("vary", "Accept-Encoding"),
    ];
    let issues = analyze_cache_security(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CacheIssue::SensitiveHeaderCached))
    );
}

#[test]
fn no_pragma_no_cache_flagged() {
    let headers = [
        ("cache-control", "public, max-age=300"),
        ("vary", "Accept-Encoding"),
    ];
    let issues = analyze_cache_security(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CacheIssue::NoPragmaNoCache))
    );
}

#[test]
fn pragma_present_suppresses_no_pragma() {
    let headers = [
        ("cache-control", "public, max-age=300"),
        ("pragma", "no-cache"),
        ("vary", "Accept-Encoding"),
    ];
    let issues = analyze_cache_security(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CacheIssue::NoPragmaNoCache))
    );
}

#[test]
fn display_missing_cache_control() {
    assert_eq!(
        CacheIssue::MissingCacheControl.to_string(),
        "missing_cache_control"
    );
}

#[test]
fn display_public_without_revalidation() {
    assert_eq!(
        CacheIssue::PublicWithoutRevalidation.to_string(),
        "public_without_revalidation"
    );
}

#[test]
fn display_long_max_age() {
    let issue = CacheIssue::LongMaxAge { seconds: 99999999 };
    assert_eq!(issue.to_string(), "long_max_age_99999999");
}

#[test]
fn display_stale_while_revalidate() {
    let issue = CacheIssue::StaleWhileRevalidate { seconds: 604800 };
    assert_eq!(issue.to_string(), "stale_while_revalidate_604800");
}

#[test]
fn display_etag_weak_hash() {
    let issue = CacheIssue::EtagWeakHash {
        etag: "W/\"abc\"".to_string(),
    };
    assert_eq!(issue.to_string(), "etag_weak_hash_W/\"abc\"");
}

#[test]
fn display_cache_control_conflict() {
    let issue = CacheIssue::CacheControlConflict {
        directives: "public, private".to_string(),
    };
    assert_eq!(issue.to_string(), "cache_control_conflict_public, private");
}

#[test]
fn display_sensitive_header_cached() {
    assert_eq!(
        CacheIssue::SensitiveHeaderCached.to_string(),
        "sensitive_header_cached"
    );
}

#[test]
fn severity_missing_cache_control() {
    assert!((cache_severity(&CacheIssue::MissingCacheControl) - 3.0).abs() < f64::EPSILON);
}

#[test]
fn severity_public_without_revalidation() {
    assert!((cache_severity(&CacheIssue::PublicWithoutRevalidation) - 4.0).abs() < f64::EPSILON);
}

#[test]
fn severity_sensitive_header_cached() {
    assert!((cache_severity(&CacheIssue::SensitiveHeaderCached) - 5.0).abs() < f64::EPSILON);
}

#[test]
fn severity_vary_wildcard() {
    assert!((cache_severity(&CacheIssue::VaryWildcard) - 2.5).abs() < f64::EPSILON);
}

#[test]
fn to_operations_per_issue() {
    let issues = vec![CacheIssue::PublicWithoutRevalidation, CacheIssue::NoNoStore];
    let mut seq = 0;
    let ops = cache_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn to_operations_empty_returns_no_ops() {
    let mut seq = 0;
    let ops = cache_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn to_operations_missing_uses_missing_header_class() {
    let issues = vec![CacheIssue::MissingCacheControl];
    let mut seq = 0;
    let ops = cache_to_operations(&issues, &mut seq);
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
fn to_operations_misconfig_uses_security_misconfiguration() {
    let issues = vec![CacheIssue::PublicWithoutRevalidation];
    let mut seq = 0;
    let ops = cache_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::SecurityMisconfiguration
            );
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn to_operations_sequence_increments() {
    let issues = vec![
        CacheIssue::VaryMissing,
        CacheIssue::NoPragmaNoCache,
        CacheIssue::NoNoStore,
    ];
    let mut seq = 5;
    let ops = cache_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 8);
    assert_eq!(ops[0].sequence_number, 6);
    assert_eq!(ops[1].sequence_number, 7);
    assert_eq!(ops[2].sequence_number, 8);
}

#[test]
fn case_insensitive_header_names() {
    let headers = [
        ("Cache-Control", "public, max-age=300"),
        ("Vary", "Accept-Encoding"),
    ];
    let issues = analyze_cache_security(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CacheIssue::PublicWithoutRevalidation))
    );
}

#[test]
fn max_age_boundary_at_one_year() {
    let headers = [
        ("cache-control", "public, max-age=31536000"),
        ("vary", "Accept-Encoding"),
    ];
    let issues = analyze_cache_security(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CacheIssue::LongMaxAge { .. }))
    );
}

#[test]
fn max_age_just_over_one_year() {
    let headers = [
        ("cache-control", "public, max-age=31536001"),
        ("vary", "Accept-Encoding"),
    ];
    let issues = analyze_cache_security(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CacheIssue::LongMaxAge { seconds } if *seconds == 31_536_001))
    );
}

#[test]
fn stale_while_revalidate_boundary() {
    let headers = [
        ("cache-control", "public, stale-while-revalidate=86400"),
        ("vary", "Accept-Encoding"),
    ];
    let issues = analyze_cache_security(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CacheIssue::StaleWhileRevalidate { .. }))
    );
}

#[test]
fn fully_secured_headers_minimal_issues() {
    let headers = [
        (
            "cache-control",
            "private, no-store, no-cache, must-revalidate",
        ),
        ("pragma", "no-cache"),
        ("vary", "Accept-Encoding"),
        ("etag", "\"strong-hash\""),
    ];
    let issues = analyze_cache_security(&headers);
    assert!(issues.is_empty());
}
