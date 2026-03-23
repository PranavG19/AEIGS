use crate::api_version_audit::*;

#[test]
fn deprecated_v1_in_path() {
    let issues = analyze_api_versioning("/api/v1/users", &[]);
    assert!(issues
        .iter()
        .any(|i| matches!(i, ApiVersionIssue::DeprecatedVersionInPath { version } if version == "v1")));
}

#[test]
fn deprecated_v0_in_path() {
    let issues = analyze_api_versioning("/api/v0/health", &[]);
    assert!(issues
        .iter()
        .any(|i| matches!(i, ApiVersionIssue::DeprecatedVersionInPath { version } if version == "v0")));
}

#[test]
fn current_version_not_deprecated() {
    let issues = analyze_api_versioning("/api/v2/users", &[]);
    assert!(!issues
        .iter()
        .any(|i| matches!(i, ApiVersionIssue::DeprecatedVersionInPath { .. })));
}

#[test]
fn unversioned_api_detected() {
    let issues = analyze_api_versioning("/api/users", &[]);
    assert!(issues
        .iter()
        .any(|i| *i == ApiVersionIssue::UnversionedApi));
}

#[test]
fn path_version_without_header() {
    let issues = analyze_api_versioning("/api/v2/users", &[]);
    assert!(issues
        .iter()
        .any(|i| *i == ApiVersionIssue::NoVersionHeader));
}

#[test]
fn header_version_only_no_issues() {
    let headers = vec![("api-version".to_string(), "2".to_string())];
    let issues = analyze_api_versioning("/api/users", &headers);
    assert!(!issues
        .iter()
        .any(|i| *i == ApiVersionIssue::UnversionedApi));
    assert!(!issues
        .iter()
        .any(|i| *i == ApiVersionIssue::NoVersionHeader));
}

#[test]
fn version_mismatch_detected() {
    let headers = vec![("api-version".to_string(), "3".to_string())];
    let issues = analyze_api_versioning("/api/v2/users", &headers);
    assert!(issues
        .iter()
        .any(|i| matches!(i, ApiVersionIssue::VersionMismatch { .. })));
}

#[test]
fn version_match_no_mismatch() {
    let headers = vec![("api-version".to_string(), "2".to_string())];
    let issues = analyze_api_versioning("/api/v2/users", &headers);
    assert!(!issues
        .iter()
        .any(|i| matches!(i, ApiVersionIssue::VersionMismatch { .. })));
}

#[test]
fn multiple_version_headers() {
    let headers = vec![
        ("api-version".to_string(), "2".to_string()),
        ("x-api-version".to_string(), "2".to_string()),
    ];
    let issues = analyze_api_versioning("/api/v2/users", &headers);
    assert!(issues
        .iter()
        .any(|i| *i == ApiVersionIssue::MultipleVersionSchemes));
}

#[test]
fn severity_ordering() {
    assert!(
        api_version_severity(&ApiVersionIssue::DeprecatedVersionInPath {
            version: "v1".to_string()
        }) > api_version_severity(&ApiVersionIssue::VersionMismatch {
            path_version: "v2".to_string(),
            header_version: "3".to_string()
        })
    );
    assert!(
        api_version_severity(&ApiVersionIssue::VersionMismatch {
            path_version: "v2".to_string(),
            header_version: "3".to_string()
        }) > api_version_severity(&ApiVersionIssue::UnversionedApi)
    );
}

#[test]
fn operations_filter_low_severity() {
    let issues = vec![ApiVersionIssue::NoVersionHeader];
    let mut seq = 0;
    let ops = api_version_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_include_high_severity() {
    let issues = vec![ApiVersionIssue::DeprecatedVersionInPath {
        version: "v1".to_string(),
    }];
    let mut seq = 0;
    let ops = api_version_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn operations_empty_for_no_issues() {
    let mut seq = 0;
    let ops = api_version_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn display_variants() {
    assert_eq!(
        ApiVersionIssue::DeprecatedVersionInPath {
            version: "v1".to_string()
        }
        .to_string(),
        "deprecated_api_version:v1"
    );
    assert_eq!(
        ApiVersionIssue::NoVersionHeader.to_string(),
        "no_api_version_header"
    );
    assert_eq!(
        ApiVersionIssue::VersionMismatch {
            path_version: "v2".to_string(),
            header_version: "3".to_string()
        }
        .to_string(),
        "version_mismatch:v2|3"
    );
    assert_eq!(
        ApiVersionIssue::UnversionedApi.to_string(),
        "unversioned_api"
    );
    assert_eq!(
        ApiVersionIssue::MultipleVersionSchemes.to_string(),
        "multiple_version_schemes"
    );
}

#[test]
fn audit_skips_localhost() {
    let issues = audit_api_versioning("http://localhost:8080");
    assert!(issues.is_empty());
}

#[test]
fn audit_skips_loopback() {
    let issues = audit_api_versioning("http://127.0.0.1");
    assert!(issues.is_empty());
}

#[test]
fn path_version_case_insensitive() {
    let issues = analyze_api_versioning("/api/V1/users", &[]);
    assert!(issues
        .iter()
        .any(|i| matches!(i, ApiVersionIssue::DeprecatedVersionInPath { .. })));
}

#[test]
fn nested_path_version() {
    let issues = analyze_api_versioning("/service/api/v1/resource/123", &[]);
    assert!(issues
        .iter()
        .any(|i| matches!(i, ApiVersionIssue::DeprecatedVersionInPath { version } if version == "v1")));
}
