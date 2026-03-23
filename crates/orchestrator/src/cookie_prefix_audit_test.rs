use crate::cookie_prefix_audit::*;

#[test]
fn no_prefix_no_issues() {
    let cookies = vec!["session=abc123; Secure; HttpOnly".to_string()];
    let issues = analyze_cookie_prefixes(&cookies);
    assert!(issues.is_empty());
}

#[test]
fn secure_prefix_with_secure_flag_ok() {
    let cookies = vec!["__Secure-token=abc; Secure; HttpOnly".to_string()];
    let issues = analyze_cookie_prefixes(&cookies);
    assert!(issues.is_empty());
}

#[test]
fn secure_prefix_missing_secure_flag() {
    let cookies = vec!["__Secure-token=abc; HttpOnly".to_string()];
    let issues = analyze_cookie_prefixes(&cookies);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        &issues[0],
        CookiePrefixIssue::SecurePrefixWithoutSecureFlag { name } if name == "__Secure-token"
    ));
}

#[test]
fn host_prefix_correct_usage() {
    let cookies = vec!["__Host-session=abc; Secure; Path=/; HttpOnly".to_string()];
    let issues = analyze_cookie_prefixes(&cookies);
    assert!(issues.is_empty());
}

#[test]
fn host_prefix_missing_secure() {
    let cookies = vec!["__Host-session=abc; Path=/; HttpOnly".to_string()];
    let issues = analyze_cookie_prefixes(&cookies);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CookiePrefixIssue::HostPrefixWithoutSecureFlag { .. }))
    );
}

#[test]
fn host_prefix_has_domain() {
    let cookies =
        vec!["__Host-session=abc; Secure; Path=/; Domain=example.com; HttpOnly".to_string()];
    let issues = analyze_cookie_prefixes(&cookies);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CookiePrefixIssue::HostPrefixWithDomain { .. }))
    );
}

#[test]
fn host_prefix_missing_root_path() {
    let cookies = vec!["__Host-session=abc; Secure; Path=/admin; HttpOnly".to_string()];
    let issues = analyze_cookie_prefixes(&cookies);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CookiePrefixIssue::HostPrefixWithoutRootPath { .. }))
    );
}

#[test]
fn host_prefix_no_path_at_all() {
    let cookies = vec!["__Host-session=abc; Secure; HttpOnly".to_string()];
    let issues = analyze_cookie_prefixes(&cookies);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CookiePrefixIssue::HostPrefixWithoutRootPath { .. }))
    );
}

#[test]
fn host_prefix_multiple_violations() {
    let cookies = vec!["__Host-bad=x; Domain=evil.com".to_string()];
    let issues = analyze_cookie_prefixes(&cookies);
    assert!(issues.len() >= 3);
}

#[test]
fn multiple_cookies_mixed() {
    let cookies = vec![
        "normal=ok; Secure; HttpOnly".to_string(),
        "__Secure-tok=x".to_string(),
        "__Host-sid=y; Secure; Path=/".to_string(),
    ];
    let issues = analyze_cookie_prefixes(&cookies);
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        &issues[0],
        CookiePrefixIssue::SecurePrefixWithoutSecureFlag { .. }
    ));
}

#[test]
fn case_insensitive_prefix() {
    let cookies = vec!["__secure-tok=abc; HttpOnly".to_string()];
    let issues = analyze_cookie_prefixes(&cookies);
    assert_eq!(issues.len(), 1);
}

#[test]
fn empty_cookies_no_issues() {
    let issues = analyze_cookie_prefixes(&[]);
    assert!(issues.is_empty());
}

#[test]
fn severity_host_no_secure_highest() {
    assert!(
        cookie_prefix_severity(&CookiePrefixIssue::HostPrefixWithoutSecureFlag {
            name: "x".to_string()
        }) > cookie_prefix_severity(&CookiePrefixIssue::SecurePrefixWithoutSecureFlag {
            name: "x".to_string()
        })
    );
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = cookie_prefix_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_created_for_issues() {
    let issues = vec![
        CookiePrefixIssue::SecurePrefixWithoutSecureFlag {
            name: "__Secure-x".to_string(),
        },
        CookiePrefixIssue::HostPrefixWithDomain {
            name: "__Host-y".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = cookie_prefix_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        CookiePrefixIssue::SecurePrefixWithoutSecureFlag {
            name: "t".to_string()
        }
        .to_string(),
        "secure_prefix_no_flag:t"
    );
    assert_eq!(
        CookiePrefixIssue::HostPrefixWithoutSecureFlag {
            name: "t".to_string()
        }
        .to_string(),
        "host_prefix_no_secure:t"
    );
    assert_eq!(
        CookiePrefixIssue::HostPrefixWithDomain {
            name: "t".to_string()
        }
        .to_string(),
        "host_prefix_has_domain:t"
    );
    assert_eq!(
        CookiePrefixIssue::HostPrefixWithoutRootPath {
            name: "t".to_string()
        }
        .to_string(),
        "host_prefix_no_root_path:t"
    );
}

#[test]
fn audit_skips_localhost() {
    let issues = audit_cookie_prefixes("http://localhost:8080");
    assert!(issues.is_empty());
}

#[test]
fn audit_skips_loopback() {
    let issues = audit_cookie_prefixes("http://127.0.0.1");
    assert!(issues.is_empty());
}
