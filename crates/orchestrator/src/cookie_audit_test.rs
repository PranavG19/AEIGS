use crate::cookie_audit::*;

#[test]
fn parse_cookie_missing_all_flags() {
    let cookie = "session=abc123; Path=/";
    let result = parse_cookie_issues(cookie).unwrap();
    assert_eq!(result.name, "session");
    assert_eq!(result.issues.len(), 3);
    assert!(result.issues.contains(&CookieIssue::MissingSecure));
    assert!(result.issues.contains(&CookieIssue::MissingHttpOnly));
    assert!(result.issues.contains(&CookieIssue::MissingSameSite));
}

#[test]
fn parse_cookie_has_secure_missing_others() {
    let cookie = "token=xyz; Secure; Path=/";
    let result = parse_cookie_issues(cookie).unwrap();
    assert_eq!(result.name, "token");
    assert_eq!(result.issues.len(), 2);
    assert!(!result.issues.contains(&CookieIssue::MissingSecure));
    assert!(result.issues.contains(&CookieIssue::MissingHttpOnly));
    assert!(result.issues.contains(&CookieIssue::MissingSameSite));
}

#[test]
fn parse_cookie_has_all_flags() {
    let cookie = "id=val; Secure; HttpOnly; SameSite=Strict; Path=/";
    assert!(parse_cookie_issues(cookie).is_none());
}

#[test]
fn parse_cookie_httponly_only() {
    let cookie = "sess=abc; HttpOnly";
    let result = parse_cookie_issues(cookie).unwrap();
    assert_eq!(result.issues.len(), 2);
    assert!(result.issues.contains(&CookieIssue::MissingSecure));
    assert!(result.issues.contains(&CookieIssue::MissingSameSite));
}

#[test]
fn parse_cookie_samesite_lax() {
    let cookie = "pref=1; SameSite=Lax";
    let result = parse_cookie_issues(cookie).unwrap();
    assert_eq!(result.issues.len(), 2);
    assert!(result.issues.contains(&CookieIssue::MissingSecure));
    assert!(result.issues.contains(&CookieIssue::MissingHttpOnly));
}

#[test]
fn parse_cookie_empty_name() {
    let cookie = "=value; Path=/";
    assert!(parse_cookie_issues(cookie).is_none());
}

#[test]
fn parse_cookie_case_insensitive_flags() {
    let cookie = "id=val; secure; httponly; samesite=strict";
    assert!(parse_cookie_issues(cookie).is_none());
}

#[test]
fn cookie_severity_missing_secure_highest() {
    assert!(
        cookie_severity(&[CookieIssue::MissingSecure])
            > cookie_severity(&[CookieIssue::MissingHttpOnly])
    );
    assert!(
        cookie_severity(&[CookieIssue::MissingHttpOnly])
            > cookie_severity(&[CookieIssue::MissingSameSite])
    );
}

#[test]
fn cookie_severity_multiple_issues_takes_max() {
    let severity = cookie_severity(&[CookieIssue::MissingSameSite, CookieIssue::MissingSecure]);
    assert_eq!(severity, 4.0);
}

#[test]
fn cookie_findings_to_operations_creates_findings() {
    let findings = vec![InsecureCookie {
        name: "session".to_string(),
        issues: vec![CookieIssue::MissingSecure, CookieIssue::MissingHttpOnly],
    }];
    let mut seq = 0;
    let ops = cookie_findings_to_operations(&findings, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            severity,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::SecurityMisconfiguration
            );
            assert_eq!(*severity, 4.0);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn cookie_findings_to_operations_empty() {
    let mut seq = 5;
    let ops = cookie_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn audit_cookies_skips_localhost() {
    let findings = audit_cookies("http://localhost:8080");
    assert!(findings.is_empty());
}

#[test]
fn audit_cookies_skips_invalid() {
    let findings = audit_cookies("not-a-url");
    assert!(findings.is_empty());
}

#[test]
fn cookie_issue_display() {
    assert_eq!(CookieIssue::MissingSecure.to_string(), "missing_secure");
    assert_eq!(CookieIssue::MissingHttpOnly.to_string(), "missing_httponly");
    assert_eq!(CookieIssue::MissingSameSite.to_string(), "missing_samesite");
}
