use crate::host_header_audit::*;

#[test]
fn analyze_no_reflection() {
    let issues = analyze_host_header_response(
        Some("https://example.com/login"),
        "<html><body>Welcome</body></html>",
        None,
        "",
    );
    assert!(issues.is_empty());
}

#[test]
fn analyze_host_reflected_in_location() {
    let issues = analyze_host_header_response(
        Some("https://evil-canary.example.com/login"),
        "<html></html>",
        None,
        "",
    );
    assert_eq!(issues, vec![HostHeaderIssue::ReflectedInLocation]);
}

#[test]
fn analyze_host_reflected_in_body() {
    let issues = analyze_host_header_response(
        Some("https://safe.example.com/"),
        r#"<html><a href="https://evil-canary.example.com/reset">Reset</a></html>"#,
        None,
        "",
    );
    assert_eq!(issues, vec![HostHeaderIssue::ReflectedInBody]);
}

#[test]
fn analyze_x_forwarded_host_in_location() {
    let issues = analyze_host_header_response(
        None,
        "",
        Some("https://evil-canary.example.com/redirect"),
        "",
    );
    assert_eq!(issues, vec![HostHeaderIssue::XForwardedHostAccepted]);
}

#[test]
fn analyze_x_forwarded_host_in_body() {
    let issues = analyze_host_header_response(
        None,
        "",
        None,
        r#"<base href="https://evil-canary.example.com/">"#,
    );
    assert_eq!(issues, vec![HostHeaderIssue::XForwardedHostAccepted]);
}

#[test]
fn analyze_multiple_issues() {
    let issues = analyze_host_header_response(
        Some("https://evil-canary.example.com/"),
        "Reflected: evil-canary.example.com",
        Some("https://evil-canary.example.com/x"),
        "",
    );
    assert_eq!(issues.len(), 3);
}

#[test]
fn severity_location_highest() {
    assert!(
        host_header_severity(&HostHeaderIssue::ReflectedInLocation)
            > host_header_severity(&HostHeaderIssue::ReflectedInBody)
    );
}

#[test]
fn severity_x_forwarded_medium() {
    let s = host_header_severity(&HostHeaderIssue::XForwardedHostAccepted);
    assert!(s > 6.0);
    assert!(s < 7.0);
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = host_header_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_created_for_issues() {
    let issues = vec![
        HostHeaderIssue::ReflectedInLocation,
        HostHeaderIssue::XForwardedHostAccepted,
    ];
    let mut seq = 0;
    let ops = host_header_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        HostHeaderIssue::ReflectedInBody.to_string(),
        "host_reflected_in_body"
    );
    assert_eq!(
        HostHeaderIssue::ReflectedInLocation.to_string(),
        "host_reflected_in_location"
    );
    assert_eq!(
        HostHeaderIssue::XForwardedHostAccepted.to_string(),
        "x_forwarded_host_accepted"
    );
}

#[test]
fn audit_host_header_skips_localhost() {
    let issues = audit_host_header("http://localhost:8080");
    assert!(issues.is_empty());
}

#[test]
fn audit_host_header_skips_loopback() {
    let issues = audit_host_header("http://127.0.0.1");
    assert!(issues.is_empty());
}

// New HostInjectionIssue Display tests (11 tests)

#[test]
fn host_injection_display_host_reflected_in_body() {
    let issue = HostInjectionIssue::HostReflectedInBody {
        canary: "test.com".to_string(),
    };
    assert_eq!(issue.to_string(), "host_reflected_in_body");
}

#[test]
fn host_injection_display_host_reflected_in_location() {
    let issue = HostInjectionIssue::HostReflectedInLocation {
        canary: "test.com".to_string(),
    };
    assert_eq!(issue.to_string(), "host_reflected_in_location");
}

#[test]
fn host_injection_display_x_forwarded_host_reflected() {
    let issue = HostInjectionIssue::XForwardedHostReflected {
        canary: "test.com".to_string(),
    };
    assert_eq!(issue.to_string(), "x_forwarded_host_reflected");
}

#[test]
fn host_injection_display_x_forwarded_for_accepted() {
    let issue = HostInjectionIssue::XForwardedForAccepted;
    assert_eq!(issue.to_string(), "x_forwarded_for_accepted");
}

#[test]
fn host_injection_display_absolute_url_accepted() {
    let issue = HostInjectionIssue::AbsoluteUrlAccepted;
    assert_eq!(issue.to_string(), "absolute_url_accepted");
}

#[test]
fn host_injection_display_port_injection() {
    let issue = HostInjectionIssue::PortInjection {
        port: "1337".to_string(),
    };
    assert_eq!(issue.to_string(), "port_injection");
}

#[test]
fn host_injection_display_duplicate_host_header() {
    let issue = HostInjectionIssue::DuplicateHostHeader;
    assert_eq!(issue.to_string(), "duplicate_host_header");
}

#[test]
fn host_injection_display_host_header_cache_poisoning() {
    let issue = HostInjectionIssue::HostHeaderCachePoisoning;
    assert_eq!(issue.to_string(), "host_header_cache_poisoning");
}

#[test]
fn host_injection_display_password_reset_poisoning() {
    let issue = HostInjectionIssue::PasswordResetPoisoning;
    assert_eq!(issue.to_string(), "password_reset_poisoning");
}

#[test]
fn host_injection_display_web_cache_poisoning() {
    let issue = HostInjectionIssue::WebCachePoisoning {
        header: "X-Forwarded-Host".to_string(),
    };
    assert_eq!(issue.to_string(), "web_cache_poisoning");
}

#[test]
fn host_injection_display_ssrf_via_host() {
    let issue = HostInjectionIssue::SsrfViaHost {
        canary: "test.com".to_string(),
    };
    assert_eq!(issue.to_string(), "ssrf_via_host");
}

// Severity tests (11 tests)

#[test]
fn host_injection_severity_password_reset_poisoning() {
    let issue = HostInjectionIssue::PasswordResetPoisoning;
    assert_eq!(host_injection_severity(&issue), 9.0);
}

#[test]
fn host_injection_severity_ssrf_via_host() {
    let issue = HostInjectionIssue::SsrfViaHost {
        canary: "test.com".to_string(),
    };
    assert_eq!(host_injection_severity(&issue), 8.5);
}

#[test]
fn host_injection_severity_host_header_cache_poisoning() {
    let issue = HostInjectionIssue::HostHeaderCachePoisoning;
    assert_eq!(host_injection_severity(&issue), 8.0);
}

#[test]
fn host_injection_severity_web_cache_poisoning() {
    let issue = HostInjectionIssue::WebCachePoisoning {
        header: "X-Forwarded-Host".to_string(),
    };
    assert_eq!(host_injection_severity(&issue), 7.5);
}

#[test]
fn host_injection_severity_host_reflected_in_location() {
    let issue = HostInjectionIssue::HostReflectedInLocation {
        canary: "test.com".to_string(),
    };
    assert_eq!(host_injection_severity(&issue), 7.0);
}

#[test]
fn host_injection_severity_x_forwarded_host_reflected() {
    let issue = HostInjectionIssue::XForwardedHostReflected {
        canary: "test.com".to_string(),
    };
    assert_eq!(host_injection_severity(&issue), 6.5);
}

#[test]
fn host_injection_severity_absolute_url_accepted() {
    let issue = HostInjectionIssue::AbsoluteUrlAccepted;
    assert_eq!(host_injection_severity(&issue), 6.0);
}

#[test]
fn host_injection_severity_duplicate_host_header() {
    let issue = HostInjectionIssue::DuplicateHostHeader;
    assert_eq!(host_injection_severity(&issue), 5.5);
}

#[test]
fn host_injection_severity_host_reflected_in_body() {
    let issue = HostInjectionIssue::HostReflectedInBody {
        canary: "test.com".to_string(),
    };
    assert_eq!(host_injection_severity(&issue), 5.0);
}

#[test]
fn host_injection_severity_port_injection() {
    let issue = HostInjectionIssue::PortInjection {
        port: "1337".to_string(),
    };
    assert_eq!(host_injection_severity(&issue), 4.5);
}

#[test]
fn host_injection_severity_x_forwarded_for_accepted() {
    let issue = HostInjectionIssue::XForwardedForAccepted;
    assert_eq!(host_injection_severity(&issue), 4.0);
}

// analyze_host_injection tests (19 tests)

#[test]
fn analyze_host_injection_host_reflected_in_location() {
    let issues = analyze_host_injection(
        200,
        Some("https://evil.com/redirect"),
        "<html></html>",
        None,
        "",
        false,
        None,
        None,
        "evil.com",
    );
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0],
        HostInjectionIssue::HostReflectedInLocation { .. }
    ));
}

#[test]
fn analyze_host_injection_host_not_reflected_no_issue() {
    let issues = analyze_host_injection(
        200,
        Some("https://safe.com/redirect"),
        "<html></html>",
        None,
        "",
        false,
        None,
        None,
        "evil.com",
    );
    assert!(issues.is_empty());
}

#[test]
fn analyze_host_injection_host_reflected_in_body() {
    let issues = analyze_host_injection(
        200,
        None,
        "<html>Visit https://evil.com/reset</html>",
        None,
        "",
        false,
        None,
        None,
        "evil.com",
    );
    assert_eq!(issues.len(), 2);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HostInjectionIssue::HostReflectedInBody { .. }))
    );
}

#[test]
fn analyze_host_injection_xfh_reflected_in_location() {
    let issues = analyze_host_injection(
        200,
        None,
        "",
        Some("https://evil.com/redirect"),
        "",
        false,
        None,
        None,
        "evil.com",
    );
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0],
        HostInjectionIssue::XForwardedHostReflected { .. }
    ));
}

#[test]
fn analyze_host_injection_xfh_reflected_in_body() {
    let issues = analyze_host_injection(
        200,
        None,
        "",
        None,
        "Base: https://evil.com",
        false,
        None,
        None,
        "evil.com",
    );
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0],
        HostInjectionIssue::XForwardedHostReflected { .. }
    ));
}

#[test]
fn analyze_host_injection_xfh_no_duplicate_when_both() {
    let issues = analyze_host_injection(
        200,
        None,
        "",
        Some("https://evil.com/redirect"),
        "Base: https://evil.com",
        false,
        None,
        None,
        "evil.com",
    );
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0],
        HostInjectionIssue::XForwardedHostReflected { .. }
    ));
}

#[test]
fn analyze_host_injection_xff_accepted() {
    let issues = analyze_host_injection(200, None, "", None, "", true, None, None, "evil.com");
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0],
        HostInjectionIssue::XForwardedForAccepted
    ));
}

#[test]
fn analyze_host_injection_xff_not_accepted() {
    let issues = analyze_host_injection(200, None, "", None, "", false, None, None, "evil.com");
    assert!(issues.is_empty());
}

#[test]
fn analyze_host_injection_absolute_url_200_accepted() {
    let issues =
        analyze_host_injection(200, None, "", None, "", false, Some(200), None, "evil.com");
    assert_eq!(issues.len(), 1);
    assert!(matches!(issues[0], HostInjectionIssue::AbsoluteUrlAccepted));
}

#[test]
fn analyze_host_injection_absolute_url_404_not_accepted() {
    let issues =
        analyze_host_injection(200, None, "", None, "", false, Some(404), None, "evil.com");
    assert!(issues.is_empty());
}

#[test]
fn analyze_host_injection_absolute_url_none() {
    let issues = analyze_host_injection(200, None, "", None, "", false, None, None, "evil.com");
    assert!(issues.is_empty());
}

#[test]
fn analyze_host_injection_port_injection_detected() {
    let issues = analyze_host_injection(
        200,
        None,
        "",
        None,
        "",
        false,
        None,
        Some("http://example.com:1337/redirect"),
        "evil.com",
    );
    assert_eq!(issues.len(), 1);
    assert!(matches!(
        issues[0],
        HostInjectionIssue::PortInjection { .. }
    ));
}

#[test]
fn analyze_host_injection_port_injection_no_port_no_issue() {
    let issues = analyze_host_injection(
        200,
        None,
        "",
        None,
        "",
        false,
        None,
        Some("http://example.com/redirect"),
        "evil.com",
    );
    assert!(issues.is_empty());
}

#[test]
fn analyze_host_injection_cache_poisoning_200_with_canary() {
    let issues = analyze_host_injection(
        200,
        None,
        "<html>Welcome to evil.com</html>",
        None,
        "",
        false,
        None,
        None,
        "evil.com",
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HostInjectionIssue::HostHeaderCachePoisoning))
    );
}

#[test]
fn analyze_host_injection_cache_poisoning_404_no_issue() {
    let issues = analyze_host_injection(
        404,
        None,
        "<html>Welcome to evil.com</html>",
        None,
        "",
        false,
        None,
        None,
        "evil.com",
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HostInjectionIssue::HostHeaderCachePoisoning))
    );
}

#[test]
fn analyze_host_injection_password_reset_poisoning_redirect() {
    let issues = analyze_host_injection(
        302,
        Some("https://evil.com/reset"),
        "",
        None,
        "",
        false,
        None,
        None,
        "evil.com",
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HostInjectionIssue::PasswordResetPoisoning))
    );
}

#[test]
fn analyze_host_injection_password_reset_poisoning_200_no_issue() {
    let issues = analyze_host_injection(
        200,
        Some("https://evil.com/reset"),
        "",
        None,
        "",
        false,
        None,
        None,
        "evil.com",
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HostInjectionIssue::PasswordResetPoisoning))
    );
}

#[test]
fn analyze_host_injection_all_clean_no_issues() {
    let issues = analyze_host_injection(
        200,
        Some("https://safe.com/"),
        "<html>Safe content</html>",
        Some("https://safe.com/"),
        "Safe body",
        false,
        Some(404),
        Some("http://safe.com:80/"),
        "evil.com",
    );
    assert!(issues.is_empty());
}

#[test]
fn analyze_host_injection_combined_multiple_issues() {
    let issues = analyze_host_injection(
        302,
        Some("https://evil.com/reset"),
        "<html>Visit evil.com</html>",
        Some("https://evil.com/xfh"),
        "XFH: evil.com",
        true,
        Some(200),
        Some("http://example.com:1337/"),
        "evil.com",
    );
    // Should have: HostReflectedInLocation, HostReflectedInBody, XForwardedHostReflected,
    // XForwardedForAccepted, AbsoluteUrlAccepted, PortInjection, PasswordResetPoisoning
    assert!(issues.len() >= 5);
}

// Operations tests (3 tests)

#[test]
fn host_injection_operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = host_injection_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn host_injection_operations_single_issue() {
    let issues = vec![HostInjectionIssue::PasswordResetPoisoning];
    let mut seq = 10;
    let ops = host_injection_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 11);
}

#[test]
fn host_injection_operations_multiple_issues() {
    let issues = vec![
        HostInjectionIssue::PasswordResetPoisoning,
        HostInjectionIssue::HostHeaderCachePoisoning,
        HostInjectionIssue::XForwardedForAccepted,
    ];
    let mut seq = 0;
    let ops = host_injection_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}
