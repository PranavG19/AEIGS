use crate::cors_preflight_audit::*;

#[test]
fn empty_response_no_issues() {
    let issues = analyze_preflight_response("", "", "", "", "", "");
    assert!(issues.is_empty());
}

#[test]
fn wildcard_origin_with_credentials_detected() {
    let issues = analyze_preflight_response("*", "true", "", "", "", "");
    assert!(
        issues
            .iter()
            .any(|i| *i == CorsPreflightIssue::WildcardOriginWithCredentials)
    );
}

#[test]
fn wildcard_origin_without_credentials_safe() {
    let issues = analyze_preflight_response("*", "false", "", "", "", "");
    assert!(
        !issues
            .iter()
            .any(|i| *i == CorsPreflightIssue::WildcardOriginWithCredentials)
    );
}

#[test]
fn null_origin_allowed_detected() {
    let issues = analyze_preflight_response("null", "", "", "", "", "");
    assert!(
        issues
            .iter()
            .any(|i| *i == CorsPreflightIssue::NullOriginAllowed)
    );
}

#[test]
fn origin_reflection_detected() {
    let issues = analyze_preflight_response("https://evil.example.com", "", "", "", "", "");
    assert!(
        issues
            .iter()
            .any(|i| *i == CorsPreflightIssue::OriginReflection)
    );
}

#[test]
fn wildcard_methods_detected() {
    let issues = analyze_preflight_response("", "", "*", "", "", "");
    assert!(
        issues
            .iter()
            .any(|i| *i == CorsPreflightIssue::WildcardMethods)
    );
}

#[test]
fn wildcard_headers_detected() {
    let issues = analyze_preflight_response("", "", "GET", "*", "", "");
    assert!(
        issues
            .iter()
            .any(|i| *i == CorsPreflightIssue::WildcardHeaders)
    );
}

#[test]
fn dangerous_put_detected() {
    let issues = analyze_preflight_response("", "", "GET, PUT, POST", "", "", "");
    assert!(issues.iter().any(|i| matches!(
        i,
        CorsPreflightIssue::DangerousMethodAllowed { method } if method == "PUT"
    )));
}

#[test]
fn dangerous_delete_detected() {
    let issues = analyze_preflight_response("", "", "DELETE", "", "", "");
    assert!(issues.iter().any(|i| matches!(
        i,
        CorsPreflightIssue::DangerousMethodAllowed { method } if method == "DELETE"
    )));
}

#[test]
fn dangerous_patch_detected() {
    let issues = analyze_preflight_response("", "", "PATCH", "", "", "");
    assert!(issues.iter().any(|i| matches!(
        i,
        CorsPreflightIssue::DangerousMethodAllowed { method } if method == "PATCH"
    )));
}

#[test]
fn dangerous_trace_detected() {
    let issues = analyze_preflight_response("", "", "TRACE", "", "", "");
    assert!(issues.iter().any(|i| matches!(
        i,
        CorsPreflightIssue::DangerousMethodAllowed { method } if method == "TRACE"
    )));
}

#[test]
fn safe_methods_no_issue() {
    let issues = analyze_preflight_response("", "", "GET, POST, HEAD", "", "", "");
    assert!(issues.is_empty());
}

#[test]
fn sensitive_authorization_header_allowed() {
    let issues = analyze_preflight_response("", "", "", "Authorization, Content-Type", "", "");
    assert!(issues.iter().any(|i| matches!(
        i,
        CorsPreflightIssue::SensitiveHeaderAllowed { header } if header == "authorization"
    )));
}

#[test]
fn sensitive_cookie_header_allowed() {
    let issues = analyze_preflight_response("", "", "", "Cookie", "", "");
    assert!(issues.iter().any(|i| matches!(
        i,
        CorsPreflightIssue::SensitiveHeaderAllowed { header } if header == "cookie"
    )));
}

#[test]
fn sensitive_authorization_header_exposed() {
    let issues = analyze_preflight_response("", "", "", "", "Authorization, Content-Type", "");
    assert!(issues.iter().any(|i| matches!(
        i,
        CorsPreflightIssue::SensitiveHeaderExposed { header } if header == "authorization"
    )));
}

#[test]
fn sensitive_set_cookie_header_exposed() {
    let issues = analyze_preflight_response("", "", "", "", "Set-Cookie", "");
    assert!(issues.iter().any(|i| matches!(
        i,
        CorsPreflightIssue::SensitiveHeaderExposed { header } if header == "set-cookie"
    )));
}

#[test]
fn sensitive_csrf_token_exposed() {
    let issues = analyze_preflight_response("", "", "", "", "X-CSRF-Token", "");
    assert!(issues.iter().any(|i| matches!(
        i,
        CorsPreflightIssue::SensitiveHeaderExposed { header } if header == "x-csrf-token"
    )));
}

#[test]
fn safe_headers_no_issue() {
    let issues = analyze_preflight_response("", "", "", "Content-Type, Accept", "", "");
    assert!(issues.is_empty());
}

#[test]
fn excessive_max_age_detected() {
    let issues = analyze_preflight_response("", "", "GET", "", "", "604800");
    assert!(issues.iter().any(|i| matches!(
        i,
        CorsPreflightIssue::ExcessiveMaxAge { seconds } if *seconds == 604800
    )));
}

#[test]
fn safe_max_age_no_issue() {
    let issues = analyze_preflight_response("", "", "GET", "", "", "3600");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CorsPreflightIssue::ExcessiveMaxAge { .. }))
    );
}

#[test]
fn missing_max_age_detected() {
    let issues = analyze_preflight_response("https://example.com", "", "GET, POST", "", "", "");
    assert!(
        issues
            .iter()
            .any(|i| *i == CorsPreflightIssue::MissingMaxAge)
    );
}

#[test]
fn missing_max_age_not_flagged_without_methods() {
    let issues = analyze_preflight_response("", "", "", "", "", "");
    assert!(
        !issues
            .iter()
            .any(|i| *i == CorsPreflightIssue::MissingMaxAge)
    );
}

#[test]
fn invalid_max_age_ignored() {
    let issues = analyze_preflight_response("", "", "", "", "", "not-a-number");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CorsPreflightIssue::ExcessiveMaxAge { .. }))
    );
}

#[test]
fn multiple_issues_combined() {
    let issues = analyze_preflight_response(
        "*",
        "true",
        "PUT, DELETE",
        "Authorization",
        "Set-Cookie",
        "604800",
    );
    assert!(issues.len() >= 6);
}

#[test]
fn severity_wildcard_origin_credentials_highest() {
    assert_eq!(
        cors_preflight_severity(&CorsPreflightIssue::WildcardOriginWithCredentials),
        9.0
    );
}

#[test]
fn severity_origin_reflection_high() {
    assert_eq!(
        cors_preflight_severity(&CorsPreflightIssue::OriginReflection),
        8.0
    );
}

#[test]
fn severity_trace_higher_than_put() {
    assert!(
        cors_preflight_severity(&CorsPreflightIssue::DangerousMethodAllowed {
            method: "TRACE".to_string()
        }) > cors_preflight_severity(&CorsPreflightIssue::DangerousMethodAllowed {
            method: "PUT".to_string()
        })
    );
}

#[test]
fn severity_auth_header_higher_than_apikey() {
    assert!(
        cors_preflight_severity(&CorsPreflightIssue::SensitiveHeaderAllowed {
            header: "authorization".to_string()
        }) > cors_preflight_severity(&CorsPreflightIssue::SensitiveHeaderAllowed {
            header: "x-api-key".to_string()
        })
    );
}

#[test]
fn severity_exposed_headers_high() {
    assert!(
        cors_preflight_severity(&CorsPreflightIssue::SensitiveHeaderExposed {
            header: "authorization".to_string()
        }) >= 7.0
    );
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0u64;
    let ops = cors_preflight_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_created_for_issues() {
    let issues = vec![
        CorsPreflightIssue::WildcardMethods,
        CorsPreflightIssue::ExcessiveMaxAge { seconds: 999999 },
    ];
    let mut seq = 0u64;
    let ops = cors_preflight_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_wildcard_origin_with_credentials() {
    assert_eq!(
        CorsPreflightIssue::WildcardOriginWithCredentials.to_string(),
        "wildcard_origin_with_credentials"
    );
}

#[test]
fn display_null_origin() {
    assert_eq!(
        CorsPreflightIssue::NullOriginAllowed.to_string(),
        "null_origin_allowed"
    );
}

#[test]
fn display_origin_reflection() {
    assert_eq!(
        CorsPreflightIssue::OriginReflection.to_string(),
        "origin_reflection"
    );
}

#[test]
fn display_dangerous_method() {
    assert_eq!(
        CorsPreflightIssue::DangerousMethodAllowed {
            method: "PUT".to_string()
        }
        .to_string(),
        "dangerous_method_allowed:PUT"
    );
}

#[test]
fn display_wildcard_methods() {
    assert_eq!(
        CorsPreflightIssue::WildcardMethods.to_string(),
        "wildcard_methods"
    );
}

#[test]
fn display_wildcard_headers() {
    assert_eq!(
        CorsPreflightIssue::WildcardHeaders.to_string(),
        "wildcard_headers"
    );
}

#[test]
fn display_sensitive_header_allowed() {
    assert_eq!(
        CorsPreflightIssue::SensitiveHeaderAllowed {
            header: "cookie".to_string()
        }
        .to_string(),
        "sensitive_header_allowed:cookie"
    );
}

#[test]
fn display_sensitive_header_exposed() {
    assert_eq!(
        CorsPreflightIssue::SensitiveHeaderExposed {
            header: "set-cookie".to_string()
        }
        .to_string(),
        "sensitive_header_exposed:set-cookie"
    );
}

#[test]
fn display_excessive_max_age() {
    assert_eq!(
        CorsPreflightIssue::ExcessiveMaxAge { seconds: 100 }.to_string(),
        "excessive_max_age:100"
    );
}

#[test]
fn display_missing_max_age() {
    assert_eq!(
        CorsPreflightIssue::MissingMaxAge.to_string(),
        "missing_max_age"
    );
}

#[test]
fn audit_skips_localhost() {
    let issues = audit_cors_preflight("http://localhost:8080");
    assert!(issues.is_empty());
}

#[test]
fn audit_skips_loopback() {
    let issues = audit_cors_preflight("http://127.0.0.1");
    assert!(issues.is_empty());
}

#[test]
fn case_insensitive_method_match() {
    let issues = analyze_preflight_response("", "", "put, delete", "", "", "");
    assert_eq!(
        issues.len(),
        2,
        "Should detect PUT and DELETE case-insensitively"
    );
}

#[test]
fn case_insensitive_header_match() {
    let issues = analyze_preflight_response("", "", "", "AUTHORIZATION", "", "");
    assert_eq!(issues.len(), 1);
}

#[test]
fn case_insensitive_credentials_match() {
    let issues = analyze_preflight_response("*", "TRUE", "", "", "", "");
    assert!(
        issues
            .iter()
            .any(|i| *i == CorsPreflightIssue::WildcardOriginWithCredentials)
    );
}

#[test]
fn case_insensitive_exposed_header_match() {
    let issues = analyze_preflight_response("", "", "", "", "SET-COOKIE", "");
    assert!(issues.iter().any(|i| matches!(
        i,
        CorsPreflightIssue::SensitiveHeaderExposed { header } if header == "set-cookie"
    )));
}
