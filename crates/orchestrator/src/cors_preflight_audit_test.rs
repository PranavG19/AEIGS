use crate::cors_preflight_audit::*;

#[test]
fn empty_response_no_issues() {
    let issues = analyze_preflight_response("", "", "");
    assert!(issues.is_empty());
}

#[test]
fn wildcard_methods_detected() {
    let issues = analyze_preflight_response("*", "", "");
    assert!(issues.iter().any(|i| *i == CorsPreflightIssue::WildcardMethods));
}

#[test]
fn wildcard_headers_detected() {
    let issues = analyze_preflight_response("GET", "*", "");
    assert!(issues.iter().any(|i| *i == CorsPreflightIssue::WildcardHeaders));
}

#[test]
fn dangerous_put_detected() {
    let issues = analyze_preflight_response("GET, PUT, POST", "", "");
    assert!(issues.iter().any(|i| matches!(
        i,
        CorsPreflightIssue::DangerousMethodAllowed { method } if method == "PUT"
    )));
}

#[test]
fn dangerous_delete_detected() {
    let issues = analyze_preflight_response("DELETE", "", "");
    assert!(issues.iter().any(|i| matches!(
        i,
        CorsPreflightIssue::DangerousMethodAllowed { method } if method == "DELETE"
    )));
}

#[test]
fn dangerous_trace_detected() {
    let issues = analyze_preflight_response("TRACE", "", "");
    assert!(issues.iter().any(|i| matches!(
        i,
        CorsPreflightIssue::DangerousMethodAllowed { method } if method == "TRACE"
    )));
}

#[test]
fn safe_methods_no_issue() {
    let issues = analyze_preflight_response("GET, POST, HEAD", "", "");
    assert!(issues.is_empty());
}

#[test]
fn sensitive_authorization_header() {
    let issues = analyze_preflight_response("", "Authorization, Content-Type", "");
    assert!(issues.iter().any(|i| matches!(
        i,
        CorsPreflightIssue::SensitiveHeaderAllowed { header } if header == "authorization"
    )));
}

#[test]
fn sensitive_cookie_header() {
    let issues = analyze_preflight_response("", "Cookie", "");
    assert!(issues.iter().any(|i| matches!(
        i,
        CorsPreflightIssue::SensitiveHeaderAllowed { header } if header == "cookie"
    )));
}

#[test]
fn safe_headers_no_issue() {
    let issues = analyze_preflight_response("", "Content-Type, Accept", "");
    assert!(issues.is_empty());
}

#[test]
fn excessive_max_age() {
    let issues = analyze_preflight_response("", "", "604800");
    assert!(issues.iter().any(|i| matches!(
        i,
        CorsPreflightIssue::ExcessiveMaxAge { seconds } if *seconds == 604800
    )));
}

#[test]
fn safe_max_age() {
    let issues = analyze_preflight_response("", "", "3600");
    assert!(issues.is_empty());
}

#[test]
fn invalid_max_age_ignored() {
    let issues = analyze_preflight_response("", "", "not-a-number");
    assert!(issues.is_empty());
}

#[test]
fn multiple_issues_combined() {
    let issues = analyze_preflight_response("PUT, DELETE", "Authorization", "604800");
    assert!(issues.len() >= 4);
}

#[test]
fn severity_trace_higher_than_put() {
    assert!(
        preflight_severity(&CorsPreflightIssue::DangerousMethodAllowed {
            method: "TRACE".to_string()
        }) > preflight_severity(&CorsPreflightIssue::DangerousMethodAllowed {
            method: "PUT".to_string()
        })
    );
}

#[test]
fn severity_auth_header_higher_than_apikey() {
    assert!(
        preflight_severity(&CorsPreflightIssue::SensitiveHeaderAllowed {
            header: "authorization".to_string()
        }) > preflight_severity(&CorsPreflightIssue::SensitiveHeaderAllowed {
            header: "x-api-key".to_string()
        })
    );
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = preflight_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_created_for_issues() {
    let issues = vec![
        CorsPreflightIssue::WildcardMethods,
        CorsPreflightIssue::ExcessiveMaxAge { seconds: 999999 },
    ];
    let mut seq = 0;
    let ops = preflight_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        CorsPreflightIssue::DangerousMethodAllowed {
            method: "PUT".to_string()
        }
        .to_string(),
        "dangerous_method_allowed:PUT"
    );
    assert_eq!(
        CorsPreflightIssue::WildcardMethods.to_string(),
        "wildcard_methods"
    );
    assert_eq!(
        CorsPreflightIssue::WildcardHeaders.to_string(),
        "wildcard_headers"
    );
    assert_eq!(
        CorsPreflightIssue::SensitiveHeaderAllowed {
            header: "cookie".to_string()
        }
        .to_string(),
        "sensitive_header_allowed:cookie"
    );
    assert_eq!(
        CorsPreflightIssue::ExcessiveMaxAge { seconds: 100 }.to_string(),
        "excessive_max_age:100"
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
    let issues = analyze_preflight_response("put, delete", "", "");
    assert_eq!(
        issues.len(),
        2,
        "Should detect PUT and DELETE case-insensitively"
    );
}

#[test]
fn case_insensitive_header_match() {
    let issues = analyze_preflight_response("", "AUTHORIZATION", "");
    assert_eq!(issues.len(), 1);
}
