use crate::open_redirect_param_audit::*;

#[test]
fn redirect_to_external_detected() {
    let issues = analyze_redirect_response("url", 302, Some("https://evil.example.com/phish"));
    assert!(issues.iter().any(
        |i| matches!(i, OpenRedirectIssue::RedirectToExternal { param, .. } if param == "url")
    ));
}

#[test]
fn javascript_scheme_detected() {
    let issues = analyze_redirect_response("redirect", 302, Some("javascript:alert(1)"));
    assert!(issues
        .iter()
        .any(|i| matches!(i, OpenRedirectIssue::JavascriptSchemeRedirect { param } if param == "redirect")));
}

#[test]
fn no_redirect_status_clean() {
    let issues = analyze_redirect_response("url", 200, Some("https://evil.example.com"));
    assert!(issues.is_empty());
}

#[test]
fn no_location_header_clean() {
    let issues = analyze_redirect_response("url", 302, None);
    assert!(issues.is_empty());
}

#[test]
fn relative_redirect_clean() {
    let issues = analyze_redirect_response("next", 302, Some("/dashboard"));
    assert!(issues.is_empty());
}

#[test]
fn redirect_to_same_domain() {
    let issues = analyze_redirect_response("next", 302, Some("https://example.com/dashboard"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, OpenRedirectIssue::RedirectNoValidation { .. }))
    );
}

#[test]
fn protocol_relative_redirect() {
    let issues = analyze_redirect_response("goto", 301, Some("//other.com/path"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, OpenRedirectIssue::RedirectNoValidation { .. }))
    );
}

#[test]
fn status_301_redirect() {
    let issues = analyze_redirect_response("url", 301, Some("https://evil.example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, OpenRedirectIssue::RedirectToExternal { .. }))
    );
}

#[test]
fn status_307_redirect() {
    let issues = analyze_redirect_response("url", 307, Some("https://evil.example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, OpenRedirectIssue::RedirectToExternal { .. }))
    );
}

#[test]
fn status_400_not_redirect() {
    let issues = analyze_redirect_response("url", 400, Some("https://evil.example.com"));
    assert!(issues.is_empty());
}

#[test]
fn severity_ordering() {
    assert!(
        open_redirect_severity(&OpenRedirectIssue::JavascriptSchemeRedirect {
            param: "x".to_string()
        }) > open_redirect_severity(&OpenRedirectIssue::RedirectToExternal {
            param: "x".to_string(),
            destination: "y".to_string()
        })
    );
    assert!(
        open_redirect_severity(&OpenRedirectIssue::RedirectToExternal {
            param: "x".to_string(),
            destination: "y".to_string()
        }) > open_redirect_severity(&OpenRedirectIssue::RedirectNoValidation {
            param: "x".to_string()
        })
    );
}

#[test]
fn operations_generated() {
    let issues = vec![OpenRedirectIssue::RedirectToExternal {
        param: "url".to_string(),
        destination: "https://evil.example.com".to_string(),
    }];
    let mut seq = 0;
    let ops = open_redirect_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn operations_empty_for_no_issues() {
    let mut seq = 0;
    let ops = open_redirect_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn display_variants() {
    assert_eq!(
        OpenRedirectIssue::RedirectToExternal {
            param: "url".to_string(),
            destination: "https://evil.com".to_string()
        }
        .to_string(),
        "open_redirect_external:url->https://evil.com"
    );
    assert_eq!(
        OpenRedirectIssue::RedirectNoValidation {
            param: "next".to_string()
        }
        .to_string(),
        "open_redirect_no_validation:next"
    );
    assert_eq!(
        OpenRedirectIssue::JavascriptSchemeRedirect {
            param: "r".to_string()
        }
        .to_string(),
        "javascript_scheme_redirect:r"
    );
}

#[test]
fn audit_skips_localhost() {
    let issues = audit_open_redirect_params("http://localhost:8080");
    assert!(issues.is_empty());
}

#[test]
fn audit_skips_loopback() {
    let issues = audit_open_redirect_params("http://127.0.0.1");
    assert!(issues.is_empty());
}

#[test]
fn case_insensitive_javascript() {
    let issues = analyze_redirect_response("r", 302, Some("JavaScript:void(0)"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, OpenRedirectIssue::JavascriptSchemeRedirect { .. }))
    );
}
