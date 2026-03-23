use crate::crlf_injection_audit::*;

#[test]
fn analyze_no_injection() {
    let headers = vec![
        ("content-type".to_string(), "text/html".to_string()),
        ("x-request-id".to_string(), "abc".to_string()),
    ];
    let result = analyze_crlf_response(&headers, "<html></html>", "url");
    assert!(result.is_none());
}

#[test]
fn analyze_header_injection_detected() {
    let headers = vec![
        ("content-type".to_string(), "text/html".to_string()),
        ("x-aegis-crlf-test".to_string(), "canary123".to_string()),
    ];
    let result = analyze_crlf_response(&headers, "", "redirect");
    assert_eq!(
        result,
        Some(CrlfIssue::HeaderInjection {
            parameter: "redirect".to_string()
        })
    );
}

#[test]
fn analyze_response_splitting_detected() {
    let headers = vec![("content-type".to_string(), "text/html".to_string())];
    let body = "HTTP/1.1 200 OK\r\nX-Aegis-Crlf-Test:canary123\r\n\r\n<html>injected</html>";
    let result = analyze_crlf_response(&headers, body, "path");
    assert_eq!(
        result,
        Some(CrlfIssue::ResponseSplitting {
            parameter: "path".to_string()
        })
    );
}

#[test]
fn analyze_header_injection_takes_priority() {
    let headers = vec![("x-aegis-crlf-test".to_string(), "canary123".to_string())];
    let body = "X-Aegis-Crlf-Test:canary123";
    let result = analyze_crlf_response(&headers, body, "q");
    assert!(matches!(result, Some(CrlfIssue::HeaderInjection { .. })));
}

#[test]
fn severity_response_splitting_higher() {
    assert!(
        crlf_severity(&CrlfIssue::ResponseSplitting {
            parameter: "x".to_string()
        }) > crlf_severity(&CrlfIssue::HeaderInjection {
            parameter: "x".to_string()
        })
    );
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = crlf_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_created_for_issues() {
    let issues = vec![
        CrlfIssue::HeaderInjection {
            parameter: "url".to_string(),
        },
        CrlfIssue::ResponseSplitting {
            parameter: "redirect".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = crlf_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_header_injection() {
    let issue = CrlfIssue::HeaderInjection {
        parameter: "url".to_string(),
    };
    assert_eq!(issue.to_string(), "crlf_header_injection:url");
}

#[test]
fn display_response_splitting() {
    let issue = CrlfIssue::ResponseSplitting {
        parameter: "redirect".to_string(),
    };
    assert_eq!(issue.to_string(), "crlf_response_splitting:redirect");
}

#[test]
fn audit_crlf_skips_localhost() {
    let issues = audit_crlf("http://localhost:8080");
    assert!(issues.is_empty());
}

#[test]
fn audit_crlf_skips_loopback() {
    let issues = audit_crlf("http://127.0.0.1");
    assert!(issues.is_empty());
}

#[test]
fn analyze_case_insensitive_header_name() {
    let headers = vec![("X-AEGIS-CRLF-TEST".to_string(), "canary123".to_string())];
    let result = analyze_crlf_response(&headers, "", "q");
    assert!(matches!(result, Some(CrlfIssue::HeaderInjection { .. })));
}
