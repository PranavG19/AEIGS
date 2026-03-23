use crate::crlf_injection_audit::*;

// --- Display tests ---

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
fn display_encoded_crlf() {
    let issue = CrlfIssue::EncodedCrlf {
        parameter: "q".to_string(),
        encoding: "double-url".to_string(),
    };
    assert_eq!(issue.to_string(), "crlf_encoded:q:double-url");
}

#[test]
fn display_unicode_crlf() {
    let issue = CrlfIssue::UnicodeCrlf {
        parameter: "path".to_string(),
    };
    assert_eq!(issue.to_string(), "crlf_unicode:path");
}

#[test]
fn display_set_cookie_injection() {
    let issue = CrlfIssue::SetCookieInjection {
        parameter: "next".to_string(),
    };
    assert_eq!(issue.to_string(), "crlf_set_cookie_injection:next");
}

#[test]
fn display_location_header_injection() {
    let issue = CrlfIssue::LocationHeaderInjection {
        parameter: "return".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "crlf_location_header_injection:return"
    );
}

#[test]
fn display_content_type_injection() {
    let issue = CrlfIssue::ContentTypeInjection {
        parameter: "url".to_string(),
    };
    assert_eq!(issue.to_string(), "crlf_content_type_injection:url");
}

#[test]
fn display_crlf_in_user_agent() {
    let issue = CrlfIssue::CrlfInUserAgent;
    assert_eq!(issue.to_string(), "crlf_in_user_agent");
}

#[test]
fn display_partial_header_injection() {
    let issue = CrlfIssue::PartialHeaderInjection {
        parameter: "q".to_string(),
    };
    assert_eq!(issue.to_string(), "crlf_partial_header_injection:q");
}

// --- Severity tests ---

#[test]
fn severity_response_splitting_higher_than_header_injection() {
    assert!(
        crlf_severity(&CrlfIssue::ResponseSplitting {
            parameter: "x".to_string()
        }) > crlf_severity(&CrlfIssue::HeaderInjection {
            parameter: "x".to_string()
        })
    );
}

#[test]
fn severity_header_injection() {
    assert!((crlf_severity(&CrlfIssue::HeaderInjection {
        parameter: "a".to_string()
    }) - 7.5)
        .abs()
        < f64::EPSILON);
}

#[test]
fn severity_response_splitting() {
    assert!((crlf_severity(&CrlfIssue::ResponseSplitting {
        parameter: "a".to_string()
    }) - 8.5)
        .abs()
        < f64::EPSILON);
}

#[test]
fn severity_encoded_crlf() {
    assert!((crlf_severity(&CrlfIssue::EncodedCrlf {
        parameter: "a".to_string(),
        encoding: "url".to_string(),
    }) - 7.0)
        .abs()
        < f64::EPSILON);
}

#[test]
fn severity_unicode_crlf() {
    assert!((crlf_severity(&CrlfIssue::UnicodeCrlf {
        parameter: "a".to_string()
    }) - 7.0)
        .abs()
        < f64::EPSILON);
}

#[test]
fn severity_set_cookie_injection() {
    assert!((crlf_severity(&CrlfIssue::SetCookieInjection {
        parameter: "a".to_string()
    }) - 8.0)
        .abs()
        < f64::EPSILON);
}

#[test]
fn severity_location_header_injection() {
    assert!((crlf_severity(&CrlfIssue::LocationHeaderInjection {
        parameter: "a".to_string()
    }) - 7.5)
        .abs()
        < f64::EPSILON);
}

#[test]
fn severity_content_type_injection() {
    assert!((crlf_severity(&CrlfIssue::ContentTypeInjection {
        parameter: "a".to_string()
    }) - 6.5)
        .abs()
        < f64::EPSILON);
}

#[test]
fn severity_crlf_in_user_agent() {
    assert!((crlf_severity(&CrlfIssue::CrlfInUserAgent) - 5.0).abs() < f64::EPSILON);
}

#[test]
fn severity_partial_header_injection() {
    assert!((crlf_severity(&CrlfIssue::PartialHeaderInjection {
        parameter: "a".to_string()
    }) - 4.0)
        .abs()
        < f64::EPSILON);
}

#[test]
fn severity_set_cookie_higher_than_encoded() {
    assert!(
        crlf_severity(&CrlfIssue::SetCookieInjection {
            parameter: "x".to_string()
        }) > crlf_severity(&CrlfIssue::EncodedCrlf {
            parameter: "x".to_string(),
            encoding: "url".to_string(),
        })
    );
}

#[test]
fn severity_partial_is_lowest() {
    let partial = crlf_severity(&CrlfIssue::PartialHeaderInjection {
        parameter: "x".to_string(),
    });
    assert!(
        partial
            < crlf_severity(&CrlfIssue::CrlfInUserAgent)
    );
}

// --- analyze_crlf_response tests ---

#[test]
fn analyze_no_injection() {
    let headers = vec![
        ("content-type".to_string(), "text/html".to_string()),
        ("x-request-id".to_string(), "abc".to_string()),
    ];
    let result = analyze_crlf_response(&headers, "<html></html>", "url");
    assert!(result.is_empty());
}

#[test]
fn analyze_header_injection_detected() {
    let headers = vec![
        ("content-type".to_string(), "text/html".to_string()),
        ("x-aegis-crlf-test".to_string(), "canary123".to_string()),
    ];
    let result = analyze_crlf_response(&headers, "", "redirect");
    assert!(result.contains(&CrlfIssue::HeaderInjection {
        parameter: "redirect".to_string()
    }));
}

#[test]
fn analyze_response_splitting_detected() {
    let headers = vec![("content-type".to_string(), "text/html".to_string())];
    let body = "HTTP/1.1 200 OK\r\nX-Aegis-Crlf-Test:canary123\r\n\r\n<html>injected</html>";
    let result = analyze_crlf_response(&headers, body, "path");
    assert!(result.contains(&CrlfIssue::ResponseSplitting {
        parameter: "path".to_string()
    }));
}

#[test]
fn analyze_header_injection_suppresses_response_splitting() {
    let headers = vec![("x-aegis-crlf-test".to_string(), "canary123".to_string())];
    let body = "X-Aegis-Crlf-Test:canary123";
    let result = analyze_crlf_response(&headers, body, "q");
    assert!(result.iter().any(|i| matches!(i, CrlfIssue::HeaderInjection { .. })));
    assert!(!result.iter().any(|i| matches!(i, CrlfIssue::ResponseSplitting { .. })));
}

#[test]
fn analyze_case_insensitive_header_name() {
    let headers = vec![("X-AEGIS-CRLF-TEST".to_string(), "canary123".to_string())];
    let result = analyze_crlf_response(&headers, "", "q");
    assert!(result.iter().any(|i| matches!(i, CrlfIssue::HeaderInjection { .. })));
}

#[test]
fn analyze_set_cookie_injection() {
    let headers = vec![
        ("content-type".to_string(), "text/html".to_string()),
        ("set-cookie".to_string(), "session=canary123; Path=/".to_string()),
    ];
    let result = analyze_crlf_response(&headers, "", "redirect");
    assert!(result.contains(&CrlfIssue::SetCookieInjection {
        parameter: "redirect".to_string()
    }));
}

#[test]
fn analyze_set_cookie_case_insensitive() {
    let headers = vec![
        ("Set-Cookie".to_string(), "tok=canary123".to_string()),
    ];
    let result = analyze_crlf_response(&headers, "", "next");
    assert!(result.iter().any(|i| matches!(i, CrlfIssue::SetCookieInjection { .. })));
}

#[test]
fn analyze_location_header_injection() {
    let headers = vec![
        ("location".to_string(), "https://evil.com/canary123".to_string()),
    ];
    let result = analyze_crlf_response(&headers, "", "url");
    assert!(result.contains(&CrlfIssue::LocationHeaderInjection {
        parameter: "url".to_string()
    }));
}

#[test]
fn analyze_location_header_no_canary() {
    let headers = vec![
        ("location".to_string(), "https://example.com/home".to_string()),
    ];
    let result = analyze_crlf_response(&headers, "", "url");
    assert!(!result.iter().any(|i| matches!(i, CrlfIssue::LocationHeaderInjection { .. })));
}

#[test]
fn analyze_content_type_injection() {
    let headers = vec![
        ("content-type".to_string(), "text/html; canary123".to_string()),
    ];
    let result = analyze_crlf_response(&headers, "", "path");
    assert!(result.contains(&CrlfIssue::ContentTypeInjection {
        parameter: "path".to_string()
    }));
}

#[test]
fn analyze_content_type_normal_not_flagged() {
    let headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
    ];
    let result = analyze_crlf_response(&headers, "{}", "q");
    assert!(!result.iter().any(|i| matches!(i, CrlfIssue::ContentTypeInjection { .. })));
}

#[test]
fn analyze_partial_header_injection_crlf_in_body() {
    let headers = vec![("content-type".to_string(), "text/html".to_string())];
    let body = "reflected: value\r\ncanary123 in body";
    let result = analyze_crlf_response(&headers, body, "q");
    assert!(result.contains(&CrlfIssue::PartialHeaderInjection {
        parameter: "q".to_string()
    }));
}

#[test]
fn analyze_partial_header_injection_encoded_in_body() {
    let headers = vec![("content-type".to_string(), "text/html".to_string())];
    let body = "value%0d%0acanary123";
    let result = analyze_crlf_response(&headers, body, "next");
    assert!(result.contains(&CrlfIssue::PartialHeaderInjection {
        parameter: "next".to_string()
    }));
}

#[test]
fn analyze_partial_not_triggered_when_header_injection_found() {
    let headers = vec![("x-aegis-crlf-test".to_string(), "canary123".to_string())];
    let body = "some\r\ncanary123 data";
    let result = analyze_crlf_response(&headers, body, "q");
    assert!(!result.iter().any(|i| matches!(i, CrlfIssue::PartialHeaderInjection { .. })));
}

#[test]
fn analyze_multiple_issues_from_one_response() {
    let headers = vec![
        ("x-aegis-crlf-test".to_string(), "canary123".to_string()),
        ("set-cookie".to_string(), "evil=canary123".to_string()),
        ("location".to_string(), "http://evil.com/canary123".to_string()),
    ];
    let result = analyze_crlf_response(&headers, "", "url");
    assert!(result.len() >= 3);
    assert!(result.iter().any(|i| matches!(i, CrlfIssue::HeaderInjection { .. })));
    assert!(result.iter().any(|i| matches!(i, CrlfIssue::SetCookieInjection { .. })));
    assert!(result.iter().any(|i| matches!(i, CrlfIssue::LocationHeaderInjection { .. })));
}

#[test]
fn analyze_empty_headers_and_body() {
    let result = analyze_crlf_response(&[], "", "url");
    assert!(result.is_empty());
}

#[test]
fn analyze_canary_value_partial_match_in_header() {
    let headers = vec![
        ("x-aegis-crlf-test".to_string(), "notcanary".to_string()),
    ];
    let result = analyze_crlf_response(&headers, "", "q");
    assert!(!result.iter().any(|i| matches!(i, CrlfIssue::HeaderInjection { .. })));
}

#[test]
fn analyze_body_crlf_without_canary_not_partial() {
    let headers = vec![("content-type".to_string(), "text/html".to_string())];
    let body = "some\r\nline break but no canary";
    let result = analyze_crlf_response(&headers, body, "q");
    assert!(result.is_empty());
}

// --- to_operations tests ---

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = crlf_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_created_for_each_issue() {
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
fn operations_sequence_increments() {
    let issues = vec![
        CrlfIssue::SetCookieInjection {
            parameter: "a".to_string(),
        },
        CrlfIssue::LocationHeaderInjection {
            parameter: "b".to_string(),
        },
        CrlfIssue::ContentTypeInjection {
            parameter: "c".to_string(),
        },
    ];
    let mut seq = 10;
    let ops = crlf_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 13);
}

#[test]
fn operations_for_all_variant_types() {
    let issues = vec![
        CrlfIssue::HeaderInjection {
            parameter: "a".to_string(),
        },
        CrlfIssue::ResponseSplitting {
            parameter: "b".to_string(),
        },
        CrlfIssue::EncodedCrlf {
            parameter: "c".to_string(),
            encoding: "url".to_string(),
        },
        CrlfIssue::UnicodeCrlf {
            parameter: "d".to_string(),
        },
        CrlfIssue::SetCookieInjection {
            parameter: "e".to_string(),
        },
        CrlfIssue::LocationHeaderInjection {
            parameter: "f".to_string(),
        },
        CrlfIssue::ContentTypeInjection {
            parameter: "g".to_string(),
        },
        CrlfIssue::CrlfInUserAgent,
        CrlfIssue::PartialHeaderInjection {
            parameter: "h".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = crlf_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 9);
    assert_eq!(seq, 9);
}

#[test]
fn operations_single_issue() {
    let issues = vec![CrlfIssue::CrlfInUserAgent];
    let mut seq = 5;
    let ops = crlf_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 6);
}

// --- audit_crlf localhost guard tests ---

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

// --- Clone / PartialEq ---

#[test]
fn clone_preserves_equality() {
    let original = CrlfIssue::EncodedCrlf {
        parameter: "url".to_string(),
        encoding: "double".to_string(),
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn different_parameters_not_equal() {
    let a = CrlfIssue::HeaderInjection {
        parameter: "url".to_string(),
    };
    let b = CrlfIssue::HeaderInjection {
        parameter: "redirect".to_string(),
    };
    assert_ne!(a, b);
}

#[test]
fn different_variants_not_equal() {
    let a = CrlfIssue::HeaderInjection {
        parameter: "url".to_string(),
    };
    let b = CrlfIssue::ResponseSplitting {
        parameter: "url".to_string(),
    };
    assert_ne!(a, b);
}
