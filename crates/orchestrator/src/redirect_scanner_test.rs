use crate::redirect_scanner::*;

// --- is_external_redirect ---

#[test]
fn is_external_redirect_https() {
    assert!(is_external_redirect("https://evil.example.com"));
    assert!(is_external_redirect("https://evil.example.com/path"));
}

#[test]
fn is_external_redirect_http() {
    assert!(is_external_redirect("http://evil.example.com"));
}

#[test]
fn is_external_redirect_protocol_relative() {
    assert!(is_external_redirect("//evil.example.com"));
}

#[test]
fn is_external_redirect_internal() {
    assert!(!is_external_redirect("/dashboard"));
    assert!(!is_external_redirect("https://safe.example.com"));
    assert!(!is_external_redirect("/"));
}

#[test]
fn is_external_redirect_empty() {
    assert!(!is_external_redirect(""));
}

// --- Display ---

#[test]
fn display_open_redirect() {
    let issue = RedirectIssue::OpenRedirect {
        param: "url".to_string(),
        location: "https://evil.example.com".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "open_redirect: param=url location=https://evil.example.com"
    );
}

#[test]
fn display_javascript_redirect() {
    let issue = RedirectIssue::JavascriptRedirect {
        param: "next".to_string(),
    };
    assert_eq!(issue.to_string(), "javascript_redirect: param=next");
}

#[test]
fn display_data_uri_redirect() {
    let issue = RedirectIssue::DataUriRedirect {
        param: "redir".to_string(),
    };
    assert_eq!(issue.to_string(), "data_uri_redirect: param=redir");
}

#[test]
fn display_meta_refresh_redirect() {
    let issue = RedirectIssue::MetaRefreshRedirect {
        url: "http://evil.com".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "meta_refresh_redirect: url=http://evil.com"
    );
}

#[test]
fn display_double_encoded_redirect() {
    let issue = RedirectIssue::DoubleEncodedRedirect {
        param: "dest".to_string(),
    };
    assert_eq!(issue.to_string(), "double_encoded_redirect: param=dest");
}

#[test]
fn display_relative_path_bypass() {
    let issue = RedirectIssue::RelativePathBypass {
        param: "go".to_string(),
        location: "/\\evil.com".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "relative_path_bypass: param=go location=/\\evil.com"
    );
}

#[test]
fn display_fragment_redirect() {
    let issue = RedirectIssue::FragmentRedirect {
        param: "link".to_string(),
        location: "/page#https://evil.com".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "fragment_redirect: param=link location=/page#https://evil.com"
    );
}

#[test]
fn display_http_to_https_downgrade() {
    let issue = RedirectIssue::HttpToHttpsDowngrade {
        param: "url".to_string(),
        location: "http://example.com".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "http_to_https_downgrade: param=url location=http://example.com"
    );
}

#[test]
fn display_redirect_chain() {
    let issue = RedirectIssue::RedirectChain {
        param: "next".to_string(),
        hops: 5,
    };
    assert_eq!(issue.to_string(), "redirect_chain: param=next hops=5");
}

#[test]
fn display_header_injection() {
    let issue = RedirectIssue::HeaderInjection {
        param: "return".to_string(),
    };
    assert_eq!(issue.to_string(), "header_injection: param=return");
}

// --- redirect_severity ---

#[test]
fn severity_open_redirect() {
    let issue = RedirectIssue::OpenRedirect {
        param: "x".to_string(),
        location: "y".to_string(),
    };
    assert_eq!(redirect_severity(&issue), 7.0);
}

#[test]
fn severity_javascript_redirect() {
    let issue = RedirectIssue::JavascriptRedirect {
        param: "x".to_string(),
    };
    assert_eq!(redirect_severity(&issue), 8.0);
}

#[test]
fn severity_data_uri_redirect() {
    let issue = RedirectIssue::DataUriRedirect {
        param: "x".to_string(),
    };
    assert_eq!(redirect_severity(&issue), 6.0);
}

#[test]
fn severity_meta_refresh_redirect() {
    let issue = RedirectIssue::MetaRefreshRedirect {
        url: "x".to_string(),
    };
    assert_eq!(redirect_severity(&issue), 4.0);
}

#[test]
fn severity_double_encoded_redirect() {
    let issue = RedirectIssue::DoubleEncodedRedirect {
        param: "x".to_string(),
    };
    assert_eq!(redirect_severity(&issue), 6.5);
}

#[test]
fn severity_relative_path_bypass() {
    let issue = RedirectIssue::RelativePathBypass {
        param: "x".to_string(),
        location: "y".to_string(),
    };
    assert_eq!(redirect_severity(&issue), 5.5);
}

#[test]
fn severity_fragment_redirect() {
    let issue = RedirectIssue::FragmentRedirect {
        param: "x".to_string(),
        location: "y".to_string(),
    };
    assert_eq!(redirect_severity(&issue), 4.0);
}

#[test]
fn severity_http_to_https_downgrade() {
    let issue = RedirectIssue::HttpToHttpsDowngrade {
        param: "x".to_string(),
        location: "y".to_string(),
    };
    assert_eq!(redirect_severity(&issue), 3.5);
}

#[test]
fn severity_redirect_chain() {
    let issue = RedirectIssue::RedirectChain {
        param: "x".to_string(),
        hops: 3,
    };
    assert_eq!(redirect_severity(&issue), 3.0);
}

#[test]
fn severity_header_injection() {
    let issue = RedirectIssue::HeaderInjection {
        param: "x".to_string(),
    };
    assert_eq!(redirect_severity(&issue), 8.5);
}

// --- analyze_redirect_location ---

#[test]
fn analyze_empty_location() {
    let issues = analyze_redirect_location("", "url");
    assert!(issues.is_empty());
}

#[test]
fn analyze_safe_relative_path() {
    let issues = analyze_redirect_location("/dashboard", "url");
    assert!(issues.is_empty());
}

#[test]
fn analyze_safe_same_domain() {
    let issues = analyze_redirect_location("https://safe.example.com/page", "url");
    assert!(issues.is_empty());
}

#[test]
fn analyze_external_redirect_https() {
    let issues = analyze_redirect_location("https://evil.example.com/phish", "next");
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        RedirectIssue::OpenRedirect {
            param: "next".to_string(),
            location: "https://evil.example.com/phish".to_string(),
        }
    );
}

#[test]
fn analyze_external_redirect_protocol_relative() {
    let issues = analyze_redirect_location("//evil.example.com", "redir");
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        RedirectIssue::OpenRedirect {
            param: "redir".to_string(),
            location: "//evil.example.com".to_string(),
        }
    );
}

#[test]
fn analyze_javascript_uri() {
    let issues = analyze_redirect_location("javascript:alert(1)", "url");
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        RedirectIssue::JavascriptRedirect {
            param: "url".to_string(),
        }
    );
}

#[test]
fn analyze_javascript_uri_case_insensitive() {
    let issues = analyze_redirect_location("JaVaScRiPt:alert(1)", "go");
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        RedirectIssue::JavascriptRedirect {
            param: "go".to_string(),
        }
    );
}

#[test]
fn analyze_data_uri() {
    let issues = analyze_redirect_location("data:text/html,<h1>pwned</h1>", "dest");
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        RedirectIssue::DataUriRedirect {
            param: "dest".to_string(),
        }
    );
}

#[test]
fn analyze_data_uri_case_insensitive() {
    let issues = analyze_redirect_location("DATA:text/html,test", "link");
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        RedirectIssue::DataUriRedirect {
            param: "link".to_string(),
        }
    );
}

#[test]
fn analyze_double_encoded_percent_252f() {
    let issues = analyze_redirect_location("/%252fevil.com", "url");
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        RedirectIssue::DoubleEncodedRedirect {
            param: "url".to_string(),
        }
    );
}

#[test]
fn analyze_double_encoded_2f2f() {
    let issues = analyze_redirect_location("/%2f%2fevil.com", "next");
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        RedirectIssue::DoubleEncodedRedirect {
            param: "next".to_string(),
        }
    );
}

#[test]
fn analyze_relative_path_bypass_backslash() {
    let issues = analyze_redirect_location("/\\evil.com", "redirect");
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        RedirectIssue::RelativePathBypass {
            param: "redirect".to_string(),
            location: "/\\evil.com".to_string(),
        }
    );
}

#[test]
fn analyze_relative_path_bypass_forward_backslash() {
    let issues = analyze_redirect_location("\\/evil.com", "go");
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        RedirectIssue::RelativePathBypass {
            param: "go".to_string(),
            location: "\\/evil.com".to_string(),
        }
    );
}

#[test]
fn analyze_fragment_redirect_https() {
    let issues = analyze_redirect_location("/page#https://evil.com", "target");
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        RedirectIssue::FragmentRedirect {
            param: "target".to_string(),
            location: "/page#https://evil.com".to_string(),
        }
    );
}

#[test]
fn analyze_fragment_redirect_protocol_relative() {
    let issues = analyze_redirect_location("/page#//evil.com", "out");
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        RedirectIssue::FragmentRedirect {
            param: "out".to_string(),
            location: "/page#//evil.com".to_string(),
        }
    );
}

#[test]
fn analyze_fragment_safe_anchor() {
    let issues = analyze_redirect_location("/page#section", "url");
    assert!(issues.is_empty());
}

#[test]
fn analyze_http_downgrade() {
    let issues = analyze_redirect_location("http://example.com/login", "return");
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0],
        RedirectIssue::HttpToHttpsDowngrade {
            param: "return".to_string(),
            location: "http://example.com/login".to_string(),
        }
    );
}

#[test]
fn analyze_http_evil_produces_two_issues() {
    let issues = analyze_redirect_location("http://evil.example.com/phish", "url");
    assert_eq!(issues.len(), 2);
    assert!(issues.iter().any(|i| matches!(
        i,
        RedirectIssue::HttpToHttpsDowngrade { .. }
    )));
    assert!(issues
        .iter()
        .any(|i| matches!(i, RedirectIssue::OpenRedirect { .. })));
}

#[test]
fn analyze_no_issue_for_https_safe() {
    let issues = analyze_redirect_location("https://safe.example.com", "url");
    assert!(issues.is_empty());
}

// --- redirect_findings_to_operations ---

#[test]
fn to_operations_uses_per_issue_severity() {
    let findings = vec![
        RedirectIssue::OpenRedirect {
            param: "url".to_string(),
            location: "https://evil.example.com".to_string(),
        },
        RedirectIssue::JavascriptRedirect {
            param: "next".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = redirect_findings_to_operations(&findings, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);

    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert_eq!(*severity, 7.0);
        }
        _ => panic!("expected AddFinding"),
    }
    match &ops[1].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert_eq!(*severity, 8.0);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn to_operations_empty() {
    let mut seq = 3;
    let ops = redirect_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 3);
}

#[test]
fn to_operations_sequence_increments() {
    let findings = vec![
        RedirectIssue::HeaderInjection {
            param: "a".to_string(),
        },
        RedirectIssue::DataUriRedirect {
            param: "b".to_string(),
        },
        RedirectIssue::RedirectChain {
            param: "c".to_string(),
            hops: 4,
        },
    ];
    let mut seq = 10;
    let ops = redirect_findings_to_operations(&findings, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 13);
    assert_eq!(ops[0].sequence_number, 11);
    assert_eq!(ops[1].sequence_number, 12);
    assert_eq!(ops[2].sequence_number, 13);
}

#[test]
fn to_operations_vuln_class_is_open_redirect() {
    let findings = vec![RedirectIssue::DoubleEncodedRedirect {
        param: "url".to_string(),
    }];
    let mut seq = 0;
    let ops = redirect_findings_to_operations(&findings, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::OpenRedirect
            );
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn to_operations_confidence_is_half() {
    let findings = vec![RedirectIssue::FragmentRedirect {
        param: "x".to_string(),
        location: "/p#https://evil.com".to_string(),
    }];
    let mut seq = 0;
    let ops = redirect_findings_to_operations(&findings, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { confidence, .. } => {
            assert!((confidence.value() - 0.5).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding"),
    }
}

// --- scan_redirects (localhost/invalid rejection) ---

#[test]
fn scan_redirects_skips_localhost() {
    let findings = scan_redirects("http://localhost:8080");
    assert!(findings.is_empty());
}

#[test]
fn scan_redirects_skips_invalid() {
    let findings = scan_redirects("not-a-url");
    assert!(findings.is_empty());
}

// --- constants ---

#[test]
fn redirect_params_not_empty() {
    assert!(!REDIRECT_PARAMS.is_empty());
    assert!(REDIRECT_PARAMS.contains(&"url"));
    assert!(REDIRECT_PARAMS.contains(&"redirect"));
    assert!(REDIRECT_PARAMS.contains(&"next"));
}

#[test]
fn canary_url_is_https_evil() {
    assert!(CANARY_URL.starts_with("https://evil.example.com"));
}

// --- RedirectIssue equality ---

#[test]
fn redirect_issue_clone_eq() {
    let a = RedirectIssue::OpenRedirect {
        param: "url".to_string(),
        location: "https://evil.example.com".to_string(),
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn redirect_issue_ne_different_variant() {
    let a = RedirectIssue::OpenRedirect {
        param: "url".to_string(),
        location: "https://evil.example.com".to_string(),
    };
    let b = RedirectIssue::JavascriptRedirect {
        param: "url".to_string(),
    };
    assert_ne!(a, b);
}
