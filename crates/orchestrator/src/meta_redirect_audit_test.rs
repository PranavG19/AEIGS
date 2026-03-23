use super::meta_redirect_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_meta_redirect("");
    assert!(issues.is_empty());
}

#[test]
fn no_redirect_no_issues() {
    let body = "<html><body>Hello</body></html>";
    let issues = analyze_meta_redirect(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_meta_refresh_redirect() {
    let body = r#"<meta http-equiv="refresh" content="0;url=https://example.com">"#;
    let issues = analyze_meta_redirect(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MetaRedirectIssue::MetaRefreshRedirect { .. }))
    );
}

#[test]
fn detects_meta_refresh_short_delay() {
    let body = r#"<meta http-equiv="refresh" content="0;url=https://example.com">"#;
    let issues = analyze_meta_redirect(body);
    assert!(issues.contains(&MetaRedirectIssue::MetaRefreshShortDelay));
}

#[test]
fn long_delay_no_short_delay_issue() {
    let body = r#"<meta http-equiv="refresh" content="30;url=https://example.com">"#;
    let issues = analyze_meta_redirect(body);
    assert!(!issues.contains(&MetaRedirectIssue::MetaRefreshShortDelay));
}

#[test]
fn detects_javascript_redirect_href() {
    let body = "window.location.href = 'https://evil.com';";
    let issues = analyze_meta_redirect(body);
    assert!(issues.contains(&MetaRedirectIssue::JavascriptRedirect));
}

#[test]
fn detects_javascript_redirect_replace() {
    let body = "location.replace('https://evil.com');";
    let issues = analyze_meta_redirect(body);
    assert!(issues.contains(&MetaRedirectIssue::JavascriptRedirect));
}

#[test]
fn detects_location_assign() {
    let body = "location.assign('https://evil.com');";
    let issues = analyze_meta_redirect(body);
    assert!(issues.contains(&MetaRedirectIssue::WindowLocationAssign));
}

#[test]
fn detects_document_write_redirect() {
    let body = r#"document.write('<script>location="url"</script>');"#;
    let issues = analyze_meta_redirect(body);
    assert!(issues.contains(&MetaRedirectIssue::DocumentWriteRedirect));
}

#[test]
fn detects_history_replace_state() {
    let body = r#"
        history.replaceState(null, '', '/new');
        location.reload();
    "#;
    let issues = analyze_meta_redirect(body);
    assert!(issues.contains(&MetaRedirectIssue::HistoryReplaceState));
}

#[test]
fn severity_document_write_highest() {
    assert_eq!(
        meta_redirect_severity(&MetaRedirectIssue::DocumentWriteRedirect),
        6.5
    );
}

#[test]
fn severity_short_delay_lowest() {
    assert_eq!(
        meta_redirect_severity(&MetaRedirectIssue::MetaRefreshShortDelay),
        3.5
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        MetaRedirectIssue::JavascriptRedirect,
        MetaRedirectIssue::MetaRefreshShortDelay,
    ];
    let mut seq = 0;
    let ops = meta_redirect_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        MetaRedirectIssue::MetaRefreshShortDelay.to_string(),
        "meta_refresh_short_delay"
    );
    assert_eq!(
        MetaRedirectIssue::JavascriptRedirect.to_string(),
        "javascript_redirect"
    );
    assert_eq!(
        MetaRedirectIssue::WindowLocationAssign.to_string(),
        "window_location_assign"
    );
    assert_eq!(
        MetaRedirectIssue::DocumentWriteRedirect.to_string(),
        "document_write_redirect"
    );
    assert_eq!(
        MetaRedirectIssue::HistoryReplaceState.to_string(),
        "history_replace_state"
    );
}

#[test]
fn display_meta_refresh() {
    let issue = MetaRedirectIssue::MetaRefreshRedirect {
        url: "https://example.com".to_string(),
    };
    assert_eq!(issue.to_string(), "meta_refresh:https://example.com");
}

#[test]
fn security_empty_body_no_issues() {
    let issues = analyze_meta_redirect_security("");
    assert!(issues.is_empty());
}

#[test]
fn security_no_redirect_no_issues() {
    let body = "<html><body>Hello</body></html>";
    let issues = analyze_meta_redirect_security(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_javascript_scheme_redirect() {
    let body = r#"<meta http-equiv="refresh" content="0;url=javascript:alert('xss')">"#;
    let issues = analyze_meta_redirect_security(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        MetaRedirectSecurityIssue::JavascriptSchemeRedirect { .. }
    )));
}

#[test]
fn javascript_scheme_captures_url() {
    let body = r#"<meta http-equiv="refresh" content="0;url=javascript:void(0)">"#;
    let issues = analyze_meta_redirect_security(body);
    let js_issue = issues.iter().find(|i| {
        matches!(
            i,
            MetaRedirectSecurityIssue::JavascriptSchemeRedirect { .. }
        )
    });
    assert!(js_issue.is_some());
    if let Some(MetaRedirectSecurityIssue::JavascriptSchemeRedirect { url }) = js_issue {
        assert!(url.contains("javascript:"));
    }
}

#[test]
fn detects_data_scheme_redirect() {
    let body =
        r#"<meta http-equiv="refresh" content="0;url=data:text/html,<script>alert(1)</script>">"#;
    let issues = analyze_meta_redirect_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MetaRedirectSecurityIssue::DataSchemeRedirect { .. }))
    );
}

#[test]
fn data_scheme_captures_url() {
    let body = r#"<meta http-equiv="refresh" content="0;url=data:text/html,test">"#;
    let issues = analyze_meta_redirect_security(body);
    let data_issue = issues
        .iter()
        .find(|i| matches!(i, MetaRedirectSecurityIssue::DataSchemeRedirect { .. }));
    assert!(data_issue.is_some());
    if let Some(MetaRedirectSecurityIssue::DataSchemeRedirect { url }) = data_issue {
        assert!(url.starts_with("data:"));
    }
}

#[test]
fn detects_open_redirect_via_meta() {
    let body = r#"<meta http-equiv="refresh" content="0;url=https://evil.com">"#;
    let issues = analyze_meta_redirect_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MetaRedirectSecurityIssue::OpenRedirectViaMeta { .. }))
    );
}

#[test]
fn open_redirect_ignores_localhost() {
    let body = r#"<meta http-equiv="refresh" content="0;url=http://localhost:3000">"#;
    let issues = analyze_meta_redirect_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MetaRedirectSecurityIssue::OpenRedirectViaMeta { .. }))
    );
}

#[test]
fn open_redirect_ignores_127() {
    let body = r#"<meta http-equiv="refresh" content="0;url=http://127.0.0.1:8080">"#;
    let issues = analyze_meta_redirect_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MetaRedirectSecurityIssue::OpenRedirectViaMeta { .. }))
    );
}

#[test]
fn detects_chained_meta_redirects() {
    let body = r#"
        <meta http-equiv="refresh" content="0;url=https://first.com">
        <meta http-equiv="refresh" content="5;url=https://second.com">
    "#;
    let issues = analyze_meta_redirect_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MetaRedirectSecurityIssue::ChainedMetaRedirects { .. }))
    );
}

#[test]
fn chained_redirects_captures_count() {
    let body = r#"
        <meta http-equiv="refresh" content="0;url=https://first.com">
        <meta http-equiv="refresh" content="1;url=https://second.com">
        <meta http-equiv="refresh" content="2;url=https://third.com">
    "#;
    let issues = analyze_meta_redirect_security(body);
    let chain_issue = issues
        .iter()
        .find(|i| matches!(i, MetaRedirectSecurityIssue::ChainedMetaRedirects { .. }));
    assert!(chain_issue.is_some());
    if let Some(MetaRedirectSecurityIssue::ChainedMetaRedirects { count }) = chain_issue {
        assert_eq!(*count, 3);
    }
}

#[test]
fn single_redirect_not_chained() {
    let body = r#"<meta http-equiv="refresh" content="0;url=https://example.com">"#;
    let issues = analyze_meta_redirect_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MetaRedirectSecurityIssue::ChainedMetaRedirects { .. }))
    );
}

#[test]
fn detects_zero_delay_redirect() {
    let body = r#"<meta http-equiv="refresh" content="0;url=https://example.com">"#;
    let issues = analyze_meta_redirect_security(body);
    assert!(issues.contains(&MetaRedirectSecurityIssue::ZeroDelayRedirect));
}

#[test]
fn detects_long_delay_redirect() {
    let body = r#"<meta http-equiv="refresh" content="30;url=https://example.com">"#;
    let issues = analyze_meta_redirect_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MetaRedirectSecurityIssue::LongDelayRedirect { .. }))
    );
}

#[test]
fn long_delay_captures_delay_value() {
    let body = r#"<meta http-equiv="refresh" content="60;url=https://example.com">"#;
    let issues = analyze_meta_redirect_security(body);
    let delay_issue = issues
        .iter()
        .find(|i| matches!(i, MetaRedirectSecurityIssue::LongDelayRedirect { .. }));
    assert!(delay_issue.is_some());
    if let Some(MetaRedirectSecurityIssue::LongDelayRedirect { delay }) = delay_issue {
        assert_eq!(*delay, 60);
    }
}

#[test]
fn normal_delay_not_flagged() {
    let body = r#"<meta http-equiv="refresh" content="5;url=https://example.com">"#;
    let issues = analyze_meta_redirect_security(body);
    assert!(!issues.contains(&MetaRedirectSecurityIssue::ZeroDelayRedirect));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MetaRedirectSecurityIssue::LongDelayRedirect { .. }))
    );
}

#[test]
fn detects_meta_redirect_with_fragment() {
    let body = r#"<meta http-equiv="refresh" content="0;url=https://example.com#token=abc">"#;
    let issues = analyze_meta_redirect_security(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        MetaRedirectSecurityIssue::MetaRedirectWithFragment { .. }
    )));
}

#[test]
fn fragment_captures_full_url() {
    let body = r#"<meta http-equiv="refresh" content="0;url=/page#section">"#;
    let issues = analyze_meta_redirect_security(body);
    let frag_issue = issues.iter().find(|i| {
        matches!(
            i,
            MetaRedirectSecurityIssue::MetaRedirectWithFragment { .. }
        )
    });
    assert!(frag_issue.is_some());
    if let Some(MetaRedirectSecurityIssue::MetaRedirectWithFragment { url }) = frag_issue {
        assert!(url.contains('#'));
    }
}

#[test]
fn detects_meta_redirect_in_iframe() {
    let body = r#"
        <iframe>
            <meta http-equiv="refresh" content="0;url=https://example.com">
        </iframe>
    "#;
    let issues = analyze_meta_redirect_security(body);
    assert!(issues.contains(&MetaRedirectSecurityIssue::MetaRedirectInIframe));
}

#[test]
fn meta_redirect_outside_iframe_not_flagged() {
    let body = r#"
        <meta http-equiv="refresh" content="0;url=https://example.com">
        <iframe src="about:blank"></iframe>
    "#;
    let issues = analyze_meta_redirect_security(body);
    assert!(!issues.contains(&MetaRedirectSecurityIssue::MetaRedirectInIframe));
}

#[test]
fn detects_phishing_redirect_login() {
    let body = r#"<meta http-equiv="refresh" content="0;url=https://evil.com/login">"#;
    let issues = analyze_meta_redirect_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MetaRedirectSecurityIssue::MetaRedirectToPhishing { .. }))
    );
}

#[test]
fn detects_phishing_redirect_signin() {
    let body = r#"<meta http-equiv="refresh" content="0;url=https://phishing.com/signin">"#;
    let issues = analyze_meta_redirect_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MetaRedirectSecurityIssue::MetaRedirectToPhishing { .. }))
    );
}

#[test]
fn detects_phishing_redirect_verify() {
    let body = r#"<meta http-equiv="refresh" content="0;url=https://bad.com/verify-account">"#;
    let issues = analyze_meta_redirect_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MetaRedirectSecurityIssue::MetaRedirectToPhishing { .. }))
    );
}

#[test]
fn detects_phishing_redirect_bank() {
    let body = r#"<meta http-equiv="refresh" content="0;url=https://fake.com/bank">"#;
    let issues = analyze_meta_redirect_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MetaRedirectSecurityIssue::MetaRedirectToPhishing { .. }))
    );
}

#[test]
fn safe_url_not_phishing() {
    let body = r#"<meta http-equiv="refresh" content="0;url=https://example.com/about">"#;
    let issues = analyze_meta_redirect_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MetaRedirectSecurityIssue::MetaRedirectToPhishing { .. }))
    );
}

#[test]
fn detects_encoded_url_slash() {
    let body = r#"<meta http-equiv="refresh" content="0;url=https://example.com%2fpath">"#;
    let issues = analyze_meta_redirect_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MetaRedirectSecurityIssue::MetaRedirectEncodedUrl { .. }))
    );
}

#[test]
fn detects_encoded_url_colon() {
    let body = r#"<meta http-equiv="refresh" content="0;url=http%3a//evil.com">"#;
    let issues = analyze_meta_redirect_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MetaRedirectSecurityIssue::MetaRedirectEncodedUrl { .. }))
    );
}

#[test]
fn detects_encoded_url_dot() {
    let body = r#"<meta http-equiv="refresh" content="0;url=https://evil%2ecom">"#;
    let issues = analyze_meta_redirect_security(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MetaRedirectSecurityIssue::MetaRedirectEncodedUrl { .. }))
    );
}

#[test]
fn normal_url_not_encoded() {
    let body = r#"<meta http-equiv="refresh" content="0;url=https://example.com/path">"#;
    let issues = analyze_meta_redirect_security(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, MetaRedirectSecurityIssue::MetaRedirectEncodedUrl { .. }))
    );
}

#[test]
fn security_severity_javascript_scheme_highest() {
    let issue = MetaRedirectSecurityIssue::JavascriptSchemeRedirect {
        url: "javascript:alert(1)".to_string(),
    };
    assert_eq!(meta_redirect_security_severity(&issue), 9.0);
}

#[test]
fn security_severity_data_scheme_high() {
    let issue = MetaRedirectSecurityIssue::DataSchemeRedirect {
        url: "data:text/html,test".to_string(),
    };
    assert_eq!(meta_redirect_security_severity(&issue), 8.5);
}

#[test]
fn security_severity_phishing_high() {
    let issue = MetaRedirectSecurityIssue::MetaRedirectToPhishing {
        url: "https://evil.com/login".to_string(),
    };
    assert_eq!(meta_redirect_security_severity(&issue), 8.0);
}

#[test]
fn security_severity_open_redirect_medium_high() {
    let issue = MetaRedirectSecurityIssue::OpenRedirectViaMeta {
        url: "https://evil.com".to_string(),
    };
    assert_eq!(meta_redirect_security_severity(&issue), 7.5);
}

#[test]
fn security_severity_zero_delay_lowest() {
    assert_eq!(
        meta_redirect_security_severity(&MetaRedirectSecurityIssue::ZeroDelayRedirect),
        4.5
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        MetaRedirectSecurityIssue::JavascriptSchemeRedirect {
            url: "javascript:alert(1)".to_string(),
        },
        MetaRedirectSecurityIssue::ZeroDelayRedirect,
    ];
    let mut seq = 0;
    let ops = meta_redirect_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_display_javascript_scheme() {
    let issue = MetaRedirectSecurityIssue::JavascriptSchemeRedirect {
        url: "javascript:alert(1)".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "javascript_scheme_redirect:javascript:alert(1)"
    );
}

#[test]
fn security_display_data_scheme() {
    let issue = MetaRedirectSecurityIssue::DataSchemeRedirect {
        url: "data:text/html,test".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "data_scheme_redirect:data:text/html,test"
    );
}

#[test]
fn security_display_open_redirect() {
    let issue = MetaRedirectSecurityIssue::OpenRedirectViaMeta {
        url: "https://evil.com".to_string(),
    };
    assert_eq!(issue.to_string(), "open_redirect_via_meta:https://evil.com");
}

#[test]
fn security_display_chained() {
    let issue = MetaRedirectSecurityIssue::ChainedMetaRedirects { count: 3 };
    assert_eq!(issue.to_string(), "chained_meta_redirects:3");
}

#[test]
fn security_display_zero_delay() {
    assert_eq!(
        MetaRedirectSecurityIssue::ZeroDelayRedirect.to_string(),
        "zero_delay_redirect"
    );
}

#[test]
fn security_display_long_delay() {
    let issue = MetaRedirectSecurityIssue::LongDelayRedirect { delay: 60 };
    assert_eq!(issue.to_string(), "long_delay_redirect:60");
}

#[test]
fn security_display_fragment() {
    let issue = MetaRedirectSecurityIssue::MetaRedirectWithFragment {
        url: "https://example.com#token".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "meta_redirect_with_fragment:https://example.com#token"
    );
}

#[test]
fn security_display_iframe() {
    assert_eq!(
        MetaRedirectSecurityIssue::MetaRedirectInIframe.to_string(),
        "meta_redirect_in_iframe"
    );
}

#[test]
fn security_display_phishing() {
    let issue = MetaRedirectSecurityIssue::MetaRedirectToPhishing {
        url: "https://evil.com/login".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "meta_redirect_to_phishing:https://evil.com/login"
    );
}

#[test]
fn security_display_encoded() {
    let issue = MetaRedirectSecurityIssue::MetaRedirectEncodedUrl {
        url: "https://evil%2ecom".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "meta_redirect_encoded_url:https://evil%2ecom"
    );
}

#[test]
fn multiple_security_issues_detected() {
    let body = r#"
        <meta http-equiv="refresh" content="0;url=javascript:alert(1)">
        <meta http-equiv="refresh" content="30;url=https://evil.com/login">
    "#;
    let issues = analyze_meta_redirect_security(body);
    assert!(issues.len() >= 3);
    assert!(issues.iter().any(|i| matches!(
        i,
        MetaRedirectSecurityIssue::JavascriptSchemeRedirect { .. }
    )));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, MetaRedirectSecurityIssue::ChainedMetaRedirects { .. }))
    );
}

#[test]
fn case_insensitive_detection() {
    let body = r#"<META HTTP-EQUIV="REFRESH" CONTENT="0;URL=javascript:alert(1)">"#;
    let issues = analyze_meta_redirect_security(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        MetaRedirectSecurityIssue::JavascriptSchemeRedirect { .. }
    )));
}
