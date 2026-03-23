use crate::clear_site_data_audit::*;

// --- Detection tests ---

#[test]
fn no_header_no_issues() {
    let issues = analyze_clear_site_data(None, true, false);
    assert!(issues.is_empty());
}

#[test]
fn wildcard_flagged() {
    let issues = analyze_clear_site_data(Some(r#""*""#), true, false);
    assert!(
        issues
            .iter()
            .any(|i| *i == ClearSiteDataIssue::WildcardOnGet)
    );
}

#[test]
fn cookies_flagged() {
    let issues = analyze_clear_site_data(Some(r#""cookies""#), true, false);
    assert!(
        issues
            .iter()
            .any(|i| *i == ClearSiteDataIssue::CookieClearOnGet)
    );
}

#[test]
fn storage_flagged() {
    let issues = analyze_clear_site_data(Some(r#""storage""#), true, false);
    assert!(
        issues
            .iter()
            .any(|i| *i == ClearSiteDataIssue::StorageClearOnGet)
    );
}

#[test]
fn cache_flagged() {
    let issues = analyze_clear_site_data(Some(r#""cache""#), true, false);
    assert!(
        issues
            .iter()
            .any(|i| *i == ClearSiteDataIssue::CacheClearOnGet)
    );
}

#[test]
fn execution_contexts_flagged() {
    let issues = analyze_clear_site_data(Some(r#""executionContexts""#), true, false);
    assert!(
        issues
            .iter()
            .any(|i| *i == ClearSiteDataIssue::ExecutionContextClear)
    );
}

#[test]
fn http_not_https_flagged() {
    let issues = analyze_clear_site_data(Some(r#""cache""#), false, false);
    assert!(
        issues
            .iter()
            .any(|i| *i == ClearSiteDataIssue::HttpNotHttps)
    );
}

#[test]
fn https_no_protocol_issue() {
    let issues = analyze_clear_site_data(Some(r#""cache""#), true, false);
    assert!(
        !issues
            .iter()
            .any(|i| *i == ClearSiteDataIssue::HttpNotHttps)
    );
}

#[test]
fn clear_on_navigation_response_flagged() {
    let issues = analyze_clear_site_data(Some(r#""cache""#), true, true);
    assert!(
        issues
            .iter()
            .any(|i| *i == ClearSiteDataIssue::ClearOnNavigationResponse)
    );
}

#[test]
fn no_navigation_no_redirect_issue() {
    let issues = analyze_clear_site_data(Some(r#""cache""#), true, false);
    assert!(
        !issues
            .iter()
            .any(|i| *i == ClearSiteDataIssue::ClearOnNavigationResponse)
    );
}

#[test]
fn unquoted_directive_flagged() {
    let issues = analyze_clear_site_data(Some("cache"), true, false);
    assert!(
        issues
            .iter()
            .any(|i| *i == ClearSiteDataIssue::UnquotedDirective)
    );
}

#[test]
fn quoted_directive_no_unquoted_issue() {
    let issues = analyze_clear_site_data(Some(r#""cache""#), true, false);
    assert!(
        !issues
            .iter()
            .any(|i| *i == ClearSiteDataIssue::UnquotedDirective)
    );
}

#[test]
fn unknown_directive_flagged() {
    let issues = analyze_clear_site_data(Some(r#""bogus""#), true, false);
    assert!(issues.iter().any(
        |i| matches!(i, ClearSiteDataIssue::UnknownDirective { directive } if directive == "bogus")
    ));
}

#[test]
fn known_directive_no_unknown_issue() {
    let issues = analyze_clear_site_data(Some(r#""cookies""#), true, false);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ClearSiteDataIssue::UnknownDirective { .. }))
    );
}

#[test]
fn multiple_directives_three_or_more() {
    let issues = analyze_clear_site_data(Some(r#""cookies", "storage", "cache""#), true, false);
    assert!(issues.iter().any(
        |i| matches!(i, ClearSiteDataIssue::MultipleClearDirectives { count } if *count == 3)
    ));
}

#[test]
fn two_directives_no_multiple_issue() {
    let issues = analyze_clear_site_data(Some(r#""cookies", "storage""#), true, false);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ClearSiteDataIssue::MultipleClearDirectives { .. }))
    );
}

#[test]
fn wildcard_returns_early_skips_individual() {
    let issues = analyze_clear_site_data(Some(r#""cookies", "*""#), true, false);
    assert!(
        issues
            .iter()
            .any(|i| *i == ClearSiteDataIssue::WildcardOnGet)
    );
    assert!(
        !issues
            .iter()
            .any(|i| *i == ClearSiteDataIssue::CookieClearOnGet)
    );
}

#[test]
fn multiple_directives_still_flags_individuals() {
    let issues = analyze_clear_site_data(Some(r#""cookies", "storage", "cache""#), true, false);
    assert!(
        issues
            .iter()
            .any(|i| *i == ClearSiteDataIssue::CookieClearOnGet)
    );
    assert!(
        issues
            .iter()
            .any(|i| *i == ClearSiteDataIssue::StorageClearOnGet)
    );
    assert!(
        issues
            .iter()
            .any(|i| *i == ClearSiteDataIssue::CacheClearOnGet)
    );
}

#[test]
fn mixed_quoted_and_unquoted() {
    let issues = analyze_clear_site_data(Some(r#""cookies", storage"#), true, false);
    assert!(
        issues
            .iter()
            .any(|i| *i == ClearSiteDataIssue::UnquotedDirective)
    );
    assert!(
        issues
            .iter()
            .any(|i| *i == ClearSiteDataIssue::CookieClearOnGet)
    );
    assert!(
        issues
            .iter()
            .any(|i| *i == ClearSiteDataIssue::StorageClearOnGet)
    );
}

#[test]
fn empty_string_no_issues() {
    let issues = analyze_clear_site_data(Some(""), true, false);
    assert!(issues.is_empty());
}

#[test]
fn whitespace_only_no_directives() {
    let issues = analyze_clear_site_data(Some("   "), true, false);
    assert!(issues.is_empty());
}

#[test]
fn http_and_redirect_both_flagged() {
    let issues = analyze_clear_site_data(Some(r#""cache""#), false, true);
    assert!(
        issues
            .iter()
            .any(|i| *i == ClearSiteDataIssue::HttpNotHttps)
    );
    assert!(
        issues
            .iter()
            .any(|i| *i == ClearSiteDataIssue::ClearOnNavigationResponse)
    );
}

// --- Display tests ---

#[test]
fn display_wildcard_on_get() {
    assert_eq!(
        ClearSiteDataIssue::WildcardOnGet.to_string(),
        "wildcard_on_get"
    );
}

#[test]
fn display_cookie_clear_on_get() {
    assert_eq!(
        ClearSiteDataIssue::CookieClearOnGet.to_string(),
        "cookie_clear_on_get"
    );
}

#[test]
fn display_storage_clear_on_get() {
    assert_eq!(
        ClearSiteDataIssue::StorageClearOnGet.to_string(),
        "storage_clear_on_get"
    );
}

#[test]
fn display_cache_clear_on_get() {
    assert_eq!(
        ClearSiteDataIssue::CacheClearOnGet.to_string(),
        "cache_clear_on_get"
    );
}

#[test]
fn display_http_not_https() {
    assert_eq!(
        ClearSiteDataIssue::HttpNotHttps.to_string(),
        "http_not_https"
    );
}

#[test]
fn display_execution_context_clear() {
    assert_eq!(
        ClearSiteDataIssue::ExecutionContextClear.to_string(),
        "execution_context_clear"
    );
}

#[test]
fn display_multiple_clear_directives() {
    let issue = ClearSiteDataIssue::MultipleClearDirectives { count: 4 };
    assert_eq!(issue.to_string(), "multiple_clear_directives_4");
}

#[test]
fn display_clear_on_navigation_response() {
    assert_eq!(
        ClearSiteDataIssue::ClearOnNavigationResponse.to_string(),
        "clear_on_navigation_response"
    );
}

#[test]
fn display_unquoted_directive() {
    assert_eq!(
        ClearSiteDataIssue::UnquotedDirective.to_string(),
        "unquoted_directive"
    );
}

#[test]
fn display_unknown_directive() {
    let issue = ClearSiteDataIssue::UnknownDirective {
        directive: "foo".to_string(),
    };
    assert_eq!(issue.to_string(), "unknown_directive_foo");
}

// --- Severity tests ---

#[test]
fn severity_wildcard_on_get() {
    assert!(
        (clear_site_data_severity(&ClearSiteDataIssue::WildcardOnGet) - 5.5).abs() < f64::EPSILON
    );
}

#[test]
fn severity_cookie_clear_on_get() {
    assert!(
        (clear_site_data_severity(&ClearSiteDataIssue::CookieClearOnGet) - 4.5).abs()
            < f64::EPSILON
    );
}

#[test]
fn severity_storage_clear_on_get() {
    assert!(
        (clear_site_data_severity(&ClearSiteDataIssue::StorageClearOnGet) - 4.0).abs()
            < f64::EPSILON
    );
}

#[test]
fn severity_cache_clear_on_get() {
    assert!(
        (clear_site_data_severity(&ClearSiteDataIssue::CacheClearOnGet) - 3.0).abs() < f64::EPSILON
    );
}

#[test]
fn severity_http_not_https() {
    assert!(
        (clear_site_data_severity(&ClearSiteDataIssue::HttpNotHttps) - 2.0).abs() < f64::EPSILON
    );
}

#[test]
fn severity_execution_context_clear() {
    assert!(
        (clear_site_data_severity(&ClearSiteDataIssue::ExecutionContextClear) - 3.5).abs()
            < f64::EPSILON
    );
}

#[test]
fn severity_multiple_clear_directives() {
    let issue = ClearSiteDataIssue::MultipleClearDirectives { count: 3 };
    assert!((clear_site_data_severity(&issue) - 3.0).abs() < f64::EPSILON);
}

#[test]
fn severity_clear_on_navigation_response() {
    assert!(
        (clear_site_data_severity(&ClearSiteDataIssue::ClearOnNavigationResponse) - 4.0).abs()
            < f64::EPSILON
    );
}

#[test]
fn severity_unquoted_directive() {
    assert!(
        (clear_site_data_severity(&ClearSiteDataIssue::UnquotedDirective) - 1.5).abs()
            < f64::EPSILON
    );
}

#[test]
fn severity_unknown_directive() {
    let issue = ClearSiteDataIssue::UnknownDirective {
        directive: "x".to_string(),
    };
    assert!((clear_site_data_severity(&issue) - 2.0).abs() < f64::EPSILON);
}

// --- to_operations tests ---

#[test]
fn operations_empty_on_no_issues() {
    let mut seq = 0;
    let ops = clear_site_data_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_one_per_issue() {
    let issues = analyze_clear_site_data(Some(r#""cookies", "storage""#), true, false);
    let mut seq = 0;
    let ops = clear_site_data_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), issues.len());
    assert_eq!(seq, issues.len() as u64);
}

#[test]
fn operations_sequence_increments() {
    let issues = vec![
        ClearSiteDataIssue::CookieClearOnGet,
        ClearSiteDataIssue::StorageClearOnGet,
        ClearSiteDataIssue::CacheClearOnGet,
    ];
    let mut seq = 5;
    let ops = clear_site_data_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 8);
    assert_eq!(ops[0].sequence_number, 6);
    assert_eq!(ops[1].sequence_number, 7);
    assert_eq!(ops[2].sequence_number, 8);
}

#[test]
fn operations_uses_security_misconfiguration() {
    let issues = vec![ClearSiteDataIssue::WildcardOnGet];
    let mut seq = 0;
    let ops = clear_site_data_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::SecurityMisconfiguration
            );
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn operations_wildcard_produces_ops() {
    let issues = analyze_clear_site_data(Some(r#""*""#), true, false);
    let mut seq = 0;
    let ops = clear_site_data_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}
