use crate::dns_prefetch_control_audit::*;

#[test]
fn missing_header_empty_body() {
    let issues = analyze_dns_prefetch(None, "");
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], DnsPrefetchControlIssue::MissingHeader);
}

#[test]
fn missing_header_with_body() {
    let issues = analyze_dns_prefetch(None, "<html><body>hello</body></html>");
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], DnsPrefetchControlIssue::MissingHeader);
}

#[test]
fn prefetch_on_flagged() {
    let issues = analyze_dns_prefetch(Some("on"), "");
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], DnsPrefetchControlIssue::PrefetchEnabled);
}

#[test]
fn prefetch_off_no_issues() {
    let issues = analyze_dns_prefetch(Some("off"), "");
    assert!(issues.is_empty());
}

#[test]
fn case_insensitive_on_upper() {
    let issues = analyze_dns_prefetch(Some("ON"), "");
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], DnsPrefetchControlIssue::PrefetchEnabled);
}

#[test]
fn case_insensitive_on_mixed() {
    let issues = analyze_dns_prefetch(Some("On"), "");
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], DnsPrefetchControlIssue::PrefetchEnabled);
}

#[test]
fn case_insensitive_off_upper() {
    let issues = analyze_dns_prefetch(Some("OFF"), "");
    assert!(issues.is_empty());
}

#[test]
fn case_insensitive_off_mixed() {
    let issues = analyze_dns_prefetch(Some("Off"), "");
    assert!(issues.is_empty());
}

#[test]
fn invalid_value_maybe() {
    let issues = analyze_dns_prefetch(Some("maybe"), "");
    assert_eq!(issues.len(), 1);
    assert!(
        matches!(&issues[0], DnsPrefetchControlIssue::InvalidValue { value } if value == "maybe")
    );
}

#[test]
fn invalid_value_numeric() {
    let issues = analyze_dns_prefetch(Some("1"), "");
    assert_eq!(issues.len(), 1);
    assert!(matches!(&issues[0], DnsPrefetchControlIssue::InvalidValue { value } if value == "1"));
}

#[test]
fn invalid_value_true() {
    let issues = analyze_dns_prefetch(Some("true"), "");
    assert_eq!(issues.len(), 1);
    assert!(
        matches!(&issues[0], DnsPrefetchControlIssue::InvalidValue { value } if value == "true")
    );
}

#[test]
fn whitespace_trimmed_off() {
    let issues = analyze_dns_prefetch(Some("  off  "), "");
    assert!(issues.is_empty());
}

#[test]
fn whitespace_trimmed_on() {
    let issues = analyze_dns_prefetch(Some("  on  "), "");
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], DnsPrefetchControlIssue::PrefetchEnabled);
}

#[test]
fn prefetch_on_with_csrf_meta() {
    let body = r#"<html><head><meta name="csrf-token" content="abc123"></head></html>"#;
    let issues = analyze_dns_prefetch(Some("on"), body);
    assert!(
        issues
            .iter()
            .any(|i| *i == DnsPrefetchControlIssue::PrefetchWithSensitiveMeta)
    );
}

#[test]
fn prefetch_on_with_api_key_meta() {
    let body = r#"<html><head><meta name="api-key" content="secret"></head></html>"#;
    let issues = analyze_dns_prefetch(Some("on"), body);
    assert!(
        issues
            .iter()
            .any(|i| *i == DnsPrefetchControlIssue::PrefetchWithSensitiveMeta)
    );
}

#[test]
fn prefetch_on_with_csrf_underscore_meta() {
    let body = r#"<html><head><meta name="csrf_token" content="abc"></head></html>"#;
    let issues = analyze_dns_prefetch(Some("on"), body);
    assert!(
        issues
            .iter()
            .any(|i| *i == DnsPrefetchControlIssue::PrefetchWithSensitiveMeta)
    );
}

#[test]
fn prefetch_off_ignores_sensitive_meta() {
    let body = r#"<html><head><meta name="csrf-token" content="abc123"></head></html>"#;
    let issues = analyze_dns_prefetch(Some("off"), body);
    assert!(issues.is_empty());
}

#[test]
fn prefetch_on_with_external_dns_prefetch_links() {
    let body = r#"<html><head>
        <link rel="dns-prefetch" href="//cdn.example.com">
        <link rel="dns-prefetch" href="//api.example.com">
    </head></html>"#;
    let issues = analyze_dns_prefetch(Some("on"), body);
    assert!(issues.iter().any(|i| matches!(
        i,
        DnsPrefetchControlIssue::PrefetchWithExternalResources { count: 2 }
    )));
}

#[test]
fn prefetch_on_with_preconnect_links() {
    let body = r#"<html><head><link rel="preconnect" href="//fonts.googleapis.com"></head></html>"#;
    let issues = analyze_dns_prefetch(Some("on"), body);
    assert!(issues.iter().any(|i| matches!(
        i,
        DnsPrefetchControlIssue::PrefetchWithExternalResources { count: 1 }
    )));
}

#[test]
fn prefetch_on_no_external_resources() {
    let body = r#"<html><head><link rel="stylesheet" href="/style.css"></head></html>"#;
    let issues = analyze_dns_prefetch(Some("on"), body);
    assert!(!issues.iter().any(|i| matches!(
        i,
        DnsPrefetchControlIssue::PrefetchWithExternalResources { .. }
    )));
}

#[test]
fn prefetch_off_ignores_external_resources() {
    let body = r#"<html><head><link rel="dns-prefetch" href="//cdn.example.com"></head></html>"#;
    let issues = analyze_dns_prefetch(Some("off"), body);
    assert!(issues.is_empty());
}

#[test]
fn conflicting_headers_detected() {
    let values = vec!["on".to_string(), "off".to_string()];
    let conflict = detect_conflicting_dns_prefetch(&values);
    assert!(conflict.is_some());
    assert!(matches!(
        conflict.unwrap(),
        DnsPrefetchControlIssue::ConflictingHeaders { .. }
    ));
}

#[test]
fn no_conflict_when_same_values() {
    let values = vec!["on".to_string(), "on".to_string()];
    let conflict = detect_conflicting_dns_prefetch(&values);
    assert!(conflict.is_none());
}

#[test]
fn no_conflict_with_single_value() {
    let values = vec!["on".to_string()];
    let conflict = detect_conflicting_dns_prefetch(&values);
    assert!(conflict.is_none());
}

#[test]
fn no_conflict_with_empty_values() {
    let values: Vec<String> = Vec::new();
    let conflict = detect_conflicting_dns_prefetch(&values);
    assert!(conflict.is_none());
}

#[test]
fn conflicting_case_insensitive_same_meaning() {
    let values = vec!["ON".to_string(), "on".to_string()];
    let conflict = detect_conflicting_dns_prefetch(&values);
    assert!(conflict.is_none());
}

#[test]
fn display_prefetch_enabled() {
    let issue = DnsPrefetchControlIssue::PrefetchEnabled;
    assert_eq!(issue.to_string(), "prefetch_enabled");
}

#[test]
fn display_invalid_value() {
    let issue = DnsPrefetchControlIssue::InvalidValue {
        value: "maybe".to_string(),
    };
    assert_eq!(issue.to_string(), "invalid_value:maybe");
}

#[test]
fn display_missing_header() {
    let issue = DnsPrefetchControlIssue::MissingHeader;
    assert_eq!(issue.to_string(), "missing_header");
}

#[test]
fn display_prefetch_with_sensitive_meta() {
    let issue = DnsPrefetchControlIssue::PrefetchWithSensitiveMeta;
    assert_eq!(issue.to_string(), "prefetch_with_sensitive_meta");
}

#[test]
fn display_prefetch_with_external_resources() {
    let issue = DnsPrefetchControlIssue::PrefetchWithExternalResources { count: 3 };
    assert_eq!(issue.to_string(), "prefetch_with_external_resources:3");
}

#[test]
fn display_conflicting_headers() {
    let issue = DnsPrefetchControlIssue::ConflictingHeaders {
        values: vec!["on".to_string(), "off".to_string()],
    };
    assert_eq!(issue.to_string(), "conflicting_headers:on,off");
}

#[test]
fn severity_prefetch_enabled() {
    assert!(
        (dns_prefetch_severity(&DnsPrefetchControlIssue::PrefetchEnabled) - 2.5).abs()
            < f64::EPSILON
    );
}

#[test]
fn severity_invalid_value() {
    let issue = DnsPrefetchControlIssue::InvalidValue {
        value: "x".to_string(),
    };
    assert!((dns_prefetch_severity(&issue) - 1.5).abs() < f64::EPSILON);
}

#[test]
fn severity_missing_header() {
    assert!(
        (dns_prefetch_severity(&DnsPrefetchControlIssue::MissingHeader) - 1.0).abs() < f64::EPSILON
    );
}

#[test]
fn severity_sensitive_meta() {
    assert!(
        (dns_prefetch_severity(&DnsPrefetchControlIssue::PrefetchWithSensitiveMeta) - 4.5).abs()
            < f64::EPSILON
    );
}

#[test]
fn severity_external_resources() {
    let issue = DnsPrefetchControlIssue::PrefetchWithExternalResources { count: 5 };
    assert!((dns_prefetch_severity(&issue) - 3.5).abs() < f64::EPSILON);
}

#[test]
fn severity_conflicting() {
    let issue = DnsPrefetchControlIssue::ConflictingHeaders {
        values: vec!["on".to_string(), "off".to_string()],
    };
    assert!((dns_prefetch_severity(&issue) - 2.0).abs() < f64::EPSILON);
}

#[test]
fn operations_empty_on_no_issues() {
    let mut seq = 0;
    let ops = dns_prefetch_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_produced_for_single_issue() {
    let issues = vec![DnsPrefetchControlIssue::PrefetchEnabled];
    let mut seq = 5;
    let ops = dns_prefetch_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 6);
}

#[test]
fn operations_produced_for_multiple_issues() {
    let issues = vec![
        DnsPrefetchControlIssue::PrefetchEnabled,
        DnsPrefetchControlIssue::PrefetchWithSensitiveMeta,
    ];
    let mut seq = 10;
    let ops = dns_prefetch_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 11);
}

#[test]
fn operations_sequence_increments_correctly() {
    let issues_a = vec![DnsPrefetchControlIssue::MissingHeader];
    let issues_b = vec![DnsPrefetchControlIssue::PrefetchEnabled];
    let mut seq = 0;
    let ops_a = dns_prefetch_to_operations(&issues_a, &mut seq);
    assert_eq!(ops_a.len(), 1);
    assert_eq!(seq, 1);
    let ops_b = dns_prefetch_to_operations(&issues_b, &mut seq);
    assert_eq!(ops_b.len(), 1);
    assert_eq!(seq, 2);
}

#[test]
fn prefetch_on_with_sensitive_meta_and_external_resources() {
    let body = r#"<html><head>
        <meta name="csrf-token" content="abc">
        <link rel="dns-prefetch" href="//cdn.example.com">
    </head></html>"#;
    let issues = analyze_dns_prefetch(Some("on"), body);
    assert_eq!(issues.len(), 3);
    assert_eq!(issues[0], DnsPrefetchControlIssue::PrefetchEnabled);
    assert_eq!(
        issues[1],
        DnsPrefetchControlIssue::PrefetchWithSensitiveMeta
    );
    assert!(matches!(
        issues[2],
        DnsPrefetchControlIssue::PrefetchWithExternalResources { count: 1 }
    ));
}

#[test]
fn invalid_value_does_not_check_body() {
    let body = r#"<html><head><meta name="csrf-token" content="abc"></head></html>"#;
    let issues = analyze_dns_prefetch(Some("banana"), body);
    assert_eq!(issues.len(), 1);
    assert!(
        matches!(&issues[0], DnsPrefetchControlIssue::InvalidValue { value } if value == "banana")
    );
}
