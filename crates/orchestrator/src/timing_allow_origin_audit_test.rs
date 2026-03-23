use crate::timing_allow_origin_audit::*;

#[test]
fn no_header_no_issues() {
    let issues = analyze_timing_allow_origin(&[]);
    assert!(issues.is_empty());
}

#[test]
fn wildcard_flagged() {
    let vals = vec!["*".to_string()];
    let issues = analyze_timing_allow_origin(&vals);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], TimingAllowIssue::Wildcard);
}

#[test]
fn single_https_origin_clean() {
    let vals = vec!["https://example.com".to_string()];
    let issues = analyze_timing_allow_origin(&vals);
    assert!(issues.is_empty());
}

#[test]
fn http_origin_flagged() {
    let vals = vec!["http://insecure.example.com".to_string()];
    let issues = analyze_timing_allow_origin(&vals);
    assert_eq!(issues.len(), 1);
    assert!(
        matches!(&issues[0], TimingAllowIssue::HttpOrigin { origin } if origin == "http://insecure.example.com")
    );
}

#[test]
fn many_origins_flagged_above_five() {
    let vals = vec![
        "https://a.com, https://b.com, https://c.com, https://d.com, https://e.com, https://f.com"
            .to_string(),
    ];
    let issues = analyze_timing_allow_origin(&vals);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TimingAllowIssue::ManyOrigins { count: 6 }))
    );
}

#[test]
fn exactly_five_origins_not_flagged() {
    let vals = vec![
        "https://a.com, https://b.com, https://c.com, https://d.com, https://e.com".to_string(),
    ];
    let issues = analyze_timing_allow_origin(&vals);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, TimingAllowIssue::ManyOrigins { .. }))
    );
}

#[test]
fn multiple_header_values() {
    let vals = vec!["https://a.com".to_string(), "http://b.com".to_string()];
    let issues = analyze_timing_allow_origin(&vals);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TimingAllowIssue::HttpOrigin { .. }))
    );
}

#[test]
fn wildcard_returns_early_no_other_issues() {
    let vals = vec!["http://insecure.com, *".to_string()];
    let issues = analyze_timing_allow_origin(&vals);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], TimingAllowIssue::Wildcard);
}

#[test]
fn subdomain_wildcard_detected() {
    let vals = vec!["*.example.com".to_string()];
    let issues = analyze_timing_allow_origin(&vals);
    assert_eq!(issues.len(), 1);
    assert!(
        matches!(&issues[0], TimingAllowIssue::SubdomainWildcard { pattern } if pattern == "*.example.com")
    );
}

#[test]
fn ip_address_origin_ipv4() {
    let vals = vec!["https://192.168.1.1".to_string()];
    let issues = analyze_timing_allow_origin(&vals);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TimingAllowIssue::IpAddressOrigin { .. }))
    );
}

#[test]
fn ip_address_origin_with_port() {
    let vals = vec!["http://10.0.0.1:8080".to_string()];
    let issues = analyze_timing_allow_origin(&vals);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TimingAllowIssue::IpAddressOrigin { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TimingAllowIssue::HttpOrigin { .. }))
    );
}

#[test]
fn null_origin_flagged() {
    let vals = vec!["null".to_string()];
    let issues = analyze_timing_allow_origin(&vals);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], TimingAllowIssue::NullOrigin);
}

#[test]
fn null_origin_case_insensitive() {
    let vals = vec!["NULL".to_string()];
    let issues = analyze_timing_allow_origin(&vals);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TimingAllowIssue::NullOrigin))
    );
}

#[test]
fn duplicate_origins_detected() {
    let vals = vec!["https://a.com, https://a.com".to_string()];
    let issues = analyze_timing_allow_origin(&vals);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TimingAllowIssue::DuplicateOrigins { .. }))
    );
}

#[test]
fn duplicate_origins_case_insensitive() {
    let vals = vec!["https://A.COM".to_string(), "https://a.com".to_string()];
    let issues = analyze_timing_allow_origin(&vals);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TimingAllowIssue::DuplicateOrigins { .. }))
    );
}

#[test]
fn display_wildcard() {
    assert_eq!(TimingAllowIssue::Wildcard.to_string(), "wildcard");
}

#[test]
fn display_http_origin() {
    let issue = TimingAllowIssue::HttpOrigin {
        origin: "http://x.com".into(),
    };
    assert_eq!(issue.to_string(), "http_origin");
}

#[test]
fn display_many_origins() {
    let issue = TimingAllowIssue::ManyOrigins { count: 8 };
    assert_eq!(issue.to_string(), "many_origins");
}

#[test]
fn display_subdomain_wildcard() {
    let issue = TimingAllowIssue::SubdomainWildcard {
        pattern: "*.foo.com".into(),
    };
    assert_eq!(issue.to_string(), "subdomain_wildcard");
}

#[test]
fn display_ip_address_origin() {
    let issue = TimingAllowIssue::IpAddressOrigin {
        ip: "1.2.3.4".into(),
    };
    assert_eq!(issue.to_string(), "ip_address_origin");
}

#[test]
fn display_null_origin() {
    assert_eq!(TimingAllowIssue::NullOrigin.to_string(), "null_origin");
}

#[test]
fn display_duplicate_origins() {
    let issue = TimingAllowIssue::DuplicateOrigins {
        origin: "https://a.com".into(),
    };
    assert_eq!(issue.to_string(), "duplicate_origins");
}

#[test]
fn severity_wildcard() {
    assert_eq!(timing_allow_severity(&TimingAllowIssue::Wildcard), 4.0);
}

#[test]
fn severity_http_origin() {
    let issue = TimingAllowIssue::HttpOrigin {
        origin: "http://x.com".into(),
    };
    assert_eq!(timing_allow_severity(&issue), 3.5);
}

#[test]
fn severity_many_origins() {
    let issue = TimingAllowIssue::ManyOrigins { count: 10 };
    assert_eq!(timing_allow_severity(&issue), 3.0);
}

#[test]
fn severity_subdomain_wildcard() {
    let issue = TimingAllowIssue::SubdomainWildcard {
        pattern: "*.x.com".into(),
    };
    assert_eq!(timing_allow_severity(&issue), 2.5);
}

#[test]
fn severity_ip_address_origin() {
    let issue = TimingAllowIssue::IpAddressOrigin {
        ip: "10.0.0.1".into(),
    };
    assert_eq!(timing_allow_severity(&issue), 2.0);
}

#[test]
fn severity_null_origin() {
    assert_eq!(timing_allow_severity(&TimingAllowIssue::NullOrigin), 3.5);
}

#[test]
fn severity_duplicate_origins() {
    let issue = TimingAllowIssue::DuplicateOrigins {
        origin: "https://a.com".into(),
    };
    assert_eq!(timing_allow_severity(&issue), 1.0);
}

#[test]
fn operations_empty_on_no_issues() {
    let mut seq = 0;
    let ops = timing_allow_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_one_per_issue() {
    let issues = vec![
        TimingAllowIssue::HttpOrigin {
            origin: "http://a.com".into(),
        },
        TimingAllowIssue::NullOrigin,
    ];
    let mut seq = 0;
    let ops = timing_allow_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn operations_seq_increments() {
    let issues = vec![TimingAllowIssue::Wildcard];
    let mut seq = 10;
    let ops = timing_allow_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 11);
}

#[test]
fn combined_http_and_ip() {
    let vals = vec!["http://192.168.1.1".to_string()];
    let issues = analyze_timing_allow_origin(&vals);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TimingAllowIssue::HttpOrigin { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, TimingAllowIssue::IpAddressOrigin { .. }))
    );
}

#[test]
fn hostname_not_flagged_as_ip() {
    let vals = vec!["https://example.com".to_string()];
    let issues = analyze_timing_allow_origin(&vals);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, TimingAllowIssue::IpAddressOrigin { .. }))
    );
}
