use crate::timing_allow_origin_audit::{
    TimingAllowIssueKind, analyze_timing_allow_origin, timing_allow_origin_to_operations,
};

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
    assert_eq!(issues[0].kind, TimingAllowIssueKind::Wildcard);
}

#[test]
fn single_https_origin_ok() {
    let vals = vec!["https://example.com".to_string()];
    let issues = analyze_timing_allow_origin(&vals);
    assert!(issues.is_empty());
}

#[test]
fn http_origin_flagged() {
    let vals = vec!["http://insecure.example.com".to_string()];
    let issues = analyze_timing_allow_origin(&vals);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == TimingAllowIssueKind::HttpOrigin)
    );
}

#[test]
fn many_origins_flagged() {
    let vals = vec![
        "https://a.com, https://b.com, https://c.com, https://d.com, https://e.com, https://f.com"
            .to_string(),
    ];
    let issues = analyze_timing_allow_origin(&vals);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == TimingAllowIssueKind::ManyOrigins)
    );
}

#[test]
fn five_origins_not_flagged() {
    let vals = vec![
        "https://a.com, https://b.com, https://c.com, https://d.com, https://e.com".to_string(),
    ];
    let issues = analyze_timing_allow_origin(&vals);
    assert!(
        !issues
            .iter()
            .any(|i| i.kind == TimingAllowIssueKind::ManyOrigins)
    );
}

#[test]
fn wildcard_returns_early() {
    let vals = vec!["https://a.com, *".to_string()];
    let issues = analyze_timing_allow_origin(&vals);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, TimingAllowIssueKind::Wildcard);
}

#[test]
fn multiple_header_values() {
    let vals = vec!["https://a.com".to_string(), "http://b.com".to_string()];
    let issues = analyze_timing_allow_origin(&vals);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == TimingAllowIssueKind::HttpOrigin)
    );
}

#[test]
fn operations_empty_on_no_issues() {
    let mut seq = 0;
    let ops = timing_allow_origin_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_produced_on_issues() {
    let vals = vec!["*".to_string()];
    let issues = analyze_timing_allow_origin(&vals);
    let mut seq = 5;
    let ops = timing_allow_origin_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 6);
}
