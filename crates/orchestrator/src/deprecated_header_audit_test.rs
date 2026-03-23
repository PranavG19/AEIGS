use crate::deprecated_header_audit::{analyze_deprecated_headers, deprecated_header_to_operations};

fn has_headers<'a>(present: &'a [&'a str]) -> impl Fn(&str) -> bool + 'a {
    move |name: &str| present.contains(&name)
}

#[test]
fn detects_expect_ct() {
    let issues = analyze_deprecated_headers(has_headers(&["expect-ct"]));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].header, "expect-ct");
}

#[test]
fn detects_feature_policy() {
    let issues = analyze_deprecated_headers(has_headers(&["feature-policy"]));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].header, "feature-policy");
}

#[test]
fn detects_hpkp() {
    let issues = analyze_deprecated_headers(has_headers(&["public-key-pins"]));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].severity, 3.0);
}

#[test]
fn detects_hpkp_report_only() {
    let issues = analyze_deprecated_headers(has_headers(&["public-key-pins-report-only"]));
    assert_eq!(issues.len(), 1);
}

#[test]
fn detects_x_xss_protection() {
    let issues = analyze_deprecated_headers(has_headers(&["x-xss-protection"]));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].header, "x-xss-protection");
}

#[test]
fn multiple_deprecated_headers() {
    let issues = analyze_deprecated_headers(has_headers(&[
        "expect-ct",
        "feature-policy",
        "x-xss-protection",
    ]));
    assert_eq!(issues.len(), 3);
}

#[test]
fn no_deprecated_headers() {
    let issues = analyze_deprecated_headers(has_headers(&[
        "content-security-policy",
        "permissions-policy",
    ]));
    assert!(issues.is_empty());
}

#[test]
fn empty_headers() {
    let issues = analyze_deprecated_headers(has_headers(&[]));
    assert!(issues.is_empty());
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = deprecated_header_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_for_issues() {
    let issues = analyze_deprecated_headers(has_headers(&["public-key-pins"]));
    let mut seq = 0;
    let ops = deprecated_header_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn reason_is_populated() {
    let issues = analyze_deprecated_headers(has_headers(&["expect-ct"]));
    assert!(!issues[0].reason.is_empty());
}
