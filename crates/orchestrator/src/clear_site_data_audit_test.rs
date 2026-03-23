use crate::clear_site_data_audit::{
    analyze_clear_site_data, clear_site_data_to_operations, ClearSiteDataIssueKind,
};

#[test]
fn no_header_no_issues() {
    let issues = analyze_clear_site_data(None, true);
    assert!(issues.is_empty());
}

#[test]
fn wildcard_flagged() {
    let issues = analyze_clear_site_data(Some(r#""*""#), true);
    assert!(issues
        .iter()
        .any(|i| i.kind == ClearSiteDataIssueKind::WildcardOnGet));
}

#[test]
fn cookies_flagged() {
    let issues = analyze_clear_site_data(Some(r#""cookies""#), true);
    assert!(issues
        .iter()
        .any(|i| i.kind == ClearSiteDataIssueKind::CookieClearOnGet));
}

#[test]
fn storage_flagged() {
    let issues = analyze_clear_site_data(Some(r#""storage""#), true);
    assert!(issues
        .iter()
        .any(|i| i.kind == ClearSiteDataIssueKind::StorageClearOnGet));
}

#[test]
fn cache_flagged() {
    let issues = analyze_clear_site_data(Some(r#""cache""#), true);
    assert!(issues
        .iter()
        .any(|i| i.kind == ClearSiteDataIssueKind::CacheClearOnGet));
}

#[test]
fn http_not_https_flagged() {
    let issues = analyze_clear_site_data(Some(r#""cache""#), false);
    assert!(issues
        .iter()
        .any(|i| i.kind == ClearSiteDataIssueKind::HttpNotHttps));
}

#[test]
fn https_no_protocol_issue() {
    let issues = analyze_clear_site_data(Some(r#""cache""#), true);
    assert!(!issues
        .iter()
        .any(|i| i.kind == ClearSiteDataIssueKind::HttpNotHttps));
}

#[test]
fn multiple_directives() {
    let issues = analyze_clear_site_data(Some(r#""cookies", "storage""#), true);
    assert!(issues
        .iter()
        .any(|i| i.kind == ClearSiteDataIssueKind::CookieClearOnGet));
    assert!(issues
        .iter()
        .any(|i| i.kind == ClearSiteDataIssueKind::StorageClearOnGet));
}

#[test]
fn wildcard_returns_early() {
    let issues = analyze_clear_site_data(Some(r#""cookies", "*""#), true);
    assert!(issues
        .iter()
        .any(|i| i.kind == ClearSiteDataIssueKind::WildcardOnGet));
    assert!(!issues
        .iter()
        .any(|i| i.kind == ClearSiteDataIssueKind::CookieClearOnGet));
}

#[test]
fn operations_empty_on_no_issues() {
    let mut seq = 0;
    let ops = clear_site_data_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_produced_on_issues() {
    let issues = analyze_clear_site_data(Some(r#""*""#), true);
    let mut seq = 5;
    let ops = clear_site_data_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 6);
}
