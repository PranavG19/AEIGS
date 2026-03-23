use crate::etag_audit::{EtagIssueKind, analyze_etag, etag_to_operations};

#[test]
fn no_header_no_issues() {
    let issues = analyze_etag(None);
    assert!(issues.is_empty());
}

#[test]
fn apache_inode_etag_detected() {
    let issues = analyze_etag(Some(r#""5f3a1b-264-5e8c4a0e""#));
    assert!(issues.iter().any(|i| i.kind == EtagIssueKind::InodeLeak));
}

#[test]
fn normal_hash_etag_ok() {
    let issues = analyze_etag(Some(r#""33a64df551425fcc55e4d42a148795d9f25f89d4""#));
    assert!(!issues.iter().any(|i| i.kind == EtagIssueKind::InodeLeak));
}

#[test]
fn weak_etag_flagged() {
    let issues = analyze_etag(Some(r#"W/"abc123""#));
    assert!(issues.iter().any(|i| i.kind == EtagIssueKind::WeakEtag));
}

#[test]
fn strong_etag_not_weak() {
    let issues = analyze_etag(Some(r#""abc123""#));
    assert!(!issues.iter().any(|i| i.kind == EtagIssueKind::WeakEtag));
}

#[test]
fn long_etag_flagged() {
    let long = format!(r#""{}""#, "a".repeat(70));
    let issues = analyze_etag(Some(&long));
    assert!(issues.iter().any(|i| i.kind == EtagIssueKind::LongEtag));
}

#[test]
fn normal_length_etag_ok() {
    let issues = analyze_etag(Some(r#""abc123def456""#));
    assert!(!issues.iter().any(|i| i.kind == EtagIssueKind::LongEtag));
}

#[test]
fn three_hex_parts_is_inode() {
    let issues = analyze_etag(Some(r#""1a2b-3c4d-5e6f""#));
    assert!(issues.iter().any(|i| i.kind == EtagIssueKind::InodeLeak));
}

#[test]
fn non_hex_parts_not_inode() {
    let issues = analyze_etag(Some(r#""hello-world-foo""#));
    assert!(!issues.iter().any(|i| i.kind == EtagIssueKind::InodeLeak));
}

#[test]
fn two_parts_not_inode() {
    let issues = analyze_etag(Some(r#""abc-def""#));
    assert!(!issues.iter().any(|i| i.kind == EtagIssueKind::InodeLeak));
}

#[test]
fn operations_empty_on_no_issues() {
    let mut seq = 0;
    let ops = etag_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_produced_on_issues() {
    let issues = analyze_etag(Some(r#""5f3a1b-264-5e8c4a0e""#));
    let mut seq = 5;
    let ops = etag_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 6);
}
