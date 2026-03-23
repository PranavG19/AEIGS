use crate::dns_prefetch_control_audit::{
    analyze_dns_prefetch_control, dns_prefetch_control_to_operations,
};

#[test]
fn no_header_no_issues() {
    let issues = analyze_dns_prefetch_control(None);
    assert!(issues.is_empty());
}

#[test]
fn on_is_flagged() {
    let issues = analyze_dns_prefetch_control(Some("on"));
    assert_eq!(issues.len(), 1);
    assert!(issues[0].severity >= 2.0);
}

#[test]
fn off_is_safe() {
    let issues = analyze_dns_prefetch_control(Some("off"));
    assert!(issues.is_empty());
}

#[test]
fn case_insensitive() {
    let issues = analyze_dns_prefetch_control(Some("ON"));
    assert_eq!(issues.len(), 1);
}

#[test]
fn invalid_value_flagged() {
    let issues = analyze_dns_prefetch_control(Some("maybe"));
    assert_eq!(issues.len(), 1);
    assert!(issues[0].severity < 2.0);
}

#[test]
fn whitespace_trimmed() {
    let issues = analyze_dns_prefetch_control(Some("  off  "));
    assert!(issues.is_empty());
}

#[test]
fn operations_empty_on_no_issues() {
    let mut seq = 0;
    let ops = dns_prefetch_control_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_produced_on_issues() {
    let issues = analyze_dns_prefetch_control(Some("on"));
    let mut seq = 5;
    let ops = dns_prefetch_control_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 6);
}
