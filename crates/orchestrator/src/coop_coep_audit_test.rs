use crate::coop_coep_audit::{CoopCoepIssueKind, analyze_coop_coep, coop_coep_to_operations};

#[test]
fn both_missing() {
    let issues = analyze_coop_coep(None, None);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == CoopCoepIssueKind::MissingCoop)
    );
    assert!(
        issues
            .iter()
            .any(|i| i.kind == CoopCoepIssueKind::MissingCoep)
    );
}

#[test]
fn coop_present_coep_missing() {
    let issues = analyze_coop_coep(Some("same-origin"), None);
    assert!(
        !issues
            .iter()
            .any(|i| i.kind == CoopCoepIssueKind::MissingCoop)
    );
    assert!(
        issues
            .iter()
            .any(|i| i.kind == CoopCoepIssueKind::MissingCoep)
    );
}

#[test]
fn coep_present_coop_missing() {
    let issues = analyze_coop_coep(None, Some("require-corp"));
    assert!(
        issues
            .iter()
            .any(|i| i.kind == CoopCoepIssueKind::MissingCoop)
    );
    assert!(
        !issues
            .iter()
            .any(|i| i.kind == CoopCoepIssueKind::MissingCoep)
    );
}

#[test]
fn both_present_safe() {
    let issues = analyze_coop_coep(Some("same-origin"), Some("require-corp"));
    assert!(issues.is_empty());
}

#[test]
fn coop_unsafe_none() {
    let issues = analyze_coop_coep(Some("unsafe-none"), Some("require-corp"));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, CoopCoepIssueKind::UnsafeCoop);
}

#[test]
fn coep_unsafe_none() {
    let issues = analyze_coop_coep(Some("same-origin"), Some("unsafe-none"));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, CoopCoepIssueKind::UnsafeCoep);
}

#[test]
fn both_unsafe_none() {
    let issues = analyze_coop_coep(Some("unsafe-none"), Some("unsafe-none"));
    assert_eq!(issues.len(), 2);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == CoopCoepIssueKind::UnsafeCoop)
    );
    assert!(
        issues
            .iter()
            .any(|i| i.kind == CoopCoepIssueKind::UnsafeCoep)
    );
}

#[test]
fn case_insensitive_unsafe_none() {
    let issues = analyze_coop_coep(Some("Unsafe-None"), Some("require-corp"));
    assert!(
        issues
            .iter()
            .any(|i| i.kind == CoopCoepIssueKind::UnsafeCoop)
    );
}

#[test]
fn same_origin_allow_popups() {
    let issues = analyze_coop_coep(Some("same-origin-allow-popups"), Some("require-corp"));
    assert!(issues.is_empty());
}

#[test]
fn credentialless_coep() {
    let issues = analyze_coop_coep(Some("same-origin"), Some("credentialless"));
    assert!(issues.is_empty());
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = coop_coep_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_for_issues() {
    let issues = analyze_coop_coep(None, None);
    let mut seq = 0;
    let ops = coop_coep_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn display_variants() {
    assert!(!format!("{}", CoopCoepIssueKind::MissingCoop).is_empty());
    assert!(!format!("{}", CoopCoepIssueKind::MissingCoep).is_empty());
    assert!(!format!("{}", CoopCoepIssueKind::UnsafeCoop).is_empty());
    assert!(!format!("{}", CoopCoepIssueKind::UnsafeCoep).is_empty());
}
