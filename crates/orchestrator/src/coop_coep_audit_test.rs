use crate::coop_coep_audit::*;

// ===== ORIGINAL 13 TESTS (PRESERVED EXACTLY) =====

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

// ===== NEW TESTS FOR CrossOriginIssue =====

// Display variant tests (12 tests)

#[test]
fn display_missing_coop() {
    assert_eq!(format!("{}", CrossOriginIssue::MissingCoop), "missing_coop");
}

#[test]
fn display_missing_coep() {
    assert_eq!(format!("{}", CrossOriginIssue::MissingCoep), "missing_coep");
}

#[test]
fn display_missing_corp() {
    assert_eq!(format!("{}", CrossOriginIssue::MissingCorp), "missing_corp");
}

#[test]
fn display_unsafe_none_coop() {
    assert_eq!(
        format!("{}", CrossOriginIssue::UnsafeNoneCoop),
        "unsafe_none_coop"
    );
}

#[test]
fn display_unsafe_none_coep() {
    assert_eq!(
        format!("{}", CrossOriginIssue::UnsafeNoneCoep),
        "unsafe_none_coep"
    );
}

#[test]
fn display_weak_coop() {
    let issue = CrossOriginIssue::WeakCoop {
        value: "same-origin-allow-popups".to_string(),
    };
    assert_eq!(format!("{}", issue), "weak_coop:same-origin-allow-popups");
}

#[test]
fn display_weak_coep() {
    let issue = CrossOriginIssue::WeakCoep {
        value: "credentialless".to_string(),
    };
    assert_eq!(format!("{}", issue), "weak_coep:credentialless");
}

#[test]
fn display_inconsistent_policies() {
    let issue = CrossOriginIssue::InconsistentPolicies {
        coop: "same-origin".to_string(),
        coep: "credentialless".to_string(),
    };
    assert_eq!(
        format!("{}", issue),
        "inconsistent_policies:same-origin:credentialless"
    );
}

#[test]
fn display_missing_reporting_endpoint() {
    let issue = CrossOriginIssue::MissingReportingEndpoint {
        header: "cross-origin-opener-policy".to_string(),
    };
    assert_eq!(
        format!("{}", issue),
        "missing_reporting:cross-origin-opener-policy"
    );
}

#[test]
fn display_report_only_coop() {
    assert_eq!(
        format!("{}", CrossOriginIssue::ReportOnlyCoop),
        "report_only_coop"
    );
}

#[test]
fn display_report_only_coep() {
    assert_eq!(
        format!("{}", CrossOriginIssue::ReportOnlyCoep),
        "report_only_coep"
    );
}

#[test]
fn display_no_isolation() {
    assert_eq!(
        format!("{}", CrossOriginIssue::NoIsolation),
        "no_cross_origin_isolation"
    );
}

// Severity tests (12 tests)

#[test]
fn severity_unsafe_none_coop() {
    assert_eq!(
        cross_origin_severity(&CrossOriginIssue::UnsafeNoneCoop),
        6.0
    );
}

#[test]
fn severity_unsafe_none_coep() {
    assert_eq!(
        cross_origin_severity(&CrossOriginIssue::UnsafeNoneCoep),
        5.5
    );
}

#[test]
fn severity_no_isolation() {
    assert_eq!(cross_origin_severity(&CrossOriginIssue::NoIsolation), 5.0);
}

#[test]
fn severity_inconsistent_policies() {
    let issue = CrossOriginIssue::InconsistentPolicies {
        coop: "same-origin".to_string(),
        coep: "credentialless".to_string(),
    };
    assert_eq!(cross_origin_severity(&issue), 5.0);
}

#[test]
fn severity_missing_coop() {
    assert_eq!(cross_origin_severity(&CrossOriginIssue::MissingCoop), 4.0);
}

#[test]
fn severity_missing_coep() {
    assert_eq!(cross_origin_severity(&CrossOriginIssue::MissingCoep), 3.5);
}

#[test]
fn severity_missing_corp() {
    assert_eq!(cross_origin_severity(&CrossOriginIssue::MissingCorp), 3.5);
}

#[test]
fn severity_weak_coop() {
    let issue = CrossOriginIssue::WeakCoop {
        value: "same-origin-allow-popups".to_string(),
    };
    assert_eq!(cross_origin_severity(&issue), 4.5);
}

#[test]
fn severity_weak_coep() {
    let issue = CrossOriginIssue::WeakCoep {
        value: "credentialless".to_string(),
    };
    assert_eq!(cross_origin_severity(&issue), 4.0);
}

#[test]
fn severity_report_only_coop() {
    assert_eq!(
        cross_origin_severity(&CrossOriginIssue::ReportOnlyCoop),
        3.0
    );
}

#[test]
fn severity_report_only_coep() {
    assert_eq!(
        cross_origin_severity(&CrossOriginIssue::ReportOnlyCoep),
        3.0
    );
}

#[test]
fn severity_missing_reporting_endpoint() {
    let issue = CrossOriginIssue::MissingReportingEndpoint {
        header: "cross-origin-opener-policy".to_string(),
    };
    assert_eq!(cross_origin_severity(&issue), 2.0);
}

// analyze_cross_origin_headers tests (26 tests)

#[test]
fn cross_origin_missing_all_headers() {
    let headers = [];
    let issues = analyze_cross_origin_headers(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::MissingCoop))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::MissingCoep))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::MissingCorp))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::NoIsolation))
    );
}

#[test]
fn cross_origin_coop_present_coep_missing() {
    let headers = [("cross-origin-opener-policy", "same-origin")];
    let issues = analyze_cross_origin_headers(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::MissingCoop))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::MissingCoep))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::MissingCorp))
    );
}

#[test]
fn cross_origin_coep_present_coop_missing() {
    let headers = [("cross-origin-embedder-policy", "require-corp")];
    let issues = analyze_cross_origin_headers(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::MissingCoop))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::MissingCoep))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::MissingCorp))
    );
}

#[test]
fn cross_origin_all_strong_policies() {
    let headers = [
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-embedder-policy", "require-corp"),
        ("cross-origin-resource-policy", "same-origin"),
    ];
    let issues = analyze_cross_origin_headers(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::MissingCoop))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::MissingCoep))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::MissingCorp))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::NoIsolation))
    );
}

#[test]
fn cross_origin_unsafe_none_coop_detected() {
    let headers = [
        ("cross-origin-opener-policy", "unsafe-none"),
        ("cross-origin-embedder-policy", "require-corp"),
    ];
    let issues = analyze_cross_origin_headers(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::UnsafeNoneCoop))
    );
}

#[test]
fn cross_origin_unsafe_none_coep_detected() {
    let headers = [
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-embedder-policy", "unsafe-none"),
    ];
    let issues = analyze_cross_origin_headers(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::UnsafeNoneCoep))
    );
}

#[test]
fn cross_origin_both_unsafe_none() {
    let headers = [
        ("cross-origin-opener-policy", "unsafe-none"),
        ("cross-origin-embedder-policy", "unsafe-none"),
    ];
    let issues = analyze_cross_origin_headers(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::UnsafeNoneCoop))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::UnsafeNoneCoep))
    );
}

#[test]
fn cross_origin_weak_coop_allow_popups() {
    let headers = [
        ("cross-origin-opener-policy", "same-origin-allow-popups"),
        ("cross-origin-embedder-policy", "require-corp"),
    ];
    let issues = analyze_cross_origin_headers(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::WeakCoop { .. }))
    );
}

#[test]
fn cross_origin_weak_coep_credentialless() {
    let headers = [
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-embedder-policy", "credentialless"),
    ];
    let issues = analyze_cross_origin_headers(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::WeakCoep { .. }))
    );
}

#[test]
fn cross_origin_missing_corp() {
    let headers = [
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-embedder-policy", "require-corp"),
    ];
    let issues = analyze_cross_origin_headers(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::MissingCorp))
    );
}

#[test]
fn cross_origin_corp_present_same_origin() {
    let headers = [
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-embedder-policy", "require-corp"),
        ("cross-origin-resource-policy", "same-origin"),
    ];
    let issues = analyze_cross_origin_headers(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::MissingCorp))
    );
}

#[test]
fn cross_origin_corp_present_cross_origin() {
    let headers = [
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-embedder-policy", "require-corp"),
        ("cross-origin-resource-policy", "cross-origin"),
    ];
    let issues = analyze_cross_origin_headers(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::MissingCorp))
    );
}

#[test]
fn cross_origin_inconsistent_strong_coop_weak_coep() {
    let headers = [
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-embedder-policy", "credentialless"),
    ];
    let issues = analyze_cross_origin_headers(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::InconsistentPolicies { .. }))
    );
}

#[test]
fn cross_origin_inconsistent_weak_coop_strong_coep() {
    let headers = [
        ("cross-origin-opener-policy", "same-origin-allow-popups"),
        ("cross-origin-embedder-policy", "require-corp"),
    ];
    let issues = analyze_cross_origin_headers(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::InconsistentPolicies { .. }))
    );
}

#[test]
fn cross_origin_consistent_both_weak_no_inconsistent() {
    let headers = [
        ("cross-origin-opener-policy", "same-origin-allow-popups"),
        ("cross-origin-embedder-policy", "credentialless"),
    ];
    let issues = analyze_cross_origin_headers(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::InconsistentPolicies { .. }))
    );
}

#[test]
fn cross_origin_no_isolation_both_missing() {
    let headers = [];
    let issues = analyze_cross_origin_headers(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::NoIsolation))
    );
}

#[test]
fn cross_origin_no_isolation_coop_only() {
    let headers = [("cross-origin-opener-policy", "same-origin")];
    let issues = analyze_cross_origin_headers(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::NoIsolation))
    );
}

#[test]
fn cross_origin_full_isolation() {
    let headers = [
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-embedder-policy", "require-corp"),
    ];
    let issues = analyze_cross_origin_headers(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::NoIsolation))
    );
}

#[test]
fn cross_origin_report_only_coop() {
    let headers = [("cross-origin-opener-policy-report-only", "same-origin")];
    let issues = analyze_cross_origin_headers(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::ReportOnlyCoop))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::MissingCoop))
    );
}

#[test]
fn cross_origin_report_only_coep() {
    let headers = [("cross-origin-embedder-policy-report-only", "require-corp")];
    let issues = analyze_cross_origin_headers(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::ReportOnlyCoep))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::MissingCoep))
    );
}

#[test]
fn cross_origin_missing_reporting_endpoints() {
    let headers = [
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-embedder-policy", "require-corp"),
    ];
    let issues = analyze_cross_origin_headers(&headers);
    let reporting_issues: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, CrossOriginIssue::MissingReportingEndpoint { .. }))
        .collect();
    assert_eq!(reporting_issues.len(), 2);
}

#[test]
fn cross_origin_reporting_endpoints_present() {
    let headers = [
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-embedder-policy", "require-corp"),
        (
            "reporting-endpoints",
            "default=\"https://example.com/report\"",
        ),
    ];
    let issues = analyze_cross_origin_headers(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::MissingReportingEndpoint { .. }))
    );
}

#[test]
fn cross_origin_report_to_header_present() {
    let headers = [
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-embedder-policy", "require-corp"),
        ("report-to", "default"),
    ];
    let issues = analyze_cross_origin_headers(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::MissingReportingEndpoint { .. }))
    );
}

#[test]
fn cross_origin_case_insensitive_header_names() {
    let headers = [
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("CROSS-ORIGIN-EMBEDDER-POLICY", "require-corp"),
        ("cross-ORIGIN-resource-POLICY", "same-origin"),
    ];
    let issues = analyze_cross_origin_headers(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::MissingCoop))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::MissingCoep))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CrossOriginIssue::MissingCorp))
    );
}

#[test]
fn cross_origin_empty_headers() {
    let headers: [(&str, &str); 0] = [];
    let issues = analyze_cross_origin_headers(&headers);
    assert!(!issues.is_empty());
}

// cross_origin_to_operations tests (3 tests)

#[test]
fn cross_origin_ops_empty_issues() {
    let mut seq = 0;
    let ops = cross_origin_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn cross_origin_ops_single_issue() {
    let issues = vec![CrossOriginIssue::UnsafeNoneCoop];
    let mut seq = 0;
    let ops = cross_origin_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn cross_origin_ops_multiple_issues() {
    let issues = vec![
        CrossOriginIssue::UnsafeNoneCoop,
        CrossOriginIssue::MissingCoep,
        CrossOriginIssue::MissingCorp,
    ];
    let mut seq = 0;
    let ops = cross_origin_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}
