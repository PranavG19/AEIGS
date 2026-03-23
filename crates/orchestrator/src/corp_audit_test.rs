use crate::corp_audit::*;

#[test]
fn no_headers_reports_missing_corp_coep_coop() {
    let issues = analyze_corp(&[]);
    assert_eq!(issues.len(), 3);
    assert!(issues.contains(&CorpIssue::Missing));
    assert!(issues.contains(&CorpIssue::MissingCoep));
    assert!(issues.contains(&CorpIssue::MissingCoop));
}

#[test]
fn corp_same_origin_no_corp_issue() {
    let headers = [("cross-origin-resource-policy", "same-origin")];
    let issues = analyze_corp(&headers);
    assert!(!issues.iter().any(|i| matches!(
        i,
        CorpIssue::Missing | CorpIssue::CrossOrigin | CorpIssue::InvalidValue { .. }
    )));
}

#[test]
fn corp_same_site_no_corp_issue() {
    let headers = [("cross-origin-resource-policy", "same-site")];
    let issues = analyze_corp(&headers);
    assert!(!issues.iter().any(|i| matches!(
        i,
        CorpIssue::Missing | CorpIssue::CrossOrigin | CorpIssue::InvalidValue { .. }
    )));
}

#[test]
fn corp_cross_origin_flagged() {
    let headers = [("cross-origin-resource-policy", "cross-origin")];
    let issues = analyze_corp(&headers);
    assert!(issues.contains(&CorpIssue::CrossOrigin));
}

#[test]
fn corp_invalid_value_flagged() {
    let headers = [("cross-origin-resource-policy", "allow-all")];
    let issues = analyze_corp(&headers);
    assert!(issues.contains(&CorpIssue::InvalidValue {
        value: "allow-all".to_string(),
    }));
}

#[test]
fn corp_case_insensitive() {
    let headers = [("cross-origin-resource-policy", "Same-Origin")];
    let issues = analyze_corp(&headers);
    assert!(!issues.iter().any(|i| matches!(
        i,
        CorpIssue::Missing | CorpIssue::CrossOrigin | CorpIssue::InvalidValue { .. }
    )));
}

#[test]
fn corp_whitespace_trimmed() {
    let headers = [("cross-origin-resource-policy", "  same-origin  ")];
    let issues = analyze_corp(&headers);
    assert!(!issues.iter().any(|i| matches!(
        i,
        CorpIssue::Missing | CorpIssue::CrossOrigin | CorpIssue::InvalidValue { .. }
    )));
}

#[test]
fn header_name_case_insensitive() {
    let headers = [("Cross-Origin-Resource-Policy", "same-origin")];
    let issues = analyze_corp(&headers);
    assert!(!issues.contains(&CorpIssue::Missing));
}

#[test]
fn coep_require_corp_no_issue() {
    let headers = [("cross-origin-embedder-policy", "require-corp")];
    let issues = analyze_corp(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CorpIssue::MissingCoep | CorpIssue::PermissiveCoep))
    );
}

#[test]
fn coep_credentialless_no_issue() {
    let headers = [("cross-origin-embedder-policy", "credentialless")];
    let issues = analyze_corp(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CorpIssue::MissingCoep | CorpIssue::PermissiveCoep))
    );
}

#[test]
fn coep_unsafe_none_permissive() {
    let headers = [("cross-origin-embedder-policy", "unsafe-none")];
    let issues = analyze_corp(&headers);
    assert!(issues.contains(&CorpIssue::PermissiveCoep));
}

#[test]
fn coep_missing_flagged() {
    let issues = analyze_corp(&[]);
    assert!(issues.contains(&CorpIssue::MissingCoep));
}

#[test]
fn coop_same_origin_no_issue() {
    let headers = [("cross-origin-opener-policy", "same-origin")];
    let issues = analyze_corp(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CorpIssue::MissingCoop | CorpIssue::UnsafeCoop { .. }))
    );
}

#[test]
fn coop_same_origin_allow_popups_no_issue() {
    let headers = [("cross-origin-opener-policy", "same-origin-allow-popups")];
    let issues = analyze_corp(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CorpIssue::MissingCoop | CorpIssue::UnsafeCoop { .. }))
    );
}

#[test]
fn coop_unsafe_none_flagged() {
    let headers = [("cross-origin-opener-policy", "unsafe-none")];
    let issues = analyze_corp(&headers);
    assert!(issues.contains(&CorpIssue::UnsafeCoop {
        value: "unsafe-none".to_string(),
    }));
}

#[test]
fn coop_missing_flagged() {
    let issues = analyze_corp(&[]);
    assert!(issues.contains(&CorpIssue::MissingCoop));
}

#[test]
fn inconsistent_policies_detected() {
    let headers = [
        ("cross-origin-resource-policy", "same-origin"),
        ("cross-origin-embedder-policy", "unsafe-none"),
    ];
    let issues = analyze_corp(&headers);
    assert!(issues.contains(&CorpIssue::InconsistentPolicies {
        corp: "same-origin".to_string(),
        coep: "unsafe-none".to_string(),
    }));
}

#[test]
fn inconsistent_not_triggered_when_coep_safe() {
    let headers = [
        ("cross-origin-resource-policy", "same-origin"),
        ("cross-origin-embedder-policy", "require-corp"),
    ];
    let issues = analyze_corp(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CorpIssue::InconsistentPolicies { .. }))
    );
}

#[test]
fn inconsistent_not_triggered_when_corp_not_same_origin() {
    let headers = [
        ("cross-origin-resource-policy", "cross-origin"),
        ("cross-origin-embedder-policy", "unsafe-none"),
    ];
    let issues = analyze_corp(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CorpIssue::InconsistentPolicies { .. }))
    );
}

#[test]
fn all_three_headers_properly_set() {
    let headers = [
        ("cross-origin-resource-policy", "same-origin"),
        ("cross-origin-embedder-policy", "require-corp"),
        ("cross-origin-opener-policy", "same-origin"),
    ];
    let issues = analyze_corp(&headers);
    assert!(issues.is_empty());
}

#[test]
fn display_missing() {
    assert_eq!(format!("{}", CorpIssue::Missing), "missing_corp");
}

#[test]
fn display_cross_origin() {
    assert_eq!(format!("{}", CorpIssue::CrossOrigin), "cross_origin");
}

#[test]
fn display_invalid_value() {
    let issue = CorpIssue::InvalidValue {
        value: "allow-all".to_string(),
    };
    assert_eq!(format!("{issue}"), "invalid_value:allow-all");
}

#[test]
fn display_missing_coep() {
    assert_eq!(format!("{}", CorpIssue::MissingCoep), "missing_coep");
}

#[test]
fn display_missing_coop() {
    assert_eq!(format!("{}", CorpIssue::MissingCoop), "missing_coop");
}

#[test]
fn display_inconsistent_policies() {
    let issue = CorpIssue::InconsistentPolicies {
        corp: "same-origin".to_string(),
        coep: "unsafe-none".to_string(),
    };
    assert_eq!(
        format!("{issue}"),
        "inconsistent_policies:same-origin+unsafe-none"
    );
}

#[test]
fn display_permissive_coep() {
    assert_eq!(format!("{}", CorpIssue::PermissiveCoep), "permissive_coep");
}

#[test]
fn display_unsafe_coop() {
    let issue = CorpIssue::UnsafeCoop {
        value: "unsafe-none".to_string(),
    };
    assert_eq!(format!("{issue}"), "unsafe_coop:unsafe-none");
}

#[test]
fn severity_missing() {
    assert!((corp_severity(&CorpIssue::Missing) - 2.0).abs() < f64::EPSILON);
}

#[test]
fn severity_cross_origin() {
    assert!((corp_severity(&CorpIssue::CrossOrigin) - 3.0).abs() < f64::EPSILON);
}

#[test]
fn severity_invalid_value() {
    let issue = CorpIssue::InvalidValue {
        value: "x".to_string(),
    };
    assert!((corp_severity(&issue) - 2.5).abs() < f64::EPSILON);
}

#[test]
fn severity_missing_coep() {
    assert!((corp_severity(&CorpIssue::MissingCoep) - 2.5).abs() < f64::EPSILON);
}

#[test]
fn severity_missing_coop() {
    assert!((corp_severity(&CorpIssue::MissingCoop) - 2.5).abs() < f64::EPSILON);
}

#[test]
fn severity_inconsistent_policies() {
    let issue = CorpIssue::InconsistentPolicies {
        corp: "same-origin".to_string(),
        coep: "unsafe-none".to_string(),
    };
    assert!((corp_severity(&issue) - 4.0).abs() < f64::EPSILON);
}

#[test]
fn severity_permissive_coep() {
    assert!((corp_severity(&CorpIssue::PermissiveCoep) - 3.5).abs() < f64::EPSILON);
}

#[test]
fn severity_unsafe_coop() {
    let issue = CorpIssue::UnsafeCoop {
        value: "unsafe-none".to_string(),
    };
    assert!((corp_severity(&issue) - 3.5).abs() < f64::EPSILON);
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = corp_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_one_per_issue() {
    let issues = vec![
        CorpIssue::Missing,
        CorpIssue::MissingCoep,
        CorpIssue::MissingCoop,
    ];
    let mut seq = 0;
    let ops = corp_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn operations_sequence_increments() {
    let issues = vec![CorpIssue::CrossOrigin, CorpIssue::PermissiveCoep];
    let mut seq = 10;
    let ops = corp_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 12);
}

#[test]
fn coep_case_insensitive() {
    let headers = [("cross-origin-embedder-policy", "Require-Corp")];
    let issues = analyze_corp(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CorpIssue::MissingCoep | CorpIssue::PermissiveCoep))
    );
}

#[test]
fn coop_case_insensitive() {
    let headers = [("cross-origin-opener-policy", "Same-Origin")];
    let issues = analyze_corp(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CorpIssue::MissingCoop | CorpIssue::UnsafeCoop { .. }))
    );
}
