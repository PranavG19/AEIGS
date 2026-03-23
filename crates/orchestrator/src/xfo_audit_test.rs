use crate::xfo_audit::*;

#[test]
fn deny_is_safe() {
    let issues = analyze_xfo(&["DENY".to_string()]);
    assert!(issues.is_empty());
}

#[test]
fn sameorigin_is_safe() {
    let issues = analyze_xfo(&["SAMEORIGIN".to_string()]);
    assert!(issues.is_empty());
}

#[test]
fn case_insensitive_deny() {
    let issues = analyze_xfo(&["deny".to_string()]);
    assert!(issues.is_empty());
}

#[test]
fn case_insensitive_sameorigin() {
    let issues = analyze_xfo(&["sameorigin".to_string()]);
    assert!(issues.is_empty());
}

#[test]
fn allowall_detected() {
    let issues = analyze_xfo(&["ALLOWALL".to_string()]);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, XfoIssueKind::AllowAll);
    assert_eq!(issues[0].severity, 6.0);
}

#[test]
fn allow_from_deprecated() {
    let issues = analyze_xfo(&["ALLOW-FROM https://example.com".to_string()]);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, XfoIssueKind::AllowFromDeprecated);
}

#[test]
fn invalid_value_flagged() {
    let issues = analyze_xfo(&["SOMETHING-ELSE".to_string()]);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, XfoIssueKind::InvalidValue);
}

#[test]
fn multiple_headers_flagged() {
    let issues = analyze_xfo(&["DENY".to_string(), "SAMEORIGIN".to_string()]);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == XfoIssueKind::MultipleHeaders)
    );
}

#[test]
fn multiple_with_bad_value() {
    let issues = analyze_xfo(&["DENY".to_string(), "ALLOWALL".to_string()]);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == XfoIssueKind::MultipleHeaders)
    );
    assert!(issues.iter().any(|i| i.kind == XfoIssueKind::AllowAll));
}

#[test]
fn empty_values_no_issues() {
    let issues = analyze_xfo(&[]);
    assert!(issues.is_empty());
}

#[test]
fn whitespace_trimmed() {
    let issues = analyze_xfo(&["  DENY  ".to_string()]);
    assert!(issues.is_empty());
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = xfo_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_for_issues() {
    let issues = analyze_xfo(&["ALLOWALL".to_string()]);
    let mut seq = 0;
    let ops = xfo_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn display_variants() {
    assert!(!format!("{}", XfoIssueKind::AllowAll).is_empty());
    assert!(!format!("{}", XfoIssueKind::InvalidValue).is_empty());
    assert!(!format!("{}", XfoIssueKind::AllowFromDeprecated).is_empty());
    assert!(!format!("{}", XfoIssueKind::MultipleHeaders).is_empty());
}

#[test]
fn missing_xfo_detected() {
    let issues = analyze_xfo_security(&[], None, false);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], XfoSecurityIssue::MissingXfo);
}

#[test]
fn missing_xfo_severity() {
    let sev = xfo_security_severity(&XfoSecurityIssue::MissingXfo);
    assert_eq!(sev, 5.0);
}

#[test]
fn xfo_with_csp_frame_ancestors() {
    let issues = analyze_xfo_security(&["DENY".to_string()], Some("frame-ancestors 'none'"), false);
    assert!(issues.contains(&XfoSecurityIssue::XfoWithCspFrameAncestors));
}

#[test]
fn xfo_with_csp_case_insensitive() {
    let issues = analyze_xfo_security(&["deny".to_string()], Some("FRAME-ANCESTORS 'none'"), false);
    assert!(issues.contains(&XfoSecurityIssue::XfoWithCspFrameAncestors));
}

#[test]
fn allow_from_wildcard_asterisk() {
    let issues = analyze_xfo_security(&["ALLOW-FROM *".to_string()], None, false);
    assert!(issues.contains(&XfoSecurityIssue::AllowFromWildcard));
}

#[test]
fn allow_from_wildcard_http() {
    let issues = analyze_xfo_security(&["ALLOW-FROM http://example.com".to_string()], None, false);
    assert!(issues.contains(&XfoSecurityIssue::AllowFromWildcard));
}

#[test]
fn allow_from_multiple_origins_comma() {
    let issues = analyze_xfo_security(
        &["ALLOW-FROM https://a.com, https://b.com".to_string()],
        None,
        false,
    );
    assert!(issues.contains(&XfoSecurityIssue::AllowFromMultipleOrigins));
}

#[test]
fn allow_from_multiple_origins_space() {
    let issues = analyze_xfo_security(
        &["ALLOW-FROM https://a.com https://b.com".to_string()],
        None,
        false,
    );
    assert!(issues.contains(&XfoSecurityIssue::AllowFromMultipleOrigins));
}

#[test]
fn allow_from_single_origin_safe() {
    let issues = analyze_xfo_security(&["ALLOW-FROM https://example.com".to_string()], None, false);
    assert!(!issues.contains(&XfoSecurityIssue::AllowFromMultipleOrigins));
}

#[test]
fn sameorigin_double_framing_vuln() {
    let issues = analyze_xfo_security(&["SAMEORIGIN".to_string()], None, false);
    assert!(issues.contains(&XfoSecurityIssue::XfoBypassViaDoubleFraming));
}

#[test]
fn deny_no_double_framing() {
    let issues = analyze_xfo_security(&["DENY".to_string()], None, false);
    assert!(!issues.contains(&XfoSecurityIssue::XfoBypassViaDoubleFraming));
}

#[test]
fn xfo_with_permissive_csp_wildcard() {
    let issues = analyze_xfo_security(&["DENY".to_string()], Some("frame-ancestors *"), false);
    assert!(issues.contains(&XfoSecurityIssue::XfoWithPermissiveCSP));
}

#[test]
fn xfo_with_permissive_csp_missing_none() {
    let issues = analyze_xfo_security(
        &["DENY".to_string()],
        Some("frame-ancestors https://example.com"),
        false,
    );
    assert!(issues.contains(&XfoSecurityIssue::XfoWithPermissiveCSP));
}

#[test]
fn xfo_deny_with_strict_csp_no_issue() {
    let issues = analyze_xfo_security(&["DENY".to_string()], Some("frame-ancestors 'none'"), false);
    assert!(!issues.contains(&XfoSecurityIssue::XfoWithPermissiveCSP));
}

#[test]
fn xfo_on_api_endpoint() {
    let issues = analyze_xfo_security(&["DENY".to_string()], None, true);
    assert!(issues.contains(&XfoSecurityIssue::XfoOnApiEndpoint));
}

#[test]
fn xfo_on_non_api_no_issue() {
    let issues = analyze_xfo_security(&["DENY".to_string()], None, false);
    assert!(!issues.contains(&XfoSecurityIssue::XfoOnApiEndpoint));
}

#[test]
fn xfo_weaker_than_csp() {
    let issues = analyze_xfo_security(
        &["SAMEORIGIN".to_string()],
        Some("frame-ancestors 'none'"),
        false,
    );
    assert!(issues.contains(&XfoSecurityIssue::XfoWeakerThanCSP));
}

#[test]
fn xfo_deny_with_strict_csp_consistent() {
    let issues = analyze_xfo_security(&["DENY".to_string()], Some("frame-ancestors 'none'"), false);
    assert!(!issues.contains(&XfoSecurityIssue::XfoWeakerThanCSP));
}

#[test]
fn inconsistent_xfo_across_pages() {
    let issues = analyze_xfo_security(&["DENY".to_string(), "SAMEORIGIN".to_string()], None, false);
    assert!(issues.contains(&XfoSecurityIssue::XfoInconsistentAcrossPages));
}

#[test]
fn consistent_deny_no_issue() {
    let issues = analyze_xfo_security(&["DENY".to_string(), "DENY".to_string()], None, false);
    assert!(!issues.contains(&XfoSecurityIssue::XfoInconsistentAcrossPages));
}

#[test]
fn missing_same_origin_policy_with_sameorigin() {
    let issues = analyze_xfo_security(&["SAMEORIGIN".to_string()], None, false);
    assert!(issues.contains(&XfoSecurityIssue::XfoMissingSameOriginPolicy));
}

#[test]
fn missing_same_origin_policy_with_allow_from() {
    let issues = analyze_xfo_security(&["ALLOW-FROM https://example.com".to_string()], None, false);
    assert!(issues.contains(&XfoSecurityIssue::XfoMissingSameOriginPolicy));
}

#[test]
fn deny_satisfies_same_origin_policy() {
    let issues = analyze_xfo_security(&["DENY".to_string()], None, false);
    assert!(!issues.contains(&XfoSecurityIssue::XfoMissingSameOriginPolicy));
}

#[test]
fn security_issue_display_all_variants() {
    assert!(!format!("{}", XfoSecurityIssue::MissingXfo).is_empty());
    assert!(!format!("{}", XfoSecurityIssue::XfoWithCspFrameAncestors).is_empty());
    assert!(!format!("{}", XfoSecurityIssue::AllowFromWildcard).is_empty());
    assert!(!format!("{}", XfoSecurityIssue::AllowFromMultipleOrigins).is_empty());
    assert!(!format!("{}", XfoSecurityIssue::XfoBypassViaDoubleFraming).is_empty());
    assert!(!format!("{}", XfoSecurityIssue::XfoWithPermissiveCSP).is_empty());
    assert!(!format!("{}", XfoSecurityIssue::XfoOnApiEndpoint).is_empty());
    assert!(!format!("{}", XfoSecurityIssue::XfoWeakerThanCSP).is_empty());
    assert!(!format!("{}", XfoSecurityIssue::XfoInconsistentAcrossPages).is_empty());
    assert!(!format!("{}", XfoSecurityIssue::XfoMissingSameOriginPolicy).is_empty());
}

#[test]
fn all_severity_values_correct() {
    assert_eq!(xfo_security_severity(&XfoSecurityIssue::MissingXfo), 5.0);
    assert_eq!(
        xfo_security_severity(&XfoSecurityIssue::XfoWithCspFrameAncestors),
        2.0
    );
    assert_eq!(
        xfo_security_severity(&XfoSecurityIssue::AllowFromWildcard),
        7.0
    );
    assert_eq!(
        xfo_security_severity(&XfoSecurityIssue::AllowFromMultipleOrigins),
        5.5
    );
    assert_eq!(
        xfo_security_severity(&XfoSecurityIssue::XfoBypassViaDoubleFraming),
        6.0
    );
    assert_eq!(
        xfo_security_severity(&XfoSecurityIssue::XfoWithPermissiveCSP),
        6.5
    );
    assert_eq!(
        xfo_security_severity(&XfoSecurityIssue::XfoOnApiEndpoint),
        2.5
    );
    assert_eq!(
        xfo_security_severity(&XfoSecurityIssue::XfoWeakerThanCSP),
        4.0
    );
    assert_eq!(
        xfo_security_severity(&XfoSecurityIssue::XfoInconsistentAcrossPages),
        4.5
    );
    assert_eq!(
        xfo_security_severity(&XfoSecurityIssue::XfoMissingSameOriginPolicy),
        3.5
    );
}

#[test]
fn security_operations_empty_for_no_issues() {
    let mut seq = 0;
    let ops = xfo_security_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn security_operations_produced() {
    let issues = vec![XfoSecurityIssue::MissingXfo];
    let mut seq = 0;
    let ops = xfo_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn security_operations_max_severity() {
    let issues = vec![
        XfoSecurityIssue::XfoWithCspFrameAncestors,
        XfoSecurityIssue::AllowFromWildcard,
    ];
    let mut seq = 0;
    let ops = xfo_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
}

#[test]
fn complex_scenario_multiple_issues() {
    let issues = analyze_xfo_security(
        &["SAMEORIGIN".to_string()],
        Some("frame-ancestors 'none'"),
        true,
    );
    assert!(issues.contains(&XfoSecurityIssue::XfoBypassViaDoubleFraming));
    assert!(issues.contains(&XfoSecurityIssue::XfoWeakerThanCSP));
    assert!(issues.contains(&XfoSecurityIssue::XfoOnApiEndpoint));
    assert!(issues.contains(&XfoSecurityIssue::XfoMissingSameOriginPolicy));
}

#[test]
fn no_csp_no_csp_related_issues() {
    let issues = analyze_xfo_security(&["DENY".to_string()], None, false);
    assert!(!issues.contains(&XfoSecurityIssue::XfoWithCspFrameAncestors));
    assert!(!issues.contains(&XfoSecurityIssue::XfoWithPermissiveCSP));
    assert!(!issues.contains(&XfoSecurityIssue::XfoWeakerThanCSP));
}

#[test]
fn case_normalization_in_analysis() {
    let issues = analyze_xfo_security(&["DenY".to_string()], None, false);
    assert!(!issues.contains(&XfoSecurityIssue::XfoMissingSameOriginPolicy));
}

#[test]
fn whitespace_trimmed_in_analysis() {
    let issues = analyze_xfo_security(&["  DENY  ".to_string()], None, false);
    assert!(!issues.contains(&XfoSecurityIssue::XfoMissingSameOriginPolicy));
}

#[test]
fn allow_from_edge_case_single_space() {
    let issues = analyze_xfo_security(
        &["ALLOW-FROM https://example.com ".to_string()],
        None,
        false,
    );
    assert!(!issues.contains(&XfoSecurityIssue::AllowFromMultipleOrigins));
}

#[test]
fn csp_without_frame_ancestors_no_redundancy() {
    let issues = analyze_xfo_security(&["DENY".to_string()], Some("default-src 'self'"), false);
    assert!(!issues.contains(&XfoSecurityIssue::XfoWithCspFrameAncestors));
}

#[test]
fn allow_from_http_lowercase() {
    let issues = analyze_xfo_security(&["allow-from http://example.com".to_string()], None, false);
    assert!(issues.contains(&XfoSecurityIssue::AllowFromWildcard));
}

#[test]
fn multiple_xfo_values_both_sameorigin() {
    let issues = analyze_xfo_security(
        &["SAMEORIGIN".to_string(), "sameorigin".to_string()],
        None,
        false,
    );
    assert!(issues.contains(&XfoSecurityIssue::XfoBypassViaDoubleFraming));
    assert!(!issues.contains(&XfoSecurityIssue::XfoInconsistentAcrossPages));
}

#[test]
fn empty_xfo_returns_only_missing() {
    let issues = analyze_xfo_security(&[], Some("frame-ancestors 'none'"), true);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], XfoSecurityIssue::MissingXfo);
}

#[test]
fn csp_frame_ancestors_partial_match() {
    let issues = analyze_xfo_security(
        &["DENY".to_string()],
        Some("default-src 'self'; frame-ancestors https://example.com"),
        false,
    );
    assert!(issues.contains(&XfoSecurityIssue::XfoWithCspFrameAncestors));
}

#[test]
fn sameorigin_with_no_csp_multiple_issues() {
    let issues = analyze_xfo_security(&["SAMEORIGIN".to_string()], None, false);
    assert!(issues.contains(&XfoSecurityIssue::XfoBypassViaDoubleFraming));
    assert!(issues.contains(&XfoSecurityIssue::XfoMissingSameOriginPolicy));
    assert!(!issues.contains(&XfoSecurityIssue::XfoWeakerThanCSP));
}

#[test]
fn allow_from_with_trailing_comma() {
    let issues = analyze_xfo_security(&["ALLOW-FROM https://a.com,".to_string()], None, false);
    assert!(issues.contains(&XfoSecurityIssue::AllowFromMultipleOrigins));
}

#[test]
fn deny_on_api_endpoint_no_overhead_issue() {
    let issues = analyze_xfo_security(&["DENY".to_string()], None, true);
    assert!(issues.contains(&XfoSecurityIssue::XfoOnApiEndpoint));
    assert!(!issues.contains(&XfoSecurityIssue::XfoBypassViaDoubleFraming));
}

#[test]
fn mixed_deny_and_allow_from() {
    let issues = analyze_xfo_security(
        &[
            "DENY".to_string(),
            "ALLOW-FROM https://example.com".to_string(),
        ],
        None,
        false,
    );
    assert!(!issues.contains(&XfoSecurityIssue::XfoMissingSameOriginPolicy));
}

#[test]
fn csp_with_multiple_frame_ancestor_values() {
    let issues = analyze_xfo_security(
        &["SAMEORIGIN".to_string()],
        Some("frame-ancestors 'self' https://example.com"),
        false,
    );
    assert!(issues.contains(&XfoSecurityIssue::XfoWithCspFrameAncestors));
    assert!(issues.contains(&XfoSecurityIssue::XfoBypassViaDoubleFraming));
}

#[test]
fn xfo_severity_ordering() {
    let wildcard_sev = xfo_security_severity(&XfoSecurityIssue::AllowFromWildcard);
    let permissive_csp_sev = xfo_security_severity(&XfoSecurityIssue::XfoWithPermissiveCSP);
    let double_framing_sev = xfo_security_severity(&XfoSecurityIssue::XfoBypassViaDoubleFraming);
    let missing_sev = xfo_security_severity(&XfoSecurityIssue::MissingXfo);

    assert!(wildcard_sev > permissive_csp_sev);
    assert!(permissive_csp_sev > double_framing_sev);
    assert!(double_framing_sev > missing_sev);
}

#[test]
fn operations_sequence_increments() {
    let issues = vec![XfoSecurityIssue::MissingXfo];
    let mut seq = 42;
    let ops = xfo_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 43);
}

#[test]
fn wildcard_asterisk_only() {
    let issues = analyze_xfo_security(&["ALLOW-FROM *".to_string()], None, false);
    assert!(issues.contains(&XfoSecurityIssue::AllowFromWildcard));
    assert!(!issues.contains(&XfoSecurityIssue::AllowFromMultipleOrigins));
}
