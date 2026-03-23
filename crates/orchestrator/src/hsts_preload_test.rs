use crate::hsts_preload::*;

#[test]
fn parse_hsts_issues_full_policy() {
    let issues = parse_hsts_issues("max-age=63072000; includeSubDomains; preload");
    assert!(issues.is_empty());
}

#[test]
fn parse_hsts_issues_short_max_age() {
    let issues = parse_hsts_issues("max-age=86400");
    assert!(issues.contains(&HstsIssue::ShortMaxAge(86400)));
}

#[test]
fn parse_hsts_issues_missing_includesubdomains() {
    let issues = parse_hsts_issues("max-age=63072000; preload");
    assert!(issues.contains(&HstsIssue::MissingIncludeSubDomains));
    assert!(!issues.contains(&HstsIssue::MissingPreload));
}

#[test]
fn parse_hsts_issues_missing_preload() {
    let issues = parse_hsts_issues("max-age=63072000; includeSubDomains");
    assert!(issues.contains(&HstsIssue::MissingPreload));
    assert!(!issues.contains(&HstsIssue::MissingIncludeSubDomains));
}

#[test]
fn parse_hsts_issues_minimal_valid() {
    let issues = parse_hsts_issues("max-age=31536000; includeSubDomains; preload");
    assert!(issues.is_empty());
}

#[test]
fn parse_hsts_issues_zero_max_age() {
    let issues = parse_hsts_issues("max-age=0");
    assert!(issues.contains(&HstsIssue::ShortMaxAge(0)));
}

#[test]
fn hsts_severity_ordering() {
    assert!(hsts_severity(&HstsIssue::Missing) > hsts_severity(&HstsIssue::ShortMaxAge(100)));
    assert!(
        hsts_severity(&HstsIssue::ShortMaxAge(100))
            > hsts_severity(&HstsIssue::MissingIncludeSubDomains)
    );
    assert!(
        hsts_severity(&HstsIssue::MissingIncludeSubDomains)
            > hsts_severity(&HstsIssue::MissingPreload)
    );
}

#[test]
fn hsts_issue_display() {
    assert_eq!(HstsIssue::Missing.to_string(), "missing_hsts");
    assert_eq!(
        HstsIssue::ShortMaxAge(3600).to_string(),
        "short_max_age_3600"
    );
    assert_eq!(
        HstsIssue::MissingIncludeSubDomains.to_string(),
        "missing_includesubdomains"
    );
    assert_eq!(HstsIssue::MissingPreload.to_string(), "missing_preload");
}

#[test]
fn hsts_findings_to_operations_creates_findings() {
    let issues = vec![HstsIssue::Missing, HstsIssue::MissingPreload];
    let mut seq = 0;
    let ops = hsts_findings_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn hsts_findings_missing_uses_missing_header_class() {
    let issues = vec![HstsIssue::Missing];
    let mut seq = 0;
    let ops = hsts_findings_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::MissingSecurityHeader
            );
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn hsts_findings_misconfig_uses_misconfig_class() {
    let issues = vec![HstsIssue::MissingPreload];
    let mut seq = 0;
    let ops = hsts_findings_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::SecurityMisconfiguration
            );
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn hsts_findings_to_operations_empty() {
    let mut seq = 3;
    let ops = hsts_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 3);
}

#[test]
fn check_hsts_preload_skips_localhost() {
    let issues = check_hsts_preload("http://localhost:8080");
    assert!(issues.is_empty());
}

// HstsCheckIssue Display tests (12 tests)

#[test]
fn hsts_check_issue_display_missing_header() {
    assert_eq!(HstsCheckIssue::MissingHeader.to_string(), "missing_header");
}

#[test]
fn hsts_check_issue_display_zero_max_age() {
    assert_eq!(HstsCheckIssue::ZeroMaxAge.to_string(), "zero_max_age");
}

#[test]
fn hsts_check_issue_display_short_max_age() {
    assert_eq!(
        HstsCheckIssue::ShortMaxAge { age: 86400 }.to_string(),
        "short_max_age_86400"
    );
}

#[test]
fn hsts_check_issue_display_missing_includesubdomains() {
    assert_eq!(
        HstsCheckIssue::MissingIncludeSubDomains.to_string(),
        "missing_includesubdomains"
    );
}

#[test]
fn hsts_check_issue_display_missing_preload() {
    assert_eq!(
        HstsCheckIssue::MissingPreload.to_string(),
        "missing_preload"
    );
}

#[test]
fn hsts_check_issue_display_http_redirect_without_hsts() {
    assert_eq!(
        HstsCheckIssue::HttpRedirectWithoutHsts.to_string(),
        "http_redirect_without_hsts"
    );
}

#[test]
fn hsts_check_issue_display_inconsistent_hsts() {
    assert_eq!(
        HstsCheckIssue::InconsistentHsts {
            main: "policy1".to_string(),
            sub: "policy2".to_string()
        }
        .to_string(),
        "inconsistent_hsts_main_policy1_sub_policy2"
    );
}

#[test]
fn hsts_check_issue_display_preload_without_requirements() {
    assert_eq!(
        HstsCheckIssue::PreloadWithoutRequirements.to_string(),
        "preload_without_requirements"
    );
}

#[test]
fn hsts_check_issue_display_multiple_hsts_headers() {
    assert_eq!(
        HstsCheckIssue::MultipleHstsHeaders.to_string(),
        "multiple_hsts_headers"
    );
}

#[test]
fn hsts_check_issue_display_invalid_max_age() {
    assert_eq!(
        HstsCheckIssue::InvalidMaxAge {
            value: "abc".to_string()
        }
        .to_string(),
        "invalid_max_age_abc"
    );
}

#[test]
fn hsts_check_issue_display_hsts_on_http() {
    assert_eq!(HstsCheckIssue::HstsOnHttp.to_string(), "hsts_on_http");
}

#[test]
fn hsts_check_issue_display_max_age_only() {
    assert_eq!(HstsCheckIssue::MaxAgeOnly.to_string(), "max_age_only");
}

// HstsCheckIssue Severity tests (12 tests)

#[test]
fn hsts_check_severity_missing_header() {
    assert_eq!(hsts_check_severity(&HstsCheckIssue::MissingHeader), 6.0);
}

#[test]
fn hsts_check_severity_zero_max_age() {
    assert_eq!(hsts_check_severity(&HstsCheckIssue::ZeroMaxAge), 5.5);
}

#[test]
fn hsts_check_severity_http_redirect_without_hsts() {
    assert_eq!(
        hsts_check_severity(&HstsCheckIssue::HttpRedirectWithoutHsts),
        5.5
    );
}

#[test]
fn hsts_check_severity_hsts_on_http() {
    assert_eq!(hsts_check_severity(&HstsCheckIssue::HstsOnHttp), 5.0);
}

#[test]
fn hsts_check_severity_short_max_age() {
    assert_eq!(
        hsts_check_severity(&HstsCheckIssue::ShortMaxAge { age: 1000 }),
        4.0
    );
}

#[test]
fn hsts_check_severity_invalid_max_age() {
    assert_eq!(
        hsts_check_severity(&HstsCheckIssue::InvalidMaxAge {
            value: "xyz".to_string()
        }),
        4.0
    );
}

#[test]
fn hsts_check_severity_preload_without_requirements() {
    assert_eq!(
        hsts_check_severity(&HstsCheckIssue::PreloadWithoutRequirements),
        3.5
    );
}

#[test]
fn hsts_check_severity_inconsistent_hsts() {
    assert_eq!(
        hsts_check_severity(&HstsCheckIssue::InconsistentHsts {
            main: "a".to_string(),
            sub: "b".to_string()
        }),
        3.5
    );
}

#[test]
fn hsts_check_severity_missing_includesubdomains() {
    assert_eq!(
        hsts_check_severity(&HstsCheckIssue::MissingIncludeSubDomains),
        3.0
    );
}

#[test]
fn hsts_check_severity_multiple_hsts_headers() {
    assert_eq!(
        hsts_check_severity(&HstsCheckIssue::MultipleHstsHeaders),
        3.0
    );
}

#[test]
fn hsts_check_severity_max_age_only() {
    assert_eq!(hsts_check_severity(&HstsCheckIssue::MaxAgeOnly), 2.5);
}

#[test]
fn hsts_check_severity_missing_preload() {
    assert_eq!(hsts_check_severity(&HstsCheckIssue::MissingPreload), 2.0);
}

// analyze_hsts tests (23 tests)

#[test]
fn analyze_hsts_missing_header_https() {
    let issues = analyze_hsts(None, true, false);
    assert_eq!(issues.len(), 1);
    assert!(issues.contains(&HstsCheckIssue::MissingHeader));
}

#[test]
fn analyze_hsts_missing_header_http_with_redirect() {
    let issues = analyze_hsts(None, false, true);
    assert_eq!(issues.len(), 2);
    assert!(issues.contains(&HstsCheckIssue::MissingHeader));
    assert!(issues.contains(&HstsCheckIssue::HttpRedirectWithoutHsts));
}

#[test]
fn analyze_hsts_hsts_on_http() {
    let issues = analyze_hsts(Some("max-age=31536000"), false, false);
    assert!(issues.contains(&HstsCheckIssue::HstsOnHttp));
}

#[test]
fn analyze_hsts_zero_max_age() {
    let issues = analyze_hsts(Some("max-age=0"), true, false);
    assert!(issues.contains(&HstsCheckIssue::ZeroMaxAge));
}

#[test]
fn analyze_hsts_short_max_age() {
    let issues = analyze_hsts(Some("max-age=86400"), true, false);
    assert!(issues.contains(&HstsCheckIssue::ShortMaxAge { age: 86400 }));
}

#[test]
fn analyze_hsts_valid_max_age_no_issue() {
    let issues = analyze_hsts(
        Some("max-age=63072000; includeSubDomains; preload"),
        true,
        false,
    );
    assert!(issues.is_empty());
}

#[test]
fn analyze_hsts_missing_include_subdomains() {
    let issues = analyze_hsts(Some("max-age=63072000; preload"), true, false);
    assert!(issues.contains(&HstsCheckIssue::MissingIncludeSubDomains));
}

#[test]
fn analyze_hsts_missing_preload() {
    let issues = analyze_hsts(Some("max-age=63072000; includeSubDomains"), true, false);
    assert!(issues.contains(&HstsCheckIssue::MissingPreload));
}

#[test]
fn analyze_hsts_full_policy_no_issues() {
    let issues = analyze_hsts(
        Some("max-age=63072000; includeSubDomains; preload"),
        true,
        false,
    );
    assert!(issues.is_empty());
}

#[test]
fn analyze_hsts_preload_without_include_subdomains() {
    let issues = analyze_hsts(Some("max-age=63072000; preload"), true, false);
    assert!(issues.contains(&HstsCheckIssue::PreloadWithoutRequirements));
    assert!(issues.contains(&HstsCheckIssue::MissingIncludeSubDomains));
}

#[test]
fn analyze_hsts_max_age_only_no_other_directives() {
    let issues = analyze_hsts(Some("max-age=63072000"), true, false);
    assert!(issues.contains(&HstsCheckIssue::MaxAgeOnly));
}

#[test]
fn analyze_hsts_invalid_max_age_non_numeric() {
    let issues = analyze_hsts(Some("max-age=invalid"), true, false);
    assert!(issues.contains(&HstsCheckIssue::InvalidMaxAge {
        value: "invalid".to_string()
    }));
}

#[test]
fn analyze_hsts_multiple_issues_combined() {
    let issues = analyze_hsts(Some("max-age=86400"), true, false);
    assert!(issues.contains(&HstsCheckIssue::ShortMaxAge { age: 86400 }));
    assert!(issues.contains(&HstsCheckIssue::MissingIncludeSubDomains));
    assert!(issues.contains(&HstsCheckIssue::MissingPreload));
    assert!(issues.contains(&HstsCheckIssue::MaxAgeOnly));
}

#[test]
fn analyze_hsts_case_insensitive() {
    let issues = analyze_hsts(
        Some("MAX-AGE=63072000; INCLUDESUBDOMAINS; PRELOAD"),
        true,
        false,
    );
    assert!(issues.is_empty());
}

#[test]
fn analyze_hsts_minimal_valid_max_age() {
    let issues = analyze_hsts(
        Some("max-age=31536000; includeSubDomains; preload"),
        true,
        false,
    );
    assert!(issues.is_empty());
}

#[test]
fn analyze_hsts_just_below_min_max_age() {
    let issues = analyze_hsts(
        Some("max-age=31535999; includeSubDomains; preload"),
        true,
        false,
    );
    assert!(issues.contains(&HstsCheckIssue::ShortMaxAge { age: 31535999 }));
}

#[test]
fn analyze_hsts_missing_header_http_no_redirect() {
    let issues = analyze_hsts(None, false, false);
    assert_eq!(issues.len(), 1);
    assert!(issues.contains(&HstsCheckIssue::MissingHeader));
    assert!(!issues.contains(&HstsCheckIssue::HttpRedirectWithoutHsts));
}

#[test]
fn analyze_hsts_whitespace_in_max_age() {
    let issues = analyze_hsts(Some("max-age=63072000 ; includeSubDomains"), true, false);
    assert!(issues.contains(&HstsCheckIssue::MissingPreload));
    assert!(!issues.contains(&HstsCheckIssue::MissingIncludeSubDomains));
}

#[test]
fn analyze_hsts_semicolon_after_max_age() {
    let issues = analyze_hsts(Some("max-age=63072000;"), true, false);
    assert!(issues.contains(&HstsCheckIssue::MissingIncludeSubDomains));
    assert!(issues.contains(&HstsCheckIssue::MissingPreload));
}

#[test]
fn analyze_hsts_invalid_max_age_empty() {
    let issues = analyze_hsts(Some("max-age="), true, false);
    assert!(issues.contains(&HstsCheckIssue::InvalidMaxAge {
        value: "".to_string()
    }));
}

#[test]
fn analyze_hsts_invalid_max_age_with_semicolon() {
    let issues = analyze_hsts(Some("max-age=bad; includeSubDomains"), true, false);
    assert!(issues.contains(&HstsCheckIssue::InvalidMaxAge {
        value: "bad".to_string()
    }));
}

#[test]
fn analyze_hsts_preload_with_include_subdomains_valid() {
    let issues = analyze_hsts(
        Some("max-age=63072000; includeSubDomains; preload"),
        true,
        false,
    );
    assert!(!issues.contains(&HstsCheckIssue::PreloadWithoutRequirements));
}

#[test]
fn analyze_hsts_no_max_age_directive() {
    let issues = analyze_hsts(Some("includeSubDomains; preload"), true, false);
    // When there's no max-age directive at all, the directives present are still detected
    assert!(!issues.contains(&HstsCheckIssue::MissingIncludeSubDomains));
    assert!(!issues.contains(&HstsCheckIssue::MissingPreload));
    assert!(!issues.contains(&HstsCheckIssue::MaxAgeOnly));
}

// hsts_check_to_operations tests (4 tests)

#[test]
fn hsts_check_to_operations_empty() {
    let mut seq = 5;
    let ops = hsts_check_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn hsts_check_to_operations_missing_uses_missing_header_class() {
    let issues = vec![HstsCheckIssue::MissingHeader];
    let mut seq = 0;
    let ops = hsts_check_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::MissingSecurityHeader
            );
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn hsts_check_to_operations_others_use_misconfig_class() {
    let issues = vec![
        HstsCheckIssue::ZeroMaxAge,
        HstsCheckIssue::MissingPreload,
        HstsCheckIssue::MaxAgeOnly,
    ];
    let mut seq = 0;
    let ops = hsts_check_to_operations(&issues, &mut seq);
    for op in &ops {
        match &op.operation {
            aegis_protocol::operation::GraphOperation::AddFinding {
                vulnerability_class,
                ..
            } => {
                assert_eq!(
                    *vulnerability_class,
                    aegis_protocol::finding::VulnerabilityClass::SecurityMisconfiguration
                );
            }
            _ => panic!("expected AddFinding"),
        }
    }
}

#[test]
fn hsts_check_to_operations_multiple_issues_correct_seq() {
    let issues = vec![
        HstsCheckIssue::MissingHeader,
        HstsCheckIssue::ZeroMaxAge,
        HstsCheckIssue::MissingPreload,
    ];
    let mut seq = 10;
    let ops = hsts_check_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 13);
}
