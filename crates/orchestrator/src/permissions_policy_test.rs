use crate::permissions_policy::*;

// === Existing 8 tests (unchanged) ===

#[test]
fn check_permissions_policy_skips_localhost() {
    let result = check_permissions_policy("http://localhost:8080");
    assert!(result.is_empty());
}

#[test]
fn check_permissions_policy_skips_loopback() {
    let result = check_permissions_policy("http://127.0.0.1");
    assert!(result.is_empty());
}

#[test]
fn analyze_policy_flags_wildcard() {
    let issues = analyze_policy("camera=*, microphone=()");
    let wildcards: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i.kind, PolicyIssueKind::WildcardAllowlist))
        .collect();
    assert_eq!(wildcards.len(), 1);
}

#[test]
fn analyze_policy_flags_unrestricted_sensitive_features() {
    let issues = analyze_policy("camera=(), microphone=()");
    let unrestricted: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i.kind, PolicyIssueKind::SensitiveFeatureUnrestricted))
        .collect();
    // 6 sensitive features not restricted (geolocation, payment, usb, bluetooth, serial, hid)
    assert_eq!(unrestricted.len(), 6);
}

#[test]
fn analyze_policy_all_restricted_no_issues() {
    let policy = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=(), serial=(), hid=()";
    let issues = analyze_policy(policy);
    assert!(issues.is_empty());
}

#[test]
fn policy_findings_to_operations_missing_header() {
    let issues = vec![PermissionsPolicyIssue {
        kind: PolicyIssueKind::MissingHeader,
        detail: "No header".to_string(),
    }];
    let mut seq = 0;
    let ops = policy_findings_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            severity,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::MissingSecurityHeader
            );
            assert!(*severity >= 3.0);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn policy_findings_to_operations_misconfig() {
    let issues = vec![PermissionsPolicyIssue {
        kind: PolicyIssueKind::WildcardAllowlist,
        detail: "wildcard".to_string(),
    }];
    let mut seq = 0;
    let ops = policy_findings_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
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
fn policy_findings_empty_returns_no_ops() {
    let mut seq = 0;
    let ops = policy_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

// === New tests for PolicyIssue enum ===

// --- Display tests ---

#[test]
fn display_missing_policy() {
    let issue = PolicyIssue::MissingPolicy;
    assert_eq!(issue.to_string(), "missing_policy");
}

#[test]
fn display_wildcard_allowlist() {
    let issue = PolicyIssue::WildcardAllowlist {
        feature: "camera".to_string(),
    };
    assert_eq!(issue.to_string(), "wildcard_allowlist:camera");
}

#[test]
fn display_sensitive_unrestricted() {
    let issue = PolicyIssue::SensitiveUnrestricted {
        feature: "geolocation".to_string(),
    };
    assert_eq!(issue.to_string(), "sensitive_unrestricted:geolocation");
}

#[test]
fn display_deprecated_feature_policy() {
    let issue = PolicyIssue::DeprecatedFeaturePolicy;
    assert_eq!(issue.to_string(), "deprecated_feature_policy");
}

#[test]
fn display_self_origin_only() {
    let issue = PolicyIssue::SelfOriginOnly {
        feature: "microphone".to_string(),
    };
    assert_eq!(issue.to_string(), "self_origin_only:microphone");
}

#[test]
fn display_third_party_allowed() {
    let issue = PolicyIssue::ThirdPartyAllowed {
        feature: "camera".to_string(),
        origin: "https://cdn.example.com".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "third_party_allowed:camera:https://cdn.example.com"
    );
}

#[test]
fn display_empty_policy() {
    let issue = PolicyIssue::EmptyPolicy;
    assert_eq!(issue.to_string(), "empty_policy");
}

#[test]
fn display_invalid_directive() {
    let issue = PolicyIssue::InvalidDirective {
        directive: "nonsense".to_string(),
    };
    assert_eq!(issue.to_string(), "invalid_directive:nonsense");
}

#[test]
fn display_all_features_unrestricted() {
    let issue = PolicyIssue::AllFeaturesUnrestricted;
    assert_eq!(issue.to_string(), "all_features_unrestricted");
}

#[test]
fn display_interest_cohort_not_blocked() {
    let issue = PolicyIssue::InterestCohortNotBlocked;
    assert_eq!(issue.to_string(), "interest_cohort_not_blocked");
}

// --- Severity tests ---

#[test]
fn severity_missing_policy() {
    assert!((policy_issue_severity(&PolicyIssue::MissingPolicy) - 3.0).abs() < f64::EPSILON);
}

#[test]
fn severity_wildcard_allowlist() {
    let issue = PolicyIssue::WildcardAllowlist {
        feature: "camera".to_string(),
    };
    assert!((policy_issue_severity(&issue) - 4.0).abs() < f64::EPSILON);
}

#[test]
fn severity_sensitive_unrestricted() {
    let issue = PolicyIssue::SensitiveUnrestricted {
        feature: "usb".to_string(),
    };
    assert!((policy_issue_severity(&issue) - 3.5).abs() < f64::EPSILON);
}

#[test]
fn severity_deprecated_feature_policy() {
    assert!(
        (policy_issue_severity(&PolicyIssue::DeprecatedFeaturePolicy) - 2.0).abs() < f64::EPSILON
    );
}

#[test]
fn severity_self_origin_only() {
    let issue = PolicyIssue::SelfOriginOnly {
        feature: "camera".to_string(),
    };
    assert!((policy_issue_severity(&issue) - 1.5).abs() < f64::EPSILON);
}

#[test]
fn severity_third_party_allowed() {
    let issue = PolicyIssue::ThirdPartyAllowed {
        feature: "camera".to_string(),
        origin: "https://cdn.example.com".to_string(),
    };
    assert!((policy_issue_severity(&issue) - 3.0).abs() < f64::EPSILON);
}

#[test]
fn severity_empty_policy() {
    assert!((policy_issue_severity(&PolicyIssue::EmptyPolicy) - 2.5).abs() < f64::EPSILON);
}

#[test]
fn severity_invalid_directive() {
    let issue = PolicyIssue::InvalidDirective {
        directive: "bad".to_string(),
    };
    assert!((policy_issue_severity(&issue) - 2.0).abs() < f64::EPSILON);
}

#[test]
fn severity_all_features_unrestricted() {
    assert!(
        (policy_issue_severity(&PolicyIssue::AllFeaturesUnrestricted) - 4.5).abs() < f64::EPSILON
    );
}

#[test]
fn severity_interest_cohort_not_blocked() {
    assert!(
        (policy_issue_severity(&PolicyIssue::InterestCohortNotBlocked) - 2.5).abs() < f64::EPSILON
    );
}

// --- analyze_permissions_policy tests ---

#[test]
fn analyze_empty_string_returns_empty_policy() {
    let issues = analyze_permissions_policy("");
    assert!(issues.contains(&PolicyIssue::EmptyPolicy));
    assert_eq!(issues.len(), 1);
}

#[test]
fn analyze_whitespace_only_returns_empty_policy() {
    let issues = analyze_permissions_policy("   ");
    assert!(issues.contains(&PolicyIssue::EmptyPolicy));
}

#[test]
fn analyze_wildcard_camera() {
    let issues = analyze_permissions_policy("camera=*");
    assert!(issues.contains(&PolicyIssue::WildcardAllowlist {
        feature: "camera".to_string(),
    }));
}

#[test]
fn analyze_multiple_wildcards() {
    let issues = analyze_permissions_policy("camera=*, microphone=*");
    let wildcards: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, PolicyIssue::WildcardAllowlist { .. }))
        .collect();
    assert_eq!(wildcards.len(), 2);
}

#[test]
fn analyze_restricted_feature_no_sensitive_unrestricted() {
    let policy = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=(), serial=(), hid=()";
    let issues = analyze_permissions_policy(policy);
    let sensitive: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, PolicyIssue::SensitiveUnrestricted { .. }))
        .collect();
    assert!(sensitive.is_empty());
}

#[test]
fn analyze_partial_restriction_flags_remaining() {
    let issues = analyze_permissions_policy("camera=(), microphone=()");
    let sensitive: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, PolicyIssue::SensitiveUnrestricted { .. }))
        .collect();
    // 6 remaining: geolocation, payment, usb, bluetooth, serial, hid
    assert_eq!(sensitive.len(), 6);
}

#[test]
fn analyze_self_origin_sensitive_feature() {
    let issues = analyze_permissions_policy("camera=(self)");
    assert!(issues.contains(&PolicyIssue::SelfOriginOnly {
        feature: "camera".to_string(),
    }));
}

#[test]
fn analyze_self_origin_non_sensitive_feature() {
    let issues = analyze_permissions_policy("autoplay=(self)");
    let self_origin: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, PolicyIssue::SelfOriginOnly { feature } if feature == "autoplay"))
        .collect();
    // autoplay is not in SENSITIVE_FEATURES, so SelfOriginOnly should not fire
    assert!(self_origin.is_empty());
}

#[test]
fn analyze_third_party_origin() {
    let issues = analyze_permissions_policy("camera=(self \"https://cdn.example.com\")");
    assert!(issues.contains(&PolicyIssue::ThirdPartyAllowed {
        feature: "camera".to_string(),
        origin: "https://cdn.example.com".to_string(),
    }));
}

#[test]
fn analyze_multiple_third_party_origins() {
    let issues = analyze_permissions_policy("camera=(self \"https://a.com\" \"https://b.com\")");
    let tp: Vec<_> = issues
        .iter()
        .filter(
            |i| matches!(i, PolicyIssue::ThirdPartyAllowed { feature, .. } if feature == "camera"),
        )
        .collect();
    assert_eq!(tp.len(), 2);
}

#[test]
fn analyze_invalid_directive_no_equals() {
    let issues = analyze_permissions_policy("nonsense");
    assert!(issues.contains(&PolicyIssue::InvalidDirective {
        directive: "nonsense".to_string(),
    }));
}

#[test]
fn analyze_interest_cohort_blocked() {
    let issues = analyze_permissions_policy("interest-cohort=()");
    assert!(!issues.contains(&PolicyIssue::InterestCohortNotBlocked));
}

#[test]
fn analyze_interest_cohort_not_blocked() {
    let issues = analyze_permissions_policy("camera=()");
    assert!(issues.contains(&PolicyIssue::InterestCohortNotBlocked));
}

#[test]
fn analyze_all_wildcards_flags_all_unrestricted() {
    let issues = analyze_permissions_policy("camera=*, microphone=*");
    assert!(issues.contains(&PolicyIssue::AllFeaturesUnrestricted));
}

#[test]
fn analyze_mixed_restricted_and_wildcard_no_all_unrestricted() {
    let issues = analyze_permissions_policy("camera=(), microphone=*");
    assert!(!issues.contains(&PolicyIssue::AllFeaturesUnrestricted));
}

#[test]
fn analyze_full_lockdown_minimal_issues() {
    let policy = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=(), serial=(), hid=(), interest-cohort=()";
    let issues = analyze_permissions_policy(policy);
    // Should only have no sensitive unrestricted, no interest-cohort issue
    assert!(!issues.contains(&PolicyIssue::InterestCohortNotBlocked));
    let sensitive: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, PolicyIssue::SensitiveUnrestricted { .. }))
        .collect();
    assert!(sensitive.is_empty());
}

#[test]
fn analyze_directive_with_extra_whitespace() {
    let issues = analyze_permissions_policy("  camera = ()  ,  microphone = ()  ");
    // camera and microphone should be parsed (feature names trimmed)
    let sensitive: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, PolicyIssue::SensitiveUnrestricted { .. }))
        .collect();
    // 6 remaining
    assert_eq!(sensitive.len(), 6);
}

#[test]
fn analyze_single_empty_restriction() {
    let issues = analyze_permissions_policy("fullscreen=()");
    // Not a sensitive feature, but interest-cohort not blocked
    assert!(issues.contains(&PolicyIssue::InterestCohortNotBlocked));
}

// --- policy_issues_to_operations tests ---

#[test]
fn operations_empty_input_returns_empty() {
    let mut seq = 0;
    let ops = policy_issues_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_one_per_issue() {
    let issues = vec![
        PolicyIssue::WildcardAllowlist {
            feature: "camera".to_string(),
        },
        PolicyIssue::SensitiveUnrestricted {
            feature: "usb".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = policy_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn operations_missing_policy_uses_missing_header_class() {
    let issues = vec![PolicyIssue::MissingPolicy];
    let mut seq = 0;
    let ops = policy_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
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
fn operations_non_missing_uses_misconfig_class() {
    let issues = vec![PolicyIssue::EmptyPolicy];
    let mut seq = 0;
    let ops = policy_issues_to_operations(&issues, &mut seq);
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
fn operations_confidence_is_half() {
    let issues = vec![PolicyIssue::InterestCohortNotBlocked];
    let mut seq = 0;
    let ops = policy_issues_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { confidence, .. } => {
            assert!((confidence.value() - 0.5).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn operations_severity_matches_policy_issue_severity() {
    let issue = PolicyIssue::WildcardAllowlist {
        feature: "camera".to_string(),
    };
    let mut seq = 0;
    let ops = policy_issues_to_operations(&[issue.clone()], &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert!((*severity - policy_issue_severity(&issue)).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn operations_sequence_increments() {
    let issues = vec![
        PolicyIssue::EmptyPolicy,
        PolicyIssue::InterestCohortNotBlocked,
        PolicyIssue::MissingPolicy,
    ];
    let mut seq = 10;
    let ops = policy_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(ops[0].sequence_number, 11);
    assert_eq!(ops[1].sequence_number, 12);
    assert_eq!(ops[2].sequence_number, 13);
    assert_eq!(seq, 13);
}

// --- issue_severity (old API, now pub) ---

#[test]
fn old_issue_severity_missing_header() {
    let issue = PermissionsPolicyIssue {
        kind: PolicyIssueKind::MissingHeader,
        detail: String::new(),
    };
    assert!((issue_severity(&issue) - 3.0).abs() < f64::EPSILON);
}

#[test]
fn old_issue_severity_wildcard() {
    let issue = PermissionsPolicyIssue {
        kind: PolicyIssueKind::WildcardAllowlist,
        detail: String::new(),
    };
    assert!((issue_severity(&issue) - 4.0).abs() < f64::EPSILON);
}

#[test]
fn old_issue_severity_sensitive() {
    let issue = PermissionsPolicyIssue {
        kind: PolicyIssueKind::SensitiveFeatureUnrestricted,
        detail: String::new(),
    };
    assert!((issue_severity(&issue) - 2.5).abs() < f64::EPSILON);
}

// --- PartialEq tests ---

#[test]
fn policy_issue_eq_missing() {
    assert_eq!(PolicyIssue::MissingPolicy, PolicyIssue::MissingPolicy);
}

#[test]
fn policy_issue_eq_wildcard_same_feature() {
    assert_eq!(
        PolicyIssue::WildcardAllowlist {
            feature: "camera".to_string()
        },
        PolicyIssue::WildcardAllowlist {
            feature: "camera".to_string()
        }
    );
}

#[test]
fn policy_issue_ne_wildcard_diff_feature() {
    assert_ne!(
        PolicyIssue::WildcardAllowlist {
            feature: "camera".to_string()
        },
        PolicyIssue::WildcardAllowlist {
            feature: "microphone".to_string()
        }
    );
}

#[test]
fn policy_issue_ne_different_variants() {
    assert_ne!(PolicyIssue::MissingPolicy, PolicyIssue::EmptyPolicy);
}

// --- Edge cases ---

#[test]
fn analyze_trailing_comma() {
    let issues = analyze_permissions_policy("camera=(),");
    // Trailing comma produces empty segment which is skipped
    let invalid: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, PolicyIssue::InvalidDirective { .. }))
        .collect();
    assert!(invalid.is_empty());
}

#[test]
fn analyze_only_interest_cohort_blocked() {
    let issues = analyze_permissions_policy("interest-cohort=()");
    assert!(!issues.contains(&PolicyIssue::InterestCohortNotBlocked));
    // All 8 sensitive features are unrestricted
    let sensitive: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, PolicyIssue::SensitiveUnrestricted { .. }))
        .collect();
    assert_eq!(sensitive.len(), 8);
}

#[test]
fn analyze_interest_cohort_wildcard_still_not_blocked() {
    let issues = analyze_permissions_policy("interest-cohort=*");
    // wildcard is not blocking, so InterestCohortNotBlocked should fire
    assert!(issues.contains(&PolicyIssue::InterestCohortNotBlocked));
}

#[test]
fn analyze_complex_realistic_policy() {
    let policy = "camera=(), microphone=(self), geolocation=(), payment=(), usb=(), bluetooth=(), serial=(), hid=(), interest-cohort=()";
    let issues = analyze_permissions_policy(policy);
    // microphone=(self) triggers SelfOriginOnly
    assert!(issues.contains(&PolicyIssue::SelfOriginOnly {
        feature: "microphone".to_string(),
    }));
    // interest-cohort blocked
    assert!(!issues.contains(&PolicyIssue::InterestCohortNotBlocked));
    // no sensitive unrestricted (all 8 are mentioned)
    let sensitive: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, PolicyIssue::SensitiveUnrestricted { .. }))
        .collect();
    assert!(sensitive.is_empty());
}
