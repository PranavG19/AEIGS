use crate::rate_limit_detector::*;

// ── Existing tests (7) ─────────────────────────────────────────────

#[test]
fn rate_limit_to_operations_creates_defense_node() {
    let info = RateLimitInfo {
        headers: vec![
            ("x-ratelimit-limit".to_string(), "100".to_string()),
            ("x-ratelimit-remaining".to_string(), "99".to_string()),
        ],
    };
    let mut seq = 0;
    let ops = rate_limit_to_operations(&info, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddNode {
            node_type,
            properties,
        } => {
            assert_eq!(*node_type, aegis_protocol::node::NodeType::Defense);
            let source = properties.iter().find(|(k, _)| k == "source").unwrap();
            assert_eq!(source.1, "rate_limit_detect");
            let limit = properties
                .iter()
                .find(|(k, _)| k == "x-ratelimit-limit")
                .unwrap();
            assert_eq!(limit.1, "100");
        }
        _ => panic!("expected AddNode"),
    }
}

#[test]
fn rate_limit_to_operations_includes_all_headers() {
    let info = RateLimitInfo {
        headers: vec![
            ("x-ratelimit-limit".to_string(), "1000".to_string()),
            ("x-ratelimit-remaining".to_string(), "500".to_string()),
            ("x-ratelimit-reset".to_string(), "1700000000".to_string()),
        ],
    };
    let mut seq = 0;
    let ops = rate_limit_to_operations(&info, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddNode { properties, .. } => {
            assert_eq!(properties.len(), 4); // 3 headers + source
        }
        _ => panic!("expected AddNode"),
    }
}

#[test]
fn detect_rate_limits_skips_localhost() {
    let result = detect_rate_limits("http://localhost:8080");
    assert!(result.is_none());
}

#[test]
fn detect_rate_limits_skips_loopback() {
    let result = detect_rate_limits("http://127.0.0.1");
    assert!(result.is_none());
}

#[test]
fn rate_limit_to_operations_increments_sequence() {
    let info = RateLimitInfo {
        headers: vec![("retry-after".to_string(), "60".to_string())],
    };
    let mut seq = 10;
    let ops = rate_limit_to_operations(&info, &mut seq);
    assert_eq!(seq, 11);
    assert_eq!(ops[0].sequence_number, 11);
}

#[test]
fn rate_limit_to_operations_single_header() {
    let info = RateLimitInfo {
        headers: vec![("retry-after".to_string(), "120".to_string())],
    };
    let mut seq = 0;
    let ops = rate_limit_to_operations(&info, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddNode { properties, .. } => {
            assert_eq!(properties.len(), 2); // 1 header + source
            let retry = properties.iter().find(|(k, _)| k == "retry-after").unwrap();
            assert_eq!(retry.1, "120");
        }
        _ => panic!("expected AddNode"),
    }
}

#[test]
fn detect_rate_limits_skips_invalid() {
    let result = detect_rate_limits("not-a-url");
    assert!(result.is_none());
}

// ── RateLimitIssue enum variant construction ────────────────────────

#[test]
fn issue_no_rate_limiting_is_constructed() {
    let issue = RateLimitIssue::NoRateLimiting;
    assert_eq!(format!("{issue:?}"), "NoRateLimiting");
}

#[test]
fn issue_high_limit_stores_value() {
    let issue = RateLimitIssue::HighLimit { limit: 50_000 };
    if let RateLimitIssue::HighLimit { limit } = issue {
        assert_eq!(limit, 50_000);
    } else {
        panic!("wrong variant");
    }
}

#[test]
fn issue_no_reset_header_is_constructed() {
    let issue = RateLimitIssue::NoResetHeader;
    assert_eq!(format!("{issue:?}"), "NoResetHeader");
}

#[test]
fn issue_inconsistent_headers_stores_list() {
    let issue = RateLimitIssue::InconsistentHeaders {
        headers: vec!["x-ratelimit-*".into(), "ratelimit-*".into()],
    };
    if let RateLimitIssue::InconsistentHeaders { headers } = &issue {
        assert_eq!(headers.len(), 2);
    } else {
        panic!("wrong variant");
    }
}

#[test]
fn issue_retry_after_missing_is_constructed() {
    let issue = RateLimitIssue::RetryAfterMissing;
    assert_eq!(format!("{issue:?}"), "RetryAfterMissing");
}

#[test]
fn issue_low_burst_allowance_stores_values() {
    let issue = RateLimitIssue::LowBurstAllowance {
        remaining: 2,
        limit: 1000,
    };
    if let RateLimitIssue::LowBurstAllowance { remaining, limit } = issue {
        assert_eq!(remaining, 2);
        assert_eq!(limit, 1000);
    } else {
        panic!("wrong variant");
    }
}

#[test]
fn issue_no_limit_on_auth_is_constructed() {
    let issue = RateLimitIssue::NoLimitOnAuth;
    assert_eq!(format!("{issue:?}"), "NoLimitOnAuth");
}

#[test]
fn issue_rate_limit_bypassable_stores_method() {
    let issue = RateLimitIssue::RateLimitBypassable {
        method: "PUT".into(),
    };
    if let RateLimitIssue::RateLimitBypassable { method } = &issue {
        assert_eq!(method, "PUT");
    } else {
        panic!("wrong variant");
    }
}

// ── Display tests ───────────────────────────────────────────────────

#[test]
fn display_no_rate_limiting() {
    assert_eq!(
        RateLimitIssue::NoRateLimiting.to_string(),
        "no_rate_limiting"
    );
}

#[test]
fn display_high_limit() {
    let issue = RateLimitIssue::HighLimit { limit: 20_000 };
    assert_eq!(issue.to_string(), "high_limit:20000");
}

#[test]
fn display_no_reset_header() {
    assert_eq!(RateLimitIssue::NoResetHeader.to_string(), "no_reset_header");
}

#[test]
fn display_inconsistent_headers() {
    let issue = RateLimitIssue::InconsistentHeaders {
        headers: vec!["x-ratelimit-*".into(), "ratelimit-*".into()],
    };
    assert_eq!(
        issue.to_string(),
        "inconsistent_headers:x-ratelimit-*,ratelimit-*"
    );
}

#[test]
fn display_retry_after_missing() {
    assert_eq!(
        RateLimitIssue::RetryAfterMissing.to_string(),
        "retry_after_missing"
    );
}

#[test]
fn display_low_burst_allowance() {
    let issue = RateLimitIssue::LowBurstAllowance {
        remaining: 3,
        limit: 500,
    };
    assert_eq!(issue.to_string(), "low_burst_allowance:3/500");
}

#[test]
fn display_no_limit_on_auth() {
    assert_eq!(
        RateLimitIssue::NoLimitOnAuth.to_string(),
        "no_limit_on_auth"
    );
}

#[test]
fn display_rate_limit_bypassable() {
    let issue = RateLimitIssue::RateLimitBypassable {
        method: "DELETE".into(),
    };
    assert_eq!(issue.to_string(), "rate_limit_bypassable:DELETE");
}

// ── Severity tests ──────────────────────────────────────────────────

#[test]
fn severity_no_limit_on_auth_highest() {
    assert_eq!(rate_limit_severity(&RateLimitIssue::NoLimitOnAuth), 7.0);
}

#[test]
fn severity_bypassable_high() {
    let issue = RateLimitIssue::RateLimitBypassable {
        method: "PATCH".into(),
    };
    assert_eq!(rate_limit_severity(&issue), 6.5);
}

#[test]
fn severity_no_rate_limiting() {
    assert_eq!(rate_limit_severity(&RateLimitIssue::NoRateLimiting), 6.0);
}

#[test]
fn severity_high_limit() {
    let issue = RateLimitIssue::HighLimit { limit: 99_999 };
    assert_eq!(rate_limit_severity(&issue), 5.0);
}

#[test]
fn severity_retry_after_missing() {
    assert_eq!(rate_limit_severity(&RateLimitIssue::RetryAfterMissing), 4.0);
}

#[test]
fn severity_low_burst_allowance() {
    let issue = RateLimitIssue::LowBurstAllowance {
        remaining: 1,
        limit: 100,
    };
    assert_eq!(rate_limit_severity(&issue), 3.5);
}

#[test]
fn severity_inconsistent_headers() {
    let issue = RateLimitIssue::InconsistentHeaders {
        headers: vec!["x-ratelimit-*".into()],
    };
    assert_eq!(rate_limit_severity(&issue), 3.0);
}

#[test]
fn severity_no_reset_header_lowest() {
    assert_eq!(rate_limit_severity(&RateLimitIssue::NoResetHeader), 2.5);
}

#[test]
fn severity_ordering_auth_above_no_rate_limiting() {
    assert!(
        rate_limit_severity(&RateLimitIssue::NoLimitOnAuth)
            > rate_limit_severity(&RateLimitIssue::NoRateLimiting)
    );
}

#[test]
fn severity_ordering_bypassable_above_high_limit() {
    let bypassable = RateLimitIssue::RateLimitBypassable {
        method: "PUT".into(),
    };
    let high = RateLimitIssue::HighLimit { limit: 50_000 };
    assert!(rate_limit_severity(&bypassable) > rate_limit_severity(&high));
}

// ── analyze_rate_limit_headers tests ────────────────────────────────

#[test]
fn analyze_empty_headers_returns_no_rate_limiting() {
    let issues = analyze_rate_limit_headers(&[]);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], RateLimitIssue::NoRateLimiting);
}

#[test]
fn analyze_unrelated_headers_returns_no_rate_limiting() {
    let headers = [("content-type", "text/html"), ("server", "nginx")];
    let issues = analyze_rate_limit_headers(&headers);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], RateLimitIssue::NoRateLimiting);
}

#[test]
fn analyze_normal_rate_limit_no_issues() {
    let headers = [
        ("x-ratelimit-limit", "100"),
        ("x-ratelimit-remaining", "95"),
        ("x-ratelimit-reset", "1700000000"),
    ];
    let issues = analyze_rate_limit_headers(&headers);
    assert!(issues.is_empty());
}

#[test]
fn analyze_high_limit_detected() {
    let headers = [
        ("x-ratelimit-limit", "50000"),
        ("x-ratelimit-remaining", "49999"),
        ("x-ratelimit-reset", "1700000000"),
    ];
    let issues = analyze_rate_limit_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        RateLimitIssue::HighLimit { limit } if *limit == 50_000
    )));
}

#[test]
fn analyze_limit_at_threshold_not_flagged() {
    let headers = [
        ("x-ratelimit-limit", "10000"),
        ("x-ratelimit-remaining", "9999"),
        ("x-ratelimit-reset", "1700000000"),
    ];
    let issues = analyze_rate_limit_headers(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, RateLimitIssue::HighLimit { .. }))
    );
}

#[test]
fn analyze_limit_just_above_threshold() {
    let headers = [
        ("x-ratelimit-limit", "10001"),
        ("x-ratelimit-remaining", "10000"),
        ("x-ratelimit-reset", "1700000000"),
    ];
    let issues = analyze_rate_limit_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        RateLimitIssue::HighLimit { limit } if *limit == 10_001
    )));
}

#[test]
fn analyze_no_reset_header_detected() {
    let headers = [
        ("x-ratelimit-limit", "100"),
        ("x-ratelimit-remaining", "50"),
    ];
    let issues = analyze_rate_limit_headers(&headers);
    assert!(issues.iter().any(|i| *i == RateLimitIssue::NoResetHeader));
}

#[test]
fn analyze_reset_header_present_no_issue() {
    let headers = [
        ("x-ratelimit-limit", "100"),
        ("x-ratelimit-remaining", "50"),
        ("x-ratelimit-reset", "1700000000"),
    ];
    let issues = analyze_rate_limit_headers(&headers);
    assert!(!issues.iter().any(|i| *i == RateLimitIssue::NoResetHeader));
}

#[test]
fn analyze_inconsistent_x_ratelimit_and_standard() {
    let headers = [
        ("x-ratelimit-limit", "100"),
        ("x-ratelimit-reset", "1700000000"),
        ("ratelimit-limit", "200"),
        ("ratelimit-reset", "1700000000"),
    ];
    let issues = analyze_rate_limit_headers(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RateLimitIssue::InconsistentHeaders { .. }))
    );
}

#[test]
fn analyze_inconsistent_includes_both_styles() {
    let headers = [
        ("x-ratelimit-limit", "100"),
        ("x-ratelimit-reset", "1700000000"),
        ("ratelimit-limit", "200"),
        ("ratelimit-reset", "1700000000"),
    ];
    let issues = analyze_rate_limit_headers(&headers);
    let inconsistent = issues
        .iter()
        .find(|i| matches!(i, RateLimitIssue::InconsistentHeaders { .. }))
        .unwrap();
    if let RateLimitIssue::InconsistentHeaders { headers } = inconsistent {
        assert!(headers.contains(&"x-ratelimit-*".to_string()));
        assert!(headers.contains(&"ratelimit-*".to_string()));
    } else {
        panic!("wrong variant");
    }
}

#[test]
fn analyze_single_style_no_inconsistency() {
    let headers = [
        ("x-ratelimit-limit", "100"),
        ("x-ratelimit-remaining", "50"),
        ("x-ratelimit-reset", "1700000000"),
    ];
    let issues = analyze_rate_limit_headers(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, RateLimitIssue::InconsistentHeaders { .. }))
    );
}

#[test]
fn analyze_low_burst_detected() {
    let headers = [
        ("x-ratelimit-limit", "1000"),
        ("x-ratelimit-remaining", "2"),
        ("x-ratelimit-reset", "1700000000"),
    ];
    let issues = analyze_rate_limit_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        RateLimitIssue::LowBurstAllowance {
            remaining: 2,
            limit: 1000
        }
    )));
}

#[test]
fn analyze_burst_at_five_percent_not_flagged() {
    let headers = [
        ("x-ratelimit-limit", "100"),
        ("x-ratelimit-remaining", "5"),
        ("x-ratelimit-reset", "1700000000"),
    ];
    let issues = analyze_rate_limit_headers(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, RateLimitIssue::LowBurstAllowance { .. }))
    );
}

#[test]
fn analyze_burst_just_below_threshold() {
    let headers = [
        ("x-ratelimit-limit", "1000"),
        ("x-ratelimit-remaining", "49"),
        ("x-ratelimit-reset", "1700000000"),
    ];
    let issues = analyze_rate_limit_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        RateLimitIssue::LowBurstAllowance {
            remaining: 49,
            limit: 1000
        }
    )));
}

#[test]
fn analyze_zero_remaining_is_low_burst() {
    let headers = [
        ("x-ratelimit-limit", "100"),
        ("x-ratelimit-remaining", "0"),
        ("x-ratelimit-reset", "1700000000"),
    ];
    let issues = analyze_rate_limit_headers(&headers);
    assert!(issues.iter().any(|i| matches!(
        i,
        RateLimitIssue::LowBurstAllowance {
            remaining: 0,
            limit: 100
        }
    )));
}

#[test]
fn analyze_only_retry_after_no_no_rate_limiting() {
    let headers = [("retry-after", "60")];
    let issues = analyze_rate_limit_headers(&headers);
    assert!(!issues.iter().any(|i| *i == RateLimitIssue::NoRateLimiting));
}

#[test]
fn analyze_case_insensitive_header_names() {
    let headers = [
        ("X-RateLimit-Limit", "100"),
        ("X-RateLimit-Remaining", "90"),
        ("X-RateLimit-Reset", "1700000000"),
    ];
    let issues = analyze_rate_limit_headers(&headers);
    assert!(issues.is_empty());
}

#[test]
fn analyze_x_rate_limit_dash_style_recognized() {
    let headers = [
        ("x-rate-limit-limit", "100"),
        ("x-rate-limit-remaining", "50"),
        ("x-rate-limit-reset", "1700000000"),
    ];
    let issues = analyze_rate_limit_headers(&headers);
    assert!(!issues.iter().any(|i| *i == RateLimitIssue::NoRateLimiting));
}

#[test]
fn analyze_non_numeric_limit_ignored_for_high_limit() {
    let headers = [
        ("x-ratelimit-limit", "unlimited"),
        ("x-ratelimit-reset", "1700000000"),
    ];
    let issues = analyze_rate_limit_headers(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, RateLimitIssue::HighLimit { .. }))
    );
}

#[test]
fn analyze_non_numeric_remaining_no_low_burst() {
    let headers = [
        ("x-ratelimit-limit", "100"),
        ("x-ratelimit-remaining", "plenty"),
        ("x-ratelimit-reset", "1700000000"),
    ];
    let issues = analyze_rate_limit_headers(&headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, RateLimitIssue::LowBurstAllowance { .. }))
    );
}

#[test]
fn analyze_multiple_issues_at_once() {
    let headers = [
        ("x-ratelimit-limit", "50000"),
        ("x-ratelimit-remaining", "1"),
        ("ratelimit-limit", "50000"),
        ("ratelimit-remaining", "1"),
    ];
    let issues = analyze_rate_limit_headers(&headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RateLimitIssue::HighLimit { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RateLimitIssue::InconsistentHeaders { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, RateLimitIssue::LowBurstAllowance { .. }))
    );
}

#[test]
fn analyze_no_rate_limiting_short_circuits() {
    let headers = [("x-powered-by", "Express")];
    let issues = analyze_rate_limit_headers(&headers);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], RateLimitIssue::NoRateLimiting);
}

// ── rate_limit_issues_to_operations tests ───────────────────────────

#[test]
fn issues_to_operations_empty_for_no_issues() {
    let mut seq = 0;
    let ops = rate_limit_issues_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn issues_to_operations_one_per_issue() {
    let issues = vec![
        RateLimitIssue::NoRateLimiting,
        RateLimitIssue::HighLimit { limit: 20_000 },
    ];
    let mut seq = 0;
    let ops = rate_limit_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn issues_to_operations_uses_add_finding() {
    let issues = vec![RateLimitIssue::NoRateLimiting];
    let mut seq = 0;
    let ops = rate_limit_issues_to_operations(&issues, &mut seq);
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
fn issues_to_operations_increments_seq() {
    let issues = vec![
        RateLimitIssue::NoResetHeader,
        RateLimitIssue::RetryAfterMissing,
        RateLimitIssue::NoLimitOnAuth,
    ];
    let mut seq = 5;
    let ops = rate_limit_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 8);
    assert_eq!(ops[0].sequence_number, 6);
    assert_eq!(ops[1].sequence_number, 7);
    assert_eq!(ops[2].sequence_number, 8);
}

#[test]
fn issues_to_operations_confidence_is_half() {
    let issues = vec![RateLimitIssue::NoRateLimiting];
    let mut seq = 0;
    let ops = rate_limit_issues_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { confidence, .. } => {
            assert!((confidence.value() - 0.5).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn issues_to_operations_severity_matches_function() {
    let issue = RateLimitIssue::NoLimitOnAuth;
    let expected_sev = rate_limit_severity(&issue);
    let mut seq = 0;
    let ops = rate_limit_issues_to_operations(&[issue], &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert!((severity - expected_sev).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding"),
    }
}

// ── Clone + PartialEq tests ─────────────────────────────────────────

#[test]
fn issue_clone_equals_original() {
    let issue = RateLimitIssue::HighLimit { limit: 15_000 };
    let cloned = issue.clone();
    assert_eq!(issue, cloned);
}

#[test]
fn issue_different_variants_not_equal() {
    let a = RateLimitIssue::NoRateLimiting;
    let b = RateLimitIssue::NoResetHeader;
    assert_ne!(a, b);
}

#[test]
fn issue_same_variant_different_data_not_equal() {
    let a = RateLimitIssue::HighLimit { limit: 10_001 };
    let b = RateLimitIssue::HighLimit { limit: 20_000 };
    assert_ne!(a, b);
}
