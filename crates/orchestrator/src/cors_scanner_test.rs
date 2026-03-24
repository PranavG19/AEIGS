use crate::cors_scanner::*;

// --- analyze_cors_headers: individual variant detection ---

#[test]
fn analyze_wildcard_origin() {
    let headers = vec![
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Methods", "GET"),
    ];
    let issues = analyze_cors_headers(&headers, "https://evil.com", "example.com");
    assert!(issues.iter().any(|i| *i == CorsIssue::WildcardOrigin));
}

#[test]
fn analyze_null_origin() {
    let headers = vec![
        ("Access-Control-Allow-Origin", "null"),
        ("Access-Control-Allow-Methods", "GET"),
    ];
    let issues = analyze_cors_headers(&headers, "https://evil.com", "example.com");
    assert!(issues.iter().any(|i| *i == CorsIssue::NullOrigin));
}

#[test]
fn analyze_reflected_origin() {
    let headers = vec![
        ("Access-Control-Allow-Origin", "https://evil.com"),
        ("Access-Control-Allow-Methods", "GET"),
        ("Vary", "Origin"),
    ];
    let issues = analyze_cors_headers(&headers, "https://evil.com", "example.com");
    assert!(issues.iter().any(
        |i| matches!(i, CorsIssue::ReflectedOrigin { origin } if origin == "https://evil.com")
    ));
}

#[test]
fn analyze_arbitrary_subdomain() {
    let headers = vec![
        ("Access-Control-Allow-Origin", "https://evil.example.com"),
        ("Access-Control-Allow-Methods", "GET"),
        ("Vary", "Origin"),
    ];
    let issues = analyze_cors_headers(&headers, "https://attacker.com", "example.com");
    assert!(issues.iter().any(|i| matches!(i, CorsIssue::ArbitrarySubdomain { origin } if origin == "https://evil.example.com")));
}

#[test]
fn analyze_credentials_with_wildcard() {
    let headers = vec![
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Credentials", "true"),
        ("Access-Control-Allow-Methods", "GET"),
    ];
    let issues = analyze_cors_headers(&headers, "https://evil.com", "example.com");
    assert!(
        issues
            .iter()
            .any(|i| *i == CorsIssue::CredentialsWithWildcard)
    );
    assert!(issues.iter().any(|i| *i == CorsIssue::WildcardOrigin));
}

#[test]
fn analyze_credentials_with_reflection() {
    let headers = vec![
        ("Access-Control-Allow-Origin", "https://evil.com"),
        ("Access-Control-Allow-Credentials", "true"),
        ("Access-Control-Allow-Methods", "GET"),
        ("Vary", "Origin"),
    ];
    let issues = analyze_cors_headers(&headers, "https://evil.com", "example.com");
    assert!(issues.iter().any(|i| matches!(i, CorsIssue::CredentialsWithReflection { origin } if origin == "https://evil.com")));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CorsIssue::ReflectedOrigin { .. }))
    );
}

#[test]
fn analyze_credentials_with_null() {
    let headers = vec![
        ("Access-Control-Allow-Origin", "null"),
        ("Access-Control-Allow-Credentials", "true"),
        ("Access-Control-Allow-Methods", "GET"),
    ];
    let issues = analyze_cors_headers(&headers, "https://evil.com", "example.com");
    assert!(issues.iter().any(|i| *i == CorsIssue::CredentialsWithNull));
    assert!(issues.iter().any(|i| *i == CorsIssue::NullOrigin));
}

#[test]
fn analyze_preflight_missing() {
    let headers = vec![("Access-Control-Allow-Origin", "https://example.com")];
    let issues = analyze_cors_headers(&headers, "https://evil.com", "example.com");
    assert!(issues.iter().any(|i| *i == CorsIssue::PreflightMissing));
}

#[test]
fn analyze_wildcard_methods() {
    let headers = vec![
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Methods", "*"),
    ];
    let issues = analyze_cors_headers(&headers, "https://evil.com", "example.com");
    assert!(issues.iter().any(|i| *i == CorsIssue::WildcardMethods));
}

#[test]
fn analyze_wildcard_headers() {
    let headers = vec![
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Headers", "*"),
        ("Access-Control-Allow-Methods", "GET"),
    ];
    let issues = analyze_cors_headers(&headers, "https://evil.com", "example.com");
    assert!(issues.iter().any(|i| *i == CorsIssue::WildcardHeaders));
}

#[test]
fn analyze_excessive_max_age() {
    let headers = vec![
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Max-Age", "86401"),
        ("Access-Control-Allow-Methods", "GET"),
    ];
    let issues = analyze_cors_headers(&headers, "https://evil.com", "example.com");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CorsIssue::ExcessiveMaxAge { seconds } if *seconds == 86401))
    );
}

#[test]
fn analyze_max_age_at_boundary_ok() {
    let headers = vec![
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Max-Age", "86400"),
        ("Access-Control-Allow-Methods", "GET"),
    ];
    let issues = analyze_cors_headers(&headers, "https://evil.com", "example.com");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CorsIssue::ExcessiveMaxAge { .. }))
    );
}

#[test]
fn analyze_vary_origin_missing() {
    let headers = vec![
        ("Access-Control-Allow-Origin", "https://example.com"),
        ("Access-Control-Allow-Methods", "GET"),
    ];
    let issues = analyze_cors_headers(&headers, "https://evil.com", "example.com");
    assert!(issues.iter().any(|i| *i == CorsIssue::VaryOriginMissing));
}

#[test]
fn analyze_vary_origin_present_suppresses_issue() {
    let headers = vec![
        ("Access-Control-Allow-Origin", "https://example.com"),
        ("Access-Control-Allow-Methods", "GET"),
        ("Vary", "Origin"),
    ];
    let issues = analyze_cors_headers(&headers, "https://evil.com", "example.com");
    assert!(!issues.iter().any(|i| *i == CorsIssue::VaryOriginMissing));
}

#[test]
fn analyze_vary_origin_in_comma_list() {
    let headers = vec![
        ("Access-Control-Allow-Origin", "https://example.com"),
        ("Access-Control-Allow-Methods", "GET"),
        ("Vary", "Accept-Encoding, Origin, Cookie"),
    ];
    let issues = analyze_cors_headers(&headers, "https://evil.com", "example.com");
    assert!(!issues.iter().any(|i| *i == CorsIssue::VaryOriginMissing));
}

#[test]
fn analyze_wildcard_acao_no_vary_origin_missing() {
    let headers = vec![
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Methods", "GET"),
    ];
    let issues = analyze_cors_headers(&headers, "https://evil.com", "example.com");
    assert!(!issues.iter().any(|i| *i == CorsIssue::VaryOriginMissing));
}

// --- Edge cases ---

#[test]
fn analyze_no_cors_headers_returns_empty() {
    let headers: Vec<(&str, &str)> = vec![("Content-Type", "text/html")];
    let issues = analyze_cors_headers(&headers, "https://evil.com", "example.com");
    assert!(issues.is_empty());
}

#[test]
fn analyze_empty_headers_returns_empty() {
    let headers: Vec<(&str, &str)> = vec![];
    let issues = analyze_cors_headers(&headers, "https://evil.com", "example.com");
    assert!(issues.is_empty());
}

#[test]
fn analyze_case_insensitive_header_names() {
    let headers = vec![
        ("access-control-allow-origin", "*"),
        ("ACCESS-CONTROL-ALLOW-METHODS", "GET"),
    ];
    let issues = analyze_cors_headers(&headers, "https://evil.com", "example.com");
    assert!(issues.iter().any(|i| *i == CorsIssue::WildcardOrigin));
}

#[test]
fn analyze_credentials_case_insensitive() {
    let headers = vec![
        ("Access-Control-Allow-Origin", "null"),
        ("Access-Control-Allow-Credentials", "TRUE"),
        ("Access-Control-Allow-Methods", "GET"),
    ];
    let issues = analyze_cors_headers(&headers, "https://evil.com", "example.com");
    assert!(issues.iter().any(|i| *i == CorsIssue::CredentialsWithNull));
}

#[test]
fn analyze_multiple_issues_single_response() {
    let headers = vec![
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Credentials", "true"),
        ("Access-Control-Allow-Methods", "*"),
        ("Access-Control-Allow-Headers", "*"),
        ("Access-Control-Max-Age", "100000"),
    ];
    let issues = analyze_cors_headers(&headers, "https://evil.com", "example.com");
    assert!(issues.iter().any(|i| *i == CorsIssue::WildcardOrigin));
    assert!(
        issues
            .iter()
            .any(|i| *i == CorsIssue::CredentialsWithWildcard)
    );
    assert!(issues.iter().any(|i| *i == CorsIssue::WildcardMethods));
    assert!(issues.iter().any(|i| *i == CorsIssue::WildcardHeaders));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CorsIssue::ExcessiveMaxAge { seconds } if *seconds == 100000))
    );
}

#[test]
fn analyze_max_age_non_numeric_ignored() {
    let headers = vec![
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Max-Age", "abc"),
        ("Access-Control-Allow-Methods", "GET"),
    ];
    let issues = analyze_cors_headers(&headers, "https://evil.com", "example.com");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CorsIssue::ExcessiveMaxAge { .. }))
    );
}

#[test]
fn analyze_specific_methods_not_wildcard() {
    let headers = vec![
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Methods", "GET, POST"),
    ];
    let issues = analyze_cors_headers(&headers, "https://evil.com", "example.com");
    assert!(!issues.iter().any(|i| *i == CorsIssue::WildcardMethods));
}

#[test]
fn analyze_specific_headers_not_wildcard() {
    let headers = vec![
        ("Access-Control-Allow-Origin", "*"),
        (
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization",
        ),
        ("Access-Control-Allow-Methods", "GET"),
    ];
    let issues = analyze_cors_headers(&headers, "https://evil.com", "example.com");
    assert!(!issues.iter().any(|i| *i == CorsIssue::WildcardHeaders));
}

// --- Display tests ---

#[test]
fn display_wildcard_origin() {
    assert_eq!(CorsIssue::WildcardOrigin.to_string(), "wildcard_origin");
}

#[test]
fn display_null_origin() {
    assert_eq!(CorsIssue::NullOrigin.to_string(), "null_origin");
}

#[test]
fn display_reflected_origin() {
    let issue = CorsIssue::ReflectedOrigin {
        origin: "https://evil.com".to_string(),
    };
    assert_eq!(issue.to_string(), "reflected_origin");
}

#[test]
fn display_arbitrary_subdomain() {
    let issue = CorsIssue::ArbitrarySubdomain {
        origin: "https://evil.example.com".to_string(),
    };
    assert_eq!(issue.to_string(), "arbitrary_subdomain");
}

#[test]
fn display_credentials_with_wildcard() {
    assert_eq!(
        CorsIssue::CredentialsWithWildcard.to_string(),
        "credentials_with_wildcard"
    );
}

#[test]
fn display_credentials_with_reflection() {
    let issue = CorsIssue::CredentialsWithReflection {
        origin: "https://evil.com".to_string(),
    };
    assert_eq!(issue.to_string(), "credentials_with_reflection");
}

#[test]
fn display_credentials_with_null() {
    assert_eq!(
        CorsIssue::CredentialsWithNull.to_string(),
        "credentials_with_null"
    );
}

#[test]
fn display_preflight_missing() {
    assert_eq!(CorsIssue::PreflightMissing.to_string(), "preflight_missing");
}

#[test]
fn display_wildcard_methods() {
    assert_eq!(CorsIssue::WildcardMethods.to_string(), "wildcard_methods");
}

#[test]
fn display_wildcard_headers() {
    assert_eq!(CorsIssue::WildcardHeaders.to_string(), "wildcard_headers");
}

#[test]
fn display_excessive_max_age() {
    let issue = CorsIssue::ExcessiveMaxAge { seconds: 90000 };
    assert_eq!(issue.to_string(), "excessive_max_age");
}

#[test]
fn display_vary_origin_missing() {
    assert_eq!(
        CorsIssue::VaryOriginMissing.to_string(),
        "vary_origin_missing"
    );
}

// --- Severity tests ---

#[test]
fn severity_credentials_with_reflection_highest() {
    assert_eq!(
        cors_severity(&CorsIssue::CredentialsWithReflection {
            origin: String::new()
        }),
        8.0
    );
}

#[test]
fn severity_credentials_with_null() {
    assert_eq!(cors_severity(&CorsIssue::CredentialsWithNull), 7.5);
}

#[test]
fn severity_credentials_with_wildcard() {
    assert_eq!(cors_severity(&CorsIssue::CredentialsWithWildcard), 7.0);
}

#[test]
fn severity_reflected_origin() {
    assert_eq!(
        cors_severity(&CorsIssue::ReflectedOrigin {
            origin: String::new()
        }),
        7.0
    );
}

#[test]
fn severity_null_origin() {
    assert_eq!(cors_severity(&CorsIssue::NullOrigin), 6.0);
}

#[test]
fn severity_arbitrary_subdomain() {
    assert_eq!(
        cors_severity(&CorsIssue::ArbitrarySubdomain {
            origin: String::new()
        }),
        5.5
    );
}

#[test]
fn severity_wildcard_methods() {
    assert_eq!(cors_severity(&CorsIssue::WildcardMethods), 4.5);
}

#[test]
fn severity_wildcard_origin() {
    assert_eq!(cors_severity(&CorsIssue::WildcardOrigin), 4.0);
}

#[test]
fn severity_wildcard_headers() {
    assert_eq!(cors_severity(&CorsIssue::WildcardHeaders), 4.0);
}

#[test]
fn severity_preflight_missing() {
    assert_eq!(cors_severity(&CorsIssue::PreflightMissing), 3.0);
}

#[test]
fn severity_vary_origin_missing() {
    assert_eq!(cors_severity(&CorsIssue::VaryOriginMissing), 2.5);
}

#[test]
fn severity_excessive_max_age() {
    assert_eq!(
        cors_severity(&CorsIssue::ExcessiveMaxAge { seconds: 90000 }),
        2.0
    );
}

#[test]
fn severity_ordering_complete() {
    let ordered = vec![
        CorsIssue::CredentialsWithReflection {
            origin: String::new(),
        },
        CorsIssue::CredentialsWithNull,
        CorsIssue::CredentialsWithWildcard,
        CorsIssue::ReflectedOrigin {
            origin: String::new(),
        },
        CorsIssue::NullOrigin,
        CorsIssue::ArbitrarySubdomain {
            origin: String::new(),
        },
        CorsIssue::WildcardMethods,
        CorsIssue::WildcardOrigin,
        CorsIssue::WildcardHeaders,
        CorsIssue::PreflightMissing,
        CorsIssue::VaryOriginMissing,
        CorsIssue::ExcessiveMaxAge { seconds: 90000 },
    ];
    for window in ordered.windows(2) {
        assert!(
            cors_severity(&window[0]) >= cors_severity(&window[1]),
            "{} ({}) should be >= {} ({})",
            window[0],
            cors_severity(&window[0]),
            window[1],
            cors_severity(&window[1])
        );
    }
}

// --- Operations tests ---

#[test]
fn cors_findings_to_operations_creates_entries() {
    let findings = vec![
        CorsIssue::WildcardOrigin,
        CorsIssue::ReflectedOrigin {
            origin: "https://evil.com".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = cors_findings_to_operations(&findings, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
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
fn cors_findings_to_operations_empty() {
    let mut seq = 3;
    let ops = cors_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 3);
}

#[test]
fn cors_findings_to_operations_severity_matches() {
    let findings = vec![CorsIssue::CredentialsWithReflection {
        origin: "https://evil.com".to_string(),
    }];
    let mut seq = 0;
    let ops = cors_findings_to_operations(&findings, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert_eq!(*severity, 8.0);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn cors_findings_to_operations_confidence_half() {
    let findings = vec![CorsIssue::WildcardOrigin];
    let mut seq = 0;
    let ops = cors_findings_to_operations(&findings, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { confidence, .. } => {
            assert_eq!(confidence.value(), 0.5);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn cors_findings_to_operations_sequence_increments() {
    let findings = vec![
        CorsIssue::WildcardOrigin,
        CorsIssue::NullOrigin,
        CorsIssue::PreflightMissing,
    ];
    let mut seq = 10;
    let ops = cors_findings_to_operations(&findings, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 13);
    assert_eq!(ops[0].sequence_number, 11);
    assert_eq!(ops[1].sequence_number, 12);
    assert_eq!(ops[2].sequence_number, 13);
}

#[test]
fn cors_findings_to_operations_per_issue_severity() {
    let findings = vec![CorsIssue::WildcardOrigin, CorsIssue::NullOrigin];
    let mut seq = 0;
    let ops = cors_findings_to_operations(&findings, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert_eq!(*severity, 4.0);
        }
        _ => panic!("expected AddFinding"),
    }
    match &ops[1].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert_eq!(*severity, 6.0);
        }
        _ => panic!("expected AddFinding"),
    }
}

// --- scan_cors localhost guard ---

#[test]
fn scan_cors_skips_localhost() {
    let findings = scan_cors("http://localhost:8080");
    assert!(findings.is_empty());
}

#[test]
fn scan_cors_skips_loopback() {
    let findings = scan_cors("http://127.0.0.1");
    assert!(findings.is_empty());
}

#[test]
fn scan_cors_skips_invalid() {
    let findings = scan_cors("not-a-url");
    assert!(findings.is_empty());
}
