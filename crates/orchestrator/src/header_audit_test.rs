use crate::header_audit::*;

fn all_secure_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "content-security-policy",
            "default-src 'self'; script-src 'self'",
        ),
        ("x-frame-options", "DENY"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "strict-origin"),
        ("permissions-policy", "geolocation=()"),
        (
            "strict-transport-security",
            "max-age=63072000; includeSubDomains",
        ),
    ]
}

// --- Missing header detection ---

#[test]
fn detects_all_missing_when_no_headers() {
    let issues = analyze_security_headers(&[]);
    let missing: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, HeaderIssue::MissingSecurityHeader { .. }))
        .collect();
    assert_eq!(missing.len(), 5);
}

#[test]
fn detects_missing_csp() {
    let headers: Vec<(&str, &str)> = vec![
        ("x-frame-options", "DENY"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "strict-origin"),
        ("permissions-policy", "geolocation=()"),
    ];
    let issues = analyze_security_headers(&headers);
    assert!(issues.contains(&HeaderIssue::MissingSecurityHeader {
        header: "content-security-policy".to_string(),
    }));
}

#[test]
fn detects_missing_x_frame_options() {
    let headers: Vec<(&str, &str)> = vec![
        ("content-security-policy", "default-src 'self'"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "strict-origin"),
        ("permissions-policy", "geolocation=()"),
    ];
    let issues = analyze_security_headers(&headers);
    assert!(issues.contains(&HeaderIssue::MissingSecurityHeader {
        header: "x-frame-options".to_string(),
    }));
}

#[test]
fn detects_missing_x_content_type_options() {
    let headers: Vec<(&str, &str)> = vec![
        ("content-security-policy", "default-src 'self'"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "strict-origin"),
        ("permissions-policy", "geolocation=()"),
    ];
    let issues = analyze_security_headers(&headers);
    assert!(issues.contains(&HeaderIssue::MissingSecurityHeader {
        header: "x-content-type-options".to_string(),
    }));
}

#[test]
fn detects_missing_referrer_policy() {
    let headers: Vec<(&str, &str)> = vec![
        ("content-security-policy", "default-src 'self'"),
        ("x-frame-options", "DENY"),
        ("x-content-type-options", "nosniff"),
        ("permissions-policy", "geolocation=()"),
    ];
    let issues = analyze_security_headers(&headers);
    assert!(issues.contains(&HeaderIssue::MissingSecurityHeader {
        header: "referrer-policy".to_string(),
    }));
}

#[test]
fn detects_missing_permissions_policy() {
    let headers: Vec<(&str, &str)> = vec![
        ("content-security-policy", "default-src 'self'"),
        ("x-frame-options", "DENY"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "strict-origin"),
    ];
    let issues = analyze_security_headers(&headers);
    assert!(issues.contains(&HeaderIssue::MissingSecurityHeader {
        header: "permissions-policy".to_string(),
    }));
}

#[test]
fn no_missing_when_all_present() {
    let issues = analyze_security_headers(&all_secure_headers());
    let missing: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, HeaderIssue::MissingSecurityHeader { .. }))
        .collect();
    assert!(missing.is_empty());
}

// --- CSP weak policy detection ---

#[test]
fn detects_csp_unsafe_inline() {
    let headers = vec![(
        "content-security-policy",
        "default-src 'self'; script-src 'unsafe-inline'",
    )];
    let issues = analyze_security_headers(&headers);
    assert!(issues.contains(&HeaderIssue::WeakCspPolicy {
        directive: "'unsafe-inline'".to_string(),
    }));
}

#[test]
fn detects_csp_unsafe_eval() {
    let headers = vec![(
        "content-security-policy",
        "default-src 'self'; script-src 'unsafe-eval'",
    )];
    let issues = analyze_security_headers(&headers);
    assert!(issues.contains(&HeaderIssue::WeakCspPolicy {
        directive: "'unsafe-eval'".to_string(),
    }));
}

#[test]
fn detects_csp_wildcard() {
    let headers = vec![("content-security-policy", "default-src *")];
    let issues = analyze_security_headers(&headers);
    assert!(issues.contains(&HeaderIssue::WeakCspPolicy {
        directive: "*".to_string(),
    }));
}

#[test]
fn strong_csp_no_weak_issues() {
    let headers = vec![(
        "content-security-policy",
        "default-src 'self'; script-src 'self' 'nonce-abc123'",
    )];
    let issues = analyze_security_headers(&headers);
    let weak: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, HeaderIssue::WeakCspPolicy { .. }))
        .collect();
    assert!(weak.is_empty());
}

#[test]
fn csp_both_unsafe_inline_and_eval() {
    let headers = vec![(
        "content-security-policy",
        "script-src 'unsafe-inline' 'unsafe-eval'",
    )];
    let issues = analyze_security_headers(&headers);
    let weak: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, HeaderIssue::WeakCspPolicy { .. }))
        .collect();
    assert_eq!(weak.len(), 2);
}

// --- CORS detection ---

#[test]
fn detects_cors_wildcard() {
    let headers = vec![("access-control-allow-origin", "*")];
    let issues = analyze_security_headers(&headers);
    assert!(issues.contains(&HeaderIssue::PermissiveCors {
        origin: "*".to_string(),
    }));
}

#[test]
fn restrictive_cors_no_issue() {
    let headers = vec![("access-control-allow-origin", "https://example.com")];
    let issues = analyze_security_headers(&headers);
    let cors: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, HeaderIssue::PermissiveCors { .. }))
        .collect();
    assert!(cors.is_empty());
}

#[test]
fn no_cors_header_no_issue() {
    let issues = analyze_security_headers(&all_secure_headers());
    let cors: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, HeaderIssue::PermissiveCors { .. }))
        .collect();
    assert!(cors.is_empty());
}

// --- HSTS detection ---

#[test]
fn detects_hsts_missing_subdomains() {
    let headers = vec![("strict-transport-security", "max-age=63072000")];
    let issues = analyze_security_headers(&headers);
    assert!(issues.contains(&HeaderIssue::MissingHstsSubdomains));
}

#[test]
fn detects_hsts_short_max_age() {
    let headers = vec![(
        "strict-transport-security",
        "max-age=3600; includeSubDomains",
    )];
    let issues = analyze_security_headers(&headers);
    assert!(issues.contains(&HeaderIssue::ShortHstsMaxAge { max_age: 3600 }));
}

#[test]
fn hsts_proper_value_no_issues() {
    let headers = vec![(
        "strict-transport-security",
        "max-age=63072000; includeSubDomains",
    )];
    let issues = analyze_security_headers(&headers);
    let hsts: Vec<_> = issues
        .iter()
        .filter(|i| {
            matches!(
                i,
                HeaderIssue::MissingHstsSubdomains | HeaderIssue::ShortHstsMaxAge { .. }
            )
        })
        .collect();
    assert!(hsts.is_empty());
}

#[test]
fn hsts_exactly_one_year_no_short_issue() {
    let headers = vec![(
        "strict-transport-security",
        "max-age=31536000; includeSubDomains",
    )];
    let issues = analyze_security_headers(&headers);
    let short: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, HeaderIssue::ShortHstsMaxAge { .. }))
        .collect();
    assert!(short.is_empty());
}

#[test]
fn hsts_one_less_than_year_is_short() {
    let headers = vec![(
        "strict-transport-security",
        "max-age=31535999; includeSubDomains",
    )];
    let issues = analyze_security_headers(&headers);
    assert!(issues.contains(&HeaderIssue::ShortHstsMaxAge {
        max_age: 31_535_999
    }));
}

// --- Referrer-Policy detection ---

#[test]
fn detects_insecure_referrer_unsafe_url() {
    let headers = vec![("referrer-policy", "unsafe-url")];
    let issues = analyze_security_headers(&headers);
    assert!(issues.contains(&HeaderIssue::InsecureReferrerPolicy {
        policy: "unsafe-url".to_string(),
    }));
}

#[test]
fn detects_insecure_referrer_no_referrer_when_downgrade() {
    let headers = vec![("referrer-policy", "no-referrer-when-downgrade")];
    let issues = analyze_security_headers(&headers);
    assert!(issues.contains(&HeaderIssue::InsecureReferrerPolicy {
        policy: "no-referrer-when-downgrade".to_string(),
    }));
}

#[test]
fn safe_referrer_strict_origin() {
    let headers = vec![("referrer-policy", "strict-origin")];
    let issues = analyze_security_headers(&headers);
    let rp: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, HeaderIssue::InsecureReferrerPolicy { .. }))
        .collect();
    assert!(rp.is_empty());
}

#[test]
fn safe_referrer_same_origin() {
    let headers = vec![("referrer-policy", "same-origin")];
    let issues = analyze_security_headers(&headers);
    let rp: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, HeaderIssue::InsecureReferrerPolicy { .. }))
        .collect();
    assert!(rp.is_empty());
}

#[test]
fn safe_referrer_no_referrer() {
    let headers = vec![("referrer-policy", "no-referrer")];
    let issues = analyze_security_headers(&headers);
    let rp: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, HeaderIssue::InsecureReferrerPolicy { .. }))
        .collect();
    assert!(rp.is_empty());
}

// --- X-XSS-Protection detection ---

#[test]
fn detects_deprecated_xss_protection() {
    let headers = vec![("x-xss-protection", "1; mode=block")];
    let issues = analyze_security_headers(&headers);
    assert!(issues.contains(&HeaderIssue::DeprecatedXssProtection));
}

#[test]
fn no_xss_protection_header_no_issue() {
    let issues = analyze_security_headers(&all_secure_headers());
    assert!(!issues.contains(&HeaderIssue::DeprecatedXssProtection));
}

// --- Server version exposure ---

#[test]
fn detects_server_version_exposed() {
    let headers = vec![("server", "Apache/2.4.51")];
    let issues = analyze_security_headers(&headers);
    assert!(issues.contains(&HeaderIssue::ServerVersionExposed {
        server: "Apache/2.4.51".to_string(),
    }));
}

#[test]
fn server_without_version_no_issue() {
    let headers = vec![("server", "nginx")];
    let issues = analyze_security_headers(&headers);
    let sv: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, HeaderIssue::ServerVersionExposed { .. }))
        .collect();
    assert!(sv.is_empty());
}

#[test]
fn detects_server_nginx_version() {
    let headers = vec![("server", "nginx/1.24.0")];
    let issues = analyze_security_headers(&headers);
    assert!(issues.contains(&HeaderIssue::ServerVersionExposed {
        server: "nginx/1.24.0".to_string(),
    }));
}

// --- X-Powered-By exposure ---

#[test]
fn detects_powered_by_exposed() {
    let headers = vec![("x-powered-by", "Express")];
    let issues = analyze_security_headers(&headers);
    assert!(issues.contains(&HeaderIssue::PoweredByExposed {
        value: "Express".to_string(),
    }));
}

#[test]
fn detects_powered_by_php() {
    let headers = vec![("x-powered-by", "PHP/8.1.0")];
    let issues = analyze_security_headers(&headers);
    assert!(issues.contains(&HeaderIssue::PoweredByExposed {
        value: "PHP/8.1.0".to_string(),
    }));
}

// --- Display format ---

#[test]
fn display_missing_security_header() {
    let issue = HeaderIssue::MissingSecurityHeader {
        header: "content-security-policy".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "missing_security_header:content-security-policy"
    );
}

#[test]
fn display_weak_csp_policy() {
    let issue = HeaderIssue::WeakCspPolicy {
        directive: "'unsafe-inline'".to_string(),
    };
    assert_eq!(issue.to_string(), "weak_csp_policy:'unsafe-inline'");
}

#[test]
fn display_permissive_cors() {
    let issue = HeaderIssue::PermissiveCors {
        origin: "*".to_string(),
    };
    assert_eq!(issue.to_string(), "permissive_cors:*");
}

#[test]
fn display_missing_hsts_subdomains() {
    let issue = HeaderIssue::MissingHstsSubdomains;
    assert_eq!(issue.to_string(), "missing_hsts_subdomains");
}

#[test]
fn display_short_hsts_max_age() {
    let issue = HeaderIssue::ShortHstsMaxAge { max_age: 3600 };
    assert_eq!(issue.to_string(), "short_hsts_max_age:3600");
}

#[test]
fn display_insecure_referrer_policy() {
    let issue = HeaderIssue::InsecureReferrerPolicy {
        policy: "unsafe-url".to_string(),
    };
    assert_eq!(issue.to_string(), "insecure_referrer_policy:unsafe-url");
}

#[test]
fn display_deprecated_xss_protection() {
    let issue = HeaderIssue::DeprecatedXssProtection;
    assert_eq!(issue.to_string(), "deprecated_xss_protection");
}

#[test]
fn display_server_version_exposed() {
    let issue = HeaderIssue::ServerVersionExposed {
        server: "Apache/2.4.51".to_string(),
    };
    assert_eq!(issue.to_string(), "server_version_exposed:Apache/2.4.51");
}

#[test]
fn display_powered_by_exposed() {
    let issue = HeaderIssue::PoweredByExposed {
        value: "Express".to_string(),
    };
    assert_eq!(issue.to_string(), "powered_by_exposed:Express");
}

// --- Severity scores ---

#[test]
fn severity_missing_csp() {
    let issue = HeaderIssue::MissingSecurityHeader {
        header: "content-security-policy".to_string(),
    };
    assert!((header_severity(&issue) - 6.0).abs() < f64::EPSILON);
}

#[test]
fn severity_missing_unknown_header() {
    let issue = HeaderIssue::MissingSecurityHeader {
        header: "unknown-header".to_string(),
    };
    assert!((header_severity(&issue) - 3.0).abs() < f64::EPSILON);
}

#[test]
fn severity_weak_csp() {
    let issue = HeaderIssue::WeakCspPolicy {
        directive: "'unsafe-inline'".to_string(),
    };
    assert!((header_severity(&issue) - 5.0).abs() < f64::EPSILON);
}

#[test]
fn severity_permissive_cors() {
    let issue = HeaderIssue::PermissiveCors {
        origin: "*".to_string(),
    };
    assert!((header_severity(&issue) - 6.0).abs() < f64::EPSILON);
}

#[test]
fn severity_missing_hsts_subdomains() {
    assert!((header_severity(&HeaderIssue::MissingHstsSubdomains) - 3.0).abs() < f64::EPSILON);
}

#[test]
fn severity_short_hsts() {
    let issue = HeaderIssue::ShortHstsMaxAge { max_age: 3600 };
    assert!((header_severity(&issue) - 3.5).abs() < f64::EPSILON);
}

#[test]
fn severity_insecure_referrer() {
    let issue = HeaderIssue::InsecureReferrerPolicy {
        policy: "unsafe-url".to_string(),
    };
    assert!((header_severity(&issue) - 2.5).abs() < f64::EPSILON);
}

#[test]
fn severity_deprecated_xss() {
    assert!((header_severity(&HeaderIssue::DeprecatedXssProtection) - 2.0).abs() < f64::EPSILON);
}

#[test]
fn severity_server_version() {
    let issue = HeaderIssue::ServerVersionExposed {
        server: "nginx/1.24".to_string(),
    };
    assert!((header_severity(&issue) - 2.5).abs() < f64::EPSILON);
}

#[test]
fn severity_powered_by() {
    let issue = HeaderIssue::PoweredByExposed {
        value: "Express".to_string(),
    };
    assert!((header_severity(&issue) - 2.0).abs() < f64::EPSILON);
}

// --- to_operations ---

#[test]
fn header_to_operations_creates_findings() {
    let issues = vec![
        HeaderIssue::MissingSecurityHeader {
            header: "content-security-policy".to_string(),
        },
        HeaderIssue::WeakCspPolicy {
            directive: "'unsafe-inline'".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = header_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn header_to_operations_missing_uses_missing_class() {
    let issues = vec![HeaderIssue::MissingSecurityHeader {
        header: "x-frame-options".to_string(),
    }];
    let mut seq = 0;
    let ops = header_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            confidence,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::MissingSecurityHeader
            );
            assert!((confidence.value() - 0.95).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn header_to_operations_weak_config_uses_misconfig_class() {
    let issues = vec![HeaderIssue::WeakCspPolicy {
        directive: "'unsafe-eval'".to_string(),
    }];
    let mut seq = 0;
    let ops = header_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            confidence,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::SecurityMisconfiguration
            );
            assert!((confidence.value() - 0.5).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn header_to_operations_empty() {
    let mut seq = 5;
    let ops = header_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn header_to_operations_correct_severity() {
    let issues = vec![HeaderIssue::PermissiveCors {
        origin: "*".to_string(),
    }];
    let mut seq = 0;
    let ops = header_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert!((severity - 6.0).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn header_findings_to_operations_backward_compat() {
    let issues = vec![HeaderIssue::MissingSecurityHeader {
        header: "x-content-type-options".to_string(),
    }];
    let mut seq = 0;
    let ops = header_findings_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

// --- Empty / edge cases ---

#[test]
fn empty_input_no_issues_except_missing() {
    let issues = analyze_security_headers(&[]);
    assert_eq!(issues.len(), 5);
    for issue in &issues {
        assert!(matches!(issue, HeaderIssue::MissingSecurityHeader { .. }));
    }
}

#[test]
fn all_secure_headers_no_issues() {
    let issues = analyze_security_headers(&all_secure_headers());
    assert!(issues.is_empty());
}

#[test]
fn audit_security_headers_skips_localhost() {
    let issues = audit_security_headers("http://localhost:8080");
    assert!(issues.is_empty());
}

#[test]
fn audit_security_headers_skips_loopback() {
    let issues = audit_security_headers("http://127.0.0.1:3000");
    assert!(issues.is_empty());
}

#[test]
fn required_headers_has_five_entries() {
    assert_eq!(REQUIRED_HEADERS.len(), 5);
}

#[test]
fn required_headers_all_lowercase() {
    for (name, _) in REQUIRED_HEADERS {
        assert_eq!(*name, name.to_lowercase());
    }
}
