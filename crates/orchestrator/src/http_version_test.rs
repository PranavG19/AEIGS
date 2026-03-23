use crate::http_version::*;

#[test]
fn version_to_operations_creates_node() {
    let info = HttpVersionInfo {
        version: "HTTP/2.0".to_string(),
        supports_h2: true,
    };
    let mut seq = 0;
    let ops = version_to_operations(&info, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddNode {
            node_type,
            properties,
        } => {
            assert_eq!(*node_type, aegis_protocol::node::NodeType::Service);
            let version = properties
                .iter()
                .find(|(k, _)| k == "http_version")
                .unwrap();
            assert_eq!(version.1, "HTTP/2.0");
            let h2 = properties.iter().find(|(k, _)| k == "supports_h2").unwrap();
            assert_eq!(h2.1, "true");
        }
        _ => panic!("expected AddNode"),
    }
}

#[test]
fn version_to_operations_no_h2() {
    let info = HttpVersionInfo {
        version: "HTTP/1.1".to_string(),
        supports_h2: false,
    };
    let mut seq = 5;
    let ops = version_to_operations(&info, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 6);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddNode { properties, .. } => {
            let h2 = properties.iter().find(|(k, _)| k == "supports_h2").unwrap();
            assert_eq!(h2.1, "false");
        }
        _ => panic!("expected AddNode"),
    }
}

#[test]
fn detect_http_version_skips_localhost() {
    let result = detect_http_version("http://localhost:8080");
    assert!(result.is_none());
}

#[test]
fn detect_http_version_skips_invalid() {
    let result = detect_http_version("not-a-url");
    assert!(result.is_none());
}

#[test]
fn version_to_operations_increments_sequence() {
    let info = HttpVersionInfo {
        version: "HTTP/1.1".to_string(),
        supports_h2: false,
    };
    let mut seq = 10;
    let ops = version_to_operations(&info, &mut seq);
    assert_eq!(seq, 11);
    assert_eq!(ops[0].sequence_number, 11);
}

#[test]
fn version_to_operations_includes_source() {
    let info = HttpVersionInfo {
        version: "HTTP/2.0".to_string(),
        supports_h2: true,
    };
    let mut seq = 0;
    let ops = version_to_operations(&info, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddNode { properties, .. } => {
            let source = properties.iter().find(|(k, _)| k == "source").unwrap();
            assert_eq!(source.1, "http_version_detect");
        }
        _ => panic!("expected AddNode"),
    }
}

#[test]
fn detect_http_version_skips_loopback() {
    let result = detect_http_version("http://127.0.0.1:8080");
    assert!(result.is_none());
}

// --- HttpVersionIssue Display tests ---

#[test]
fn display_http10() {
    let issue = HttpVersionIssue::Http10 {
        version: "HTTP/1.0".to_string(),
    };
    assert_eq!(issue.to_string(), "http10_detected");
}

#[test]
fn display_http11_only() {
    assert_eq!(HttpVersionIssue::Http11Only.to_string(), "http11_only");
}

#[test]
fn display_no_hsts() {
    assert_eq!(HttpVersionIssue::NoHsts.to_string(), "no_hsts");
}

#[test]
fn display_insecure_downgrade() {
    assert_eq!(
        HttpVersionIssue::InsecureDowngrade.to_string(),
        "insecure_downgrade"
    );
}

#[test]
fn display_missing_security_headers() {
    let issue = HttpVersionIssue::MissingSecurityHeaders {
        headers: vec!["x-frame-options".to_string()],
    };
    assert_eq!(issue.to_string(), "missing_security_headers");
}

#[test]
fn display_server_version_exposed() {
    let issue = HttpVersionIssue::ServerVersionExposed {
        server: "Apache/2.4.51".to_string(),
    };
    assert_eq!(issue.to_string(), "server_version_exposed");
}

#[test]
fn display_deprecated_protocol() {
    let issue = HttpVersionIssue::DeprecatedProtocol {
        protocol: "SSLv3".to_string(),
    };
    assert_eq!(issue.to_string(), "deprecated_protocol");
}

#[test]
fn display_connection_keep_alive() {
    assert_eq!(
        HttpVersionIssue::ConnectionKeepAlive.to_string(),
        "connection_keep_alive"
    );
}

// --- Severity tests ---

#[test]
fn severity_insecure_downgrade_highest() {
    let severity = http_version_severity(&HttpVersionIssue::InsecureDowngrade);
    assert_eq!(severity, 7.0);
}

#[test]
fn severity_server_version_exposed() {
    let severity = http_version_severity(&HttpVersionIssue::ServerVersionExposed {
        server: "nginx/1.20.0".to_string(),
    });
    assert_eq!(severity, 5.0);
}

#[test]
fn severity_no_hsts() {
    assert_eq!(http_version_severity(&HttpVersionIssue::NoHsts), 5.0);
}

#[test]
fn severity_http10() {
    let severity = http_version_severity(&HttpVersionIssue::Http10 {
        version: "HTTP/1.0".to_string(),
    });
    assert_eq!(severity, 4.0);
}

#[test]
fn severity_deprecated_protocol() {
    let severity = http_version_severity(&HttpVersionIssue::DeprecatedProtocol {
        protocol: "SSLv3".to_string(),
    });
    assert_eq!(severity, 4.0);
}

#[test]
fn severity_missing_security_headers() {
    let severity = http_version_severity(&HttpVersionIssue::MissingSecurityHeaders {
        headers: vec!["x-frame-options".to_string()],
    });
    assert_eq!(severity, 3.5);
}

#[test]
fn severity_http11_only() {
    assert_eq!(http_version_severity(&HttpVersionIssue::Http11Only), 2.0);
}

#[test]
fn severity_connection_keep_alive() {
    assert_eq!(
        http_version_severity(&HttpVersionIssue::ConnectionKeepAlive),
        2.0
    );
}

#[test]
fn severity_ordering_insecure_downgrade_above_server_exposed() {
    let high = http_version_severity(&HttpVersionIssue::InsecureDowngrade);
    let low = http_version_severity(&HttpVersionIssue::ServerVersionExposed {
        server: "Apache/2.4.51".to_string(),
    });
    assert!(high > low);
}

#[test]
fn severity_ordering_server_exposed_above_http11_only() {
    let high = http_version_severity(&HttpVersionIssue::ServerVersionExposed {
        server: "nginx/1.20.0".to_string(),
    });
    let low = http_version_severity(&HttpVersionIssue::Http11Only);
    assert!(high > low);
}

// --- analyze_http_version tests ---

#[test]
fn analyze_detects_http10() {
    let issues = analyze_http_version("HTTP/1.0", false, &[]);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::Http10 { .. }))
    );
}

#[test]
fn analyze_http10_case_insensitive() {
    let issues = analyze_http_version("http/1.0", false, &[]);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::Http10 { .. }))
    );
}

#[test]
fn analyze_http10_preserves_version_string() {
    let issues = analyze_http_version("HTTP/1.0", false, &[]);
    let http10 = issues
        .iter()
        .find(|i| matches!(i, HttpVersionIssue::Http10 { .. }))
        .unwrap();
    match http10 {
        HttpVersionIssue::Http10 { version } => assert_eq!(version, "HTTP/1.0"),
        _ => panic!("expected Http10"),
    }
}

#[test]
fn analyze_http11_no_h2_detects_http11_only() {
    let issues = analyze_http_version("HTTP/1.1", false, &[]);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::Http11Only))
    );
}

#[test]
fn analyze_http2_no_http11_only() {
    let headers = &[("strict-transport-security", "max-age=31536000")];
    let issues = analyze_http_version("HTTP/2.0", true, headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::Http11Only))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::Http10 { .. }))
    );
}

#[test]
fn analyze_detects_no_hsts() {
    let issues = analyze_http_version("HTTP/2.0", true, &[]);
    assert!(issues.iter().any(|i| matches!(i, HttpVersionIssue::NoHsts)));
}

#[test]
fn analyze_hsts_present_no_issue() {
    let headers = &[
        ("strict-transport-security", "max-age=31536000"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("x-xss-protection", "1; mode=block"),
        ("content-security-policy", "default-src 'self'"),
        ("referrer-policy", "strict-origin"),
    ];
    let issues = analyze_http_version("HTTP/2.0", true, headers);
    assert!(!issues.iter().any(|i| matches!(i, HttpVersionIssue::NoHsts)));
}

#[test]
fn analyze_hsts_case_insensitive() {
    let headers = &[("Strict-Transport-Security", "max-age=31536000")];
    let issues = analyze_http_version("HTTP/2.0", true, headers);
    assert!(!issues.iter().any(|i| matches!(i, HttpVersionIssue::NoHsts)));
}

#[test]
fn analyze_server_apache_version_exposed() {
    let headers = &[("server", "Apache/2.4.51")];
    let issues = analyze_http_version("HTTP/1.1", false, headers);
    let exposed = issues
        .iter()
        .find(|i| matches!(i, HttpVersionIssue::ServerVersionExposed { .. }));
    assert!(exposed.is_some());
    match exposed.unwrap() {
        HttpVersionIssue::ServerVersionExposed { server } => {
            assert_eq!(server, "Apache/2.4.51");
        }
        _ => panic!("expected ServerVersionExposed"),
    }
}

#[test]
fn analyze_server_nginx_version_exposed() {
    let headers = &[("server", "nginx/1.20.0")];
    let issues = analyze_http_version("HTTP/1.1", false, headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::ServerVersionExposed { .. }))
    );
}

#[test]
fn analyze_server_without_version_no_issue() {
    let headers = &[("server", "Apache")];
    let issues = analyze_http_version("HTTP/2.0", true, headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::ServerVersionExposed { .. }))
    );
}

#[test]
fn analyze_server_generic_name_no_issue() {
    let headers = &[("server", "cloudflare")];
    let issues = analyze_http_version("HTTP/2.0", true, headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::ServerVersionExposed { .. }))
    );
}

#[test]
fn analyze_connection_keep_alive_without_timeout() {
    let headers = &[("connection", "keep-alive")];
    let issues = analyze_http_version("HTTP/1.1", false, headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::ConnectionKeepAlive))
    );
}

#[test]
fn analyze_connection_keep_alive_with_timeout_no_issue() {
    let headers = &[
        ("connection", "keep-alive"),
        ("keep-alive", "timeout=5, max=100"),
    ];
    let issues = analyze_http_version("HTTP/1.1", false, headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::ConnectionKeepAlive))
    );
}

#[test]
fn analyze_connection_keep_alive_case_insensitive() {
    let headers = &[("Connection", "Keep-Alive")];
    let issues = analyze_http_version("HTTP/1.1", false, headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::ConnectionKeepAlive))
    );
}

#[test]
fn analyze_no_connection_header_no_keep_alive_issue() {
    let issues = analyze_http_version("HTTP/1.1", false, &[]);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::ConnectionKeepAlive))
    );
}

#[test]
fn analyze_connection_close_no_keep_alive_issue() {
    let headers = &[("connection", "close")];
    let issues = analyze_http_version("HTTP/1.1", false, headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::ConnectionKeepAlive))
    );
}

#[test]
fn analyze_missing_security_headers_all() {
    let issues = analyze_http_version("HTTP/2.0", true, &[]);
    let missing = issues
        .iter()
        .find(|i| matches!(i, HttpVersionIssue::MissingSecurityHeaders { .. }))
        .unwrap();
    match missing {
        HttpVersionIssue::MissingSecurityHeaders { headers } => {
            assert!(headers.contains(&"x-content-type-options".to_string()));
            assert!(headers.contains(&"x-frame-options".to_string()));
            assert!(headers.contains(&"x-xss-protection".to_string()));
            assert!(headers.contains(&"content-security-policy".to_string()));
            assert!(headers.contains(&"referrer-policy".to_string()));
            assert_eq!(headers.len(), 5);
        }
        _ => panic!("expected MissingSecurityHeaders"),
    }
}

#[test]
fn analyze_missing_security_headers_partial() {
    let headers = &[
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
    ];
    let issues = analyze_http_version("HTTP/2.0", true, headers);
    let missing = issues
        .iter()
        .find(|i| matches!(i, HttpVersionIssue::MissingSecurityHeaders { .. }))
        .unwrap();
    match missing {
        HttpVersionIssue::MissingSecurityHeaders { headers } => {
            assert_eq!(headers.len(), 3);
            assert!(!headers.contains(&"x-content-type-options".to_string()));
            assert!(!headers.contains(&"x-frame-options".to_string()));
            assert!(headers.contains(&"x-xss-protection".to_string()));
            assert!(headers.contains(&"content-security-policy".to_string()));
            assert!(headers.contains(&"referrer-policy".to_string()));
        }
        _ => panic!("expected MissingSecurityHeaders"),
    }
}

#[test]
fn analyze_all_security_headers_present_no_issue() {
    let headers = &[
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("x-xss-protection", "1; mode=block"),
        ("content-security-policy", "default-src 'self'"),
        ("referrer-policy", "strict-origin"),
        ("strict-transport-security", "max-age=31536000"),
    ];
    let issues = analyze_http_version("HTTP/2.0", true, headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::MissingSecurityHeaders { .. }))
    );
}

#[test]
fn analyze_security_headers_case_insensitive() {
    let headers = &[
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("X-XSS-Protection", "1; mode=block"),
        ("Content-Security-Policy", "default-src 'self'"),
        ("Referrer-Policy", "strict-origin"),
        ("Strict-Transport-Security", "max-age=31536000"),
    ];
    let issues = analyze_http_version("HTTP/2.0", true, headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::MissingSecurityHeaders { .. }))
    );
    assert!(!issues.iter().any(|i| matches!(i, HttpVersionIssue::NoHsts)));
}

#[test]
fn analyze_empty_headers_multiple_issues() {
    let issues = analyze_http_version("HTTP/1.1", false, &[]);
    assert!(issues.len() >= 3);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::Http11Only))
    );
    assert!(issues.iter().any(|i| matches!(i, HttpVersionIssue::NoHsts)));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::MissingSecurityHeaders { .. }))
    );
}

#[test]
fn analyze_http10_does_not_emit_http11_only() {
    let issues = analyze_http_version("HTTP/1.0", false, &[]);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::Http10 { .. }))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::Http11Only))
    );
}

#[test]
fn analyze_http2_with_h2_no_version_issue() {
    let headers = &[("strict-transport-security", "max-age=31536000")];
    let issues = analyze_http_version("HTTP/2.0", true, headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::Http10 { .. }))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::Http11Only))
    );
}

#[test]
fn analyze_server_iis_version_exposed() {
    let headers = &[("server", "Microsoft-IIS/10.0")];
    let issues = analyze_http_version("HTTP/1.1", false, headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::ServerVersionExposed { .. }))
    );
}

#[test]
fn analyze_server_lighttpd_version_exposed() {
    let headers = &[("server", "lighttpd/1.4.59")];
    let issues = analyze_http_version("HTTP/1.1", false, headers);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::ServerVersionExposed { .. }))
    );
}

#[test]
fn analyze_server_header_absent_no_exposed() {
    let issues = analyze_http_version("HTTP/2.0", true, &[]);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::ServerVersionExposed { .. }))
    );
}

// --- http_version_to_operations tests ---

#[test]
fn operations_one_per_issue() {
    let issues = vec![
        HttpVersionIssue::NoHsts,
        HttpVersionIssue::Http11Only,
        HttpVersionIssue::ConnectionKeepAlive,
    ];
    let mut seq = 0;
    let ops = http_version_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn operations_empty_issues_empty_ops() {
    let mut seq = 5;
    let ops = http_version_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn operations_sequence_numbers_increment() {
    let issues = vec![HttpVersionIssue::NoHsts, HttpVersionIssue::Http11Only];
    let mut seq = 10;
    let ops = http_version_to_operations(&issues, &mut seq);
    assert_eq!(ops[0].sequence_number, 11);
    assert_eq!(ops[1].sequence_number, 12);
    assert_eq!(seq, 12);
}

#[test]
fn operations_use_add_finding() {
    let issues = vec![HttpVersionIssue::NoHsts];
    let mut seq = 0;
    let ops = http_version_to_operations(&issues, &mut seq);
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
    let issues = vec![HttpVersionIssue::NoHsts];
    let mut seq = 0;
    let ops = http_version_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { confidence, .. } => {
            assert!((confidence.value() - 0.5).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn operations_severity_matches_issue() {
    let issues = vec![HttpVersionIssue::InsecureDowngrade];
    let mut seq = 0;
    let ops = http_version_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert!((severity - 7.0).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding"),
    }
}

// --- Edge case tests ---

#[test]
fn analyze_http10_variant_string() {
    let issues = analyze_http_version("1.0", false, &[]);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::Http10 { .. }))
    );
}

#[test]
fn analyze_http20_string_with_h2() {
    let headers = &[("strict-transport-security", "max-age=31536000")];
    let issues = analyze_http_version("HTTP/2", true, headers);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::Http10 { .. }))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, HttpVersionIssue::Http11Only))
    );
}

#[test]
fn analyze_full_secure_config_minimal_issues() {
    let headers = &[
        (
            "strict-transport-security",
            "max-age=63072000; includeSubDomains; preload",
        ),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("x-xss-protection", "1; mode=block"),
        ("content-security-policy", "default-src 'self'"),
        ("referrer-policy", "strict-origin-when-cross-origin"),
        ("server", "cloudflare"),
    ];
    let issues = analyze_http_version("HTTP/2.0", true, headers);
    assert!(issues.is_empty());
}

#[test]
fn issue_equality() {
    assert_eq!(HttpVersionIssue::NoHsts, HttpVersionIssue::NoHsts);
    assert_eq!(HttpVersionIssue::Http11Only, HttpVersionIssue::Http11Only);
    assert_ne!(HttpVersionIssue::NoHsts, HttpVersionIssue::Http11Only);
}

#[test]
fn issue_clone() {
    let issue = HttpVersionIssue::ServerVersionExposed {
        server: "Apache/2.4.51".to_string(),
    };
    let cloned = issue.clone();
    assert_eq!(issue, cloned);
}

#[test]
fn issue_debug() {
    let issue = HttpVersionIssue::NoHsts;
    let debug = format!("{:?}", issue);
    assert!(debug.contains("NoHsts"));
}
