use crate::info_disclosure::*;

// ── Existing tests (8) ──────────────────────────────────────────────

#[test]
fn disclosure_headers_list() {
    assert!(DISCLOSURE_HEADERS.contains(&"server"));
    assert!(DISCLOSURE_HEADERS.contains(&"x-powered-by"));
    assert!(DISCLOSURE_HEADERS.contains(&"x-debug-token"));
}

#[test]
fn disclosure_severity_debug_highest() {
    assert!(disclosure_severity("x-debug-token") > disclosure_severity("x-powered-by"));
    assert!(disclosure_severity("x-powered-by") > disclosure_severity("server"));
}

#[test]
fn disclosure_severity_aspnet_versions() {
    assert_eq!(
        disclosure_severity("x-aspnet-version"),
        disclosure_severity("x-aspnetmvc-version")
    );
    assert!(disclosure_severity("x-aspnet-version") > disclosure_severity("server"));
}

#[test]
fn disclosure_findings_to_operations_creates_findings() {
    let findings = vec![
        DisclosedHeader {
            header: "server".to_string(),
            value: "Apache/2.4.51".to_string(),
        },
        DisclosedHeader {
            header: "x-powered-by".to_string(),
            value: "PHP/8.1".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = disclosure_findings_to_operations(&findings, &mut seq);
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
                    aegis_protocol::finding::VulnerabilityClass::InformationDisclosure
                );
            }
            _ => panic!("expected AddFinding"),
        }
    }
}

#[test]
fn disclosure_findings_severity_matches_header() {
    let findings = vec![DisclosedHeader {
        header: "x-debug-token".to_string(),
        value: "abc123".to_string(),
    }];
    let mut seq = 0;
    let ops = disclosure_findings_to_operations(&findings, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert_eq!(*severity, 5.0);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn disclosure_findings_to_operations_empty() {
    let mut seq = 5;
    let ops = disclosure_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn scan_info_disclosure_skips_localhost() {
    let findings = scan_info_disclosure("http://localhost:8080");
    assert!(findings.is_empty());
}

#[test]
fn scan_info_disclosure_skips_invalid() {
    let findings = scan_info_disclosure("not-a-url");
    assert!(findings.is_empty());
}

// ── InfoDisclosureIssue enum ────────────────────────────────────────

#[test]
fn issue_enum_debug_format() {
    let issue = InfoDisclosureIssue::StackTraceExposed;
    let dbg = format!("{:?}", issue);
    assert!(dbg.contains("StackTraceExposed"));
}

#[test]
fn issue_enum_clone() {
    let issue = InfoDisclosureIssue::ServerVersion {
        header: "Server".into(),
        value: "Apache/2.4.51".into(),
    };
    let cloned = issue.clone();
    assert_eq!(issue, cloned);
}

#[test]
fn issue_enum_eq() {
    let a = InfoDisclosureIssue::DirectoryListing;
    let b = InfoDisclosureIssue::DirectoryListing;
    assert_eq!(a, b);
}

#[test]
fn issue_enum_ne_different_variants() {
    let a = InfoDisclosureIssue::StackTraceExposed;
    let b = InfoDisclosureIssue::DirectoryListing;
    assert_ne!(a, b);
}

// ── Display ─────────────────────────────────────────────────────────

#[test]
fn display_server_version() {
    let issue = InfoDisclosureIssue::ServerVersion {
        header: "Server".into(),
        value: "Apache/2.4.51".into(),
    };
    let s = issue.to_string();
    assert!(s.contains("Server"));
    assert!(s.contains("Apache/2.4.51"));
}

#[test]
fn display_framework_exposed() {
    let issue = InfoDisclosureIssue::FrameworkExposed {
        header: "X-Powered-By".into(),
        value: "Express".into(),
    };
    let s = issue.to_string();
    assert!(s.contains("X-Powered-By"));
    assert!(s.contains("Express"));
}

#[test]
fn display_debug_enabled() {
    let issue = InfoDisclosureIssue::DebugEnabled {
        header: "X-Debug-Token".into(),
        value: "abc123".into(),
    };
    let s = issue.to_string();
    assert!(s.contains("Debug mode"));
    assert!(s.contains("abc123"));
}

#[test]
fn display_internal_ip() {
    let issue = InfoDisclosureIssue::InternalIpExposed {
        header: "X-Forwarded-For".into(),
        ip: "10.0.0.5".into(),
    };
    let s = issue.to_string();
    assert!(s.contains("10.0.0.5"));
    assert!(s.contains("X-Forwarded-For"));
}

#[test]
fn display_stack_trace() {
    let s = InfoDisclosureIssue::StackTraceExposed.to_string();
    assert!(s.contains("Stack trace"));
}

#[test]
fn display_directory_listing() {
    let s = InfoDisclosureIssue::DirectoryListing.to_string();
    assert!(s.contains("Directory listing"));
}

#[test]
fn display_version_in_body() {
    let issue = InfoDisclosureIssue::VersionInBody {
        technology: "nginx".into(),
        version: "1.20.0".into(),
    };
    let s = issue.to_string();
    assert!(s.contains("nginx/1.20.0"));
}

#[test]
fn display_error_message() {
    let issue = InfoDisclosureIssue::ErrorMessageExposed {
        message: "NullPointerException".into(),
    };
    let s = issue.to_string();
    assert!(s.contains("NullPointerException"));
}

#[test]
fn display_phpinfo() {
    let s = InfoDisclosureIssue::PhpInfoExposed.to_string();
    assert!(s.contains("phpinfo()"));
}

#[test]
fn display_backup_file() {
    let issue = InfoDisclosureIssue::BackupFileExposed {
        path: "/db.sql.bak".into(),
    };
    let s = issue.to_string();
    assert!(s.contains("/db.sql.bak"));
}

// ── info_disclosure_severity ────────────────────────────────────────

#[test]
fn severity_phpinfo_highest() {
    assert_eq!(
        info_disclosure_severity(&InfoDisclosureIssue::PhpInfoExposed),
        7.0
    );
}

#[test]
fn severity_backup_file_highest() {
    let issue = InfoDisclosureIssue::BackupFileExposed {
        path: "/backup.zip".into(),
    };
    assert_eq!(info_disclosure_severity(&issue), 7.0);
}

#[test]
fn severity_stack_trace() {
    assert_eq!(
        info_disclosure_severity(&InfoDisclosureIssue::StackTraceExposed),
        6.0
    );
}

#[test]
fn severity_error_message() {
    let issue = InfoDisclosureIssue::ErrorMessageExposed {
        message: "err".into(),
    };
    assert_eq!(info_disclosure_severity(&issue), 5.5);
}

#[test]
fn severity_internal_ip() {
    let issue = InfoDisclosureIssue::InternalIpExposed {
        header: "h".into(),
        ip: "10.0.0.1".into(),
    };
    assert_eq!(info_disclosure_severity(&issue), 5.0);
}

#[test]
fn severity_debug_enabled() {
    let issue = InfoDisclosureIssue::DebugEnabled {
        header: "h".into(),
        value: "v".into(),
    };
    assert_eq!(info_disclosure_severity(&issue), 5.0);
}

#[test]
fn severity_directory_listing() {
    assert_eq!(
        info_disclosure_severity(&InfoDisclosureIssue::DirectoryListing),
        5.0
    );
}

#[test]
fn severity_server_version() {
    let issue = InfoDisclosureIssue::ServerVersion {
        header: "Server".into(),
        value: "Apache/2.4".into(),
    };
    assert_eq!(info_disclosure_severity(&issue), 3.0);
}

#[test]
fn severity_framework_exposed() {
    let issue = InfoDisclosureIssue::FrameworkExposed {
        header: "X-Powered-By".into(),
        value: "PHP/8.1".into(),
    };
    assert_eq!(info_disclosure_severity(&issue), 3.0);
}

#[test]
fn severity_version_in_body() {
    let issue = InfoDisclosureIssue::VersionInBody {
        technology: "nginx".into(),
        version: "1.20".into(),
    };
    assert_eq!(info_disclosure_severity(&issue), 3.0);
}

#[test]
fn severity_ordering_phpinfo_gt_stack_trace() {
    assert!(
        info_disclosure_severity(&InfoDisclosureIssue::PhpInfoExposed)
            > info_disclosure_severity(&InfoDisclosureIssue::StackTraceExposed)
    );
}

#[test]
fn severity_ordering_stack_trace_gt_server_version() {
    let sv = InfoDisclosureIssue::ServerVersion {
        header: "Server".into(),
        value: "x/1".into(),
    };
    assert!(
        info_disclosure_severity(&InfoDisclosureIssue::StackTraceExposed)
            > info_disclosure_severity(&sv)
    );
}

// ── analyze_info_disclosure — header checks ─────────────────────────

#[test]
fn analyze_server_apache() {
    let headers = vec![("Server", "Apache/2.4.51")];
    let issues = analyze_info_disclosure(&headers, "");
    assert!(issues.iter().any(|i| matches!(
        i,
        InfoDisclosureIssue::ServerVersion { value, .. } if value == "Apache/2.4.51"
    )));
}

#[test]
fn analyze_server_nginx() {
    let headers = vec![("Server", "nginx/1.20.0")];
    let issues = analyze_info_disclosure(&headers, "");
    assert!(issues.iter().any(|i| matches!(
        i,
        InfoDisclosureIssue::ServerVersion { value, .. } if value == "nginx/1.20.0"
    )));
}

#[test]
fn analyze_server_iis() {
    let headers = vec![("Server", "Microsoft-IIS/10.0")];
    let issues = analyze_info_disclosure(&headers, "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, InfoDisclosureIssue::ServerVersion { .. }))
    );
}

#[test]
fn analyze_server_no_version_no_issue() {
    let headers = vec![("Server", "cloudflare")];
    let issues = analyze_info_disclosure(&headers, "");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, InfoDisclosureIssue::ServerVersion { .. }))
    );
}

#[test]
fn analyze_framework_x_powered_by() {
    let headers = vec![("X-Powered-By", "PHP/8.1")];
    let issues = analyze_info_disclosure(&headers, "");
    assert!(issues.iter().any(|i| matches!(
        i,
        InfoDisclosureIssue::FrameworkExposed { value, .. } if value == "PHP/8.1"
    )));
}

#[test]
fn analyze_framework_express() {
    let headers = vec![("X-Powered-By", "Express")];
    let issues = analyze_info_disclosure(&headers, "");
    assert!(issues.iter().any(|i| matches!(
        i,
        InfoDisclosureIssue::FrameworkExposed { value, .. } if value == "Express"
    )));
}

#[test]
fn analyze_framework_aspnet() {
    let headers = vec![("X-Powered-By", "ASP.NET")];
    let issues = analyze_info_disclosure(&headers, "");
    assert!(issues.iter().any(|i| matches!(
        i,
        InfoDisclosureIssue::FrameworkExposed { value, .. } if value == "ASP.NET"
    )));
}

#[test]
fn analyze_framework_x_generator() {
    let headers = vec![("X-Generator", "WordPress 6.4")];
    let issues = analyze_info_disclosure(&headers, "");
    assert!(issues.iter().any(|i| matches!(
        i,
        InfoDisclosureIssue::FrameworkExposed { header, .. } if header == "X-Generator"
    )));
}

#[test]
fn analyze_debug_token() {
    let headers = vec![("X-Debug-Token", "abc123")];
    let issues = analyze_info_disclosure(&headers, "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, InfoDisclosureIssue::DebugEnabled { .. }))
    );
}

#[test]
fn analyze_debug_token_link() {
    let headers = vec![("X-Debug-Token-Link", "/_profiler/abc123")];
    let issues = analyze_info_disclosure(&headers, "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, InfoDisclosureIssue::DebugEnabled { .. }))
    );
}

#[test]
fn analyze_x_debug_header() {
    let headers = vec![("X-Debug", "true")];
    let issues = analyze_info_disclosure(&headers, "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, InfoDisclosureIssue::DebugEnabled { .. }))
    );
}

#[test]
fn analyze_internal_ip_10_prefix() {
    let headers = vec![("X-Forwarded-For", "10.0.0.5")];
    let issues = analyze_info_disclosure(&headers, "");
    assert!(issues.iter().any(|i| matches!(
        i,
        InfoDisclosureIssue::InternalIpExposed { ip, .. } if ip == "10.0.0.5"
    )));
}

#[test]
fn analyze_internal_ip_172_16() {
    let headers = vec![("X-Real-IP", "172.16.0.1")];
    let issues = analyze_info_disclosure(&headers, "");
    assert!(issues.iter().any(|i| matches!(
        i,
        InfoDisclosureIssue::InternalIpExposed { ip, .. } if ip == "172.16.0.1"
    )));
}

#[test]
fn analyze_internal_ip_172_31() {
    let headers = vec![("X-Real-IP", "172.31.255.1")];
    let issues = analyze_info_disclosure(&headers, "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, InfoDisclosureIssue::InternalIpExposed { .. }))
    );
}

#[test]
fn analyze_no_internal_ip_172_32() {
    let headers = vec![("X-Real-IP", "172.32.0.1")];
    let issues = analyze_info_disclosure(&headers, "");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, InfoDisclosureIssue::InternalIpExposed { .. }))
    );
}

#[test]
fn analyze_internal_ip_192_168() {
    let headers = vec![("Via", "192.168.1.100")];
    let issues = analyze_info_disclosure(&headers, "");
    assert!(issues.iter().any(|i| matches!(
        i,
        InfoDisclosureIssue::InternalIpExposed { ip, .. } if ip == "192.168.1.100"
    )));
}

#[test]
fn analyze_no_internal_ip_public() {
    let headers = vec![("X-Forwarded-For", "8.8.8.8")];
    let issues = analyze_info_disclosure(&headers, "");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, InfoDisclosureIssue::InternalIpExposed { .. }))
    );
}

// ── analyze_info_disclosure — body checks ───────────────────────────

#[test]
fn analyze_stack_trace_python() {
    let body = r#"Traceback (most recent call last):
  File "/app/main.py", line 42, in handler"#;
    let issues = analyze_info_disclosure(&[], body);
    assert!(issues.contains(&InfoDisclosureIssue::StackTraceExposed));
}

#[test]
fn analyze_stack_trace_java() {
    let body = "Exception in thread \"main\" java.lang.NullPointerException";
    let issues = analyze_info_disclosure(&[], body);
    assert!(issues.contains(&InfoDisclosureIssue::StackTraceExposed));
}

#[test]
fn analyze_stack_trace_php() {
    let body = r#"Fatal error: Uncaught Error at <class>"#;
    let issues = analyze_info_disclosure(&[], body);
    assert!(issues.contains(&InfoDisclosureIssue::StackTraceExposed));
}

#[test]
fn analyze_stack_trace_file_pattern() {
    let body = r#"  File "/app/handler.py", line 10, in get"#;
    let issues = analyze_info_disclosure(&[], body);
    assert!(issues.contains(&InfoDisclosureIssue::StackTraceExposed));
}

#[test]
fn analyze_directory_listing_index_of() {
    let body = "<html><body><h1>Index of /uploads</h1></body></html>";
    let issues = analyze_info_disclosure(&[], body);
    assert!(issues.contains(&InfoDisclosureIssue::DirectoryListing));
}

#[test]
fn analyze_directory_listing_parent() {
    let body = "<a href=\"..\">Parent Directory</a>";
    let issues = analyze_info_disclosure(&[], body);
    assert!(issues.contains(&InfoDisclosureIssue::DirectoryListing));
}

#[test]
fn analyze_directory_listing_title() {
    let body = "<title>Index of /var/www/html</title>";
    let issues = analyze_info_disclosure(&[], body);
    assert!(issues.contains(&InfoDisclosureIssue::DirectoryListing));
}

#[test]
fn analyze_phpinfo_function() {
    let body = "<h1>phpinfo()</h1><table>";
    let issues = analyze_info_disclosure(&[], body);
    assert!(issues.contains(&InfoDisclosureIssue::PhpInfoExposed));
}

#[test]
fn analyze_phpinfo_version() {
    let body = "<h1>PHP Version 8.2.3</h1>";
    let issues = analyze_info_disclosure(&[], body);
    assert!(issues.contains(&InfoDisclosureIssue::PhpInfoExposed));
}

#[test]
fn analyze_phpinfo_credits() {
    let body = "<h2>PHP Credits</h2>";
    let issues = analyze_info_disclosure(&[], body);
    assert!(issues.contains(&InfoDisclosureIssue::PhpInfoExposed));
}

#[test]
fn analyze_version_apache_in_body() {
    let body = "Server: Apache/2.4.51 (Ubuntu)";
    let issues = analyze_info_disclosure(&[], body);
    assert!(issues.iter().any(|i| matches!(
        i,
        InfoDisclosureIssue::VersionInBody { technology, version }
            if technology == "Apache" && version == "2.4.51"
    )));
}

#[test]
fn analyze_version_nginx_in_body() {
    let body = "<center>nginx/1.20.0</center>";
    let issues = analyze_info_disclosure(&[], body);
    assert!(issues.iter().any(|i| matches!(
        i,
        InfoDisclosureIssue::VersionInBody { technology, version }
            if technology == "nginx" && version == "1.20.0"
    )));
}

#[test]
fn analyze_version_php_in_body() {
    let body = "X-Powered-By: PHP/8.1.2";
    let issues = analyze_info_disclosure(&[], body);
    assert!(issues.iter().any(|i| matches!(
        i,
        InfoDisclosureIssue::VersionInBody { technology, version }
            if technology == "PHP" && version == "8.1.2"
    )));
}

#[test]
fn analyze_version_iis_in_body() {
    let body = "Microsoft-IIS/10.0";
    let issues = analyze_info_disclosure(&[], body);
    assert!(issues.iter().any(|i| matches!(
        i,
        InfoDisclosureIssue::VersionInBody { technology, version }
            if technology == "IIS" && version == "10.0"
    )));
}

#[test]
fn analyze_no_issues_clean_response() {
    let headers = vec![("Content-Type", "text/html"), ("Cache-Control", "no-cache")];
    let body = "<html><body>Hello World</body></html>";
    let issues = analyze_info_disclosure(&headers, body);
    assert!(issues.is_empty());
}

#[test]
fn analyze_multiple_issues_combined() {
    let headers = vec![
        ("Server", "Apache/2.4.51"),
        ("X-Powered-By", "PHP/8.1"),
        ("X-Debug-Token", "tok_abc"),
    ];
    let body = "Traceback (most recent call last):";
    let issues = analyze_info_disclosure(&headers, body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, InfoDisclosureIssue::ServerVersion { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, InfoDisclosureIssue::FrameworkExposed { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, InfoDisclosureIssue::DebugEnabled { .. }))
    );
    assert!(issues.contains(&InfoDisclosureIssue::StackTraceExposed));
}

#[test]
fn analyze_case_insensitive_header_names() {
    let headers = vec![("x-powered-by", "Express")];
    let issues = analyze_info_disclosure(&headers, "");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, InfoDisclosureIssue::FrameworkExposed { .. }))
    );
}

#[test]
fn analyze_stack_trace_only_once() {
    let body = "Traceback\nFile \"/app/a.py\"\nException in thread";
    let issues = analyze_info_disclosure(&[], body);
    let count = issues
        .iter()
        .filter(|i| matches!(i, InfoDisclosureIssue::StackTraceExposed))
        .count();
    assert_eq!(count, 1);
}

// ── info_issues_to_operations ───────────────────────────────────────

#[test]
fn info_issues_ops_creates_findings() {
    let issues = vec![
        InfoDisclosureIssue::StackTraceExposed,
        InfoDisclosureIssue::DirectoryListing,
    ];
    let mut seq = 0;
    let ops = info_issues_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn info_issues_ops_empty() {
    let mut seq = 10;
    let ops = info_issues_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 10);
}

#[test]
fn info_issues_ops_vuln_class() {
    let issues = vec![InfoDisclosureIssue::PhpInfoExposed];
    let mut seq = 0;
    let ops = info_issues_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::InformationDisclosure
            );
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn info_issues_ops_severity_matches() {
    let issues = vec![InfoDisclosureIssue::StackTraceExposed];
    let mut seq = 0;
    let ops = info_issues_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { severity, .. } => {
            assert_eq!(*severity, 6.0);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn info_issues_ops_confidence_half() {
    let issues = vec![InfoDisclosureIssue::DirectoryListing];
    let mut seq = 0;
    let ops = info_issues_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding { confidence, .. } => {
            assert!((confidence.value() - 0.5).abs() < f64::EPSILON);
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn info_issues_ops_sequence_increments() {
    let issues = vec![
        InfoDisclosureIssue::PhpInfoExposed,
        InfoDisclosureIssue::StackTraceExposed,
        InfoDisclosureIssue::DirectoryListing,
    ];
    let mut seq = 5;
    let ops = info_issues_to_operations(&issues, &mut seq);
    assert_eq!(seq, 8);
    assert_eq!(ops[0].sequence_number, 6);
    assert_eq!(ops[1].sequence_number, 7);
    assert_eq!(ops[2].sequence_number, 8);
}

#[test]
fn analyze_internal_ip_in_comma_list() {
    let headers = vec![("X-Forwarded-For", "8.8.8.8, 10.1.2.3, 1.2.3.4")];
    let issues = analyze_info_disclosure(&headers, "");
    assert!(issues.iter().any(|i| matches!(
        i,
        InfoDisclosureIssue::InternalIpExposed { ip, .. } if ip == "10.1.2.3"
    )));
}

#[test]
fn analyze_no_version_in_clean_body() {
    let body = "Welcome to our website.";
    let issues = analyze_info_disclosure(&[], body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, InfoDisclosureIssue::VersionInBody { .. }))
    );
}
