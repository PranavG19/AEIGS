use std::collections::HashMap;

use super::error_disclosure::*;

#[test]
fn generate_error_triggers_returns_at_least_15() {
    let triggers = generate_error_triggers("/api");
    assert!(
        triggers.len() >= 15,
        "expected ≥15 triggers, got {}",
        triggers.len()
    );
}

#[test]
fn generate_error_triggers_unique_names() {
    let triggers = generate_error_triggers("/");
    let names: Vec<&str> = triggers.iter().map(|t| t.name.as_str()).collect();
    let mut deduped = names.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(names.len(), deduped.len(), "trigger names must be unique");
}

#[test]
fn generate_error_triggers_all_have_descriptions() {
    let triggers = generate_error_triggers("/");
    for t in &triggers {
        assert!(
            !t.description.is_empty(),
            "trigger {} missing description",
            t.name
        );
    }
}

#[test]
fn generate_error_triggers_with_empty_base_path() {
    let triggers = generate_error_triggers("");
    assert!(triggers.len() >= 15);
    for t in &triggers {
        assert!(
            !t.path.is_empty(),
            "path should not be empty for trigger {}",
            t.name
        );
    }
}

#[test]
fn detect_java_stack_trace() {
    let body = "500 Internal Server Error\nat com.example.MyService(MyService.java:42)\nat org.springframework.web.servlet.FrameworkServlet.service(FrameworkServlet.java:97)";
    let findings = analyze_error_response(body, &HashMap::new());
    let st_findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.category == ErrorDisclosureCategory::StackTrace
                && f.language == Some(StackTraceLanguage::Java)
        })
        .collect();
    assert!(!st_findings.is_empty(), "should detect Java stack trace");
}

#[test]
fn detect_python_stack_trace() {
    let body = r#"Traceback (most recent call last):
  File "/app/views.py", line 42, in index
    result = do_something()
ValueError: invalid literal"#;
    let findings = analyze_error_response(body, &HashMap::new());
    let langs: Vec<_> = findings.iter().filter_map(|f| f.language).collect();
    assert!(
        langs.contains(&StackTraceLanguage::Python),
        "should detect Python"
    );
}

#[test]
fn detect_php_stack_trace() {
    let body = "Fatal error: Uncaught TypeError in /var/www/html/index.php on line 12";
    let findings = analyze_error_response(body, &HashMap::new());
    let langs: Vec<_> = findings.iter().filter_map(|f| f.language).collect();
    assert!(
        langs.contains(&StackTraceLanguage::Php),
        "should detect PHP"
    );
}

#[test]
fn detect_dotnet_stack_trace() {
    let body = "System.NullReferenceException: Object reference not set\n   at MyApp.Controllers.HomeController.Index() in C:\\Users\\dev\\src\\HomeController.cs:line 28";
    let findings = analyze_error_response(body, &HashMap::new());
    let langs: Vec<_> = findings.iter().filter_map(|f| f.language).collect();
    assert!(
        langs.contains(&StackTraceLanguage::DotNet),
        "should detect .NET"
    );
}

#[test]
fn detect_nodejs_stack_trace() {
    let body = "TypeError: Cannot read property 'id' of undefined\n    at Object.<anonymous> (/app/routes/user.js:15:23)";
    let findings = analyze_error_response(body, &HashMap::new());
    let langs: Vec<_> = findings.iter().filter_map(|f| f.language).collect();
    assert!(
        langs.contains(&StackTraceLanguage::NodeJs),
        "should detect Node.js"
    );
}

#[test]
fn detect_ruby_stack_trace() {
    let body = "/app/controllers/users_controller.rb:14:in `show'\n/app/config/routes.rb:5:in `block in <main>'";
    let findings = analyze_error_response(body, &HashMap::new());
    let langs: Vec<_> = findings.iter().filter_map(|f| f.language).collect();
    assert!(
        langs.contains(&StackTraceLanguage::Ruby),
        "should detect Ruby"
    );
}

#[test]
fn detect_go_stack_trace() {
    let body = "goroutine 1 [running]:\nmain.handler(0xc0000b4000)\n\t/app/main.go:28 +0x1a5";
    let findings = analyze_error_response(body, &HashMap::new());
    let langs: Vec<_> = findings.iter().filter_map(|f| f.language).collect();
    assert!(langs.contains(&StackTraceLanguage::Go), "should detect Go");
}

#[test]
fn detect_mysql_error() {
    let body = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version";
    let findings = analyze_error_response(body, &HashMap::new());
    let dbs: Vec<_> = findings.iter().filter_map(|f| f.database).collect();
    assert!(dbs.contains(&DatabaseType::MySql), "should detect MySQL");
}

#[test]
fn detect_postgresql_error() {
    let body =
        "ERROR:  syntax error at or near \"WHERE\"\nLINE 1: SELECT * FROM users WHERE WHERE id = 1";
    let findings = analyze_error_response(body, &HashMap::new());
    let dbs: Vec<_> = findings.iter().filter_map(|f| f.database).collect();
    assert!(
        dbs.contains(&DatabaseType::PostgreSql),
        "should detect PostgreSQL"
    );
}

#[test]
fn detect_mssql_error() {
    let body =
        "[Microsoft][ODBC SQL Server Driver][SQL Server]Incorrect syntax near the keyword 'WHERE'.";
    let findings = analyze_error_response(body, &HashMap::new());
    let dbs: Vec<_> = findings.iter().filter_map(|f| f.database).collect();
    assert!(dbs.contains(&DatabaseType::MsSql), "should detect MSSQL");
}

#[test]
fn detect_oracle_error() {
    let body = "ORA-00933: SQL command not properly ended";
    let findings = analyze_error_response(body, &HashMap::new());
    let dbs: Vec<_> = findings.iter().filter_map(|f| f.database).collect();
    assert!(dbs.contains(&DatabaseType::Oracle), "should detect Oracle");
}

#[test]
fn detect_mongodb_error() {
    let body = "MongoError: E11000 duplicate key error collection: mydb.users";
    let findings = analyze_error_response(body, &HashMap::new());
    let dbs: Vec<_> = findings.iter().filter_map(|f| f.database).collect();
    assert!(
        dbs.contains(&DatabaseType::MongoDb),
        "should detect MongoDB"
    );
}

#[test]
fn detect_unix_path_disclosure() {
    let body = "FileNotFoundError: [Errno 2] No such file or directory: '/var/www/html/config.php'";
    let findings = analyze_error_response(body, &HashMap::new());
    let path_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == ErrorDisclosureCategory::PathDisclosure)
        .collect();
    assert!(!path_findings.is_empty(), "should detect Unix path");
    assert!(path_findings[0].evidence.contains("/var/www/html"));
}

#[test]
fn detect_windows_path_disclosure() {
    let body = r"Could not find file 'C:\Users\admin\Documents\app\web.config'";
    let findings = analyze_error_response(body, &HashMap::new());
    let path_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == ErrorDisclosureCategory::PathDisclosure)
        .collect();
    assert!(!path_findings.is_empty(), "should detect Windows path");
}

#[test]
fn detect_version_in_body() {
    let body = "Server: Apache/2.4.51 (Ubuntu)";
    let findings = analyze_error_response(body, &HashMap::new());
    let ver_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == ErrorDisclosureCategory::VersionDisclosure)
        .collect();
    assert!(
        !ver_findings.is_empty(),
        "should detect Apache version in body"
    );
    assert!(ver_findings[0].detail.contains("2.4.51"));
}

#[test]
fn detect_version_in_headers() {
    let mut headers = HashMap::new();
    headers.insert("server".into(), "nginx/1.21.6".into());
    let findings = analyze_error_response("", &headers);
    let ver_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == ErrorDisclosureCategory::VersionDisclosure)
        .collect();
    assert!(
        !ver_findings.is_empty(),
        "should detect version in server header"
    );
}

#[test]
fn detect_x_powered_by_version() {
    let mut headers = HashMap::new();
    headers.insert("x-powered-by".into(), "PHP/8.1.12".into());
    let findings = analyze_error_response("", &headers);
    let ver_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == ErrorDisclosureCategory::VersionDisclosure)
        .collect();
    assert!(
        !ver_findings.is_empty(),
        "should detect x-powered-by version"
    );
}

#[test]
fn detect_internal_ip_leak() {
    let body = "Forwarded request to backend server 10.0.1.55 failed with timeout";
    let findings = analyze_error_response(body, &HashMap::new());
    let ip_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == ErrorDisclosureCategory::HostnameOrIpLeak)
        .collect();
    assert!(!ip_findings.is_empty(), "should detect internal IP");
    assert!(ip_findings[0].evidence.contains("10.0.1.55"));
}

#[test]
fn detect_internal_hostname_leak() {
    let body = "hostname: web-prod-03.internal failed to resolve upstream";
    let findings = analyze_error_response(body, &HashMap::new());
    let host_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == ErrorDisclosureCategory::HostnameOrIpLeak)
        .collect();
    assert!(!host_findings.is_empty(), "should detect internal hostname");
}

#[test]
fn detect_django_debug_mode() {
    let body = "<h1>DisallowedHost</h1>\nDjango Version: 4.2.1\nDEBUG = True\nSettings module: myapp.settings";
    let findings = analyze_error_response(body, &HashMap::new());
    let debug_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == ErrorDisclosureCategory::DebugMode)
        .collect();
    assert!(
        !debug_findings.is_empty(),
        "should detect Django debug mode"
    );
}

#[test]
fn detect_laravel_debug_mode() {
    let body = "APP_DEBUG = true\nWhoops! Stack trace:\n#0 /app/vendor/laravel/framework";
    let findings = analyze_error_response(body, &HashMap::new());
    let debug_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == ErrorDisclosureCategory::DebugMode)
        .collect();
    assert!(
        !debug_findings.is_empty(),
        "should detect Laravel debug mode"
    );
}

#[test]
fn detect_express_error_page() {
    let body = "<html><head><title>Error - Express</title></head><body><pre>TypeError: cannot read property</pre></body></html>";
    let findings = analyze_error_response(body, &HashMap::new());
    let debug_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == ErrorDisclosureCategory::DebugMode)
        .collect();
    assert!(
        !debug_findings.is_empty(),
        "should detect Express error page"
    );
}

#[test]
fn detect_symfony_debug_header() {
    let mut headers = HashMap::new();
    headers.insert("x-debug-token".into(), "abc123".into());
    let findings = analyze_error_response("", &headers);
    let debug_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == ErrorDisclosureCategory::DebugMode)
        .collect();
    assert!(
        !debug_findings.is_empty(),
        "should detect Symfony debug token"
    );
}

#[test]
fn no_findings_on_clean_response() {
    let body = "<html><body><h1>404 Not Found</h1><p>The page you requested was not found.</p></body></html>";
    let findings = analyze_error_response(body, &HashMap::new());
    assert!(findings.is_empty(), "clean 404 should produce no findings");
}

#[test]
fn build_report_aggregates_categories() {
    let findings = vec![
        ErrorDisclosureFinding {
            category: ErrorDisclosureCategory::StackTrace,
            detail: "Java trace".into(),
            evidence: "at com.example.Main(Main.java:1)".into(),
            language: Some(StackTraceLanguage::Java),
            database: None,
        },
        ErrorDisclosureFinding {
            category: ErrorDisclosureCategory::SqlError,
            detail: "MySQL error".into(),
            evidence: "You have an error in your SQL syntax".into(),
            language: None,
            database: Some(DatabaseType::MySql),
        },
        ErrorDisclosureFinding {
            category: ErrorDisclosureCategory::StackTrace,
            detail: "Python trace".into(),
            evidence: "Traceback (most recent call last)".into(),
            language: Some(StackTraceLanguage::Python),
            database: None,
        },
    ];
    let report = build_disclosure_report(findings, 15);
    assert_eq!(
        *report
            .category_counts
            .get(&ErrorDisclosureCategory::StackTrace)
            .unwrap(),
        2
    );
    assert_eq!(
        *report
            .category_counts
            .get(&ErrorDisclosureCategory::SqlError)
            .unwrap(),
        1
    );
    assert_eq!(report.detected_languages.len(), 2);
    assert_eq!(report.detected_databases.len(), 1);
    assert_eq!(report.trigger_requests_used, 15);
}

#[test]
fn build_report_deduplicates_languages() {
    let findings = vec![
        ErrorDisclosureFinding {
            category: ErrorDisclosureCategory::StackTrace,
            detail: "Java #1".into(),
            evidence: "at Foo(Foo.java:1)".into(),
            language: Some(StackTraceLanguage::Java),
            database: None,
        },
        ErrorDisclosureFinding {
            category: ErrorDisclosureCategory::StackTrace,
            detail: "Java #2".into(),
            evidence: "at Bar(Bar.java:2)".into(),
            language: Some(StackTraceLanguage::Java),
            database: None,
        },
    ];
    let report = build_disclosure_report(findings, 5);
    assert_eq!(
        report.detected_languages.len(),
        1,
        "duplicate languages should be deduplicated"
    );
}

#[test]
fn fingerprint_maps_language_and_db() {
    let findings = vec![
        ErrorDisclosureFinding {
            category: ErrorDisclosureCategory::StackTrace,
            detail: "Python trace".into(),
            evidence: "Traceback...".into(),
            language: Some(StackTraceLanguage::Python),
            database: None,
        },
        ErrorDisclosureFinding {
            category: ErrorDisclosureCategory::SqlError,
            detail: "PostgreSQL error".into(),
            evidence: "ERROR: syntax error".into(),
            language: None,
            database: Some(DatabaseType::PostgreSql),
        },
    ];
    let tech = fingerprint_error_to_tech(&findings);
    assert_eq!(tech.get("language").unwrap(), "Python");
    assert_eq!(tech.get("database").unwrap(), "PostgreSQL");
}

#[test]
fn fingerprint_maps_web_server() {
    let findings = vec![ErrorDisclosureFinding {
        category: ErrorDisclosureCategory::VersionDisclosure,
        detail: "nginx version 1.21.6 disclosed in body".into(),
        evidence: "nginx/1.21.6".into(),
        language: None,
        database: None,
    }];
    let tech = fingerprint_error_to_tech(&findings);
    assert_eq!(tech.get("web_server").unwrap(), "nginx");
}

#[test]
fn fingerprint_maps_debug_framework() {
    let findings = vec![ErrorDisclosureFinding {
        category: ErrorDisclosureCategory::DebugMode,
        detail: "Django DEBUG=True detected".into(),
        evidence: "DEBUG = True".into(),
        language: None,
        database: None,
    }];
    let tech = fingerprint_error_to_tech(&findings);
    assert_eq!(tech.get("framework").unwrap(), "Django");
    assert_eq!(tech.get("debug_mode").unwrap(), "true");
}

#[test]
fn category_display_all_six() {
    let categories = [
        ErrorDisclosureCategory::StackTrace,
        ErrorDisclosureCategory::SqlError,
        ErrorDisclosureCategory::PathDisclosure,
        ErrorDisclosureCategory::VersionDisclosure,
        ErrorDisclosureCategory::HostnameOrIpLeak,
        ErrorDisclosureCategory::DebugMode,
    ];
    let displays: Vec<String> = categories.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), 6);
    for d in &displays {
        assert!(!d.is_empty());
    }
}

#[test]
fn language_display_all_seven() {
    let langs = [
        StackTraceLanguage::Java,
        StackTraceLanguage::Python,
        StackTraceLanguage::Php,
        StackTraceLanguage::DotNet,
        StackTraceLanguage::NodeJs,
        StackTraceLanguage::Ruby,
        StackTraceLanguage::Go,
    ];
    let displays: Vec<String> = langs.iter().map(|l| l.to_string()).collect();
    assert_eq!(displays.len(), 7);
    assert!(displays.contains(&"Java".to_string()));
    assert!(displays.contains(&".NET".to_string()));
    assert!(displays.contains(&"Node.js".to_string()));
}

#[test]
fn database_display_all_five() {
    let dbs = [
        DatabaseType::MySql,
        DatabaseType::PostgreSql,
        DatabaseType::MsSql,
        DatabaseType::Oracle,
        DatabaseType::MongoDb,
    ];
    let displays: Vec<String> = dbs.iter().map(|d| d.to_string()).collect();
    assert_eq!(displays.len(), 5);
    assert!(displays.contains(&"MySQL".to_string()));
    assert!(displays.contains(&"PostgreSQL".to_string()));
}

#[test]
fn multiple_categories_in_single_response() {
    let body = "Traceback (most recent call last):\n  File \"/var/www/app/views.py\", line 42\nERROR:  syntax error at or near\nServer running on host: db-master.internal\nDjango Version: 4.2.1\nDEBUG = True";
    let findings = analyze_error_response(body, &HashMap::new());
    let categories: Vec<ErrorDisclosureCategory> = findings.iter().map(|f| f.category).collect();
    assert!(categories.contains(&ErrorDisclosureCategory::StackTrace));
    assert!(categories.contains(&ErrorDisclosureCategory::PathDisclosure));
    assert!(categories.contains(&ErrorDisclosureCategory::SqlError));
    assert!(categories.contains(&ErrorDisclosureCategory::HostnameOrIpLeak));
    assert!(categories.contains(&ErrorDisclosureCategory::DebugMode));
}

#[test]
fn private_ip_192_168_range() {
    let body = "Connection refused to backend at 192.168.1.100 port 8080";
    let findings = analyze_error_response(body, &HashMap::new());
    let ip_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == ErrorDisclosureCategory::HostnameOrIpLeak)
        .collect();
    assert!(!ip_findings.is_empty(), "should detect 192.168.x.x range");
}

#[test]
fn evidence_truncated_at_200_chars() {
    let long_trace = format!(
        "at com.example.very.deeply.nested.package.name.that.goes.on.forever.and.ever.ClassName(ClassName.java:1) {}",
        "x".repeat(300)
    );
    let findings = analyze_error_response(&long_trace, &HashMap::new());
    for f in &findings {
        assert!(
            f.evidence.len() <= 203,
            "evidence should be truncated: len={}",
            f.evidence.len()
        );
    }
}

#[test]
fn trigger_requests_have_valid_methods() {
    let triggers = generate_error_triggers("/test");
    let valid_methods = [
        "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "FOOBAR",
    ];
    for t in &triggers {
        assert!(
            valid_methods.contains(&t.method.as_str()),
            "unexpected method {} in trigger {}",
            t.method,
            t.name,
        );
    }
}
