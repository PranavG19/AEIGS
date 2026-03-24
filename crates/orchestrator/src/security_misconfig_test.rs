use crate::security_misconfig::{
    analyze_cookie_security, analyze_error_verbosity, analyze_server_headers, backup_suffixes,
    default_credential_pairs, detect_admin_panel, detect_backup_file, detect_dangerous_methods,
    detect_debug_endpoint, detect_directory_listing, detect_exposed_config, is_default_credential,
    max_severity, misconfig_to_operations, owasp_category, MisconfigCategory, SecurityMisconfig,
};

// ── Default Credentials ──

#[test]
fn detects_admin_admin() {
    assert!(is_default_credential("admin", "admin"));
}

#[test]
fn detects_admin_password() {
    assert!(is_default_credential("admin", "password"));
}

#[test]
fn detects_root_toor() {
    assert!(is_default_credential("root", "toor"));
}

#[test]
fn detects_case_insensitive_credentials() {
    assert!(is_default_credential("Admin", "Admin"));
    assert!(is_default_credential("ROOT", "ROOT"));
}

#[test]
fn rejects_non_default_credentials() {
    assert!(!is_default_credential("admin", "s3cur3P@ssw0rd!"));
    assert!(!is_default_credential("appuser", "randompass"));
}

#[test]
fn default_credential_pairs_not_empty() {
    assert!(default_credential_pairs().len() >= 15);
}

// ── Debug Endpoints / Unnecessary Features ──

#[test]
fn detects_debug_endpoint_accessible() {
    let result = detect_debug_endpoint(200, "/__debug__/");
    assert!(result.is_some());
    let f = result.unwrap();
    assert_eq!(f.category, MisconfigCategory::UnnecessaryFeatures);
}

#[test]
fn detects_profiler_endpoint() {
    let result = detect_debug_endpoint(200, "/_profiler/");
    assert!(result.is_some());
}

#[test]
fn detects_actuator_endpoint() {
    let result = detect_debug_endpoint(200, "/actuator");
    assert!(result.is_some());
}

#[test]
fn ignores_404_debug_endpoint() {
    let result = detect_debug_endpoint(404, "/__debug__/");
    assert!(result.is_none());
}

#[test]
fn ignores_500_debug_endpoint() {
    let result = detect_debug_endpoint(500, "/__debug__/");
    assert!(result.is_none());
}

// ── Verbose Error Handling ──

#[test]
fn detects_python_traceback_verbose() {
    let body = "Traceback (most recent call last):\n  File app.py line 42";
    let findings = analyze_error_verbosity(body, "/error");
    assert!(!findings.is_empty());
    assert_eq!(
        findings[0].category,
        MisconfigCategory::VerboseErrorHandling
    );
}

#[test]
fn detects_java_stacktrace_verbose() {
    let body = "Exception at java.lang.Thread.run()";
    let findings = analyze_error_verbosity(body, "/error");
    assert!(!findings.is_empty());
}

#[test]
fn detects_sql_error_verbose() {
    let body = "SQLSTATE[42000]: Syntax error or access violation";
    let findings = analyze_error_verbosity(body, "/api");
    assert!(!findings.is_empty());
}

#[test]
fn deduplicates_verbose_errors() {
    let body = "SQLSTATE[42000] error and mysql_connect() failed";
    let findings = analyze_error_verbosity(body, "/api");
    let sql_count = findings
        .iter()
        .filter(|f| f.detail.contains("sql") || f.detail.contains("mysql"))
        .count();
    assert_eq!(sql_count, 2);
}

#[test]
fn no_verbose_errors_in_clean_body() {
    let body = "<html><body>Welcome to our website</body></html>";
    let findings = analyze_error_verbosity(body, "/");
    assert!(findings.is_empty());
}

// ── Directory Listing ──

#[test]
fn detects_apache_directory_listing() {
    let body = "<html><head><title>Index of /uploads</title></head>";
    let result = detect_directory_listing(body, "/uploads/");
    assert!(result.is_some());
    let f = result.unwrap();
    assert_eq!(f.category, MisconfigCategory::DirectoryListing);
}

#[test]
fn detects_python_directory_listing() {
    let body = "Directory listing for /static/";
    let result = detect_directory_listing(body, "/static/");
    assert!(result.is_some());
}

#[test]
fn detects_parent_directory_link() {
    let body = "<a href=\"../\">Parent Directory</a>";
    let result = detect_directory_listing(body, "/assets/");
    assert!(result.is_some());
}

#[test]
fn no_directory_listing_on_normal_page() {
    let body = "<html><body>Hello world</body></html>";
    let result = detect_directory_listing(body, "/");
    assert!(result.is_none());
}

// ── Backup Files ──

#[test]
fn detects_bak_file() {
    let result = detect_backup_file(200, "application/octet-stream", "/config.php.bak");
    assert!(result.is_some());
    let f = result.unwrap();
    assert_eq!(f.category, MisconfigCategory::BackupFileExposed);
}

#[test]
fn detects_old_file() {
    let result = detect_backup_file(200, "text/plain", "/database.sql.old");
    assert!(result.is_some());
}

#[test]
fn detects_swp_file() {
    let result = detect_backup_file(200, "application/octet-stream", "/.config.swp");
    assert!(result.is_some());
}

#[test]
fn detects_tilde_backup() {
    let result = detect_backup_file(200, "text/plain", "/settings.py~");
    assert!(result.is_some());
}

#[test]
fn ignores_404_backup() {
    let result = detect_backup_file(404, "text/html", "/config.php.bak");
    assert!(result.is_none());
}

#[test]
fn ignores_html_backup_response() {
    let result = detect_backup_file(200, "text/html", "/config.php.bak");
    assert!(result.is_none());
}

#[test]
fn backup_suffixes_not_empty() {
    assert!(backup_suffixes().len() >= 10);
}

// ── Exposed Admin Panels ──

#[test]
fn detects_admin_panel_200() {
    let result = detect_admin_panel(200, "/admin");
    assert!(result.is_some());
    let f = result.unwrap();
    assert_eq!(f.category, MisconfigCategory::ExposedAdminPanel);
}

#[test]
fn detects_phpmyadmin_redirect() {
    let result = detect_admin_panel(302, "/phpmyadmin/");
    assert!(result.is_some());
}

#[test]
fn ignores_403_admin_panel() {
    let result = detect_admin_panel(403, "/admin");
    assert!(result.is_none());
}

#[test]
fn ignores_404_admin_panel() {
    let result = detect_admin_panel(404, "/wp-admin/");
    assert!(result.is_none());
}

// ── Exposed Config Files ──

#[test]
fn detects_env_file() {
    let body = "DB_HOST=localhost\nDB_PASSWORD=secret\nAPI_KEY=abc123";
    let result = detect_exposed_config(200, body, "/.env");
    assert!(result.is_some());
    let f = result.unwrap();
    assert_eq!(f.category, MisconfigCategory::ExposedConfigFile);
    assert!(f.severity >= 9.0);
}

#[test]
fn detects_git_config() {
    let body = "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]";
    let result = detect_exposed_config(200, body, "/.git/config");
    assert!(result.is_some());
}

#[test]
fn detects_git_head() {
    let body = "ref: refs/heads/main";
    let result = detect_exposed_config(200, body, "/.git/HEAD");
    assert!(result.is_some());
}

#[test]
fn ignores_404_config() {
    let body = "Not found";
    let result = detect_exposed_config(404, body, "/.env");
    assert!(result.is_none());
}

#[test]
fn ignores_config_without_sensitive_content() {
    let body = "<html>Hello</html>";
    let result = detect_exposed_config(200, body, "/.env");
    assert!(result.is_none());
}

// ── Dangerous HTTP Methods ──

#[test]
fn detects_delete_method() {
    let findings = detect_dangerous_methods(&["GET", "POST", "DELETE"], "/api/users");
    assert!(!findings.is_empty());
    assert_eq!(findings[0].category, MisconfigCategory::DangerousHttpMethod);
}

#[test]
fn detects_put_method() {
    let findings = detect_dangerous_methods(&["GET", "PUT"], "/api/data");
    assert!(!findings.is_empty());
}

#[test]
fn detects_trace_method() {
    let findings = detect_dangerous_methods(&["TRACE"], "/");
    assert!(!findings.is_empty());
}

#[test]
fn detects_multiple_dangerous_methods() {
    let findings = detect_dangerous_methods(&["GET", "PUT", "DELETE", "TRACE"], "/api");
    assert_eq!(findings.len(), 3);
}

#[test]
fn case_insensitive_method_detection() {
    let findings = detect_dangerous_methods(&["delete", "put"], "/api");
    assert_eq!(findings.len(), 2);
}

#[test]
fn no_findings_for_safe_methods() {
    let findings = detect_dangerous_methods(&["GET", "POST", "HEAD", "OPTIONS"], "/api");
    assert!(findings.is_empty());
}

// ── Server Information Leakage ──

#[test]
fn detects_server_header_with_version() {
    let headers = vec![("Server", "Apache/2.4.41 (Ubuntu)")];
    let findings = analyze_server_headers(&headers);
    assert!(!findings.is_empty());
    assert_eq!(findings[0].category, MisconfigCategory::ServerInfoLeakage);
    assert!(findings[0].severity > 5.0);
}

#[test]
fn detects_x_powered_by() {
    let headers = vec![("X-Powered-By", "PHP/7.4.3")];
    let findings = analyze_server_headers(&headers);
    assert!(!findings.is_empty());
}

#[test]
fn detects_x_aspnet_version() {
    let headers = vec![("X-AspNet-Version", "4.0.30319")];
    let findings = analyze_server_headers(&headers);
    assert!(!findings.is_empty());
}

#[test]
fn lower_severity_without_version() {
    let headers = vec![("Server", "custom-server")];
    let findings = analyze_server_headers(&headers);
    assert!(!findings.is_empty());
    assert!(findings[0].severity < 5.0);
}

#[test]
fn no_findings_for_irrelevant_headers() {
    let headers = vec![("Content-Type", "text/html"), ("Cache-Control", "no-cache")];
    let findings = analyze_server_headers(&headers);
    assert!(findings.is_empty());
}

// ── Insecure Cookie Configuration ──

#[test]
fn detects_missing_secure_flag() {
    let cookies = vec!["session=abc123; HttpOnly; SameSite=Strict"];
    let findings = analyze_cookie_security(&cookies);
    assert!(!findings.is_empty());
    assert_eq!(
        findings[0].category,
        MisconfigCategory::InsecureCookieConfig
    );
    assert!(findings[0].detail.contains("Secure"));
}

#[test]
fn detects_missing_httponly_flag() {
    let cookies = vec!["session=abc123; Secure; SameSite=Strict"];
    let findings = analyze_cookie_security(&cookies);
    assert!(!findings.is_empty());
    assert!(findings[0].detail.contains("HttpOnly"));
}

#[test]
fn detects_missing_samesite_flag() {
    let cookies = vec!["session=abc123; Secure; HttpOnly"];
    let findings = analyze_cookie_security(&cookies);
    assert!(!findings.is_empty());
    assert!(findings[0].detail.contains("SameSite"));
}

#[test]
fn detects_all_missing_cookie_flags() {
    let cookies = vec!["session=abc123"];
    let findings = analyze_cookie_security(&cookies);
    assert!(!findings.is_empty());
    let detail = &findings[0].detail;
    assert!(detail.contains("Secure"));
    assert!(detail.contains("HttpOnly"));
    assert!(detail.contains("SameSite"));
}

#[test]
fn no_findings_for_secure_cookie() {
    let cookies = vec!["session=abc123; Secure; HttpOnly; SameSite=Strict"];
    let findings = analyze_cookie_security(&cookies);
    assert!(findings.is_empty());
}

#[test]
fn handles_multiple_cookies() {
    let cookies = vec![
        "session=abc123; Secure; HttpOnly; SameSite=Strict",
        "tracking=xyz789",
    ];
    let findings = analyze_cookie_security(&cookies);
    assert_eq!(findings.len(), 1);
    assert!(findings[0].detail.contains("tracking"));
}

// ── Operations & Severity ──

#[test]
fn operations_empty_when_no_findings() {
    let mut seq = 0;
    let ops = misconfig_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_produced_for_findings() {
    let findings = vec![SecurityMisconfig {
        category: MisconfigCategory::DefaultCredentials,
        detail: "admin:admin".to_string(),
        severity: 9.5,
        path: "/login".to_string(),
    }];
    let mut seq = 0;
    let ops = misconfig_to_operations(&findings, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn max_severity_selects_highest() {
    let findings = vec![
        SecurityMisconfig {
            category: MisconfigCategory::ServerInfoLeakage,
            detail: "server header".to_string(),
            severity: 3.5,
            path: String::new(),
        },
        SecurityMisconfig {
            category: MisconfigCategory::ExposedConfigFile,
            detail: ".env".to_string(),
            severity: 9.0,
            path: "/.env".to_string(),
        },
        SecurityMisconfig {
            category: MisconfigCategory::DirectoryListing,
            detail: "listing".to_string(),
            severity: 5.0,
            path: "/uploads/".to_string(),
        },
    ];
    assert!((max_severity(&findings) - 9.0).abs() < f64::EPSILON);
}

#[test]
fn max_severity_zero_when_empty() {
    assert!((max_severity(&[]) - 0.0).abs() < f64::EPSILON);
}

// ── Display Formatting ──

#[test]
fn display_default_credentials() {
    let cat = MisconfigCategory::DefaultCredentials;
    assert_eq!(cat.to_string(), "Default credentials detected");
}

#[test]
fn display_directory_listing() {
    let cat = MisconfigCategory::DirectoryListing;
    assert_eq!(cat.to_string(), "Directory listing enabled");
}

#[test]
fn display_insecure_cookie() {
    let cat = MisconfigCategory::InsecureCookieConfig;
    assert_eq!(cat.to_string(), "Insecure cookie configuration");
}

#[test]
fn display_exposed_config_file() {
    let cat = MisconfigCategory::ExposedConfigFile;
    assert_eq!(cat.to_string(), "Configuration file publicly accessible");
}

#[test]
fn display_dangerous_method() {
    let cat = MisconfigCategory::DangerousHttpMethod;
    assert_eq!(cat.to_string(), "Dangerous HTTP method allowed");
}

// ── OWASP Category ──

#[test]
fn owasp_category_label() {
    assert_eq!(owasp_category(), "A05:2021 Security Misconfiguration");
}

// ── Category count validation ──

#[test]
fn at_least_ten_misconfig_categories() {
    let categories = vec![
        MisconfigCategory::DefaultCredentials,
        MisconfigCategory::UnnecessaryFeatures,
        MisconfigCategory::VerboseErrorHandling,
        MisconfigCategory::DirectoryListing,
        MisconfigCategory::BackupFileExposed,
        MisconfigCategory::ExposedAdminPanel,
        MisconfigCategory::ExposedConfigFile,
        MisconfigCategory::DangerousHttpMethod,
        MisconfigCategory::ServerInfoLeakage,
        MisconfigCategory::InsecureCookieConfig,
    ];
    assert!(categories.len() >= 10);
}

// ── Delete severity is highest dangerous method ──

#[test]
fn delete_severity_higher_than_trace() {
    let del = detect_dangerous_methods(&["DELETE"], "/api");
    let trace = detect_dangerous_methods(&["TRACE"], "/api");
    assert!(del[0].severity > trace[0].severity);
}

// ── Edge cases ──

#[test]
fn empty_headers_no_findings() {
    let findings = analyze_server_headers(&[]);
    assert!(findings.is_empty());
}

#[test]
fn empty_cookies_no_findings() {
    let findings = analyze_cookie_security(&[]);
    assert!(findings.is_empty());
}

#[test]
fn empty_body_no_verbose_errors() {
    let findings = analyze_error_verbosity("", "/");
    assert!(findings.is_empty());
}

#[test]
fn empty_methods_no_findings() {
    let findings = detect_dangerous_methods(&[], "/api");
    assert!(findings.is_empty());
}
