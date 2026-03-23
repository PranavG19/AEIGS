use crate::error_page_audit::{
    ErrorPageLeak, ErrorPageSecurityIssue, analyze_error_body, analyze_error_page_security,
    error_page_security_severity, error_page_security_to_operations, error_page_to_operations,
};

#[test]
fn detects_python_traceback() {
    let body = "Error\nTraceback (most recent call last):\n  File \"app.py\"";
    let leaks = analyze_error_body(body, "/test");
    assert!(leaks.iter().any(|l| l.pattern_name == "python_traceback"));
}

#[test]
fn detects_java_stacktrace() {
    let body = "Error at java.lang.Thread.run(Thread.java:750)";
    let leaks = analyze_error_body(body, "/test");
    assert!(leaks.iter().any(|l| l.pattern_name == "java_stacktrace"));
}

#[test]
fn detects_node_stacktrace() {
    let body = "TypeError: Cannot read property\n    at Object.<anonymous>";
    let leaks = analyze_error_body(body, "/test");
    assert!(leaks.iter().any(|l| l.pattern_name == "node_stacktrace"));
}

#[test]
fn detects_go_stacktrace() {
    let body = "goroutine 1 [running]:\nmain.main()";
    let leaks = analyze_error_body(body, "/test");
    assert!(leaks.iter().any(|l| l.pattern_name == "go_stacktrace"));
}

#[test]
fn detects_sql_error() {
    let body = "SQLSTATE[42000]: Syntax error or access violation";
    let leaks = analyze_error_body(body, "/test");
    assert!(leaks.iter().any(|l| l.pattern_name == "sql_error"));
}

#[test]
fn detects_django_debug() {
    let body = "<h1>Django Debug page</h1><p>Settings</p>";
    let leaks = analyze_error_body(body, "/test");
    assert!(leaks.iter().any(|l| l.pattern_name == "django_debug"));
}

#[test]
fn detects_internal_path() {
    let body = "Error loading config from /var/www/app/config.json";
    let leaks = analyze_error_body(body, "/test");
    assert!(leaks.iter().any(|l| l.pattern_name == "internal_path"));
}

#[test]
fn detects_windows_path() {
    let body = r"Error: file not found at C:\inetpub\wwwroot\web.config";
    let leaks = analyze_error_body(body, "/test");
    assert!(leaks.iter().any(|l| l.pattern_name == "internal_path"));
}

#[test]
fn detects_whoops_debug() {
    let body = "<div class='Whoops!'>Stack trace</div>";
    let leaks = analyze_error_body(body, "/test");
    assert!(leaks.iter().any(|l| l.pattern_name == "whoops_debug"));
}

#[test]
fn no_leaks_in_clean_page() {
    let body = "<html><body><h1>404 - Page Not Found</h1></body></html>";
    let leaks = analyze_error_body(body, "/test");
    assert!(leaks.is_empty());
}

#[test]
fn deduplicates_same_category() {
    let body = "SQLSTATE[42000] error\nmysql_connect() failed";
    let leaks = analyze_error_body(body, "/test");
    let sql_count = leaks
        .iter()
        .filter(|l| l.pattern_name == "sql_error")
        .count();
    assert_eq!(sql_count, 1);
}

#[test]
fn multiple_categories() {
    let body = "Traceback (most recent call last):\n  /var/www/app.py";
    let leaks = analyze_error_body(body, "/test");
    assert!(leaks.len() >= 2);
}

#[test]
fn operations_empty_when_no_leaks() {
    let mut seq = 0;
    let ops = error_page_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_for_leaks() {
    let leaks = vec![ErrorPageLeak {
        path: "/test".to_string(),
        pattern_name: "python_traceback".to_string(),
        severity: 7.0,
    }];
    let mut seq = 0;
    let ops = error_page_to_operations(&leaks, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn preserves_path_in_leak() {
    let body = "Traceback (most recent call last):";
    let leaks = analyze_error_body(body, "/custom-path");
    assert!(leaks.iter().all(|l| l.path == "/custom-path"));
}

// New security issue detection tests

#[test]
fn detects_stack_trace_python() {
    let body = "Traceback (most recent call last):\n  File \"app.py\"";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::StackTraceExposed));
}

#[test]
fn detects_stack_trace_java() {
    let body = "Error at java.lang.Thread.run(Thread.java:750)";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::StackTraceExposed));
}

#[test]
fn detects_stack_trace_node() {
    let body = "TypeError: Cannot read property\n    at node:internal/module";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::StackTraceExposed));
}

#[test]
fn detects_stack_trace_go() {
    let body = "goroutine 1 [running]:\nmain.main()";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::StackTraceExposed));
}

#[test]
fn detects_stack_trace_generic() {
    let body = "Error occurred\nStack trace:\n  at Object.handler";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::StackTraceExposed));
}

#[test]
fn detects_database_error_sqlstate() {
    let body = "SQLSTATE[42000]: Syntax error or access violation";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::DatabaseErrorExposed));
}

#[test]
fn detects_database_error_mysql() {
    let body = "mysql_connect() failed: Access denied for user";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::DatabaseErrorExposed));
}

#[test]
fn detects_database_error_postgres() {
    let body = "pg_query(): Query failed: ERROR: relation does not exist";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::DatabaseErrorExposed));
}

#[test]
fn detects_database_error_oracle() {
    let body = "ORA-12154: TNS:could not resolve the connect identifier";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::DatabaseErrorExposed));
}

#[test]
fn detects_database_connection_string() {
    let body = "Failed to connect: Connection string invalid";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::DatabaseErrorExposed));
}

#[test]
fn detects_framework_version_django() {
    let body = "Django version 3.2.5 - Debug mode";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::FrameworkVersionLeaked));
}

#[test]
fn detects_framework_version_laravel() {
    let body = "Laravel Framework v8.83.27";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::FrameworkVersionLeaked));
}

#[test]
fn detects_framework_version_apache() {
    let body = "Apache/2.4.41 (Ubuntu) Server at localhost Port 80";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::FrameworkVersionLeaked));
}

#[test]
fn detects_framework_version_nginx() {
    let body = "nginx/1.18.0\n404 Not Found";
    let issues = analyze_error_page_security(body, 404);
    assert!(issues.contains(&ErrorPageSecurityIssue::FrameworkVersionLeaked));
}

#[test]
fn detects_framework_version_tomcat() {
    let body = "Apache Tomcat/9.0.54 - Error report";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::FrameworkVersionLeaked));
}

#[test]
fn detects_internal_path_linux() {
    let body = "Error loading file: /var/www/html/app/config.php";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::InternalPathExposed));
}

#[test]
fn detects_internal_path_windows() {
    let body = r"File not found: C:\inetpub\wwwroot\web.config";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::InternalPathExposed));
}

#[test]
fn detects_internal_path_home() {
    let body = "Config error at /home/ubuntu/app/settings.json";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::InternalPathExposed));
}

#[test]
fn detects_internal_path_app() {
    let body = "Module not found: /app/node_modules/express";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::InternalPathExposed));
}

#[test]
fn detects_debug_mode_django() {
    let body = "<h1>Django Debug</h1><p>Debug mode is ON</p>";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::DebugModeEnabled));
}

#[test]
fn detects_debug_mode_whoops() {
    let body = "<div class='Whoops!'>Exception occurred</div>";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::DebugModeEnabled));
}

#[test]
fn detects_debug_mode_development() {
    let body = "Application running in development mode";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::DebugModeEnabled));
}

#[test]
fn detects_debug_mode_explicit() {
    let body = "Error: debug = true in production";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::DebugModeEnabled));
}

#[test]
fn detects_environment_variable_path() {
    let body = "PATH=/usr/local/bin:/usr/bin:/bin";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::EnvironmentVariableLeaked));
}

#[test]
fn detects_environment_variable_api_key() {
    let body = "Configuration error: API_KEY=sk_test_12345678";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::EnvironmentVariableLeaked));
}

#[test]
fn detects_environment_variable_secret() {
    let body = "SECRET_KEY=django-insecure-abc123def456";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::EnvironmentVariableLeaked));
}

#[test]
fn detects_environment_variable_aws() {
    let body = "AWS_ACCESS_KEY_ID leaked in error";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::EnvironmentVariableLeaked));
}

#[test]
fn detects_source_code_python() {
    let body = "def handle_request():\n    return user.password";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::SourceCodeExposed));
}

#[test]
fn detects_source_code_javascript() {
    let body = "function authenticate() {\n  const token = req.headers.auth;";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::SourceCodeExposed));
}

#[test]
fn detects_source_code_java() {
    let body = "public class UserController {\n  private String password;";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::SourceCodeExposed));
}

#[test]
fn detects_source_code_php() {
    let body = "<?php\n$password = $_POST['pass'];\n?>";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::SourceCodeExposed));
}

#[test]
fn detects_session_info_session_id() {
    let body = "Error processing request with session_id=abc123xyz789";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::SessionInfoInError));
}

#[test]
fn detects_session_info_phpsessid() {
    let body = "PHPSESSID=a1b2c3d4e5f6g7h8i9j0";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::SessionInfoInError));
}

#[test]
fn detects_session_info_csrf_token() {
    let body = "CSRF validation failed: csrf_token=token123456";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::SessionInfoInError));
}

#[test]
fn detects_session_info_bearer() {
    let body = "Authorization failed: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    let issues = analyze_error_page_security(body, 401);
    assert!(issues.contains(&ErrorPageSecurityIssue::SessionInfoInError));
}

#[test]
fn detects_custom_error_missing_apache() {
    let body = "Apache Server at example.com Port 80\n404 Not Found";
    let issues = analyze_error_page_security(body, 404);
    assert!(issues.contains(&ErrorPageSecurityIssue::CustomErrorMissing));
}

#[test]
fn detects_custom_error_missing_nginx() {
    let body = "nginx error page\n404 Not Found";
    let issues = analyze_error_page_security(body, 404);
    assert!(issues.contains(&ErrorPageSecurityIssue::CustomErrorMissing));
}

#[test]
fn detects_custom_error_missing_tomcat() {
    let body = "Apache Tomcat Status Report\n404 - Not Found";
    let issues = analyze_error_page_security(body, 404);
    assert!(issues.contains(&ErrorPageSecurityIssue::CustomErrorMissing));
}

#[test]
fn detects_verbose_exception_fatal_error() {
    let body = "Fatal error: Uncaught Error in /var/www/app.php:42";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::VerboseExceptionDetails));
}

#[test]
fn detects_verbose_exception_unhandled() {
    let body = "Unhandled exception at line 156 in module auth.js";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::VerboseExceptionDetails));
}

#[test]
fn detects_verbose_exception_type_error() {
    let body = "TypeError: Cannot read property 'id' of undefined";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::VerboseExceptionDetails));
}

#[test]
fn detects_verbose_exception_null_pointer() {
    let body = "java.lang.NullPointerException at UserService.authenticate";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.contains(&ErrorPageSecurityIssue::VerboseExceptionDetails));
}

#[test]
fn no_issues_in_clean_error_page() {
    let body = "<html><body><h1>404 - Page Not Found</h1></body></html>";
    let issues = analyze_error_page_security(body, 404);
    assert!(issues.is_empty());
}

#[test]
fn multiple_security_issues() {
    let body = "Traceback (most recent call last):\n  File \"/var/www/app.py\"\n  DEBUG=True\n  API_KEY=secret123";
    let issues = analyze_error_page_security(body, 500);
    assert!(issues.len() >= 3);
    assert!(issues.contains(&ErrorPageSecurityIssue::StackTraceExposed));
    assert!(issues.contains(&ErrorPageSecurityIssue::InternalPathExposed));
    assert!(issues.contains(&ErrorPageSecurityIssue::DebugModeEnabled));
}

#[test]
fn severity_stack_trace() {
    let severity = error_page_security_severity(&ErrorPageSecurityIssue::StackTraceExposed);
    assert_eq!(severity, 7.0);
}

#[test]
fn severity_database_error() {
    let severity = error_page_security_severity(&ErrorPageSecurityIssue::DatabaseErrorExposed);
    assert_eq!(severity, 8.0);
}

#[test]
fn severity_session_info() {
    let severity = error_page_security_severity(&ErrorPageSecurityIssue::SessionInfoInError);
    assert_eq!(severity, 9.5);
}

#[test]
fn severity_custom_error_missing() {
    let severity = error_page_security_severity(&ErrorPageSecurityIssue::CustomErrorMissing);
    assert_eq!(severity, 4.0);
}

#[test]
fn operations_empty_when_no_security_issues() {
    let mut seq = 0;
    let ops = error_page_security_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_for_security_issues() {
    let issues = vec![ErrorPageSecurityIssue::StackTraceExposed];
    let mut seq = 0;
    let ops = error_page_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn operations_use_max_severity() {
    let issues = vec![
        ErrorPageSecurityIssue::CustomErrorMissing,
        ErrorPageSecurityIssue::SessionInfoInError,
        ErrorPageSecurityIssue::StackTraceExposed,
    ];
    let mut seq = 0;
    let ops = error_page_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
}

#[test]
fn display_format_stack_trace() {
    let issue = ErrorPageSecurityIssue::StackTraceExposed;
    assert_eq!(issue.to_string(), "Stack trace exposed in error page");
}

#[test]
fn display_format_environment_variable() {
    let issue = ErrorPageSecurityIssue::EnvironmentVariableLeaked;
    assert_eq!(issue.to_string(), "Environment variable leaked");
}
