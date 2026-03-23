use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

const ERROR_PATHS: &[&str] = &["/doesnotexist-aegis-404-probe", "/%00", "/~", "/..;/"];

const STACK_TRACE_PATTERNS: &[(&str, &str, f64)] = &[
    ("traceback (most recent call last)", "python_traceback", 7.0),
    ("at java.", "java_stacktrace", 7.0),
    ("at node:", "node_stacktrace", 6.5),
    ("at object.", "node_stacktrace", 6.5),
    ("goroutine ", "go_stacktrace", 6.5),
    ("exception in thread", "java_stacktrace", 7.0),
    ("stack trace:", "generic_stacktrace", 6.0),
    ("fatal error:", "fatal_error", 6.5),
    ("unhandled exception", "unhandled_exception", 6.5),
    ("syntax error", "syntax_error", 5.0),
    ("debug mode is on", "debug_mode", 6.0),
    ("django debug", "django_debug", 7.0),
    ("laravel", "laravel_debug", 6.0),
    ("whoops!", "whoops_debug", 6.0),
    ("express-error-handler", "express_debug", 5.5),
    ("sqlstate[", "sql_error", 7.0),
    ("mysql_", "sql_error", 7.0),
    ("pg_query", "sql_error", 7.0),
    ("odbc error", "sql_error", 7.0),
    ("/var/www/", "internal_path", 5.0),
    ("/home/", "internal_path", 4.5),
    ("/usr/local/", "internal_path", 4.0),
    ("c:\\inetpub\\", "internal_path", 5.0),
    ("c:\\users\\", "internal_path", 4.5),
];

#[derive(Debug, Clone)]
pub struct ErrorPageLeak {
    pub path: String,
    pub pattern_name: String,
    pub severity: f64,
}

pub fn audit_error_pages(target: &str) -> Vec<ErrorPageLeak> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };

    let base = target.trim_end_matches('/');
    let mut leaks = Vec::new();

    for path in ERROR_PATHS {
        let url = format!("{base}{path}");
        let body = match client.get(&url).send().and_then(|r| r.text()) {
            Ok(t) => t,
            Err(_) => continue,
        };
        leaks.extend(analyze_error_body(&body, path));
    }

    leaks
}

pub(crate) fn analyze_error_body(body: &str, path: &str) -> Vec<ErrorPageLeak> {
    let lower = body.to_ascii_lowercase();
    let mut seen = Vec::new();
    let mut leaks = Vec::new();

    for (pattern, name, severity) in STACK_TRACE_PATTERNS {
        if lower.contains(pattern) && !seen.contains(name) {
            seen.push(name);
            leaks.push(ErrorPageLeak {
                path: path.to_string(),
                pattern_name: name.to_string(),
                severity: *severity,
            });
        }
    }

    leaks
}

pub fn error_page_to_operations(leaks: &[ErrorPageLeak], seq: &mut u64) -> Vec<OperationLogEntry> {
    if leaks.is_empty() {
        return Vec::new();
    }

    let max_severity = leaks.iter().map(|l| l.severity).fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::InformationDisclosure,
        max_severity,
        0.8,
    )]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorPageSecurityIssue {
    StackTraceExposed,
    DatabaseErrorExposed,
    FrameworkVersionLeaked,
    InternalPathExposed,
    DebugModeEnabled,
    EnvironmentVariableLeaked,
    SourceCodeExposed,
    SessionInfoInError,
    CustomErrorMissing,
    VerboseExceptionDetails,
}

impl std::fmt::Display for ErrorPageSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StackTraceExposed => write!(f, "Stack trace exposed in error page"),
            Self::DatabaseErrorExposed => write!(f, "Database error details exposed"),
            Self::FrameworkVersionLeaked => write!(f, "Framework/server version leaked"),
            Self::InternalPathExposed => write!(f, "Internal filesystem path exposed"),
            Self::DebugModeEnabled => write!(f, "Debug mode enabled indicators"),
            Self::EnvironmentVariableLeaked => write!(f, "Environment variable leaked"),
            Self::SourceCodeExposed => write!(f, "Source code snippet exposed"),
            Self::SessionInfoInError => write!(f, "Session information in error"),
            Self::CustomErrorMissing => write!(f, "Default server error page detected"),
            Self::VerboseExceptionDetails => write!(f, "Verbose exception details exposed"),
        }
    }
}

pub fn analyze_error_page_security(body: &str, status_code: u16) -> Vec<ErrorPageSecurityIssue> {
    let lower = body.to_ascii_lowercase();
    let mut issues = Vec::new();

    // StackTraceExposed
    if lower.contains("traceback (most recent call last)")
        || lower.contains("at java.")
        || lower.contains("at node:")
        || lower.contains("goroutine ")
        || lower.contains("stack trace:")
        || lower.contains("at object.")
    {
        issues.push(ErrorPageSecurityIssue::StackTraceExposed);
    }

    // DatabaseErrorExposed
    if lower.contains("sqlstate[")
        || lower.contains("mysql_")
        || lower.contains("pg_query")
        || lower.contains("odbc error")
        || lower.contains("ora-")
        || lower.contains("connection string")
        || lower.contains("database connection failed")
        || lower.contains("sql syntax")
    {
        issues.push(ErrorPageSecurityIssue::DatabaseErrorExposed);
    }

    // FrameworkVersionLeaked
    if (lower.contains("django") && lower.contains("version"))
        || (lower.contains("laravel") && lower.contains("v"))
        || lower.contains("express-error-handler")
        || lower.contains("apache/")
        || lower.contains("nginx/")
        || lower.contains("microsoft-iis/")
        || (lower.contains("php/") && body.contains('/'))
        || lower.contains("tomcat/")
        || lower.contains("jetty/")
    {
        issues.push(ErrorPageSecurityIssue::FrameworkVersionLeaked);
    }

    // InternalPathExposed
    if lower.contains("/var/www/")
        || lower.contains("/home/")
        || lower.contains("/usr/local/")
        || lower.contains("c:\\inetpub\\")
        || lower.contains("c:\\users\\")
        || lower.contains("/app/")
        || lower.contains("/opt/")
        || lower.contains("/srv/")
    {
        issues.push(ErrorPageSecurityIssue::InternalPathExposed);
    }

    // DebugModeEnabled
    if lower.contains("debug mode is on")
        || lower.contains("django debug")
        || lower.contains("whoops!")
        || lower.contains("development mode")
        || lower.contains("debug = true")
        || lower.contains("debug=true")
        || lower.contains("app_debug")
        || lower.contains("flask debugger")
    {
        issues.push(ErrorPageSecurityIssue::DebugModeEnabled);
    }

    // EnvironmentVariableLeaked
    if (lower.contains("env[") || lower.contains("$env"))
        || (lower.contains("path=") && lower.contains("/bin"))
        || lower.contains("api_key=")
        || lower.contains("secret_key=")
        || lower.contains("database_url=")
        || lower.contains("aws_access_key")
    {
        issues.push(ErrorPageSecurityIssue::EnvironmentVariableLeaked);
    }

    // SourceCodeExposed
    if (body.contains("def ") && body.contains("return"))
        || (body.contains("function ") && body.contains('{'))
        || (body.contains("public class") && body.contains('{'))
        || (body.contains("<?php") || body.contains("?>"))
        || (body.contains("namespace ") && body.contains("class "))
    {
        issues.push(ErrorPageSecurityIssue::SourceCodeExposed);
    }

    // SessionInfoInError
    if lower.contains("session_id=")
        || lower.contains("sessionid=")
        || lower.contains("phpsessid=")
        || lower.contains("jsessionid=")
        || lower.contains("csrf_token=")
        || lower.contains("bearer ")
        || (lower.contains("token") && body.chars().filter(|&c| c == '=' || c == ':').count() > 3)
    {
        issues.push(ErrorPageSecurityIssue::SessionInfoInError);
    }

    // CustomErrorMissing (default server error pages)
    if status_code >= 400
        && (lower.contains("apache") && lower.contains("server at")
            || lower.contains("nginx") && lower.contains("error page")
            || lower.contains("iis") && lower.contains("detailed error")
            || lower.contains("tomcat") && lower.contains("status report"))
    {
        issues.push(ErrorPageSecurityIssue::CustomErrorMissing);
    }

    // VerboseExceptionDetails
    if lower.contains("exception in thread")
        || lower.contains("fatal error:")
        || lower.contains("unhandled exception")
        || (lower.contains("error:") && lower.contains("line "))
        || (lower.contains("exception:") && body.lines().count() > 10)
        || lower.contains("typeerror:")
        || lower.contains("referenceerror:")
        || lower.contains("nullpointerexception")
    {
        issues.push(ErrorPageSecurityIssue::VerboseExceptionDetails);
    }

    issues
}

pub fn error_page_security_severity(issue: &ErrorPageSecurityIssue) -> f64 {
    match issue {
        ErrorPageSecurityIssue::StackTraceExposed => 7.0,
        ErrorPageSecurityIssue::DatabaseErrorExposed => 8.0,
        ErrorPageSecurityIssue::FrameworkVersionLeaked => 5.5,
        ErrorPageSecurityIssue::InternalPathExposed => 6.0,
        ErrorPageSecurityIssue::DebugModeEnabled => 7.5,
        ErrorPageSecurityIssue::EnvironmentVariableLeaked => 9.0,
        ErrorPageSecurityIssue::SourceCodeExposed => 8.5,
        ErrorPageSecurityIssue::SessionInfoInError => 9.5,
        ErrorPageSecurityIssue::CustomErrorMissing => 4.0,
        ErrorPageSecurityIssue::VerboseExceptionDetails => 6.5,
    }
}

pub fn error_page_security_to_operations(
    issues: &[ErrorPageSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let max_severity = issues
        .iter()
        .map(error_page_security_severity)
        .fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::InformationDisclosure,
        max_severity,
        0.85,
    )]
}
