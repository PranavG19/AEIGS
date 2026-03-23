use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

const ERROR_PATHS: &[&str] = &[
    "/doesnotexist-aegis-404-probe",
    "/%00",
    "/~",
    "/..;/",
];

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

pub fn error_page_to_operations(
    leaks: &[ErrorPageLeak],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if leaks.is_empty() {
        return Vec::new();
    }

    let max_severity = leaks
        .iter()
        .map(|l| l.severity)
        .fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::InformationDisclosure,
        max_severity,
        0.8,
    )]
}
