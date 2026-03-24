use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

/// Default credential pairs commonly found on web apps, databases, and admin panels.
const DEFAULT_CREDENTIALS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("test", "test"),
    ("guest", "guest"),
    ("user", "user"),
    ("admin", ""),
    ("administrator", "administrator"),
    ("tomcat", "tomcat"),
    ("manager", "manager"),
    ("postgres", "postgres"),
    ("mysql", "mysql"),
    ("sa", ""),
    ("oracle", "oracle"),
    ("weblogic", "weblogic"),
    ("pi", "raspberry"),
];

/// Paths that indicate debug endpoints or unnecessary features left enabled.
const DEBUG_ENDPOINT_PATHS: &[&str] = &[
    "/__debug__/",
    "/debug/",
    "/debug/default/",
    "/_profiler/",
    "/elmah.axd",
    "/trace.axd",
    "/phpinfo.php",
    "/_debugbar/",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/configprops",
    "/console/",
    "/h2-console/",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/api-docs",
    "/graphiql",
    "/test/",
    "/testing/",
    "/__tests__/",
    "/dev/",
    "/staging/",
    "/_dev/",
];

/// Patterns that indicate verbose error handling in production.
const VERBOSE_ERROR_PATTERNS: &[(&str, &str)] = &[
    ("traceback (most recent call last)", "python_stacktrace"),
    ("at java.", "java_stacktrace"),
    ("at node:", "node_stacktrace"),
    ("goroutine ", "go_stacktrace"),
    ("stack trace:", "generic_stacktrace"),
    ("fatal error:", "fatal_error"),
    ("unhandled exception", "unhandled_exception"),
    ("sqlstate[", "sql_error_verbose"),
    ("mysql_", "mysql_error_verbose"),
    ("pg_query", "postgres_error_verbose"),
    ("odbc error", "odbc_error_verbose"),
    ("debug mode is on", "debug_mode_verbose"),
    ("django debug", "django_debug_verbose"),
    ("whoops!", "whoops_debug_verbose"),
    ("flask debugger", "flask_debugger_verbose"),
    ("express-error-handler", "express_debug_verbose"),
];

/// Paths that reveal directory listing when accessible.
const DIRECTORY_LISTING_PROBES: &[&str] = &[
    "/",
    "/images/",
    "/assets/",
    "/uploads/",
    "/static/",
    "/css/",
    "/js/",
    "/media/",
    "/files/",
    "/backup/",
    "/tmp/",
    "/logs/",
    "/data/",
];

/// Patterns that confirm directory listing is enabled.
const DIRECTORY_LISTING_INDICATORS: &[&str] = &[
    "index of /",
    "directory listing for",
    "<title>directory listing",
    "parent directory",
    "[to parent directory]",
    "directory contents",
    "apache server at",
    "<pre><a href=\"../\"",
];

/// Backup file suffixes to probe.
const BACKUP_SUFFIXES: &[&str] = &[
    ".bak", ".old", ".copy", ".swp", "~", ".save", ".orig", ".backup", ".tmp", ".dist", ".sample",
    ".bkp", ".prev",
];

/// Common admin panel paths.
const ADMIN_PANEL_PATHS: &[&str] = &[
    "/admin",
    "/admin/",
    "/administrator/",
    "/wp-admin/",
    "/wp-login.php",
    "/phpmyadmin/",
    "/adminer/",
    "/cpanel/",
    "/webmin/",
    "/manager/html",
    "/admin/login",
    "/admin/dashboard",
    "/backend/",
    "/panel/",
    "/controlpanel/",
    "/admin-console/",
    "/jmx-console/",
    "/web-console/",
];

/// Exposed configuration file paths.
const EXPOSED_CONFIG_PATHS: &[&str] = &[
    "/.env",
    "/.env.production",
    "/.env.local",
    "/.env.development",
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/.hg/requires",
    "/web.config",
    "/application.properties",
    "/application.yml",
    "/config.json",
    "/config.yml",
    "/config.xml",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/.htaccess",
    "/.htpasswd",
    "/composer.json",
    "/package.json",
    "/Gemfile",
    "/requirements.txt",
    "/Dockerfile",
    "/docker-compose.yml",
    "/.dockerenv",
];

/// Dangerous HTTP methods that should not be enabled on arbitrary endpoints.
const DANGEROUS_METHODS: &[&str] = &["DELETE", "PUT", "TRACE", "CONNECT", "PATCH"];

/// Headers that leak server information.
const SERVER_LEAK_HEADERS: &[&str] = &[
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-runtime",
    "x-version",
    "x-generator",
    "x-drupal-cache",
    "x-drupal-dynamic-cache",
];

/// Patterns that indicate version information in header values.
const VERSION_PATTERNS: &[&str] = &[
    "apache/",
    "nginx/",
    "microsoft-iis/",
    "php/",
    "openresty/",
    "litespeed/",
    "tomcat/",
    "jetty/",
    "express",
    "kestrel",
    "gunicorn",
    "werkzeug",
    "tornado/",
    "cowboy",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MisconfigCategory {
    DefaultCredentials,
    UnnecessaryFeatures,
    VerboseErrorHandling,
    DirectoryListing,
    BackupFileExposed,
    ExposedAdminPanel,
    ExposedConfigFile,
    DangerousHttpMethod,
    ServerInfoLeakage,
    InsecureCookieConfig,
}

impl std::fmt::Display for MisconfigCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DefaultCredentials => write!(f, "Default credentials detected"),
            Self::UnnecessaryFeatures => write!(f, "Unnecessary feature enabled"),
            Self::VerboseErrorHandling => write!(f, "Verbose error handling in production"),
            Self::DirectoryListing => write!(f, "Directory listing enabled"),
            Self::BackupFileExposed => write!(f, "Backup file publicly accessible"),
            Self::ExposedAdminPanel => write!(f, "Admin panel exposed without restriction"),
            Self::ExposedConfigFile => write!(f, "Configuration file publicly accessible"),
            Self::DangerousHttpMethod => write!(f, "Dangerous HTTP method allowed"),
            Self::ServerInfoLeakage => write!(f, "Server information leaked via headers"),
            Self::InsecureCookieConfig => write!(f, "Insecure cookie configuration"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecurityMisconfig {
    pub category: MisconfigCategory,
    pub detail: String,
    pub severity: f64,
    pub path: String,
}

/// Checks a username/password pair against the default credentials list.
pub fn is_default_credential(username: &str, password: &str) -> bool {
    let u_lower = username.to_ascii_lowercase();
    let p_lower = password.to_ascii_lowercase();
    DEFAULT_CREDENTIALS
        .iter()
        .any(|(u, p)| u_lower == *u && p_lower == *p)
}

/// Returns the full list of default credential pairs for external use.
pub fn default_credential_pairs() -> &'static [(&'static str, &'static str)] {
    DEFAULT_CREDENTIALS
}

/// Analyzes response headers for server information leakage.
pub fn analyze_server_headers(headers: &[(&str, &str)]) -> Vec<SecurityMisconfig> {
    let mut findings = Vec::new();

    for (name, value) in headers {
        let name_lower = name.to_ascii_lowercase();
        let value_lower = value.to_ascii_lowercase();

        let is_leak_header = SERVER_LEAK_HEADERS.iter().any(|h| name_lower == *h);

        if !is_leak_header {
            continue;
        }

        let has_version = VERSION_PATTERNS.iter().any(|p| value_lower.contains(p));

        let severity = if has_version { 5.5 } else { 3.5 };

        findings.push(SecurityMisconfig {
            category: MisconfigCategory::ServerInfoLeakage,
            detail: format!("{name}: {value}"),
            severity,
            path: String::new(),
        });
    }

    findings
}

/// Analyzes Set-Cookie headers for insecure configuration.
pub fn analyze_cookie_security(set_cookie_headers: &[&str]) -> Vec<SecurityMisconfig> {
    let mut findings = Vec::new();

    for cookie in set_cookie_headers {
        let lower = cookie.to_ascii_lowercase();
        let mut missing = Vec::new();

        if !lower.contains("secure") {
            missing.push("Secure");
        }
        if !lower.contains("httponly") {
            missing.push("HttpOnly");
        }
        if !lower.contains("samesite") {
            missing.push("SameSite");
        }

        if !missing.is_empty() {
            let cookie_name = cookie.split('=').next().unwrap_or("unknown").trim();
            findings.push(SecurityMisconfig {
                category: MisconfigCategory::InsecureCookieConfig,
                detail: format!(
                    "Cookie '{}' missing attributes: {}",
                    cookie_name,
                    missing.join(", ")
                ),
                severity: if missing.contains(&"Secure") {
                    6.5
                } else {
                    5.0
                },
                path: String::new(),
            });
        }
    }

    findings
}

/// Checks a response body for verbose error patterns.
pub fn analyze_error_verbosity(body: &str, path: &str) -> Vec<SecurityMisconfig> {
    let lower = body.to_ascii_lowercase();
    let mut findings = Vec::new();
    let mut seen_patterns: Vec<&str> = Vec::new();

    for (pattern, name) in VERBOSE_ERROR_PATTERNS {
        if lower.contains(pattern) && !seen_patterns.contains(name) {
            seen_patterns.push(name);
            findings.push(SecurityMisconfig {
                category: MisconfigCategory::VerboseErrorHandling,
                detail: format!("Pattern '{name}' detected in response"),
                severity: 6.5,
                path: path.to_string(),
            });
        }
    }

    findings
}

/// Checks whether a response body indicates directory listing is enabled.
pub fn detect_directory_listing(body: &str, path: &str) -> Option<SecurityMisconfig> {
    let lower = body.to_ascii_lowercase();
    for indicator in DIRECTORY_LISTING_INDICATORS {
        if lower.contains(indicator) {
            return Some(SecurityMisconfig {
                category: MisconfigCategory::DirectoryListing,
                detail: format!("Directory listing detected via pattern: {indicator}"),
                severity: 5.0,
                path: path.to_string(),
            });
        }
    }
    None
}

/// Checks whether a response to a backup file probe indicates the file exists.
pub fn detect_backup_file(
    status_code: u16,
    content_type: &str,
    path: &str,
) -> Option<SecurityMisconfig> {
    if status_code == 200 && !content_type.contains("text/html") {
        let is_backup = BACKUP_SUFFIXES.iter().any(|s| path.ends_with(s));
        if is_backup {
            return Some(SecurityMisconfig {
                category: MisconfigCategory::BackupFileExposed,
                detail: format!("Backup file accessible: {path}"),
                severity: 7.0,
                path: path.to_string(),
            });
        }
    }
    None
}

/// Checks whether an admin panel path returns a non-404 response.
pub fn detect_admin_panel(status_code: u16, path: &str) -> Option<SecurityMisconfig> {
    if status_code != 404
        && status_code != 403
        && status_code < 500
        && ADMIN_PANEL_PATHS.contains(&path)
    {
        return Some(SecurityMisconfig {
            category: MisconfigCategory::ExposedAdminPanel,
            detail: format!("Admin panel accessible at {path}"),
            severity: 8.0,
            path: path.to_string(),
        });
    }
    None
}

/// Checks whether a config file path returns content that looks like configuration.
pub fn detect_exposed_config(
    status_code: u16,
    body: &str,
    path: &str,
) -> Option<SecurityMisconfig> {
    if status_code != 200 {
        return None;
    }
    if !EXPOSED_CONFIG_PATHS.contains(&path) {
        return None;
    }

    let lower = body.to_ascii_lowercase();
    let looks_like_config = lower.contains("password")
        || lower.contains("secret")
        || lower.contains("api_key")
        || lower.contains("database")
        || lower.contains("db_host")
        || lower.contains("aws_")
        || lower.contains("[core]")
        || lower.contains("ref:")
        || lower.contains("host=")
        || lower.contains("port=")
        || body.contains('=') && body.lines().count() > 2;

    if looks_like_config {
        return Some(SecurityMisconfig {
            category: MisconfigCategory::ExposedConfigFile,
            detail: format!("Configuration file exposed: {path}"),
            severity: 9.0,
            path: path.to_string(),
        });
    }
    None
}

/// Checks whether dangerous HTTP methods are enabled on a given endpoint.
pub fn detect_dangerous_methods(allowed_methods: &[&str], path: &str) -> Vec<SecurityMisconfig> {
    let mut findings = Vec::new();

    for method in allowed_methods {
        let upper = method.to_ascii_uppercase();
        if DANGEROUS_METHODS.contains(&upper.as_str()) {
            let severity = match upper.as_str() {
                "DELETE" => 7.5,
                "PUT" => 6.0,
                "TRACE" => 5.5,
                "CONNECT" => 4.0,
                "PATCH" => 4.5,
                _ => 4.0,
            };
            findings.push(SecurityMisconfig {
                category: MisconfigCategory::DangerousHttpMethod,
                detail: format!("Method {upper} allowed on {path}"),
                severity,
                path: path.to_string(),
            });
        }
    }

    findings
}

/// Checks whether debug/unnecessary endpoints return non-error status codes.
pub fn detect_debug_endpoint(status_code: u16, path: &str) -> Option<SecurityMisconfig> {
    if status_code >= 400 {
        return None;
    }
    if DEBUG_ENDPOINT_PATHS.contains(&path) {
        return Some(SecurityMisconfig {
            category: MisconfigCategory::UnnecessaryFeatures,
            detail: format!("Debug/test endpoint accessible: {path}"),
            severity: 7.0,
            path: path.to_string(),
        });
    }
    None
}

/// Runs the full live misconfiguration scan against a target URL.
pub fn audit_security_misconfig(target: &str) -> Vec<SecurityMisconfig> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };

    let base = target.trim_end_matches('/');
    let mut findings = Vec::new();

    for path in DEBUG_ENDPOINT_PATHS {
        let url = format!("{base}{path}");
        if let Ok(resp) = client.get(&url).send()
            && let Some(f) = detect_debug_endpoint(resp.status().as_u16(), path)
        {
            findings.push(f);
        }
    }

    for path in DIRECTORY_LISTING_PROBES {
        let url = format!("{base}{path}");
        if let Ok(resp) = client.get(&url).send()
            && let Ok(body) = resp.text()
            && let Some(f) = detect_directory_listing(&body, path)
        {
            findings.push(f);
        }
    }

    for path in EXPOSED_CONFIG_PATHS {
        let url = format!("{base}{path}");
        if let Ok(resp) = client.get(&url).send() {
            let status = resp.status().as_u16();
            if let Ok(body) = resp.text()
                && let Some(f) = detect_exposed_config(status, &body, path)
            {
                findings.push(f);
            }
        }
    }

    for path in ADMIN_PANEL_PATHS {
        let url = format!("{base}{path}");
        if let Ok(resp) = client.get(&url).send()
            && let Some(f) = detect_admin_panel(resp.status().as_u16(), path)
        {
            findings.push(f);
        }
    }

    findings
}

/// Returns the OWASP category label for misconfiguration findings.
pub fn owasp_category() -> &'static str {
    "A05:2021 Security Misconfiguration"
}

/// Computes the maximum severity from a set of findings.
pub fn max_severity(findings: &[SecurityMisconfig]) -> f64 {
    findings.iter().map(|f| f.severity).fold(0.0_f64, f64::max)
}

/// Converts misconfiguration findings into knowledge-graph operation log entries.
pub fn misconfig_to_operations(
    findings: &[SecurityMisconfig],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if findings.is_empty() {
        return Vec::new();
    }

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::SecurityMisconfiguration,
        max_severity(findings),
        0.85,
    )]
}

/// Returns the complete list of admin panel paths for external use.
pub fn admin_panel_paths() -> &'static [&'static str] {
    ADMIN_PANEL_PATHS
}

/// Returns the complete list of exposed config paths for external use.
pub fn exposed_config_paths() -> &'static [&'static str] {
    EXPOSED_CONFIG_PATHS
}

/// Returns the complete list of backup suffixes for external use.
pub fn backup_suffixes() -> &'static [&'static str] {
    BACKUP_SUFFIXES
}

/// Returns the complete list of debug endpoint paths for external use.
pub fn debug_endpoint_paths() -> &'static [&'static str] {
    DEBUG_ENDPOINT_PATHS
}

/// Returns the complete list of directory listing probe paths.
pub fn directory_listing_probes() -> &'static [&'static str] {
    DIRECTORY_LISTING_PROBES
}

/// Returns the complete list of dangerous HTTP methods.
pub fn dangerous_methods() -> &'static [&'static str] {
    DANGEROUS_METHODS
}

/// Returns the complete list of server leak headers.
pub fn server_leak_headers() -> &'static [&'static str] {
    SERVER_LEAK_HEADERS
}
