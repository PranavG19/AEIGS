use std::collections::HashMap;

use regex::Regex;

/// Categories of information disclosed via error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorDisclosureCategory {
    StackTrace,
    SqlError,
    PathDisclosure,
    VersionDisclosure,
    HostnameOrIpLeak,
    DebugMode,
}

impl std::fmt::Display for ErrorDisclosureCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StackTrace => write!(f, "Stack Trace"),
            Self::SqlError => write!(f, "SQL Error"),
            Self::PathDisclosure => write!(f, "Path Disclosure"),
            Self::VersionDisclosure => write!(f, "Version Disclosure"),
            Self::HostnameOrIpLeak => write!(f, "Hostname/IP Leak"),
            Self::DebugMode => write!(f, "Debug Mode"),
        }
    }
}

/// Programming language detected from a stack trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StackTraceLanguage {
    Java,
    Python,
    Php,
    DotNet,
    NodeJs,
    Ruby,
    Go,
}

impl std::fmt::Display for StackTraceLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Java => write!(f, "Java"),
            Self::Python => write!(f, "Python"),
            Self::Php => write!(f, "PHP"),
            Self::DotNet => write!(f, ".NET"),
            Self::NodeJs => write!(f, "Node.js"),
            Self::Ruby => write!(f, "Ruby"),
            Self::Go => write!(f, "Go"),
        }
    }
}

/// Database type detected from SQL error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DatabaseType {
    MySql,
    PostgreSql,
    MsSql,
    Oracle,
    MongoDb,
}

impl std::fmt::Display for DatabaseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MySql => write!(f, "MySQL"),
            Self::PostgreSql => write!(f, "PostgreSQL"),
            Self::MsSql => write!(f, "MSSQL"),
            Self::Oracle => write!(f, "Oracle"),
            Self::MongoDb => write!(f, "MongoDB"),
        }
    }
}

/// A single finding from error disclosure analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct ErrorDisclosureFinding {
    pub category: ErrorDisclosureCategory,
    pub detail: String,
    pub evidence: String,
    pub language: Option<StackTraceLanguage>,
    pub database: Option<DatabaseType>,
}

/// An error-triggering request pattern.
#[derive(Debug, Clone, PartialEq)]
pub struct ErrorTriggerRequest {
    pub name: String,
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub description: String,
}

/// Aggregated results of error disclosure analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct ErrorDisclosureReport {
    pub findings: Vec<ErrorDisclosureFinding>,
    pub category_counts: HashMap<ErrorDisclosureCategory, usize>,
    pub detected_languages: Vec<StackTraceLanguage>,
    pub detected_databases: Vec<DatabaseType>,
    pub trigger_requests_used: usize,
}

/// Generates a set of error-triggering request patterns.
/// Returns ≥15 distinct patterns designed to provoke verbose error responses.
pub fn generate_error_triggers(base_path: &str) -> Vec<ErrorTriggerRequest> {
    let path = if base_path.is_empty() { "/" } else { base_path };

    vec![
        ErrorTriggerRequest {
            name: "invalid_http_method".into(),
            method: "FOOBAR".into(),
            path: path.into(),
            headers: vec![],
            body: None,
            description: "Invalid HTTP method to trigger 405/error".into(),
        },
        ErrorTriggerRequest {
            name: "oversized_header".into(),
            method: "GET".into(),
            path: path.into(),
            headers: vec![("X-Overflow".into(), "A".repeat(16384))],
            body: None,
            description: "Oversized header value to trigger 431/server error".into(),
        },
        ErrorTriggerRequest {
            name: "bad_content_type".into(),
            method: "POST".into(),
            path: path.into(),
            headers: vec![("Content-Type".into(), "application/x-invalid-type".into())],
            body: Some("{}".into()),
            description: "Invalid Content-Type to trigger parsing error".into(),
        },
        ErrorTriggerRequest {
            name: "malformed_json".into(),
            method: "POST".into(),
            path: path.into(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: Some("{{{invalid json!!!".into()),
            description: "Malformed JSON body to trigger parse error".into(),
        },
        ErrorTriggerRequest {
            name: "string_where_int_expected".into(),
            method: "POST".into(),
            path: path.into(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: Some(r#"{"id":"not_a_number","count":"abc"}"#.into()),
            description: "Type confusion: string where integer expected".into(),
        },
        ErrorTriggerRequest {
            name: "array_where_object_expected".into(),
            method: "POST".into(),
            path: path.into(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: Some(r#"[1,2,3]"#.into()),
            description: "Type confusion: array where object expected".into(),
        },
        ErrorTriggerRequest {
            name: "max_int_boundary".into(),
            method: "POST".into(),
            path: path.into(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: Some(r#"{"id":9999999999999999999999999999}"#.into()),
            description: "Boundary value: MAX_INT overflow".into(),
        },
        ErrorTriggerRequest {
            name: "empty_string_fields".into(),
            method: "POST".into(),
            path: path.into(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: Some(r#"{"username":"","password":"","email":""}"#.into()),
            description: "Boundary value: empty string fields".into(),
        },
        ErrorTriggerRequest {
            name: "null_byte_injection".into(),
            method: "GET".into(),
            path: format!("{path}%00.php"),
            headers: vec![],
            body: None,
            description: "Null byte in URL path to trigger path parsing error".into(),
        },
        ErrorTriggerRequest {
            name: "path_traversal_trigger".into(),
            method: "GET".into(),
            path: format!("{path}/../../../../../etc/passwd"),
            headers: vec![],
            body: None,
            description: "Path traversal to trigger filesystem error disclosure".into(),
        },
        ErrorTriggerRequest {
            name: "sql_injection_trigger".into(),
            method: "GET".into(),
            path: format!("{path}?id=1'%20OR%20'1'='1"),
            headers: vec![],
            body: None,
            description: "SQL injection probe to trigger database error".into(),
        },
        ErrorTriggerRequest {
            name: "nonexistent_deep_path".into(),
            method: "GET".into(),
            path: format!("{path}/definitely/does/not/exist/here.aspx"),
            headers: vec![],
            body: None,
            description: "Deep nonexistent path to trigger verbose 404".into(),
        },
        ErrorTriggerRequest {
            name: "xml_content_as_json".into(),
            method: "POST".into(),
            path: path.into(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: Some("<?xml version=\"1.0\"?><root>test</root>".into()),
            description: "XML body sent as JSON Content-Type".into(),
        },
        ErrorTriggerRequest {
            name: "negative_content_length".into(),
            method: "POST".into(),
            path: path.into(),
            headers: vec![("Content-Length".into(), "-1".into())],
            body: Some("test".into()),
            description: "Negative Content-Length header".into(),
        },
        ErrorTriggerRequest {
            name: "duplicate_content_type".into(),
            method: "POST".into(),
            path: path.into(),
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
                ("Content-Type".into(), "text/xml".into()),
            ],
            body: Some("{}".into()),
            description: "Duplicate conflicting Content-Type headers".into(),
        },
        ErrorTriggerRequest {
            name: "null_json_values".into(),
            method: "POST".into(),
            path: path.into(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: Some(r#"{"id":null,"name":null,"value":null}"#.into()),
            description: "All-null JSON field values".into(),
        },
        ErrorTriggerRequest {
            name: "deeply_nested_json".into(),
            method: "POST".into(),
            path: path.into(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: Some(generate_nested_json(128)),
            description: "Deeply nested JSON to trigger recursion/stack error".into(),
        },
        ErrorTriggerRequest {
            name: "special_chars_in_path".into(),
            method: "GET".into(),
            path: format!("{path}/<script>alert(1)</script>"),
            headers: vec![],
            body: None,
            description: "Special characters in path to trigger encoding error".into(),
        },
    ]
}

fn generate_nested_json(depth: usize) -> String {
    let mut s = String::new();
    for _ in 0..depth {
        s.push_str(r#"{"a":"#);
    }
    s.push('1');
    for _ in 0..depth {
        s.push('}');
    }
    s
}

/// Analyzes a response body (and optional headers) for information disclosure.
pub fn analyze_error_response(
    body: &str,
    headers: &HashMap<String, String>,
) -> Vec<ErrorDisclosureFinding> {
    let mut findings = Vec::new();
    findings.extend(detect_stack_traces(body));
    findings.extend(detect_sql_errors(body));
    findings.extend(detect_path_disclosure(body));
    findings.extend(detect_version_disclosure(body, headers));
    findings.extend(detect_hostname_ip_leak(body));
    findings.extend(detect_debug_mode(body, headers));
    findings
}

/// Builds an aggregated report from a list of findings.
pub fn build_disclosure_report(
    findings: Vec<ErrorDisclosureFinding>,
    trigger_count: usize,
) -> ErrorDisclosureReport {
    let mut category_counts: HashMap<ErrorDisclosureCategory, usize> = HashMap::new();
    let mut languages = Vec::new();
    let mut databases = Vec::new();

    for f in &findings {
        *category_counts.entry(f.category).or_default() += 1;
        if let Some(lang) = f.language
            && !languages.contains(&lang)
        {
            languages.push(lang);
        }
        if let Some(db) = f.database
            && !databases.contains(&db)
        {
            databases.push(db);
        }
    }

    ErrorDisclosureReport {
        findings,
        category_counts,
        detected_languages: languages,
        detected_databases: databases,
        trigger_requests_used: trigger_count,
    }
}

fn detect_stack_traces(body: &str) -> Vec<ErrorDisclosureFinding> {
    let mut findings = Vec::new();

    let java_re =
        Regex::new(r"(?i)(at\s+[\w.$]+\([\w]+\.java:\d+\)|java\.\w+\.[\w.]+Exception)").unwrap();
    if java_re.is_match(body) {
        let evidence = extract_match(&java_re, body);
        findings.push(ErrorDisclosureFinding {
            category: ErrorDisclosureCategory::StackTrace,
            detail: "Java stack trace detected".into(),
            evidence,
            language: Some(StackTraceLanguage::Java),
            database: None,
        });
    }

    let python_re =
        Regex::new(r#"(?i)(Traceback \(most recent call last\)|File "[\w/\\._-]+\.py", line \d+)"#)
            .unwrap();
    if python_re.is_match(body) {
        let evidence = extract_match(&python_re, body);
        findings.push(ErrorDisclosureFinding {
            category: ErrorDisclosureCategory::StackTrace,
            detail: "Python stack trace detected".into(),
            evidence,
            language: Some(StackTraceLanguage::Python),
            database: None,
        });
    }

    let php_re = Regex::new(
        r"(?i)(Fatal error:.*in\s+[\w/\\._-]+\.php\s+on\s+line\s+\d+|Stack trace:.*#\d+\s+[\w/\\._-]+\.php\(\d+\))",
    )
    .unwrap();
    if php_re.is_match(body) {
        let evidence = extract_match(&php_re, body);
        findings.push(ErrorDisclosureFinding {
            category: ErrorDisclosureCategory::StackTrace,
            detail: "PHP stack trace detected".into(),
            evidence,
            language: Some(StackTraceLanguage::Php),
            database: None,
        });
    }

    let dotnet_re = Regex::new(
        r"(?i)(at\s+[\w.]+\s+in\s+[\w\\/_.-]+\.cs:line\s+\d+|System\.\w+Exception:|Server Error in .+ Application)",
    )
    .unwrap();
    if dotnet_re.is_match(body) {
        let evidence = extract_match(&dotnet_re, body);
        findings.push(ErrorDisclosureFinding {
            category: ErrorDisclosureCategory::StackTrace,
            detail: ".NET stack trace detected".into(),
            evidence,
            language: Some(StackTraceLanguage::DotNet),
            database: None,
        });
    }

    let node_re = Regex::new(
        r"(?i)(at\s+[\w.]+\s+\([\w/\\._-]+\.js:\d+:\d+\)|TypeError:|ReferenceError:|RangeError:)",
    )
    .unwrap();
    if node_re.is_match(body) {
        let evidence = extract_match(&node_re, body);
        findings.push(ErrorDisclosureFinding {
            category: ErrorDisclosureCategory::StackTrace,
            detail: "Node.js stack trace detected".into(),
            evidence,
            language: Some(StackTraceLanguage::NodeJs),
            database: None,
        });
    }

    let ruby_re = Regex::new(r"(?i)([\w/\\._-]+\.rb:\d+:in\s+`[\w]+')").unwrap();
    if ruby_re.is_match(body) {
        let evidence = extract_match(&ruby_re, body);
        findings.push(ErrorDisclosureFinding {
            category: ErrorDisclosureCategory::StackTrace,
            detail: "Ruby stack trace detected".into(),
            evidence,
            language: Some(StackTraceLanguage::Ruby),
            database: None,
        });
    }

    let go_re =
        Regex::new(r"(?i)(goroutine\s+\d+\s+\[running\]|[\w/\\._-]+\.go:\d+\s+\+0x[0-9a-f]+)")
            .unwrap();
    if go_re.is_match(body) {
        let evidence = extract_match(&go_re, body);
        findings.push(ErrorDisclosureFinding {
            category: ErrorDisclosureCategory::StackTrace,
            detail: "Go stack trace detected".into(),
            evidence,
            language: Some(StackTraceLanguage::Go),
            database: None,
        });
    }

    findings
}

fn detect_sql_errors(body: &str) -> Vec<ErrorDisclosureFinding> {
    let mut findings = Vec::new();

    let mysql_patterns = [
        r"(?i)you have an error in your sql syntax",
        r"(?i)mysql_fetch",
        r"(?i)mysql_num_rows",
        r"(?i)Warning:.*mysql_",
        r"(?i)MySqlException",
        r"(?i)com\.mysql\.jdbc",
    ];
    for pat in &mysql_patterns {
        let re = Regex::new(pat).unwrap();
        if re.is_match(body) {
            findings.push(ErrorDisclosureFinding {
                category: ErrorDisclosureCategory::SqlError,
                detail: "MySQL error message detected".into(),
                evidence: extract_match(&re, body),
                language: None,
                database: Some(DatabaseType::MySql),
            });
            break;
        }
    }

    let pg_patterns = [
        r"(?i)ERROR:\s+syntax error at or near",
        r"(?i)pg_query",
        r"(?i)pg_exec",
        r"(?i)PostgreSQL.*ERROR",
        r"(?i)Npgsql\.",
        r"(?i)org\.postgresql\.util\.PSQLException",
    ];
    for pat in &pg_patterns {
        let re = Regex::new(pat).unwrap();
        if re.is_match(body) {
            findings.push(ErrorDisclosureFinding {
                category: ErrorDisclosureCategory::SqlError,
                detail: "PostgreSQL error message detected".into(),
                evidence: extract_match(&re, body),
                language: None,
                database: Some(DatabaseType::PostgreSql),
            });
            break;
        }
    }

    let mssql_patterns = [
        r"(?i)\[Microsoft\]\[ODBC SQL Server Driver\]",
        r"(?i)Unclosed quotation mark after the character string",
        r"(?i)Microsoft OLE DB Provider for SQL Server",
        r"(?i)SqlException",
        r"(?i)Incorrect syntax near",
    ];
    for pat in &mssql_patterns {
        let re = Regex::new(pat).unwrap();
        if re.is_match(body) {
            findings.push(ErrorDisclosureFinding {
                category: ErrorDisclosureCategory::SqlError,
                detail: "MSSQL error message detected".into(),
                evidence: extract_match(&re, body),
                language: None,
                database: Some(DatabaseType::MsSql),
            });
            break;
        }
    }

    let oracle_patterns = [
        r"(?i)ORA-\d{5}",
        r"(?i)Oracle.*Driver",
        r"(?i)oracle\.jdbc",
        r"(?i)quoted string not properly terminated",
    ];
    for pat in &oracle_patterns {
        let re = Regex::new(pat).unwrap();
        if re.is_match(body) {
            findings.push(ErrorDisclosureFinding {
                category: ErrorDisclosureCategory::SqlError,
                detail: "Oracle error message detected".into(),
                evidence: extract_match(&re, body),
                language: None,
                database: Some(DatabaseType::Oracle),
            });
            break;
        }
    }

    let mongo_patterns = [
        r"(?i)MongoError",
        r"(?i)MongoDB.*Error",
        r"(?i)\$where.*MongoServerError",
        r"(?i)BSONTypeError",
    ];
    for pat in &mongo_patterns {
        let re = Regex::new(pat).unwrap();
        if re.is_match(body) {
            findings.push(ErrorDisclosureFinding {
                category: ErrorDisclosureCategory::SqlError,
                detail: "MongoDB error message detected".into(),
                evidence: extract_match(&re, body),
                language: None,
                database: Some(DatabaseType::MongoDb),
            });
            break;
        }
    }

    findings
}

fn detect_path_disclosure(body: &str) -> Vec<ErrorDisclosureFinding> {
    let mut findings = Vec::new();

    let unix_path_re = Regex::new(r"(/(?:home|var|usr|etc|opt|srv|tmp|root)/[\w./_-]+)").unwrap();
    if let Some(m) = unix_path_re.find(body) {
        findings.push(ErrorDisclosureFinding {
            category: ErrorDisclosureCategory::PathDisclosure,
            detail: "Unix file path disclosed in error".into(),
            evidence: m.as_str().to_string(),
            language: None,
            database: None,
        });
    }

    let win_path_re =
        Regex::new(r"(?i)([A-Z]:\\(?:Users|Windows|Program Files|inetpub|wwwroot)[\w.\\ _-]+)")
            .unwrap();
    if let Some(m) = win_path_re.find(body) {
        findings.push(ErrorDisclosureFinding {
            category: ErrorDisclosureCategory::PathDisclosure,
            detail: "Windows file path disclosed in error".into(),
            evidence: m.as_str().to_string(),
            language: None,
            database: None,
        });
    }

    findings
}

fn detect_version_disclosure(
    body: &str,
    headers: &HashMap<String, String>,
) -> Vec<ErrorDisclosureFinding> {
    let mut findings = Vec::new();

    let version_patterns = [
        (r"(?i)Apache/([\d.]+)", "Apache"),
        (r"(?i)nginx/([\d.]+)", "nginx"),
        (r"(?i)Microsoft-IIS/([\d.]+)", "IIS"),
        (r"(?i)PHP/([\d.]+)", "PHP"),
        (r"(?i)Express/([\d.]+)", "Express"),
        (r"(?i)Django/([\d.]+)", "Django"),
        (r"(?i)Laravel\s+v?([\d.]+)", "Laravel"),
        (r"(?i)ASP\.NET\s+Version[:\s]+([\d.]+)", "ASP.NET"),
        (r"(?i)Flask/([\d.]+)", "Flask"),
        (r"(?i)Spring\s+Boot\s+v?([\d.]+)", "Spring Boot"),
    ];

    for (pat, tech_name) in &version_patterns {
        let re = Regex::new(pat).unwrap();
        if let Some(caps) = re.captures(body) {
            let version = caps.get(1).map_or("", |m| m.as_str());
            findings.push(ErrorDisclosureFinding {
                category: ErrorDisclosureCategory::VersionDisclosure,
                detail: format!("{tech_name} version {version} disclosed in body"),
                evidence: caps.get(0).map_or("", |m| m.as_str()).to_string(),
                language: None,
                database: None,
            });
        }
    }

    let header_keys = ["server", "x-powered-by", "x-aspnet-version", "x-generator"];
    let version_re = Regex::new(r"[\d]+\.[\d]+").unwrap();
    for key in &header_keys {
        if let Some(val) = headers.get(*key)
            && version_re.is_match(val)
        {
            findings.push(ErrorDisclosureFinding {
                category: ErrorDisclosureCategory::VersionDisclosure,
                detail: format!("Version disclosed in `{key}` header"),
                evidence: format!("{key}: {val}"),
                language: None,
                database: None,
            });
        }
    }

    findings
}

fn detect_hostname_ip_leak(body: &str) -> Vec<ErrorDisclosureFinding> {
    let mut findings = Vec::new();

    let internal_ip_re = Regex::new(
        r"(?:^|\s|[^0-9])((?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}))(?:\s|[^0-9]|$)",
    )
    .unwrap();
    if let Some(caps) = internal_ip_re.captures(body) {
        findings.push(ErrorDisclosureFinding {
            category: ErrorDisclosureCategory::HostnameOrIpLeak,
            detail: "Internal IP address leaked in error response".into(),
            evidence: caps.get(1).map_or("", |m| m.as_str()).to_string(),
            language: None,
            database: None,
        });
    }

    let hostname_re = Regex::new(
        r"(?i)(?:hostname|server[_-]?name|host)[:\s=]+([a-zA-Z][\w.-]+\.(?:internal|local|corp|lan|intra|priv))",
    )
    .unwrap();
    if let Some(caps) = hostname_re.captures(body) {
        findings.push(ErrorDisclosureFinding {
            category: ErrorDisclosureCategory::HostnameOrIpLeak,
            detail: "Internal hostname leaked in error response".into(),
            evidence: caps.get(1).map_or("", |m| m.as_str()).to_string(),
            language: None,
            database: None,
        });
    }

    findings
}

fn detect_debug_mode(body: &str, headers: &HashMap<String, String>) -> Vec<ErrorDisclosureFinding> {
    let mut findings = Vec::new();

    let debug_patterns = [
        (
            r"(?is)Django\s+Version.*DEBUG\s*=\s*True",
            "Django DEBUG=True",
        ),
        (r"(?i)Whoops!.*Stack\s+trace", "Laravel/Whoops debug page"),
        (r"(?i)APP_DEBUG\s*=\s*true", "Laravel APP_DEBUG=true"),
        (
            r#"(?i)<pre\s+class=['"]cake-error['"]>"#,
            "CakePHP debug mode",
        ),
        (
            r"(?i)Symfony\\Component\\HttpKernel\\Exception",
            "Symfony debug exception",
        ),
        (r"(?i)X-Debug-Token:", "Symfony debug toolbar token"),
        (
            r"(?i)WEB_DEBUG\s*=\s*(?:true|1|on)",
            "Generic WEB_DEBUG enabled",
        ),
        (
            r"(?i)<title>Error\s*-\s*Express</title>",
            "Express default error page",
        ),
    ];

    for (pat, desc) in &debug_patterns {
        let re = Regex::new(pat).unwrap();
        if re.is_match(body) {
            findings.push(ErrorDisclosureFinding {
                category: ErrorDisclosureCategory::DebugMode,
                detail: format!("{desc} detected"),
                evidence: extract_match(&re, body),
                language: None,
                database: None,
            });
        }
    }

    if let Some(val) = headers.get("x-debug-token") {
        findings.push(ErrorDisclosureFinding {
            category: ErrorDisclosureCategory::DebugMode,
            detail: "Symfony debug token in response header".into(),
            evidence: format!("x-debug-token: {val}"),
            language: None,
            database: None,
        });
    }

    if let Some(val) = headers.get("x-debug-token-link") {
        findings.push(ErrorDisclosureFinding {
            category: ErrorDisclosureCategory::DebugMode,
            detail: "Symfony debug token link in response header".into(),
            evidence: format!("x-debug-token-link: {val}"),
            language: None,
            database: None,
        });
    }

    findings
}

fn extract_match(re: &Regex, text: &str) -> String {
    re.find(text)
        .map(|m| {
            let s = m.as_str();
            if s.len() > 200 {
                format!("{}...", &s[..200])
            } else {
                s.to_string()
            }
        })
        .unwrap_or_default()
}

/// Maps an error fingerprint to likely technology stack.
pub fn fingerprint_error_to_tech(findings: &[ErrorDisclosureFinding]) -> HashMap<String, String> {
    let mut tech_map = HashMap::new();

    for f in findings {
        match f.category {
            ErrorDisclosureCategory::StackTrace => {
                if let Some(lang) = f.language {
                    tech_map.insert("language".into(), lang.to_string());
                }
            }
            ErrorDisclosureCategory::SqlError => {
                if let Some(db) = f.database {
                    tech_map.insert("database".into(), db.to_string());
                }
            }
            ErrorDisclosureCategory::VersionDisclosure => {
                if f.detail.contains("Apache") {
                    tech_map.insert("web_server".into(), "Apache".into());
                } else if f.detail.contains("nginx") {
                    tech_map.insert("web_server".into(), "nginx".into());
                } else if f.detail.contains("IIS") {
                    tech_map.insert("web_server".into(), "IIS".into());
                }
                if f.detail.contains("Django") || f.detail.contains("Flask") {
                    tech_map.insert("framework".into(), f.detail.clone());
                } else if f.detail.contains("Express") {
                    tech_map.insert("framework".into(), "Express".into());
                } else if f.detail.contains("Laravel") {
                    tech_map.insert("framework".into(), "Laravel".into());
                } else if f.detail.contains("Spring") {
                    tech_map.insert("framework".into(), "Spring Boot".into());
                }
            }
            ErrorDisclosureCategory::DebugMode => {
                if f.detail.contains("Django") {
                    tech_map.insert("framework".into(), "Django".into());
                    tech_map.insert("debug_mode".into(), "true".into());
                } else if f.detail.contains("Laravel") || f.detail.contains("Whoops") {
                    tech_map.insert("framework".into(), "Laravel".into());
                    tech_map.insert("debug_mode".into(), "true".into());
                } else if f.detail.contains("Symfony") {
                    tech_map.insert("framework".into(), "Symfony".into());
                    tech_map.insert("debug_mode".into(), "true".into());
                } else if f.detail.contains("Express") {
                    tech_map.insert("framework".into(), "Express".into());
                    tech_map.insert("debug_mode".into(), "true".into());
                }
            }
            _ => {}
        }
    }

    tech_map
}
