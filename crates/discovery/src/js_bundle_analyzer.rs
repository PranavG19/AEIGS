/// Deep analysis of JavaScript bundles for security intelligence.
///
/// Covers: webpack chunk enumeration, source map discovery, API endpoint
/// extraction from fetch/axios calls, hardcoded secrets/tokens, admin/debug
/// routes in client-side routing, environment variable leakage (process.env).
use regex::Regex;
use std::collections::HashSet;
use std::fmt;

/// Category of a JS bundle finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JsBundleFindingCategory {
    ApiEndpoint,
    HardcodedSecret,
    SourceMapExposed,
    WebpackChunk,
    AdminRoute,
    DebugRoute,
    EnvVariableLeak,
    InternalUrl,
    CloudConfig,
    AuthBypass,
}

impl fmt::Display for JsBundleFindingCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiEndpoint => write!(f, "API Endpoint"),
            Self::HardcodedSecret => write!(f, "Hardcoded Secret"),
            Self::SourceMapExposed => write!(f, "Source Map Exposed"),
            Self::WebpackChunk => write!(f, "Webpack Chunk"),
            Self::AdminRoute => write!(f, "Admin Route"),
            Self::DebugRoute => write!(f, "Debug Route"),
            Self::EnvVariableLeak => write!(f, "Environment Variable Leak"),
            Self::InternalUrl => write!(f, "Internal URL"),
            Self::CloudConfig => write!(f, "Cloud Configuration"),
            Self::AuthBypass => write!(f, "Auth Bypass Hint"),
        }
    }
}

/// Severity of a JS bundle finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JsBundleSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for JsBundleSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// A single finding from JS bundle analysis.
#[derive(Debug, Clone)]
pub struct JsBundleFinding {
    pub category: JsBundleFindingCategory,
    pub severity: JsBundleSeverity,
    pub description: String,
    pub evidence: String,
    pub source_file: String,
    pub line_number: Option<usize>,
}

/// An API endpoint extracted from JavaScript.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExtractedEndpoint {
    pub url: String,
    pub method: Option<String>,
    pub source_context: String,
}

/// A webpack chunk reference.
#[derive(Debug, Clone)]
pub struct WebpackChunk {
    pub chunk_id: String,
    pub filename: String,
    pub is_lazy: bool,
}

/// A source map reference found in a JS bundle.
#[derive(Debug, Clone)]
pub struct SourceMapRef {
    pub js_file: String,
    pub map_url: String,
}

/// Result of JS bundle analysis.
#[derive(Debug, Clone)]
pub struct JsBundleAnalysisResult {
    pub source_file: String,
    pub findings: Vec<JsBundleFinding>,
    pub endpoints: Vec<ExtractedEndpoint>,
    pub webpack_chunks: Vec<WebpackChunk>,
    pub source_maps: Vec<SourceMapRef>,
    pub env_variables: Vec<String>,
    pub routes: Vec<String>,
}

/// Compiled regex patterns for extraction. Built once and reused.
struct BundlePatterns {
    fetch_call: Regex,
    axios_call: Regex,
    xhr_open: Regex,
    api_string: Regex,
    source_map_comment: Regex,
    #[allow(dead_code)]
    source_map_header: Regex,
    webpack_chunk: Regex,
    webpack_jsonp: Regex,
    process_env: Regex,
    route_path: Regex,
    react_router: Regex,
    vue_router: Regex,
    aws_key: Regex,
    stripe_key: Regex,
    github_token: Regex,
    jwt_token: Regex,
    private_key: Regex,
    generic_secret: Regex,
    db_connection: Regex,
    internal_url: Regex,
    firebase_config: Regex,
    gcp_key: Regex,
    auth_bypass: Regex,
}

impl BundlePatterns {
    fn new() -> Self {
        Self {
            fetch_call: Regex::new(r#"fetch\s*\(\s*["'`]([^"'`]+)["'`]"#).unwrap(),
            axios_call: Regex::new(r#"axios\s*\.\s*(get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]+)["'`]"#).unwrap(),
            xhr_open: Regex::new(r#"\.open\s*\(\s*["'](GET|POST|PUT|DELETE|PATCH)["']\s*,\s*["']([^"']+)["']"#).unwrap(),
            api_string: Regex::new(r#"["'`](/api/[^"'`\s]{2,})["'`]"#).unwrap(),
            source_map_comment: Regex::new(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)").unwrap(),
            source_map_header: Regex::new(r#"[Ss]ource[Mm]ap:\s*(\S+)"#).unwrap(),
            webpack_chunk: Regex::new(r#"["']([a-zA-Z0-9_-]+)\s*["']\s*:\s*["']([a-f0-9]{6,20})["']"#).unwrap(),
            webpack_jsonp: Regex::new(r#"webpackJsonp|__webpack_require__"#).unwrap(),
            process_env: Regex::new(r#"process\.env\.([A-Z_][A-Z0-9_]*)"#).unwrap(),
            route_path: Regex::new(r#"(?:path|route)\s*:\s*["'`](/[^"'`\s]{1,100})["'`]"#).unwrap(),
            react_router: Regex::new(r#"<Route\s+[^>]*path\s*=\s*["']([^"']+)["']"#).unwrap(),
            vue_router: Regex::new(r#"path\s*:\s*["'](/[^"']*?)["']"#).unwrap(),
            aws_key: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            stripe_key: Regex::new(r"sk_live_[0-9a-zA-Z]{24,}").unwrap(),
            github_token: Regex::new(r"gh[ps]_[0-9a-zA-Z]{36}").unwrap(),
            jwt_token: Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]+").unwrap(),
            private_key: Regex::new(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----").unwrap(),
            generic_secret: Regex::new(r#"(?i)(?:api_?key|secret_?key|auth_?token|access_?token|password)\s*[=:]\s*["']([^"']{8,})["']"#).unwrap(),
            db_connection: Regex::new(r#"(?:postgres|mysql|mongodb|redis)://[^\s"'<>]{8,}"#).unwrap(),
            internal_url: Regex::new(r#"https?://[a-zA-Z0-9._-]+\.(?:internal|local|corp|intranet)(?:[:/][^\s"'<>]*)?"#).unwrap(),
            firebase_config: Regex::new(r#"(?:firebase|firebaseio)\.com"#).unwrap(),
            gcp_key: Regex::new(r"AIza[0-9A-Za-z\-_]{35}").unwrap(),
            auth_bypass: Regex::new(r#"(?i)(?:isAdmin|is_admin|isAuthenticated|skipAuth|bypassAuth|devMode|debugMode)\s*[=:]\s*(true|false|1|0)"#).unwrap(),
        }
    }
}

/// Analyzes JavaScript bundle content for security-relevant information.
pub struct JsBundleAnalyzer {
    patterns: BundlePatterns,
}

impl JsBundleAnalyzer {
    pub fn new() -> Self {
        Self {
            patterns: BundlePatterns::new(),
        }
    }

    /// Analyze a single JS bundle file.
    pub fn analyze(&self, filename: &str, content: &str) -> JsBundleAnalysisResult {
        let mut findings = Vec::new();
        let mut endpoints = HashSet::new();
        let mut webpack_chunks = Vec::new();
        let mut source_maps = Vec::new();
        let mut env_variables = Vec::new();
        let mut routes = HashSet::new();

        self.extract_api_endpoints(filename, content, &mut findings, &mut endpoints);
        self.extract_secrets(filename, content, &mut findings);
        self.extract_source_maps(filename, content, &mut findings, &mut source_maps);
        self.extract_webpack_chunks(filename, content, &mut findings, &mut webpack_chunks);
        self.extract_env_variables(filename, content, &mut findings, &mut env_variables);
        self.extract_routes(filename, content, &mut findings, &mut routes);
        self.extract_internal_urls(filename, content, &mut findings);
        self.extract_cloud_configs(filename, content, &mut findings);
        self.extract_auth_bypasses(filename, content, &mut findings);

        JsBundleAnalysisResult {
            source_file: filename.to_string(),
            findings,
            endpoints: endpoints.into_iter().collect(),
            webpack_chunks,
            source_maps,
            env_variables,
            routes: routes.into_iter().collect(),
        }
    }

    fn extract_api_endpoints(
        &self,
        filename: &str,
        content: &str,
        findings: &mut Vec<JsBundleFinding>,
        endpoints: &mut HashSet<ExtractedEndpoint>,
    ) {
        for (line_idx, line) in content.lines().enumerate() {
            for caps in self.patterns.fetch_call.captures_iter(line) {
                let url = caps[1].to_string();
                endpoints.insert(ExtractedEndpoint {
                    url: url.clone(),
                    method: Some("GET".into()),
                    source_context: "fetch()".into(),
                });
                findings.push(JsBundleFinding {
                    category: JsBundleFindingCategory::ApiEndpoint,
                    severity: JsBundleSeverity::Info,
                    description: format!("API endpoint found in fetch() call: {}", url),
                    evidence: truncate_line(line, 200),
                    source_file: filename.into(),
                    line_number: Some(line_idx + 1),
                });
            }

            for caps in self.patterns.axios_call.captures_iter(line) {
                let method = caps[1].to_uppercase();
                let url = caps[2].to_string();
                endpoints.insert(ExtractedEndpoint {
                    url: url.clone(),
                    method: Some(method.clone()),
                    source_context: format!("axios.{}()", method.to_lowercase()),
                });
                findings.push(JsBundleFinding {
                    category: JsBundleFindingCategory::ApiEndpoint,
                    severity: JsBundleSeverity::Info,
                    description: format!(
                        "API endpoint found in axios.{}(): {}",
                        method.to_lowercase(),
                        url
                    ),
                    evidence: truncate_line(line, 200),
                    source_file: filename.into(),
                    line_number: Some(line_idx + 1),
                });
            }

            for caps in self.patterns.xhr_open.captures_iter(line) {
                let method = caps[1].to_string();
                let url = caps[2].to_string();
                endpoints.insert(ExtractedEndpoint {
                    url: url.clone(),
                    method: Some(method.clone()),
                    source_context: "XMLHttpRequest.open()".into(),
                });
            }

            for caps in self.patterns.api_string.captures_iter(line) {
                let url = caps[1].to_string();
                endpoints.insert(ExtractedEndpoint {
                    url: url.clone(),
                    method: None,
                    source_context: "string literal".into(),
                });
            }
        }
    }

    fn extract_secrets(&self, filename: &str, content: &str, findings: &mut Vec<JsBundleFinding>) {
        for (line_idx, line) in content.lines().enumerate() {
            if self.patterns.aws_key.is_match(line) {
                findings.push(JsBundleFinding {
                    category: JsBundleFindingCategory::HardcodedSecret,
                    severity: JsBundleSeverity::Critical,
                    description: "AWS Access Key ID found in JavaScript bundle".into(),
                    evidence: truncate_line(line, 120),
                    source_file: filename.into(),
                    line_number: Some(line_idx + 1),
                });
            }

            if self.patterns.stripe_key.is_match(line) {
                findings.push(JsBundleFinding {
                    category: JsBundleFindingCategory::HardcodedSecret,
                    severity: JsBundleSeverity::Critical,
                    description: "Stripe secret key found in JavaScript bundle".into(),
                    evidence: truncate_line(line, 120),
                    source_file: filename.into(),
                    line_number: Some(line_idx + 1),
                });
            }

            if self.patterns.github_token.is_match(line) {
                findings.push(JsBundleFinding {
                    category: JsBundleFindingCategory::HardcodedSecret,
                    severity: JsBundleSeverity::Critical,
                    description: "GitHub token found in JavaScript bundle".into(),
                    evidence: truncate_line(line, 120),
                    source_file: filename.into(),
                    line_number: Some(line_idx + 1),
                });
            }

            if self.patterns.private_key.is_match(line) {
                findings.push(JsBundleFinding {
                    category: JsBundleFindingCategory::HardcodedSecret,
                    severity: JsBundleSeverity::Critical,
                    description: "Private key found in JavaScript bundle".into(),
                    evidence: truncate_line(line, 120),
                    source_file: filename.into(),
                    line_number: Some(line_idx + 1),
                });
            }

            if self.patterns.db_connection.is_match(line) {
                findings.push(JsBundleFinding {
                    category: JsBundleFindingCategory::HardcodedSecret,
                    severity: JsBundleSeverity::Critical,
                    description: "Database connection string found in JavaScript bundle".into(),
                    evidence: truncate_line(line, 120),
                    source_file: filename.into(),
                    line_number: Some(line_idx + 1),
                });
            }

            if self.patterns.jwt_token.is_match(line) {
                findings.push(JsBundleFinding {
                    category: JsBundleFindingCategory::HardcodedSecret,
                    severity: JsBundleSeverity::High,
                    description: "JWT token found hardcoded in JavaScript bundle".into(),
                    evidence: truncate_line(line, 120),
                    source_file: filename.into(),
                    line_number: Some(line_idx + 1),
                });
            }

            for caps in self.patterns.generic_secret.captures_iter(line) {
                let secret_val = &caps[1];
                if !is_placeholder(secret_val) {
                    findings.push(JsBundleFinding {
                        category: JsBundleFindingCategory::HardcodedSecret,
                        severity: JsBundleSeverity::High,
                        description: "Hardcoded secret/token found in JavaScript bundle".into(),
                        evidence: truncate_line(line, 120),
                        source_file: filename.into(),
                        line_number: Some(line_idx + 1),
                    });
                }
            }
        }
    }

    fn extract_source_maps(
        &self,
        filename: &str,
        content: &str,
        findings: &mut Vec<JsBundleFinding>,
        source_maps: &mut Vec<SourceMapRef>,
    ) {
        for caps in self.patterns.source_map_comment.captures_iter(content) {
            let map_url = caps[1].to_string();
            source_maps.push(SourceMapRef {
                js_file: filename.into(),
                map_url: map_url.clone(),
            });
            findings.push(JsBundleFinding {
                category: JsBundleFindingCategory::SourceMapExposed,
                severity: JsBundleSeverity::High,
                description: format!("Source map reference found: {}", map_url),
                evidence:
                    "Source maps expose original source code including comments and variable names"
                        .into(),
                source_file: filename.into(),
                line_number: None,
            });
        }
    }

    fn extract_webpack_chunks(
        &self,
        filename: &str,
        content: &str,
        findings: &mut Vec<JsBundleFinding>,
        chunks: &mut Vec<WebpackChunk>,
    ) {
        if !self.patterns.webpack_jsonp.is_match(content) {
            return;
        }

        let mut seen: HashSet<String> = HashSet::new();
        for caps in self.patterns.webpack_chunk.captures_iter(content) {
            let chunk_id = caps[1].to_string();
            let hash = caps[2].to_string();
            if seen.insert(chunk_id.clone()) {
                chunks.push(WebpackChunk {
                    chunk_id: chunk_id.clone(),
                    filename: format!("{}.{}.js", chunk_id, hash),
                    is_lazy: true,
                });
            }
        }

        if !chunks.is_empty() {
            findings.push(JsBundleFinding {
                category: JsBundleFindingCategory::WebpackChunk,
                severity: JsBundleSeverity::Low,
                description: format!(
                    "{} webpack chunks discovered — additional JS bundles to analyze",
                    chunks.len()
                ),
                evidence: chunks
                    .iter()
                    .map(|c| c.filename.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                source_file: filename.into(),
                line_number: None,
            });
        }
    }

    fn extract_env_variables(
        &self,
        filename: &str,
        content: &str,
        findings: &mut Vec<JsBundleFinding>,
        env_vars: &mut Vec<String>,
    ) {
        let mut seen: HashSet<String> = HashSet::new();
        for (line_idx, line) in content.lines().enumerate() {
            for caps in self.patterns.process_env.captures_iter(line) {
                let var_name = caps[1].to_string();
                if seen.insert(var_name.clone()) {
                    let severity = classify_env_severity(&var_name);
                    env_vars.push(var_name.clone());
                    findings.push(JsBundleFinding {
                        category: JsBundleFindingCategory::EnvVariableLeak,
                        severity,
                        description: format!(
                            "Environment variable process.env.{} referenced in bundle",
                            var_name
                        ),
                        evidence: truncate_line(line, 200),
                        source_file: filename.into(),
                        line_number: Some(line_idx + 1),
                    });
                }
            }
        }
    }

    fn extract_routes(
        &self,
        filename: &str,
        content: &str,
        findings: &mut Vec<JsBundleFinding>,
        routes: &mut HashSet<String>,
    ) {
        let route_patterns = [
            &self.patterns.route_path,
            &self.patterns.react_router,
            &self.patterns.vue_router,
        ];

        for pattern in &route_patterns {
            for caps in pattern.captures_iter(content) {
                let path = caps[1].to_string();
                if routes.insert(path.clone()) {
                    let (category, severity) = classify_route(&path);
                    findings.push(JsBundleFinding {
                        category,
                        severity,
                        description: format!("Client-side route discovered: {}", path),
                        evidence: "Found in routing configuration".into(),
                        source_file: filename.into(),
                        line_number: None,
                    });
                }
            }
        }
    }

    fn extract_internal_urls(
        &self,
        filename: &str,
        content: &str,
        findings: &mut Vec<JsBundleFinding>,
    ) {
        for (line_idx, line) in content.lines().enumerate() {
            for mat in self.patterns.internal_url.find_iter(line) {
                findings.push(JsBundleFinding {
                    category: JsBundleFindingCategory::InternalUrl,
                    severity: JsBundleSeverity::Medium,
                    description: format!("Internal URL leaked in JS bundle: {}", mat.as_str()),
                    evidence: truncate_line(line, 200),
                    source_file: filename.into(),
                    line_number: Some(line_idx + 1),
                });
            }
        }
    }

    fn extract_cloud_configs(
        &self,
        filename: &str,
        content: &str,
        findings: &mut Vec<JsBundleFinding>,
    ) {
        if self.patterns.firebase_config.is_match(content) {
            findings.push(JsBundleFinding {
                category: JsBundleFindingCategory::CloudConfig,
                severity: JsBundleSeverity::Medium,
                description: "Firebase configuration found in JS bundle".into(),
                evidence: "Firebase project references detected".into(),
                source_file: filename.into(),
                line_number: None,
            });
        }

        for (line_idx, line) in content.lines().enumerate() {
            if self.patterns.gcp_key.is_match(line) {
                findings.push(JsBundleFinding {
                    category: JsBundleFindingCategory::CloudConfig,
                    severity: JsBundleSeverity::High,
                    description: "GCP API key found in JS bundle".into(),
                    evidence: truncate_line(line, 120),
                    source_file: filename.into(),
                    line_number: Some(line_idx + 1),
                });
            }
        }
    }

    fn extract_auth_bypasses(
        &self,
        filename: &str,
        content: &str,
        findings: &mut Vec<JsBundleFinding>,
    ) {
        for (line_idx, line) in content.lines().enumerate() {
            for caps in self.patterns.auth_bypass.captures_iter(line) {
                findings.push(JsBundleFinding {
                    category: JsBundleFindingCategory::AuthBypass,
                    severity: JsBundleSeverity::Medium,
                    description: format!(
                        "Client-side auth/debug flag found: {}",
                        truncate_line(&caps[0], 80)
                    ),
                    evidence: truncate_line(line, 200),
                    source_file: filename.into(),
                    line_number: Some(line_idx + 1),
                });
            }
        }
    }
}

impl Default for JsBundleAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

fn truncate_line(line: &str, max_len: usize) -> String {
    if line.len() <= max_len {
        line.to_string()
    } else {
        format!("{}...", &line[..max_len])
    }
}

fn is_placeholder(value: &str) -> bool {
    let lower = value.to_lowercase();
    let placeholders = [
        "your_",
        "example",
        "placeholder",
        "changeme",
        "replace",
        "xxxx",
        "todo",
        "insert",
        "fake",
        "dummy",
        "test_",
        "sample",
        "change_me",
    ];
    placeholders.iter().any(|p| lower.contains(p))
}

fn classify_env_severity(var_name: &str) -> JsBundleSeverity {
    let upper = var_name.to_uppercase();
    if upper.contains("SECRET") || upper.contains("PASSWORD") || upper.contains("PRIVATE") {
        JsBundleSeverity::Critical
    } else if upper.contains("API_KEY") || upper.contains("TOKEN") || upper.contains("DATABASE") {
        JsBundleSeverity::High
    } else if upper == "NODE_ENV" || upper.contains("DEBUG") || upper.contains("LOG") {
        JsBundleSeverity::Low
    } else {
        JsBundleSeverity::Medium
    }
}

fn classify_route(path: &str) -> (JsBundleFindingCategory, JsBundleSeverity) {
    let lower = path.to_lowercase();
    let admin_keywords = [
        "admin",
        "dashboard",
        "manage",
        "internal",
        "staff",
        "control",
    ];
    let debug_keywords = ["debug", "test", "dev", "staging", "sandbox"];

    if admin_keywords.iter().any(|kw| lower.contains(kw)) {
        (
            JsBundleFindingCategory::AdminRoute,
            JsBundleSeverity::Medium,
        )
    } else if debug_keywords.iter().any(|kw| lower.contains(kw)) {
        (
            JsBundleFindingCategory::DebugRoute,
            JsBundleSeverity::Medium,
        )
    } else {
        (JsBundleFindingCategory::ApiEndpoint, JsBundleSeverity::Info)
    }
}
