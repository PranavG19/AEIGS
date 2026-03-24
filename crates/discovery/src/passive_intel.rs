use std::collections::HashSet;

use regex::Regex;

/// Categories of passively extracted intelligence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntelCategory {
    LeakedIp,
    ApiKey,
    VersionString,
    InternalPath,
    FrameworkSignature,
    Email,
    S3Bucket,
    DeveloperComment,
    Hostname,
}

impl std::fmt::Display for IntelCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LeakedIp => write!(f, "Leaked IP"),
            Self::ApiKey => write!(f, "API Key"),
            Self::VersionString => write!(f, "Version String"),
            Self::InternalPath => write!(f, "Internal Path"),
            Self::FrameworkSignature => write!(f, "Framework Signature"),
            Self::Email => write!(f, "Email"),
            Self::S3Bucket => write!(f, "S3 Bucket"),
            Self::DeveloperComment => write!(f, "Developer Comment"),
            Self::Hostname => write!(f, "Hostname"),
        }
    }
}

/// A single piece of extracted intelligence.
#[derive(Debug, Clone, PartialEq)]
pub struct IntelItem {
    pub category: IntelCategory,
    pub value: String,
    pub source: String,
    pub confidence: f64,
}

/// Aggregated intelligence from one or more HTTP responses.
#[derive(Debug, Clone, Default)]
pub struct IntelReport {
    pub items: Vec<IntelItem>,
}

impl IntelReport {
    pub fn items_by_category(&self, cat: IntelCategory) -> Vec<&IntelItem> {
        self.items.iter().filter(|i| i.category == cat).collect()
    }

    pub fn merge(&mut self, other: IntelReport) {
        self.items.extend(other.items);
    }
}

/// An HTTP response to analyse (no network call required).
#[derive(Debug, Clone)]
pub struct ResponseData {
    pub url: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// Main entry point: extract all intelligence from a single response.
pub fn extract_intel(response: &ResponseData) -> IntelReport {
    let mut items = Vec::new();

    items.extend(extract_version_strings(&response.headers));
    items.extend(extract_framework_signatures_headers(&response.headers));
    items.extend(extract_leaked_ips(&response.body));
    items.extend(extract_leaked_ips_headers(&response.headers));
    items.extend(extract_hostnames(&response.body));
    items.extend(extract_api_keys(&response.body));
    items.extend(extract_emails(&response.body));
    items.extend(extract_s3_buckets(&response.body));
    items.extend(extract_internal_paths(&response.body));
    items.extend(extract_developer_comments(&response.body));
    items.extend(extract_framework_signatures_body(&response.body));

    let items = deduplicate_items(items);
    IntelReport { items }
}

/// Batch-extract intelligence from multiple responses.
pub fn extract_intel_batch(responses: &[ResponseData]) -> IntelReport {
    let mut report = IntelReport::default();
    for resp in responses {
        report.merge(extract_intel(resp));
    }
    report.items = deduplicate_items(report.items);
    report
}

// ---------------------------------------------------------------------------
// Version strings from headers
// ---------------------------------------------------------------------------

fn extract_version_strings(headers: &[(String, String)]) -> Vec<IntelItem> {
    let version_re = Regex::new(r"[\w./-]+/\d+[\d.]*\w*").unwrap();
    let mut results = Vec::new();

    for (name, value) in headers {
        let key = name.to_lowercase();
        let interesting = matches!(
            key.as_str(),
            "server" | "x-powered-by" | "x-aspnet-version" | "x-aspnetmvc-version" | "x-generator"
        );
        if !interesting {
            continue;
        }
        for m in version_re.find_iter(value) {
            results.push(IntelItem {
                category: IntelCategory::VersionString,
                value: m.as_str().to_string(),
                source: format!("header {name}"),
                confidence: 0.9,
            });
        }
        if key == "x-aspnet-version" || key == "x-aspnetmvc-version" {
            results.push(IntelItem {
                category: IntelCategory::VersionString,
                value: format!("{name}: {value}"),
                source: format!("header {name}"),
                confidence: 0.95,
            });
        }
    }
    results
}

// ---------------------------------------------------------------------------
// Framework signatures from headers (cookie names, specific headers)
// ---------------------------------------------------------------------------

fn extract_framework_signatures_headers(headers: &[(String, String)]) -> Vec<IntelItem> {
    let cookie_sigs: &[(&str, &str)] = &[
        ("PHPSESSID", "PHP"),
        ("JSESSIONID", "Java/Servlet"),
        ("ASP.NET_SessionId", "ASP.NET"),
        ("connect.sid", "Express/Node.js"),
        ("csrftoken", "Django"),
        ("_rails_session", "Ruby on Rails"),
        ("laravel_session", "Laravel"),
        ("ci_session", "CodeIgniter"),
        ("PLAY_SESSION", "Play Framework"),
        ("rack.session", "Rack/Ruby"),
    ];

    let header_sigs: &[(&str, &str, &str)] = &[
        ("x-powered-by", "Express", "Express/Node.js"),
        ("x-powered-by", "PHP", "PHP"),
        ("x-powered-by", "ASP.NET", "ASP.NET"),
        ("x-powered-by", "Next.js", "Next.js"),
        ("x-drupal-cache", "", "Drupal"),
        ("x-drupal-dynamic-cache", "", "Drupal"),
        ("x-generator", "WordPress", "WordPress"),
        ("x-generator", "Drupal", "Drupal"),
        ("x-django-request-id", "", "Django"),
    ];

    let mut results = Vec::new();
    for (name, value) in headers {
        let key = name.to_lowercase();
        if key == "set-cookie" {
            for &(pattern, framework) in cookie_sigs {
                if value.contains(pattern) {
                    results.push(IntelItem {
                        category: IntelCategory::FrameworkSignature,
                        value: framework.to_string(),
                        source: format!("cookie pattern: {pattern}"),
                        confidence: 0.85,
                    });
                }
            }
        }
        for &(hdr, pattern, framework) in header_sigs {
            if key == hdr && (pattern.is_empty() || value.contains(pattern)) {
                results.push(IntelItem {
                    category: IntelCategory::FrameworkSignature,
                    value: framework.to_string(),
                    source: format!("header {name}: {value}"),
                    confidence: 0.9,
                });
            }
        }
    }
    results
}

// ---------------------------------------------------------------------------
// Framework signatures from HTML body
// ---------------------------------------------------------------------------

fn extract_framework_signatures_body(body: &str) -> Vec<IntelItem> {
    let body_sigs: &[(&str, &str)] = &[
        ("wp-content/", "WordPress"),
        ("wp-includes/", "WordPress"),
        ("__NEXT_DATA__", "Next.js"),
        ("/_next/", "Next.js"),
        ("__NUXT__", "Nuxt.js"),
        ("ng-version=", "Angular"),
        ("data-reactroot", "React"),
        ("data-v-", "Vue.js"),
        ("Drupal.settings", "Drupal"),
        ("csrfmiddlewaretoken", "Django"),
        ("laravel_token", "Laravel"),
        ("__RequestVerificationToken", "ASP.NET MVC"),
    ];

    let mut results = Vec::new();
    for &(pattern, framework) in body_sigs {
        if body.contains(pattern) {
            results.push(IntelItem {
                category: IntelCategory::FrameworkSignature,
                value: framework.to_string(),
                source: format!("body pattern: {pattern}"),
                confidence: 0.8,
            });
        }
    }

    let generator_re = Regex::new(
        r#"<meta\s+[^>]*(?:name\s*=\s*["']generator["'][^>]*content\s*=\s*["']([^"']+)["']|content\s*=\s*["']([^"']+)["'][^>]*name\s*=\s*["']generator["'])"#,
    )
    .unwrap();
    for caps in generator_re.captures_iter(body) {
        let content = caps
            .get(1)
            .or_else(|| caps.get(2))
            .map(|m| m.as_str())
            .unwrap_or("");
        if !content.is_empty() {
            results.push(IntelItem {
                category: IntelCategory::FrameworkSignature,
                value: content.to_string(),
                source: "meta generator tag".to_string(),
                confidence: 0.9,
            });
        }
    }
    results
}

// ---------------------------------------------------------------------------
// Leaked private/internal IPs
// ---------------------------------------------------------------------------

fn extract_leaked_ips(body: &str) -> Vec<IntelItem> {
    let ip_re = Regex::new(
        r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
    )
    .unwrap();
    let mut results = Vec::new();
    let mut seen = HashSet::new();
    for m in ip_re.find_iter(body) {
        let ip = m.as_str().to_string();
        if seen.insert(ip.clone()) {
            results.push(IntelItem {
                category: IntelCategory::LeakedIp,
                value: ip,
                source: "response body".to_string(),
                confidence: 0.85,
            });
        }
    }
    results
}

fn extract_leaked_ips_headers(headers: &[(String, String)]) -> Vec<IntelItem> {
    let ip_re = Regex::new(
        r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
    )
    .unwrap();
    let mut results = Vec::new();
    for (name, value) in headers {
        for m in ip_re.find_iter(value) {
            results.push(IntelItem {
                category: IntelCategory::LeakedIp,
                value: m.as_str().to_string(),
                source: format!("header {name}"),
                confidence: 0.9,
            });
        }
    }
    results
}

// ---------------------------------------------------------------------------
// Internal hostnames
// ---------------------------------------------------------------------------

fn extract_hostnames(body: &str) -> Vec<IntelItem> {
    let hostname_re = Regex::new(
        r"\b([a-zA-Z][a-zA-Z0-9-]*\.(?:internal|local|corp|lan|intra|priv|dev|staging|test))\b",
    )
    .unwrap();
    let mut results = Vec::new();
    let mut seen = HashSet::new();
    for m in hostname_re.find_iter(body) {
        let host = m.as_str().to_string();
        if seen.insert(host.clone()) {
            results.push(IntelItem {
                category: IntelCategory::Hostname,
                value: host,
                source: "response body".to_string(),
                confidence: 0.8,
            });
        }
    }
    results
}

// ---------------------------------------------------------------------------
// API keys and tokens
// ---------------------------------------------------------------------------

fn extract_api_keys(body: &str) -> Vec<IntelItem> {
    let patterns: &[(&str, &str)] = &[
        (
            r#"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["']?([a-zA-Z0-9_\-]{20,})"#,
            "Generic API key",
        ),
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
        (
            r#"(?i)(?:aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9/+=]{30,})"#,
            "AWS Secret Key",
        ),
        (r"sk-[a-zA-Z0-9]{20,}", "OpenAI/Stripe Secret Key"),
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
        (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth Token"),
        (r"glpat-[a-zA-Z0-9\-_]{20,}", "GitLab Personal Access Token"),
        (r"(?i)(?:Bearer\s+)([a-zA-Z0-9\-_.~+/]+=*)", "Bearer Token"),
        (
            r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_.+/=]+",
            "JWT",
        ),
        (r"xox[bprs]-[0-9a-zA-Z\-]{10,}", "Slack Token"),
        (
            r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
            "SendGrid API Key",
        ),
        (r"sq0atp-[0-9A-Za-z\-_]{22}", "Square Access Token"),
        (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
    ];

    let mut results = Vec::new();
    let mut seen = HashSet::new();
    for &(pat, label) in patterns {
        let re = Regex::new(pat).unwrap();
        for caps in re.captures_iter(body) {
            let matched = caps.get(1).unwrap_or_else(|| caps.get(0).unwrap());
            let val = matched.as_str().to_string();
            if seen.insert(val.clone()) {
                results.push(IntelItem {
                    category: IntelCategory::ApiKey,
                    value: val,
                    source: format!("pattern: {label}"),
                    confidence: 0.9,
                });
            }
        }
    }
    results
}

// ---------------------------------------------------------------------------
// Email addresses
// ---------------------------------------------------------------------------

fn extract_emails(body: &str) -> Vec<IntelItem> {
    let email_re = Regex::new(r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b").unwrap();
    let mut results = Vec::new();
    let mut seen = HashSet::new();

    let ignore_exts = [".png", ".jpg", ".gif", ".svg", ".css", ".js", ".woff"];
    for m in email_re.find_iter(body) {
        let email = m.as_str().to_string();
        let lower = email.to_lowercase();
        if ignore_exts.iter().any(|ext| lower.ends_with(ext)) {
            continue;
        }
        if lower.ends_with("@example.com") || lower.ends_with("@test.com") {
            continue;
        }
        if seen.insert(lower) {
            results.push(IntelItem {
                category: IntelCategory::Email,
                value: email,
                source: "response body".to_string(),
                confidence: 0.85,
            });
        }
    }
    results
}

// ---------------------------------------------------------------------------
// S3 bucket references
// ---------------------------------------------------------------------------

fn extract_s3_buckets(body: &str) -> Vec<IntelItem> {
    let patterns = [
        Regex::new(r"(?i)([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3[.\-](?:[\w-]+\.)?amazonaws\.com").unwrap(),
        Regex::new(r"(?i)s3://([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])").unwrap(),
        Regex::new(r"(?i)(?:https?://)?s3[.\-](?:[\w-]+\.)?amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])").unwrap(),
        Regex::new(r#"(?i)(?:arn:aws:s3:::)([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])"#).unwrap(),
    ];

    let mut results = Vec::new();
    let mut seen = HashSet::new();
    for re in &patterns {
        for caps in re.captures_iter(body) {
            let bucket = caps
                .get(1)
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            if !bucket.is_empty() && seen.insert(bucket.clone()) {
                results.push(IntelItem {
                    category: IntelCategory::S3Bucket,
                    value: bucket,
                    source: "response body".to_string(),
                    confidence: 0.9,
                });
            }
        }
    }
    results
}

// ---------------------------------------------------------------------------
// Internal path disclosures (stack traces, error messages)
// ---------------------------------------------------------------------------

fn extract_internal_paths(body: &str) -> Vec<IntelItem> {
    let path_patterns = [
        Regex::new(r"(?:(?:/(?:home|var|usr|opt|srv|etc|app|tmp|data)/[\w./-]{5,})|(?:[A-Z]:\\[\w\\./-]{5,}))").unwrap(),
        Regex::new(r#"(?:File\s+"([^"]+\.py)",\s+line\s+\d+)"#).unwrap(),
        Regex::new(r"(?:at\s+[\w.$]+\((/[\w./-]+\.(?:java|kt|scala)):\d+\))").unwrap(),
        Regex::new(r"(?:in\s+(/[\w./-]+\.php)\s+on\s+line\s+\d+)").unwrap(),
        Regex::new(r"(?:at\s+(/[\w./-]+\.rb):\d+)").unwrap(),
        Regex::new(r"(?:at\s+[\w.$<>]+\s*\((/[\w./-]+\.(?:cs|vb)):\d+\))").unwrap(),
    ];

    let mut results = Vec::new();
    let mut seen = HashSet::new();
    for re in &path_patterns {
        for caps in re.captures_iter(body) {
            let path = caps
                .get(1)
                .unwrap_or_else(|| caps.get(0).unwrap())
                .as_str()
                .to_string();
            if seen.insert(path.clone()) {
                results.push(IntelItem {
                    category: IntelCategory::InternalPath,
                    value: path,
                    source: "response body".to_string(),
                    confidence: 0.85,
                });
            }
        }
    }
    results
}

// ---------------------------------------------------------------------------
// Developer comments in HTML
// ---------------------------------------------------------------------------

fn extract_developer_comments(body: &str) -> Vec<IntelItem> {
    let comment_re = Regex::new(r"<!--\s*(.*?)\s*-->").unwrap();

    let boring = [
        "endif", "[if ", "begin", "end ", "<![", "google", "schema", "noindex",
    ];

    let interesting_keywords = [
        "todo",
        "fixme",
        "hack",
        "bug",
        "xxx",
        "temp",
        "password",
        "secret",
        "credential",
        "debug",
        "admin",
        "internal",
        "deprecated",
        "remove",
        "workaround",
        "insecure",
        "unsafe",
        "vulnerability",
        "leak",
    ];

    let mut results = Vec::new();
    for caps in comment_re.captures_iter(body) {
        let content = caps[1].trim();
        if content.len() < 4 || content.len() > 1000 {
            continue;
        }
        let lower = content.to_lowercase();
        if boring.iter().any(|b| lower.starts_with(b)) {
            continue;
        }
        let is_interesting = interesting_keywords.iter().any(|kw| lower.contains(kw));
        if is_interesting {
            results.push(IntelItem {
                category: IntelCategory::DeveloperComment,
                value: content.to_string(),
                source: "HTML comment".to_string(),
                confidence: 0.75,
            });
        }
    }
    results
}

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

fn deduplicate_items(items: Vec<IntelItem>) -> Vec<IntelItem> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for item in items {
        let key = format!("{:?}::{}", item.category, item.value);
        if seen.insert(key) {
            result.push(item);
        }
    }
    result
}
