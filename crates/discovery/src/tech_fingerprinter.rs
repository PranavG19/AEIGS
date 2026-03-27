use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use regex::Regex;
use reqwest::blocking::Client;
use url::Url;

use aegis_protocol::target_validation::validate_target_is_localhost;

use crate::discovery_client::{DefaultDiscoveryClient, DiscoveryHttpClient};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Aggregated technology fingerprint for a target, containing all detected technologies.
#[derive(Debug, Clone, PartialEq)]
pub struct TechFingerprint {
    pub technologies: Vec<DetectedTech>,
}

/// A single technology detected on the target, with version and confidence.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectedTech {
    pub name: String,
    pub version: Option<String>,
    pub category: TechCategory,
    pub confidence: f64,
    pub evidence: String,
}

/// Broad category of a detected technology (server, framework, CMS, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TechCategory {
    WebServer,
    Framework,
    Cms,
    ProgrammingLanguage,
    JavaScript,
    Cdn,
    Analytics,
    Security,
}

impl std::fmt::Display for TechCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WebServer => write!(f, "Web Server"),
            Self::Framework => write!(f, "Framework"),
            Self::Cms => write!(f, "CMS"),
            Self::ProgrammingLanguage => write!(f, "Programming Language"),
            Self::JavaScript => write!(f, "JavaScript"),
            Self::Cdn => write!(f, "CDN"),
            Self::Analytics => write!(f, "Analytics"),
            Self::Security => write!(f, "Security"),
        }
    }
}

/// Errors that can occur during technology fingerprinting.
#[derive(Debug)]
pub enum FingerprintError {
    InvalidUrl(String),
    NonLocalhostTarget(String),
    HttpError(String),
}

impl std::fmt::Display for FingerprintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl(url) => write!(f, "invalid URL: {url}"),
            Self::NonLocalhostTarget(url) => write!(f, "non-localhost target: {url}"),
            Self::HttpError(msg) => write!(f, "HTTP error: {msg}"),
        }
    }
}

impl std::error::Error for FingerprintError {}

/// Identifies server software, frameworks, and client-side libraries on a target.
///
/// Combines HTTP header analysis, HTML meta/content patterns, and known-path probing.
/// Deduplicates results by technology name, keeping the highest-confidence detection.
pub struct TechFingerprinter {
    client: Client,
    evasion_client: Option<Arc<dyn DiscoveryHttpClient>>,
}

impl std::fmt::Debug for TechFingerprinter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TechFingerprinter")
            .field("uses_evasion_client", &self.evasion_client.is_some())
            .finish()
    }
}

impl TechFingerprinter {
    pub fn new() -> Result<Self, FingerprintError> {
        let client = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| FingerprintError::HttpError(e.to_string()))?;

        Ok(Self {
            client,
            evasion_client: None,
        })
    }

    /// Attach an evasion-aware HTTP client for stealth scanning.
    /// When set, all HTTP requests route through this client instead
    /// of the built-in bare reqwest client.
    pub fn with_evasion_client(mut self, client: Arc<dyn DiscoveryHttpClient>) -> Self {
        self.evasion_client = Some(client);
        self
    }

    pub fn fingerprint(&self, target: &str) -> Result<TechFingerprint, FingerprintError> {
        let base = validate_and_normalize(target)?;
        let mut all_techs = Vec::new();

        if let Ok(resp) = self.client.get(&base).send() {
            let headers: Vec<(String, String)> = resp
                .headers()
                .iter()
                .map(|(k, v)| {
                    (
                        k.as_str().to_lowercase(),
                        v.to_str().unwrap_or("").to_string(),
                    )
                })
                .collect();
            all_techs.extend(fingerprint_from_headers(&headers));

            if let Ok(body) = resp.text() {
                all_techs.extend(fingerprint_from_html(&body));
            }
        }

        all_techs.extend(self.fingerprint_from_paths(&base));

        Ok(TechFingerprint {
            technologies: deduplicate(all_techs),
        })
    }

    fn fingerprint_from_paths(&self, base_url: &str) -> Vec<DetectedTech> {
        let mut results = Vec::new();
        for probe in PATH_PROBES {
            let url = format!("{base_url}{}", probe.path);
            if let Ok(resp) = self.client.get(&url).send()
                && resp.status().as_u16() == 200
            {
                results.push(DetectedTech {
                    name: probe.name.to_string(),
                    version: None,
                    category: probe.category,
                    confidence: 0.7,
                    evidence: format!("path {} returned 200", probe.path),
                });
            }
        }
        results
    }
}

pub(crate) struct PathProbe {
    pub(crate) path: &'static str,
    pub(crate) name: &'static str,
    pub(crate) category: TechCategory,
}

pub(crate) const PATH_PROBES: &[PathProbe] = &[
    PathProbe {
        path: "/wp-admin/",
        name: "WordPress",
        category: TechCategory::Cms,
    },
    PathProbe {
        path: "/wp-login.php",
        name: "WordPress",
        category: TechCategory::Cms,
    },
    PathProbe {
        path: "/administrator/",
        name: "Joomla",
        category: TechCategory::Cms,
    },
    PathProbe {
        path: "/user/login",
        name: "Drupal",
        category: TechCategory::Cms,
    },
    PathProbe {
        path: "/rails/info/properties",
        name: "Ruby on Rails",
        category: TechCategory::Framework,
    },
    PathProbe {
        path: "/actuator/info",
        name: "Spring Boot",
        category: TechCategory::Framework,
    },
    PathProbe {
        path: "/__debug__/",
        name: "Django",
        category: TechCategory::Framework,
    },
    PathProbe {
        path: "/telescope",
        name: "Laravel",
        category: TechCategory::Framework,
    },
    PathProbe {
        path: "/elmah.axd",
        name: "ASP.NET",
        category: TechCategory::Framework,
    },
    PathProbe {
        path: "/server-status",
        name: "Apache",
        category: TechCategory::WebServer,
    },
];

pub fn fingerprint_from_headers(headers: &[(String, String)]) -> Vec<DetectedTech> {
    let mut results = Vec::new();

    for (name, value) in headers {
        match name.as_str() {
            "server" => results.extend(detect_server_header(value)),
            "x-powered-by" => results.extend(detect_powered_by(value)),
            "x-generator" => results.extend(detect_generator_header(value)),
            "x-aspnet-version" => results.push(DetectedTech {
                name: "ASP.NET".to_string(),
                version: Some(value.trim().to_string()),
                category: TechCategory::Framework,
                confidence: 0.95,
                evidence: format!("X-AspNet-Version: {value}"),
            }),
            "x-aspnetmvc-version" => results.push(DetectedTech {
                name: "ASP.NET MVC".to_string(),
                version: Some(value.trim().to_string()),
                category: TechCategory::Framework,
                confidence: 0.95,
                evidence: format!("X-AspNetMvc-Version: {value}"),
            }),
            "set-cookie" => results.extend(detect_session_cookies(value)),
            _ => {}
        }
    }

    results
}

fn detect_server_header(value: &str) -> Vec<DetectedTech> {
    let servers: &[(&str, &str, TechCategory)] = &[
        ("Apache", "Apache", TechCategory::WebServer),
        ("nginx", "nginx", TechCategory::WebServer),
        ("Microsoft-IIS", "IIS", TechCategory::WebServer),
        ("Caddy", "Caddy", TechCategory::WebServer),
        ("LiteSpeed", "LiteSpeed", TechCategory::WebServer),
    ];

    let mut results = Vec::new();
    for &(pattern, name, category) in servers {
        if value.contains(pattern) {
            let version = extract_version_after_slash(value, pattern);
            results.push(DetectedTech {
                name: name.to_string(),
                version,
                category,
                confidence: 0.9,
                evidence: format!("Server: {value}"),
            });
        }
    }
    results
}

fn extract_version_after_slash(header: &str, server_name: &str) -> Option<String> {
    let start = header.find(server_name)? + server_name.len();
    let rest = &header[start..];
    if let Some(version_str) = rest.strip_prefix('/') {
        let end = version_str
            .find([' ', '(', ','])
            .unwrap_or(version_str.len());
        let version = &version_str[..end];
        if !version.is_empty() {
            return Some(version.to_string());
        }
    }
    None
}

fn detect_powered_by(value: &str) -> Vec<DetectedTech> {
    let frameworks: &[(&str, &str, TechCategory)] = &[
        ("Express", "Express", TechCategory::Framework),
        ("PHP", "PHP", TechCategory::ProgrammingLanguage),
        ("ASP.NET", "ASP.NET", TechCategory::Framework),
        ("Next.js", "Next.js", TechCategory::Framework),
        ("Nuxt.js", "Nuxt.js", TechCategory::Framework),
    ];

    let mut results = Vec::new();
    for &(pattern, name, category) in frameworks {
        if value.contains(pattern) {
            let version = extract_version_after_slash(value, pattern);
            results.push(DetectedTech {
                name: name.to_string(),
                version,
                category,
                confidence: 0.9,
                evidence: format!("X-Powered-By: {value}"),
            });
        }
    }
    results
}

fn detect_generator_header(value: &str) -> Vec<DetectedTech> {
    let generators: &[(&str, &str, TechCategory)] = &[
        ("WordPress", "WordPress", TechCategory::Cms),
        ("Drupal", "Drupal", TechCategory::Cms),
        ("Jekyll", "Jekyll", TechCategory::Cms),
        ("Hugo", "Hugo", TechCategory::Cms),
    ];

    let mut results = Vec::new();
    for &(pattern, name, category) in generators {
        if value.contains(pattern) {
            results.push(DetectedTech {
                name: name.to_string(),
                version: None,
                category,
                confidence: 0.9,
                evidence: format!("X-Generator: {value}"),
            });
        }
    }
    results
}

fn detect_session_cookies(value: &str) -> Vec<DetectedTech> {
    let cookie_patterns: &[(&str, &str, TechCategory)] = &[
        ("PHPSESSID", "PHP", TechCategory::ProgrammingLanguage),
        ("JSESSIONID", "Java", TechCategory::ProgrammingLanguage),
        ("ASP.NET_SessionId", "ASP.NET", TechCategory::Framework),
        ("connect.sid", "Express", TechCategory::Framework),
        ("csrftoken", "Django", TechCategory::Framework),
        ("_rails_session", "Ruby on Rails", TechCategory::Framework),
        ("laravel_session", "Laravel", TechCategory::Framework),
    ];

    let mut results = Vec::new();
    for &(pattern, name, category) in cookie_patterns {
        if value.contains(pattern) {
            results.push(DetectedTech {
                name: name.to_string(),
                version: None,
                category,
                confidence: 0.8,
                evidence: format!("Set-Cookie contains {pattern}"),
            });
        }
    }
    results
}

pub fn fingerprint_from_html(body: &str) -> Vec<DetectedTech> {
    let mut results = Vec::new();
    results.extend(detect_meta_generator(body));
    results.extend(detect_html_patterns(body));
    results.extend(detect_cdn_libraries(body));
    results
}

fn detect_meta_generator(body: &str) -> Vec<DetectedTech> {
    let re = Regex::new(
        r#"<meta\s+[^>]*name\s*=\s*["']generator["'][^>]*content\s*=\s*["']([^"']+)["']"#,
    )
    .unwrap();
    let re_alt = Regex::new(
        r#"<meta\s+[^>]*content\s*=\s*["']([^"']+)["'][^>]*name\s*=\s*["']generator["']"#,
    )
    .unwrap();

    let mut results = Vec::new();
    for caps in re.captures_iter(body).chain(re_alt.captures_iter(body)) {
        let content = &caps[1];
        let (name, version) = parse_generator_content(content);
        results.push(DetectedTech {
            name,
            version,
            category: TechCategory::Cms,
            confidence: 0.9,
            evidence: format!("meta generator: {content}"),
        });
    }
    results
}

fn parse_generator_content(content: &str) -> (String, Option<String>) {
    let parts: Vec<&str> = content.splitn(2, ' ').collect();
    if parts.len() == 2 && !parts[1].is_empty() {
        (parts[0].to_string(), Some(parts[1].to_string()))
    } else {
        (content.to_string(), None)
    }
}

struct HtmlPattern {
    pattern: &'static str,
    name: &'static str,
    category: TechCategory,
    confidence: f64,
}

const HTML_PATTERNS: &[HtmlPattern] = &[
    HtmlPattern {
        pattern: "wp-content/",
        name: "WordPress",
        category: TechCategory::Cms,
        confidence: 0.85,
    },
    HtmlPattern {
        pattern: "wp-includes/",
        name: "WordPress",
        category: TechCategory::Cms,
        confidence: 0.85,
    },
    HtmlPattern {
        pattern: "drupal.js",
        name: "Drupal",
        category: TechCategory::Cms,
        confidence: 0.85,
    },
    HtmlPattern {
        pattern: "Drupal.settings",
        name: "Drupal",
        category: TechCategory::Cms,
        confidence: 0.85,
    },
    HtmlPattern {
        pattern: "/_next/",
        name: "Next.js",
        category: TechCategory::Framework,
        confidence: 0.85,
    },
    HtmlPattern {
        pattern: "__NEXT_DATA__",
        name: "Next.js",
        category: TechCategory::Framework,
        confidence: 0.9,
    },
    HtmlPattern {
        pattern: "/__nuxt/",
        name: "Nuxt.js",
        category: TechCategory::Framework,
        confidence: 0.85,
    },
    HtmlPattern {
        pattern: "__NUXT__",
        name: "Nuxt.js",
        category: TechCategory::Framework,
        confidence: 0.9,
    },
    HtmlPattern {
        pattern: "ng-version",
        name: "Angular",
        category: TechCategory::JavaScript,
        confidence: 0.85,
    },
    HtmlPattern {
        pattern: "ng-app",
        name: "Angular",
        category: TechCategory::JavaScript,
        confidence: 0.8,
    },
    HtmlPattern {
        pattern: "data-reactroot",
        name: "React",
        category: TechCategory::JavaScript,
        confidence: 0.85,
    },
    HtmlPattern {
        pattern: "__REACT",
        name: "React",
        category: TechCategory::JavaScript,
        confidence: 0.8,
    },
    HtmlPattern {
        pattern: "data-v-",
        name: "Vue.js",
        category: TechCategory::JavaScript,
        confidence: 0.8,
    },
];

fn detect_html_patterns(body: &str) -> Vec<DetectedTech> {
    let mut results = Vec::new();
    for hp in HTML_PATTERNS {
        if body.contains(hp.pattern) {
            results.push(DetectedTech {
                name: hp.name.to_string(),
                version: None,
                category: hp.category,
                confidence: hp.confidence,
                evidence: format!("HTML contains \"{}\"", hp.pattern),
            });
        }
    }
    results.extend(detect_powered_by_link(body));
    results
}

fn detect_powered_by_link(body: &str) -> Vec<DetectedTech> {
    let re = Regex::new(r#"[Pp]owered\s+by\s+<a\s+[^>]*>([^<]+)</a>"#).unwrap();
    let mut results = Vec::new();
    for caps in re.captures_iter(body) {
        let name = caps[1].trim().to_string();
        if !name.is_empty() {
            results.push(DetectedTech {
                name,
                version: None,
                category: TechCategory::Cms,
                confidence: 0.7,
                evidence: "Powered by link in HTML".to_string(),
            });
        }
    }
    results
}

struct CdnPattern {
    substring: &'static str,
    name: &'static str,
}

const CDN_PATTERNS: &[CdnPattern] = &[
    CdnPattern {
        substring: "jquery",
        name: "jQuery",
    },
    CdnPattern {
        substring: "bootstrap",
        name: "Bootstrap",
    },
    CdnPattern {
        substring: "react",
        name: "React",
    },
    CdnPattern {
        substring: "vue",
        name: "Vue.js",
    },
    CdnPattern {
        substring: "angular",
        name: "Angular",
    },
    CdnPattern {
        substring: "lodash",
        name: "Lodash",
    },
    CdnPattern {
        substring: "moment",
        name: "Moment.js",
    },
];

fn detect_cdn_libraries(body: &str) -> Vec<DetectedTech> {
    let re = Regex::new(r#"<script\s+[^>]*src\s*=\s*["']([^"']+)["'][^>]*integrity\s*=\s*["']sha"#)
        .unwrap();
    let re_alt = Regex::new(
        r#"<script\s+[^>]*integrity\s*=\s*["']sha[^"']*["'][^>]*src\s*=\s*["']([^"']+)["']"#,
    )
    .unwrap();

    let mut results = Vec::new();
    for caps in re.captures_iter(body).chain(re_alt.captures_iter(body)) {
        let src = caps[1].to_lowercase();
        for cdn in CDN_PATTERNS {
            if src.contains(cdn.substring) {
                results.push(DetectedTech {
                    name: cdn.name.to_string(),
                    version: None,
                    category: TechCategory::JavaScript,
                    confidence: 0.75,
                    evidence: format!("CDN script with SRI: {}", &caps[1]),
                });
            }
        }
    }
    results
}

fn deduplicate(techs: Vec<DetectedTech>) -> Vec<DetectedTech> {
    let mut best: HashMap<String, DetectedTech> = HashMap::new();

    for tech in techs {
        let key = tech.name.to_lowercase();
        let entry = best.entry(key);
        entry
            .and_modify(|existing| {
                if tech.confidence > existing.confidence {
                    *existing = tech.clone();
                }
                if existing.version.is_none() && tech.version.is_some() {
                    existing.version = tech.version.clone();
                }
            })
            .or_insert(tech);
    }

    let mut result: Vec<DetectedTech> = best.into_values().collect();
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

fn validate_and_normalize(url: &str) -> Result<String, FingerprintError> {
    if url.is_empty() {
        return Err(FingerprintError::InvalidUrl(url.to_string()));
    }
    let _ = Url::parse(url).map_err(|_| FingerprintError::InvalidUrl(url.to_string()))?;
    validate_target_is_localhost(url)
        .map_err(|_| FingerprintError::NonLocalhostTarget(url.to_string()))?;
    Ok(url.trim_end_matches('/').to_string())
}
