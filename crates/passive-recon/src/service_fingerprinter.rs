/// Identifies services from HTTP response patterns: web server, framework,
/// CMS, CDN, WAF vendor, load balancer, and API gateway.
///
/// All analysis is passive — operates on response headers, body content,
/// and cookie patterns without sending active probes.
use std::collections::HashMap;
use std::fmt;

/// Confidence level for a service identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FingerprintConfidence {
    Low,
    Medium,
    High,
    Definite,
}

impl fmt::Display for FingerprintConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Definite => write!(f, "definite"),
        }
    }
}

/// Category of identified service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceCategory {
    WebServer,
    Framework,
    Cms,
    Cdn,
    Waf,
    LoadBalancer,
    ApiGateway,
    CacheLayer,
    Language,
    OperatingSystem,
}

impl fmt::Display for ServiceCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WebServer => write!(f, "Web Server"),
            Self::Framework => write!(f, "Framework"),
            Self::Cms => write!(f, "CMS"),
            Self::Cdn => write!(f, "CDN"),
            Self::Waf => write!(f, "WAF"),
            Self::LoadBalancer => write!(f, "Load Balancer"),
            Self::ApiGateway => write!(f, "API Gateway"),
            Self::CacheLayer => write!(f, "Cache Layer"),
            Self::Language => write!(f, "Language"),
            Self::OperatingSystem => write!(f, "Operating System"),
        }
    }
}

/// A single identified service.
#[derive(Debug, Clone)]
pub struct IdentifiedService {
    pub category: ServiceCategory,
    pub name: String,
    pub version: Option<String>,
    pub confidence: FingerprintConfidence,
    pub evidence: Vec<String>,
}

/// HTTP response data to analyze.
#[derive(Debug, Clone)]
pub struct HttpResponseData {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub url: String,
}

/// Result of service fingerprinting.
#[derive(Debug, Clone)]
pub struct FingerprintResult {
    pub target_url: String,
    pub services: Vec<IdentifiedService>,
    pub raw_server_header: Option<String>,
    pub security_headers_present: Vec<String>,
    pub security_headers_missing: Vec<String>,
}

/// Fingerprints network services from HTTP response data.
pub struct ServiceFingerprinter;

struct HeaderRule {
    header: &'static str,
    contains: &'static str,
    service_name: &'static str,
    category: ServiceCategory,
    confidence: FingerprintConfidence,
}

const HEADER_RULES: &[HeaderRule] = &[
    // Web servers
    HeaderRule {
        header: "server",
        contains: "apache",
        service_name: "Apache",
        category: ServiceCategory::WebServer,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "server",
        contains: "nginx",
        service_name: "Nginx",
        category: ServiceCategory::WebServer,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "server",
        contains: "microsoft-iis",
        service_name: "IIS",
        category: ServiceCategory::WebServer,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "server",
        contains: "caddy",
        service_name: "Caddy",
        category: ServiceCategory::WebServer,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "server",
        contains: "lighttpd",
        service_name: "lighttpd",
        category: ServiceCategory::WebServer,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "server",
        contains: "litespeed",
        service_name: "LiteSpeed",
        category: ServiceCategory::WebServer,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "server",
        contains: "openresty",
        service_name: "OpenResty",
        category: ServiceCategory::WebServer,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "server",
        contains: "gunicorn",
        service_name: "Gunicorn",
        category: ServiceCategory::WebServer,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "server",
        contains: "uvicorn",
        service_name: "Uvicorn",
        category: ServiceCategory::WebServer,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "server",
        contains: "cowboy",
        service_name: "Cowboy (Erlang)",
        category: ServiceCategory::WebServer,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "server",
        contains: "kestrel",
        service_name: "Kestrel (.NET)",
        category: ServiceCategory::WebServer,
        confidence: FingerprintConfidence::Definite,
    },
    // CDNs
    HeaderRule {
        header: "server",
        contains: "cloudflare",
        service_name: "Cloudflare",
        category: ServiceCategory::Cdn,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "cf-ray",
        contains: "",
        service_name: "Cloudflare",
        category: ServiceCategory::Cdn,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "cf-cache-status",
        contains: "",
        service_name: "Cloudflare",
        category: ServiceCategory::Cdn,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "x-amz-cf-id",
        contains: "",
        service_name: "CloudFront",
        category: ServiceCategory::Cdn,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "x-amz-cf-pop",
        contains: "",
        service_name: "CloudFront",
        category: ServiceCategory::Cdn,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "x-cache",
        contains: "cloudfront",
        service_name: "CloudFront",
        category: ServiceCategory::Cdn,
        confidence: FingerprintConfidence::High,
    },
    HeaderRule {
        header: "server",
        contains: "cloudfront",
        service_name: "CloudFront",
        category: ServiceCategory::Cdn,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "x-akamai-transformed",
        contains: "",
        service_name: "Akamai",
        category: ServiceCategory::Cdn,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "x-akamai-request-id",
        contains: "",
        service_name: "Akamai",
        category: ServiceCategory::Cdn,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "x-fastly-request-id",
        contains: "",
        service_name: "Fastly",
        category: ServiceCategory::Cdn,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "x-served-by",
        contains: "cache-",
        service_name: "Fastly",
        category: ServiceCategory::Cdn,
        confidence: FingerprintConfidence::High,
    },
    HeaderRule {
        header: "x-cdn",
        contains: "bunny",
        service_name: "BunnyCDN",
        category: ServiceCategory::Cdn,
        confidence: FingerprintConfidence::Definite,
    },
    // WAFs
    HeaderRule {
        header: "x-sucuri-id",
        contains: "",
        service_name: "Sucuri WAF",
        category: ServiceCategory::Waf,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "x-sucuri-cache",
        contains: "",
        service_name: "Sucuri WAF",
        category: ServiceCategory::Waf,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "server",
        contains: "akamaighost",
        service_name: "Akamai WAF",
        category: ServiceCategory::Waf,
        confidence: FingerprintConfidence::High,
    },
    HeaderRule {
        header: "x-powered-by",
        contains: "aws lambda",
        service_name: "AWS WAF/Lambda@Edge",
        category: ServiceCategory::Waf,
        confidence: FingerprintConfidence::Medium,
    },
    // Frameworks via X-Powered-By
    HeaderRule {
        header: "x-powered-by",
        contains: "express",
        service_name: "Express.js",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "x-powered-by",
        contains: "php",
        service_name: "PHP",
        category: ServiceCategory::Language,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "x-powered-by",
        contains: "asp.net",
        service_name: "ASP.NET",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "x-powered-by",
        contains: "next.js",
        service_name: "Next.js",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "x-powered-by",
        contains: "nuxt",
        service_name: "Nuxt.js",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "x-powered-by",
        contains: "django",
        service_name: "Django",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "x-powered-by",
        contains: "rails",
        service_name: "Ruby on Rails",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "x-powered-by",
        contains: "laravel",
        service_name: "Laravel",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::Definite,
    },
    // Load balancers
    HeaderRule {
        header: "x-haproxy-server-state",
        contains: "",
        service_name: "HAProxy",
        category: ServiceCategory::LoadBalancer,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "x-varnish",
        contains: "",
        service_name: "Varnish",
        category: ServiceCategory::CacheLayer,
        confidence: FingerprintConfidence::Definite,
    },
    // API Gateways
    HeaderRule {
        header: "x-amzn-requestid",
        contains: "",
        service_name: "AWS API Gateway",
        category: ServiceCategory::ApiGateway,
        confidence: FingerprintConfidence::High,
    },
    HeaderRule {
        header: "x-kong-upstream-latency",
        contains: "",
        service_name: "Kong",
        category: ServiceCategory::ApiGateway,
        confidence: FingerprintConfidence::Definite,
    },
    HeaderRule {
        header: "x-kong-proxy-latency",
        contains: "",
        service_name: "Kong",
        category: ServiceCategory::ApiGateway,
        confidence: FingerprintConfidence::Definite,
    },
];

/// Body-based fingerprint rules.
struct BodyRule {
    contains: &'static str,
    service_name: &'static str,
    category: ServiceCategory,
    confidence: FingerprintConfidence,
}

const BODY_RULES: &[BodyRule] = &[
    // CMS platforms
    BodyRule {
        contains: "wp-content",
        service_name: "WordPress",
        category: ServiceCategory::Cms,
        confidence: FingerprintConfidence::High,
    },
    BodyRule {
        contains: "wp-includes",
        service_name: "WordPress",
        category: ServiceCategory::Cms,
        confidence: FingerprintConfidence::High,
    },
    BodyRule {
        contains: "/wp-json/",
        service_name: "WordPress",
        category: ServiceCategory::Cms,
        confidence: FingerprintConfidence::High,
    },
    BodyRule {
        contains: "Drupal.settings",
        service_name: "Drupal",
        category: ServiceCategory::Cms,
        confidence: FingerprintConfidence::Definite,
    },
    BodyRule {
        contains: "sites/default/files",
        service_name: "Drupal",
        category: ServiceCategory::Cms,
        confidence: FingerprintConfidence::High,
    },
    BodyRule {
        contains: "/media/jui/",
        service_name: "Joomla",
        category: ServiceCategory::Cms,
        confidence: FingerprintConfidence::High,
    },
    BodyRule {
        contains: "content=\"Joomla",
        service_name: "Joomla",
        category: ServiceCategory::Cms,
        confidence: FingerprintConfidence::Definite,
    },
    BodyRule {
        contains: "content=\"WordPress",
        service_name: "WordPress",
        category: ServiceCategory::Cms,
        confidence: FingerprintConfidence::Definite,
    },
    BodyRule {
        contains: "shopify.com",
        service_name: "Shopify",
        category: ServiceCategory::Cms,
        confidence: FingerprintConfidence::High,
    },
    BodyRule {
        contains: "Squarespace",
        service_name: "Squarespace",
        category: ServiceCategory::Cms,
        confidence: FingerprintConfidence::High,
    },
    BodyRule {
        contains: "ghost.org",
        service_name: "Ghost",
        category: ServiceCategory::Cms,
        confidence: FingerprintConfidence::High,
    },
    // Frameworks from body
    BodyRule {
        contains: "__next",
        service_name: "Next.js",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::High,
    },
    BodyRule {
        contains: "__nuxt",
        service_name: "Nuxt.js",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::High,
    },
    BodyRule {
        contains: "ng-app",
        service_name: "AngularJS",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::High,
    },
    BodyRule {
        contains: "ng-version",
        service_name: "Angular",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::High,
    },
    BodyRule {
        contains: "__REACT_DEVTOOLS_GLOBAL_HOOK__",
        service_name: "React",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::Medium,
    },
    BodyRule {
        contains: "data-reactroot",
        service_name: "React",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::High,
    },
    BodyRule {
        contains: "csrf-token",
        service_name: "Ruby on Rails",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::Medium,
    },
    BodyRule {
        contains: "csrfmiddlewaretoken",
        service_name: "Django",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::High,
    },
    BodyRule {
        contains: "laravel_session",
        service_name: "Laravel",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::Definite,
    },
    BodyRule {
        contains: "spring",
        service_name: "Spring",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::Low,
    },
    BodyRule {
        contains: "swagger-ui",
        service_name: "Swagger/OpenAPI",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::High,
    },
    BodyRule {
        contains: "graphql",
        service_name: "GraphQL",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::Medium,
    },
];

/// Cookie-based fingerprint rules.
struct CookieRule {
    cookie_name: &'static str,
    service_name: &'static str,
    category: ServiceCategory,
    confidence: FingerprintConfidence,
}

const COOKIE_RULES: &[CookieRule] = &[
    CookieRule {
        cookie_name: "PHPSESSID",
        service_name: "PHP",
        category: ServiceCategory::Language,
        confidence: FingerprintConfidence::Definite,
    },
    CookieRule {
        cookie_name: "JSESSIONID",
        service_name: "Java",
        category: ServiceCategory::Language,
        confidence: FingerprintConfidence::Definite,
    },
    CookieRule {
        cookie_name: "ASP.NET_SessionId",
        service_name: "ASP.NET",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::Definite,
    },
    CookieRule {
        cookie_name: "rack.session",
        service_name: "Ruby/Rack",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::High,
    },
    CookieRule {
        cookie_name: "_rails_session",
        service_name: "Ruby on Rails",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::Definite,
    },
    CookieRule {
        cookie_name: "laravel_session",
        service_name: "Laravel",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::Definite,
    },
    CookieRule {
        cookie_name: "django_session",
        service_name: "Django",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::Definite,
    },
    CookieRule {
        cookie_name: "connect.sid",
        service_name: "Express.js",
        category: ServiceCategory::Framework,
        confidence: FingerprintConfidence::High,
    },
    CookieRule {
        cookie_name: "__cfduid",
        service_name: "Cloudflare",
        category: ServiceCategory::Cdn,
        confidence: FingerprintConfidence::Definite,
    },
    CookieRule {
        cookie_name: "wordpress_logged_in",
        service_name: "WordPress",
        category: ServiceCategory::Cms,
        confidence: FingerprintConfidence::Definite,
    },
    CookieRule {
        cookie_name: "wp-settings-",
        service_name: "WordPress",
        category: ServiceCategory::Cms,
        confidence: FingerprintConfidence::Definite,
    },
];

const SECURITY_HEADERS: &[&str] = &[
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
];

impl ServiceFingerprinter {
    pub fn new() -> Self {
        Self
    }

    /// Fingerprint services from a single HTTP response.
    pub fn fingerprint(&self, response: &HttpResponseData) -> FingerprintResult {
        let mut services_map: HashMap<String, IdentifiedService> = HashMap::new();
        let lower_headers: HashMap<String, String> = response
            .headers
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.clone()))
            .collect();

        self.check_header_rules(&lower_headers, &mut services_map);
        self.check_body_rules(&response.body, &mut services_map);
        self.check_cookie_rules(&lower_headers, &mut services_map);
        self.check_error_page_signatures(&response.body, response.status_code, &mut services_map);
        self.detect_os_from_headers(&lower_headers, &mut services_map);

        let raw_server = lower_headers.get("server").cloned();

        let (present, missing) = self.check_security_headers(&lower_headers);

        FingerprintResult {
            target_url: response.url.clone(),
            services: services_map.into_values().collect(),
            raw_server_header: raw_server,
            security_headers_present: present,
            security_headers_missing: missing,
        }
    }

    /// Fingerprint services from multiple responses (more accurate).
    pub fn fingerprint_multi(&self, responses: &[HttpResponseData]) -> FingerprintResult {
        let mut combined_map: HashMap<String, IdentifiedService> = HashMap::new();
        let mut raw_server = None;
        let mut all_lower_headers: HashMap<String, String> = HashMap::new();

        for response in responses {
            let single = self.fingerprint(response);
            if raw_server.is_none() {
                raw_server = single.raw_server_header;
            }
            for svc in single.services {
                let key = format!("{}:{}", svc.category, svc.name);
                let entry = combined_map.entry(key).or_insert(svc.clone());
                if svc.confidence > entry.confidence {
                    entry.confidence = svc.confidence;
                }
                for ev in &svc.evidence {
                    if !entry.evidence.contains(ev) {
                        entry.evidence.push(ev.clone());
                    }
                }
            }
            for (k, v) in &response.headers {
                all_lower_headers
                    .entry(k.to_lowercase())
                    .or_insert_with(|| v.clone());
            }
        }

        let (present, missing) = self.check_security_headers(&all_lower_headers);

        FingerprintResult {
            target_url: responses.first().map(|r| r.url.clone()).unwrap_or_default(),
            services: combined_map.into_values().collect(),
            raw_server_header: raw_server,
            security_headers_present: present,
            security_headers_missing: missing,
        }
    }

    fn check_header_rules(
        &self,
        headers: &HashMap<String, String>,
        services: &mut HashMap<String, IdentifiedService>,
    ) {
        for rule in HEADER_RULES {
            if let Some(val) = headers.get(rule.header) {
                let matches = if rule.contains.is_empty() {
                    true
                } else {
                    val.to_lowercase().contains(rule.contains)
                };

                if matches {
                    let key = format!("{}:{}", rule.category, rule.service_name);
                    let version = extract_version(val, rule.service_name);
                    let entry = services.entry(key).or_insert_with(|| IdentifiedService {
                        category: rule.category,
                        name: rule.service_name.to_string(),
                        version: None,
                        confidence: rule.confidence,
                        evidence: Vec::new(),
                    });
                    if version.is_some() {
                        entry.version = version;
                    }
                    if rule.confidence > entry.confidence {
                        entry.confidence = rule.confidence;
                    }
                    entry.evidence.push(format!("{}: {}", rule.header, val));
                }
            }
        }
    }

    fn check_body_rules(&self, body: &str, services: &mut HashMap<String, IdentifiedService>) {
        let lower_body = body.to_lowercase();
        for rule in BODY_RULES {
            if lower_body.contains(&rule.contains.to_lowercase()) {
                let key = format!("{}:{}", rule.category, rule.service_name);
                let entry = services.entry(key).or_insert_with(|| IdentifiedService {
                    category: rule.category,
                    name: rule.service_name.to_string(),
                    version: None,
                    confidence: rule.confidence,
                    evidence: Vec::new(),
                });
                if rule.confidence > entry.confidence {
                    entry.confidence = rule.confidence;
                }
                entry
                    .evidence
                    .push(format!("Body contains '{}'", rule.contains));
            }
        }
    }

    fn check_cookie_rules(
        &self,
        headers: &HashMap<String, String>,
        services: &mut HashMap<String, IdentifiedService>,
    ) {
        let cookie_header = headers
            .get("set-cookie")
            .or_else(|| headers.get("cookie"))
            .cloned()
            .unwrap_or_default();

        for rule in COOKIE_RULES {
            if cookie_header.contains(rule.cookie_name) {
                let key = format!("{}:{}", rule.category, rule.service_name);
                let entry = services.entry(key).or_insert_with(|| IdentifiedService {
                    category: rule.category,
                    name: rule.service_name.to_string(),
                    version: None,
                    confidence: rule.confidence,
                    evidence: Vec::new(),
                });
                if rule.confidence > entry.confidence {
                    entry.confidence = rule.confidence;
                }
                entry
                    .evidence
                    .push(format!("Cookie '{}' present", rule.cookie_name));
            }
        }
    }

    fn check_error_page_signatures(
        &self,
        body: &str,
        status_code: u16,
        services: &mut HashMap<String, IdentifiedService>,
    ) {
        if status_code < 400 {
            return;
        }

        let error_sigs: &[(&str, &str, ServiceCategory)] = &[
            ("Apache/", "Apache", ServiceCategory::WebServer),
            ("nginx/", "Nginx", ServiceCategory::WebServer),
            ("Microsoft-IIS/", "IIS", ServiceCategory::WebServer),
            (
                "Whitelabel Error Page",
                "Spring Boot",
                ServiceCategory::Framework,
            ),
            (
                "at org.apache.catalina",
                "Apache Tomcat",
                ServiceCategory::WebServer,
            ),
            (
                "Traceback (most recent call last)",
                "Python",
                ServiceCategory::Language,
            ),
            (
                "ActionController::RoutingError",
                "Ruby on Rails",
                ServiceCategory::Framework,
            ),
            ("Laravel", "Laravel", ServiceCategory::Framework),
        ];

        for &(pattern, name, cat) in error_sigs {
            if body.contains(pattern) {
                let key = format!("{}:{}", cat, name);
                let entry = services.entry(key).or_insert_with(|| IdentifiedService {
                    category: cat,
                    name: name.to_string(),
                    version: None,
                    confidence: FingerprintConfidence::High,
                    evidence: Vec::new(),
                });
                entry
                    .evidence
                    .push(format!("Error page signature: '{}'", pattern));
            }
        }
    }

    fn detect_os_from_headers(
        &self,
        headers: &HashMap<String, String>,
        services: &mut HashMap<String, IdentifiedService>,
    ) {
        if let Some(server) = headers.get("server") {
            let lower = server.to_lowercase();
            let os = if lower.contains("win32")
                || lower.contains("win64")
                || lower.contains("windows")
            {
                Some("Windows")
            } else if lower.contains("unix") || lower.contains("linux") {
                Some("Linux/Unix")
            } else if lower.contains("debian") {
                Some("Debian Linux")
            } else if lower.contains("ubuntu") {
                Some("Ubuntu Linux")
            } else if lower.contains("centos") {
                Some("CentOS Linux")
            } else {
                None
            };

            if let Some(os_name) = os {
                let key = format!("{}:{}", ServiceCategory::OperatingSystem, os_name);
                services.entry(key).or_insert_with(|| IdentifiedService {
                    category: ServiceCategory::OperatingSystem,
                    name: os_name.to_string(),
                    version: None,
                    confidence: FingerprintConfidence::Medium,
                    evidence: vec![format!("server: {}", server)],
                });
            }
        }
    }

    fn check_security_headers(
        &self,
        headers: &HashMap<String, String>,
    ) -> (Vec<String>, Vec<String>) {
        let mut present = Vec::new();
        let mut missing = Vec::new();
        for &hdr in SECURITY_HEADERS {
            if headers.contains_key(hdr) {
                present.push(hdr.to_string());
            } else {
                missing.push(hdr.to_string());
            }
        }
        (present, missing)
    }
}

impl Default for ServiceFingerprinter {
    fn default() -> Self {
        Self::new()
    }
}

fn extract_version(header_value: &str, service_name: &str) -> Option<String> {
    let lower_name = service_name.to_lowercase();
    let lower_val = header_value.to_lowercase();

    if let Some(idx) = lower_val.find(&lower_name) {
        let after_name = &header_value[idx + service_name.len()..];
        let trimmed = after_name.trim_start_matches('/').trim();
        let version: String = trimmed
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        if !version.is_empty() {
            return Some(version);
        }
    }
    None
}
