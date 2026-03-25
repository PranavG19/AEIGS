use std::collections::HashMap;
use std::fmt;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Category of HTTP security feature being assessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecurityFeature {
    Hsts,
    Csp,
    XFrameOptions,
    ReferrerPolicy,
    PermissionsPolicy,
    SubresourceIntegrity,
    XContentTypeOptions,
    XssProtection,
    CacheControl,
    CrossOriginPolicies,
}

impl fmt::Display for SecurityFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Hsts => "HSTS",
            Self::Csp => "CSP",
            Self::XFrameOptions => "X-Frame-Options",
            Self::ReferrerPolicy => "Referrer-Policy",
            Self::PermissionsPolicy => "Permissions-Policy",
            Self::SubresourceIntegrity => "Subresource Integrity",
            Self::XContentTypeOptions => "X-Content-Type-Options",
            Self::XssProtection => "X-XSS-Protection",
            Self::CacheControl => "Cache-Control",
            Self::CrossOriginPolicies => "Cross-Origin Policies",
        };
        write!(f, "{label}")
    }
}

/// Status of a security feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum FeatureStatus {
    /// Feature properly configured.
    Present,
    /// Feature present but misconfigured.
    Misconfigured,
    /// Feature missing entirely.
    Missing,
}

impl fmt::Display for FeatureStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Present => "present",
            Self::Misconfigured => "misconfigured",
            Self::Missing => "missing",
        };
        write!(f, "{label}")
    }
}

/// Severity of a security feature finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum SecurityFeatureSeverity {
    Info,
    Low,
    Medium,
    High,
}

impl fmt::Display for SecurityFeatureSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        };
        write!(f, "{label}")
    }
}

/// A single security feature assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFeatureFinding {
    pub feature: SecurityFeature,
    pub status: FeatureStatus,
    pub severity: SecurityFeatureSeverity,
    pub header_value: Option<String>,
    pub description: String,
    pub recommendation: String,
}

/// Full security feature analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFeatureAnalysis {
    pub target_url: String,
    pub findings: Vec<SecurityFeatureFinding>,
    pub summary: SecurityFeatureSummary,
    pub score: f64,
}

/// Summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFeatureSummary {
    pub total_features_checked: usize,
    pub present_count: usize,
    pub misconfigured_count: usize,
    pub missing_count: usize,
    pub high_severity_count: usize,
}

/// Parsed HTTP response headers for security analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseHeaders {
    pub headers: HashMap<String, String>,
}

impl ResponseHeaders {
    pub fn new() -> Self {
        Self {
            headers: HashMap::new(),
        }
    }

    pub fn set(&mut self, name: &str, value: &str) -> &mut Self {
        self.headers.insert(name.to_lowercase(), value.to_string());
        self
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_lowercase()).map(|s| s.as_str())
    }

    pub fn has(&self, name: &str) -> bool {
        self.headers.contains_key(&name.to_lowercase())
    }
}

/// HTML source for SRI checking.
#[derive(Debug, Clone, Default)]
pub struct PageSource {
    pub html: String,
}

/// Configuration for security feature detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFeatureConfig {
    pub target_url: String,
    pub is_https: bool,
    pub check_sri: bool,
}

impl Default for SecurityFeatureConfig {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            is_https: true,
            check_sri: true,
        }
    }
}

impl SecurityFeatureConfig {
    pub fn with_target(mut self, url: &str) -> Self {
        self.target_url = url.to_string();
        self.is_https = url.starts_with("https://");
        self
    }

    pub fn with_sri_check(mut self, enabled: bool) -> Self {
        self.check_sri = enabled;
        self
    }
}

/// Analyze HSTS (HTTP Strict Transport Security).
pub fn check_hsts(
    headers: &ResponseHeaders,
    config: &SecurityFeatureConfig,
) -> SecurityFeatureFinding {
    if !config.is_https {
        return SecurityFeatureFinding {
            feature: SecurityFeature::Hsts,
            status: FeatureStatus::Missing,
            severity: SecurityFeatureSeverity::High,
            header_value: None,
            description: "Site served over HTTP - HSTS not applicable without HTTPS".to_string(),
            recommendation: "Enable HTTPS and deploy HSTS header.".to_string(),
        };
    }

    match headers.get("strict-transport-security") {
        None => SecurityFeatureFinding {
            feature: SecurityFeature::Hsts,
            status: FeatureStatus::Missing,
            severity: SecurityFeatureSeverity::High,
            header_value: None,
            description: "Strict-Transport-Security header is missing".to_string(),
            recommendation:
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                    .to_string(),
        },
        Some(val) => {
            let max_age = extract_max_age(val);
            let has_include_subdomains = val.to_lowercase().contains("includesubdomains");
            let has_preload = val.to_lowercase().contains("preload");

            if max_age < 31536000 {
                SecurityFeatureFinding {
                    feature: SecurityFeature::Hsts,
                    status: FeatureStatus::Misconfigured,
                    severity: SecurityFeatureSeverity::Medium,
                    header_value: Some(val.to_string()),
                    description: format!(
                        "HSTS max-age is {} seconds ({:.0} days) - should be at least 1 year (31536000)",
                        max_age,
                        max_age as f64 / 86400.0
                    ),
                    recommendation: "Increase max-age to at least 31536000 (1 year).".to_string(),
                }
            } else if !has_include_subdomains {
                SecurityFeatureFinding {
                    feature: SecurityFeature::Hsts,
                    status: FeatureStatus::Misconfigured,
                    severity: SecurityFeatureSeverity::Low,
                    header_value: Some(val.to_string()),
                    description: "HSTS is set but missing includeSubDomains directive".to_string(),
                    recommendation: "Add includeSubDomains to protect all subdomains.".to_string(),
                }
            } else {
                SecurityFeatureFinding {
                    feature: SecurityFeature::Hsts,
                    status: FeatureStatus::Present,
                    severity: SecurityFeatureSeverity::Info,
                    header_value: Some(val.to_string()),
                    description: format!(
                        "HSTS properly configured (max-age={}, includeSubDomains={}, preload={})",
                        max_age, has_include_subdomains, has_preload
                    ),
                    recommendation: if !has_preload {
                        "Consider adding preload directive and submitting to HSTS preload list."
                            .to_string()
                    } else {
                        "HSTS is well configured.".to_string()
                    },
                }
            }
        }
    }
}

fn extract_max_age(hsts_value: &str) -> u64 {
    let re = Regex::new(r"(?i)max-age\s*=\s*(\d+)").expect("valid regex");
    re.captures(hsts_value)
        .and_then(|c| c[1].parse::<u64>().ok())
        .unwrap_or(0)
}

/// Analyze Content-Security-Policy.
pub fn check_csp(headers: &ResponseHeaders) -> SecurityFeatureFinding {
    let csp = headers
        .get("content-security-policy")
        .or_else(|| headers.get("content-security-policy-report-only"));

    match csp {
        None => SecurityFeatureFinding {
            feature: SecurityFeature::Csp,
            status: FeatureStatus::Missing,
            severity: SecurityFeatureSeverity::High,
            header_value: None,
            description: "Content-Security-Policy header is missing".to_string(),
            recommendation: "Deploy a CSP. Start with: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'".to_string(),
        },
        Some(val) => {
            let mut issues = Vec::new();

            if val.contains("unsafe-inline") {
                issues.push("allows 'unsafe-inline' (XSS bypass)");
            }
            if val.contains("unsafe-eval") {
                issues.push("allows 'unsafe-eval' (code injection)");
            }
            if val.contains("data:") && (val.contains("script-src") || val.contains("default-src")) {
                issues.push("allows data: URIs in script context");
            }
            if val.contains("*") {
                issues.push("contains wildcard (*) source");
            }
            if !val.contains("default-src") {
                issues.push("missing default-src directive");
            }
            if !val.contains("frame-ancestors") && !val.contains("frame-src") {
                issues.push("missing frame-ancestors (clickjacking protection)");
            }
            if !val.contains("object-src") {
                issues.push("missing object-src directive (plugin abuse)");
            }
            if !val.contains("base-uri") {
                issues.push("missing base-uri directive (base tag injection)");
            }

            let is_report_only = headers.has("content-security-policy-report-only")
                && !headers.has("content-security-policy");

            if is_report_only {
                issues.push("CSP is report-only mode (not enforced)");
            }

            if issues.is_empty() {
                SecurityFeatureFinding {
                    feature: SecurityFeature::Csp,
                    status: FeatureStatus::Present,
                    severity: SecurityFeatureSeverity::Info,
                    header_value: Some(val.to_string()),
                    description: "Content-Security-Policy is well configured".to_string(),
                    recommendation: "CSP looks good. Consider adding report-uri for monitoring.".to_string(),
                }
            } else {
                let severity = if issues.iter().any(|i| i.contains("unsafe-inline") || i.contains("unsafe-eval") || i.contains("wildcard")) {
                    SecurityFeatureSeverity::High
                } else if is_report_only {
                    SecurityFeatureSeverity::Medium
                } else {
                    SecurityFeatureSeverity::Low
                };

                SecurityFeatureFinding {
                    feature: SecurityFeature::Csp,
                    status: FeatureStatus::Misconfigured,
                    severity,
                    header_value: Some(val.to_string()),
                    description: format!("CSP issues: {}", issues.join("; ")),
                    recommendation: "Fix the identified CSP weaknesses. Remove 'unsafe-inline' and 'unsafe-eval' where possible.".to_string(),
                }
            }
        }
    }
}

/// Analyze X-Frame-Options.
pub fn check_x_frame_options(headers: &ResponseHeaders) -> SecurityFeatureFinding {
    match headers.get("x-frame-options") {
        None => SecurityFeatureFinding {
            feature: SecurityFeature::XFrameOptions,
            status: FeatureStatus::Missing,
            severity: SecurityFeatureSeverity::Medium,
            header_value: None,
            description: "X-Frame-Options header is missing - clickjacking possible".to_string(),
            recommendation: "Add: X-Frame-Options: DENY (or SAMEORIGIN if framing is needed)."
                .to_string(),
        },
        Some(val) => {
            let upper = val.to_uppercase();
            if upper == "DENY" || upper == "SAMEORIGIN" {
                SecurityFeatureFinding {
                    feature: SecurityFeature::XFrameOptions,
                    status: FeatureStatus::Present,
                    severity: SecurityFeatureSeverity::Info,
                    header_value: Some(val.to_string()),
                    description: format!("X-Frame-Options: {val} is properly set"),
                    recommendation:
                        "Consider also using CSP frame-ancestors for broader browser support."
                            .to_string(),
                }
            } else if upper.starts_with("ALLOW-FROM") {
                SecurityFeatureFinding {
                    feature: SecurityFeature::XFrameOptions,
                    status: FeatureStatus::Misconfigured,
                    severity: SecurityFeatureSeverity::Medium,
                    header_value: Some(val.to_string()),
                    description: "X-Frame-Options: ALLOW-FROM is deprecated and not supported by modern browsers".to_string(),
                    recommendation: "Use CSP frame-ancestors instead of ALLOW-FROM.".to_string(),
                }
            } else {
                SecurityFeatureFinding {
                    feature: SecurityFeature::XFrameOptions,
                    status: FeatureStatus::Misconfigured,
                    severity: SecurityFeatureSeverity::Medium,
                    header_value: Some(val.to_string()),
                    description: format!("X-Frame-Options has invalid value: {val}"),
                    recommendation: "Set to DENY or SAMEORIGIN.".to_string(),
                }
            }
        }
    }
}

/// Analyze Referrer-Policy.
pub fn check_referrer_policy(headers: &ResponseHeaders) -> SecurityFeatureFinding {
    match headers.get("referrer-policy") {
        None => SecurityFeatureFinding {
            feature: SecurityFeature::ReferrerPolicy,
            status: FeatureStatus::Missing,
            severity: SecurityFeatureSeverity::Low,
            header_value: None,
            description: "Referrer-Policy header is missing - full URL may be leaked in Referer header".to_string(),
            recommendation: "Add: Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for maximum privacy).".to_string(),
        },
        Some(val) => {
            let safe_policies = [
                "no-referrer",
                "same-origin",
                "strict-origin",
                "strict-origin-when-cross-origin",
                "no-referrer-when-downgrade",
            ];

            let lower = val.to_lowercase();
            if safe_policies.iter().any(|p| lower.contains(p)) {
                SecurityFeatureFinding {
                    feature: SecurityFeature::ReferrerPolicy,
                    status: FeatureStatus::Present,
                    severity: SecurityFeatureSeverity::Info,
                    header_value: Some(val.to_string()),
                    description: format!("Referrer-Policy: {val} is properly configured"),
                    recommendation: "Referrer-Policy is well configured.".to_string(),
                }
            } else if lower == "unsafe-url" {
                SecurityFeatureFinding {
                    feature: SecurityFeature::ReferrerPolicy,
                    status: FeatureStatus::Misconfigured,
                    severity: SecurityFeatureSeverity::Medium,
                    header_value: Some(val.to_string()),
                    description: "Referrer-Policy: unsafe-url sends full URL as referer on all requests".to_string(),
                    recommendation: "Change to strict-origin-when-cross-origin or no-referrer.".to_string(),
                }
            } else {
                SecurityFeatureFinding {
                    feature: SecurityFeature::ReferrerPolicy,
                    status: FeatureStatus::Misconfigured,
                    severity: SecurityFeatureSeverity::Low,
                    header_value: Some(val.to_string()),
                    description: format!("Referrer-Policy has weak value: {val}"),
                    recommendation: "Use strict-origin-when-cross-origin for a good balance of privacy and functionality.".to_string(),
                }
            }
        }
    }
}

/// Analyze Permissions-Policy (formerly Feature-Policy).
pub fn check_permissions_policy(headers: &ResponseHeaders) -> SecurityFeatureFinding {
    let pp = headers
        .get("permissions-policy")
        .or_else(|| headers.get("feature-policy"));

    match pp {
        None => SecurityFeatureFinding {
            feature: SecurityFeature::PermissionsPolicy,
            status: FeatureStatus::Missing,
            severity: SecurityFeatureSeverity::Low,
            header_value: None,
            description: "Permissions-Policy header is missing - browser features like camera, microphone, geolocation are unrestricted".to_string(),
            recommendation: "Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()".to_string(),
        },
        Some(val) => {
            let sensitive_features = [
                "camera", "microphone", "geolocation", "payment",
                "usb", "magnetometer", "gyroscope", "accelerometer",
            ];

            let restricted: Vec<&str> = sensitive_features
                .iter()
                .filter(|feat| val.contains(*feat))
                .copied()
                .collect();

            if restricted.len() >= 4 {
                SecurityFeatureFinding {
                    feature: SecurityFeature::PermissionsPolicy,
                    status: FeatureStatus::Present,
                    severity: SecurityFeatureSeverity::Info,
                    header_value: Some(val.to_string()),
                    description: format!("Permissions-Policy restricts {} features", restricted.len()),
                    recommendation: "Permissions-Policy is well configured.".to_string(),
                }
            } else {
                SecurityFeatureFinding {
                    feature: SecurityFeature::PermissionsPolicy,
                    status: FeatureStatus::Misconfigured,
                    severity: SecurityFeatureSeverity::Low,
                    header_value: Some(val.to_string()),
                    description: format!(
                        "Permissions-Policy only restricts {} of {} sensitive features",
                        restricted.len(),
                        sensitive_features.len()
                    ),
                    recommendation: "Restrict more browser features: camera=(), microphone=(), geolocation=(), payment=(), usb=()".to_string(),
                }
            }
        }
    }
}

/// Analyze Subresource Integrity on scripts and stylesheets.
pub fn check_sri(html_source: &str) -> SecurityFeatureFinding {
    let script_re = Regex::new(r#"<script\s+[^>]*src\s*=\s*(?:"([^"]+)"|'([^']+)')[^>]*>"#)
        .expect("valid regex");
    let link_re = Regex::new(
        r#"<link\s+[^>]*href\s*=\s*(?:"([^"]+)"|'([^']+)')[^>]*rel\s*=\s*['"]stylesheet['"][^>]*>"#,
    )
    .expect("valid regex");
    let link_re2 = Regex::new(
        r#"<link\s+[^>]*rel\s*=\s*['"]stylesheet['"][^>]*href\s*=\s*(?:"([^"]+)"|'([^']+)')[^>]*>"#,
    )
    .expect("valid regex");
    let integrity_re = Regex::new(r#"integrity\s*=\s*['"]sha(?:256|384|512)-[A-Za-z0-9+/=]+['"]"#)
        .expect("valid regex");

    let mut external_scripts = 0u32;
    let mut external_styles = 0u32;
    let mut scripts_with_sri = 0u32;
    let mut styles_with_sri = 0u32;

    for cap in script_re.captures_iter(html_source) {
        let src = cap
            .get(1)
            .or_else(|| cap.get(2))
            .map(|m| m.as_str())
            .unwrap_or("");
        if is_external_resource(src) {
            external_scripts += 1;
            let full_tag = cap[0].to_string();
            if integrity_re.is_match(&full_tag) {
                scripts_with_sri += 1;
            }
        }
    }

    for re in &[&link_re, &link_re2] {
        for cap in re.captures_iter(html_source) {
            let href = cap
                .get(1)
                .or_else(|| cap.get(2))
                .map(|m| m.as_str())
                .unwrap_or("");
            if is_external_resource(href) {
                external_styles += 1;
                let full_tag = cap[0].to_string();
                if integrity_re.is_match(&full_tag) {
                    styles_with_sri += 1;
                }
            }
        }
    }

    let total_external = external_scripts + external_styles;
    let total_with_sri = scripts_with_sri + styles_with_sri;

    if total_external == 0 {
        SecurityFeatureFinding {
            feature: SecurityFeature::SubresourceIntegrity,
            status: FeatureStatus::Present,
            severity: SecurityFeatureSeverity::Info,
            header_value: None,
            description: "No external scripts or stylesheets found - SRI not needed".to_string(),
            recommendation: "No action needed.".to_string(),
        }
    } else if total_with_sri == total_external {
        SecurityFeatureFinding {
            feature: SecurityFeature::SubresourceIntegrity,
            status: FeatureStatus::Present,
            severity: SecurityFeatureSeverity::Info,
            header_value: None,
            description: format!(
                "All {total_external} external resources have SRI integrity attributes"
            ),
            recommendation: "SRI is well configured.".to_string(),
        }
    } else if total_with_sri > 0 {
        SecurityFeatureFinding {
            feature: SecurityFeature::SubresourceIntegrity,
            status: FeatureStatus::Misconfigured,
            severity: SecurityFeatureSeverity::Medium,
            header_value: None,
            description: format!(
                "Only {total_with_sri}/{total_external} external resources have SRI ({scripts_with_sri}/{external_scripts} scripts, {styles_with_sri}/{external_styles} styles)"
            ),
            recommendation: "Add integrity attributes to all external script and stylesheet tags.".to_string(),
        }
    } else {
        SecurityFeatureFinding {
            feature: SecurityFeature::SubresourceIntegrity,
            status: FeatureStatus::Missing,
            severity: SecurityFeatureSeverity::Medium,
            header_value: None,
            description: format!(
                "None of {total_external} external resources have SRI ({external_scripts} scripts, {external_styles} styles)"
            ),
            recommendation: "Add integrity and crossorigin attributes to all external script and link tags.".to_string(),
        }
    }
}

fn is_external_resource(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://") || url.starts_with("//")
}

/// Analyze X-Content-Type-Options.
pub fn check_x_content_type_options(headers: &ResponseHeaders) -> SecurityFeatureFinding {
    match headers.get("x-content-type-options") {
        None => SecurityFeatureFinding {
            feature: SecurityFeature::XContentTypeOptions,
            status: FeatureStatus::Missing,
            severity: SecurityFeatureSeverity::Medium,
            header_value: None,
            description: "X-Content-Type-Options header is missing - MIME type sniffing possible"
                .to_string(),
            recommendation: "Add: X-Content-Type-Options: nosniff".to_string(),
        },
        Some(val) => {
            if val.to_lowercase().trim() == "nosniff" {
                SecurityFeatureFinding {
                    feature: SecurityFeature::XContentTypeOptions,
                    status: FeatureStatus::Present,
                    severity: SecurityFeatureSeverity::Info,
                    header_value: Some(val.to_string()),
                    description: "X-Content-Type-Options: nosniff is properly set".to_string(),
                    recommendation: "No action needed.".to_string(),
                }
            } else {
                SecurityFeatureFinding {
                    feature: SecurityFeature::XContentTypeOptions,
                    status: FeatureStatus::Misconfigured,
                    severity: SecurityFeatureSeverity::Medium,
                    header_value: Some(val.to_string()),
                    description: format!("X-Content-Type-Options has invalid value: {val}"),
                    recommendation: "Set to: X-Content-Type-Options: nosniff".to_string(),
                }
            }
        }
    }
}

/// Analyze Cache-Control for sensitive pages.
pub fn check_cache_control(headers: &ResponseHeaders) -> SecurityFeatureFinding {
    match headers.get("cache-control") {
        None => SecurityFeatureFinding {
            feature: SecurityFeature::CacheControl,
            status: FeatureStatus::Missing,
            severity: SecurityFeatureSeverity::Low,
            header_value: None,
            description: "Cache-Control header is missing - sensitive responses may be cached"
                .to_string(),
            recommendation:
                "Add: Cache-Control: no-store, no-cache, must-revalidate for sensitive pages."
                    .to_string(),
        },
        Some(val) => {
            let lower = val.to_lowercase();
            if lower.contains("no-store")
                || (lower.contains("no-cache") && lower.contains("must-revalidate"))
            {
                SecurityFeatureFinding {
                    feature: SecurityFeature::CacheControl,
                    status: FeatureStatus::Present,
                    severity: SecurityFeatureSeverity::Info,
                    header_value: Some(val.to_string()),
                    description: "Cache-Control properly prevents caching of sensitive content"
                        .to_string(),
                    recommendation: "Cache-Control is well configured.".to_string(),
                }
            } else if lower.contains("public") || lower.contains("max-age") {
                SecurityFeatureFinding {
                    feature: SecurityFeature::CacheControl,
                    status: FeatureStatus::Misconfigured,
                    severity: SecurityFeatureSeverity::Medium,
                    header_value: Some(val.to_string()),
                    description: format!("Cache-Control allows caching: {val} - sensitive data may persist in caches"),
                    recommendation: "For sensitive pages, use: Cache-Control: no-store, no-cache, must-revalidate".to_string(),
                }
            } else {
                SecurityFeatureFinding {
                    feature: SecurityFeature::CacheControl,
                    status: FeatureStatus::Present,
                    severity: SecurityFeatureSeverity::Info,
                    header_value: Some(val.to_string()),
                    description: format!("Cache-Control: {val}"),
                    recommendation: "Review caching policy for sensitive endpoints.".to_string(),
                }
            }
        }
    }
}

/// Analyze Cross-Origin policies (COOP, COEP, CORP).
pub fn check_cross_origin_policies(headers: &ResponseHeaders) -> SecurityFeatureFinding {
    let coop = headers.get("cross-origin-opener-policy");
    let coep = headers.get("cross-origin-embedder-policy");
    let corp = headers.get("cross-origin-resource-policy");

    let mut present = Vec::new();
    let mut missing = Vec::new();

    if coop.is_some() {
        present.push("COOP");
    } else {
        missing.push("Cross-Origin-Opener-Policy");
    }

    if coep.is_some() {
        present.push("COEP");
    } else {
        missing.push("Cross-Origin-Embedder-Policy");
    }

    if corp.is_some() {
        present.push("CORP");
    } else {
        missing.push("Cross-Origin-Resource-Policy");
    }

    if missing.is_empty() {
        SecurityFeatureFinding {
            feature: SecurityFeature::CrossOriginPolicies,
            status: FeatureStatus::Present,
            severity: SecurityFeatureSeverity::Info,
            header_value: None,
            description: format!("All cross-origin policies present: {}", present.join(", ")),
            recommendation: "Cross-origin isolation is well configured.".to_string(),
        }
    } else if present.is_empty() {
        SecurityFeatureFinding {
            feature: SecurityFeature::CrossOriginPolicies,
            status: FeatureStatus::Missing,
            severity: SecurityFeatureSeverity::Low,
            header_value: None,
            description: format!("Missing cross-origin policies: {}", missing.join(", ")),
            recommendation: "Add: Cross-Origin-Opener-Policy: same-origin, Cross-Origin-Embedder-Policy: require-corp, Cross-Origin-Resource-Policy: same-origin".to_string(),
        }
    } else {
        SecurityFeatureFinding {
            feature: SecurityFeature::CrossOriginPolicies,
            status: FeatureStatus::Misconfigured,
            severity: SecurityFeatureSeverity::Low,
            header_value: None,
            description: format!(
                "Partial cross-origin policies: {} present, {} missing",
                present.join(", "),
                missing.join(", ")
            ),
            recommendation: format!("Add missing policies: {}", missing.join(", ")),
        }
    }
}

/// Run the full HTTP security feature analysis.
pub fn analyze_security_features(
    headers: &ResponseHeaders,
    html_source: Option<&str>,
    config: &SecurityFeatureConfig,
) -> SecurityFeatureAnalysis {
    let mut findings = Vec::new();

    findings.push(check_hsts(headers, config));
    findings.push(check_csp(headers));
    findings.push(check_x_frame_options(headers));
    findings.push(check_referrer_policy(headers));
    findings.push(check_permissions_policy(headers));
    findings.push(check_x_content_type_options(headers));
    findings.push(check_cache_control(headers));
    findings.push(check_cross_origin_policies(headers));

    if config.check_sri {
        if let Some(html) = html_source {
            findings.push(check_sri(html));
        }
    }

    let present_count = findings
        .iter()
        .filter(|f| f.status == FeatureStatus::Present)
        .count();
    let misconfigured_count = findings
        .iter()
        .filter(|f| f.status == FeatureStatus::Misconfigured)
        .count();
    let missing_count = findings
        .iter()
        .filter(|f| f.status == FeatureStatus::Missing)
        .count();
    let high_severity_count = findings
        .iter()
        .filter(|f| f.severity == SecurityFeatureSeverity::High)
        .count();

    let total = findings.len() as f64;
    let score = if total > 0.0 {
        let present_weight = present_count as f64 * 1.0;
        let misconfig_weight = misconfigured_count as f64 * 0.5;
        (present_weight + misconfig_weight) / total
    } else {
        0.0
    };

    let summary = SecurityFeatureSummary {
        total_features_checked: findings.len(),
        present_count,
        misconfigured_count,
        missing_count,
        high_severity_count,
    };

    SecurityFeatureAnalysis {
        target_url: config.target_url.clone(),
        findings,
        summary,
        score,
    }
}

/// Compute a letter grade from the security score.
pub fn score_to_grade(score: f64) -> &'static str {
    match score {
        s if s >= 0.9 => "A",
        s if s >= 0.8 => "B",
        s if s >= 0.65 => "C",
        s if s >= 0.5 => "D",
        _ => "F",
    }
}
