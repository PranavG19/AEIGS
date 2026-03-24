use std::collections::HashMap;
use std::fmt;

use aegis_evasion_engine::{
    analyze_probe, build_report, generate_poc_html, generate_probes, CorsExploitReport,
    CorsHeaders, CorsMisconfigKind, CorsProbeResult, CorsSeverity,
};

/// Origin test variants sent per endpoint during V2 scanning.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OriginTestKind {
    /// Origin: null — exploitable via sandboxed iframes
    Null,
    /// Arbitrary subdomain of the target (e.g. evil.target.com)
    Subdomain,
    /// Sibling domain sharing the same parent (e.g. other.parent.com for app.parent.com)
    Sibling,
    /// Completely unrelated attacker domain
    Attacker,
    /// Regex bypass via prefix match (e.g. evil-target.com)
    RegexBypassPrefix,
    /// Regex bypass via suffix match (e.g. target.com.evil.com)
    RegexBypassSuffix,
    /// Internal network origin (e.g. http://192.168.1.1)
    InternalNetwork,
    /// Wildcard test — verify if server returns ACAO: *
    Wildcard,
    /// HTTP downgrade of the HTTPS target origin
    HttpDowngrade,
}

impl fmt::Display for OriginTestKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => write!(f, "null_origin"),
            Self::Subdomain => write!(f, "subdomain"),
            Self::Sibling => write!(f, "sibling_domain"),
            Self::Attacker => write!(f, "attacker_domain"),
            Self::RegexBypassPrefix => write!(f, "regex_bypass_prefix"),
            Self::RegexBypassSuffix => write!(f, "regex_bypass_suffix"),
            Self::InternalNetwork => write!(f, "internal_network"),
            Self::Wildcard => write!(f, "wildcard_test"),
            Self::HttpDowngrade => write!(f, "http_downgrade"),
        }
    }
}

/// Impact categories for a confirmed CORS misconfiguration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ImpactCategory {
    CredentialTheft,
    DataExfiltration,
    InternalNetworkPivot,
    SessionHijack,
    AccountTakeover,
    CsrfTokenLeak,
    PiiExposure,
}

impl fmt::Display for ImpactCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CredentialTheft => write!(f, "Credential Theft"),
            Self::DataExfiltration => write!(f, "Data Exfiltration"),
            Self::InternalNetworkPivot => write!(f, "Internal Network Pivot"),
            Self::SessionHijack => write!(f, "Session Hijack"),
            Self::AccountTakeover => write!(f, "Account Takeover"),
            Self::CsrfTokenLeak => write!(f, "CSRF Token Leak"),
            Self::PiiExposure => write!(f, "PII Exposure"),
        }
    }
}

/// Impact classification for a CORS misconfiguration.
#[derive(Debug, Clone, PartialEq)]
pub struct ImpactClassification {
    pub severity: CorsSeverity,
    pub categories: Vec<ImpactCategory>,
    pub business_impact: String,
    pub cvss_estimate: f64,
}

/// A single origin test with the origin value and its classification.
#[derive(Debug, Clone)]
pub struct OriginTest {
    pub kind: OriginTestKind,
    pub origin_value: String,
    pub include_credentials: bool,
}

/// Preflight analysis result for an endpoint.
#[derive(Debug, Clone, PartialEq)]
pub struct PreflightAnalysis {
    pub cache_duration_seconds: Option<u64>,
    pub credential_reflection: bool,
    pub wildcard_methods: bool,
    pub wildcard_headers: bool,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub issues: Vec<String>,
}

/// Full V2 scan result combining detection, exploitation, and impact analysis.
#[derive(Debug, Clone)]
pub struct CorsV2ScanResult {
    pub endpoint: String,
    pub domain: String,
    pub origin_tests: Vec<OriginTestResult>,
    pub preflight: Option<PreflightAnalysis>,
    pub exploit_report: CorsExploitReport,
    pub impact: Option<ImpactClassification>,
    pub subdomain_takeover_chain: bool,
}

/// Result of testing a single origin value against an endpoint.
#[derive(Debug, Clone)]
pub struct OriginTestResult {
    pub test: OriginTest,
    pub reflected: bool,
    pub credentials_allowed: bool,
    pub response_origin: Option<String>,
    pub poc_html: Option<String>,
}

/// Generates origin test values for a given target domain. Returns >= 7 distinct origin tests.
pub fn generate_origin_tests(target_domain: &str) -> Vec<OriginTest> {
    let parent_domain = extract_parent_domain(target_domain);

    vec![
        OriginTest {
            kind: OriginTestKind::Null,
            origin_value: "null".to_string(),
            include_credentials: true,
        },
        OriginTest {
            kind: OriginTestKind::Subdomain,
            origin_value: format!("https://evil.{target_domain}"),
            include_credentials: true,
        },
        OriginTest {
            kind: OriginTestKind::Sibling,
            origin_value: format!("https://sibling.{parent_domain}"),
            include_credentials: true,
        },
        OriginTest {
            kind: OriginTestKind::Attacker,
            origin_value: "https://evil-attacker.com".to_string(),
            include_credentials: true,
        },
        OriginTest {
            kind: OriginTestKind::RegexBypassPrefix,
            origin_value: format!("https://evil-{target_domain}"),
            include_credentials: true,
        },
        OriginTest {
            kind: OriginTestKind::RegexBypassSuffix,
            origin_value: format!("https://{target_domain}.evil.com"),
            include_credentials: true,
        },
        OriginTest {
            kind: OriginTestKind::InternalNetwork,
            origin_value: "http://192.168.1.1".to_string(),
            include_credentials: false,
        },
        OriginTest {
            kind: OriginTestKind::Wildcard,
            origin_value: "https://wildcard-check.example.org".to_string(),
            include_credentials: false,
        },
        OriginTest {
            kind: OriginTestKind::HttpDowngrade,
            origin_value: format!("http://{target_domain}"),
            include_credentials: true,
        },
    ]
}

/// Extracts the parent domain (e.g., "example.com" from "app.example.com").
fn extract_parent_domain(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() > 2 {
        parts[parts.len() - 2..].join(".")
    } else {
        domain.to_string()
    }
}

/// Analyzes CORS response headers from a single origin test.
pub fn analyze_origin_test(
    test: &OriginTest,
    response_headers: &HashMap<String, String>,
) -> OriginTestResult {
    let cors_headers = CorsHeaders::from_header_map(response_headers);

    let reflected = match &cors_headers.allow_origin {
        Some(origin) => {
            origin == &test.origin_value
                || origin == "*"
                || (test.kind == OriginTestKind::Null && origin == "null")
        }
        None => false,
    };

    let credentials_allowed = cors_headers.allow_credentials.unwrap_or(false);

    let response_origin = cors_headers.allow_origin.clone();

    let poc_html = if reflected {
        let misconfig_kind = origin_test_to_misconfig_kind(&test.kind);
        Some(generate_poc_html(
            misconfig_kind,
            "TARGET_URL_PLACEHOLDER",
            &test.origin_value,
        ))
    } else {
        None
    };

    OriginTestResult {
        test: test.clone(),
        reflected,
        credentials_allowed,
        response_origin,
        poc_html,
    }
}

/// Analyzes OPTIONS preflight response headers.
pub fn analyze_preflight(response_headers: &HashMap<String, String>) -> PreflightAnalysis {
    let cors_headers = CorsHeaders::from_header_map(response_headers);
    let mut issues = Vec::new();

    let cache_duration_seconds = cors_headers.max_age;
    if let Some(age) = cache_duration_seconds {
        if age > 86400 {
            issues.push(format!(
                "Preflight cache duration {age}s exceeds 24h — enables persistent cache poisoning"
            ));
        } else if age > 7200 {
            issues.push(format!(
                "Preflight cache duration {age}s exceeds 2h — elevated cache poisoning risk"
            ));
        }
    }

    let credential_reflection = cors_headers.allow_credentials.unwrap_or(false);
    if credential_reflection {
        issues.push(
            "Preflight allows credentials — cross-origin requests carry cookies/auth".to_string(),
        );
    }

    let methods = cors_headers.allow_methods.clone().unwrap_or_default();
    let wildcard_methods = methods.iter().any(|m| m.trim() == "*");
    if wildcard_methods {
        issues.push(
            "Wildcard methods (*) in preflight — all HTTP methods allowed cross-origin".to_string(),
        );
    }

    let headers_list = cors_headers.allow_headers.clone().unwrap_or_default();
    let wildcard_headers = headers_list.iter().any(|h| h.trim() == "*");
    if wildcard_headers {
        issues.push(
            "Wildcard headers (*) in preflight — all custom headers allowed cross-origin"
                .to_string(),
        );
    }

    PreflightAnalysis {
        cache_duration_seconds,
        credential_reflection,
        wildcard_methods,
        wildcard_headers,
        allowed_methods: methods,
        allowed_headers: headers_list,
        issues,
    }
}

/// Maps an OriginTestKind to its corresponding CorsMisconfigKind for PoC generation.
pub fn origin_test_to_misconfig_kind(kind: &OriginTestKind) -> CorsMisconfigKind {
    match kind {
        OriginTestKind::Null => CorsMisconfigKind::NullOriginBypass,
        OriginTestKind::Subdomain => CorsMisconfigKind::SubdomainWildcard,
        OriginTestKind::Sibling => CorsMisconfigKind::SubdomainWildcard,
        OriginTestKind::Attacker => CorsMisconfigKind::OriginReflection,
        OriginTestKind::RegexBypassPrefix => CorsMisconfigKind::RegexBypass,
        OriginTestKind::RegexBypassSuffix => CorsMisconfigKind::RegexBypass,
        OriginTestKind::InternalNetwork => CorsMisconfigKind::InternalNetworkAccess,
        OriginTestKind::Wildcard => CorsMisconfigKind::WildcardExposure,
        OriginTestKind::HttpDowngrade => CorsMisconfigKind::OriginReflection,
    }
}

/// Classifies the business impact of a CORS misconfiguration based on credential
/// reflection, scope, and misconfig kind.
pub fn classify_impact(
    severity: CorsSeverity,
    credentials_allowed: bool,
    kind: &OriginTestKind,
) -> ImpactClassification {
    let mut categories = Vec::new();

    if credentials_allowed {
        categories.push(ImpactCategory::CredentialTheft);
        categories.push(ImpactCategory::SessionHijack);
        categories.push(ImpactCategory::CsrfTokenLeak);
    }

    match kind {
        OriginTestKind::InternalNetwork => {
            categories.push(ImpactCategory::InternalNetworkPivot);
            categories.push(ImpactCategory::DataExfiltration);
        }
        OriginTestKind::Attacker
        | OriginTestKind::RegexBypassPrefix
        | OriginTestKind::RegexBypassSuffix => {
            categories.push(ImpactCategory::DataExfiltration);
            if credentials_allowed {
                categories.push(ImpactCategory::AccountTakeover);
            }
        }
        OriginTestKind::Subdomain | OriginTestKind::Sibling => {
            categories.push(ImpactCategory::DataExfiltration);
            if credentials_allowed {
                categories.push(ImpactCategory::AccountTakeover);
                categories.push(ImpactCategory::PiiExposure);
            }
        }
        OriginTestKind::Null => {
            categories.push(ImpactCategory::DataExfiltration);
            if credentials_allowed {
                categories.push(ImpactCategory::AccountTakeover);
            }
        }
        OriginTestKind::HttpDowngrade => {
            categories.push(ImpactCategory::DataExfiltration);
            if credentials_allowed {
                categories.push(ImpactCategory::SessionHijack);
            }
        }
        OriginTestKind::Wildcard => {
            categories.push(ImpactCategory::DataExfiltration);
        }
    }

    let cvss_estimate = match severity {
        CorsSeverity::Critical => 9.1,
        CorsSeverity::High => 7.5,
        CorsSeverity::Medium => 5.3,
        CorsSeverity::Low => 3.1,
    };

    let business_impact = build_business_impact_description(&severity, &categories);

    ImpactClassification {
        severity,
        categories,
        business_impact,
        cvss_estimate,
    }
}

fn build_business_impact_description(
    severity: &CorsSeverity,
    categories: &[ImpactCategory],
) -> String {
    let cat_names: Vec<String> = categories.iter().map(|c| c.to_string()).collect();
    let cat_str = cat_names.join(", ");

    match severity {
        CorsSeverity::Critical => format!(
            "CRITICAL: Immediate risk of {cat_str}. Attacker can read authenticated responses \
             cross-origin, leading to full account compromise. Remediate immediately."
        ),
        CorsSeverity::High => format!(
            "HIGH: Significant risk of {cat_str}. Cross-origin data readable by attacker-controlled \
             pages. Restrict ACAO to specific trusted origins."
        ),
        CorsSeverity::Medium => format!(
            "MEDIUM: Moderate risk of {cat_str}. Misconfiguration exploitable under specific \
             conditions (e.g., subdomain compromise, cache poisoning window)."
        ),
        CorsSeverity::Low => format!(
            "LOW: Limited risk of {cat_str}. Public data exposure or informational misconfiguration \
             with minimal direct exploitation potential."
        ),
    }
}

/// Generates a PoC HTML page for a specific origin test result.
pub fn generate_poc_for_result(result: &OriginTestResult, target_url: &str) -> String {
    let kind = origin_test_to_misconfig_kind(&result.test.kind);
    generate_poc_html(kind, target_url, &result.test.origin_value)
}

/// Determines severity from origin test result characteristics.
pub fn determine_severity(
    result: &OriginTestResult,
    wildcard_with_credentials: bool,
) -> CorsSeverity {
    if wildcard_with_credentials {
        return CorsSeverity::Critical;
    }

    let creds = result.credentials_allowed;
    match &result.test.kind {
        OriginTestKind::InternalNetwork if result.reflected => CorsSeverity::Critical,
        OriginTestKind::Attacker if result.reflected && creds => CorsSeverity::Critical,
        OriginTestKind::Null if result.reflected && creds => CorsSeverity::Critical,
        OriginTestKind::Subdomain if result.reflected && creds => CorsSeverity::Critical,
        OriginTestKind::Sibling if result.reflected && creds => CorsSeverity::Critical,
        OriginTestKind::RegexBypassPrefix if result.reflected && creds => CorsSeverity::Critical,
        OriginTestKind::RegexBypassSuffix if result.reflected && creds => CorsSeverity::Critical,
        OriginTestKind::HttpDowngrade if result.reflected && creds => CorsSeverity::High,
        _ if result.reflected && creds => CorsSeverity::High,
        _ if result.reflected => CorsSeverity::Medium,
        _ => CorsSeverity::Low,
    }
}

/// Checks if a subdomain takeover chain is possible by combining CORS trust
/// with potential subdomain takeover indicators.
pub fn detect_subdomain_takeover_chain(
    origin_results: &[OriginTestResult],
    takeover_candidates: &[String],
) -> bool {
    let subdomain_trusted = origin_results.iter().any(|r| {
        (r.test.kind == OriginTestKind::Subdomain || r.test.kind == OriginTestKind::Sibling)
            && r.reflected
    });

    if !subdomain_trusted {
        return false;
    }

    !takeover_candidates.is_empty()
}

/// Runs the complete V2 CORS scan pipeline on a set of simulated response headers.
/// Used for offline / unit-test analysis where HTTP responses are pre-collected.
pub fn run_v2_analysis(
    endpoint: &str,
    domain: &str,
    response_map: &HashMap<String, HashMap<String, String>>,
    preflight_headers: Option<&HashMap<String, String>>,
    takeover_candidates: &[String],
) -> CorsV2ScanResult {
    let origin_tests = generate_origin_tests(domain);

    let origin_results: Vec<OriginTestResult> = origin_tests
        .iter()
        .map(|test| {
            let headers = response_map
                .get(&test.origin_value)
                .cloned()
                .unwrap_or_default();
            analyze_origin_test(test, &headers)
        })
        .collect();

    let preflight = preflight_headers.map(analyze_preflight);

    let wildcard_with_credentials = origin_results
        .iter()
        .any(|r| r.response_origin.as_deref() == Some("*") && r.credentials_allowed);

    let vulnerable_results: Vec<&OriginTestResult> =
        origin_results.iter().filter(|r| r.reflected).collect();

    let max_severity = if vulnerable_results.is_empty() {
        None
    } else {
        vulnerable_results
            .iter()
            .map(|r| determine_severity(r, wildcard_with_credentials))
            .max()
    };

    let impact = max_severity.map(|sev| {
        let most_severe = vulnerable_results
            .iter()
            .max_by_key(|r| determine_severity(r, wildcard_with_credentials))
            .unwrap();
        classify_impact(sev, most_severe.credentials_allowed, &most_severe.test.kind)
    });

    let subdomain_takeover_chain =
        detect_subdomain_takeover_chain(&origin_results, takeover_candidates);

    let probes = generate_probes(endpoint, domain);
    let probe_results: Vec<CorsProbeResult> = probes
        .iter()
        .map(|probe| {
            let headers = response_map.get(&probe.origin).cloned().unwrap_or_default();
            let cors_headers = CorsHeaders::from_header_map(&headers);
            analyze_probe(probe, &cors_headers)
        })
        .collect();

    let exploit_report = build_report(endpoint, domain, &probe_results);

    CorsV2ScanResult {
        endpoint: endpoint.to_string(),
        domain: domain.to_string(),
        origin_tests: origin_results,
        preflight,
        exploit_report,
        impact,
        subdomain_takeover_chain,
    }
}

/// Converts V2 severity to numeric CVSS-like score for sorting/comparison.
pub fn severity_to_score(severity: &CorsSeverity) -> f64 {
    match severity {
        CorsSeverity::Critical => 9.0,
        CorsSeverity::High => 7.0,
        CorsSeverity::Medium => 5.0,
        CorsSeverity::Low => 3.0,
    }
}

/// Summary statistics from a V2 scan for reporting.
#[derive(Debug, Clone)]
pub struct CorsV2Summary {
    pub total_origins_tested: usize,
    pub reflected_count: usize,
    pub credentials_exposed_count: usize,
    pub max_severity: Option<CorsSeverity>,
    pub chain_attack_count: usize,
    pub has_subdomain_takeover_chain: bool,
    pub poc_count: usize,
}

/// Builds a summary from a V2 scan result.
pub fn summarize_v2_result(result: &CorsV2ScanResult) -> CorsV2Summary {
    let reflected_count = result.origin_tests.iter().filter(|r| r.reflected).count();
    let credentials_exposed_count = result
        .origin_tests
        .iter()
        .filter(|r| r.reflected && r.credentials_allowed)
        .count();
    let poc_count = result
        .origin_tests
        .iter()
        .filter(|r| r.poc_html.is_some())
        .count();

    CorsV2Summary {
        total_origins_tested: result.origin_tests.len(),
        reflected_count,
        credentials_exposed_count,
        max_severity: result.impact.as_ref().map(|i| i.severity),
        chain_attack_count: result.exploit_report.chain_attacks.len(),
        has_subdomain_takeover_chain: result.subdomain_takeover_chain,
        poc_count,
    }
}
