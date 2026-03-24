use std::collections::HashMap;

use aegis_evasion_engine::CorsMisconfigKind;
use aegis_evasion_engine::CorsSeverity;

use crate::cors_scanner_v2::*;

fn make_headers(acao: Option<&str>, acac: Option<bool>) -> HashMap<String, String> {
    let mut h = HashMap::new();
    if let Some(origin) = acao {
        h.insert(
            "access-control-allow-origin".to_string(),
            origin.to_string(),
        );
    }
    if let Some(creds) = acac {
        h.insert(
            "access-control-allow-credentials".to_string(),
            creds.to_string(),
        );
    }
    h
}

fn make_preflight_headers(
    max_age: Option<u64>,
    methods: Option<&str>,
    headers: Option<&str>,
    credentials: bool,
) -> HashMap<String, String> {
    let mut h = HashMap::new();
    if let Some(age) = max_age {
        h.insert("access-control-max-age".to_string(), age.to_string());
    }
    if let Some(m) = methods {
        h.insert("access-control-allow-methods".to_string(), m.to_string());
    }
    if let Some(hdr) = headers {
        h.insert("access-control-allow-headers".to_string(), hdr.to_string());
    }
    if credentials {
        h.insert(
            "access-control-allow-credentials".to_string(),
            "true".to_string(),
        );
    }
    h
}

#[test]
fn test_generate_origin_tests_produces_at_least_seven() {
    let tests = generate_origin_tests("example.com");
    assert!(
        tests.len() >= 7,
        "expected >= 7 origin tests, got {}",
        tests.len()
    );
}

#[test]
fn test_generate_origin_tests_includes_null() {
    let tests = generate_origin_tests("example.com");
    assert!(tests.iter().any(|t| t.kind == OriginTestKind::Null));
}

#[test]
fn test_generate_origin_tests_includes_subdomain() {
    let tests = generate_origin_tests("example.com");
    let sub = tests
        .iter()
        .find(|t| t.kind == OriginTestKind::Subdomain)
        .unwrap();
    assert!(sub.origin_value.contains("evil.example.com"));
}

#[test]
fn test_generate_origin_tests_includes_sibling() {
    let tests = generate_origin_tests("app.example.com");
    let sib = tests
        .iter()
        .find(|t| t.kind == OriginTestKind::Sibling)
        .unwrap();
    assert!(sib.origin_value.contains("sibling.example.com"));
}

#[test]
fn test_generate_origin_tests_includes_attacker() {
    let tests = generate_origin_tests("example.com");
    assert!(tests.iter().any(|t| t.kind == OriginTestKind::Attacker));
}

#[test]
fn test_generate_origin_tests_includes_regex_bypass_prefix() {
    let tests = generate_origin_tests("example.com");
    let bp = tests
        .iter()
        .find(|t| t.kind == OriginTestKind::RegexBypassPrefix)
        .unwrap();
    assert!(bp.origin_value.contains("evil-example.com"));
}

#[test]
fn test_generate_origin_tests_includes_regex_bypass_suffix() {
    let tests = generate_origin_tests("example.com");
    let bs = tests
        .iter()
        .find(|t| t.kind == OriginTestKind::RegexBypassSuffix)
        .unwrap();
    assert!(bs.origin_value.contains("example.com.evil.com"));
}

#[test]
fn test_generate_origin_tests_includes_internal_network() {
    let tests = generate_origin_tests("example.com");
    let internal = tests
        .iter()
        .find(|t| t.kind == OriginTestKind::InternalNetwork)
        .unwrap();
    assert!(internal.origin_value.contains("192.168"));
}

#[test]
fn test_generate_origin_tests_includes_http_downgrade() {
    let tests = generate_origin_tests("example.com");
    let dg = tests
        .iter()
        .find(|t| t.kind == OriginTestKind::HttpDowngrade)
        .unwrap();
    assert_eq!(dg.origin_value, "http://example.com");
}

#[test]
fn test_analyze_origin_test_reflected() {
    let test = OriginTest {
        kind: OriginTestKind::Attacker,
        origin_value: "https://evil-attacker.com".to_string(),
        include_credentials: true,
    };
    let headers = make_headers(Some("https://evil-attacker.com"), Some(true));
    let result = analyze_origin_test(&test, &headers);

    assert!(result.reflected);
    assert!(result.credentials_allowed);
    assert!(result.poc_html.is_some());
}

#[test]
fn test_analyze_origin_test_not_reflected() {
    let test = OriginTest {
        kind: OriginTestKind::Attacker,
        origin_value: "https://evil-attacker.com".to_string(),
        include_credentials: true,
    };
    let headers = make_headers(Some("https://allowed.example.com"), None);
    let result = analyze_origin_test(&test, &headers);

    assert!(!result.reflected);
    assert!(result.poc_html.is_none());
}

#[test]
fn test_analyze_origin_test_wildcard_reflected() {
    let test = OriginTest {
        kind: OriginTestKind::Wildcard,
        origin_value: "https://wildcard-check.example.org".to_string(),
        include_credentials: false,
    };
    let headers = make_headers(Some("*"), None);
    let result = analyze_origin_test(&test, &headers);

    assert!(result.reflected);
    assert_eq!(result.response_origin, Some("*".to_string()));
}

#[test]
fn test_analyze_origin_test_null_reflected() {
    let test = OriginTest {
        kind: OriginTestKind::Null,
        origin_value: "null".to_string(),
        include_credentials: true,
    };
    let headers = make_headers(Some("null"), Some(true));
    let result = analyze_origin_test(&test, &headers);

    assert!(result.reflected);
    assert!(result.credentials_allowed);
}

#[test]
fn test_analyze_origin_test_no_cors_headers() {
    let test = OriginTest {
        kind: OriginTestKind::Attacker,
        origin_value: "https://evil-attacker.com".to_string(),
        include_credentials: true,
    };
    let headers = HashMap::new();
    let result = analyze_origin_test(&test, &headers);

    assert!(!result.reflected);
    assert!(!result.credentials_allowed);
    assert!(result.poc_html.is_none());
}

#[test]
fn test_analyze_preflight_excessive_cache() {
    let headers = make_preflight_headers(Some(100_000), Some("GET, POST"), None, false);
    let result = analyze_preflight(&headers);

    assert_eq!(result.cache_duration_seconds, Some(100_000));
    assert!(!result.issues.is_empty());
    assert!(result.issues.iter().any(|i| i.contains("24h")));
}

#[test]
fn test_analyze_preflight_moderate_cache() {
    let headers = make_preflight_headers(Some(10_000), Some("GET, POST"), None, false);
    let result = analyze_preflight(&headers);

    assert_eq!(result.cache_duration_seconds, Some(10_000));
    assert!(result.issues.iter().any(|i| i.contains("2h")));
}

#[test]
fn test_analyze_preflight_acceptable_cache() {
    let headers = make_preflight_headers(Some(600), Some("GET"), None, false);
    let result = analyze_preflight(&headers);

    assert_eq!(result.cache_duration_seconds, Some(600));
    assert!(result.issues.is_empty());
}

#[test]
fn test_analyze_preflight_wildcard_methods() {
    let headers = make_preflight_headers(None, Some("*"), None, false);
    let result = analyze_preflight(&headers);

    assert!(result.wildcard_methods);
    assert!(result.issues.iter().any(|i| i.contains("Wildcard methods")));
}

#[test]
fn test_analyze_preflight_wildcard_headers() {
    let headers = make_preflight_headers(None, Some("GET"), Some("*"), false);
    let result = analyze_preflight(&headers);

    assert!(result.wildcard_headers);
    assert!(result.issues.iter().any(|i| i.contains("Wildcard headers")));
}

#[test]
fn test_analyze_preflight_credentials() {
    let headers = make_preflight_headers(None, Some("GET"), None, true);
    let result = analyze_preflight(&headers);

    assert!(result.credential_reflection);
    assert!(result.issues.iter().any(|i| i.contains("credentials")));
}

#[test]
fn test_classify_impact_critical_with_credentials() {
    let impact = classify_impact(CorsSeverity::Critical, true, &OriginTestKind::Attacker);

    assert_eq!(impact.severity, CorsSeverity::Critical);
    assert!(impact.categories.contains(&ImpactCategory::CredentialTheft));
    assert!(impact.categories.contains(&ImpactCategory::AccountTakeover));
    assert!(impact.cvss_estimate > 9.0);
    assert!(impact.business_impact.contains("CRITICAL"));
}

#[test]
fn test_classify_impact_medium_no_credentials() {
    let impact = classify_impact(CorsSeverity::Medium, false, &OriginTestKind::Wildcard);

    assert_eq!(impact.severity, CorsSeverity::Medium);
    assert!(impact
        .categories
        .contains(&ImpactCategory::DataExfiltration));
    assert!(!impact.categories.contains(&ImpactCategory::CredentialTheft));
}

#[test]
fn test_classify_impact_internal_network() {
    let impact = classify_impact(
        CorsSeverity::Critical,
        false,
        &OriginTestKind::InternalNetwork,
    );

    assert!(impact
        .categories
        .contains(&ImpactCategory::InternalNetworkPivot));
}

#[test]
fn test_determine_severity_critical_attacker_with_creds() {
    let result = OriginTestResult {
        test: OriginTest {
            kind: OriginTestKind::Attacker,
            origin_value: "https://evil.com".to_string(),
            include_credentials: true,
        },
        reflected: true,
        credentials_allowed: true,
        response_origin: Some("https://evil.com".to_string()),
        poc_html: Some("html".to_string()),
    };

    assert_eq!(determine_severity(&result, false), CorsSeverity::Critical);
}

#[test]
fn test_determine_severity_medium_reflected_no_creds() {
    let result = OriginTestResult {
        test: OriginTest {
            kind: OriginTestKind::Attacker,
            origin_value: "https://evil.com".to_string(),
            include_credentials: true,
        },
        reflected: true,
        credentials_allowed: false,
        response_origin: Some("https://evil.com".to_string()),
        poc_html: Some("html".to_string()),
    };

    assert_eq!(determine_severity(&result, false), CorsSeverity::Medium);
}

#[test]
fn test_determine_severity_low_not_reflected() {
    let result = OriginTestResult {
        test: OriginTest {
            kind: OriginTestKind::Attacker,
            origin_value: "https://evil.com".to_string(),
            include_credentials: true,
        },
        reflected: false,
        credentials_allowed: false,
        response_origin: None,
        poc_html: None,
    };

    assert_eq!(determine_severity(&result, false), CorsSeverity::Low);
}

#[test]
fn test_determine_severity_wildcard_with_credentials_critical() {
    let result = OriginTestResult {
        test: OriginTest {
            kind: OriginTestKind::Wildcard,
            origin_value: "https://test.com".to_string(),
            include_credentials: false,
        },
        reflected: true,
        credentials_allowed: true,
        response_origin: Some("*".to_string()),
        poc_html: None,
    };

    assert_eq!(determine_severity(&result, true), CorsSeverity::Critical);
}

#[test]
fn test_detect_subdomain_takeover_chain_positive() {
    let results = vec![OriginTestResult {
        test: OriginTest {
            kind: OriginTestKind::Subdomain,
            origin_value: "https://evil.example.com".to_string(),
            include_credentials: true,
        },
        reflected: true,
        credentials_allowed: true,
        response_origin: Some("https://evil.example.com".to_string()),
        poc_html: Some("html".to_string()),
    }];

    let candidates = vec!["orphan.example.com".to_string()];
    assert!(detect_subdomain_takeover_chain(&results, &candidates));
}

#[test]
fn test_detect_subdomain_takeover_chain_no_candidates() {
    let results = vec![OriginTestResult {
        test: OriginTest {
            kind: OriginTestKind::Subdomain,
            origin_value: "https://evil.example.com".to_string(),
            include_credentials: true,
        },
        reflected: true,
        credentials_allowed: true,
        response_origin: Some("https://evil.example.com".to_string()),
        poc_html: Some("html".to_string()),
    }];

    assert!(!detect_subdomain_takeover_chain(&results, &[]));
}

#[test]
fn test_detect_subdomain_takeover_chain_not_reflected() {
    let results = vec![OriginTestResult {
        test: OriginTest {
            kind: OriginTestKind::Subdomain,
            origin_value: "https://evil.example.com".to_string(),
            include_credentials: true,
        },
        reflected: false,
        credentials_allowed: false,
        response_origin: None,
        poc_html: None,
    }];

    let candidates = vec!["orphan.example.com".to_string()];
    assert!(!detect_subdomain_takeover_chain(&results, &candidates));
}

#[test]
fn test_generate_poc_for_result() {
    let result = OriginTestResult {
        test: OriginTest {
            kind: OriginTestKind::Null,
            origin_value: "null".to_string(),
            include_credentials: true,
        },
        reflected: true,
        credentials_allowed: true,
        response_origin: Some("null".to_string()),
        poc_html: None,
    };

    let poc = generate_poc_for_result(&result, "https://target.com/api/data");
    assert!(poc.contains("target.com"));
    assert!(poc.contains("Null Origin"));
    assert!(poc.contains("iframe"));
}

#[test]
fn test_run_v2_analysis_full_pipeline() {
    let domain = "example.com";
    let endpoint = "https://example.com/api/user";

    let mut response_map: HashMap<String, HashMap<String, String>> = HashMap::new();

    response_map.insert("null".to_string(), make_headers(Some("null"), Some(true)));
    response_map.insert(
        "https://evil-attacker.com".to_string(),
        make_headers(Some("https://evil-attacker.com"), Some(true)),
    );
    response_map.insert(
        format!("https://evil.{domain}"),
        make_headers(Some(&format!("https://evil.{domain}")), Some(true)),
    );

    let preflight = make_preflight_headers(Some(100_000), Some("*"), Some("*"), true);

    let result = run_v2_analysis(
        endpoint,
        domain,
        &response_map,
        Some(&preflight),
        &["orphan.example.com".to_string()],
    );

    assert_eq!(result.endpoint, endpoint);
    assert_eq!(result.domain, domain);
    assert!(result.origin_tests.len() >= 7);
    assert!(result.preflight.is_some());

    let reflected_count = result.origin_tests.iter().filter(|r| r.reflected).count();
    assert!(
        reflected_count >= 3,
        "expected >= 3 reflected, got {reflected_count}"
    );

    assert!(result.impact.is_some());
    let impact = result.impact.unwrap();
    assert_eq!(impact.severity, CorsSeverity::Critical);

    assert!(result.subdomain_takeover_chain);
}

#[test]
fn test_run_v2_analysis_no_vulns() {
    let domain = "secure.example.com";
    let endpoint = "https://secure.example.com/api";

    let response_map: HashMap<String, HashMap<String, String>> = HashMap::new();

    let result = run_v2_analysis(endpoint, domain, &response_map, None, &[]);

    let reflected_count = result.origin_tests.iter().filter(|r| r.reflected).count();
    assert_eq!(reflected_count, 0);
    assert!(result.impact.is_none());
    assert!(!result.subdomain_takeover_chain);
}

#[test]
fn test_summarize_v2_result() {
    let domain = "example.com";
    let endpoint = "https://example.com/api";

    let mut response_map: HashMap<String, HashMap<String, String>> = HashMap::new();
    response_map.insert(
        "https://evil-attacker.com".to_string(),
        make_headers(Some("https://evil-attacker.com"), Some(true)),
    );
    response_map.insert("null".to_string(), make_headers(Some("null"), Some(true)));

    let result = run_v2_analysis(endpoint, domain, &response_map, None, &[]);
    let summary = summarize_v2_result(&result);

    assert!(summary.total_origins_tested >= 7);
    assert!(summary.reflected_count >= 2);
    assert!(summary.credentials_exposed_count >= 2);
    assert!(summary.poc_count >= 2);
}

#[test]
fn test_severity_to_score_ordering() {
    assert!(severity_to_score(&CorsSeverity::Critical) > severity_to_score(&CorsSeverity::High));
    assert!(severity_to_score(&CorsSeverity::High) > severity_to_score(&CorsSeverity::Medium));
    assert!(severity_to_score(&CorsSeverity::Medium) > severity_to_score(&CorsSeverity::Low));
}

#[test]
fn test_origin_test_kind_display() {
    assert_eq!(OriginTestKind::Null.to_string(), "null_origin");
    assert_eq!(OriginTestKind::Subdomain.to_string(), "subdomain");
    assert_eq!(OriginTestKind::Sibling.to_string(), "sibling_domain");
    assert_eq!(OriginTestKind::Attacker.to_string(), "attacker_domain");
    assert_eq!(
        OriginTestKind::RegexBypassPrefix.to_string(),
        "regex_bypass_prefix"
    );
    assert_eq!(
        OriginTestKind::RegexBypassSuffix.to_string(),
        "regex_bypass_suffix"
    );
    assert_eq!(
        OriginTestKind::InternalNetwork.to_string(),
        "internal_network"
    );
    assert_eq!(OriginTestKind::Wildcard.to_string(), "wildcard_test");
    assert_eq!(OriginTestKind::HttpDowngrade.to_string(), "http_downgrade");
}

#[test]
fn test_impact_category_display() {
    assert_eq!(
        ImpactCategory::CredentialTheft.to_string(),
        "Credential Theft"
    );
    assert_eq!(
        ImpactCategory::DataExfiltration.to_string(),
        "Data Exfiltration"
    );
    assert_eq!(
        ImpactCategory::InternalNetworkPivot.to_string(),
        "Internal Network Pivot"
    );
    assert_eq!(ImpactCategory::SessionHijack.to_string(), "Session Hijack");
    assert_eq!(
        ImpactCategory::AccountTakeover.to_string(),
        "Account Takeover"
    );
    assert_eq!(ImpactCategory::CsrfTokenLeak.to_string(), "CSRF Token Leak");
    assert_eq!(ImpactCategory::PiiExposure.to_string(), "PII Exposure");
}

#[test]
fn test_extract_parent_domain_subdomain() {
    let tests = generate_origin_tests("deep.sub.example.com");
    let sib = tests
        .iter()
        .find(|t| t.kind == OriginTestKind::Sibling)
        .unwrap();
    assert!(sib.origin_value.contains("sibling.example.com"));
}

#[test]
fn test_determine_severity_internal_network_critical() {
    let result = OriginTestResult {
        test: OriginTest {
            kind: OriginTestKind::InternalNetwork,
            origin_value: "http://192.168.1.1".to_string(),
            include_credentials: false,
        },
        reflected: true,
        credentials_allowed: false,
        response_origin: Some("http://192.168.1.1".to_string()),
        poc_html: Some("html".to_string()),
    };

    assert_eq!(determine_severity(&result, false), CorsSeverity::Critical);
}

#[test]
fn test_determine_severity_http_downgrade_with_creds() {
    let result = OriginTestResult {
        test: OriginTest {
            kind: OriginTestKind::HttpDowngrade,
            origin_value: "http://example.com".to_string(),
            include_credentials: true,
        },
        reflected: true,
        credentials_allowed: true,
        response_origin: Some("http://example.com".to_string()),
        poc_html: Some("html".to_string()),
    };

    assert_eq!(determine_severity(&result, false), CorsSeverity::High);
}

#[test]
fn test_origin_test_to_misconfig_kind_mapping() {
    assert_eq!(
        origin_test_to_misconfig_kind(&OriginTestKind::Null),
        CorsMisconfigKind::NullOriginBypass
    );
    assert_eq!(
        origin_test_to_misconfig_kind(&OriginTestKind::Attacker),
        CorsMisconfigKind::OriginReflection
    );
    assert_eq!(
        origin_test_to_misconfig_kind(&OriginTestKind::InternalNetwork),
        CorsMisconfigKind::InternalNetworkAccess
    );
}
