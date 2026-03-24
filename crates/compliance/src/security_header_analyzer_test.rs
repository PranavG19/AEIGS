use super::security_header_analyzer::*;
use std::collections::HashMap;

fn headers_with(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn missing_all_headers_grades_f() {
    let report = analyze_headers(&HashMap::new());
    assert_eq!(report.overall_grade, Grade::F);
    for a in &report.header_analyses {
        assert!(!a.present);
        assert_eq!(a.grade, Grade::F);
    }
}

#[test]
fn csp_missing_grades_f() {
    let report = analyze_headers(&HashMap::new());
    let csp = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::ContentSecurityPolicy)
        .unwrap();
    assert_eq!(csp.grade, Grade::F);
    assert!(!csp.present);
}

#[test]
fn csp_strict_policy_grades_a() {
    let h = headers_with(&[(
        "content-security-policy",
        "default-src 'self'; script-src 'nonce-abc123'; object-src 'none'; base-uri 'self'",
    )]);
    let report = analyze_headers(&h);
    let csp = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::ContentSecurityPolicy)
        .unwrap();
    assert_eq!(csp.grade, Grade::A);
    assert!(csp.present);
}

#[test]
fn csp_unsafe_inline_penalized() {
    let h = headers_with(&[(
        "content-security-policy",
        "default-src 'self'; script-src 'unsafe-inline'; object-src 'none'; base-uri 'self'",
    )]);
    let report = analyze_headers(&h);
    let csp = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::ContentSecurityPolicy)
        .unwrap();
    assert!(csp.grade >= Grade::C);
    assert!(csp.findings.iter().any(|f| f.contains("unsafe-inline")));
}

#[test]
fn csp_unsafe_eval_penalized() {
    let h = headers_with(&[(
        "content-security-policy",
        "default-src 'self'; script-src 'unsafe-eval'; object-src 'none'; base-uri 'self'",
    )]);
    let report = analyze_headers(&h);
    let csp = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::ContentSecurityPolicy)
        .unwrap();
    assert!(csp.grade >= Grade::C);
    assert!(csp.findings.iter().any(|f| f.contains("unsafe-eval")));
}

#[test]
fn csp_wildcard_penalized() {
    let h = headers_with(&[(
        "content-security-policy",
        "default-src *; object-src 'none'; base-uri 'self'",
    )]);
    let report = analyze_headers(&h);
    let csp = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::ContentSecurityPolicy)
        .unwrap();
    assert!(csp.grade >= Grade::B);
    assert!(csp.findings.iter().any(|f| f.contains("wildcard")));
}

#[test]
fn csp_directive_parsing_extracts_nonce() {
    let h = headers_with(&[(
        "content-security-policy",
        "script-src 'nonce-r4nd0m' 'strict-dynamic'",
    )]);
    let report = analyze_headers(&h);
    let nonce_directive = report
        .csp_directives
        .iter()
        .find(|d| d.directive == "script-src")
        .unwrap();
    assert!(nonce_directive.has_nonce);
    assert!(!nonce_directive.has_unsafe_inline);
}

#[test]
fn csp_directive_parsing_extracts_hash() {
    let h = headers_with(&[("content-security-policy", "script-src 'sha256-abc123'")]);
    let report = analyze_headers(&h);
    let d = report
        .csp_directives
        .iter()
        .find(|d| d.directive == "script-src")
        .unwrap();
    assert!(d.has_hash);
}

#[test]
fn hsts_full_config_grades_a() {
    let h = headers_with(&[(
        "strict-transport-security",
        "max-age=63072000; includeSubDomains; preload",
    )]);
    let report = analyze_headers(&h);
    let hsts = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::StrictTransportSecurity)
        .unwrap();
    assert_eq!(hsts.grade, Grade::A);
}

#[test]
fn hsts_short_max_age_penalized() {
    let h = headers_with(&[("strict-transport-security", "max-age=3600")]);
    let report = analyze_headers(&h);
    let hsts = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::StrictTransportSecurity)
        .unwrap();
    assert!(hsts.grade >= Grade::D);
    assert!(hsts
        .findings
        .iter()
        .any(|f| f.contains("dangerously short")));
}

#[test]
fn hsts_missing_preload_noted() {
    let h = headers_with(&[(
        "strict-transport-security",
        "max-age=31536000; includeSubDomains",
    )]);
    let report = analyze_headers(&h);
    let hsts = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::StrictTransportSecurity)
        .unwrap();
    assert!(hsts.findings.iter().any(|f| f.contains("preload")));
    assert_eq!(hsts.grade, Grade::B);
}

#[test]
fn xcto_nosniff_grades_a() {
    let h = headers_with(&[("x-content-type-options", "nosniff")]);
    let report = analyze_headers(&h);
    let xcto = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::XContentTypeOptions)
        .unwrap();
    assert_eq!(xcto.grade, Grade::A);
}

#[test]
fn xcto_invalid_value_grades_d() {
    let h = headers_with(&[("x-content-type-options", "sniff")]);
    let report = analyze_headers(&h);
    let xcto = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::XContentTypeOptions)
        .unwrap();
    assert_eq!(xcto.grade, Grade::D);
}

#[test]
fn xfo_deny_grades_a() {
    let h = headers_with(&[("x-frame-options", "DENY")]);
    let report = analyze_headers(&h);
    let xfo = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::XFrameOptions)
        .unwrap();
    assert_eq!(xfo.grade, Grade::A);
}

#[test]
fn xfo_sameorigin_grades_b() {
    let h = headers_with(&[("x-frame-options", "SAMEORIGIN")]);
    let report = analyze_headers(&h);
    let xfo = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::XFrameOptions)
        .unwrap();
    assert_eq!(xfo.grade, Grade::B);
}

#[test]
fn xfo_allow_from_deprecated_grades_d() {
    let h = headers_with(&[("x-frame-options", "ALLOW-FROM https://example.com")]);
    let report = analyze_headers(&h);
    let xfo = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::XFrameOptions)
        .unwrap();
    assert_eq!(xfo.grade, Grade::D);
    assert!(xfo.findings.iter().any(|f| f.contains("deprecated")));
}

#[test]
fn referrer_no_referrer_grades_a() {
    let h = headers_with(&[("referrer-policy", "no-referrer")]);
    let report = analyze_headers(&h);
    let rp = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::ReferrerPolicy)
        .unwrap();
    assert_eq!(rp.grade, Grade::A);
}

#[test]
fn referrer_unsafe_url_grades_f() {
    let h = headers_with(&[("referrer-policy", "unsafe-url")]);
    let report = analyze_headers(&h);
    let rp = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::ReferrerPolicy)
        .unwrap();
    assert_eq!(rp.grade, Grade::F);
}

#[test]
fn permissions_all_restricted_grades_a() {
    let h = headers_with(&[(
        "permissions-policy",
        "camera=(), microphone=(), geolocation=(), payment=()",
    )]);
    let report = analyze_headers(&h);
    let pp = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::PermissionsPolicy)
        .unwrap();
    assert_eq!(pp.grade, Grade::A);
}

#[test]
fn permissions_partial_restrictions_grades_below_a() {
    let h = headers_with(&[("permissions-policy", "camera=(), microphone=()")]);
    let report = analyze_headers(&h);
    let pp = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::PermissionsPolicy)
        .unwrap();
    assert!(pp.grade > Grade::A);
}

#[test]
fn coep_require_corp_grades_a() {
    let h = headers_with(&[("cross-origin-embedder-policy", "require-corp")]);
    let report = analyze_headers(&h);
    let coep = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::CrossOriginEmbedderPolicy)
        .unwrap();
    assert_eq!(coep.grade, Grade::A);
}

#[test]
fn coop_same_origin_grades_a() {
    let h = headers_with(&[("cross-origin-opener-policy", "same-origin")]);
    let report = analyze_headers(&h);
    let coop = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::CrossOriginOpenerPolicy)
        .unwrap();
    assert_eq!(coop.grade, Grade::A);
}

#[test]
fn corp_same_origin_grades_a() {
    let h = headers_with(&[("cross-origin-resource-policy", "same-origin")]);
    let report = analyze_headers(&h);
    let corp = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::CrossOriginResourcePolicy)
        .unwrap();
    assert_eq!(corp.grade, Grade::A);
}

#[test]
fn corp_cross_origin_grades_d() {
    let h = headers_with(&[("cross-origin-resource-policy", "cross-origin")]);
    let report = analyze_headers(&h);
    let corp = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::CrossOriginResourcePolicy)
        .unwrap();
    assert_eq!(corp.grade, Grade::D);
}

#[test]
fn cache_control_no_store_grades_a() {
    let h = headers_with(&[("cache-control", "no-store, no-cache, private")]);
    let report = analyze_headers(&h);
    let cc = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::CacheControl)
        .unwrap();
    assert_eq!(cc.grade, Grade::A);
}

#[test]
fn cache_control_public_without_no_store_penalized() {
    let h = headers_with(&[("cache-control", "public, max-age=3600")]);
    let report = analyze_headers(&h);
    let cc = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::CacheControl)
        .unwrap();
    assert!(cc.grade >= Grade::C);
    assert!(cc.findings.iter().any(|f| f.contains("public")));
}

#[test]
fn cookie_all_flags_grades_a() {
    let h = headers_with(&[(
        "set-cookie",
        "__Host-session=abc; Secure; HttpOnly; SameSite=Strict; Path=/",
    )]);
    let report = analyze_headers(&h);
    assert_eq!(report.cookie_analyses.len(), 1);
    let cookie = &report.cookie_analyses[0];
    assert_eq!(cookie.grade, Grade::A);
    assert!(cookie.has_secure);
    assert!(cookie.has_httponly);
    assert_eq!(cookie.samesite.as_deref(), Some("strict"));
    assert!(cookie.has_host_prefix);
}

#[test]
fn cookie_missing_secure_penalized() {
    let h = headers_with(&[("set-cookie", "session=abc; HttpOnly; SameSite=Strict")]);
    let report = analyze_headers(&h);
    let cookie = &report.cookie_analyses[0];
    assert!(!cookie.has_secure);
    assert!(cookie.grade >= Grade::C);
    assert!(cookie.findings.iter().any(|f| f.contains("Secure")));
}

#[test]
fn cookie_missing_httponly_penalized() {
    let h = headers_with(&[("set-cookie", "session=abc; Secure; SameSite=Strict")]);
    let report = analyze_headers(&h);
    let cookie = &report.cookie_analyses[0];
    assert!(!cookie.has_httponly);
    assert!(cookie.grade >= Grade::C);
    assert!(cookie.findings.iter().any(|f| f.contains("HttpOnly")));
}

#[test]
fn cookie_samesite_none_penalized() {
    let h = headers_with(&[("set-cookie", "session=abc; Secure; HttpOnly; SameSite=None")]);
    let report = analyze_headers(&h);
    let cookie = &report.cookie_analyses[0];
    assert_eq!(cookie.samesite.as_deref(), Some("none"));
    assert!(cookie.grade >= Grade::B);
}

#[test]
fn cookie_secure_prefix_detected() {
    let h = headers_with(&[(
        "set-cookie",
        "__Secure-token=xyz; Secure; HttpOnly; SameSite=Strict",
    )]);
    let report = analyze_headers(&h);
    let cookie = &report.cookie_analyses[0];
    assert!(cookie.has_secure_prefix);
    assert!(!cookie.has_host_prefix);
}

#[test]
fn reporting_endpoints_grades_a() {
    let h = headers_with(&[(
        "reporting-endpoints",
        "csp-endpoint=\"https://example.com/csp-report\"",
    )]);
    let report = analyze_headers(&h);
    let rep = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::ReportingEndpoints)
        .unwrap();
    assert_eq!(rep.grade, Grade::A);
    assert!(rep.present);
}

#[test]
fn legacy_report_to_grades_b() {
    let h = headers_with(&[(
        "report-to",
        "{\"group\":\"csp\",\"max_age\":86400,\"endpoints\":[{\"url\":\"https://example.com\"}]}",
    )]);
    let report = analyze_headers(&h);
    let rep = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::ReportingEndpoints)
        .unwrap();
    assert_eq!(rep.grade, Grade::B);
}

#[test]
fn analyze_header_pairs_merges_duplicates() {
    let pairs = vec![
        (
            "Set-Cookie".to_string(),
            "a=1; Secure; HttpOnly; SameSite=Strict".to_string(),
        ),
        (
            "Set-Cookie".to_string(),
            "b=2; Secure; HttpOnly; SameSite=Strict".to_string(),
        ),
    ];
    let report = analyze_header_pairs(&pairs);
    assert!(report.cookie_analyses.len() >= 2);
}

#[test]
fn overall_grade_a_when_all_configured() {
    let h = headers_with(&[
        (
            "content-security-policy",
            "default-src 'self'; script-src 'nonce-x'; object-src 'none'; base-uri 'self'",
        ),
        (
            "strict-transport-security",
            "max-age=63072000; includeSubDomains; preload",
        ),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        (
            "permissions-policy",
            "camera=(), microphone=(), geolocation=(), payment=()",
        ),
        ("cross-origin-embedder-policy", "require-corp"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
        ("cache-control", "no-store, no-cache, private"),
        (
            "set-cookie",
            "__Host-s=x; Secure; HttpOnly; SameSite=Strict; Path=/",
        ),
        (
            "reporting-endpoints",
            "default=\"https://example.com/report\"",
        ),
    ]);
    let report = analyze_headers(&h);
    assert_eq!(report.overall_grade, Grade::A);
}

#[test]
fn grade_display_formatting() {
    assert_eq!(Grade::A.to_string(), "A");
    assert_eq!(Grade::F.to_string(), "F");
}

#[test]
fn grade_ordering() {
    assert!(Grade::A < Grade::B);
    assert!(Grade::B < Grade::C);
    assert!(Grade::D < Grade::F);
}

#[test]
fn header_type_display() {
    assert_eq!(
        HeaderType::ContentSecurityPolicy.to_string(),
        "Content-Security-Policy"
    );
    assert_eq!(HeaderType::SetCookie.to_string(), "Set-Cookie");
}

#[test]
fn csp_data_uri_detected() {
    let h = headers_with(&[(
        "content-security-policy",
        "default-src 'self'; script-src data:; object-src 'none'; base-uri 'self'",
    )]);
    let report = analyze_headers(&h);
    let d = report
        .csp_directives
        .iter()
        .find(|d| d.directive == "script-src")
        .unwrap();
    assert!(d.has_data_uri);
}

#[test]
fn coep_credentialless_grades_b() {
    let h = headers_with(&[("cross-origin-embedder-policy", "credentialless")]);
    let report = analyze_headers(&h);
    let coep = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::CrossOriginEmbedderPolicy)
        .unwrap();
    assert_eq!(coep.grade, Grade::B);
}

#[test]
fn coop_allow_popups_grades_b() {
    let h = headers_with(&[("cross-origin-opener-policy", "same-origin-allow-popups")]);
    let report = analyze_headers(&h);
    let coop = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::CrossOriginOpenerPolicy)
        .unwrap();
    assert_eq!(coop.grade, Grade::B);
}

#[test]
fn referrer_strict_origin_grades_b() {
    let h = headers_with(&[("referrer-policy", "strict-origin")]);
    let report = analyze_headers(&h);
    let rp = report
        .header_analyses
        .iter()
        .find(|a| a.header_type == HeaderType::ReferrerPolicy)
        .unwrap();
    assert_eq!(rp.grade, Grade::B);
}

#[test]
fn all_twelve_header_types_analyzed() {
    let report = analyze_headers(&HashMap::new());
    let unique_types: std::collections::HashSet<_> = report
        .header_analyses
        .iter()
        .map(|a| std::mem::discriminant(&a.header_type))
        .collect();
    assert!(
        unique_types.len() >= 12,
        "Expected 12+ header types, got {}",
        unique_types.len()
    );
}

#[test]
fn every_analysis_has_remediation() {
    let report = analyze_headers(&HashMap::new());
    for a in &report.header_analyses {
        assert!(
            !a.remediation.is_empty(),
            "Missing remediation for {:?}",
            a.header_type
        );
    }
}
