use super::cors_v3::*;

fn make_config() -> CorsConfig {
    CorsConfig::default().with_target("https://example.com/api", "example.com")
}

#[test]
fn generates_at_least_20_test_origins() {
    let origins = generate_test_origins("example.com");
    assert!(
        origins.len() >= 20,
        "should generate at least 20 test origins, got {}",
        origins.len()
    );

    let origin_strs: Vec<&str> = origins.iter().map(|(o, _)| o.as_str()).collect();
    assert!(origin_strs.contains(&"*"), "should include wildcard");
    assert!(origin_strs.contains(&"null"), "should include null");
    assert!(
        origin_strs.iter().any(|o| o.contains("evil")),
        "should include evil domains"
    );
    assert!(
        origin_strs.iter().any(|o| o.contains("localhost")),
        "should include localhost"
    );
    assert!(
        origin_strs.iter().any(|o| o.starts_with("http://")),
        "should include HTTP origins"
    );
}

#[test]
fn detects_wildcard_origin() {
    let config = make_config();
    let probes = vec![build_probe(
        "https://evil.com",
        Some("*"),
        None,
        None,
        None,
        None,
        Some("Origin"),
    )];

    let analysis = analyze_cors(&probes, &config);

    let wildcard = analysis
        .findings
        .iter()
        .find(|f| f.misconfig_type == CorsMisconfigType::WildcardOrigin);

    assert!(wildcard.is_some(), "should detect wildcard ACAO");
    assert_eq!(wildcard.unwrap().severity, CorsSeverity::Medium);
}

#[test]
fn detects_wildcard_with_credentials_is_critical() {
    let config = make_config();
    let probes = vec![build_probe(
        "https://evil.com",
        Some("*"),
        Some("true"),
        None,
        None,
        None,
        Some("Origin"),
    )];

    let analysis = analyze_cors(&probes, &config);

    let has_critical = analysis.findings.iter().any(|f| {
        f.misconfig_type == CorsMisconfigType::WildcardOrigin
            && f.severity == CorsSeverity::Critical
    });

    assert!(has_critical, "wildcard with credentials should be critical");
}

#[test]
fn detects_origin_reflection() {
    let config = make_config();
    let probes = vec![build_probe(
        "https://evil.com",
        Some("https://evil.com"),
        None,
        None,
        None,
        None,
        Some("Origin"),
    )];

    let analysis = analyze_cors(&probes, &config);

    let reflection = analysis
        .findings
        .iter()
        .find(|f| f.misconfig_type == CorsMisconfigType::OriginReflection);

    assert!(reflection.is_some(), "should detect origin reflection");
    assert_eq!(reflection.unwrap().severity, CorsSeverity::High);
}

#[test]
fn detects_origin_reflection_with_credentials() {
    let config = make_config();
    let probes = vec![build_probe(
        "https://evil.com",
        Some("https://evil.com"),
        Some("true"),
        None,
        None,
        None,
        Some("Origin"),
    )];

    let analysis = analyze_cors(&probes, &config);

    let has_critical = analysis.findings.iter().any(|f| {
        f.misconfig_type == CorsMisconfigType::OriginReflection
            && f.severity == CorsSeverity::Critical
    });

    assert!(
        has_critical,
        "origin reflection with credentials should be critical"
    );
}

#[test]
fn detects_null_origin() {
    let config = make_config();
    let probes = vec![build_probe(
        "null",
        Some("null"),
        Some("true"),
        None,
        None,
        None,
        Some("Origin"),
    )];

    let analysis = analyze_cors(&probes, &config);

    let null_finding = analysis
        .findings
        .iter()
        .find(|f| f.misconfig_type == CorsMisconfigType::NullOriginAllowed);

    assert!(null_finding.is_some(), "should detect null origin");
    assert_eq!(null_finding.unwrap().severity, CorsSeverity::Critical);
}

#[test]
fn detects_pre_tld_bypass() {
    let config = make_config();
    let probes = vec![build_probe(
        "https://example.com.evil.com",
        Some("https://example.com.evil.com"),
        None,
        None,
        None,
        None,
        Some("Origin"),
    )];

    let analysis = analyze_cors(&probes, &config);

    let pretld = analysis
        .findings
        .iter()
        .find(|f| f.misconfig_type == CorsMisconfigType::PreTldBypass);

    assert!(pretld.is_some(), "should detect pre-TLD bypass");
}

#[test]
fn detects_http_origin_on_https() {
    let config = make_config();
    let probes = vec![build_probe(
        "http://example.com",
        Some("http://example.com"),
        None,
        None,
        None,
        None,
        Some("Origin"),
    )];

    let analysis = analyze_cors(&probes, &config);

    let http_finding = analysis
        .findings
        .iter()
        .find(|f| f.misconfig_type == CorsMisconfigType::HttpOriginOnHttps);

    assert!(
        http_finding.is_some(),
        "should detect HTTP origin on HTTPS target"
    );
}

#[test]
fn detects_internal_origin_exposure() {
    let config = make_config();
    let probes = vec![build_probe(
        "http://localhost",
        Some("http://localhost"),
        None,
        None,
        None,
        None,
        Some("Origin"),
    )];

    let analysis = analyze_cors(&probes, &config);

    let internal = analysis
        .findings
        .iter()
        .find(|f| f.misconfig_type == CorsMisconfigType::InternalOriginExposed);

    assert!(internal.is_some(), "should detect internal origin exposure");
}

#[test]
fn detects_partial_origin_match() {
    let config = make_config();
    let probes = vec![build_probe(
        "https://evil-example.com",
        Some("https://evil-example.com"),
        None,
        None,
        None,
        None,
        Some("Origin"),
    )];

    let analysis = analyze_cors(&probes, &config);

    let partial = analysis
        .findings
        .iter()
        .find(|f| f.misconfig_type == CorsMisconfigType::PartialOriginMatch);

    assert!(
        partial.is_some(),
        "should detect partial origin match bypass"
    );
}

#[test]
fn detects_subdomain_wildcard() {
    let config = make_config();
    let probes = vec![build_probe(
        "https://sub.example.com",
        Some("https://sub.example.com"),
        None,
        None,
        None,
        None,
        Some("Origin"),
    )];

    let analysis = analyze_cors(&probes, &config);

    let subdomain = analysis
        .findings
        .iter()
        .find(|f| f.misconfig_type == CorsMisconfigType::SubdomainWildcard);

    assert!(
        subdomain.is_some(),
        "should detect subdomain wildcard acceptance"
    );
}

#[test]
fn detects_credentials_with_permissive_origin() {
    let config = make_config();
    let probes = vec![build_probe(
        "https://evil.com",
        Some("https://evil.com"),
        Some("true"),
        None,
        None,
        None,
        Some("Origin"),
    )];

    let analysis = analyze_cors(&probes, &config);

    let cred_finding = analysis
        .findings
        .iter()
        .find(|f| f.misconfig_type == CorsMisconfigType::CredentialsWithPermissiveOrigin);

    assert!(
        cred_finding.is_some(),
        "should detect credentials with permissive origin"
    );
    assert_eq!(cred_finding.unwrap().severity, CorsSeverity::Critical);
    assert_eq!(cred_finding.unwrap().credential_exposure_score, 1.0);
}

#[test]
fn detects_sensitive_methods() {
    let config = make_config();
    let probes = vec![build_probe(
        "https://evil.com",
        Some("https://evil.com"),
        None,
        Some("GET, POST, PUT, DELETE"),
        None,
        None,
        Some("Origin"),
    )];

    let analysis = analyze_cors(&probes, &config);

    let methods = analysis
        .findings
        .iter()
        .find(|f| f.misconfig_type == CorsMisconfigType::SensitiveMethodsExposed);

    assert!(methods.is_some(), "should detect sensitive methods exposed");
}

#[test]
fn detects_wildcard_headers() {
    let config = make_config();
    let probes = vec![build_probe(
        "https://evil.com",
        Some("https://evil.com"),
        None,
        None,
        Some("*"),
        None,
        Some("Origin"),
    )];

    let analysis = analyze_cors(&probes, &config);

    let wildcard_h = analysis
        .findings
        .iter()
        .find(|f| f.misconfig_type == CorsMisconfigType::WildcardHeaders);

    assert!(wildcard_h.is_some(), "should detect wildcard headers");
}

#[test]
fn detects_excessive_max_age() {
    let config = make_config();
    let probes = vec![build_probe(
        "https://evil.com",
        Some("https://evil.com"),
        None,
        None,
        None,
        Some("604800"),
        Some("Origin"),
    )];

    let analysis = analyze_cors(&probes, &config);

    let max_age = analysis
        .findings
        .iter()
        .find(|f| f.misconfig_type == CorsMisconfigType::ExcessiveMaxAge);

    assert!(
        max_age.is_some(),
        "should detect excessive max-age (7 days)"
    );
}

#[test]
fn detects_missing_vary_origin() {
    let config = make_config();
    let probes = vec![build_probe(
        "https://evil.com",
        Some("https://evil.com"),
        None,
        None,
        None,
        None,
        None,
    )];

    let analysis = analyze_cors(&probes, &config);

    let vary = analysis
        .findings
        .iter()
        .find(|f| f.misconfig_type == CorsMisconfigType::MissingVaryOrigin);

    assert!(vary.is_some(), "should detect missing Vary: Origin header");
}

#[test]
fn secure_cors_produces_no_critical_findings() {
    let config = make_config();
    let probes = vec![
        build_probe("https://evil.com", None, None, None, None, None, None),
        build_probe("null", None, None, None, None, None, None),
        build_probe("http://localhost", None, None, None, None, None, None),
    ];

    let analysis = analyze_cors(&probes, &config);

    assert_eq!(
        analysis.summary.critical_count, 0,
        "properly configured CORS should have no critical findings"
    );
    assert_eq!(analysis.summary.total_findings, 0);
}

#[test]
fn poc_generation() {
    let config = make_config();
    let probes = vec![build_probe(
        "https://evil.com",
        Some("*"),
        Some("true"),
        None,
        None,
        None,
        Some("Origin"),
    )];

    let analysis = analyze_cors(&probes, &config);

    let pocs: Vec<_> = analysis
        .findings
        .iter()
        .filter(|f| f.exploit_poc.is_some())
        .collect();

    assert!(
        !pocs.is_empty(),
        "should generate PoC for exploitable findings"
    );

    for f in &pocs {
        let poc = f.exploit_poc.as_ref().unwrap();
        assert!(poc.contains("<!DOCTYPE html>"), "PoC should be valid HTML");
        assert!(poc.contains("<script>"), "PoC should include JS payload");
    }
}

#[test]
fn null_origin_poc_uses_sandboxed_iframe() {
    let config = make_config();
    let poc = generate_null_origin_poc(&config);

    assert!(
        poc.contains("sandbox"),
        "null origin PoC should use sandboxed iframe"
    );
    assert!(
        poc.contains("srcdoc"),
        "should use srcdoc for inline content"
    );
}

#[test]
fn credential_exposure_scoring() {
    let config = make_config();
    let probes = vec![build_probe(
        "https://evil.com",
        Some("https://evil.com"),
        Some("true"),
        None,
        None,
        None,
        Some("Origin"),
    )];

    let analysis = analyze_cors(&probes, &config);

    assert!(
        analysis.summary.max_credential_exposure >= 0.9,
        "reflected origin with credentials should have high exposure score"
    );
}

#[test]
fn cors_security_score_computation() {
    let score_empty = compute_cors_score(&[]);
    assert_eq!(score_empty, 1.0, "no findings should yield perfect score");

    let config = make_config();
    let probes = vec![build_probe(
        "https://evil.com",
        Some("https://evil.com"),
        Some("true"),
        None,
        None,
        None,
        Some("Origin"),
    )];

    let analysis = analyze_cors(&probes, &config);
    let score = compute_cors_score(&analysis.findings);
    assert!(
        score < 0.2,
        "critical findings should yield low score, got {}",
        score
    );
}

#[test]
fn summary_counts_correct() {
    let config = make_config();
    let probes = vec![
        build_probe(
            "https://evil.com",
            Some("*"),
            Some("true"),
            None,
            None,
            None,
            Some("Origin"),
        ),
        build_probe(
            "null",
            Some("null"),
            Some("true"),
            None,
            None,
            None,
            Some("Origin"),
        ),
    ];

    let analysis = analyze_cors(&probes, &config);

    assert_eq!(analysis.summary.total_probes, 2);
    assert_eq!(analysis.summary.total_findings, analysis.findings.len());

    let actual_critical = analysis
        .findings
        .iter()
        .filter(|f| f.severity == CorsSeverity::Critical)
        .count();
    assert_eq!(analysis.summary.critical_count, actual_critical);
}

#[test]
fn findings_sorted_by_severity() {
    let config = make_config();
    let probes = vec![build_probe(
        "https://evil.com",
        Some("*"),
        Some("true"),
        Some("GET, DELETE"),
        Some("*"),
        Some("604800"),
        None,
    )];

    let analysis = analyze_cors(&probes, &config);

    for pair in analysis.findings.windows(2) {
        assert!(
            pair[0].severity >= pair[1].severity,
            "findings should be sorted by severity descending"
        );
    }
}

#[test]
fn severity_display_formatting() {
    assert_eq!(format!("{}", CorsSeverity::Critical), "critical");
    assert_eq!(format!("{}", CorsSeverity::High), "high");
    assert_eq!(format!("{}", CorsSeverity::Medium), "medium");
    assert_eq!(format!("{}", CorsSeverity::Low), "low");
    assert_eq!(format!("{}", CorsSeverity::Info), "info");
}

#[test]
fn misconfig_type_display_formatting() {
    assert_eq!(
        format!("{}", CorsMisconfigType::WildcardOrigin),
        "wildcard-origin"
    );
    assert_eq!(
        format!("{}", CorsMisconfigType::OriginReflection),
        "origin-reflection"
    );
    assert_eq!(
        format!("{}", CorsMisconfigType::NullOriginAllowed),
        "null-origin-allowed"
    );
    assert_eq!(
        format!("{}", CorsMisconfigType::CredentialsWithPermissiveOrigin),
        "credentials-with-permissive-origin"
    );
}

#[test]
fn config_builder_pattern() {
    let config = CorsConfig::default()
        .with_target("https://target.com", "target.com")
        .with_poc(false)
        .with_custom_origins(vec!["https://custom.com".to_string()]);

    assert_eq!(config.target_url, "https://target.com");
    assert_eq!(config.target_domain, "target.com");
    assert!(!config.generate_poc);
    assert_eq!(config.custom_origins.len(), 1);
}

#[test]
fn subdomain_chain_poc_generation() {
    let config = make_config();
    let poc = generate_subdomain_chain_poc(&config, "taken-over.example.com");

    assert!(poc.contains("taken-over.example.com"));
    assert!(poc.contains("example.com/api"));
    assert!(poc.contains("credentials"));
}
