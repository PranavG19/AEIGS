use super::*;

fn make_response(overrides: impl FnOnce(&mut CorsPreflightResponse)) -> CorsPreflightResponse {
    let mut resp = CorsPreflightResponse {
        status: 204,
        allow_origin: None,
        allow_methods: vec!["GET".into(), "POST".into()],
        allow_headers: vec!["Content-Type".into()],
        allow_credentials: false,
        max_age_seconds: None,
        expose_headers: Vec::new(),
        vary_headers: vec!["Origin".into()],
        response_time_ms: 50,
        all_headers: Vec::new(),
    };
    overrides(&mut resp);
    resp
}

// ─── CorsPreflightResponse::from_headers ───

#[test]
fn from_headers_parses_all_cors_fields() {
    let headers = vec![
        (
            "Access-Control-Allow-Origin".into(),
            "https://example.com".into(),
        ),
        (
            "Access-Control-Allow-Methods".into(),
            "GET, POST, DELETE".into(),
        ),
        (
            "Access-Control-Allow-Headers".into(),
            "Authorization, Content-Type".into(),
        ),
        ("Access-Control-Allow-Credentials".into(), "true".into()),
        ("Access-Control-Max-Age".into(), "3600".into()),
        (
            "Access-Control-Expose-Headers".into(),
            "X-Request-Id".into(),
        ),
        ("Vary".into(), "Origin, Accept".into()),
    ];
    let resp = CorsPreflightResponse::from_headers(204, &headers, 42);

    assert_eq!(resp.status, 204);
    assert_eq!(resp.allow_origin.as_deref(), Some("https://example.com"));
    assert_eq!(resp.allow_methods, vec!["GET", "POST", "DELETE"]);
    assert_eq!(resp.allow_headers, vec!["Authorization", "Content-Type"]);
    assert!(resp.allow_credentials);
    assert_eq!(resp.max_age_seconds, Some(3600));
    assert_eq!(resp.expose_headers, vec!["X-Request-Id"]);
    assert_eq!(resp.vary_headers, vec!["Origin", "Accept"]);
    assert_eq!(resp.response_time_ms, 42);
}

#[test]
fn from_headers_case_insensitive() {
    let headers = vec![
        ("access-control-allow-origin".into(), "*".into()),
        ("ACCESS-CONTROL-ALLOW-CREDENTIALS".into(), "TRUE".into()),
    ];
    let resp = CorsPreflightResponse::from_headers(200, &headers, 10);
    assert_eq!(resp.allow_origin.as_deref(), Some("*"));
    assert!(resp.allow_credentials);
}

#[test]
fn from_headers_missing_fields_default_to_none() {
    let resp = CorsPreflightResponse::from_headers(200, &[], 5);
    assert!(resp.allow_origin.is_none());
    assert!(resp.allow_methods.is_empty());
    assert!(!resp.allow_credentials);
    assert!(resp.max_age_seconds.is_none());
}

// ─── analyze_cache_timing ───

#[test]
fn cache_timing_empty_samples() {
    let result = analyze_cache_timing(&[]);
    assert!(!result.is_cached);
    assert_eq!(result.initial_time_ms, 0);
    assert_eq!(result.speedup_ratio, 1.0);
}

#[test]
fn cache_timing_detects_caching() {
    let samples = vec![
        TimingSample {
            request_index: 0,
            response_time_ms: 100,
            origin_sent: "https://a.com".into(),
            method_sent: "GET".into(),
        },
        TimingSample {
            request_index: 1,
            response_time_ms: 10,
            origin_sent: "https://a.com".into(),
            method_sent: "GET".into(),
        },
        TimingSample {
            request_index: 2,
            response_time_ms: 12,
            origin_sent: "https://a.com".into(),
            method_sent: "GET".into(),
        },
    ];
    let result = analyze_cache_timing(&samples);
    assert!(result.is_cached);
    assert_eq!(result.initial_time_ms, 100);
    assert_eq!(result.subsequent_avg_ms, 11);
    assert!(result.speedup_ratio > 5.0);
}

#[test]
fn cache_timing_no_speedup_means_no_cache() {
    let samples = vec![
        TimingSample {
            request_index: 0,
            response_time_ms: 50,
            origin_sent: "https://a.com".into(),
            method_sent: "GET".into(),
        },
        TimingSample {
            request_index: 1,
            response_time_ms: 48,
            origin_sent: "https://a.com".into(),
            method_sent: "GET".into(),
        },
    ];
    let result = analyze_cache_timing(&samples);
    assert!(!result.is_cached);
    assert!(result.speedup_ratio < CACHE_SPEEDUP_THRESHOLD);
}

#[test]
fn cache_timing_single_sample() {
    let samples = vec![TimingSample {
        request_index: 0,
        response_time_ms: 200,
        origin_sent: "https://a.com".into(),
        method_sent: "GET".into(),
    }];
    let result = analyze_cache_timing(&samples);
    assert!(!result.is_cached);
    assert_eq!(result.initial_time_ms, 200);
    assert_eq!(result.subsequent_avg_ms, 200);
}

// ─── analyze_max_age ───

#[test]
fn max_age_high_severity_for_very_long_cache() {
    let analysis = analyze_max_age(604800);
    assert!(analysis.is_overly_permissive);
    assert_eq!(analysis.risk_level, Severity::High);
    assert_eq!(analysis.persistence_window, Duration::from_secs(604800));
}

#[test]
fn max_age_medium_severity_for_moderate_cache() {
    let analysis = analyze_max_age(7200);
    assert!(analysis.is_overly_permissive);
    assert_eq!(analysis.risk_level, Severity::Medium);
}

#[test]
fn max_age_info_for_short_cache() {
    let analysis = analyze_max_age(600);
    assert!(!analysis.is_overly_permissive);
    assert_eq!(analysis.risk_level, Severity::Info);
}

// ─── generate_poison_payloads ───

#[test]
fn generates_at_least_five_payloads() {
    let resp = make_response(|_| {});
    let payloads = generate_poison_payloads("https://target.com/api", &resp);
    assert!(
        payloads.len() >= 5,
        "Expected >=5 payloads, got {}",
        payloads.len()
    );
}

#[test]
fn payload_ids_are_unique() {
    let resp = make_response(|_| {});
    let payloads = generate_poison_payloads("https://target.com/api", &resp);
    let ids: Vec<usize> = payloads.iter().map(|p| p.id).collect();
    let unique: std::collections::HashSet<usize> = ids.iter().copied().collect();
    assert_eq!(ids.len(), unique.len());
}

#[test]
fn payloads_include_max_age_when_overly_permissive() {
    let resp = make_response(|r| {
        r.max_age_seconds = Some(86400);
    });
    let payloads = generate_poison_payloads("https://target.com/api", &resp);
    let has_max_age = payloads
        .iter()
        .any(|p| p.abuse_type == PreflightAbuse::MaxAgeAbuse);
    assert!(
        has_max_age,
        "Should include Max-Age abuse payload for 86400s cache"
    );
}

#[test]
fn payloads_skip_max_age_when_short() {
    let resp = make_response(|r| {
        r.max_age_seconds = Some(300);
    });
    let payloads = generate_poison_payloads("https://target.com/api", &resp);
    let has_max_age = payloads
        .iter()
        .any(|p| p.abuse_type == PreflightAbuse::MaxAgeAbuse);
    assert!(
        !has_max_age,
        "Should NOT include Max-Age abuse for 300s cache"
    );
}

#[test]
fn payloads_include_null_origin() {
    let resp = make_response(|_| {});
    let payloads = generate_poison_payloads("https://target.com/api", &resp);
    let has_null = payloads.iter().any(|p| p.origin == "null");
    assert!(has_null, "Should include null origin payload");
}

#[test]
fn payloads_cover_all_abuse_types() {
    let resp = make_response(|r| {
        r.max_age_seconds = Some(100_000);
    });
    let payloads = generate_poison_payloads("https://target.com/api", &resp);
    let types: std::collections::HashSet<PreflightAbuse> =
        payloads.iter().map(|p| p.abuse_type).collect();
    assert!(types.contains(&PreflightAbuse::CachePoisoning));
    assert!(types.contains(&PreflightAbuse::MethodAllowlistExpansion));
    assert!(types.contains(&PreflightAbuse::HeaderAllowlistExpansion));
    assert!(types.contains(&PreflightAbuse::CredentialsEscalation));
    assert!(types.contains(&PreflightAbuse::NullOriginBypass));
    assert!(types.contains(&PreflightAbuse::WildcardOriginCredentials));
    assert!(types.contains(&PreflightAbuse::VaryHeaderAbuse));
    assert!(types.contains(&PreflightAbuse::MaxAgeAbuse));
}

// ─── analyze_preflight ───

#[test]
fn detects_wildcard_credentials_critical() {
    let resp = make_response(|r| {
        r.allow_origin = Some("*".into());
        r.allow_credentials = true;
    });
    let findings = analyze_preflight("https://target.com/api", &resp);
    let wc = findings
        .iter()
        .find(|f| f.abuse_type == PreflightAbuse::WildcardOriginCredentials);
    assert!(wc.is_some());
    assert_eq!(wc.unwrap().severity, Severity::Critical);
}

#[test]
fn detects_null_origin_acceptance() {
    let resp = make_response(|r| {
        r.allow_origin = Some("null".into());
    });
    let findings = analyze_preflight("https://target.com/api", &resp);
    let null_finding = findings
        .iter()
        .find(|f| f.abuse_type == PreflightAbuse::NullOriginBypass);
    assert!(null_finding.is_some());
    assert_eq!(null_finding.unwrap().severity, Severity::High);
}

#[test]
fn detects_origin_reflection_with_credentials_is_critical() {
    let resp = make_response(|r| {
        r.allow_origin = Some("https://evil.attacker.com".into());
        r.allow_credentials = true;
    });
    let findings = analyze_preflight("https://target.com/api", &resp);
    let reflection = findings
        .iter()
        .find(|f| f.abuse_type == PreflightAbuse::CachePoisoning);
    assert!(reflection.is_some());
    assert_eq!(reflection.unwrap().severity, Severity::Critical);
}

#[test]
fn detects_origin_reflection_without_credentials_is_high() {
    let resp = make_response(|r| {
        r.allow_origin = Some("https://evil.attacker.com".into());
        r.allow_credentials = false;
    });
    let findings = analyze_preflight("https://target.com/api", &resp);
    let reflection = findings
        .iter()
        .find(|f| f.abuse_type == PreflightAbuse::CachePoisoning);
    assert!(reflection.is_some());
    assert_eq!(reflection.unwrap().severity, Severity::High);
}

#[test]
fn detects_dangerous_method_expansion() {
    let resp = make_response(|r| {
        r.allow_methods = vec!["GET".into(), "DELETE".into(), "PATCH".into()];
    });
    let findings = analyze_preflight("https://target.com/api", &resp);
    let method_finding = findings
        .iter()
        .find(|f| f.abuse_type == PreflightAbuse::MethodAllowlistExpansion);
    assert!(method_finding.is_some());
    assert_eq!(method_finding.unwrap().severity, Severity::Medium);
}

#[test]
fn no_method_finding_for_safe_methods() {
    let resp = make_response(|r| {
        r.allow_methods = vec!["GET".into(), "POST".into(), "HEAD".into()];
    });
    let findings = analyze_preflight("https://target.com/api", &resp);
    let method_finding = findings
        .iter()
        .find(|f| f.abuse_type == PreflightAbuse::MethodAllowlistExpansion);
    assert!(method_finding.is_none());
}

#[test]
fn detects_sensitive_header_expansion() {
    let resp = make_response(|r| {
        r.allow_headers = vec![
            "Content-Type".into(),
            "Authorization".into(),
            "X-CSRF-Token".into(),
        ];
    });
    let findings = analyze_preflight("https://target.com/api", &resp);
    let hdr_finding = findings
        .iter()
        .find(|f| f.abuse_type == PreflightAbuse::HeaderAllowlistExpansion);
    assert!(hdr_finding.is_some());
}

#[test]
fn detects_max_age_abuse() {
    let resp = make_response(|r| {
        r.max_age_seconds = Some(86400);
    });
    let findings = analyze_preflight("https://target.com/api", &resp);
    let max_age = findings
        .iter()
        .find(|f| f.abuse_type == PreflightAbuse::MaxAgeAbuse);
    assert!(max_age.is_some());
    assert_eq!(max_age.unwrap().severity, Severity::High);
}

#[test]
fn no_max_age_finding_for_short_duration() {
    let resp = make_response(|r| {
        r.max_age_seconds = Some(600);
    });
    let findings = analyze_preflight("https://target.com/api", &resp);
    let max_age = findings
        .iter()
        .find(|f| f.abuse_type == PreflightAbuse::MaxAgeAbuse);
    assert!(max_age.is_none());
}

#[test]
fn detects_vary_header_abuse_when_missing_origin() {
    let resp = make_response(|r| {
        r.allow_origin = Some("https://example.com".into());
        r.vary_headers = vec!["Accept".into()];
    });
    let findings = analyze_preflight("https://target.com/api", &resp);
    let vary = findings
        .iter()
        .find(|f| f.abuse_type == PreflightAbuse::VaryHeaderAbuse);
    assert!(vary.is_some());
    assert_eq!(vary.unwrap().severity, Severity::High);
}

#[test]
fn no_vary_finding_when_origin_in_vary() {
    let resp = make_response(|r| {
        r.allow_origin = Some("https://example.com".into());
        r.vary_headers = vec!["Origin".into(), "Accept".into()];
    });
    let findings = analyze_preflight("https://target.com/api", &resp);
    let vary = findings
        .iter()
        .find(|f| f.abuse_type == PreflightAbuse::VaryHeaderAbuse);
    assert!(vary.is_none());
}

#[test]
fn detects_credentials_escalation() {
    let resp = make_response(|r| {
        r.allow_origin = Some("https://trusted-partner.com".into());
        r.allow_credentials = true;
    });
    let findings = analyze_preflight("https://target.com/api", &resp);
    let cred = findings
        .iter()
        .find(|f| f.abuse_type == PreflightAbuse::CredentialsEscalation);
    assert!(cred.is_some());
    assert_eq!(cred.unwrap().severity, Severity::Medium);
}

// ─── run_preflight_analysis (integration) ───

#[test]
fn full_analysis_combines_findings_and_payloads() {
    let resp = make_response(|r| {
        r.allow_origin = Some("https://evil.attacker.com".into());
        r.allow_credentials = true;
        r.allow_methods = vec!["GET".into(), "DELETE".into()];
        r.allow_headers = vec!["Authorization".into()];
        r.max_age_seconds = Some(86400);
        r.vary_headers = Vec::new();
    });
    let samples = vec![
        TimingSample {
            request_index: 0,
            response_time_ms: 100,
            origin_sent: "a".into(),
            method_sent: "GET".into(),
        },
        TimingSample {
            request_index: 1,
            response_time_ms: 5,
            origin_sent: "a".into(),
            method_sent: "GET".into(),
        },
    ];
    let result = run_preflight_analysis("https://target.com/api", &resp, &samples);

    assert!(result.cache_timing.is_some());
    assert!(result.cache_timing.as_ref().unwrap().is_cached);
    assert!(result.max_age_analysis.is_some());
    assert!(
        result
            .max_age_analysis
            .as_ref()
            .unwrap()
            .is_overly_permissive
    );
    assert!(!result.findings.is_empty());
    assert!(result.payloads_generated.len() >= 5);

    // Cache timing evidence attached to all findings
    for finding in &result.findings {
        assert!(finding.evidence.cache_timing.is_some());
    }
}

#[test]
fn full_analysis_no_timing_samples() {
    let resp = make_response(|r| {
        r.allow_origin = Some("https://evil.attacker.com".into());
    });
    let result = run_preflight_analysis("https://target.com/api", &resp, &[]);
    assert!(result.cache_timing.is_none());
    assert!(!result.findings.is_empty());
}

// ─── findings_by_type / count_by_min_severity ───

#[test]
fn findings_by_type_groups_correctly() {
    let resp = make_response(|r| {
        r.allow_origin = Some("https://evil.attacker.com".into());
        r.allow_credentials = true;
        r.allow_methods = vec!["DELETE".into()];
        r.vary_headers = Vec::new();
    });
    let findings = analyze_preflight("https://target.com/api", &resp);
    let grouped = findings_by_type(&findings);
    assert!(grouped.contains_key(&PreflightAbuse::CachePoisoning));
    assert!(grouped.contains_key(&PreflightAbuse::VaryHeaderAbuse));
}

#[test]
fn count_by_severity_filters_correctly() {
    let resp = make_response(|r| {
        r.allow_origin = Some("https://evil.attacker.com".into());
        r.allow_credentials = true;
        r.allow_methods = vec!["DELETE".into()];
        r.allow_headers = vec!["Authorization".into()];
        r.max_age_seconds = Some(86400);
        r.vary_headers = Vec::new();
    });
    let findings = analyze_preflight("https://target.com/api", &resp);

    let critical_count = count_by_min_severity(&findings, Severity::Critical);
    let high_and_up = count_by_min_severity(&findings, Severity::High);
    let all = count_by_min_severity(&findings, Severity::Info);

    assert!(critical_count > 0);
    assert!(high_and_up >= critical_count);
    assert!(all >= high_and_up);
}

// ─── PoC generation ───

#[test]
fn poc_contains_endpoint_url() {
    let resp = make_response(|r| {
        r.allow_origin = Some("*".into());
        r.allow_credentials = true;
    });
    let findings = analyze_preflight("https://target.com/secret/api", &resp);
    for finding in &findings {
        assert!(
            finding.poc_html.contains("https://target.com/secret/api"),
            "PoC for {} should contain the target endpoint",
            finding.abuse_type
        );
    }
}

#[test]
fn poc_html_is_valid_html_structure() {
    let resp = make_response(|r| {
        r.allow_origin = Some("null".into());
    });
    let findings = analyze_preflight("https://target.com/api", &resp);
    for finding in &findings {
        assert!(finding.poc_html.contains("<!DOCTYPE html>"));
        assert!(finding.poc_html.contains("</html>"));
        assert!(finding.poc_html.contains("<script>"));
    }
}

// ─── Display / Serialize ───

#[test]
fn preflight_abuse_display() {
    assert_eq!(
        PreflightAbuse::CachePoisoning.to_string(),
        "Preflight Cache Poisoning"
    );
    assert_eq!(
        PreflightAbuse::WildcardOriginCredentials.to_string(),
        "Wildcard Origin + Credentials"
    );
    assert_eq!(
        PreflightAbuse::NullOriginBypass.to_string(),
        "Null Origin via Iframe Sandbox"
    );
}

#[test]
fn severity_display_and_ordering() {
    assert_eq!(Severity::Critical.to_string(), "Critical");
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    assert!(Severity::Low > Severity::Info);
}

#[test]
fn preflight_response_serialization_roundtrip() {
    let resp = make_response(|r| {
        r.allow_origin = Some("https://example.com".into());
        r.max_age_seconds = Some(3600);
    });
    let json = serde_json::to_string(&resp).unwrap();
    let deserialized: CorsPreflightResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.allow_origin, resp.allow_origin);
    assert_eq!(deserialized.max_age_seconds, resp.max_age_seconds);
}

// ─── extract_domain ───

#[test]
fn extract_domain_from_urls() {
    assert_eq!(extract_domain("https://target.com/api/v1"), "target.com");
    assert_eq!(extract_domain("http://localhost:8080/test"), "localhost");
    assert_eq!(
        extract_domain("https://sub.domain.co.uk/path"),
        "sub.domain.co.uk"
    );
    assert_eq!(extract_domain("bare-domain/path"), "bare-domain");
}

// ─── split_header_list ───

#[test]
fn split_header_list_handles_edge_cases() {
    assert_eq!(
        split_header_list("GET, POST, DELETE"),
        vec!["GET", "POST", "DELETE"]
    );
    assert_eq!(split_header_list("  GET ,  POST  "), vec!["GET", "POST"]);
    assert!(split_header_list("").is_empty());
    assert_eq!(split_header_list("single"), vec!["single"]);
}
