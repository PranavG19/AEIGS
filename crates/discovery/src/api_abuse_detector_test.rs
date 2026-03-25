use super::api_abuse_detector::*;
use std::collections::HashMap;

fn sample_config() -> AbuseDetectorConfig {
    AbuseDetectorConfig {
        base_url: "http://localhost:8080".to_string(),
        endpoints: vec![
            EndpointInfo {
                path: "/api/v1/users".to_string(),
                method: "GET".to_string(),
                params: vec!["page".to_string(), "limit".to_string(), "id".to_string()],
                accepts_body: false,
                requires_auth: true,
            },
            EndpointInfo {
                path: "/api/v1/users".to_string(),
                method: "POST".to_string(),
                params: vec![],
                accepts_body: true,
                requires_auth: true,
            },
            EndpointInfo {
                path: "/api/v1/users".to_string(),
                method: "PUT".to_string(),
                params: vec![],
                accepts_body: true,
                requires_auth: true,
            },
            EndpointInfo {
                path: "/admin/settings".to_string(),
                method: "GET".to_string(),
                params: vec![],
                accepts_body: false,
                requires_auth: true,
            },
            EndpointInfo {
                path: "/api/batch".to_string(),
                method: "POST".to_string(),
                params: vec![],
                accepts_body: true,
                requires_auth: false,
            },
            EndpointInfo {
                path: "/graphql".to_string(),
                method: "POST".to_string(),
                params: vec![],
                accepts_body: true,
                requires_auth: false,
            },
        ],
        auth_token: Some("user-token-123".to_string()),
        admin_token: Some("admin-token-456".to_string()),
    }
}

#[test]
fn test_new_valid_config() {
    let config = sample_config();
    let detector = ApiAbuseDetector::new(config);
    assert!(detector.is_ok());
}

#[test]
fn test_new_empty_base_url_rejected() {
    let config = AbuseDetectorConfig {
        base_url: String::new(),
        endpoints: vec![EndpointInfo {
            path: "/test".to_string(),
            method: "GET".to_string(),
            params: vec![],
            accepts_body: false,
            requires_auth: false,
        }],
        auth_token: None,
        admin_token: None,
    };
    let result = ApiAbuseDetector::new(config);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        AbuseDetectorError::InvalidConfig(_)
    ));
}

#[test]
fn test_new_no_endpoints_rejected() {
    let config = AbuseDetectorConfig {
        base_url: "http://localhost".to_string(),
        endpoints: vec![],
        auth_token: None,
        admin_token: None,
    };
    let result = ApiAbuseDetector::new(config);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        AbuseDetectorError::NoEndpoints
    ));
}

#[test]
fn test_pattern_count_is_eight() {
    assert_eq!(ApiAbuseDetector::pattern_count(), 8);
}

#[test]
fn test_generate_probes_covers_all_patterns() {
    let detector = ApiAbuseDetector::new(sample_config()).unwrap();
    let probes = detector.generate_probes();
    let patterns: Vec<AbusePattern> = probes.iter().map(|p| p.pattern.clone()).collect();
    assert!(patterns.contains(&AbusePattern::PaginationAbuse));
    assert!(patterns.contains(&AbusePattern::RateLimitBypass));
    assert!(patterns.contains(&AbusePattern::MassAssignment));
    assert!(patterns.contains(&AbusePattern::ExcessiveDataExposure));
    assert!(patterns.contains(&AbusePattern::BrokenFunctionLevelAuth));
    assert!(patterns.contains(&AbusePattern::ResourceEnumeration));
    assert!(patterns.contains(&AbusePattern::BatchEndpointAbuse));
    assert!(patterns.contains(&AbusePattern::GraphQlQueryCostBypass));
}

#[test]
fn test_pagination_probes_have_payloads() {
    let detector = ApiAbuseDetector::new(sample_config()).unwrap();
    let probes = detector.generate_pagination_probes();
    assert!(!probes.is_empty());
    for probe in &probes {
        assert_eq!(probe.pattern, AbusePattern::PaginationAbuse);
        assert!(!probe.payloads.is_empty());
        assert_eq!(probe.severity, Severity::High);
    }
}

#[test]
fn test_pagination_negative_offset_present() {
    let detector = ApiAbuseDetector::new(sample_config()).unwrap();
    let probes = detector.generate_pagination_probes();
    let has_negative_offset = probes.iter().any(|p| {
        p.payloads
            .iter()
            .any(|pl| pl.query_params.get("offset") == Some(&"-1".to_string()))
    });
    assert!(has_negative_offset);
}

#[test]
fn test_pagination_huge_page_size_present() {
    let detector = ApiAbuseDetector::new(sample_config()).unwrap();
    let probes = detector.generate_pagination_probes();
    let has_huge_limit = probes.iter().any(|p| {
        p.payloads
            .iter()
            .any(|pl| pl.query_params.get("limit") == Some(&"999999".to_string()))
    });
    assert!(has_huge_limit);
}

#[test]
fn test_rate_limit_bypass_has_five_plus_headers() {
    assert!(RATE_LIMIT_BYPASS_HEADERS.len() >= 5);
}

#[test]
fn test_rate_limit_bypass_probes_generated() {
    let detector = ApiAbuseDetector::new(sample_config()).unwrap();
    let probes = detector.generate_rate_limit_bypass_probes();
    assert!(!probes.is_empty());
    for probe in &probes {
        assert_eq!(probe.pattern, AbusePattern::RateLimitBypass);
        assert!(probe.payloads.len() >= 5);
    }
}

#[test]
fn test_rate_limit_bypass_includes_x_forwarded_for() {
    let detector = ApiAbuseDetector::new(sample_config()).unwrap();
    let probes = detector.generate_rate_limit_bypass_probes();
    let has_xff = probes.iter().any(|p| {
        p.payloads
            .iter()
            .any(|pl| pl.headers.contains_key("X-Forwarded-For"))
    });
    assert!(has_xff);
}

#[test]
fn test_rate_limit_bypass_includes_cf_connecting_ip() {
    let detector = ApiAbuseDetector::new(sample_config()).unwrap();
    let probes = detector.generate_rate_limit_bypass_probes();
    let has_cf = probes.iter().any(|p| {
        p.payloads
            .iter()
            .any(|pl| pl.headers.contains_key("CF-Connecting-IP"))
    });
    assert!(has_cf);
}

#[test]
fn test_mass_assignment_only_body_endpoints() {
    let detector = ApiAbuseDetector::new(sample_config()).unwrap();
    let probes = detector.generate_mass_assignment_probes();
    for probe in &probes {
        assert_eq!(probe.pattern, AbusePattern::MassAssignment);
        assert_eq!(probe.severity, Severity::Critical);
        for payload in &probe.payloads {
            assert!(payload.body.is_some());
        }
    }
}

#[test]
fn test_mass_assignment_injects_admin_role() {
    let detector = ApiAbuseDetector::new(sample_config()).unwrap();
    let probes = detector.generate_mass_assignment_probes();
    let has_role_admin = probes.iter().any(|p| {
        p.payloads
            .iter()
            .any(|pl| pl.body.as_deref().unwrap_or("").contains("\"role\""))
    });
    assert!(has_role_admin);
}

#[test]
fn test_mass_assignment_payload_generation() {
    let existing = HashMap::from([("name".to_string(), "test".to_string())]);
    let payload = ApiAbuseDetector::generate_mass_assignment_payload(&existing);
    assert!(payload.contains_key("name"));
    assert!(payload.contains_key("role"));
    assert!(payload.contains_key("is_admin"));
    assert!(payload.len() > existing.len());
}

#[test]
fn test_mass_assignment_does_not_overwrite_existing() {
    let existing = HashMap::from([("role".to_string(), "user".to_string())]);
    let payload = ApiAbuseDetector::generate_mass_assignment_payload(&existing);
    assert_eq!(payload.get("role").unwrap(), "user");
}

#[test]
fn test_data_exposure_only_get_endpoints() {
    let detector = ApiAbuseDetector::new(sample_config()).unwrap();
    let probes = detector.generate_data_exposure_probes();
    for probe in &probes {
        assert_eq!(probe.method, "GET");
        assert_eq!(probe.pattern, AbusePattern::ExcessiveDataExposure);
    }
}

#[test]
fn test_data_exposure_includes_auth_comparison() {
    let detector = ApiAbuseDetector::new(sample_config()).unwrap();
    let probes = detector.generate_data_exposure_probes();
    let has_auth_probe = probes.iter().any(|p| {
        p.payloads
            .iter()
            .any(|pl| pl.headers.contains_key("Authorization"))
    });
    assert!(has_auth_probe);
}

#[test]
fn test_bfla_targets_admin_endpoints() {
    let detector = ApiAbuseDetector::new(sample_config()).unwrap();
    let probes = detector.generate_bfla_probes();
    assert!(!probes.is_empty());
    for probe in &probes {
        assert_eq!(probe.pattern, AbusePattern::BrokenFunctionLevelAuth);
        assert_eq!(probe.severity, Severity::Critical);
        assert!(probe.endpoint.contains("admin"));
    }
}

#[test]
fn test_bfla_includes_jwt_none_alg() {
    let detector = ApiAbuseDetector::new(sample_config()).unwrap();
    let probes = detector.generate_bfla_probes();
    let has_none_jwt = probes.iter().any(|p| {
        p.payloads.iter().any(|pl| {
            pl.headers
                .get("Authorization")
                .map(|v| v.contains("eyJhbGciOiJub25lIi"))
                .unwrap_or(false)
        })
    });
    assert!(has_none_jwt);
}

#[test]
fn test_enumeration_probes_for_id_params() {
    let detector = ApiAbuseDetector::new(sample_config()).unwrap();
    let probes = detector.generate_enumeration_probes();
    assert!(!probes.is_empty());
    for probe in &probes {
        assert_eq!(probe.pattern, AbusePattern::ResourceEnumeration);
    }
}

#[test]
fn test_enumeration_includes_sequential_ids() {
    let detector = ApiAbuseDetector::new(sample_config()).unwrap();
    let probes = detector.generate_enumeration_probes();
    let has_sequential = probes.iter().any(|p| {
        p.payloads
            .iter()
            .any(|pl| pl.query_params.get("id") == Some(&"1".to_string()))
    });
    assert!(has_sequential);
}

#[test]
fn test_enumeration_includes_uuid_probe() {
    let detector = ApiAbuseDetector::new(sample_config()).unwrap();
    let probes = detector.generate_enumeration_probes();
    let has_uuid = probes.iter().any(|p| {
        p.payloads.iter().any(|pl| {
            pl.query_params
                .get("id")
                .map(|v| v.contains('-') && v.len() == 36)
                .unwrap_or(false)
        })
    });
    assert!(has_uuid);
}

#[test]
fn test_batch_abuse_targets_batch_endpoints() {
    let detector = ApiAbuseDetector::new(sample_config()).unwrap();
    let probes = detector.generate_batch_abuse_probes();
    assert!(!probes.is_empty());
    for probe in &probes {
        assert_eq!(probe.pattern, AbusePattern::BatchEndpointAbuse);
        assert!(
            probe.endpoint.contains("batch")
                || probe.endpoint.contains("bulk")
                || probe.endpoint.contains("graphql")
        );
    }
}

#[test]
fn test_batch_abuse_includes_large_batch() {
    let detector = ApiAbuseDetector::new(sample_config()).unwrap();
    let probes = detector.generate_batch_abuse_probes();
    let has_large = probes.iter().any(|p| {
        p.payloads
            .iter()
            .any(|pl| pl.description.contains("100-request"))
    });
    assert!(has_large);
}

#[test]
fn test_graphql_cost_bypass_probes() {
    let detector = ApiAbuseDetector::new(sample_config()).unwrap();
    let probes = detector.generate_graphql_cost_probes();
    assert!(!probes.is_empty());
    for probe in &probes {
        assert_eq!(probe.pattern, AbusePattern::GraphQlQueryCostBypass);
        assert!(probe.endpoint.contains("graphql"));
    }
}

#[test]
fn test_graphql_alias_multiplication() {
    let detector = ApiAbuseDetector::new(sample_config()).unwrap();
    let probes = detector.generate_graphql_cost_probes();
    let has_alias = probes.iter().any(|p| {
        p.payloads
            .iter()
            .any(|pl| pl.body.as_deref().unwrap_or("").contains("a0:"))
    });
    assert!(has_alias);
}

#[test]
fn test_graphql_deep_nesting() {
    let detector = ApiAbuseDetector::new(sample_config()).unwrap();
    let probes = detector.generate_graphql_cost_probes();
    let has_deep = probes.iter().any(|p| {
        p.payloads
            .iter()
            .any(|pl| pl.description.contains("deep nesting"))
    });
    assert!(has_deep);
}

#[test]
fn test_idor_detect_sequential_integer() {
    let indicators = ApiAbuseDetector::detect_idor_indicators("/api/users/42");
    assert!(
        indicators
            .iter()
            .any(|i| i.pattern == IdorPattern::SequentialInteger && i.value == "42")
    );
}

#[test]
fn test_idor_detect_uuid_v1() {
    let indicators =
        ApiAbuseDetector::detect_idor_indicators("/api/users/6ba7b810-9dad-11d1-80b4-00c04fd430c8");
    assert!(
        indicators
            .iter()
            .any(|i| i.pattern == IdorPattern::PredictableUuidV1)
    );
}

#[test]
fn test_idor_detect_uuid_v4() {
    let indicators =
        ApiAbuseDetector::detect_idor_indicators("/api/users/550e8400-e29b-41d4-a716-446655440000");
    assert!(
        indicators
            .iter()
            .any(|i| i.pattern == IdorPattern::RandomUuidV4)
    );
}

#[test]
fn test_idor_detect_short_hash() {
    let indicators = ApiAbuseDetector::detect_idor_indicators("/api/commits/a1b2c3d4e5");
    assert!(
        indicators
            .iter()
            .any(|i| i.pattern == IdorPattern::ShortHash)
    );
}

#[test]
fn test_idor_no_indicators_for_text_path() {
    let indicators = ApiAbuseDetector::detect_idor_indicators("/api/users/profile");
    assert!(indicators.is_empty());
}

#[test]
fn test_generate_bypass_headers_returns_five() {
    let headers = ApiAbuseDetector::generate_bypass_headers(0);
    assert_eq!(headers.len(), 5);
    assert!(headers.contains_key("X-Forwarded-For"));
}

#[test]
fn test_generate_bypass_headers_rotation() {
    let h0 = ApiAbuseDetector::generate_bypass_headers(0);
    let h3 = ApiAbuseDetector::generate_bypass_headers(3);
    let ip0 = h0.get("X-Forwarded-For").unwrap();
    let ip3 = h3.get("X-Forwarded-For").unwrap();
    assert_ne!(ip0, ip3);
}

#[test]
fn test_abuse_pattern_display() {
    assert_eq!(
        AbusePattern::PaginationAbuse.to_string(),
        "Pagination Abuse"
    );
    assert_eq!(
        AbusePattern::RateLimitBypass.to_string(),
        "Rate Limit Bypass"
    );
    assert_eq!(AbusePattern::MassAssignment.to_string(), "Mass Assignment");
    assert_eq!(
        AbusePattern::GraphQlQueryCostBypass.to_string(),
        "GraphQL Query Cost Bypass"
    );
}

#[test]
fn test_severity_display() {
    assert_eq!(Severity::Low.to_string(), "Low");
    assert_eq!(Severity::Critical.to_string(), "Critical");
}

#[test]
fn test_idor_pattern_display() {
    assert_eq!(
        IdorPattern::SequentialInteger.to_string(),
        "Sequential Integer"
    );
    assert_eq!(
        IdorPattern::PredictableUuidV1.to_string(),
        "Predictable UUID v1"
    );
}

#[test]
fn test_abuse_detector_error_display() {
    let e1 = AbuseDetectorError::InvalidConfig("bad url".to_string());
    assert_eq!(e1.to_string(), "invalid config: bad url");
    let e2 = AbuseDetectorError::NoEndpoints;
    assert_eq!(e2.to_string(), "no endpoints provided");
}

#[test]
fn test_debug_formatting() {
    let detector = ApiAbuseDetector::new(sample_config()).unwrap();
    let debug_str = format!("{:?}", detector);
    assert!(debug_str.contains("ApiAbuseDetector"));
    assert!(debug_str.contains("localhost"));
}
