use super::*;

#[test]
fn bypass_technique_count_is_at_least_ten() {
    assert!(BypassTechnique::all().len() >= 10);
}

#[test]
fn bypass_technique_display_names_are_unique() {
    let names: Vec<String> = BypassTechnique::all()
        .iter()
        .map(|t| t.to_string())
        .collect();
    let unique: std::collections::HashSet<&String> = names.iter().collect();
    assert_eq!(names.len(), unique.len());
}

#[test]
fn ip_rotation_headers_at_least_eight() {
    assert!(ip_header_variant_count() >= 8);
}

#[test]
fn ip_rotation_header_names_match_count() {
    let names = ip_rotation_header_names();
    assert_eq!(names.len(), ip_header_variant_count());
}

#[test]
fn ip_rotation_cycles_through_headers() {
    let config = RateLimitBypassConfig {
        enabled_techniques: vec![BypassTechnique::IpRotation],
        ..Default::default()
    };
    let mut engine = RateLimitBypassEngine::new(config, 42);

    let mut seen_headers = std::collections::HashSet::new();
    for _ in 0..IP_ROTATION_HEADERS.len() {
        let (name, _ip) = engine.next_ip_header();
        seen_headers.insert(name);
    }
    assert_eq!(seen_headers.len(), IP_ROTATION_HEADERS.len());
}

#[test]
fn ip_rotation_uses_configured_pool() {
    let pool = vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()];
    let config = RateLimitBypassConfig {
        ip_pool: pool.clone(),
        enabled_techniques: vec![BypassTechnique::IpRotation],
        ..Default::default()
    };
    let mut engine = RateLimitBypassEngine::new(config, 0);

    for _ in 0..10 {
        let (_header, ip) = engine.next_ip_header();
        assert!(pool.contains(&ip), "IP {ip} not in configured pool");
    }
}

#[test]
fn ip_rotation_generates_random_ips_when_pool_empty() {
    let config = RateLimitBypassConfig {
        ip_pool: Vec::new(),
        enabled_techniques: vec![BypassTechnique::IpRotation],
        ..Default::default()
    };
    let mut engine = RateLimitBypassEngine::new(config, 99);
    let (_, ip) = engine.next_ip_header();
    let parts: Vec<&str> = ip.split('.').collect();
    assert_eq!(parts.len(), 4);
    for part in parts {
        let _n: u8 = part.parse().expect("each octet should be a valid u8");
    }
}

#[test]
fn api_key_multiplexing_rotates_keys() {
    let keys = vec![
        "key-a".to_string(),
        "key-b".to_string(),
        "key-c".to_string(),
    ];
    let config = RateLimitBypassConfig {
        api_keys: keys.clone(),
        enabled_techniques: vec![BypassTechnique::ApiKeyMultiplexing],
        ..Default::default()
    };
    let mut engine = RateLimitBypassEngine::new(config, 0);

    let results = engine.generate_bypass("/api/test", "GET");
    assert_eq!(results.len(), 1);
    let auth_header = &results[0].headers[0];
    assert_eq!(auth_header.0, "Authorization");
    assert!(auth_header.1.starts_with("Bearer key-"));
}

#[test]
fn api_key_multiplexing_skipped_when_no_keys() {
    let config = RateLimitBypassConfig {
        api_keys: Vec::new(),
        enabled_techniques: vec![BypassTechnique::ApiKeyMultiplexing],
        ..Default::default()
    };
    let mut engine = RateLimitBypassEngine::new(config, 0);
    let results = engine.generate_bypass("/test", "GET");
    assert!(results.is_empty());
}

#[test]
fn endpoint_aliasing_produces_multiple_variants() {
    let aliases = generate_path_aliases("/api/v1/users");
    assert!(
        aliases.len() >= 4,
        "expected >=4 aliases, got {}",
        aliases.len()
    );
    assert!(aliases.iter().any(|a| a.ends_with('/')));
    assert!(aliases.iter().any(|a| a.contains("//")));
}

#[test]
fn endpoint_aliasing_trailing_slash_toggle() {
    let with_slash = generate_path_aliases("/api/users/");
    assert!(with_slash.iter().any(|a| a == "/api/users"));

    let without_slash = generate_path_aliases("/api/users");
    assert!(without_slash.iter().any(|a| a == "/api/users/"));
}

#[test]
fn endpoint_aliasing_cache_buster_param() {
    let aliases = generate_path_aliases("/api/users");
    assert!(aliases.iter().any(|a| a.contains("?_=")));
}

#[test]
fn http_method_switching_excludes_original() {
    let config = RateLimitBypassConfig {
        enabled_techniques: vec![BypassTechnique::HttpMethodSwitching],
        ..Default::default()
    };
    let mut engine = RateLimitBypassEngine::new(config, 0);
    let results = engine.generate_bypass("/test", "GET");
    for req in &results {
        assert_ne!(req.method, "GET");
    }
    assert!(results.len() >= 4);
}

#[test]
fn unicode_path_normalization_at_least_five_variants() {
    let variants = generate_unicode_variants("/api/users");
    assert!(
        variants.len() >= 5,
        "expected >=5 unicode variants, got {}",
        variants.len()
    );
}

#[test]
fn unicode_path_normalization_includes_percent_encoding() {
    let variants = generate_unicode_variants("/api/users");
    assert!(
        variants.iter().any(|v| v.contains('%')),
        "expected at least one percent-encoded variant"
    );
}

#[test]
fn unicode_path_normalization_includes_fullwidth() {
    let variants = generate_unicode_variants("/api/users");
    let has_fullwidth = variants
        .iter()
        .any(|v| v.chars().any(|c| (0xFF21..=0xFF3A).contains(&(c as u32))));
    assert!(has_fullwidth, "expected a fullwidth character variant");
}

#[test]
fn unicode_path_normalization_slash_encoding() {
    let variants = generate_unicode_variants("/api/users");
    assert!(
        variants
            .iter()
            .any(|v| v.contains("%2F") || v.contains("%2f")),
        "expected slash-encoded variant"
    );
}

#[test]
fn h2_multiplex_increments_stream_id() {
    let config = RateLimitBypassConfig {
        enabled_techniques: vec![BypassTechnique::Http2Multiplexing],
        h2_max_streams: 10,
        ..Default::default()
    };
    let mut engine = RateLimitBypassEngine::new(config, 0);

    let r1 = engine.generate_bypass("/test", "GET");
    let r2 = engine.generate_bypass("/test", "GET");

    let id1: u32 = r1[0].headers[0].1.parse().unwrap();
    let id2: u32 = r2[0].headers[0].1.parse().unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn h2_multiplex_wraps_at_max_streams() {
    let config = RateLimitBypassConfig {
        enabled_techniques: vec![BypassTechnique::Http2Multiplexing],
        h2_max_streams: 3,
        ..Default::default()
    };
    let mut engine = RateLimitBypassEngine::new(config, 0);

    let mut ids = Vec::new();
    for _ in 0..4 {
        let results = engine.generate_bypass("/test", "GET");
        let id: u32 = results[0].headers[0].1.parse().unwrap();
        ids.push(id);
    }
    assert!(ids.contains(&0), "stream id should wrap back to 0");
}

#[test]
fn distributed_timing_uniform_jitter() {
    let config = RateLimitBypassConfig {
        jitter_shape: JitterShape::Uniform,
        min_delay_ms: 100,
        max_delay_ms: 500,
        enabled_techniques: vec![BypassTechnique::DistributedTiming],
        ..Default::default()
    };
    let mut engine = RateLimitBypassEngine::new(config, 42);

    for _ in 0..50 {
        let results = engine.generate_bypass("/test", "GET");
        let delay = results[0].delay_ms;
        assert!(delay >= 100 && delay <= 500, "delay {delay} out of range");
    }
}

#[test]
fn distributed_timing_normal_jitter() {
    let config = RateLimitBypassConfig {
        jitter_shape: JitterShape::Normal,
        min_delay_ms: 50,
        max_delay_ms: 200,
        enabled_techniques: vec![BypassTechnique::DistributedTiming],
        ..Default::default()
    };
    let mut engine = RateLimitBypassEngine::new(config, 77);

    for _ in 0..50 {
        let delay = engine.compute_jitter_ms();
        assert!(
            delay >= 50 && delay <= 200,
            "normal delay {delay} out of range"
        );
    }
}

#[test]
fn distributed_timing_exponential_jitter() {
    let config = RateLimitBypassConfig {
        jitter_shape: JitterShape::Exponential,
        min_delay_ms: 10,
        max_delay_ms: 1000,
        enabled_techniques: vec![BypassTechnique::DistributedTiming],
        ..Default::default()
    };
    let mut engine = RateLimitBypassEngine::new(config, 12);

    for _ in 0..50 {
        let delay = engine.compute_jitter_ms();
        assert!(
            delay >= 10 && delay <= 1000,
            "exponential delay {delay} out of range"
        );
    }
}

#[test]
fn distributed_timing_equal_min_max_returns_min() {
    let config = RateLimitBypassConfig {
        jitter_shape: JitterShape::Normal,
        min_delay_ms: 100,
        max_delay_ms: 100,
        enabled_techniques: vec![BypassTechnique::DistributedTiming],
        ..Default::default()
    };
    let mut engine = RateLimitBypassEngine::new(config, 0);
    let delay = engine.compute_jitter_ms();
    assert_eq!(delay, 100);
}

#[test]
fn case_variation_produces_multiple_variants() {
    let variants = generate_case_variants("/api/v1/users");
    assert!(variants.len() >= 3);
    assert!(variants.contains(&"/API/V1/USERS".to_string()));
    assert!(variants.contains(&"/api/v1/users".to_string()));
}

#[test]
fn case_variation_alternating_case() {
    let variants = generate_case_variants("/api/users");
    let has_alternating = variants.iter().any(|v| {
        let chars: Vec<char> = v.chars().collect();
        chars.len() > 2
            && chars
                .iter()
                .enumerate()
                .any(|(i, c)| i > 0 && c.is_uppercase() && chars[i - 1].is_lowercase())
    });
    assert!(has_alternating, "expected an alternating-case variant");
}

#[test]
fn content_type_switching_produces_variants() {
    let config = RateLimitBypassConfig {
        enabled_techniques: vec![BypassTechnique::ContentTypeSwitching],
        ..Default::default()
    };
    let mut engine = RateLimitBypassEngine::new(config, 0);
    let results = engine.generate_bypass("/api/test", "POST");
    assert!(results.len() >= 4);

    let types: Vec<&str> = results.iter().map(|r| r.headers[0].1.as_str()).collect();
    assert!(types.contains(&"application/json"));
    assert!(types.contains(&"application/xml"));
}

#[test]
fn referer_manipulation_produces_variants() {
    let config = RateLimitBypassConfig {
        enabled_techniques: vec![BypassTechnique::RefererManipulation],
        ..Default::default()
    };
    let mut engine = RateLimitBypassEngine::new(config, 0);
    let results = engine.generate_bypass("/api/test", "GET");
    assert!(results.len() >= 4);

    for req in &results {
        let header_names: Vec<&str> = req.headers.iter().map(|(n, _)| n.as_str()).collect();
        assert!(header_names.contains(&"Referer"));
        assert!(header_names.contains(&"Origin"));
    }
}

#[test]
fn generate_bypass_all_techniques_returns_nonempty() {
    let config = RateLimitBypassConfig {
        api_keys: vec!["test-key".to_string()],
        ..Default::default()
    };
    let mut engine = RateLimitBypassEngine::new(config, 42);
    let results = engine.generate_bypass("/api/v1/users", "GET");
    assert!(
        results.len() > 10,
        "expected >10 bypass requests, got {}",
        results.len()
    );

    let techniques: std::collections::HashSet<BypassTechnique> =
        results.iter().map(|r| r.technique).collect();
    assert_eq!(
        techniques.len(),
        10,
        "all 10 techniques should be represented"
    );
}

#[test]
fn builder_produces_custom_config() {
    let config = RateLimitBypassConfigBuilder::new()
        .with_ip_pool(vec!["9.9.9.9".to_string()])
        .with_api_keys(vec!["my-key".to_string()])
        .with_jitter_shape(JitterShape::Exponential)
        .with_delay_range(10, 100)
        .with_h2_max_streams(50)
        .build();

    assert_eq!(config.ip_pool, vec!["9.9.9.9"]);
    assert_eq!(config.api_keys, vec!["my-key"]);
    assert_eq!(config.jitter_shape, JitterShape::Exponential);
    assert_eq!(config.min_delay_ms, 10);
    assert_eq!(config.max_delay_ms, 100);
    assert_eq!(config.h2_max_streams, 50);
}

#[test]
fn builder_with_techniques_limits_output() {
    let config = RateLimitBypassConfigBuilder::new()
        .with_techniques(vec![
            BypassTechnique::IpRotation,
            BypassTechnique::CaseVariation,
        ])
        .build();
    let mut engine = RateLimitBypassEngine::new(config, 0);
    let results = engine.generate_bypass("/test", "GET");
    let techniques: std::collections::HashSet<BypassTechnique> =
        results.iter().map(|r| r.technique).collect();
    assert!(techniques.contains(&BypassTechnique::IpRotation));
    assert!(techniques.contains(&BypassTechnique::CaseVariation));
    assert!(!techniques.contains(&BypassTechnique::ContentTypeSwitching));
}

#[test]
fn default_config_has_eight_ips_in_pool() {
    let config = RateLimitBypassConfig::default();
    assert!(config.ip_pool.len() >= 8);
}

#[test]
fn technique_summary_reflects_enabled() {
    let config = RateLimitBypassConfigBuilder::new()
        .with_techniques(vec![BypassTechnique::IpRotation])
        .build();
    let summary = technique_summary(&config);
    assert_eq!(summary[&BypassTechnique::IpRotation], true);
    assert_eq!(summary[&BypassTechnique::CaseVariation], false);
}

#[test]
fn engine_config_accessor() {
    let config = RateLimitBypassConfig::default();
    let engine = RateLimitBypassEngine::new(config.clone(), 0);
    assert_eq!(engine.config().h2_max_streams, config.h2_max_streams);
}

#[test]
fn bypass_request_preserves_original_path_for_non_path_techniques() {
    let config = RateLimitBypassConfig {
        enabled_techniques: vec![
            BypassTechnique::IpRotation,
            BypassTechnique::ContentTypeSwitching,
        ],
        ..Default::default()
    };
    let mut engine = RateLimitBypassEngine::new(config, 0);
    let results = engine.generate_bypass("/exact/path", "POST");
    for req in &results {
        assert_eq!(req.path, "/exact/path");
    }
}

#[test]
fn path_aliases_dotdot_traversal() {
    let aliases = generate_path_aliases("/api/v1/users");
    assert!(
        aliases.iter().any(|a| a.contains("../")),
        "expected a dot-dot traversal alias"
    );
}

#[test]
fn unicode_variants_double_encoding_only_when_percent_present() {
    let variants_no_pct = generate_unicode_variants("/api/users");
    let variants_with_pct = generate_unicode_variants("/api/users%20test");
    assert!(variants_with_pct.iter().any(|v| v.contains("%25")));
    assert!(!variants_no_pct.iter().any(|v| v.contains("%25")));
}
