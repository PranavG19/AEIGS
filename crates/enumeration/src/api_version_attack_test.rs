use std::collections::HashSet;

use crate::api_version_attack::{
    ALL_SCHEMES, AttackCategory, CONTENT_TYPE_PATTERNS, VERSION_HEADERS, VERSION_PROBES,
    VERSION_QUERY_PARAMS, VersionAttackConfig, VersionAttackEngine, VersionProbe,
    VersionedEndpoint, VersioningScheme, diff_versions, extract_host, graphql_schema_diff_queries,
    unique_schemes, unique_versions, version_ordinal,
};

#[test]
fn all_schemes_has_at_least_five() {
    assert!(ALL_SCHEMES.len() >= 5, "Must support ≥5 versioning schemes");
}

#[test]
fn all_schemes_contains_required_types() {
    let schemes: HashSet<VersioningScheme> = ALL_SCHEMES.iter().copied().collect();
    assert!(schemes.contains(&VersioningScheme::UrlPath));
    assert!(schemes.contains(&VersioningScheme::Header));
    assert!(schemes.contains(&VersioningScheme::QueryParam));
    assert!(schemes.contains(&VersioningScheme::Subdomain));
    assert!(schemes.contains(&VersioningScheme::ContentType));
}

#[test]
fn version_probes_has_at_least_twenty() {
    assert!(
        VERSION_PROBES.len() >= 20,
        "Must have ≥20 version probe values, got {}",
        VERSION_PROBES.len()
    );
}

#[test]
fn version_probes_includes_required_values() {
    let probes: HashSet<&str> = VERSION_PROBES.iter().copied().collect();
    for required in &[
        "v0", "v1", "v2", "v10", "beta", "alpha", "canary", "internal", "latest", "edge",
    ] {
        assert!(
            probes.contains(required),
            "Missing required probe: {}",
            required
        );
    }
}

#[test]
fn config_builder_defaults() {
    let config = VersionAttackConfig::new("https://api.example.com");
    assert_eq!(config.base_url, "https://api.example.com");
    assert!(config.known_endpoints.is_empty());
    assert_eq!(config.schemes.len(), ALL_SCHEMES.len());
    assert_eq!(config.version_values.len(), VERSION_PROBES.len());
    assert!(config.current_version.is_none());
}

#[test]
fn config_builder_with_endpoints() {
    let config = VersionAttackConfig::new("https://api.example.com")
        .with_endpoints(vec!["/users".to_string(), "/orders".to_string()]);
    assert_eq!(config.known_endpoints.len(), 2);
}

#[test]
fn config_strips_trailing_slash() {
    let config = VersionAttackConfig::new("https://api.example.com/");
    assert_eq!(config.base_url, "https://api.example.com");
}

#[test]
fn url_path_probes_generated() {
    let config = VersionAttackConfig::new("https://api.example.com")
        .with_endpoints(vec!["/users".to_string()])
        .with_version_values(vec!["v1".to_string(), "v2".to_string()]);
    let engine = VersionAttackEngine::new(config);
    let probes = engine.generate_url_path_probes();
    assert_eq!(probes.len(), 2);
    assert_eq!(probes[0].scheme, VersioningScheme::UrlPath);
    assert!(probes[0].url.contains("/v1/users"));
    assert!(probes[1].url.contains("/v2/users"));
}

#[test]
fn header_probes_generated_per_header_name() {
    let config = VersionAttackConfig::new("https://api.example.com")
        .with_endpoints(vec!["/users".to_string()])
        .with_version_values(vec!["v1".to_string()]);
    let engine = VersionAttackEngine::new(config);
    let probes = engine.generate_header_probes();
    assert_eq!(probes.len(), VERSION_HEADERS.len());
    for probe in &probes {
        assert_eq!(probe.scheme, VersioningScheme::Header);
        assert!(!probe.headers.is_empty());
    }
}

#[test]
fn query_param_probes_generated_per_param_name() {
    let config = VersionAttackConfig::new("https://api.example.com")
        .with_endpoints(vec!["/users".to_string()])
        .with_version_values(vec!["v1".to_string()]);
    let engine = VersionAttackEngine::new(config);
    let probes = engine.generate_query_param_probes();
    assert_eq!(probes.len(), VERSION_QUERY_PARAMS.len());
    for probe in &probes {
        assert_eq!(probe.scheme, VersioningScheme::QueryParam);
        assert!(probe.url.contains('?'));
    }
}

#[test]
fn subdomain_probes_generated() {
    let config = VersionAttackConfig::new("https://api.example.com")
        .with_version_values(vec!["v1".to_string(), "beta".to_string()]);
    let engine = VersionAttackEngine::new(config);
    let probes = engine.generate_subdomain_probes();
    assert_eq!(probes.len(), 2);
    assert!(probes[0].url.contains("v1.api.example.com"));
    assert!(probes[1].url.contains("beta.api.example.com"));
}

#[test]
fn content_type_probes_generated() {
    let config = VersionAttackConfig::new("https://api.example.com")
        .with_endpoints(vec!["/users".to_string()])
        .with_version_values(vec!["v1".to_string()]);
    let engine = VersionAttackEngine::new(config);
    let probes = engine.generate_content_type_probes();
    assert_eq!(probes.len(), CONTENT_TYPE_PATTERNS.len());
    for probe in &probes {
        assert_eq!(probe.scheme, VersioningScheme::ContentType);
        assert!(probe.headers.contains_key("Content-Type"));
    }
}

#[test]
fn accept_header_probes_generated() {
    let config = VersionAttackConfig::new("https://api.example.com")
        .with_endpoints(vec!["/users".to_string()])
        .with_version_values(vec!["v1".to_string()]);
    let engine = VersionAttackEngine::new(config);
    let probes = engine.generate_accept_header_probes();
    assert_eq!(probes.len(), 2);
    for probe in &probes {
        assert_eq!(probe.scheme, VersioningScheme::AcceptHeader);
        assert!(probe.headers.contains_key("Accept"));
    }
}

#[test]
fn generate_all_probes_covers_all_schemes() {
    let config = VersionAttackConfig::new("https://api.example.com")
        .with_endpoints(vec!["/users".to_string()])
        .with_version_values(vec!["v1".to_string()]);
    let engine = VersionAttackEngine::new(config);
    let probes = engine.generate_all_probes();
    let schemes = unique_schemes(&probes);
    assert!(schemes.len() >= 5);
}

#[test]
fn undocumented_version_probes_generated() {
    let config = VersionAttackConfig::new("https://api.example.com")
        .with_endpoints(vec!["/users".to_string()]);
    let engine = VersionAttackEngine::new(config);
    let attacks = engine.generate_undocumented_version_probes();
    assert!(!attacks.is_empty());
    for attack in &attacks {
        assert_eq!(attack.category, AttackCategory::UndocumentedVersion);
    }
    let versions: HashSet<&str> = attacks
        .iter()
        .map(|a| a.probe.version_value.as_str())
        .collect();
    assert!(versions.contains("v0"));
    assert!(versions.contains("v99"));
    assert!(versions.contains("internal"));
    assert!(versions.contains("canary"));
}

#[test]
fn rollback_probes_target_older_versions() {
    let config = VersionAttackConfig::new("https://api.example.com")
        .with_endpoints(vec!["/users".to_string()])
        .with_current_version("v3");
    let engine = VersionAttackEngine::new(config);
    let attacks = engine.generate_rollback_probes();
    assert!(!attacks.is_empty());
    for attack in &attacks {
        assert_eq!(attack.category, AttackCategory::VersionRollback);
        let ordinal = version_ordinal(&attack.probe.version_value);
        assert!(ordinal < version_ordinal("v3"));
    }
}

#[test]
fn mixed_version_idor_probes_generated() {
    let config = VersionAttackConfig::new("https://api.example.com")
        .with_endpoints(vec!["/users/1".to_string()]);
    let engine = VersionAttackEngine::new(config);
    let attacks = engine.generate_mixed_version_idor_probes();
    assert!(!attacks.is_empty());
    for attack in &attacks {
        assert_eq!(attack.category, AttackCategory::MixedVersionIdor);
        assert!(attack.probe.headers.contains_key("API-Version"));
    }
}

#[test]
fn header_injection_probes_generated() {
    let config = VersionAttackConfig::new("https://api.example.com")
        .with_endpoints(vec!["/users".to_string()]);
    let engine = VersionAttackEngine::new(config);
    let attacks = engine.generate_header_injection_probes();
    assert!(!attacks.is_empty());
    for attack in &attacks {
        assert_eq!(attack.category, AttackCategory::VersionHeaderInjection);
        assert!(attack.probe.url.contains("/v2/"));
    }
}

#[test]
fn gateway_bypass_probes_generated() {
    let config = VersionAttackConfig::new("https://api.example.com")
        .with_endpoints(vec!["/users".to_string()]);
    let engine = VersionAttackEngine::new(config);
    let attacks = engine.generate_gateway_bypass_probes();
    assert!(!attacks.is_empty());
    for attack in &attacks {
        assert_eq!(attack.category, AttackCategory::ApiGatewayBypass);
    }
    let urls: Vec<&str> = attacks.iter().map(|a| a.probe.url.as_str()).collect();
    assert!(urls.iter().any(|u| u.contains("/internal/")));
    assert!(urls.iter().any(|u| u.contains("/backend/")));
}

#[test]
fn generate_all_attacks_includes_all_categories() {
    let config = VersionAttackConfig::new("https://api.example.com")
        .with_endpoints(vec!["/users".to_string()])
        .with_current_version("v3");
    let engine = VersionAttackEngine::new(config);
    let attacks = engine.generate_all_attacks();
    let categories: HashSet<AttackCategory> = attacks.iter().map(|a| a.category).collect();
    assert!(categories.contains(&AttackCategory::UndocumentedVersion));
    assert!(categories.contains(&AttackCategory::VersionRollback));
    assert!(categories.contains(&AttackCategory::MixedVersionIdor));
    assert!(categories.contains(&AttackCategory::VersionHeaderInjection));
    assert!(categories.contains(&AttackCategory::ApiGatewayBypass));
}

#[test]
fn diff_versions_detects_removed_endpoints() {
    let old = vec![
        VersionedEndpoint {
            path: "/users".to_string(),
            method: "GET".to_string(),
            version: "v1".to_string(),
        },
        VersionedEndpoint {
            path: "/admin".to_string(),
            method: "GET".to_string(),
            version: "v1".to_string(),
        },
        VersionedEndpoint {
            path: "/debug".to_string(),
            method: "POST".to_string(),
            version: "v1".to_string(),
        },
    ];
    let new = vec![VersionedEndpoint {
        path: "/users".to_string(),
        method: "GET".to_string(),
        version: "v2".to_string(),
    }];
    let diff = diff_versions("v1", &old, "v2", &new);
    assert_eq!(diff.removed_in_new.len(), 2);
    assert_eq!(diff.deprecated_endpoints().len(), 2);
    let removed_paths: HashSet<&str> = diff
        .removed_in_new
        .iter()
        .map(|e| e.path.as_str())
        .collect();
    assert!(removed_paths.contains("/admin"));
    assert!(removed_paths.contains("/debug"));
}

#[test]
fn diff_versions_detects_added_endpoints() {
    let old = vec![VersionedEndpoint {
        path: "/users".to_string(),
        method: "GET".to_string(),
        version: "v1".to_string(),
    }];
    let new = vec![
        VersionedEndpoint {
            path: "/users".to_string(),
            method: "GET".to_string(),
            version: "v2".to_string(),
        },
        VersionedEndpoint {
            path: "/audit".to_string(),
            method: "GET".to_string(),
            version: "v2".to_string(),
        },
    ];
    let diff = diff_versions("v1", &old, "v2", &new);
    assert_eq!(diff.added_in_new.len(), 1);
    assert_eq!(diff.added_in_new[0].path, "/audit");
}

#[test]
fn diff_versions_empty_when_identical() {
    let endpoints = vec![VersionedEndpoint {
        path: "/users".to_string(),
        method: "GET".to_string(),
        version: "v1".to_string(),
    }];
    let diff = diff_versions("v1", &endpoints, "v2", &endpoints);
    assert!(diff.removed_in_new.is_empty());
    assert!(diff.added_in_new.is_empty());
}

#[test]
fn graphql_schema_diff_queries_generated() {
    let probes = graphql_schema_diff_queries("v1", "v2");
    assert!(probes.len() >= 2);
    for probe in &probes {
        assert_eq!(probe.category, AttackCategory::GraphqlSchemaDiff);
    }
}

#[test]
fn version_ordinal_numeric_sorting() {
    assert!(version_ordinal("v0") < version_ordinal("v1"));
    assert!(version_ordinal("v1") < version_ordinal("v2"));
    assert!(version_ordinal("v9") < version_ordinal("v10"));
}

#[test]
fn version_ordinal_named_versions() {
    assert!(version_ordinal("alpha") < version_ordinal("v0"));
    assert!(version_ordinal("beta") < version_ordinal("v0"));
    assert!(version_ordinal("legacy") < version_ordinal("alpha"));
    assert!(version_ordinal("latest") > version_ordinal("v10"));
}

#[test]
fn extract_host_strips_scheme_and_path() {
    assert_eq!(
        extract_host("https://api.example.com/v1/users"),
        "api.example.com"
    );
    assert_eq!(extract_host("http://localhost:8080/api"), "localhost:8080");
    assert_eq!(extract_host("api.example.com"), "api.example.com");
}

#[test]
fn unique_schemes_collects_distinct() {
    let probes = vec![
        VersionProbe {
            scheme: VersioningScheme::UrlPath,
            version_value: "v1".to_string(),
            url: "http://x/v1/a".to_string(),
            headers: Default::default(),
            description: String::new(),
        },
        VersionProbe {
            scheme: VersioningScheme::UrlPath,
            version_value: "v2".to_string(),
            url: "http://x/v2/a".to_string(),
            headers: Default::default(),
            description: String::new(),
        },
        VersionProbe {
            scheme: VersioningScheme::Header,
            version_value: "v1".to_string(),
            url: "http://x/a".to_string(),
            headers: Default::default(),
            description: String::new(),
        },
    ];
    let schemes = unique_schemes(&probes);
    assert_eq!(schemes.len(), 2);
}

#[test]
fn unique_versions_collects_distinct() {
    let probes = vec![
        VersionProbe {
            scheme: VersioningScheme::UrlPath,
            version_value: "v1".to_string(),
            url: String::new(),
            headers: Default::default(),
            description: String::new(),
        },
        VersionProbe {
            scheme: VersioningScheme::Header,
            version_value: "v1".to_string(),
            url: String::new(),
            headers: Default::default(),
            description: String::new(),
        },
        VersionProbe {
            scheme: VersioningScheme::UrlPath,
            version_value: "beta".to_string(),
            url: String::new(),
            headers: Default::default(),
            description: String::new(),
        },
    ];
    let versions = unique_versions(&probes);
    assert_eq!(versions.len(), 2);
}

#[test]
fn versioning_scheme_display() {
    assert_eq!(VersioningScheme::UrlPath.to_string(), "url-path");
    assert_eq!(VersioningScheme::Header.to_string(), "header");
    assert_eq!(VersioningScheme::QueryParam.to_string(), "query-param");
    assert_eq!(VersioningScheme::Subdomain.to_string(), "subdomain");
    assert_eq!(VersioningScheme::ContentType.to_string(), "content-type");
    assert_eq!(VersioningScheme::AcceptHeader.to_string(), "accept-header");
}

#[test]
fn attack_category_display() {
    assert_eq!(
        AttackCategory::VersionDiscovery.to_string(),
        "version-discovery"
    );
    assert_eq!(
        AttackCategory::DeprecatedEndpointAccess.to_string(),
        "deprecated-endpoint-access"
    );
    assert_eq!(
        AttackCategory::VersionRollback.to_string(),
        "version-rollback"
    );
    assert_eq!(
        AttackCategory::MixedVersionIdor.to_string(),
        "mixed-version-idor"
    );
    assert_eq!(
        AttackCategory::ApiGatewayBypass.to_string(),
        "api-gateway-bypass"
    );
}

#[test]
fn default_endpoints_used_when_none_configured() {
    let config = VersionAttackConfig::new("https://api.example.com")
        .with_version_values(vec!["v1".to_string()]);
    let engine = VersionAttackEngine::new(config);
    let probes = engine.generate_url_path_probes();
    assert!(!probes.is_empty());
    assert!(probes.iter().any(|p| p.url.contains("api/users")));
}

#[test]
fn rollback_with_no_current_version_defaults_to_v2() {
    let config = VersionAttackConfig::new("https://api.example.com")
        .with_endpoints(vec!["/users".to_string()]);
    let engine = VersionAttackEngine::new(config);
    let attacks = engine.generate_rollback_probes();
    assert!(!attacks.is_empty());
    for attack in &attacks {
        let ordinal = version_ordinal(&attack.probe.version_value);
        assert!(ordinal < version_ordinal("v2"));
    }
}

#[test]
fn config_with_custom_schemes() {
    let config = VersionAttackConfig::new("https://api.example.com")
        .with_schemes(vec![VersioningScheme::UrlPath, VersioningScheme::Header])
        .with_endpoints(vec!["/users".to_string()])
        .with_version_values(vec!["v1".to_string()]);
    let engine = VersionAttackEngine::new(config);
    let probes = engine.generate_all_probes();
    let schemes = unique_schemes(&probes);
    assert_eq!(schemes.len(), 2);
    assert!(schemes.contains(&VersioningScheme::UrlPath));
    assert!(schemes.contains(&VersioningScheme::Header));
    assert!(!schemes.contains(&VersioningScheme::Subdomain));
}
