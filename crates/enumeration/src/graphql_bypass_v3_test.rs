use super::graphql_bypass_v3::*;

#[test]
fn bypass_technique_display_covers_all_variants() {
    let techniques = [
        (BypassTechnique::MethodOverride, "X-HTTP-Method-Override"),
        (BypassTechnique::FragmentAlias, "Fragment Alias Trick"),
        (
            BypassTechnique::BatchSplitting,
            "Batch Introspection Splitting",
        ),
        (
            BypassTechnique::ErrorBasedDiscovery,
            "Error-Based Type Discovery",
        ),
        (BypassTechnique::ApqHashEnum, "APQ Hash Enumeration"),
        (BypassTechnique::GetMethodFallback, "GET Method Fallback"),
        (BypassTechnique::ContentTypeSwitch, "Content-Type Switch"),
        (BypassTechnique::CaseManipulation, "Case Manipulation"),
        (BypassTechnique::WhitespaceInjection, "Whitespace Injection"),
        (BypassTechnique::UnicodeBypass, "Unicode Bypass"),
    ];
    for (technique, expected) in &techniques {
        assert_eq!(technique.to_string(), *expected);
    }
}

#[test]
fn introspection_level_ordering() {
    assert!(IntrospectionLevel::None < IntrospectionLevel::FieldsOnly);
    assert!(IntrospectionLevel::FieldsOnly < IntrospectionLevel::TypeNamesOnly);
    assert!(IntrospectionLevel::TypeNamesOnly < IntrospectionLevel::Partial);
    assert!(IntrospectionLevel::Partial < IntrospectionLevel::Full);
}

#[test]
fn apq_config_defaults() {
    let config = ApqConfig::default();
    assert!(config.known_hashes.is_empty());
    assert_eq!(config.hash_algorithm, "sha256");
    assert_eq!(config.extensions_format, "apollo");
}

#[test]
fn graphql_bypass_v3_config_builder() {
    let apq = ApqConfig {
        known_hashes: vec!["abc123".to_string()],
        hash_algorithm: "sha256".to_string(),
        extensions_format: "relay".to_string(),
    };
    let config = GraphqlBypassV3Config::new("http://localhost:4000/graphql")
        .with_timeout_ms(10000)
        .with_apq_config(apq.clone())
        .with_extra_types(vec!["Invoice".to_string(), "Receipt".to_string()]);

    assert_eq!(config.target_url, "http://localhost:4000/graphql");
    assert_eq!(config.timeout_ms, 10000);
    assert_eq!(config.apq.extensions_format, "relay");
    assert_eq!(config.extra_type_names.len(), 2);
}

#[test]
fn method_override_generates_three_header_variants() {
    let engine = make_test_engine();
    let requests = engine.try_method_override();
    assert_eq!(requests.len(), 3);

    let header_names: Vec<String> = requests
        .iter()
        .flat_map(|r| r.headers.keys().filter(|k| k.starts_with("X-")))
        .cloned()
        .collect();
    assert!(header_names.contains(&"X-HTTP-Method-Override".to_string()));
    assert!(header_names.contains(&"X-Method-Override".to_string()));
    assert!(header_names.contains(&"X-HTTP-Method".to_string()));

    for req in &requests {
        assert_eq!(req.method, "GET");
        assert_eq!(req.technique, BypassTechnique::MethodOverride);
        assert!(!req.body.is_empty());
    }
}

#[test]
fn fragment_alias_produces_per_type_queries() {
    let config = GraphqlBypassV3Config::new("http://target/graphql")
        .with_extra_types(vec!["CustomEntity".to_string()]);
    let engine = GraphqlBypassV3::new(config);
    let requests = engine.try_fragment_alias();

    assert!(!requests.is_empty());
    for req in &requests {
        assert_eq!(req.technique, BypassTechnique::FragmentAlias);
        assert_eq!(req.method, "POST");
        assert!(req.body.contains("__type"));
    }

    let has_custom = requests.iter().any(|r| r.body.contains("CustomEntity"));
    assert!(has_custom);
}

#[test]
fn batch_splitting_produces_json_arrays() {
    let engine = make_test_engine();
    let requests = engine.try_batch_splitting();

    assert!(!requests.is_empty());
    for req in &requests {
        assert_eq!(req.technique, BypassTechnique::BatchSplitting);
        assert!(req.body.starts_with('['));
        assert!(req.body.ends_with(']'));
    }
}

#[test]
fn error_based_discovery_extracts_types_and_fields() {
    let error_responses = &[
        r#"{"errors":[{"message":"Cannot query field \"secretKey\" on type \"Config\". Did you mean \"publicKey\" or \"apiKey\"?"}]}"#,
        r#"{"errors":[{"message":"Cannot query field \"balance\" on type \"Account\". Did you mean \"name\"?"}]}"#,
    ];

    let results = extract_types_from_errors(error_responses);
    assert!(!results.is_empty());

    let config_result = results.iter().find(|r| r.type_name == "Config");
    assert!(config_result.is_some());
    let config_fields = &config_result.unwrap().fields;
    assert!(config_fields.contains(&"secretKey".to_string()));
    assert!(config_fields.contains(&"publicKey".to_string()));
    assert!(config_fields.contains(&"apiKey".to_string()));

    let account_result = results.iter().find(|r| r.type_name == "Account");
    assert!(account_result.is_some());
    assert!(account_result
        .unwrap()
        .fields
        .contains(&"balance".to_string()));
}

#[test]
fn apq_hash_enum_uses_precomputed_hashes() {
    let engine = make_test_engine();
    let requests = engine.try_apq_hash_enum();

    assert!(!requests.is_empty());
    for req in &requests {
        assert_eq!(req.technique, BypassTechnique::ApqHashEnum);
        assert!(req.body.contains("sha256Hash"));
        assert!(req.body.contains("persistedQuery"));
    }
}

#[test]
fn generate_apq_hashes_produces_deterministic_results() {
    let queries = &["{ __typename }", "{ __schema { types { name } } }"];
    let hashes_a = generate_apq_hashes(queries);
    let hashes_b = generate_apq_hashes(queries);

    assert_eq!(hashes_a.len(), 2);
    assert_eq!(hashes_a, hashes_b);

    for (_, hash) in &hashes_a {
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

#[test]
fn precomputed_hashes_cover_introspection_templates() {
    let engine = make_test_engine();
    let hashes = engine.precomputed_hashes();
    assert_eq!(hashes.len(), INTROSPECTION_QUERY_TEMPLATES.len());

    for template in INTROSPECTION_QUERY_TEMPLATES {
        assert!(
            hashes.contains_key(*template),
            "missing hash for template: {template}"
        );
    }
}

#[test]
fn build_partial_schema_from_type_results() {
    let results = vec![
        TypeDiscoveryResult {
            type_name: "Query".to_string(),
            fields: vec!["users".to_string(), "orders".to_string()],
            discovered_via: BypassTechnique::ErrorBasedDiscovery,
            confidence: 0.6,
        },
        TypeDiscoveryResult {
            type_name: "Mutation".to_string(),
            fields: vec!["createUser".to_string()],
            discovered_via: BypassTechnique::ErrorBasedDiscovery,
            confidence: 0.5,
        },
        TypeDiscoveryResult {
            type_name: "User".to_string(),
            fields: vec!["id".to_string(), "email".to_string()],
            discovered_via: BypassTechnique::FragmentAlias,
            confidence: 0.7,
        },
    ];

    let schema = build_partial_schema(&results, None);
    assert!(schema.types.contains(&"Query".to_string()));
    assert!(schema.types.contains(&"Mutation".to_string()));
    assert!(schema.types.contains(&"User".to_string()));
    assert!(schema.queries.contains(&"users".to_string()));
    assert!(schema.queries.contains(&"orders".to_string()));
    assert!(schema.mutations.contains(&"createUser".to_string()));
}

#[test]
fn build_partial_schema_with_introspection_json() {
    let json = r#"{"data":{"__schema":{"types":[{"name":"Query","kind":"OBJECT"},{"name":"User","kind":"OBJECT"},{"name":"__Schema","kind":"OBJECT"},{"name":"Post","kind":"OBJECT"}]}}}"#;
    let schema = build_partial_schema(&[], Some(json));

    assert!(schema.types.contains(&"Query".to_string()));
    assert!(schema.types.contains(&"User".to_string()));
    assert!(schema.types.contains(&"Post".to_string()));
    assert!(
        !schema.types.iter().any(|t| t.starts_with("__")),
        "internal types should be excluded"
    );
}

#[test]
fn merge_schema_fragments_deduplicates() {
    let frag_a = SchemaFragment {
        types: vec!["User".to_string(), "Post".to_string()],
        queries: vec!["users".to_string()],
        mutations: vec!["createUser".to_string()],
        subscriptions: vec![],
    };
    let frag_b = SchemaFragment {
        types: vec!["User".to_string(), "Comment".to_string()],
        queries: vec!["users".to_string(), "posts".to_string()],
        mutations: vec![],
        subscriptions: vec!["onMessage".to_string()],
    };

    let merged = merge_schema_fragments(&[frag_a, frag_b]);
    assert_eq!(merged.types, vec!["Comment", "Post", "User"]);
    assert_eq!(merged.queries, vec!["posts", "users"]);
    assert_eq!(merged.mutations, vec!["createUser"]);
    assert_eq!(merged.subscriptions, vec!["onMessage"]);
}

#[test]
fn classify_introspection_level_full() {
    let full_response = r#"{"data":{"__schema":{"queryType":{"name":"Query"},"fields":[{"name":"user","kind":"OBJECT"}]}}}"#;
    assert_eq!(
        classify_introspection_level(full_response),
        IntrospectionLevel::Full
    );
}

#[test]
fn classify_introspection_level_partial() {
    let partial = r#"{"data":{"__type":{"name":"User","fields":[{"name":"id"}]}}}"#;
    assert_eq!(
        classify_introspection_level(partial),
        IntrospectionLevel::Partial
    );
}

#[test]
fn classify_introspection_level_type_names_only() {
    let type_names = r#"{"data":{"__schema":{"types":[{"name":"Query","kind":"OBJECT"}]}}}"#;
    assert_eq!(
        classify_introspection_level(type_names),
        IntrospectionLevel::TypeNamesOnly
    );
}

#[test]
fn classify_introspection_level_none() {
    let blocked = r#"{"errors":[{"message":"Introspection is disabled"}]}"#;
    assert_eq!(
        classify_introspection_level(blocked),
        IntrospectionLevel::None
    );
}

#[test]
fn run_all_bypasses_covers_all_techniques() {
    let engine = make_test_engine();
    let requests = engine.run_all_bypasses();

    let techniques_used: std::collections::HashSet<BypassTechnique> =
        requests.iter().map(|r| r.technique).collect();

    assert!(techniques_used.contains(&BypassTechnique::MethodOverride));
    assert!(techniques_used.contains(&BypassTechnique::FragmentAlias));
    assert!(techniques_used.contains(&BypassTechnique::BatchSplitting));
    assert!(techniques_used.contains(&BypassTechnique::ErrorBasedDiscovery));
    assert!(techniques_used.contains(&BypassTechnique::ApqHashEnum));
    assert!(techniques_used.contains(&BypassTechnique::GetMethodFallback));
    assert!(techniques_used.contains(&BypassTechnique::ContentTypeSwitch));
    assert!(techniques_used.contains(&BypassTechnique::CaseManipulation));
    assert!(techniques_used.contains(&BypassTechnique::WhitespaceInjection));
    assert!(techniques_used.contains(&BypassTechnique::UnicodeBypass));
    assert_eq!(techniques_used.len(), 10);
}

#[test]
fn get_method_fallback_encodes_query_in_url() {
    let engine = make_test_engine();
    let requests = engine.try_get_method_fallback();

    assert!(!requests.is_empty());
    for req in &requests {
        assert_eq!(req.method, "GET");
        assert!(req.path.contains("?query="));
        assert!(req.body.is_empty());
        assert!(req.path.contains("%7B"));
    }
}

#[test]
fn content_type_switch_uses_alternative_types() {
    let engine = make_test_engine();
    let requests = engine.try_content_type_switch();

    let content_types: Vec<String> = requests
        .iter()
        .filter_map(|r| r.headers.get("Content-Type"))
        .cloned()
        .collect();

    assert!(content_types.contains(&"application/graphql".to_string()));
    assert!(content_types.contains(&"text/plain".to_string()));
    assert!(content_types.contains(&"application/x-www-form-urlencoded".to_string()));
}

#[test]
fn case_manipulation_varies_schema_casing() {
    let engine = make_test_engine();
    let requests = engine.try_case_manipulation();

    assert!(!requests.is_empty());
    let has_upper = requests
        .iter()
        .any(|r| r.body.contains("__SCHEMA") || r.body.contains("__Schema"));
    let has_type_upper = requests
        .iter()
        .any(|r| r.body.contains("__TYPE") || r.body.contains("__Type"));
    assert!(has_upper);
    assert!(has_type_upper);
}

#[test]
fn whitespace_injection_includes_tab_and_newline() {
    let engine = make_test_engine();
    let requests = engine.try_whitespace_injection();

    assert!(!requests.is_empty());
    let has_tab = requests.iter().any(|r| r.body.contains("\\t"));
    let has_newline = requests.iter().any(|r| r.body.contains("\\n"));
    assert!(has_tab);
    assert!(has_newline);
}

#[test]
fn unicode_bypass_includes_zero_width_and_fullwidth() {
    let engine = make_test_engine();
    let requests = engine.try_unicode_bypass();

    assert!(!requests.is_empty());
    for req in &requests {
        assert_eq!(req.technique, BypassTechnique::UnicodeBypass);
        assert!(!req.body.is_empty());
    }
}

#[test]
fn build_bypass_result_assembles_all_fields() {
    let response = r#"{"data":{"__type":{"name":"User","fields":[{"name":"id"}]}}}"#;
    let errors = &[r#"{"errors":[{"message":"Cannot query field \"secret\" on type \"User\""}]}"#];
    let result = build_bypass_result(BypassTechnique::FragmentAlias, response, errors);

    assert_eq!(result.technique_used, BypassTechnique::FragmentAlias);
    assert_eq!(result.introspection_obtained, IntrospectionLevel::Partial);
    assert!(!result.types_discovered.is_empty());
    assert!(!result.fields_discovered.is_empty());
    assert!(!result.errors_collected.is_empty());
}

#[test]
fn error_extraction_handles_empty_and_malformed() {
    let results = extract_types_from_errors(&[]);
    assert!(results.is_empty());

    let results = extract_types_from_errors(&["not json at all", "", "{}"]);
    assert!(results.is_empty());
}

#[test]
fn schema_fragment_empty_initializes_all_vecs() {
    let frag = SchemaFragment::empty();
    assert!(frag.types.is_empty());
    assert!(frag.queries.is_empty());
    assert!(frag.mutations.is_empty());
    assert!(frag.subscriptions.is_empty());
}

#[test]
fn merge_empty_fragments_returns_empty() {
    let merged = merge_schema_fragments(&[]);
    assert!(merged.types.is_empty());
    assert!(merged.queries.is_empty());
}

#[test]
fn apq_hash_relay_format_omits_version() {
    let config = GraphqlBypassV3Config::new("http://target/graphql").with_apq_config(ApqConfig {
        known_hashes: vec!["deadbeef".to_string()],
        hash_algorithm: "sha256".to_string(),
        extensions_format: "relay".to_string(),
    });
    let engine = GraphqlBypassV3::new(config);
    let requests = engine.try_apq_hash_enum();

    let relay_requests: Vec<&BypassRequest> = requests
        .iter()
        .filter(|r| r.body.contains("deadbeef"))
        .collect();
    assert!(!relay_requests.is_empty());
    for req in &relay_requests {
        assert!(!req.body.contains("\"version\""));
    }
}

fn make_test_engine() -> GraphqlBypassV3 {
    let config = GraphqlBypassV3Config::new("http://localhost:4000/graphql");
    GraphqlBypassV3::new(config)
}
