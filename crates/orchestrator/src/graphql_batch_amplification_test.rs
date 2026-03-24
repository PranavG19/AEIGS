use super::*;

fn login_seed() -> OperationSeed {
    OperationSeed {
        operation_type: OperationType::Mutation,
        field_name: "login".to_string(),
        arguments: vec![
            (
                "username".to_string(),
                ArgumentSlot::Fixed("admin".to_string()),
            ),
            (
                "password".to_string(),
                ArgumentSlot::Fixed("test123".to_string()),
            ),
        ],
        selection_set: vec!["token".to_string(), "success".to_string()],
    }
}

fn user_query_seed() -> OperationSeed {
    OperationSeed {
        operation_type: OperationType::Query,
        field_name: "user".to_string(),
        arguments: vec![("id".to_string(), ArgumentSlot::BruteRange(1, 100))],
        selection_set: vec!["id".to_string(), "email".to_string(), "name".to_string()],
    }
}

fn simple_query_seed() -> OperationSeed {
    OperationSeed {
        operation_type: OperationType::Query,
        field_name: "me".to_string(),
        arguments: vec![],
        selection_set: vec!["id".to_string(), "role".to_string()],
    }
}

fn brute_login_seed(passwords: Vec<String>) -> OperationSeed {
    OperationSeed {
        operation_type: OperationType::Mutation,
        field_name: "authenticate".to_string(),
        arguments: vec![
            ("user".to_string(), ArgumentSlot::Fixed("admin".to_string())),
            ("pass".to_string(), ArgumentSlot::Iterable(passwords)),
        ],
        selection_set: vec!["ok".to_string(), "jwt".to_string()],
    }
}

#[test]
fn test_default_config() {
    let config = BatchConfig::default();
    assert_eq!(config.max_aliases_per_query, 500);
    assert_eq!(config.max_queries_per_batch, 100);
    assert_eq!(config.max_depth, 7);
    assert!(config.include_introspection_probe);
    assert_eq!(config.techniques.len(), 5);
}

#[test]
fn test_engine_creation() {
    let engine = BatchAmplificationEngine::new(BatchConfig::default());
    assert!(!engine.behavior().supports_array_batch);
    assert!(!engine.behavior().supports_aliases);
    assert_eq!(engine.behavior().rate_limit_scope, RateLimitScope::Unknown);
}

#[test]
fn test_engine_with_behavior() {
    let behavior = BatchBehavior {
        supports_array_batch: true,
        max_observed_batch_size: 50,
        ..Default::default()
    };
    let engine = BatchAmplificationEngine::new(BatchConfig::default()).with_behavior(behavior);
    assert!(engine.behavior().supports_array_batch);
    assert_eq!(engine.behavior().max_observed_batch_size, 50);
}

#[test]
fn test_array_batch_generation() {
    let config = BatchConfig {
        max_queries_per_batch: 10,
        techniques: vec![AmplificationTechnique::ArrayBatch],
        ..Default::default()
    };
    let engine = BatchAmplificationEngine::new(config);
    let payloads = engine.generate_payloads(&login_seed());

    assert!(!payloads.is_empty());
    for p in &payloads {
        assert_eq!(p.technique, AmplificationTechnique::ArrayBatch);
        assert!(p.body.starts_with('['));
        assert!(p.body.ends_with(']'));
        assert!(p.operation_count >= 2);
        assert_eq!(p.purpose, PayloadPurpose::RateLimitBypass);
    }
}

#[test]
fn test_array_batch_contains_query() {
    let config = BatchConfig {
        max_queries_per_batch: 5,
        techniques: vec![AmplificationTechnique::ArrayBatch],
        ..Default::default()
    };
    let engine = BatchAmplificationEngine::new(config);
    let payloads = engine.generate_payloads(&login_seed());

    for p in &payloads {
        assert!(p.body.contains("login"));
        assert!(p.body.contains("mutation"));
    }
}

#[test]
fn test_alias_brute_range() {
    let config = BatchConfig {
        max_aliases_per_query: 50,
        techniques: vec![AmplificationTechnique::AliasDuplication],
        ..Default::default()
    };
    let engine = BatchAmplificationEngine::new(config);
    let payloads = engine.generate_payloads(&user_query_seed());

    assert!(!payloads.is_empty());
    let p = &payloads[0];
    assert_eq!(p.technique, AmplificationTechnique::AliasDuplication);
    assert!(p.body.contains("a0:"));
    assert!(p.body.contains("a1:"));
    assert_eq!(p.purpose, PayloadPurpose::BruteForce);
}

#[test]
fn test_alias_iterable() {
    let passwords = vec!["pass1".into(), "pass2".into(), "pass3".into()];
    let seed = brute_login_seed(passwords);
    let config = BatchConfig {
        max_aliases_per_query: 100,
        techniques: vec![AmplificationTechnique::AliasDuplication],
        ..Default::default()
    };
    let engine = BatchAmplificationEngine::new(config);
    let payloads = engine.generate_payloads(&seed);

    assert!(!payloads.is_empty());
    let p = &payloads[0];
    assert_eq!(p.technique, AmplificationTechnique::AliasDuplication);
    assert_eq!(p.purpose, PayloadPurpose::DataExfiltration);
    assert_eq!(p.operation_count, 3);
    assert!(p.body.contains("a0:"));
    assert!(p.body.contains("a2:"));
}

#[test]
fn test_alias_no_iterable_fallback() {
    let config = BatchConfig {
        max_aliases_per_query: 10,
        techniques: vec![AmplificationTechnique::AliasDuplication],
        ..Default::default()
    };
    let engine = BatchAmplificationEngine::new(config);
    let payloads = engine.generate_payloads(&simple_query_seed());

    assert!(!payloads.is_empty());
    let p = &payloads[0];
    assert_eq!(p.purpose, PayloadPurpose::RateLimitBypass);
    assert!(p.operation_count <= 10);
}

#[test]
fn test_nested_fragment_generation() {
    let config = BatchConfig {
        max_depth: 7,
        techniques: vec![AmplificationTechnique::NestedFragment],
        ..Default::default()
    };
    let engine = BatchAmplificationEngine::new(config);
    let payloads = engine.generate_payloads(&simple_query_seed());

    assert_eq!(payloads.len(), 3); // depth 3, 5, 7
    for p in &payloads {
        assert_eq!(p.technique, AmplificationTechnique::NestedFragment);
        assert_eq!(p.purpose, PayloadPurpose::DenialOfService);
        assert_eq!(p.operation_count, 1);
        assert!(p.estimated_resolver_calls >= 8);
        assert!(p.body.contains("fragment F0"));
    }
}

#[test]
fn test_nested_fragment_respects_max_depth() {
    let config = BatchConfig {
        max_depth: 4,
        techniques: vec![AmplificationTechnique::NestedFragment],
        ..Default::default()
    };
    let engine = BatchAmplificationEngine::new(config);
    let payloads = engine.generate_payloads(&simple_query_seed());

    assert_eq!(payloads.len(), 1); // only depth 3 fits
}

#[test]
fn test_directive_overload_generation() {
    let config = BatchConfig {
        techniques: vec![AmplificationTechnique::DirectiveOverload],
        ..Default::default()
    };
    let engine = BatchAmplificationEngine::new(config);
    let payloads = engine.generate_payloads(&login_seed());

    assert_eq!(payloads.len(), 3);
    for p in &payloads {
        assert_eq!(p.technique, AmplificationTechnique::DirectiveOverload);
        assert_eq!(p.purpose, PayloadPurpose::CostAnalysis);
        assert!(p.body.contains("@include") || p.body.contains("@skip"));
    }
}

#[test]
fn test_variable_batch_generation() {
    let config = BatchConfig {
        max_queries_per_batch: 50,
        techniques: vec![AmplificationTechnique::VariableBatch],
        ..Default::default()
    };
    let engine = BatchAmplificationEngine::new(config);
    let payloads = engine.generate_payloads(&login_seed());

    assert!(!payloads.is_empty());
    for p in &payloads {
        assert_eq!(p.technique, AmplificationTechnique::VariableBatch);
        assert_eq!(p.purpose, PayloadPurpose::RateLimitBypass);
        assert!(p.body.contains("variables"));
    }
}

#[test]
fn test_variable_batch_empty_args() {
    let config = BatchConfig {
        techniques: vec![AmplificationTechnique::VariableBatch],
        ..Default::default()
    };
    let engine = BatchAmplificationEngine::new(config);
    let payloads = engine.generate_payloads(&simple_query_seed());

    assert!(payloads.is_empty());
}

#[test]
fn test_generate_all_techniques() {
    let engine = BatchAmplificationEngine::new(BatchConfig::default());
    let payloads = engine.generate_payloads(&login_seed());

    let techniques: Vec<AmplificationTechnique> = payloads.iter().map(|p| p.technique).collect();
    assert!(techniques.contains(&AmplificationTechnique::ArrayBatch));
    assert!(techniques.contains(&AmplificationTechnique::AliasDuplication));
    assert!(techniques.contains(&AmplificationTechnique::NestedFragment));
    assert!(techniques.contains(&AmplificationTechnique::DirectiveOverload));
    assert!(techniques.contains(&AmplificationTechnique::VariableBatch));
}

#[test]
fn test_brute_force_helper() {
    let passwords: Vec<String> = (0..20).map(|i| format!("pw{i}")).collect();
    let engine = BatchAmplificationEngine::new(BatchConfig::default());
    let payloads = engine.generate_brute_force("login", "admin", &passwords, &["token".into()]);

    assert!(!payloads.is_empty());
    let p = &payloads[0];
    assert_eq!(p.technique, AmplificationTechnique::AliasDuplication);
    assert!(p.body.contains("admin"));
    assert_eq!(p.operation_count, 20);
}

#[test]
fn test_id_enumeration_helper() {
    let engine = BatchAmplificationEngine::new(BatchConfig {
        max_aliases_per_query: 50,
        ..Default::default()
    });
    let payloads =
        engine.generate_id_enumeration("user", "id", (1, 30), &["email".into(), "name".into()]);

    assert!(!payloads.is_empty());
    let p = &payloads[0];
    assert_eq!(p.purpose, PayloadPurpose::BruteForce);
    assert_eq!(p.operation_count, 29);
    assert!(p.body.contains("a0:"));
    assert!(p.body.contains("user"));
}

#[test]
fn test_race_payload() {
    let seed = OperationSeed {
        operation_type: OperationType::Mutation,
        field_name: "transferFunds".to_string(),
        arguments: vec![
            ("amount".to_string(), ArgumentSlot::Fixed("100".to_string())),
            (
                "to".to_string(),
                ArgumentSlot::Fixed("attacker".to_string()),
            ),
        ],
        selection_set: vec!["success".to_string(), "balance".to_string()],
    };
    let engine = BatchAmplificationEngine::new(BatchConfig::default());
    let payload = engine.generate_race_payload(&seed, 10);

    assert_eq!(payload.technique, AmplificationTechnique::AliasDuplication);
    assert_eq!(payload.purpose, PayloadPurpose::RaceCondition);
    assert_eq!(payload.operation_count, 10);
    assert!(payload.body.contains("a0:"));
    assert!(payload.body.contains("a9:"));
    assert!(payload.body.contains("transferFunds"));
}

#[test]
fn test_analyze_array_batch_probe() {
    let mut engine = BatchAmplificationEngine::new(BatchConfig::default());
    let probes = vec![ProbeResult {
        technique: AmplificationTechnique::ArrayBatch,
        success: true,
        operations_executed: 25,
        response_time_ms: 100,
        error_message: None,
        raw_response: Some(r#"[{"data":{}},...]"#.into()),
    }];
    let findings = engine.analyze_behavior(&probes);

    assert!(!findings.is_empty());
    assert!(engine.behavior().supports_array_batch);
    assert_eq!(engine.behavior().max_observed_batch_size, 25);
    let f = &findings[0];
    assert_eq!(f.amplification_factor, 25.0);
    assert!(f.severity >= FindingSeverity::Medium);
}

#[test]
fn test_analyze_alias_probe() {
    let mut engine = BatchAmplificationEngine::new(BatchConfig::default());
    let probes = vec![ProbeResult {
        technique: AmplificationTechnique::AliasDuplication,
        success: true,
        operations_executed: 200,
        response_time_ms: 500,
        error_message: None,
        raw_response: Some("data ok".into()),
    }];
    let findings = engine.analyze_behavior(&probes);

    assert!(engine.behavior().supports_aliases);
    assert_eq!(engine.behavior().max_observed_aliases, 200);
    let f = &findings[0];
    assert_eq!(f.severity, FindingSeverity::High);
}

#[test]
fn test_analyze_depth_limit_detected() {
    let mut engine = BatchAmplificationEngine::new(BatchConfig::default());
    let probes = vec![ProbeResult {
        technique: AmplificationTechnique::NestedFragment,
        success: false,
        operations_executed: 0,
        response_time_ms: 10,
        error_message: Some("Query depth limit of 5 exceeded".into()),
        raw_response: None,
    }];
    let findings = engine.analyze_behavior(&probes);

    assert!(engine.behavior().has_query_depth_limit);
    assert_eq!(engine.behavior().observed_depth_limit, Some(5));
    assert_eq!(findings[0].severity, FindingSeverity::Info);
}

#[test]
fn test_analyze_no_depth_limit() {
    let mut engine = BatchAmplificationEngine::new(BatchConfig::default());
    let probes = vec![ProbeResult {
        technique: AmplificationTechnique::NestedFragment,
        success: true,
        operations_executed: 32,
        response_time_ms: 200,
        error_message: None,
        raw_response: Some("deep nesting accepted".into()),
    }];
    let findings = engine.analyze_behavior(&probes);

    assert!(!engine.behavior().has_query_depth_limit);
    let f = &findings[0];
    assert_eq!(f.severity, FindingSeverity::High);
    assert_eq!(f.amplification_factor, 32.0);
}

#[test]
fn test_analyze_directive_overload() {
    let mut engine = BatchAmplificationEngine::new(BatchConfig::default());
    let probes = vec![ProbeResult {
        technique: AmplificationTechnique::DirectiveOverload,
        success: true,
        operations_executed: 1,
        response_time_ms: 50,
        error_message: None,
        raw_response: Some("ok".into()),
    }];
    let findings = engine.analyze_behavior(&probes);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, FindingSeverity::Low);
}

#[test]
fn test_analyze_combined_amplification() {
    let mut engine = BatchAmplificationEngine::new(BatchConfig::default());
    let probes = vec![
        ProbeResult {
            technique: AmplificationTechnique::ArrayBatch,
            success: true,
            operations_executed: 50,
            response_time_ms: 100,
            error_message: None,
            raw_response: None,
        },
        ProbeResult {
            technique: AmplificationTechnique::AliasDuplication,
            success: true,
            operations_executed: 100,
            response_time_ms: 200,
            error_message: None,
            raw_response: None,
        },
    ];
    let findings = engine.analyze_behavior(&probes);

    let critical = findings
        .iter()
        .find(|f| f.severity == FindingSeverity::Critical);
    assert!(critical.is_some());
    let c = critical.unwrap();
    assert_eq!(c.amplification_factor, 5000.0);
    assert!(c.description.contains("5000"));
}

#[test]
fn test_analyze_failed_probes_no_findings() {
    let mut engine = BatchAmplificationEngine::new(BatchConfig::default());
    let probes = vec![
        ProbeResult {
            technique: AmplificationTechnique::ArrayBatch,
            success: false,
            operations_executed: 0,
            response_time_ms: 10,
            error_message: Some("batching disabled".into()),
            raw_response: None,
        },
        ProbeResult {
            technique: AmplificationTechnique::AliasDuplication,
            success: false,
            operations_executed: 0,
            response_time_ms: 10,
            error_message: Some("too many aliases".into()),
            raw_response: None,
        },
    ];
    let findings = engine.analyze_behavior(&probes);
    assert!(findings.is_empty());
}

#[test]
fn test_generate_probes() {
    let engine = BatchAmplificationEngine::new(BatchConfig::default());
    let probes = engine.generate_probes(&login_seed());

    assert_eq!(probes.len(), 3);
    let techniques: Vec<_> = probes.iter().map(|p| p.technique).collect();
    assert!(techniques.contains(&AmplificationTechnique::ArrayBatch));
    assert!(techniques.contains(&AmplificationTechnique::AliasDuplication));
    assert!(techniques.contains(&AmplificationTechnique::NestedFragment));
}

#[test]
fn test_probe_sizes_limited() {
    let config = BatchConfig {
        max_queries_per_batch: 3,
        techniques: vec![AmplificationTechnique::ArrayBatch],
        ..Default::default()
    };
    let engine = BatchAmplificationEngine::new(config);
    let payloads = engine.generate_payloads(&login_seed());

    for p in &payloads {
        assert!(p.operation_count <= 3);
    }
}

#[test]
fn test_escape_json() {
    let input = r#"query { login(u: "a", p: "b") { ok } }"#;
    let escaped = escape_json(input);
    assert!(!escaped.contains('"') || escaped.contains("\\\""));
    assert!(escaped.contains("\\\""));
}

#[test]
fn test_render_single_operation() {
    let seed = login_seed();
    let rendered = render_single_operation(&seed, None);
    assert!(rendered.starts_with("mutation"));
    assert!(rendered.contains("login"));
    assert!(rendered.contains("token"));
}

#[test]
fn test_render_with_alias() {
    let seed = login_seed();
    let rendered = render_single_operation(&seed, Some("attempt_0"));
    assert!(rendered.contains("attempt_0: login"));
}

#[test]
fn test_render_aliased_field_numeric_arg() {
    let seed = user_query_seed();
    let rendered = render_aliased_field(&seed, 5, "val");
    assert!(rendered.starts_with("a5:"));
    assert!(rendered.contains("id: 6")); // lo=1, index=5 → 6
    assert!(rendered.contains("email"));
}

#[test]
fn test_render_aliased_field_string_arg() {
    let seed = login_seed();
    let rendered = render_aliased_field(&seed, 0, "val");
    assert!(rendered.starts_with("a0:"));
    assert!(rendered.contains(r#"username: "admin""#));
}

#[test]
fn test_build_nested_fragments_depth_3() {
    let fragments = build_nested_fragments("user", 3);
    assert!(fragments.contains("fragment F0 on Query"));
    assert!(fragments.contains("fragment F1 on Query"));
    assert!(fragments.contains("fragment F2 on Query"));
    assert!(fragments.contains("...F1"));
    assert!(fragments.contains("...F2"));
    assert!(fragments.contains("__typename"));
}

#[test]
fn test_build_nested_fragments_depth_1() {
    let fragments = build_nested_fragments("me", 1);
    assert!(fragments.contains("fragment F0 on Query"));
    assert!(fragments.contains("__typename"));
    assert!(!fragments.contains("F1"));
}

#[test]
fn test_severity_for_factor() {
    assert_eq!(severity_for_factor(1.0), FindingSeverity::Info);
    assert_eq!(severity_for_factor(5.0), FindingSeverity::Low);
    assert_eq!(severity_for_factor(15.0), FindingSeverity::Medium);
    assert_eq!(severity_for_factor(75.0), FindingSeverity::High);
    assert_eq!(severity_for_factor(200.0), FindingSeverity::Critical);
}

#[test]
fn test_extract_depth_from_error() {
    assert_eq!(
        extract_depth_from_error("Query depth limit of 5 exceeded"),
        Some(5)
    );
    assert_eq!(
        extract_depth_from_error("maximum depth 10 reached"),
        Some(10)
    );
    assert_eq!(extract_depth_from_error("no numbers here"), None);
    assert_eq!(extract_depth_from_error("depth exceeded (7)"), Some(7));
}

#[test]
fn test_serde_style_map() {
    let mut map = HashMap::new();
    map.insert("count".to_string(), "42".to_string());
    map.insert("name".to_string(), "test".to_string());
    let json = serde_style_map(&map);
    assert!(json.starts_with('{'));
    assert!(json.ends_with('}'));
    assert!(json.contains(r#""count":42"#));
    assert!(json.contains(r#""name":"test""#));
}

#[test]
fn test_operation_type_display() {
    assert_eq!(format!("{}", OperationType::Query), "query");
    assert_eq!(format!("{}", OperationType::Mutation), "mutation");
}

#[test]
fn test_technique_display() {
    assert_eq!(
        format!("{}", AmplificationTechnique::ArrayBatch),
        "array-batch"
    );
    assert_eq!(
        format!("{}", AmplificationTechnique::AliasDuplication),
        "alias-duplication"
    );
    assert_eq!(
        format!("{}", AmplificationTechnique::NestedFragment),
        "nested-fragment"
    );
}

#[test]
fn test_purpose_display() {
    assert_eq!(format!("{}", PayloadPurpose::BruteForce), "brute-force");
    assert_eq!(
        format!("{}", PayloadPurpose::RaceCondition),
        "race-condition"
    );
}

#[test]
fn test_severity_ordering() {
    assert!(FindingSeverity::Info < FindingSeverity::Low);
    assert!(FindingSeverity::Low < FindingSeverity::Medium);
    assert!(FindingSeverity::Medium < FindingSeverity::High);
    assert!(FindingSeverity::High < FindingSeverity::Critical);
}

#[test]
fn test_estimated_resolver_calls_scaling() {
    let seed = user_query_seed(); // 3 fields in selection set
    let config = BatchConfig {
        max_queries_per_batch: 10,
        techniques: vec![AmplificationTechnique::ArrayBatch],
        ..Default::default()
    };
    let engine = BatchAmplificationEngine::new(config);
    let payloads = engine.generate_payloads(&seed);

    for p in &payloads {
        assert_eq!(p.estimated_resolver_calls, p.operation_count * 3);
    }
}

#[test]
fn test_brute_range_clamped_to_max_aliases() {
    let config = BatchConfig {
        max_aliases_per_query: 10,
        techniques: vec![AmplificationTechnique::AliasDuplication],
        ..Default::default()
    };
    let engine = BatchAmplificationEngine::new(config);
    let seed = OperationSeed {
        operation_type: OperationType::Query,
        field_name: "user".to_string(),
        arguments: vec![("id".to_string(), ArgumentSlot::BruteRange(1, 1000))],
        selection_set: vec!["name".to_string()],
    };
    let payloads = engine.generate_payloads(&seed);

    for p in &payloads {
        assert!(p.operation_count <= 10);
    }
}

#[test]
fn test_variable_batch_brute_range_values() {
    let config = BatchConfig {
        max_queries_per_batch: 10,
        techniques: vec![AmplificationTechnique::VariableBatch],
        ..Default::default()
    };
    let engine = BatchAmplificationEngine::new(config);
    let payloads = engine.generate_payloads(&user_query_seed());

    assert!(!payloads.is_empty());
    for p in &payloads {
        assert!(p.body.contains("variables"));
        assert!(p.body.contains("query"));
    }
}

#[test]
fn test_analyze_variable_batch_probe() {
    let mut engine = BatchAmplificationEngine::new(BatchConfig::default());
    let probes = vec![ProbeResult {
        technique: AmplificationTechnique::VariableBatch,
        success: true,
        operations_executed: 15,
        response_time_ms: 80,
        error_message: None,
        raw_response: Some("batch ok".into()),
    }];
    let findings = engine.analyze_behavior(&probes);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].technique, AmplificationTechnique::VariableBatch);
    assert_eq!(findings[0].amplification_factor, 15.0);
}

#[test]
fn test_probe_array_batch_is_small() {
    let engine = BatchAmplificationEngine::new(BatchConfig::default());
    let probes = engine.generate_probes(&login_seed());
    let array_probe = probes
        .iter()
        .find(|p| p.technique == AmplificationTechnique::ArrayBatch)
        .unwrap();
    assert_eq!(array_probe.operation_count, 2);
}

#[test]
fn test_probe_alias_is_small() {
    let engine = BatchAmplificationEngine::new(BatchConfig::default());
    let probes = engine.generate_probes(&login_seed());
    let alias_probe = probes
        .iter()
        .find(|p| p.technique == AmplificationTechnique::AliasDuplication)
        .unwrap();
    assert_eq!(alias_probe.operation_count, 5);
}

#[test]
fn test_combined_no_critical_when_small() {
    let mut engine = BatchAmplificationEngine::new(BatchConfig::default());
    let probes = vec![
        ProbeResult {
            technique: AmplificationTechnique::ArrayBatch,
            success: true,
            operations_executed: 5,
            response_time_ms: 50,
            error_message: None,
            raw_response: None,
        },
        ProbeResult {
            technique: AmplificationTechnique::AliasDuplication,
            success: true,
            operations_executed: 10,
            response_time_ms: 50,
            error_message: None,
            raw_response: None,
        },
    ];
    let findings = engine.analyze_behavior(&probes);
    let has_combined_critical = findings
        .iter()
        .any(|f| f.severity == FindingSeverity::Critical && f.description.contains("Combined"));
    assert!(!has_combined_critical);
}

#[test]
fn test_render_arguments_empty() {
    let args: Vec<(String, ArgumentSlot)> = vec![];
    assert_eq!(render_arguments(&args), "");
}

#[test]
fn test_render_arguments_mixed_types() {
    let args = vec![
        ("id".to_string(), ArgumentSlot::Fixed("42".to_string())),
        ("name".to_string(), ArgumentSlot::Fixed("test".to_string())),
        (
            "active".to_string(),
            ArgumentSlot::Fixed("true".to_string()),
        ),
    ];
    let rendered = render_arguments(&args);
    assert!(rendered.contains("id: 42"));
    assert!(rendered.contains(r#"name: "test""#));
    assert!(rendered.contains("active: true"));
}

#[test]
fn test_count_selected_fields_minimum_one() {
    let seed = OperationSeed {
        operation_type: OperationType::Query,
        field_name: "ping".to_string(),
        arguments: vec![],
        selection_set: vec![],
    };
    assert_eq!(count_selected_fields(&seed), 1);
}

#[test]
fn test_probe_batch_sizes() {
    assert_eq!(probe_batch_sizes(1), Vec::<usize>::new());
    assert_eq!(probe_batch_sizes(5), vec![2, 5]);
    assert_eq!(probe_batch_sizes(100), vec![2, 5, 10, 25, 50, 100]);
    assert_eq!(probe_batch_sizes(30), vec![2, 5, 10, 25]);
}
