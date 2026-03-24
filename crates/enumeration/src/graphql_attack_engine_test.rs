use crate::graphql_attack_engine::*;

// ─── Field Suggestion Extraction Tests ───────────────────────────────────────

#[test]
fn extract_suggestions_graphql_js_format() {
    let error = r#"Did you mean "users", "user", or "username"?"#;
    let fields = extract_suggestions_from_error(error);
    assert!(fields.contains(&"users".to_string()));
    assert!(fields.contains(&"user".to_string()));
    assert!(fields.contains(&"username".to_string()));
    assert_eq!(fields.len(), 3);
}

#[test]
fn extract_suggestions_sangria_format() {
    let error = "Field 'usr' is not defined by type 'Query'. Did you mean 'user', 'users'?";
    let fields = extract_suggestions_from_error(error);
    assert!(fields.contains(&"user".to_string()));
    assert!(fields.contains(&"users".to_string()));
}

#[test]
fn extract_suggestions_ruby_format() {
    let error = "Field 'psot' doesn't exist on type 'Query'. Did you mean 'post'?";
    let fields = extract_suggestions_from_error(error);
    assert!(fields.contains(&"post".to_string()));
}

#[test]
fn extract_suggestions_go_format() {
    let error = r#"Cannot query field "baz" on type "Query". Did you mean "bar" or "bat"?"#;
    let fields = extract_suggestions_from_error(error);
    assert!(fields.contains(&"baz".to_string()));
    assert!(fields.contains(&"bar".to_string()));
    assert!(fields.contains(&"bat".to_string()));
}

#[test]
fn extract_suggestions_hasura_format() {
    let error = r#"field "badField" not found in type: 'Query'. Did you mean "goodField"?"#;
    let fields = extract_suggestions_from_error(error);
    assert!(fields.contains(&"goodField".to_string()));
}

#[test]
fn extract_suggestions_empty_string() {
    let fields = extract_suggestions_from_error("");
    assert!(fields.is_empty());
}

#[test]
fn extract_suggestions_no_suggestions_present() {
    let error = "Internal server error";
    let fields = extract_suggestions_from_error(error);
    assert!(fields.is_empty());
}

#[test]
fn extract_suggestions_rejects_invalid_identifiers() {
    let error = r#"Did you mean "valid_field", "123bad", "also-bad"?"#;
    let fields = extract_suggestions_from_error(error);
    assert!(fields.contains(&"valid_field".to_string()));
    assert!(!fields.iter().any(|f| f == "123bad"));
    assert!(!fields.iter().any(|f| f == "also-bad"));
}

// ─── Suggestion Probe Tests ──────────────────────────────────────────────────

#[test]
fn build_suggestion_probes_generates_all_probes() {
    let probes = build_suggestion_probes();
    assert_eq!(probes.len(), SUGGESTION_PROBES.len());
    for probe in &probes {
        assert!(probe.starts_with("{ "));
        assert!(probe.ends_with(" }"));
    }
}

#[test]
fn process_suggestion_responses_aggregates_fields() {
    let responses = vec![
        ("{ usr }", r#"Did you mean "user" or "users"?"#),
        ("{ psot }", r#"Did you mean "post" or "posts"?"#),
        ("{ nothing }", "Syntax error"),
    ];
    let result = process_suggestion_responses(&responses);
    assert_eq!(result.unique_field_count, 4);
    assert_eq!(result.effective_probes.len(), 2);
    assert!(result.discovered_fields.contains_key("{ usr }"));
    assert!(result.discovered_fields.contains_key("{ psot }"));
}

// ─── Depth/Complexity Bypass Tests ───────────────────────────────────────────

#[test]
fn fragment_spread_bypass_generates_chained_fragments() {
    let config = DepthBypassConfig {
        target_depth: 5,
        nesting_field: "friends".to_string(),
        leaf_field: "id".to_string(),
        alias_multiplier: 1,
    };
    let payload = generate_fragment_spread_bypass(&config);
    assert_eq!(payload.effective_depth, 5);
    assert_eq!(payload.technique, DepthBypassTechnique::FragmentSpreading);
    assert!(payload.query.contains("...F0"));
    assert!(payload.query.contains("fragment F0 on Query"));
    assert!(payload.query.contains("fragment F4 on Query { id }"));
    assert!(payload.query.contains("friends"));
}

#[test]
fn inline_fragment_bypass_nests_correctly() {
    let config = DepthBypassConfig {
        target_depth: 3,
        nesting_field: "node".to_string(),
        leaf_field: "__typename".to_string(),
        alias_multiplier: 1,
    };
    let payload = generate_inline_fragment_bypass(&config);
    assert_eq!(payload.effective_depth, 3);
    assert_eq!(payload.technique, DepthBypassTechnique::InlineFragment);
    assert!(payload.query.contains("... on Query"));
    assert!(payload.query.contains("__typename"));
}

#[test]
fn alias_multiplication_multiplies_at_each_level() {
    let config = DepthBypassConfig {
        target_depth: 2,
        nesting_field: "edges".to_string(),
        leaf_field: "id".to_string(),
        alias_multiplier: 3,
    };
    let payload = generate_alias_multiplication(&config);
    assert_eq!(payload.effective_depth, 2);
    assert_eq!(payload.technique, DepthBypassTechnique::AliasMultiplication);
    assert!(payload.query.contains("a0_0:"));
    assert!(payload.query.contains("a0_1:"));
    assert!(payload.query.contains("a0_2:"));
    assert!(payload.query.contains("a1_0:"));
}

#[test]
fn combined_bypass_uses_fragments_and_aliases() {
    let config = DepthBypassConfig {
        target_depth: 3,
        nesting_field: "node".to_string(),
        leaf_field: "id".to_string(),
        alias_multiplier: 2,
    };
    let payload = generate_combined_bypass(&config);
    assert_eq!(payload.technique, DepthBypassTechnique::Combined);
    assert!(payload.query.contains("...C0"));
    assert!(payload.query.contains("leaf_0: id"));
    assert!(payload.query.contains("leaf_1: id"));
}

#[test]
fn generate_all_depth_bypasses_returns_four_techniques() {
    let config = DepthBypassConfig::default();
    let payloads = generate_all_depth_bypasses(&config);
    assert_eq!(payloads.len(), 4);

    let techniques: Vec<DepthBypassTechnique> = payloads.iter().map(|p| p.technique).collect();
    assert!(techniques.contains(&DepthBypassTechnique::FragmentSpreading));
    assert!(techniques.contains(&DepthBypassTechnique::InlineFragment));
    assert!(techniques.contains(&DepthBypassTechnique::AliasMultiplication));
    assert!(techniques.contains(&DepthBypassTechnique::Combined));
}

#[test]
fn depth_bypass_caps_at_max_fragment_depth() {
    let config = DepthBypassConfig {
        target_depth: 10_000,
        nesting_field: "node".to_string(),
        leaf_field: "id".to_string(),
        alias_multiplier: 1,
    };
    let payload = generate_fragment_spread_bypass(&config);
    assert_eq!(payload.effective_depth, 64);
}

#[test]
fn zero_depth_produces_leaf_only_query() {
    let config = DepthBypassConfig {
        target_depth: 0,
        nesting_field: "node".to_string(),
        leaf_field: "id".to_string(),
        alias_multiplier: 1,
    };
    let payload = generate_fragment_spread_bypass(&config);
    assert_eq!(payload.effective_depth, 0);
    assert!(payload.query.contains("id"));
}

// ─── Batch Query Smuggling Tests ─────────────────────────────────────────────

#[test]
fn build_batch_query_combines_operations() {
    let ops = vec![
        BatchOperation {
            name: "users".to_string(),
            body: "users { id }".to_string(),
        },
        BatchOperation {
            name: "posts".to_string(),
            body: "posts { title }".to_string(),
        },
    ];
    let batch = build_batch_query(&ops);
    assert_eq!(batch.operation_count, 2);
    assert!(!batch.deduplicated);
    assert!(batch.query.contains("op0_users:"));
    assert!(batch.query.contains("op1_posts:"));
}

#[test]
fn build_batch_query_deduplicates_identical_bodies() {
    let ops = vec![
        BatchOperation {
            name: "a".to_string(),
            body: "users { id }".to_string(),
        },
        BatchOperation {
            name: "b".to_string(),
            body: "users { id }".to_string(),
        },
    ];
    let batch = build_batch_query(&ops);
    assert_eq!(batch.operation_count, 1);
    assert!(batch.deduplicated);
}

#[test]
fn build_enumeration_batch_creates_aliased_queries() {
    let values = vec!["1", "2", "3"];
    let batch = build_enumeration_batch("user", "id", &values);
    assert_eq!(batch.operation_count, 3);
    assert!(batch.query.contains("q0: user(id: \"1\")"));
    assert!(batch.query.contains("q1: user(id: \"2\")"));
    assert!(batch.query.contains("q2: user(id: \"3\")"));
}

#[test]
fn build_batch_query_empty_operations() {
    let batch = build_batch_query(&[]);
    assert_eq!(batch.operation_count, 0);
    assert_eq!(batch.query, "{  }");
}

// ─── Type Confusion Tests ────────────────────────────────────────────────────

#[test]
fn type_confusion_generates_cross_type_access() {
    let types = vec![
        GraphQlType {
            name: "Admin".to_string(),
            fields: vec!["secretKey".to_string(), "role".to_string()],
            kind: TypeKind::Object,
        },
        GraphQlType {
            name: "User".to_string(),
            fields: vec!["name".to_string(), "email".to_string()],
            kind: TypeKind::Object,
        },
    ];
    let payloads = generate_type_confusion_payloads("account", &types);
    assert!(!payloads.is_empty());

    let admin_payload = payloads
        .iter()
        .find(|p| p.confused_types[0] == "Admin")
        .unwrap();
    assert!(admin_payload.query.contains("... on Admin"));
    assert!(admin_payload.query.contains("... on User"));
    assert!(admin_payload.accessed_fields.contains(&"name".to_string()));
}

#[test]
fn type_confusion_empty_member_types() {
    let payloads = generate_type_confusion_payloads("node", &[]);
    assert!(payloads.is_empty());
}

#[test]
fn type_confusion_single_type_no_foreign_fields() {
    let types = vec![GraphQlType {
        name: "Solo".to_string(),
        fields: vec!["only".to_string()],
        kind: TypeKind::Object,
    }];
    let payloads = generate_type_confusion_payloads("node", &types);
    assert!(payloads.is_empty());
}

// ─── Subscription Abuse Tests ────────────────────────────────────────────────

#[test]
fn subscription_probes_include_basic_and_exfil() {
    let probes = generate_subscription_probes(&[]);
    assert_eq!(probes.len(), COMMON_SUBSCRIPTION_FIELDS.len() * 2);

    let basic_count = probes.iter().filter(|p| !p.exfiltration_fields).count();
    let exfil_count = probes.iter().filter(|p| p.exfiltration_fields).count();
    assert_eq!(basic_count, exfil_count);
}

#[test]
fn subscription_probes_include_additional_fields() {
    let probes = generate_subscription_probes(&["customEvent"]);
    let custom = probes
        .iter()
        .filter(|p| p.field_name == "customEvent")
        .count();
    assert_eq!(custom, 2);
}

#[test]
fn subscription_probe_exfil_requests_sensitive_fields() {
    let probes = generate_subscription_probes(&[]);
    let exfil_probe = probes.iter().find(|p| p.exfiltration_fields).unwrap();
    assert!(exfil_probe.query.contains("email"));
    assert!(exfil_probe.query.contains("token"));
    assert!(exfil_probe.query.contains("sessionId"));
}

// ─── Directive Injection Tests ───────────────────────────────────────────────

#[test]
fn directive_injection_generates_five_techniques() {
    let payloads = generate_directive_injection_payloads("user", &["secretField", "adminFlag"]);
    assert_eq!(payloads.len(), 5);

    let techniques: Vec<DirectiveInjectionTechnique> =
        payloads.iter().map(|p| p.technique).collect();
    assert!(techniques.contains(&DirectiveInjectionTechnique::SkipChain));
    assert!(techniques.contains(&DirectiveInjectionTechnique::IncludeChain));
    assert!(techniques.contains(&DirectiveInjectionTechnique::SkipIncludeCombination));
    assert!(techniques.contains(&DirectiveInjectionTechnique::DeprecatedAccess));
    assert!(techniques.contains(&DirectiveInjectionTechnique::FragmentDirective));
}

#[test]
fn directive_skip_chain_contains_skip_false() {
    let payloads = generate_directive_injection_payloads("user", &["secret"]);
    let skip_payload = payloads
        .iter()
        .find(|p| p.technique == DirectiveInjectionTechnique::SkipChain)
        .unwrap();
    assert!(skip_payload.query.contains("@skip(if: false)"));
    assert!(skip_payload.query.contains("secret"));
}

#[test]
fn directive_fragment_uses_inline_spread() {
    let payloads = generate_directive_injection_payloads("user", &["token"]);
    let frag_payload = payloads
        .iter()
        .find(|p| p.technique == DirectiveInjectionTechnique::FragmentDirective)
        .unwrap();
    assert!(frag_payload.query.contains("... @skip(if: false)"));
    assert!(frag_payload.query.contains("token"));
}

#[test]
fn directive_injection_empty_fields_returns_empty() {
    let payloads = generate_directive_injection_payloads("user", &[]);
    assert!(payloads.is_empty());
}

// ─── Aggregate Engine Tests ──────────────────────────────────────────────────

#[test]
fn run_attack_engine_with_all_modules() {
    let config = AttackEngineConfig::default();
    let error_responses = vec![("{ usr }", r#"Did you mean "user" or "users"?"#)];
    let member_types = vec![
        GraphQlType {
            name: "Admin".to_string(),
            fields: vec!["secret".to_string()],
            kind: TypeKind::Object,
        },
        GraphQlType {
            name: "User".to_string(),
            fields: vec!["name".to_string()],
            kind: TypeKind::Object,
        },
    ];
    let target_fields = &["users", "posts"];
    let result = run_attack_engine(&config, &error_responses, &member_types, target_fields);

    assert!(result.suggestion_results.is_some());
    assert_eq!(result.depth_bypass_payloads.len(), 4);
    assert!(!result.batch_queries.is_empty());
    assert!(!result.type_confusion_payloads.is_empty());
    assert!(!result.subscription_probes.is_empty());
    assert!(!result.directive_payloads.is_empty());
}

#[test]
fn run_attack_engine_all_disabled() {
    let config = AttackEngineConfig {
        enable_suggestions: false,
        enable_depth_bypass: false,
        enable_batch_smuggling: false,
        enable_type_confusion: false,
        enable_subscription_abuse: false,
        enable_directive_injection: false,
        depth_config: DepthBypassConfig::default(),
    };
    let result = run_attack_engine(&config, &[], &[], &[]);
    assert!(result.suggestion_results.is_none());
    assert!(result.depth_bypass_payloads.is_empty());
    assert!(result.batch_queries.is_empty());
    assert!(result.type_confusion_payloads.is_empty());
    assert!(result.subscription_probes.is_empty());
    assert!(result.directive_payloads.is_empty());
}
