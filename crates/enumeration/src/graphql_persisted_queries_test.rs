use crate::graphql_persisted_queries::*;

// ─── APQ Hash Computation ───────────────────────────────────────────────────

#[test]
fn compute_apq_hash_deterministic() {
    let query = "{ __typename }";
    let h1 = compute_apq_hash(query);
    let h2 = compute_apq_hash(query);
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 64);
}

#[test]
fn compute_apq_hash_different_for_different_queries() {
    let h1 = compute_apq_hash("{ users { id } }");
    let h2 = compute_apq_hash("{ posts { id } }");
    assert_ne!(h1, h2);
}

#[test]
fn compute_apq_hash_whitespace_sensitive() {
    let h1 = compute_apq_hash("{ users { id } }");
    let h2 = compute_apq_hash("{users{id}}");
    assert_ne!(h1, h2);
}

#[test]
fn compute_apq_hash_lowercase_hex() {
    let hash = compute_apq_hash("test");
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(!hash.contains(|c: char| c.is_ascii_uppercase()));
}

// ─── APQ Probe Payload ──────────────────────────────────────────────────────

#[test]
fn build_apq_probe_contains_hash_no_query() {
    let payload = build_apq_probe_payload("{ me { id } }");
    assert!(payload.contains("sha256Hash"));
    assert!(payload.contains("persistedQuery"));
    assert!(!payload.contains("\"query\""));
    assert!(payload.contains("\"version\":1"));
}

#[test]
fn build_apq_register_contains_query_and_hash() {
    let payload = build_apq_register_payload("{ me { id } }");
    assert!(payload.contains("\"query\""));
    assert!(payload.contains("sha256Hash"));
    assert!(payload.contains("persistedQuery"));
}

#[test]
fn build_apq_register_escapes_quotes() {
    let query = r#"{ __type(name: "User") { name } }"#;
    let payload = build_apq_register_payload(query);
    assert!(payload.contains(r#"__type(name: \"User\")"#));
}

// ─── APQ Response Analysis ──────────────────────────────────────────────────

#[test]
fn analyze_apollo_persisted_query_not_found() {
    let response = r#"{"errors":[{"message":"PersistedQueryNotFound","extensions":{"code":"PERSISTED_QUERY_NOT_FOUND"}}]}"#;
    let result = analyze_apq_response(response);
    assert!(result.apq_recognized);
    assert!(result.persisted_query_not_found);
    assert!(!result.hash_hit);
    assert_eq!(
        result.error_code.as_deref(),
        Some("PERSISTED_QUERY_NOT_FOUND")
    );
    assert_eq!(result.server_hint, Some(ApqServerHint::ApolloServer));
}

#[test]
fn analyze_relay_persisted_query_not_found() {
    let response = r#"{"errors":[{"message":"PersistedQueryNotFound"}]}"#;
    let result = analyze_apq_response(response);
    assert!(result.apq_recognized);
    assert!(result.persisted_query_not_found);
    assert_eq!(result.server_hint, Some(ApqServerHint::RelayCompat));
}

#[test]
fn analyze_successful_data_response() {
    let response = r#"{"data":{"users":[{"id":"1"}]}}"#;
    let result = analyze_apq_response(response);
    assert!(result.hash_hit);
    assert!(!result.persisted_query_not_found);
}

#[test]
fn analyze_unrelated_error() {
    let response = r#"{"errors":[{"message":"Syntax Error"}]}"#;
    let result = analyze_apq_response(response);
    assert!(!result.apq_recognized);
    assert!(!result.persisted_query_not_found);
    assert!(!result.hash_hit);
    assert!(result.server_hint.is_none());
}

#[test]
fn analyze_data_null_not_treated_as_hit() {
    let response = r#"{"data":null,"errors":[{"message":"PERSISTED_QUERY_NOT_FOUND"}]}"#;
    let result = analyze_apq_response(response);
    assert!(result.persisted_query_not_found);
    assert!(!result.hash_hit);
}

// ─── Hash Enumeration ───────────────────────────────────────────────────────

#[test]
fn generate_hash_probes_covers_all_patterns() {
    let probes = generate_hash_probes();
    assert_eq!(probes.len(), COMMON_QUERY_PATTERNS.len());
    for probe in &probes {
        assert_eq!(probe.hash.len(), 64);
        assert!(probe.payload.contains(&probe.hash));
        assert!(!probe.query_pattern.is_empty());
    }
}

#[test]
fn generate_custom_hash_probes_from_user_queries() {
    let queries = vec!["{ custom { id } }", "mutation { doThing { ok } }"];
    let probes = generate_custom_hash_probes(&queries);
    assert_eq!(probes.len(), 2);
    assert_eq!(probes[0].query_pattern, "{ custom { id } }");
    assert_eq!(probes[1].query_pattern, "mutation { doThing { ok } }");
    assert_ne!(probes[0].hash, probes[1].hash);
}

#[test]
fn process_hash_enumeration_identifies_hits_and_misses() {
    let probes = generate_hash_probes();
    let hit_response = r#"{"data":{"users":[{"id":"1"}]}}"#;
    let miss_response = r#"{"errors":[{"message":"PersistedQueryNotFound","extensions":{"code":"PERSISTED_QUERY_NOT_FOUND"}}]}"#;
    let error_response = r#"{"errors":[{"message":"Internal error"}]}"#;

    let probe_responses: Vec<(&HashProbe, &str)> = vec![
        (&probes[0], hit_response),
        (&probes[1], miss_response),
        (&probes[2], error_response),
    ];

    let result = process_hash_enumeration(&probe_responses);
    assert_eq!(result.total_probed, 3);
    assert_eq!(result.hits.len(), 1);
    assert_eq!(result.misses, 1);
    assert_eq!(result.discovered_queries.len(), 1);
}

// ─── Bypass Payloads ────────────────────────────────────────────────────────

#[test]
fn generate_bypass_payloads_without_known_hash() {
    let payloads = generate_bypass_payloads(None, "{ __schema { types { name } } }");
    assert!(payloads.len() >= 6);

    let techniques: Vec<BypassTechnique> = payloads.iter().map(|p| p.technique).collect();
    assert!(techniques.contains(&BypassTechnique::QueryBodyOverride));
    assert!(techniques.contains(&BypassTechnique::ApqAutoRegister));
    assert!(techniques.contains(&BypassTechnique::FieldAliasReshape));
    assert!(techniques.contains(&BypassTechnique::FragmentInjection));
    assert!(techniques.contains(&BypassTechnique::HashCollisionWhitespace));
    assert!(techniques.contains(&BypassTechnique::IntrospectionPiggyback));
    assert!(!techniques.contains(&BypassTechnique::BatchSmuggling));
}

#[test]
fn generate_bypass_payloads_with_known_hash_includes_batch() {
    let payloads = generate_bypass_payloads(Some("abc123"), "{ me { id } }");
    let techniques: Vec<BypassTechnique> = payloads.iter().map(|p| p.technique).collect();
    assert!(techniques.contains(&BypassTechnique::BatchSmuggling));
    assert_eq!(payloads.len(), 7);
}

#[test]
fn bypass_query_body_override_contains_both_query_and_hash() {
    let payloads = generate_bypass_payloads(None, "{ test }");
    let override_payload = payloads
        .iter()
        .find(|p| p.technique == BypassTechnique::QueryBodyOverride)
        .unwrap();
    assert!(override_payload.payload.contains("\"query\""));
    assert!(override_payload.payload.contains("sha256Hash"));
}

#[test]
fn bypass_hash_collision_whitespace_changes_hash() {
    let original = "{ me { id } }";
    let original_hash = compute_apq_hash(original);
    let payloads = generate_bypass_payloads(None, original);
    let whitespace_payload = payloads
        .iter()
        .find(|p| p.technique == BypassTechnique::HashCollisionWhitespace)
        .unwrap();
    assert!(!whitespace_payload.payload.contains(&original_hash));
}

// ─── Allowlist Bypass ───────────────────────────────────────────────────────

#[test]
fn generate_allowlist_bypasses_produces_five_techniques() {
    let payloads = generate_allowlist_bypasses("{ user { id } }", "User", &["email", "ssn"]);
    assert_eq!(payloads.len(), 5);

    let techniques: Vec<AllowlistBypassTechnique> = payloads.iter().map(|p| p.technique).collect();
    assert!(techniques.contains(&AllowlistBypassTechnique::AliasEnumeration));
    assert!(techniques.contains(&AllowlistBypassTechnique::InlineFragmentWidening));
    assert!(techniques.contains(&AllowlistBypassTechnique::NamedFragmentSpread));
    assert!(techniques.contains(&AllowlistBypassTechnique::TypenameProbe));
    assert!(techniques.contains(&AllowlistBypassTechnique::MultiOperationMerge));
}

#[test]
fn allowlist_alias_enumeration_contains_aliases() {
    let payloads = generate_allowlist_bypasses("{ user { id } }", "User", &["email", "secret"]);
    let alias_payload = payloads
        .iter()
        .find(|p| p.technique == AllowlistBypassTechnique::AliasEnumeration)
        .unwrap();
    assert!(alias_payload.query.contains("a0: email"));
    assert!(alias_payload.query.contains("a1: secret"));
}

#[test]
fn allowlist_fragment_spread_creates_named_fragment() {
    let payloads = generate_allowlist_bypasses("{ user { id } }", "User", &["token"]);
    let frag_payload = payloads
        .iter()
        .find(|p| p.technique == AllowlistBypassTechnique::NamedFragmentSpread)
        .unwrap();
    assert!(
        frag_payload
            .query
            .contains("fragment RestrictedFields on User")
    );
    assert!(frag_payload.query.contains("token"));
}

#[test]
fn allowlist_bypass_empty_fields_returns_empty() {
    let payloads = generate_allowlist_bypasses("{ user { id } }", "User", &[]);
    assert!(payloads.is_empty());
}

// ─── Batch APQ ──────────────────────────────────────────────────────────────

#[test]
fn build_batch_apq_request_packs_hashes() {
    let probes = generate_hash_probes();
    let first_five: Vec<HashProbe> = probes.into_iter().take(5).collect();
    let batch = build_batch_apq_request(&first_five);
    assert_eq!(batch.hash_count, 5);
    assert_eq!(batch.hashes.len(), 5);
    assert!(batch.payload.starts_with('['));
    assert!(batch.payload.ends_with(']'));
    for hash in &batch.hashes {
        assert!(batch.payload.contains(hash.as_str()));
    }
}

#[test]
fn build_batch_apq_request_caps_at_max() {
    let queries: Vec<String> = (0..200).map(|i| format!("{{ field{i} }}")).collect();
    let query_refs: Vec<&str> = queries.iter().map(|s| s.as_str()).collect();
    let probes = generate_custom_hash_probes(&query_refs);
    let batch = build_batch_apq_request(&probes);
    assert_eq!(batch.hash_count, MAX_BATCH_HASHES);
}

#[test]
fn parse_batch_apq_response_identifies_hit_indices() {
    let response = r#"[{"data":{"users":[]}},{"errors":[{"message":"PERSISTED_QUERY_NOT_FOUND"}]},{"data":{"posts":[]}}]"#;
    let hits = parse_batch_apq_response(response, 3);
    assert_eq!(hits, vec![0, 2]);
}

#[test]
fn parse_batch_apq_response_non_array_returns_empty() {
    let hits = parse_batch_apq_response(r#"{"error":"bad request"}"#, 1);
    assert!(hits.is_empty());
}

#[test]
fn parse_batch_apq_response_all_misses() {
    let response = r#"[{"errors":[{"extensions":{"code":"PERSISTED_QUERY_NOT_FOUND"}}]},{"errors":[{"extensions":{"code":"PERSISTED_QUERY_NOT_FOUND"}}]}]"#;
    let hits = parse_batch_apq_response(response, 2);
    assert!(hits.is_empty());
}

// ─── SSRF Probes ────────────────────────────────────────────────────────────

#[test]
fn generate_ssrf_probes_includes_internal_and_callback() {
    let probes = generate_apq_ssrf_probes("https://evil.com");
    assert!(probes.len() >= 9);
    let has_callback = probes.iter().any(|p| p.target_url.contains("evil.com"));
    let has_internal = probes.iter().any(|p| p.target_url.contains("127.0.0.1"));
    let has_metadata = probes
        .iter()
        .any(|p| p.target_url.contains("169.254.169.254"));
    assert!(has_callback);
    assert!(has_internal);
    assert!(has_metadata);
}

#[test]
fn ssrf_probes_payloads_are_valid_json_ish() {
    let probes = generate_apq_ssrf_probes("https://test.com");
    for probe in &probes {
        assert!(probe.payload.starts_with('{'));
        assert!(probe.payload.ends_with('}'));
        assert!(probe.payload.contains("persistedQuery"));
    }
}

// ─── Cache Poisoning ────────────────────────────────────────────────────────

#[test]
fn generate_cache_poison_payloads_produces_register_and_verify() {
    let payloads = generate_cache_poison_payloads("User");
    assert_eq!(payloads.len(), 3);
    for p in &payloads {
        assert_eq!(p.hash.len(), 64);
        assert!(p.register_payload.contains("\"query\""));
        assert!(p.register_payload.contains(&p.hash));
        assert!(!p.verify_payload.contains("\"query\""));
        assert!(!p.malicious_query.is_empty());
        assert!(!p.description.is_empty());
    }
}

#[test]
fn cache_poison_hash_matches_malicious_query() {
    let payloads = generate_cache_poison_payloads("Account");
    for p in &payloads {
        let computed = compute_apq_hash(&p.malicious_query);
        assert_eq!(computed, p.hash);
    }
}

// ─── Aggregate Engine ───────────────────────────────────────────────────────

#[test]
fn run_engine_default_config_generates_all_categories() {
    let config = PersistedQueryConfig::default();
    let response = r#"{"errors":[{"extensions":{"code":"PERSISTED_QUERY_NOT_FOUND"}}]}"#;
    let result = run_persisted_query_engine(&config, Some(response));

    assert!(result.apq_probe.is_some());
    let probe = result.apq_probe.unwrap();
    assert!(probe.persisted_query_not_found);

    assert!(!result.hash_probes.is_empty());
    assert!(!result.bypass_payloads.is_empty());
    assert!(!result.allowlist_bypasses.is_empty());
    assert!(!result.batch_requests.is_empty());
    assert!(!result.ssrf_probes.is_empty());
    assert!(!result.cache_poison_payloads.is_empty());
}

#[test]
fn run_engine_all_disabled_returns_empty() {
    let config = PersistedQueryConfig {
        enable_apq_probe: true,
        enable_hash_enumeration: false,
        enable_bypass: false,
        enable_allowlist_bypass: false,
        enable_batch_apq: false,
        enable_ssrf: false,
        enable_cache_poison: false,
        known_valid_hash: None,
        injection_query: String::new(),
        allowed_query: None,
        target_type: "User".to_string(),
        restricted_fields: Vec::new(),
        callback_url: None,
    };
    let result = run_persisted_query_engine(&config, None);
    assert!(result.apq_probe.is_none());
    assert!(result.hash_probes.is_empty());
    assert!(result.bypass_payloads.is_empty());
    assert!(result.allowlist_bypasses.is_empty());
    assert!(result.batch_requests.is_empty());
    assert!(result.ssrf_probes.is_empty());
    assert!(result.cache_poison_payloads.is_empty());
}

#[test]
fn run_engine_no_apq_response_probe_is_none() {
    let config = PersistedQueryConfig::default();
    let result = run_persisted_query_engine(&config, None);
    assert!(result.apq_probe.is_none());
}
