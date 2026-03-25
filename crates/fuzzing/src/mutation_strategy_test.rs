use crate::mutation_strategy::{
    JsonValueType, MutationStrategyEngine, SmartMutationKind, VulnDictionary,
};

#[test]
fn structure_aware_mutates_json_object() {
    let engine = MutationStrategyEngine::new();
    let results = engine.mutate_structure_aware("{\"name\": \"alice\", \"age\": 30}");
    assert!(!results.is_empty());
    for r in &results {
        assert_eq!(r.kind, SmartMutationKind::StructureAware);
        assert!(!r.value.is_empty());
    }
}

#[test]
fn structure_aware_handles_invalid_json() {
    let engine = MutationStrategyEngine::new();
    let results = engine.mutate_structure_aware("not json at all");
    assert!(results.is_empty());
}

#[test]
fn structure_aware_mutates_json_array() {
    let engine = MutationStrategyEngine::new();
    let results = engine.mutate_structure_aware("[1, 2, 3]");
    assert!(!results.is_empty());
    let has_empty_array = results.iter().any(|r| r.value == "[]");
    assert!(has_empty_array);
}

#[test]
fn type_aware_detects_integer() {
    let engine = MutationStrategyEngine::new();
    let results = engine.mutate_type_aware("42");
    assert!(!results.is_empty());
    for r in &results {
        assert_eq!(r.kind, SmartMutationKind::TypeAware);
    }
    let values: Vec<&str> = results.iter().map(|r| r.value.as_str()).collect();
    assert!(values.contains(&"0"));
    assert!(values.contains(&"-1"));
}

#[test]
fn type_aware_detects_string() {
    let engine = MutationStrategyEngine::new();
    let results = engine.mutate_type_aware("hello");
    assert!(!results.is_empty());
    let has_sqli = results.iter().any(|r| r.value.contains("OR '1'='1"));
    assert!(has_sqli);
}

#[test]
fn type_aware_detects_boolean() {
    let engine = MutationStrategyEngine::new();
    let results = engine.mutate_type_aware("true");
    assert!(!results.is_empty());
    let values: Vec<&str> = results.iter().map(|r| r.value.as_str()).collect();
    assert!(values.contains(&"false"));
    assert!(values.contains(&"0"));
}

#[test]
fn type_aware_detects_null() {
    let engine = MutationStrategyEngine::new();
    let results = engine.mutate_type_aware("null");
    assert!(!results.is_empty());
    let values: Vec<&str> = results.iter().map(|r| r.value.as_str()).collect();
    assert!(values.contains(&"undefined"));
}

#[test]
fn type_aware_detects_float() {
    let engine = MutationStrategyEngine::new();
    let results = engine.mutate_type_aware("3.14");
    assert!(!results.is_empty());
    let values: Vec<&str> = results.iter().map(|r| r.value.as_str()).collect();
    assert!(values.contains(&"NaN"));
    assert!(values.contains(&"Infinity"));
}

#[test]
fn boundary_payloads_cover_key_values() {
    let engine = MutationStrategyEngine::new();
    let payloads = engine.generate_boundary_payloads();
    assert!(payloads.len() > 20);
    let values: Vec<&str> = payloads.iter().map(|p| p.value.as_str()).collect();
    assert!(values.contains(&""));
    assert!(values.contains(&"0"));
    assert!(values.contains(&"-1"));
    assert!(values.contains(&"NaN"));
    assert!(values.contains(&"null"));
    assert!(values.contains(&"[]"));
    assert!(values.contains(&"{}"));
    for p in &payloads {
        assert_eq!(p.kind, SmartMutationKind::BoundaryFocused);
    }
}

#[test]
fn format_preserving_email() {
    let engine = MutationStrategyEngine::new();
    let results = engine.mutate_format_preserving("user@example.com");
    assert!(!results.is_empty());
    for r in &results {
        assert_eq!(r.kind, SmartMutationKind::FormatPreserving);
    }
    let has_localhost = results.iter().any(|r| r.value.contains("localhost"));
    assert!(has_localhost);
}

#[test]
fn format_preserving_url() {
    let engine = MutationStrategyEngine::new();
    let results = engine.mutate_format_preserving("https://example.com/api");
    assert!(!results.is_empty());
    let has_traversal = results.iter().any(|r| r.value.contains("../"));
    assert!(has_traversal);
}

#[test]
fn format_preserving_uuid() {
    let engine = MutationStrategyEngine::new();
    let results = engine.mutate_format_preserving("550e8400-e29b-41d4-a716-446655440000");
    assert!(!results.is_empty());
    let has_zero_uuid = results
        .iter()
        .any(|r| r.value.contains("00000000-0000-0000-0000-000000000000"));
    assert!(has_zero_uuid);
}

#[test]
fn format_preserving_ip() {
    let engine = MutationStrategyEngine::new();
    let results = engine.mutate_format_preserving("192.168.1.1");
    assert!(!results.is_empty());
    let has_loopback = results.iter().any(|r| r.value.contains("127.0.0.1"));
    assert!(has_loopback);
}

#[test]
fn format_preserving_date() {
    let engine = MutationStrategyEngine::new();
    let results = engine.mutate_format_preserving("2024-01-15");
    assert!(!results.is_empty());
    let has_zero_date = results.iter().any(|r| r.value.contains("0000-00-00"));
    assert!(has_zero_date);
}

#[test]
fn format_preserving_unknown_format_gets_null_byte() {
    let engine = MutationStrategyEngine::new();
    let results = engine.mutate_format_preserving("random_string_42");
    assert!(!results.is_empty());
    let has_null = results.iter().any(|r| r.value.contains('\x00'));
    assert!(has_null);
}

#[test]
fn dictionary_sqli_injection() {
    let engine = MutationStrategyEngine::new();
    let results = engine.inject_from_dictionary("sqli");
    assert!(!results.is_empty());
    for r in &results {
        assert_eq!(r.kind, SmartMutationKind::DictionaryBased);
    }
    let has_or_payload = results.iter().any(|r| r.value.contains("OR"));
    assert!(has_or_payload);
}

#[test]
fn dictionary_xss_injection() {
    let engine = MutationStrategyEngine::new();
    let results = engine.inject_from_dictionary("xss");
    assert!(!results.is_empty());
    let has_script = results.iter().any(|r| r.value.contains("<script>"));
    assert!(has_script);
}

#[test]
fn dictionary_unknown_category_returns_empty() {
    let engine = MutationStrategyEngine::new();
    let results = engine.inject_from_dictionary("nonexistent_category");
    assert!(results.is_empty());
}

#[test]
fn dictionary_custom_category() {
    let dict = VulnDictionary::new().with_category("custom", vec!["payload1".to_string()]);
    let engine = MutationStrategyEngine::new().with_dictionary(dict);
    let results = engine.inject_from_dictionary("custom");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].value, "payload1");
}

#[test]
fn genetic_breed_requires_two_parents() {
    let mut engine = MutationStrategyEngine::new();
    engine.record_fitness("single_parent", 1.0);
    let offspring = engine.breed_generation(5);
    assert!(offspring.is_empty());
}

#[test]
fn genetic_breed_produces_offspring() {
    let mut engine = MutationStrategyEngine::new();
    engine.record_fitness("payload_alpha", 5.0);
    engine.record_fitness("payload_beta", 3.0);
    engine.record_fitness("payload_gamma", 8.0);

    let offspring = engine.breed_generation(10);
    assert_eq!(offspring.len(), 10);
    for child in &offspring {
        assert_eq!(child.kind, SmartMutationKind::GeneticCrossover);
        assert!(!child.value.is_empty());
        assert_eq!(child.parent_indices.len(), 2);
    }
}

#[test]
fn genetic_generation_increments() {
    let mut engine = MutationStrategyEngine::new();
    assert_eq!(engine.current_generation(), 0);
    engine.record_fitness("a", 1.0);
    engine.record_fitness("b", 1.0);
    engine.breed_generation(1);
    assert_eq!(engine.current_generation(), 1);
    engine.breed_generation(1);
    assert_eq!(engine.current_generation(), 2);
}

#[test]
fn genetic_pool_size_capped() {
    let mut engine = MutationStrategyEngine::new().with_max_pool_size(10);
    for i in 0..20 {
        engine.record_fitness(&format!("payload_{}", i), i as f64);
    }
    assert!(engine.genetic_pool_size() <= 15);
}

#[test]
fn crossover_rate_clamped() {
    let engine = MutationStrategyEngine::new().with_crossover_rate(1.5);
    engine.dictionary();
}

#[test]
fn default_trait_works() {
    let engine = MutationStrategyEngine::default();
    assert_eq!(engine.current_generation(), 0);
    assert_eq!(engine.genetic_pool_size(), 0);
}

#[test]
fn dictionary_default_has_all_categories() {
    let dict = VulnDictionary::new();
    let categories = dict.categories();
    assert!(categories.contains(&"sqli"));
    assert!(categories.contains(&"xss"));
    assert!(categories.contains(&"cmdi"));
    assert!(categories.contains(&"traversal"));
    assert!(categories.contains(&"ssti"));
}

#[test]
fn structure_aware_injects_sqli_into_string_field() {
    let engine = MutationStrategyEngine::new();
    let results = engine.mutate_structure_aware("{\"username\": \"admin\"}");
    let has_sqli = results.iter().any(|r| r.value.contains("OR '1'='1"));
    assert!(has_sqli);
}

#[test]
fn structure_aware_removes_key() {
    let engine = MutationStrategyEngine::new();
    let results = engine.mutate_structure_aware("{\"a\": 1, \"b\": 2}");
    let has_removed = results
        .iter()
        .any(|r| !r.value.contains("\"a\"") || !r.value.contains("\"b\""));
    assert!(has_removed);
}

#[test]
fn structure_aware_type_changes_string_to_int() {
    let engine = MutationStrategyEngine::new();
    let results = engine.mutate_structure_aware("{\"role\": \"admin\"}");
    let has_int = results.iter().any(|r| r.value.contains(":42"));
    assert!(has_int);
}
