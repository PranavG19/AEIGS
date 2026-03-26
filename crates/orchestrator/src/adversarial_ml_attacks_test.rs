use super::adversarial_ml_attacks::*;

fn make_target() -> MlModelTarget {
    MlModelTarget {
        model_name: "waf-classifier-v2".into(),
        model_type: ModelType::Classifier,
        endpoint_url: "http://127.0.0.1:8080/predict".into(),
        input_format: "text/plain".into(),
        output_format: "application/json".into(),
        confidence_threshold: 0.7,
    }
}

fn make_config(attack_type: MlAttackType) -> AttackConfig {
    AttackConfig {
        attack_type,
        target: make_target(),
        max_iterations: 10,
        perturbation_budget: 0.3,
        success_threshold: 0.5,
        timeout_secs: 30,
    }
}

#[test]
fn test_engine_creation() {
    let engine = MlAttackEngine::new();
    assert!(engine.attack_log.is_empty());
    assert!(engine.payloads.is_empty());
    assert!(engine.evasion_techniques.is_empty());
    assert_eq!(engine.attack_count(), 0);
}

#[test]
fn test_generate_adversarial_examples() {
    let mut engine = MlAttackEngine::new();
    let config = make_config(MlAttackType::AdversarialExample);
    let inputs = vec![
        "<script>alert(1)</script>".into(),
        "SELECT * FROM users".into(),
    ];

    let payloads = engine
        .generate_adversarial_examples(&config, &inputs)
        .unwrap();

    assert_eq!(payloads.len(), 8);

    let types: Vec<&str> = payloads
        .iter()
        .map(|p| p.perturbation_type.as_str())
        .collect();
    assert!(types.contains(&"unicode_homoglyph"));
    assert!(types.contains(&"whitespace_injection"));
    assert!(types.contains(&"case_alternation"));
    assert!(types.contains(&"null_byte_padding"));

    for payload in &payloads {
        assert_ne!(payload.original_input, payload.perturbed_input);
        assert!(payload.magnitude > 0.0);
    }

    assert_eq!(engine.payloads.len(), 8);
}

#[test]
fn test_generate_adversarial_examples_homoglyph_content() {
    let mut engine = MlAttackEngine::new();
    let config = make_config(MlAttackType::AdversarialExample);
    let inputs = vec!["accept".into()];

    let payloads = engine
        .generate_adversarial_examples(&config, &inputs)
        .unwrap();

    let homoglyph = payloads
        .iter()
        .find(|p| p.perturbation_type == "unicode_homoglyph")
        .unwrap();

    assert_ne!(homoglyph.perturbed_input, "accept");
    assert_ne!(
        homoglyph.perturbed_input.as_bytes(),
        b"accept",
        "homoglyph substitution should produce different bytes"
    );
}

#[test]
fn test_model_inversion_simulation() {
    let mut engine = MlAttackEngine::new();
    let config = make_config(MlAttackType::ModelInversion);

    let result = engine.simulate_model_inversion(&config).unwrap();

    assert!(!result.recovered_features.is_empty());
    assert_eq!(result.feature_count, result.recovered_features.len());
    assert!(result.confidence > 0.0);
    assert!(result.confidence <= 1.0);

    assert_eq!(engine.attack_count(), 1);
    assert_eq!(
        engine.attack_log[0].attack_type,
        MlAttackType::ModelInversion
    );
}

#[test]
fn test_membership_inference() {
    let mut engine = MlAttackEngine::new();
    let config = make_config(MlAttackType::MembershipInference);
    let samples = vec!["sample_a".into(), "sample_b".into(), "sample_c".into()];

    let result = engine
        .simulate_membership_inference(&config, &samples)
        .unwrap();

    assert!(result.confidence > 0.0);
    assert!(result.shadow_model_accuracy > 0.0);
    assert_eq!(result.threshold_used, 0.5);

    assert_eq!(engine.attack_count(), 1);
    assert_eq!(
        engine.attack_log[0].attack_type,
        MlAttackType::MembershipInference
    );
}

#[test]
fn test_model_extraction() {
    let mut engine = MlAttackEngine::new();
    let config = make_config(MlAttackType::ModelExtraction);
    let query_count = 50;

    let result = engine
        .simulate_model_extraction(&config, query_count)
        .unwrap();

    assert!(result.extracted_params_count > 0);
    assert!(result.fidelity_score > 0.0);
    assert_eq!(result.queries_used, query_count);
    assert_eq!(result.model_type_guess, "Classifier");

    assert_eq!(engine.attack_count(), 1);
}

#[test]
fn test_data_poisoning() {
    let engine = MlAttackEngine::new();
    let samples = vec![
        "normal request".into(),
        "another request".into(),
        "third request".into(),
        "fourth request".into(),
    ];

    let results = engine
        .generate_poison_samples(&samples, "malicious", 0.5)
        .unwrap();

    assert_eq!(results.len(), 2);
    for sample in &results {
        assert_eq!(sample.target_label, "malicious");
        assert!(sample.poisoned.contains("[[TRIGGER_PATTERN]]"));
        assert!(!sample.original.contains("[[TRIGGER_PATTERN]]"));
        assert!((sample.poison_rate - 0.5).abs() < f64::EPSILON);
    }
}

#[test]
fn test_waf_evasion_evaluation() {
    let mut engine = MlAttackEngine::new();
    let config = make_config(MlAttackType::EvasionAttack);
    let payloads = vec![
        "payload_0".into(),
        "payload_1".into(),
        "payload_2".into(),
        "payload_3".into(),
        "payload_4".into(),
        "payload_5".into(),
        "payload_6".into(),
        "payload_7".into(),
        "payload_8".into(),
        "payload_9".into(),
    ];

    let result = engine.evaluate_waf_evasion(&config, &payloads).unwrap();

    assert_eq!(result.attack_type, MlAttackType::EvasionAttack);
    assert_eq!(result.samples_tested, 10);
    assert!(result.evasion_rate >= 0.0 && result.evasion_rate <= 1.0);
    assert!(result.confidence_before > result.confidence_after);
    assert_eq!(engine.attack_count(), 1);
}

#[test]
fn test_evasion_technique_registration_and_lookup() {
    let mut engine = MlAttackEngine::new();

    let technique = EvasionTechnique {
        name: "Test Technique".into(),
        description: "A test evasion technique".into(),
        applicable_models: vec![ModelType::Classifier, ModelType::NeuralNetwork],
        success_rate: 0.80,
    };

    engine.register_evasion_technique(technique);
    assert_eq!(engine.evasion_techniques.len(), 1);

    let classifier_techniques = engine.get_techniques_for_model(&ModelType::Classifier);
    assert_eq!(classifier_techniques.len(), 1);
    assert_eq!(classifier_techniques[0].name, "Test Technique");

    let regression_techniques = engine.get_techniques_for_model(&ModelType::Regression);
    assert!(regression_techniques.is_empty());
}

#[test]
fn test_default_evasion_techniques() {
    let mut engine = MlAttackEngine::new();
    engine.build_default_evasion_techniques();

    assert!(engine.evasion_techniques.len() >= 5);

    let names: Vec<&str> = engine
        .evasion_techniques
        .iter()
        .map(|t| t.name.as_str())
        .collect();
    assert!(names.contains(&"Unicode Homoglyphs"));
    assert!(names.contains(&"Whitespace Injection"));
    assert!(names.contains(&"Case Alternation"));
    assert!(names.contains(&"Encoding Tricks"));
    assert!(names.contains(&"Comment Injection"));

    let classifier_techniques = engine.get_techniques_for_model(&ModelType::Classifier);
    assert!(classifier_techniques.len() >= 5);
}

#[test]
fn test_attack_logging_and_count() {
    let mut engine = MlAttackEngine::new();

    let config_inv = make_config(MlAttackType::ModelInversion);
    engine.simulate_model_inversion(&config_inv).unwrap();
    assert_eq!(engine.attack_count(), 1);

    let config_ext = make_config(MlAttackType::ModelExtraction);
    engine.simulate_model_extraction(&config_ext, 20).unwrap();
    assert_eq!(engine.attack_count(), 2);

    let config_mem = make_config(MlAttackType::MembershipInference);
    engine
        .simulate_membership_inference(&config_mem, &["s1".into()])
        .unwrap();
    assert_eq!(engine.attack_count(), 3);
}

#[test]
fn test_overall_evasion_rate() {
    let mut engine = MlAttackEngine::new();

    assert!((engine.overall_evasion_rate() - 0.0).abs() < f64::EPSILON);

    engine.attack_log.push(AttackResult {
        attack_type: MlAttackType::EvasionAttack,
        success: true,
        iterations_used: 10,
        perturbation_magnitude: 0.1,
        confidence_before: 0.95,
        confidence_after: 0.3,
        evasion_rate: 0.8,
        samples_tested: 10,
        samples_evaded: 8,
        elapsed_ms: 50,
        details: "test".into(),
    });

    engine.attack_log.push(AttackResult {
        attack_type: MlAttackType::EvasionAttack,
        success: true,
        iterations_used: 10,
        perturbation_magnitude: 0.1,
        confidence_before: 0.90,
        confidence_after: 0.4,
        evasion_rate: 0.6,
        samples_tested: 10,
        samples_evaded: 6,
        elapsed_ms: 50,
        details: "test".into(),
    });

    let rate = engine.overall_evasion_rate();
    assert!(
        (rate - 0.7).abs() < f64::EPSILON,
        "expected 14/20 = 0.7, got {rate}"
    );
}

#[test]
fn test_attack_report_export() {
    let mut engine = MlAttackEngine::new();
    engine.build_default_evasion_techniques();

    let config = make_config(MlAttackType::ModelInversion);
    engine.simulate_model_inversion(&config).unwrap();

    let report = engine.export_attack_report();

    assert!(report.contains("Adversarial ML Attack Report"));
    assert!(report.contains("Total attacks: 1"));
    assert!(report.contains("Model Inversion"));
    assert!(report.contains("Attack #1"));
    assert!(report.contains("Evasion techniques: 5"));
}

#[test]
fn test_invalid_config_zero_iterations() {
    let mut engine = MlAttackEngine::new();
    let mut config = make_config(MlAttackType::AdversarialExample);
    config.max_iterations = 0;

    let err = engine
        .generate_adversarial_examples(&config, &["test".into()])
        .unwrap_err();
    assert_eq!(
        err,
        MlAttackError::InvalidConfig("max_iterations must be greater than 0".into())
    );

    let inv_err = engine.simulate_model_inversion(&config).unwrap_err();
    assert_eq!(
        inv_err,
        MlAttackError::InvalidConfig("max_iterations must be greater than 0".into())
    );
}

#[test]
fn test_insufficient_samples_errors() {
    let mut engine = MlAttackEngine::new();
    let config = make_config(MlAttackType::AdversarialExample);

    let err = engine
        .generate_adversarial_examples(&config, &[])
        .unwrap_err();
    assert!(matches!(err, MlAttackError::InsufficientSamples(_)));

    let mem_err = engine
        .simulate_membership_inference(&config, &[])
        .unwrap_err();
    assert!(matches!(mem_err, MlAttackError::InsufficientSamples(_)));

    let poison_err = engine
        .generate_poison_samples(&[], "label", 0.5)
        .unwrap_err();
    assert!(matches!(poison_err, MlAttackError::InsufficientSamples(_)));

    let waf_err = engine.evaluate_waf_evasion(&config, &[]).unwrap_err();
    assert!(matches!(waf_err, MlAttackError::InsufficientSamples(_)));
}

#[test]
fn test_poison_rate_validation() {
    let engine = MlAttackEngine::new();
    let samples = vec!["test".into()];

    let err = engine
        .generate_poison_samples(&samples, "label", 1.5)
        .unwrap_err();
    assert!(matches!(err, MlAttackError::InvalidConfig(_)));

    let err2 = engine
        .generate_poison_samples(&samples, "label", -0.1)
        .unwrap_err();
    assert!(matches!(err2, MlAttackError::InvalidConfig(_)));
}

#[test]
fn test_model_extraction_zero_queries() {
    let mut engine = MlAttackEngine::new();
    let config = make_config(MlAttackType::ModelExtraction);

    let err = engine.simulate_model_extraction(&config, 0).unwrap_err();
    assert_eq!(
        err,
        MlAttackError::InvalidConfig("query_count must be greater than 0".into())
    );
}

#[test]
fn test_ml_attack_type_display() {
    assert_eq!(MlAttackType::ModelInversion.to_string(), "Model Inversion");
    assert_eq!(
        MlAttackType::MembershipInference.to_string(),
        "Membership Inference"
    );
    assert_eq!(
        MlAttackType::AdversarialExample.to_string(),
        "Adversarial Example"
    );
    assert_eq!(
        MlAttackType::ModelExtraction.to_string(),
        "Model Extraction"
    );
    assert_eq!(MlAttackType::DataPoisoning.to_string(), "Data Poisoning");
    assert_eq!(MlAttackType::GradientAttack.to_string(), "Gradient Attack");
    assert_eq!(MlAttackType::TransferAttack.to_string(), "Transfer Attack");
    assert_eq!(MlAttackType::EvasionAttack.to_string(), "Evasion Attack");
}

#[test]
fn test_ml_attack_error_display() {
    let err = MlAttackError::TargetUnreachable("host down".into());
    assert_eq!(err.to_string(), "Target unreachable: host down");

    let err2 = MlAttackError::TimeoutExceeded;
    assert_eq!(err2.to_string(), "Timeout exceeded");
}

#[test]
fn test_serialization_roundtrip() {
    let result = AttackResult {
        attack_type: MlAttackType::EvasionAttack,
        success: true,
        iterations_used: 42,
        perturbation_magnitude: 0.25,
        confidence_before: 0.95,
        confidence_after: 0.30,
        evasion_rate: 0.73,
        samples_tested: 100,
        samples_evaded: 73,
        elapsed_ms: 1234,
        details: "roundtrip test".into(),
    };

    let json = serde_json::to_string(&result).unwrap();
    let deserialized: AttackResult = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.attack_type, MlAttackType::EvasionAttack);
    assert_eq!(deserialized.iterations_used, 42);
    assert!((deserialized.evasion_rate - 0.73).abs() < f64::EPSILON);
}
