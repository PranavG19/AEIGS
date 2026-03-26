use crate::ai_fine_tuner::*;

fn make_outcome(
    id: &str,
    model: &str,
    confidence: f64,
    confirmed: bool,
    vuln_class: &str,
) -> HypothesisOutcome {
    HypothesisOutcome {
        hypothesis_id: id.to_string(),
        endpoint: "/api/test".to_string(),
        vulnerability_class: vuln_class.to_string(),
        predicted_confidence: confidence,
        was_confirmed: confirmed,
        evidence_level: "Statistical".to_string(),
        response_time_ms: 120,
        model_id: model.to_string(),
        timestamp_ms: 1700000000000,
    }
}

#[test]
fn record_outcome_increments_count() {
    let mut ft = FineTuner::new();
    assert_eq!(ft.outcome_count(), 0);

    ft.record_outcome(make_outcome("h1", "sonnet", 0.9, true, "SqlInjection"));
    assert_eq!(ft.outcome_count(), 1);

    ft.record_outcome(make_outcome("h2", "sonnet", 0.3, false, "Xss"));
    assert_eq!(ft.outcome_count(), 2);
}

#[test]
fn model_performance_tracking() {
    let mut ft = FineTuner::new();
    ft.record_outcome(make_outcome("h1", "sonnet", 0.9, true, "SqlInjection"));
    ft.record_outcome(make_outcome("h2", "sonnet", 0.8, true, "Xss"));
    ft.record_outcome(make_outcome("h3", "sonnet", 0.7, false, "SqlInjection"));

    let perf = ft.get_model_performance("sonnet").expect("should exist");
    assert_eq!(perf.total_predictions, 3);
    assert_eq!(perf.model_id, "sonnet");
    assert!(perf.avg_confidence > 0.0);
}

#[test]
fn generate_training_example_creates_three_messages() {
    let mut ft = FineTuner::new();
    let outcome = make_outcome("h1", "sonnet", 0.85, true, "SqlInjection");

    let example = ft.generate_training_example(
        &outcome,
        "You are a security analysis model.",
        "Endpoint /api/test shows SQL error in response body.",
    );

    assert_eq!(example.messages.len(), 3);
    assert_eq!(example.messages[0].role, "system");
    assert_eq!(example.messages[1].role, "user");
    assert_eq!(example.messages[2].role, "assistant");
    assert!(example.messages[2].content.contains("CONFIRMED"));
    assert_eq!(example.metadata.vulnerability_class, "SqlInjection");
    assert!(example.metadata.confirmed);
    assert_eq!(ft.training_examples.len(), 1);
}

#[test]
fn generate_training_example_refuted() {
    let mut ft = FineTuner::new();
    let outcome = make_outcome("h2", "haiku", 0.4, false, "Xss");

    let example = ft.generate_training_example(&outcome, "system", "context");
    assert!(example.messages[2].content.contains("REFUTED"));
    assert!(!example.metadata.confirmed);
}

#[test]
fn export_openai_jsonl_produces_valid_lines() {
    let mut ft = FineTuner::new();
    let outcome = make_outcome("h1", "sonnet", 0.9, true, "SqlInjection");
    ft.generate_training_example(&outcome, "sys prompt", "user context");

    let jsonl = ft.export_openai_jsonl().expect("should export");
    let lines: Vec<&str> = jsonl.lines().collect();
    assert_eq!(lines.len(), 1);

    let parsed: serde_json::Value = serde_json::from_str(lines[0]).expect("valid json");
    assert!(parsed.get("messages").is_some());
    let messages = parsed["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 3);
}

#[test]
fn export_bedrock_jsonl_separates_system() {
    let mut ft = FineTuner::new();
    let outcome = make_outcome("h1", "sonnet", 0.9, true, "SqlInjection");
    ft.generate_training_example(&outcome, "sys prompt", "scan data");

    let jsonl = ft.export_bedrock_jsonl().expect("should export");
    let parsed: serde_json::Value =
        serde_json::from_str(jsonl.lines().next().unwrap()).expect("valid json");

    assert_eq!(parsed["system"].as_str().unwrap(), "sys prompt");
    let messages = parsed["messages"].as_array().unwrap();
    assert!(messages
        .iter()
        .all(|m| m["role"].as_str().unwrap() != "system"));
}

#[test]
fn export_empty_returns_insufficient_data() {
    let ft = FineTuner::new();
    let err = ft.export_openai_jsonl().unwrap_err();
    match err {
        FineTuneError::InsufficientData(_) => {}
        other => panic!("expected InsufficientData, got: {other:?}"),
    }
}

#[test]
fn ab_test_start_and_evaluate() {
    let mut ft = FineTuner::new();

    let config = AbTestConfig {
        model_a: "sonnet".to_string(),
        model_b: "haiku".to_string(),
        traffic_split: 0.5,
        min_samples: 2,
        started_at: 1700000000000,
    };
    ft.start_ab_test(config).expect("should start");

    ft.record_outcome(make_outcome("h1", "sonnet", 0.9, true, "SqlInjection"));
    ft.record_outcome(make_outcome("h2", "sonnet", 0.8, true, "Xss"));
    ft.record_outcome(make_outcome("h3", "haiku", 0.6, true, "SqlInjection"));
    ft.record_outcome(make_outcome("h4", "haiku", 0.7, false, "Xss"));

    let result = ft
        .evaluate_ab_test("sonnet", "haiku")
        .expect("should evaluate");
    assert_eq!(result.total_samples, 4);
    assert_eq!(result.model_a_perf.total_predictions, 2);
    assert_eq!(result.model_b_perf.total_predictions, 2);
}

#[test]
fn ab_test_invalid_same_model() {
    let mut ft = FineTuner::new();
    let config = AbTestConfig {
        model_a: "sonnet".to_string(),
        model_b: "sonnet".to_string(),
        traffic_split: 0.5,
        min_samples: 10,
        started_at: 0,
    };
    let err = ft.start_ab_test(config).unwrap_err();
    match err {
        FineTuneError::InvalidConfig(_) => {}
        other => panic!("expected InvalidConfig, got: {other:?}"),
    }
}

#[test]
fn model_selection_with_ab_test() {
    let mut ft = FineTuner::new();

    let config = AbTestConfig {
        model_a: "sonnet".to_string(),
        model_b: "haiku".to_string(),
        traffic_split: 0.5,
        min_samples: 10,
        started_at: 0,
    };
    ft.start_ab_test(config).unwrap();

    let mut saw_a = false;
    let mut saw_b = false;
    for _ in 0..200 {
        let model = ft.select_model_for_request();
        if model == "sonnet" {
            saw_a = true;
        } else if model == "haiku" {
            saw_b = true;
        }
        if saw_a && saw_b {
            break;
        }
    }
    assert!(saw_a, "should have selected model_a at least once");
    assert!(saw_b, "should have selected model_b at least once");
}

#[test]
fn compute_metrics_precision_recall_f1() {
    let outcomes = vec![
        make_outcome("h1", "m1", 0.9, true, "SqlInjection"),
        make_outcome("h2", "m1", 0.8, true, "Xss"),
        make_outcome("h3", "m1", 0.7, false, "SqlInjection"),
        make_outcome("h4", "m1", 0.2, false, "Xss"),
    ];

    let perf = FineTuner::compute_model_metrics(&outcomes, "m1");
    assert_eq!(perf.total_predictions, 4);

    // h1: predicted positive (0.9>=0.5), confirmed=true  → TP
    // h2: predicted positive (0.8>=0.5), confirmed=true  → TP
    // h3: predicted positive (0.7>=0.5), confirmed=false → FP
    // h4: predicted negative (0.2<0.5),  confirmed=false → TN
    // precision = 2/(2+1) = 0.666..
    // recall    = 2/(2+0) = 1.0
    // f1        = 2*0.666*1.0/(0.666+1.0) = 0.8
    assert!((perf.precision - 2.0 / 3.0).abs() < 1e-9);
    assert!((perf.recall - 1.0).abs() < 1e-9);
    assert!((perf.f1_score - 0.8).abs() < 1e-9);
    assert_eq!(perf.false_positives, 1);
    assert_eq!(perf.false_negatives, 0);
    assert_eq!(perf.correct_predictions, 3);
}

#[test]
fn successful_hypothesis_rate_calculation() {
    let mut ft = FineTuner::new();
    assert_eq!(ft.successful_hypothesis_rate(), 0.0);

    ft.record_outcome(make_outcome("h1", "m1", 0.9, true, "SqlInjection"));
    ft.record_outcome(make_outcome("h2", "m1", 0.8, false, "Xss"));
    ft.record_outcome(make_outcome("h3", "m1", 0.7, true, "SqlInjection"));

    let rate = ft.successful_hypothesis_rate();
    assert!((rate - 2.0 / 3.0).abs() < 1e-9);
}

#[test]
fn top_performing_model_by_f1() {
    let mut ft = FineTuner::new();
    assert!(ft.top_performing_model().is_none());

    // Model "alpha": all correct high-confidence true positives
    ft.record_outcome(make_outcome("h1", "alpha", 0.95, true, "SqlInjection"));
    ft.record_outcome(make_outcome("h2", "alpha", 0.90, true, "Xss"));

    // Model "beta": mixed — one FP drags F1 down
    ft.record_outcome(make_outcome("h3", "beta", 0.8, true, "SqlInjection"));
    ft.record_outcome(make_outcome("h4", "beta", 0.9, false, "Xss"));

    let top = ft.top_performing_model().expect("should have a top model");
    assert_eq!(top, "alpha");
}

#[test]
fn full_lifecycle_record_generate_export_evaluate() {
    let mut ft = FineTuner::new();

    // Record several outcomes across two models
    for i in 0..5 {
        ft.record_outcome(make_outcome(
            &format!("s{i}"),
            "sonnet",
            0.85,
            i % 2 == 0,
            "SqlInjection",
        ));
        ft.record_outcome(make_outcome(
            &format!("h{i}"),
            "haiku",
            0.6,
            i % 3 == 0,
            "Xss",
        ));
    }

    assert_eq!(ft.outcome_count(), 10);

    // Generate training examples from all outcomes
    for outcome in ft.outcomes.clone() {
        ft.generate_training_example(&outcome, "system prompt", "scan context");
    }
    assert_eq!(ft.training_examples.len(), 10);

    // Export in multiple formats
    let openai = ft
        .export_training_data(TrainingFormat::OpenAiJsonl)
        .unwrap();
    assert_eq!(openai.lines().count(), 10);

    let bedrock = ft
        .export_training_data(TrainingFormat::BedrockJsonl)
        .unwrap();
    assert_eq!(bedrock.lines().count(), 10);

    // Start and evaluate an A/B test
    ft.start_ab_test(AbTestConfig {
        model_a: "sonnet".to_string(),
        model_b: "haiku".to_string(),
        traffic_split: 0.5,
        min_samples: 3,
        started_at: 0,
    })
    .unwrap();

    let result = ft.evaluate_ab_test("sonnet", "haiku").unwrap();
    assert_eq!(result.model_a_perf.total_predictions, 5);
    assert_eq!(result.model_b_perf.total_predictions, 5);
    assert!(result.total_samples == 10);

    // Verify top model exists
    assert!(ft.top_performing_model().is_some());
}

#[test]
fn export_training_data_anthropic_format() {
    let mut ft = FineTuner::new();
    let outcome = make_outcome("h1", "opus", 0.95, true, "Xss");
    ft.generate_training_example(&outcome, "you are a vuln analyzer", "xss payload reflected");

    let anthropic = ft
        .export_training_data(TrainingFormat::AnthropicJsonl)
        .unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(anthropic.lines().next().unwrap()).unwrap();
    assert!(parsed.get("system").is_some());
    assert!(parsed.get("messages").is_some());
}

#[test]
fn ab_test_not_found() {
    let ft = FineTuner::new();
    let err = ft.evaluate_ab_test("x", "y").unwrap_err();
    match err {
        FineTuneError::AbTestNotFound(_) => {}
        other => panic!("expected AbTestNotFound, got: {other:?}"),
    }
}
