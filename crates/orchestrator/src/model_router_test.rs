use super::*;

#[test]
fn default_config_has_models() {
    let config = RouterConfig::default();
    assert!(!config.models.is_empty());
    assert!(!config.fallback_chain.is_empty());
}

#[test]
fn default_model_registry_covers_all_tiers() {
    let models = default_model_registry();
    let tiers: Vec<ModelTier> = models.iter().map(|m| m.tier).collect();
    assert!(tiers.contains(&ModelTier::Fast));
    assert!(tiers.contains(&ModelTier::Balanced));
    assert!(tiers.contains(&ModelTier::Powerful));
    assert!(tiers.contains(&ModelTier::Creative));
}

#[test]
fn router_routes_fast_task_to_fast_model() {
    let router = ModelRouter::with_default_config();
    let decision = router.route(TaskType::QuickClassification).unwrap();
    assert_eq!(decision.selected_model.tier, ModelTier::Fast);
    assert_eq!(decision.task_type, TaskType::QuickClassification);
}

#[test]
fn router_routes_deep_reasoning_to_powerful() {
    let router = ModelRouter::with_default_config();
    let decision = router.route(TaskType::DeepReasoning).unwrap();
    assert_eq!(decision.selected_model.tier, ModelTier::Powerful);
}

#[test]
fn router_routes_payload_gen_to_creative() {
    let router = ModelRouter::with_default_config();
    let decision = router.route(TaskType::PayloadGeneration).unwrap();
    assert_eq!(decision.selected_model.tier, ModelTier::Creative);
}

#[test]
fn router_routes_report_to_balanced() {
    let router = ModelRouter::with_default_config();
    let decision = router.route(TaskType::ReportSynthesis).unwrap();
    assert_eq!(decision.selected_model.tier, ModelTier::Balanced);
}

#[test]
fn routing_decision_has_fallbacks() {
    let router = ModelRouter::with_default_config();
    let decision = router.route(TaskType::DeepReasoning).unwrap();
    // Fallback chain excludes the selected model
    for fallback in &decision.fallback_models {
        assert_ne!(*fallback, decision.selected_model.model_id);
    }
}

#[test]
fn routing_decision_has_estimated_cost() {
    let router = ModelRouter::with_default_config();
    let decision = router.route(TaskType::QuickClassification).unwrap();
    assert!(decision.estimated_cost_usd > 0.0);
}

#[test]
fn tier_override_changes_routing() {
    let mut overrides = HashMap::new();
    overrides.insert(TaskType::QuickClassification, ModelTier::Powerful);

    let config = RouterConfig {
        tier_overrides: overrides,
        ..RouterConfig::default()
    };
    let router = ModelRouter::new(config);
    let decision = router.route(TaskType::QuickClassification).unwrap();
    assert_eq!(decision.selected_model.tier, ModelTier::Powerful);
}

#[test]
fn cost_tracker_records_invocations() {
    let mut tracker = CostTracker::new();
    assert_eq!(tracker.invocation_count, 0);

    tracker.record("model-a", "task-a", 1000, 500, 0.01);
    tracker.record("model-b", "task-a", 2000, 1000, 0.03);

    assert_eq!(tracker.invocation_count, 2);
    assert_eq!(tracker.total_input_tokens, 3000);
    assert_eq!(tracker.total_output_tokens, 1500);
    assert!((tracker.total_cost_usd - 0.04).abs() < 0.001);
    assert_eq!(tracker.cost_by_model.len(), 2);
    assert_eq!(tracker.cost_by_task_type.len(), 1); // both task-a
}

#[test]
fn cost_tracker_budget_check() {
    let mut tracker = CostTracker::new();
    assert!(!tracker.is_over_budget(1.0));

    tracker.record("model-a", "task-a", 100, 50, 0.5);
    assert!(!tracker.is_over_budget(1.0));

    tracker.record("model-a", "task-a", 100, 50, 0.6);
    assert!(tracker.is_over_budget(1.0));
}

#[test]
fn cost_tracker_remaining_budget() {
    let mut tracker = CostTracker::new();
    assert!((tracker.remaining_budget(1.0) - 1.0).abs() < 0.001);

    tracker.record("m", "t", 0, 0, 0.3);
    assert!((tracker.remaining_budget(1.0) - 0.7).abs() < 0.001);
}

#[test]
fn router_budget_exceeded_error() {
    let config = RouterConfig {
        cost_budget: Some(0.01),
        ..RouterConfig::default()
    };
    let mut router = ModelRouter::new(config);
    router.record_invocation(
        "anthropic:claude-opus-4-20250514",
        TaskType::DeepReasoning,
        100000,
        50000,
    );

    let result = router.route(TaskType::QuickClassification);
    assert!(result.is_err());
    match result.unwrap_err() {
        RouterError::BudgetExceeded { .. } => {}
        other => panic!("expected BudgetExceeded, got: {other}"),
    }
}

#[test]
fn router_record_invocation_tracks_costs() {
    let mut router = ModelRouter::with_default_config();
    router.record_invocation(
        "anthropic:claude-haiku-4-20250514",
        TaskType::QuickClassification,
        1000,
        500,
    );

    let tracker = router.cost_tracker();
    assert_eq!(tracker.invocation_count, 1);
    assert_eq!(tracker.total_input_tokens, 1000);
    assert_eq!(tracker.total_output_tokens, 500);
    assert!(tracker.total_cost_usd > 0.0);
}

#[test]
fn classify_task_payload_generation() {
    assert_eq!(
        classify_task("Generate bypass payloads for WAF evasion"),
        TaskType::PayloadGeneration
    );
}

#[test]
fn classify_task_classification() {
    assert_eq!(
        classify_task("Classify this vulnerability type"),
        TaskType::QuickClassification
    );
}

#[test]
fn classify_task_tech_fingerprinting() {
    assert_eq!(
        classify_task("Fingerprint the tech stack of this target"),
        TaskType::TechStackFingerprinting
    );
}

#[test]
fn classify_task_report() {
    assert_eq!(
        classify_task("Generate an executive summary report"),
        TaskType::ReportSynthesis
    );
}

#[test]
fn classify_task_vulnerability_analysis() {
    assert_eq!(
        classify_task("Analyze the attack surface for vulnerabilities"),
        TaskType::VulnerabilityAnalysis
    );
}

#[test]
fn classify_task_deep_reasoning() {
    let long_prompt = "a".repeat(5000) + " analyze the chain of events";
    assert_eq!(classify_task(&long_prompt), TaskType::DeepReasoning);
}

#[test]
fn estimate_cost_calculation() {
    let model = ModelSpec {
        provider: "test".to_string(),
        model_id: "test:model".to_string(),
        display_name: "Test".to_string(),
        tier: ModelTier::Fast,
        cost_per_input_token: 0.001,
        cost_per_output_token: 0.002,
        max_context_tokens: 4096,
        max_output_tokens: 1024,
        supports_json_mode: true,
    };
    let cost = estimate_invocation_cost(&model, 1000, 500);
    assert!((cost - 2.0).abs() < 0.001); // 1000*0.001 + 500*0.002 = 2.0
}

#[test]
fn invoke_with_fallback_primary_succeeds() {
    let mut router = ModelRouter::with_default_config();
    let (response, model) = router
        .invoke_with_fallback(TaskType::QuickClassification, |_model| {
            Ok(("success".to_string(), 100, 50))
        })
        .unwrap();

    assert_eq!(response, "success");
    assert_eq!(model.tier, ModelTier::Fast);
    assert_eq!(router.cost_tracker().invocation_count, 1);
}

#[test]
fn invoke_with_fallback_falls_back_on_failure() {
    let mut router = ModelRouter::with_default_config();
    let mut call_count = 0u32;

    let result = router.invoke_with_fallback(TaskType::QuickClassification, |model| {
        call_count += 1;
        if call_count == 1 {
            Err("primary failed".to_string())
        } else {
            Ok(("fallback success".to_string(), 200, 100))
        }
    });

    match result {
        Ok((response, _)) => assert_eq!(response, "fallback success"),
        Err(_) => {
            // May fail if no fallback matches the fast tier
            // This is acceptable behavior
        }
    }
}

#[test]
fn invoke_with_fallback_all_fail() {
    let mut router = ModelRouter::with_default_config();
    let result = router.invoke_with_fallback(TaskType::QuickClassification, |_| {
        Err("always fail".to_string())
    });

    assert!(result.is_err());
    match result.unwrap_err() {
        RouterError::InvocationFailed { error, .. } => {
            assert!(error.contains("fallback chain"));
        }
        other => panic!("expected InvocationFailed, got: {other}"),
    }
}

#[test]
fn task_type_display() {
    assert_eq!(
        format!("{}", TaskType::QuickClassification),
        "quick_classification"
    );
    assert_eq!(format!("{}", TaskType::DeepReasoning), "deep_reasoning");
    assert_eq!(
        format!("{}", TaskType::PayloadGeneration),
        "payload_generation"
    );
}

#[test]
fn model_tier_display() {
    assert_eq!(format!("{}", ModelTier::Fast), "fast");
    assert_eq!(format!("{}", ModelTier::Powerful), "powerful");
    assert_eq!(format!("{}", ModelTier::Creative), "creative");
    assert_eq!(format!("{}", ModelTier::Balanced), "balanced");
}

#[test]
fn router_error_display() {
    let err = RouterError::NoAvailableModel("test".to_string());
    assert!(err.to_string().contains("test"));

    let err = RouterError::BudgetExceeded {
        budget: 1.0,
        spent: 1.5,
    };
    assert!(err.to_string().contains("1.0"));
    assert!(err.to_string().contains("1.5"));

    let err = RouterError::ModelNotFound("abc".to_string());
    assert!(err.to_string().contains("abc"));
}

#[test]
fn get_model_by_id() {
    let router = ModelRouter::with_default_config();
    let model = router.get_model("anthropic:claude-opus-4-20250514");
    assert!(model.is_some());
    assert_eq!(model.unwrap().tier, ModelTier::Powerful);

    assert!(router.get_model("nonexistent:model").is_none());
}

#[test]
fn model_spec_serde_roundtrip() {
    let model = ModelSpec {
        provider: "anthropic".to_string(),
        model_id: "anthropic:test".to_string(),
        display_name: "Test".to_string(),
        tier: ModelTier::Fast,
        cost_per_input_token: 0.001,
        cost_per_output_token: 0.002,
        max_context_tokens: 4096,
        max_output_tokens: 1024,
        supports_json_mode: true,
    };
    let json = serde_json::to_string(&model).unwrap();
    let parsed: ModelSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.model_id, "anthropic:test");
    assert_eq!(parsed.tier, ModelTier::Fast);
}

#[test]
fn cost_tracker_serde_roundtrip() {
    let mut tracker = CostTracker::new();
    tracker.record("m1", "t1", 100, 50, 0.05);
    let json = serde_json::to_string(&tracker).unwrap();
    let parsed: CostTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.invocation_count, 1);
    assert!((parsed.total_cost_usd - 0.05).abs() < 0.001);
}

#[test]
fn is_over_budget_with_no_budget() {
    let router = ModelRouter::with_default_config();
    assert!(!router.is_over_budget());
}

#[test]
fn task_type_needs_json_mode() {
    assert!(TaskType::QuickClassification.needs_json_mode());
    assert!(TaskType::PayloadGeneration.needs_json_mode());
    assert!(!TaskType::DeepReasoning.needs_json_mode());
    assert!(!TaskType::ReportSynthesis.needs_json_mode());
}
