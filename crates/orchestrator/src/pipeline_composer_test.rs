use super::pipeline_composer::*;

#[test]
fn validate_default_pipeline_succeeds() {
    let def = default_pipeline();
    assert!(validate_pipeline(&def).is_ok());
}

#[test]
fn validate_empty_pipeline_fails() {
    let def = PipelineDefinition::new();
    let err = validate_pipeline(&def).unwrap_err();
    assert!(matches!(err, ComposerError::EmptyPipeline));
}

#[test]
fn validate_duplicate_names_fails() {
    let mut def = PipelineDefinition::new();
    def.add_stage(PipelineStage::new("recon", PhaseType::Source));
    def.add_stage(PipelineStage::new("recon", PhaseType::Sink));
    let err = validate_pipeline(&def).unwrap_err();
    assert!(matches!(err, ComposerError::DuplicateStageName(ref n) if n == "recon"));
}

#[test]
fn validate_missing_dependency_fails() {
    let mut def = PipelineDefinition::new();
    def.add_stage(PipelineStage::new("recon", PhaseType::Source));
    def.add_stage(PipelineStage::new("report", PhaseType::Sink).with_dependency("analyze"));
    let err = validate_pipeline(&def).unwrap_err();
    assert!(
        matches!(err, ComposerError::MissingDependency { ref dependency, .. } if dependency == "analyze")
    );
}

#[test]
fn validate_cyclic_dependency_fails() {
    let mut def = PipelineDefinition::new();
    def.add_stage(PipelineStage::new("source", PhaseType::Source));
    def.add_stage(PipelineStage::new("a", PhaseType::Transform).with_dependency("b"));
    def.add_stage(PipelineStage::new("b", PhaseType::Transform).with_dependency("a"));
    def.add_stage(PipelineStage::new("sink", PhaseType::Sink).with_dependency("source"));
    let err = validate_pipeline(&def).unwrap_err();
    assert!(matches!(err, ComposerError::CyclicDependency(_)));
}

#[test]
fn validate_no_source_stage_fails() {
    let mut def = PipelineDefinition::new();
    def.add_stage(PipelineStage::new("fuzz", PhaseType::Transform));
    def.add_stage(PipelineStage::new("report", PhaseType::Sink).with_dependency("fuzz"));
    let err = validate_pipeline(&def).unwrap_err();
    assert!(matches!(err, ComposerError::NoSourceStage));
}

#[test]
fn validate_no_sink_stage_fails() {
    let mut def = PipelineDefinition::new();
    def.add_stage(PipelineStage::new("recon", PhaseType::Source));
    def.add_stage(PipelineStage::new("fuzz", PhaseType::Transform).with_dependency("recon"));
    let err = validate_pipeline(&def).unwrap_err();
    assert!(matches!(err, ComposerError::NoSinkStage));
}

#[test]
fn topological_order_returns_valid_order() {
    let def = default_pipeline();
    let order = topological_order(&def).unwrap();
    assert_eq!(order.len(), 7);
    let recon_pos = order.iter().position(|n| n == "recon").unwrap();
    let crawl_pos = order.iter().position(|n| n == "crawl").unwrap();
    let fuzz_pos = order.iter().position(|n| n == "fuzz").unwrap();
    let analyze_pos = order.iter().position(|n| n == "analyze").unwrap();
    let dom_verify_pos = order.iter().position(|n| n == "dom_verify").unwrap();
    let report_pos = order.iter().position(|n| n == "report").unwrap();
    assert!(recon_pos < crawl_pos);
    assert!(crawl_pos < fuzz_pos);
    assert!(fuzz_pos < analyze_pos);
    assert!(analyze_pos < dom_verify_pos);
    assert!(dom_verify_pos < report_pos);
}

#[test]
fn topological_order_with_parallel_stages() {
    let mut def = PipelineDefinition::new();
    def.add_stage(PipelineStage::new("recon", PhaseType::Source));
    def.add_stage(PipelineStage::new("fuzz", PhaseType::Transform).with_dependency("recon"));
    def.add_stage(PipelineStage::new("fingerprint", PhaseType::Source).with_dependency("recon"));
    def.add_stage(
        PipelineStage::new("report", PhaseType::Sink)
            .with_dependency("fuzz")
            .with_dependency("fingerprint"),
    );
    let order = topological_order(&def).unwrap();
    let recon_pos = order.iter().position(|n| n == "recon").unwrap();
    let fuzz_pos = order.iter().position(|n| n == "fuzz").unwrap();
    let fp_pos = order.iter().position(|n| n == "fingerprint").unwrap();
    let report_pos = order.iter().position(|n| n == "report").unwrap();
    assert!(recon_pos < fuzz_pos);
    assert!(recon_pos < fp_pos);
    assert!(fuzz_pos < report_pos);
    assert!(fp_pos < report_pos);
}

#[test]
fn topological_order_detects_cycle() {
    let mut def = PipelineDefinition::new();
    def.add_stage(PipelineStage::new("a", PhaseType::Source).with_dependency("c"));
    def.add_stage(PipelineStage::new("b", PhaseType::Transform).with_dependency("a"));
    def.add_stage(PipelineStage::new("c", PhaseType::Sink).with_dependency("b"));
    let err = topological_order(&def).unwrap_err();
    assert!(matches!(err, ComposerError::CyclicDependency(_)));
}

#[test]
fn default_pipeline_has_seven_stages() {
    let def = default_pipeline();
    assert_eq!(def.stages.len(), 7);
}

#[test]
fn default_pipeline_validates() {
    assert!(validate_pipeline(&default_pipeline()).is_ok());
}

#[test]
fn minimal_pipeline_has_three_stages() {
    let def = minimal_pipeline();
    assert_eq!(def.stages.len(), 3);
}

#[test]
fn minimal_pipeline_validates() {
    assert!(validate_pipeline(&minimal_pipeline()).is_ok());
}

#[test]
fn recon_only_pipeline_has_two_stages() {
    let def = recon_only_pipeline();
    assert_eq!(def.stages.len(), 2);
}

#[test]
fn recon_only_pipeline_validates() {
    assert!(validate_pipeline(&recon_only_pipeline()).is_ok());
}

#[test]
fn add_stage_appends_to_list() {
    let mut def = PipelineDefinition::new();
    assert_eq!(def.stages.len(), 0);
    def.add_stage(PipelineStage::new("recon", PhaseType::Source));
    assert_eq!(def.stages.len(), 1);
    assert_eq!(def.stages[0].name, "recon");
}

#[test]
fn with_max_iterations_sets_value() {
    let mut def = PipelineDefinition::new();
    def.with_max_iterations(10);
    assert_eq!(def.max_iterations, 10);
}

#[test]
fn with_convergence_threshold_sets_value() {
    let mut def = PipelineDefinition::new();
    def.with_convergence_threshold(5);
    assert_eq!(def.convergence_threshold, 5);
}

#[test]
fn execution_plan_single_wave_for_independent_stages() {
    let mut def = PipelineDefinition::new();
    def.add_stage(PipelineStage::new("source_a", PhaseType::Source));
    def.add_stage(PipelineStage::new("source_b", PhaseType::Source));
    def.add_stage(
        PipelineStage::new("sink", PhaseType::Sink)
            .with_dependency("source_a")
            .with_dependency("source_b"),
    );
    let waves = execution_plan(&def).unwrap();
    assert_eq!(waves.len(), 2);
    assert_eq!(waves[0].len(), 2);
    assert_eq!(waves[1].len(), 1);
}

#[test]
fn execution_plan_multi_wave_for_chain() {
    let def = recon_only_pipeline();
    let waves = execution_plan(&def).unwrap();
    assert_eq!(waves.len(), 2);
    assert_eq!(waves[0], vec!["recon"]);
    assert_eq!(waves[1], vec!["report"]);
}

#[test]
fn execution_plan_default_pipeline_has_correct_waves() {
    let def = default_pipeline();
    let waves = execution_plan(&def).unwrap();
    assert_eq!(waves[0], vec!["recon"]);
    assert_eq!(waves[1], vec!["crawl"]);
    assert!(waves[2].contains(&"fingerprint".to_string()));
    assert!(waves[2].contains(&"fuzz".to_string()));
    let analyze_wave = waves
        .iter()
        .position(|w| w.contains(&"analyze".to_string()))
        .unwrap();
    let dom_verify_wave = waves
        .iter()
        .position(|w| w.contains(&"dom_verify".to_string()))
        .unwrap();
    let report_wave = waves
        .iter()
        .position(|w| w.contains(&"report".to_string()))
        .unwrap();
    assert!(analyze_wave > 2);
    assert!(dom_verify_wave > analyze_wave);
    assert!(report_wave > dom_verify_wave);
}

#[test]
fn describe_pipeline_includes_stage_names() {
    let def = default_pipeline();
    let desc = describe_pipeline(&def);
    assert!(desc.contains("recon"));
    assert!(desc.contains("crawl"));
    assert!(desc.contains("fingerprint"));
    assert!(desc.contains("fuzz"));
    assert!(desc.contains("analyze"));
    assert!(desc.contains("dom_verify"));
    assert!(desc.contains("report"));
}

#[test]
fn describe_pipeline_empty_says_empty() {
    let def = PipelineDefinition::new();
    let desc = describe_pipeline(&def);
    assert_eq!(desc, "empty pipeline");
}

#[test]
fn pipeline_stage_default_values() {
    let stage = PipelineStage::new("test", PhaseType::Source);
    assert_eq!(stage.name, "test");
    assert_eq!(stage.phase_type, PhaseType::Source);
    assert!(stage.depends_on.is_empty());
    assert!(!stage.optional);
    assert_eq!(stage.max_retries, 0);
}

#[test]
fn phase_type_equality() {
    assert_eq!(PhaseType::Source, PhaseType::Source);
    assert_eq!(PhaseType::Transform, PhaseType::Transform);
    assert_eq!(PhaseType::Sink, PhaseType::Sink);
    assert_eq!(PhaseType::Observer, PhaseType::Observer);
    assert_ne!(PhaseType::Source, PhaseType::Sink);
    assert_ne!(PhaseType::Transform, PhaseType::Observer);
}

#[test]
fn stage_result_default_values() {
    let result = StageResult::new("recon");
    assert_eq!(result.stage_name, "recon");
    assert_eq!(result.events_produced, 0);
    assert_eq!(result.events_consumed, 0);
    assert_eq!(result.duration_ms, 0);
    assert_eq!(result.retries_used, 0);
    assert!(!result.skipped);
    assert!(result.error.is_none());
}

#[test]
fn pipeline_result_tracks_stages() {
    let mut pr = PipelineResult::new();
    assert!(pr.stage_results.is_empty());
    pr.stage_results.push(StageResult::new("recon"));
    pr.stage_results.push(StageResult::new("report"));
    assert_eq!(pr.stage_results.len(), 2);
    assert_eq!(pr.stage_results[0].stage_name, "recon");
    assert_eq!(pr.stage_results[1].stage_name, "report");
}

#[test]
fn composer_error_display_duplicate() {
    let err = ComposerError::DuplicateStageName("recon".to_string());
    assert_eq!(format!("{err}"), "duplicate stage name: recon");
}

#[test]
fn composer_error_display_missing_dependency() {
    let err = ComposerError::MissingDependency {
        stage: "fuzz".to_string(),
        dependency: "recon".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("fuzz"));
    assert!(msg.contains("recon"));
}

#[test]
fn composer_error_display_cyclic() {
    let err = ComposerError::CyclicDependency("a, b".to_string());
    let msg = format!("{err}");
    assert!(msg.contains("cyclic"));
    assert!(msg.contains("a, b"));
}

#[test]
fn composer_error_display_empty() {
    let err = ComposerError::EmptyPipeline;
    assert_eq!(format!("{err}"), "pipeline has no stages");
}

#[test]
fn composer_error_display_no_source() {
    let err = ComposerError::NoSourceStage;
    assert!(format!("{err}").contains("Source"));
}

#[test]
fn composer_error_display_no_sink() {
    let err = ComposerError::NoSinkStage;
    assert!(format!("{err}").contains("Sink"));
}

#[test]
fn execution_plan_minimal_pipeline() {
    let def = minimal_pipeline();
    let waves = execution_plan(&def).unwrap();
    assert_eq!(waves.len(), 3);
    assert_eq!(waves[0], vec!["recon"]);
    assert_eq!(waves[1], vec!["fuzz"]);
    assert_eq!(waves[2], vec!["report"]);
}

#[test]
fn topological_order_preserves_definition_order_for_non_dependent_stages() {
    let mut def = PipelineDefinition::new();
    def.add_stage(PipelineStage::new("alpha", PhaseType::Source));
    def.add_stage(PipelineStage::new("beta", PhaseType::Source));
    def.add_stage(
        PipelineStage::new("sink", PhaseType::Sink)
            .with_dependency("alpha")
            .with_dependency("beta"),
    );
    let order = topological_order(&def).unwrap();
    let alpha_pos = order.iter().position(|n| n == "alpha").unwrap();
    let beta_pos = order.iter().position(|n| n == "beta").unwrap();
    assert!(alpha_pos < beta_pos);
}

#[test]
fn validate_pipeline_allows_observer_without_being_a_sink() {
    let mut def = PipelineDefinition::new();
    def.add_stage(PipelineStage::new("recon", PhaseType::Source));
    def.add_stage(PipelineStage::new("convergence", PhaseType::Observer).with_dependency("recon"));
    def.add_stage(PipelineStage::new("report", PhaseType::Sink).with_dependency("recon"));
    assert!(validate_pipeline(&def).is_ok());
}

#[test]
fn pipeline_stage_with_dependency_builder() {
    let stage = PipelineStage::new("fuzz", PhaseType::Transform)
        .with_dependency("recon")
        .with_dependency("fingerprint");
    assert_eq!(stage.depends_on, vec!["recon", "fingerprint"]);
}

#[test]
fn pipeline_stage_with_optional_builder() {
    let stage = PipelineStage::new("fp", PhaseType::Source).with_optional(true);
    assert!(stage.optional);
}

#[test]
fn pipeline_stage_with_max_retries_builder() {
    let stage = PipelineStage::new("fuzz", PhaseType::Transform).with_max_retries(3);
    assert_eq!(stage.max_retries, 3);
}

#[test]
fn pipeline_definition_default_iterations() {
    let def = PipelineDefinition::new();
    assert_eq!(def.max_iterations, 1);
    assert_eq!(def.convergence_threshold, 2);
}

#[test]
fn pipeline_result_default_values() {
    let pr = PipelineResult::new();
    assert!(pr.stage_results.is_empty());
    assert_eq!(pr.total_events, 0);
    assert_eq!(pr.total_duration_ms, 0);
    assert!(!pr.converged);
    assert_eq!(pr.iterations_completed, 0);
}

#[test]
fn composer_error_is_std_error() {
    let err = ComposerError::EmptyPipeline;
    let _: &dyn std::error::Error = &err;
}

#[test]
fn phase_type_debug() {
    let dbg = format!("{:?}", PhaseType::Source);
    assert_eq!(dbg, "Source");
}

#[test]
fn describe_pipeline_uses_arrows() {
    let def = minimal_pipeline();
    let desc = describe_pipeline(&def);
    assert!(desc.contains("->"));
}

#[test]
fn default_pipeline_fingerprint_is_optional() {
    let def = default_pipeline();
    let fp = def.stages.iter().find(|s| s.name == "fingerprint").unwrap();
    assert!(fp.optional);
}

#[test]
fn default_pipeline_convergence_settings() {
    let def = default_pipeline();
    assert_eq!(def.max_iterations, 1);
    assert_eq!(def.convergence_threshold, 2);
}

#[test]
fn execution_plan_diamond_dependency() {
    let mut def = PipelineDefinition::new();
    def.add_stage(PipelineStage::new("source", PhaseType::Source));
    def.add_stage(PipelineStage::new("left", PhaseType::Transform).with_dependency("source"));
    def.add_stage(PipelineStage::new("right", PhaseType::Transform).with_dependency("source"));
    def.add_stage(
        PipelineStage::new("sink", PhaseType::Sink)
            .with_dependency("left")
            .with_dependency("right"),
    );
    let waves = execution_plan(&def).unwrap();
    assert_eq!(waves.len(), 3);
    assert_eq!(waves[0], vec!["source"]);
    assert_eq!(waves[1].len(), 2);
    assert!(waves[1].contains(&"left".to_string()));
    assert!(waves[1].contains(&"right".to_string()));
    assert_eq!(waves[2], vec!["sink"]);
}

#[test]
fn phase_type_serde_roundtrip() {
    let json = serde_json::to_string(&PhaseType::Transform).unwrap();
    let back: PhaseType = serde_json::from_str(&json).unwrap();
    assert_eq!(back, PhaseType::Transform);
}

#[test]
fn stage_result_with_error() {
    let mut result = StageResult::new("fuzz");
    result.error = Some("timeout".to_string());
    result.retries_used = 2;
    assert_eq!(result.error.as_deref(), Some("timeout"));
    assert_eq!(result.retries_used, 2);
}

#[test]
fn add_stage_returns_self_for_chaining() {
    let mut def = PipelineDefinition::new();
    def.add_stage(PipelineStage::new("recon", PhaseType::Source))
        .add_stage(PipelineStage::new("report", PhaseType::Sink));
    assert_eq!(def.stages.len(), 2);
}
