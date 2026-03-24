use super::*;

fn sample_observation() -> AgentObservation {
    AgentObservation {
        target_url: "http://127.0.0.1:3000".to_string(),
        tech_stack: vec!["Express".to_string(), "Node.js".to_string()],
        endpoints: vec![
            EndpointObservation {
                url: "http://127.0.0.1:3000/api/users".to_string(),
                method: "GET".to_string(),
                parameters: vec!["id".to_string()],
                response_code: Some(200),
                content_type: Some("application/json".to_string()),
                auth_required: false,
                fuzz_attempts: 0,
                vulnerability_classes_tested: vec![],
            },
            EndpointObservation {
                url: "http://127.0.0.1:3000/api/admin".to_string(),
                method: "POST".to_string(),
                parameters: vec!["action".to_string()],
                response_code: Some(403),
                content_type: Some("application/json".to_string()),
                auth_required: true,
                fuzz_attempts: 1,
                vulnerability_classes_tested: vec!["SQLi".to_string()],
            },
        ],
        findings: vec![FindingObservation {
            finding_id: 1,
            vulnerability_class: "XSS".to_string(),
            endpoint: "http://127.0.0.1:3000/api/search".to_string(),
            confidence: 0.85,
            evidence_level: "Controlled".to_string(),
            exploitable: true,
            chained_with: vec![],
        }],
        defense_profile: DefenseObservation {
            has_waf: true,
            waf_vendor: Some("ModSecurity".to_string()),
            blocked_categories: vec!["XSS".to_string()],
            rate_limit_rps: Some(10.0),
            bot_detection_present: false,
            bot_detection_evaded: false,
            csp_present: true,
            cors_misconfigured: false,
        },
        failed_attempts: vec![FailedAttempt {
            endpoint: "http://127.0.0.1:3000/api/search".to_string(),
            vulnerability_class: "XSS".to_string(),
            payload_type: "script_tag".to_string(),
            failure_reason: FailureReason::WafBlocked,
            iteration: 0,
        }],
        iteration: 1,
        total_requests_sent: 150,
        scan_duration_ms: 30000,
    }
}

#[test]
fn agent_loop_state_starts_at_observe() {
    let state = AgentLoopState::new(AgentConfig::default());
    assert_eq!(state.phase, AgentPhase::Observe);
    assert_eq!(state.iteration, 0);
}

#[test]
fn agent_phase_advances_through_ohpel_cycle() {
    let mut state = AgentLoopState::new(AgentConfig::default());
    assert_eq!(state.phase, AgentPhase::Observe);

    state.advance_phase();
    assert_eq!(state.phase, AgentPhase::Hypothesize);

    state.advance_phase();
    assert_eq!(state.phase, AgentPhase::Plan);

    state.advance_phase();
    assert_eq!(state.phase, AgentPhase::Execute);

    state.advance_phase();
    assert_eq!(state.phase, AgentPhase::Learn);
}

#[test]
fn learn_phase_advances_to_observe_and_increments_iteration() {
    let mut state = AgentLoopState::new(AgentConfig::default());
    // cycle through O-H-P-E-L
    for _ in 0..5 {
        state.advance_phase();
    }
    assert_eq!(state.phase, AgentPhase::Observe);
    assert_eq!(state.iteration, 1);
}

#[test]
fn converges_after_max_iterations() {
    let config = AgentConfig {
        max_iterations: 2,
        ..Default::default()
    };
    let mut state = AgentLoopState::new(config);

    // Two full cycles
    for _ in 0..10 {
        state.advance_phase();
    }
    assert_eq!(state.phase, AgentPhase::Converged);
    assert_eq!(state.iteration, 2);
}

#[test]
fn converges_when_stuck() {
    let config = AgentConfig {
        convergence_threshold: 2,
        max_iterations: 100,
        ..Default::default()
    };
    let mut state = AgentLoopState::new(config);

    // Record two dry iterations
    state.memory.record_iteration(IterationSummary {
        iteration: 0,
        actions_taken: 5,
        new_findings: 0,
        new_endpoints: 0,
        waf_blocks_encountered: 0,
        most_productive_action: None,
        duration_ms: 1000,
    });
    state.memory.record_iteration(IterationSummary {
        iteration: 1,
        actions_taken: 5,
        new_findings: 0,
        new_endpoints: 0,
        waf_blocks_encountered: 0,
        most_productive_action: None,
        duration_ms: 1000,
    });

    // Complete a full OHPEL cycle
    for _ in 0..5 {
        state.advance_phase();
    }
    assert_eq!(state.phase, AgentPhase::Converged);
}

#[test]
fn does_not_converge_when_finding_things() {
    let config = AgentConfig {
        convergence_threshold: 2,
        max_iterations: 100,
        ..Default::default()
    };
    let mut state = AgentLoopState::new(config);

    state.memory.record_iteration(IterationSummary {
        iteration: 0,
        actions_taken: 5,
        new_findings: 3,
        new_endpoints: 1,
        waf_blocks_encountered: 0,
        most_productive_action: Some("fuzz /api/users".to_string()),
        duration_ms: 1000,
    });
    state.memory.record_iteration(IterationSummary {
        iteration: 1,
        actions_taken: 5,
        new_findings: 0,
        new_endpoints: 0,
        waf_blocks_encountered: 0,
        most_productive_action: None,
        duration_ms: 1000,
    });

    for _ in 0..5 {
        state.advance_phase();
    }
    assert_eq!(state.phase, AgentPhase::Observe); // should continue
}

#[test]
fn effectiveness_starts_at_zero() {
    let state = AgentLoopState::new(AgentConfig::default());
    assert_eq!(state.effectiveness(), 0.0);
}

#[test]
fn effectiveness_tracks_confirmation_rate() {
    let mut state = AgentLoopState::new(AgentConfig::default());
    state.memory.hypotheses_generated = 10;
    state.memory.hypotheses_confirmed = 3;
    state.memory.total_actions_taken = 10;
    assert!((state.effectiveness() - 0.3).abs() < 0.01);
}

#[test]
fn memory_success_rate_returns_half_with_no_data() {
    let memory = AgentMemory::default();
    assert_eq!(memory.success_rate_for_class("XSS"), 0.5);
}

#[test]
fn memory_success_rate_tracks_correctly() {
    let mut memory = AgentMemory::default();
    memory.record_success(TechniqueRecord {
        vulnerability_class: "XSS".to_string(),
        endpoint: "/api".to_string(),
        payload_type: "script".to_string(),
        evasion_used: None,
        iteration: 0,
    });
    memory.record_failure(TechniqueRecord {
        vulnerability_class: "XSS".to_string(),
        endpoint: "/api/v2".to_string(),
        payload_type: "img_onerror".to_string(),
        evasion_used: None,
        iteration: 0,
    });
    assert_eq!(memory.success_rate_for_class("XSS"), 0.5);
    assert_eq!(memory.success_rate_for_class("SQLi"), 0.5);
}

#[test]
fn memory_is_stuck_detection() {
    let mut memory = AgentMemory::default();
    assert!(!memory.is_stuck(2));

    memory.record_iteration(IterationSummary {
        iteration: 0,
        actions_taken: 5,
        new_findings: 0,
        new_endpoints: 0,
        waf_blocks_encountered: 0,
        most_productive_action: None,
        duration_ms: 1000,
    });
    assert!(!memory.is_stuck(2)); // only 1 dry iteration

    memory.record_iteration(IterationSummary {
        iteration: 1,
        actions_taken: 5,
        new_findings: 0,
        new_endpoints: 0,
        waf_blocks_encountered: 0,
        most_productive_action: None,
        duration_ms: 1000,
    });
    assert!(memory.is_stuck(2));
}

#[test]
fn memory_bypasses_for_defense() {
    let mut memory = AgentMemory::default();
    memory.record_waf_bypass(WafBypassRecord {
        defense_type: "waf".to_string(),
        bypass_technique: "double_encoding".to_string(),
        payload_mutation: "encoded".to_string(),
        successful: true,
        iteration: 0,
    });
    memory.record_waf_bypass(WafBypassRecord {
        defense_type: "waf".to_string(),
        bypass_technique: "unicode".to_string(),
        payload_mutation: "normalized".to_string(),
        successful: false,
        iteration: 0,
    });

    let bypasses = memory.bypasses_for_defense("waf");
    assert_eq!(bypasses.len(), 1);
    assert_eq!(bypasses[0].bypass_technique, "double_encoding");
}

#[test]
fn build_hypothesis_prompt_contains_xml_structure() {
    let mut state = AgentLoopState::new(AgentConfig::default());
    state.current_observation = Some(sample_observation());

    let prompt = state.build_hypothesis_prompt();
    assert!(prompt.contains("<role>"));
    assert!(prompt.contains("<task>"));
    assert!(prompt.contains("<scan_context>"));
    assert!(prompt.contains("<agent_memory>"));
    assert!(prompt.contains("<constraints>"));
    assert!(prompt.contains("<output_format>"));
}

#[test]
fn build_hypothesis_prompt_includes_observation_data() {
    let mut state = AgentLoopState::new(AgentConfig::default());
    state.current_observation = Some(sample_observation());

    let prompt = state.build_hypothesis_prompt();
    assert!(prompt.contains("127.0.0.1:3000"));
    assert!(prompt.contains("Express"));
    assert!(prompt.contains("/api/users"));
}

#[test]
fn fallback_plan_generates_actions_for_untested_endpoints() {
    let obs = sample_observation();
    let memory = AgentMemory::default();

    let plan = build_fallback_plan(&obs, &memory);
    assert!(!plan.actions.is_empty());
    assert!(plan.confidence > 0.0);

    let fuzz_actions: Vec<_> = plan
        .actions
        .iter()
        .filter(|a| matches!(a.action, AgentAction::FuzzEndpoint { .. }))
        .collect();
    assert!(!fuzz_actions.is_empty());
}

#[test]
fn fallback_plan_includes_waf_bypass_when_blocked() {
    let obs = sample_observation();
    let memory = AgentMemory::default();

    let plan = build_fallback_plan(&obs, &memory);

    let has_aggressive = plan.actions.iter().any(|a| {
        if let AgentAction::FuzzEndpoint { evasion_level, .. } = &a.action {
            *evasion_level == EvasionLevel::Aggressive
        } else {
            false
        }
    });
    assert!(
        has_aggressive,
        "should have aggressive evasion for WAF bypass"
    );
}

#[test]
fn fallback_plan_includes_discovery_when_few_endpoints() {
    let obs = sample_observation();
    let memory = AgentMemory::default();

    let plan = build_fallback_plan(&obs, &memory);

    let has_discovery = plan
        .actions
        .iter()
        .any(|a| matches!(a.action, AgentAction::DiscoverEndpoints { .. }));
    assert!(has_discovery, "should discover more endpoints when < 10");
}

#[test]
fn record_results_updates_memory() {
    let mut state = AgentLoopState::new(AgentConfig::default());

    let results = vec![ActionResult {
        action_index: 0,
        success: true,
        new_findings: vec![FindingObservation {
            finding_id: 42,
            vulnerability_class: "SQLi".to_string(),
            endpoint: "/api/users".to_string(),
            confidence: 0.9,
            evidence_level: "Confirmed".to_string(),
            exploitable: true,
            chained_with: vec![],
        }],
        new_endpoints: vec!["/api/admin/debug".to_string()],
        defense_changes: vec![],
        execution_time_ms: 500,
        notes: "found SQL injection".to_string(),
    }];

    state.record_results(results);

    assert_eq!(state.memory.iteration_summaries.len(), 1);
    assert_eq!(state.memory.iteration_summaries[0].new_findings, 1);
    assert_eq!(state.memory.iteration_summaries[0].new_endpoints, 1);
    assert_eq!(state.memory.hypotheses_confirmed, 1);
    assert_eq!(state.memory.total_actions_taken, 1);
}

#[test]
fn failure_reason_display() {
    assert_eq!(FailureReason::WafBlocked.to_string(), "WAF blocked");
    assert_eq!(FailureReason::RateLimited.to_string(), "rate limited");
    assert_eq!(FailureReason::NotVulnerable.to_string(), "not vulnerable");
    assert_eq!(
        FailureReason::AuthRequired.to_string(),
        "authentication required"
    );
}

#[test]
fn evasion_level_display() {
    assert_eq!(EvasionLevel::None.to_string(), "none");
    assert_eq!(EvasionLevel::Paranoid.to_string(), "paranoid");
}

#[test]
fn agent_phase_display() {
    assert_eq!(AgentPhase::Observe.to_string(), "observe");
    assert_eq!(AgentPhase::Hypothesize.to_string(), "hypothesize");
    assert_eq!(AgentPhase::Plan.to_string(), "plan");
    assert_eq!(AgentPhase::Execute.to_string(), "execute");
    assert_eq!(AgentPhase::Learn.to_string(), "learn");
    assert_eq!(AgentPhase::Converged.to_string(), "converged");
}

#[test]
fn agent_config_default_is_reasonable() {
    let config = AgentConfig::default();
    assert_eq!(config.max_iterations, 10);
    assert_eq!(config.convergence_threshold, 3);
    assert_eq!(config.max_actions_per_iteration, 20);
    assert_eq!(config.evasion_level, EvasionLevel::Moderate);
    assert!(config.use_llm);
    assert_eq!(config.llm_backend, "bedrock");
}

#[test]
fn memory_most_productive_iteration() {
    let mut memory = AgentMemory::default();

    memory.record_iteration(IterationSummary {
        iteration: 0,
        actions_taken: 5,
        new_findings: 2,
        new_endpoints: 0,
        waf_blocks_encountered: 0,
        most_productive_action: None,
        duration_ms: 1000,
    });
    memory.record_iteration(IterationSummary {
        iteration: 1,
        actions_taken: 3,
        new_findings: 7,
        new_endpoints: 2,
        waf_blocks_encountered: 0,
        most_productive_action: Some("fuzz /admin".to_string()),
        duration_ms: 2000,
    });

    let best = memory.most_productive_iteration().unwrap();
    assert_eq!(best.iteration, 1);
    assert_eq!(best.new_findings, 7);
}

#[test]
fn converged_and_stopped_phases_are_terminal() {
    let mut state = AgentLoopState::new(AgentConfig::default());

    state.phase = AgentPhase::Converged;
    state.advance_phase();
    assert_eq!(state.phase, AgentPhase::Converged);

    state.phase = AgentPhase::Stopped;
    state.advance_phase();
    assert_eq!(state.phase, AgentPhase::Stopped);
}

#[test]
fn observation_context_returns_none_without_observation() {
    let state = AgentLoopState::new(AgentConfig::default());
    assert!(state.observation_context().is_none());
}

#[test]
fn observation_context_returns_json_with_observation() {
    let mut state = AgentLoopState::new(AgentConfig::default());
    state.current_observation = Some(sample_observation());
    let ctx = state.observation_context().unwrap();
    assert!(ctx.contains("target_url"));
    assert!(ctx.contains("127.0.0.1"));
}

#[test]
fn discovery_technique_display() {
    assert_eq!(
        DiscoveryTechnique::DirectoryBruteForce.to_string(),
        "directory brute-force"
    );
    assert_eq!(
        DiscoveryTechnique::ApiSchemaInference.to_string(),
        "API schema inference"
    );
}

#[test]
fn analysis_type_display() {
    assert_eq!(AnalysisType::TimingOracle.to_string(), "timing oracle");
    assert_eq!(
        AnalysisType::RaceConditionProbe.to_string(),
        "race condition probe"
    );
}
