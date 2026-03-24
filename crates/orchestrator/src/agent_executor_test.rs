use super::*;
use crate::agent_loop::{
    AgentAction, AgentConfig, AgentLoopState, AgentMemory, AgentPhase, AnalysisType, AuthMethod,
    DiscoveryTechnique, EndpointBehavior, EvasionLevel, FindingObservation, IterationSummary,
    PayloadStrategy, WafBypassRecord,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn test_config() -> AgentConfig {
    AgentConfig {
        max_iterations: 5,
        convergence_threshold: 2,
        max_actions_per_iteration: 10,
        evasion_level: EvasionLevel::Moderate,
        use_llm: false,
        llm_backend: "stub".to_string(),
        max_concurrent_actions: 3,
        pause_between_iterations_ms: 0,
    }
}

/// Handler that always fails.
struct FailingHandler;

impl ActionHandler for FailingHandler {
    fn handle(&self, action: &AgentAction) -> DispatchOutcome {
        DispatchOutcome {
            action_type: action_type_tag(action).to_string(),
            success: false,
            findings: vec![],
            discovered_endpoints: vec![],
            defense_observations: vec![],
            execution_ms: 10,
            detail: "intentional failure".to_string(),
        }
    }
    fn name(&self) -> &str {
        "failing"
    }
}

/// Handler that produces exactly one finding per fuzz action.
struct SingleFindingHandler;

impl ActionHandler for SingleFindingHandler {
    fn handle(&self, action: &AgentAction) -> DispatchOutcome {
        let tag = action_type_tag(action);
        match action {
            AgentAction::FuzzEndpoint { endpoint, .. } => DispatchOutcome {
                action_type: tag.to_string(),
                success: true,
                findings: vec![FindingObservation {
                    finding_id: 42,
                    vulnerability_class: "XSS".to_string(),
                    endpoint: endpoint.clone(),
                    confidence: 0.9,
                    evidence_level: "Confirmed".to_string(),
                    exploitable: true,
                    chained_with: vec![],
                }],
                discovered_endpoints: vec![],
                defense_observations: vec![],
                execution_ms: 100,
                detail: format!("single finding on {endpoint}"),
            },
            _ => StubActionHandler.handle(action),
        }
    }
    fn name(&self) -> &str {
        "single_finding"
    }
}

// ── 1. action_type_tag covers all variants ───────────────────────────────────

#[test]
fn action_type_tag_fuzz_endpoint() {
    let action = AgentAction::FuzzEndpoint {
        endpoint: "http://localhost/test".to_string(),
        method: "GET".to_string(),
        vulnerability_classes: vec!["XSS".to_string()],
        evasion_level: EvasionLevel::None,
        payload_strategy: PayloadStrategy::Standard,
    };
    assert_eq!(action_type_tag(&action), "fuzz_endpoint");
}

#[test]
fn action_type_tag_exploit_finding() {
    let action = AgentAction::ExploitFinding {
        finding_id: 1,
        tool: "sqlmap".to_string(),
        custom_args: vec![],
    };
    assert_eq!(action_type_tag(&action), "exploit_finding");
}

#[test]
fn action_type_tag_discover_endpoints() {
    let action = AgentAction::DiscoverEndpoints {
        technique: DiscoveryTechnique::DirectoryBruteForce,
        scope: "http://localhost".to_string(),
    };
    assert_eq!(action_type_tag(&action), "discover_endpoints");
}

#[test]
fn action_type_tag_chain_findings() {
    let action = AgentAction::ChainFindings {
        finding_ids: vec![1, 2],
        chain_hypothesis: "test".to_string(),
    };
    assert_eq!(action_type_tag(&action), "chain_findings");
}

#[test]
fn action_type_tag_authenticate() {
    let action = AgentAction::AuthenticateFirst {
        auth_endpoint: "/login".to_string(),
        auth_method: AuthMethod::BearerToken,
    };
    assert_eq!(action_type_tag(&action), "authenticate");
}

#[test]
fn action_type_tag_evade_defense() {
    let action = AgentAction::EvadeDefense {
        defense_type: "waf".to_string(),
        evasion_technique: "encoding_chain".to_string(),
    };
    assert_eq!(action_type_tag(&action), "evade_defense");
}

#[test]
fn action_type_tag_deep_analyze() {
    let action = AgentAction::DeepAnalyze {
        endpoint: "/api".to_string(),
        analysis_type: AnalysisType::TimingOracle,
    };
    assert_eq!(action_type_tag(&action), "deep_analyze");
}

#[test]
fn action_type_tag_generate_report() {
    let action = AgentAction::GenerateReport {
        format: "developer".to_string(),
    };
    assert_eq!(action_type_tag(&action), "generate_report");
}

#[test]
fn action_type_tag_pause() {
    let action = AgentAction::Pause {
        reason: "cooldown".to_string(),
        resume_after_ms: 5000,
    };
    assert_eq!(action_type_tag(&action), "pause");
}

// ── 2. StubActionHandler dispatches all 9 action types ───────────────────────

#[test]
fn stub_handler_fuzz_returns_finding() {
    let handler = StubActionHandler;
    let action = AgentAction::FuzzEndpoint {
        endpoint: "http://localhost/search".to_string(),
        method: "GET".to_string(),
        vulnerability_classes: vec!["SQLi".to_string()],
        evasion_level: EvasionLevel::Light,
        payload_strategy: PayloadStrategy::Standard,
    };
    let outcome = handler.handle(&action);
    assert!(outcome.success);
    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(outcome.findings[0].vulnerability_class, "SQLi");
}

#[test]
fn stub_handler_discover_returns_endpoints() {
    let handler = StubActionHandler;
    let action = AgentAction::DiscoverEndpoints {
        technique: DiscoveryTechnique::JavaScriptExtraction,
        scope: "http://localhost".to_string(),
    };
    let outcome = handler.handle(&action);
    assert!(outcome.success);
    assert_eq!(outcome.discovered_endpoints.len(), 2);
}

#[test]
fn stub_handler_chain_returns_chain_finding() {
    let handler = StubActionHandler;
    let action = AgentAction::ChainFindings {
        finding_ids: vec![1, 2, 3],
        chain_hypothesis: "SSRF to RCE".to_string(),
    };
    let outcome = handler.handle(&action);
    assert!(outcome.success);
    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(outcome.findings[0].vulnerability_class, "AttackChain");
    assert_eq!(outcome.findings[0].chained_with, vec![1, 2, 3]);
}

#[test]
fn stub_handler_evade_reports_defense_observation() {
    let handler = StubActionHandler;
    let action = AgentAction::EvadeDefense {
        defense_type: "waf".to_string(),
        evasion_technique: "unicode_normalization".to_string(),
    };
    let outcome = handler.handle(&action);
    assert!(outcome.success);
    assert!(!outcome.defense_observations.is_empty());
}

#[test]
fn stub_handler_authenticate_succeeds() {
    let handler = StubActionHandler;
    let action = AgentAction::AuthenticateFirst {
        auth_endpoint: "/login".to_string(),
        auth_method: AuthMethod::Cookie,
    };
    let outcome = handler.handle(&action);
    assert!(outcome.success);
    assert!(outcome.detail.contains("/login"));
}

#[test]
fn stub_handler_deep_analyze_returns_finding() {
    let handler = StubActionHandler;
    let action = AgentAction::DeepAnalyze {
        endpoint: "/api/transfer".to_string(),
        analysis_type: AnalysisType::RaceConditionProbe,
    };
    let outcome = handler.handle(&action);
    assert!(outcome.success);
    assert_eq!(outcome.findings.len(), 1);
}

// ── 3. execute_action converts outcome to ActionResult ───────────────────────

#[test]
fn execute_action_converts_correctly() {
    let handler = StubActionHandler;
    let action = AgentAction::GenerateReport {
        format: "executive".to_string(),
    };
    let result = execute_action(&handler, &action, 7);
    assert_eq!(result.action_index, 7);
    assert!(result.success);
    assert!(result.notes.contains("executive"));
}

// ── 4. execute_batch processes multiple actions ──────────────────────────────

#[test]
fn execute_batch_processes_all_actions() {
    let handler = StubActionHandler;
    let actions = vec![
        AgentAction::FuzzEndpoint {
            endpoint: "/a".to_string(),
            method: "GET".to_string(),
            vulnerability_classes: vec!["XSS".to_string()],
            evasion_level: EvasionLevel::None,
            payload_strategy: PayloadStrategy::Standard,
        },
        AgentAction::FuzzEndpoint {
            endpoint: "/b".to_string(),
            method: "POST".to_string(),
            vulnerability_classes: vec!["SQLi".to_string()],
            evasion_level: EvasionLevel::Aggressive,
            payload_strategy: PayloadStrategy::WafBypass,
        },
        AgentAction::DiscoverEndpoints {
            technique: DiscoveryTechnique::SitemapCrawl,
            scope: "http://localhost".to_string(),
        },
    ];
    let results = execute_batch(&handler, &actions);
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].action_index, 0);
    assert_eq!(results[1].action_index, 1);
    assert_eq!(results[2].action_index, 2);
}

// ── 5. execute_batch_concurrent respects chunk size ──────────────────────────

#[test]
fn execute_batch_concurrent_chunks_correctly() {
    let handler = StubActionHandler;
    let actions: Vec<AgentAction> = (0..7)
        .map(|i| AgentAction::FuzzEndpoint {
            endpoint: format!("/ep{i}"),
            method: "GET".to_string(),
            vulnerability_classes: vec!["XSS".to_string()],
            evasion_level: EvasionLevel::None,
            payload_strategy: PayloadStrategy::Standard,
        })
        .collect();
    let results = execute_batch_concurrent(&handler, &actions, 3);
    assert_eq!(results.len(), 7);
    for (i, r) in results.iter().enumerate() {
        assert_eq!(r.action_index, i);
    }
}

#[test]
fn execute_batch_concurrent_single_action_no_threading() {
    let handler = StubActionHandler;
    let actions = vec![AgentAction::Pause {
        reason: "test".to_string(),
        resume_after_ms: 0,
    }];
    let results = execute_batch_concurrent(&handler, &actions, 5);
    assert_eq!(results.len(), 1);
}

// ── 6. InMemoryMemoryStore CRUD ──────────────────────────────────────────────

#[test]
fn memory_store_save_and_load() {
    let store = InMemoryMemoryStore::new();
    let mut memory = AgentMemory::default();
    memory.hypotheses_generated = 10;
    memory.hypotheses_confirmed = 3;

    store
        .save("http://target.test", &memory)
        .expect("save failed");
    let loaded = store
        .load("http://target.test")
        .expect("load failed")
        .expect("not found");
    assert_eq!(loaded.hypotheses_generated, 10);
    assert_eq!(loaded.hypotheses_confirmed, 3);
}

#[test]
fn memory_store_load_nonexistent_returns_none() {
    let store = InMemoryMemoryStore::new();
    let result = store.load("http://nothing.test").expect("load failed");
    assert!(result.is_none());
}

#[test]
fn memory_store_list_and_delete() {
    let store = InMemoryMemoryStore::new();
    let memory = AgentMemory::default();
    store.save("target-a", &memory).unwrap();
    store.save("target-b", &memory).unwrap();

    let mut targets = store.list_targets().unwrap();
    targets.sort();
    assert_eq!(targets, vec!["target-a", "target-b"]);

    store.delete("target-a").unwrap();
    let targets = store.list_targets().unwrap();
    assert_eq!(targets.len(), 1);
    assert!(targets.contains(&"target-b".to_string()));
}

// ── 7. build_observation_from_memory ─────────────────────────────────────────

#[test]
fn build_observation_includes_endpoint_behaviors() {
    let mut memory = AgentMemory::default();
    memory.record_endpoint_behavior(
        "http://localhost/api".to_string(),
        EndpointBehavior {
            typical_response_code: 200,
            typical_response_time_ms: 50,
            content_type: "application/json".to_string(),
            parameters_discovered: vec!["id".to_string()],
            auth_type: None,
            response_varies_with_input: true,
            timing_variance_ms: 5.0,
        },
    );
    let obs = build_observation_from_memory("http://localhost", &memory, 3);
    assert_eq!(obs.target_url, "http://localhost");
    assert_eq!(obs.iteration, 3);
    assert_eq!(obs.endpoints.len(), 1);
    assert_eq!(obs.endpoints[0].url, "http://localhost/api");
}

#[test]
fn build_observation_detects_waf_from_bypass_records() {
    let mut memory = AgentMemory::default();
    memory.record_waf_bypass(WafBypassRecord {
        defense_type: "waf".to_string(),
        bypass_technique: "encoding".to_string(),
        payload_mutation: "double-url-encode".to_string(),
        successful: true,
        iteration: 0,
    });
    let obs = build_observation_from_memory("http://localhost", &memory, 0);
    assert!(obs.defense_profile.has_waf);
}

// ── 8. run_agent_cycle: full OHPEL cycle ─────────────────────────────────────

#[test]
fn run_agent_cycle_completes_one_cycle() {
    let mut state = AgentLoopState::new(test_config());
    let handler = StubActionHandler;

    // Seed an endpoint so the fallback planner has something to fuzz
    state.memory.record_endpoint_behavior(
        "http://localhost/search".to_string(),
        EndpointBehavior {
            typical_response_code: 200,
            typical_response_time_ms: 50,
            content_type: "text/html".to_string(),
            parameters_discovered: vec!["q".to_string()],
            auth_type: None,
            response_varies_with_input: true,
            timing_variance_ms: 5.0,
        },
    );

    let result =
        run_agent_cycle(&mut state, &handler, "http://localhost", None).expect("cycle failed");

    assert!(result.actions_dispatched > 0);
    assert!(state.phase == AgentPhase::Observe || state.phase == AgentPhase::Converged);
}

#[test]
fn run_agent_cycle_records_findings_in_memory() {
    let mut state = AgentLoopState::new(test_config());
    let handler = SingleFindingHandler;

    state.memory.record_endpoint_behavior(
        "http://localhost/form".to_string(),
        EndpointBehavior {
            typical_response_code: 200,
            typical_response_time_ms: 30,
            content_type: "text/html".to_string(),
            parameters_discovered: vec!["name".to_string()],
            auth_type: None,
            response_varies_with_input: true,
            timing_variance_ms: 2.0,
        },
    );

    run_agent_cycle(&mut state, &handler, "http://localhost", None).unwrap();
    assert!(!state.memory.successful_techniques.is_empty());
}

// ── 9. run_agent_cycle rejects invalid starting phase ────────────────────────

#[test]
fn run_agent_cycle_rejects_converged_state() {
    let mut state = AgentLoopState::new(test_config());
    state.phase = AgentPhase::Converged;
    let handler = StubActionHandler;

    let err = run_agent_cycle(&mut state, &handler, "http://localhost", None).unwrap_err();
    assert!(
        matches!(err, ExecutorError::ConvergenceReached { .. }),
        "expected ConvergenceReached, got: {err}"
    );
}

#[test]
fn run_agent_cycle_rejects_stopped_state() {
    let mut state = AgentLoopState::new(test_config());
    state.phase = AgentPhase::Stopped;
    let handler = StubActionHandler;

    let err = run_agent_cycle(&mut state, &handler, "http://localhost", None).unwrap_err();
    assert!(matches!(err, ExecutorError::ConvergenceReached { .. }));
}

#[test]
fn run_agent_cycle_rejects_mid_phase_start() {
    let mut state = AgentLoopState::new(test_config());
    state.phase = AgentPhase::Execute;
    let handler = StubActionHandler;

    let err = run_agent_cycle(&mut state, &handler, "http://localhost", None).unwrap_err();
    assert!(matches!(err, ExecutorError::InvalidPhaseTransition { .. }));
}

// ── 10. run_to_completion converges ──────────────────────────────────────────

#[test]
fn run_to_completion_converges_on_empty_target() {
    let config = AgentConfig {
        max_iterations: 5,
        convergence_threshold: 2,
        max_actions_per_iteration: 10,
        evasion_level: EvasionLevel::None,
        use_llm: false,
        llm_backend: "stub".to_string(),
        max_concurrent_actions: 2,
        pause_between_iterations_ms: 0,
    };
    let handler = FailingHandler;
    let (cycles, final_state) = run_to_completion(config, &handler, "http://empty.test", None);

    assert!(!cycles.is_empty());
    assert!(final_state.phase == AgentPhase::Converged || final_state.phase == AgentPhase::Observe);
}

#[test]
fn run_to_completion_with_memory_store_persists() {
    let store = InMemoryMemoryStore::new();
    let config = test_config();
    let handler = StubActionHandler;

    let (cycles, _) = run_to_completion(config, &handler, "http://persist.test", Some(&store));

    assert!(!cycles.is_empty());
    let saved = store
        .load("http://persist.test")
        .unwrap()
        .expect("memory should be persisted");
    assert!(saved.total_actions_taken > 0 || !saved.iteration_summaries.is_empty());
}

// ── 11. detect_convergence ───────────────────────────────────────────────────

#[test]
fn detect_convergence_returns_false_when_not_stuck() {
    let mut memory = AgentMemory::default();
    memory.record_iteration(IterationSummary {
        iteration: 0,
        actions_taken: 5,
        new_findings: 3,
        new_endpoints: 1,
        waf_blocks_encountered: 0,
        most_productive_action: None,
        duration_ms: 100,
    });
    assert!(!detect_convergence(&memory, 2));
}

#[test]
fn detect_convergence_returns_true_when_stuck() {
    let mut memory = AgentMemory::default();
    for i in 0..3 {
        memory.record_iteration(IterationSummary {
            iteration: i,
            actions_taken: 5,
            new_findings: 0,
            new_endpoints: 0,
            waf_blocks_encountered: 0,
            most_productive_action: None,
            duration_ms: 50,
        });
    }
    assert!(detect_convergence(&memory, 3));
}

// ── 12. FailingHandler produces no findings ──────────────────────────────────

#[test]
fn failing_handler_records_failures() {
    let handler = FailingHandler;
    let action = AgentAction::FuzzEndpoint {
        endpoint: "/test".to_string(),
        method: "GET".to_string(),
        vulnerability_classes: vec!["XSS".to_string()],
        evasion_level: EvasionLevel::None,
        payload_strategy: PayloadStrategy::Standard,
    };
    let result = execute_action(&handler, &action, 0);
    assert!(!result.success);
    assert!(result.new_findings.is_empty());
}

// ── 13. extract_action_context ───────────────────────────────────────────────

#[test]
fn extract_context_from_fuzz_action() {
    let action = AgentAction::FuzzEndpoint {
        endpoint: "/api/users".to_string(),
        method: "POST".to_string(),
        vulnerability_classes: vec!["SQLi".to_string(), "XSS".to_string()],
        evasion_level: EvasionLevel::None,
        payload_strategy: PayloadStrategy::Standard,
    };
    let (endpoint, vuln) = extract_action_context(&action);
    assert_eq!(endpoint, "/api/users");
    assert_eq!(vuln, "SQLi");
}

#[test]
fn extract_context_from_exploit_action() {
    let action = AgentAction::ExploitFinding {
        finding_id: 42,
        tool: "nuclei".to_string(),
        custom_args: vec![],
    };
    let (endpoint, tool) = extract_action_context(&action);
    assert_eq!(endpoint, "finding:42");
    assert_eq!(tool, "nuclei");
}

// ── 14. ExecutorError display ────────────────────────────────────────────────

#[test]
fn executor_error_display_handler_not_found() {
    let err = ExecutorError::HandlerNotFound("unknown_tool".to_string());
    let msg = format!("{err}");
    assert!(msg.contains("unknown_tool"));
}

#[test]
fn executor_error_display_convergence() {
    let err = ExecutorError::ConvergenceReached {
        iterations: 5,
        dry_runs: 3,
    };
    let msg = format!("{err}");
    assert!(msg.contains("5"));
    assert!(msg.contains("3"));
}

#[test]
fn executor_error_display_max_iterations() {
    let err = ExecutorError::MaxIterationsReached(10);
    let msg = format!("{err}");
    assert!(msg.contains("10"));
}

#[test]
fn executor_error_display_invalid_phase() {
    let err = ExecutorError::InvalidPhaseTransition {
        from: AgentPhase::Execute,
        attempted: "observe".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("execute"));
    assert!(msg.contains("observe"));
}

// ── 15. Memory store overwrite semantics ─────────────────────────────────────

#[test]
fn memory_store_overwrites_on_same_key() {
    let store = InMemoryMemoryStore::new();
    let mut mem1 = AgentMemory::default();
    mem1.hypotheses_generated = 5;
    store.save("target", &mem1).unwrap();

    let mut mem2 = AgentMemory::default();
    mem2.hypotheses_generated = 99;
    store.save("target", &mem2).unwrap();

    let loaded = store.load("target").unwrap().unwrap();
    assert_eq!(loaded.hypotheses_generated, 99);
}

// ── 16. Cycle result reflects phase after cycle ──────────────────────────────

#[test]
fn cycle_result_converged_flag_matches_state() {
    let mut config = test_config();
    config.max_iterations = 1;
    let mut state = AgentLoopState::new(config);
    let handler = FailingHandler;

    let result = run_agent_cycle(&mut state, &handler, "http://localhost", None).unwrap();

    // After 1 iteration with max_iterations=1, state should converge
    assert!(result.converged || state.phase == AgentPhase::Observe);
}
