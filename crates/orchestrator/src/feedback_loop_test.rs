use super::*;

fn make_valid_response(hypotheses: usize, confidence: f64) -> String {
    let mut hyps = Vec::new();
    for i in 0..hypotheses {
        hyps.push(format!(
            r#"{{"endpoint": "/api/test{i}", "vulnerability_class": "SQL Injection", "reasoning": "test {i}", "suggested_payloads": ["payload{i}"], "confidence": {confidence}, "priority": 1}}"#
        ));
    }
    format!(
        r#"{{"hypotheses": [{}], "actions": [], "reasoning_summary": "test analysis"}}"#,
        hyps.join(",")
    )
}

fn always_confirm(h: &ParsedHypothesis) -> TestOutcome {
    TestOutcome::Confirmed {
        vulnerability_class: h.vulnerability_class.clone(),
        endpoint: h.endpoint.clone(),
        payload: h.suggested_payloads.first().cloned().unwrap_or_default(),
        severity: 8.0,
    }
}

fn always_refute(h: &ParsedHypothesis) -> TestOutcome {
    TestOutcome::Refuted {
        vulnerability_class: h.vulnerability_class.clone(),
        endpoint: h.endpoint.clone(),
        reason: "not vulnerable".to_string(),
    }
}

fn alternating_outcomes() -> impl FnMut(&ParsedHypothesis) -> TestOutcome {
    let mut counter = 0u32;
    move |h: &ParsedHypothesis| {
        counter += 1;
        if counter % 2 == 0 {
            TestOutcome::Confirmed {
                vulnerability_class: h.vulnerability_class.clone(),
                endpoint: h.endpoint.clone(),
                payload: "test".to_string(),
                severity: 7.0,
            }
        } else {
            TestOutcome::Refuted {
                vulnerability_class: h.vulnerability_class.clone(),
                endpoint: h.endpoint.clone(),
                reason: "not vulnerable".to_string(),
            }
        }
    }
}

#[test]
fn default_config_sane_values() {
    let config = FeedbackLoopConfig::default();
    assert_eq!(config.max_iterations, 5);
    assert_eq!(config.convergence_threshold, 2);
    assert_eq!(config.max_hypotheses_per_round, 20);
    assert!(config.min_confidence_threshold > 0.0);
}

#[test]
fn process_iteration_with_valid_response() {
    let raw = make_valid_response(3, 0.8);
    let config = FeedbackLoopConfig::default();
    let result = process_iteration(1, &raw, &config, always_confirm);

    assert_eq!(result.iteration, 1);
    assert_eq!(result.hypotheses_received, 3);
    assert_eq!(result.hypotheses_tested, 3);
    assert_eq!(result.confirmed, 3);
    assert_eq!(result.refuted, 0);
    assert_eq!(result.partial, 0);
    assert!(result.new_failed_attempts.is_empty());
    assert_eq!(result.parse_method, "direct_json");
}

#[test]
fn process_iteration_refuted_creates_failed_attempts() {
    let raw = make_valid_response(2, 0.7);
    let config = FeedbackLoopConfig::default();
    let result = process_iteration(1, &raw, &config, always_refute);

    assert_eq!(result.confirmed, 0);
    assert_eq!(result.refuted, 2);
    assert_eq!(result.new_failed_attempts.len(), 2);
    assert!(result.new_failed_attempts[0]
        .failure_reason
        .contains("not vulnerable"));
}

#[test]
fn process_iteration_filters_low_confidence() {
    let raw = make_valid_response(3, 0.1); // below default threshold
    let config = FeedbackLoopConfig {
        min_confidence_threshold: 0.5,
        ..FeedbackLoopConfig::default()
    };
    let result = process_iteration(1, &raw, &config, always_confirm);

    assert_eq!(result.hypotheses_received, 3);
    assert_eq!(result.hypotheses_tested, 0); // all filtered
}

#[test]
fn process_iteration_caps_hypotheses() {
    let raw = make_valid_response(10, 0.8);
    let config = FeedbackLoopConfig {
        max_hypotheses_per_round: 3,
        ..FeedbackLoopConfig::default()
    };
    let result = process_iteration(1, &raw, &config, always_confirm);

    assert_eq!(result.hypotheses_received, 10);
    assert_eq!(result.hypotheses_tested, 3);
}

#[test]
fn process_iteration_with_malformed_response() {
    let raw = "This is not JSON at all. Just some text.";
    let config = FeedbackLoopConfig::default();
    let result = process_iteration(1, raw, &config, always_confirm);

    assert_eq!(result.hypotheses_received, 0);
    assert_eq!(result.hypotheses_tested, 0);
    assert_eq!(result.parse_method, "text_fallback");
}

#[test]
fn process_iteration_with_partial_outcomes() {
    let raw = make_valid_response(2, 0.8);
    let config = FeedbackLoopConfig::default();

    let result = process_iteration(1, &raw, &config, |h| TestOutcome::Partial {
        vulnerability_class: h.vulnerability_class.clone(),
        endpoint: h.endpoint.clone(),
        detail: "needs more testing".to_string(),
        needs_further_testing: true,
    });

    assert_eq!(result.partial, 2);
    assert_eq!(result.confirmed, 0);
    assert_eq!(result.refuted, 0);
    // needs_further_testing = true → not added to failed attempts
    assert!(result.new_failed_attempts.is_empty());
}

#[test]
fn prepare_hypotheses_sorts_by_priority_then_confidence() {
    let response = ParsedResponse {
        hypotheses: vec![
            ParsedHypothesis {
                endpoint: "/low".to_string(),
                vulnerability_class: "XSS".to_string(),
                reasoning: "test".to_string(),
                suggested_payloads: vec![],
                confidence: 0.9,
                priority: 3,
            },
            ParsedHypothesis {
                endpoint: "/high".to_string(),
                vulnerability_class: "SQLi".to_string(),
                reasoning: "test".to_string(),
                suggested_payloads: vec![],
                confidence: 0.5,
                priority: 1,
            },
        ],
        actions: vec![],
        reasoning: crate::llm_response_parser::ParsedReasoning {
            summary: String::new(),
            observations: vec![],
            attack_graph_notes: vec![],
        },
        raw_text: String::new(),
        parse_method: ParseMethod::DirectJson,
        tokens_used: None,
    };
    let config = FeedbackLoopConfig::default();
    let prepared = prepare_hypotheses(&response, &config);

    assert_eq!(prepared[0].endpoint, "/high"); // priority 1
    assert_eq!(prepared[1].endpoint, "/low"); // priority 3
}

#[test]
fn check_convergence_not_enough_iterations() {
    let results = vec![IterationResult {
        iteration: 1,
        hypotheses_received: 3,
        hypotheses_tested: 3,
        confirmed: 0,
        refuted: 3,
        partial: 0,
        new_failed_attempts: vec![],
        parse_method: "direct_json".to_string(),
        duration_ms: 100,
    }];
    assert!(check_convergence(&results, 2).is_none());
}

#[test]
fn check_convergence_detects_stall() {
    let results = vec![
        IterationResult {
            iteration: 1,
            hypotheses_received: 5,
            hypotheses_tested: 5,
            confirmed: 0,
            refuted: 5,
            partial: 0,
            new_failed_attempts: vec![],
            parse_method: "direct_json".to_string(),
            duration_ms: 100,
        },
        IterationResult {
            iteration: 2,
            hypotheses_received: 3,
            hypotheses_tested: 3,
            confirmed: 0,
            refuted: 3,
            partial: 0,
            new_failed_attempts: vec![],
            parse_method: "direct_json".to_string(),
            duration_ms: 100,
        },
    ];
    let reason = check_convergence(&results, 2);
    assert!(reason.is_some());
    assert!(reason.unwrap().contains("zero confirmed"));
}

#[test]
fn check_convergence_not_triggered_with_findings() {
    let results = vec![
        IterationResult {
            iteration: 1,
            hypotheses_received: 3,
            hypotheses_tested: 3,
            confirmed: 1,
            refuted: 2,
            partial: 0,
            new_failed_attempts: vec![],
            parse_method: "direct_json".to_string(),
            duration_ms: 100,
        },
        IterationResult {
            iteration: 2,
            hypotheses_received: 3,
            hypotheses_tested: 3,
            confirmed: 0,
            refuted: 3,
            partial: 0,
            new_failed_attempts: vec![],
            parse_method: "direct_json".to_string(),
            duration_ms: 100,
        },
    ];
    assert!(check_convergence(&results, 2).is_none());
}

#[test]
fn run_feedback_loop_converges() {
    let config = FeedbackLoopConfig {
        max_iterations: 10,
        convergence_threshold: 2,
        ..FeedbackLoopConfig::default()
    };

    let state = run_feedback_loop(
        &config,
        |_, _| Ok(make_valid_response(2, 0.8)),
        always_refute,
    )
    .unwrap();

    assert!(state.converged);
    assert!(state.convergence_reason.is_some());
    assert_eq!(state.total_confirmed, 0);
    assert!(state.total_refuted > 0);
    // Should converge after 2 iterations (threshold=2, all refuted)
    assert_eq!(state.iterations_completed(), 2);
}

#[test]
fn run_feedback_loop_hits_max_iterations() {
    let config = FeedbackLoopConfig {
        max_iterations: 3,
        convergence_threshold: 10, // won't converge
        ..FeedbackLoopConfig::default()
    };

    let state = run_feedback_loop(
        &config,
        |_, _| Ok(make_valid_response(1, 0.8)),
        always_confirm,
    )
    .unwrap();

    assert!(!state.converged);
    assert_eq!(state.iterations_completed(), 3);
    assert!(state
        .convergence_reason
        .as_ref()
        .unwrap()
        .contains("max iterations"));
}

#[test]
fn run_feedback_loop_accumulates_failed_attempts() {
    let config = FeedbackLoopConfig {
        max_iterations: 3,
        convergence_threshold: 5,
        ..FeedbackLoopConfig::default()
    };

    let state = run_feedback_loop(
        &config,
        |_, _| Ok(make_valid_response(2, 0.8)),
        always_refute,
    )
    .unwrap();

    // 3 iterations × 2 hypotheses × all refuted = 6 failed attempts
    // (but convergence might kick in before 3 iterations)
    assert!(!state.failed_attempts.is_empty());
}

#[test]
fn run_feedback_loop_brain_failure() {
    let config = FeedbackLoopConfig::default();

    let result = run_feedback_loop(
        &config,
        |_, _| Err("brain offline".to_string()),
        always_confirm,
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        FeedbackLoopError::BrainInvocationFailed(msg) => {
            assert!(msg.contains("brain offline"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn run_feedback_loop_with_alternating_outcomes() {
    let config = FeedbackLoopConfig {
        max_iterations: 3,
        convergence_threshold: 10,
        ..FeedbackLoopConfig::default()
    };

    let state = run_feedback_loop(
        &config,
        |_, _| Ok(make_valid_response(4, 0.8)),
        alternating_outcomes(),
    )
    .unwrap();

    assert!(state.total_confirmed > 0);
    assert!(state.total_refuted > 0);
    assert_eq!(state.iterations_completed(), 3);
}

#[test]
fn test_outcome_accessors() {
    let confirmed = TestOutcome::Confirmed {
        vulnerability_class: "XSS".to_string(),
        endpoint: "/api".to_string(),
        payload: "test".to_string(),
        severity: 7.0,
    };
    assert!(confirmed.is_confirmed());
    assert!(!confirmed.is_refuted());
    assert_eq!(confirmed.vulnerability_class(), "XSS");
    assert_eq!(confirmed.endpoint(), "/api");

    let refuted = TestOutcome::Refuted {
        vulnerability_class: "SQLi".to_string(),
        endpoint: "/login".to_string(),
        reason: "nope".to_string(),
    };
    assert!(!refuted.is_confirmed());
    assert!(refuted.is_refuted());
}

#[test]
fn feedback_loop_state_accessors() {
    let mut state = FeedbackLoopState::new();
    assert_eq!(state.total_tested(), 0);
    assert_eq!(state.iterations_completed(), 0);

    state.iteration_results.push(IterationResult {
        iteration: 1,
        hypotheses_received: 5,
        hypotheses_tested: 3,
        confirmed: 1,
        refuted: 2,
        partial: 0,
        new_failed_attempts: vec![],
        parse_method: "direct_json".to_string(),
        duration_ms: 100,
    });

    assert_eq!(state.total_tested(), 3);
    assert_eq!(state.iterations_completed(), 1);
}

#[test]
fn feedback_loop_error_display() {
    let err = FeedbackLoopError::BrainInvocationFailed("timeout".to_string());
    assert!(err.to_string().contains("timeout"));

    let err = FeedbackLoopError::MaxIterationsExceeded(5);
    assert!(err.to_string().contains("5"));

    let err = FeedbackLoopError::NoHypothesesGenerated(3);
    assert!(err.to_string().contains("3"));
}

#[test]
fn outcome_to_failed_attempt_for_refuted() {
    let outcome = TestOutcome::Refuted {
        vulnerability_class: "XSS".to_string(),
        endpoint: "/test".to_string(),
        reason: "filtered".to_string(),
    };
    let failed = outcome_to_failed_attempt(&outcome).unwrap();
    assert_eq!(failed.vulnerability_class, "XSS");
    assert_eq!(failed.failure_reason, "filtered");
}

#[test]
fn outcome_to_failed_attempt_confirmed_is_none() {
    let outcome = TestOutcome::Confirmed {
        vulnerability_class: "XSS".to_string(),
        endpoint: "/test".to_string(),
        payload: "test".to_string(),
        severity: 5.0,
    };
    assert!(outcome_to_failed_attempt(&outcome).is_none());
}

#[test]
fn outcome_to_failed_attempt_partial_needs_testing_is_none() {
    let outcome = TestOutcome::Partial {
        vulnerability_class: "SSRF".to_string(),
        endpoint: "/api".to_string(),
        detail: "partial".to_string(),
        needs_further_testing: true,
    };
    assert!(outcome_to_failed_attempt(&outcome).is_none());
}

#[test]
fn outcome_to_failed_attempt_partial_no_further_testing() {
    let outcome = TestOutcome::Partial {
        vulnerability_class: "SSRF".to_string(),
        endpoint: "/api".to_string(),
        detail: "dead end".to_string(),
        needs_further_testing: false,
    };
    let failed = outcome_to_failed_attempt(&outcome).unwrap();
    assert!(failed.failure_reason.contains("partial"));
}

#[test]
fn iteration_result_serde_roundtrip() {
    let result = IterationResult {
        iteration: 1,
        hypotheses_received: 5,
        hypotheses_tested: 3,
        confirmed: 1,
        refuted: 2,
        partial: 0,
        new_failed_attempts: vec![],
        parse_method: "direct_json".to_string(),
        duration_ms: 100,
    };
    let json = serde_json::to_string(&result).unwrap();
    let parsed: IterationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.confirmed, 1);
    assert_eq!(parsed.iteration, 1);
}

#[test]
fn run_feedback_loop_passes_failed_attempts_to_brain() {
    let config = FeedbackLoopConfig {
        max_iterations: 2,
        convergence_threshold: 10,
        ..FeedbackLoopConfig::default()
    };

    let mut seen_failed_counts = Vec::new();

    let state = run_feedback_loop(
        &config,
        |iter, failed| {
            seen_failed_counts.push((iter, failed.len()));
            Ok(make_valid_response(1, 0.8))
        },
        always_refute,
    )
    .unwrap();

    // Iteration 1: 0 failed attempts passed
    // Iteration 2: 1 failed attempt passed (from iter 1)
    assert_eq!(seen_failed_counts.len(), 2);
    assert_eq!(seen_failed_counts[0], (1, 0));
    assert_eq!(seen_failed_counts[1], (2, 1));
    assert_eq!(state.failed_attempts.len(), 2);
}
