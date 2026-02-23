use super::scan_strategy::*;
use std::collections::HashMap;

fn base_state() -> ScanState {
    ScanState {
        target: "http://localhost:3000".to_string(),
        tech_stack: vec!["Express".to_string(), "Node.js".to_string()],
        endpoints_discovered: 20,
        findings_count: 5,
        findings_by_severity: HashMap::from([("high".to_string(), 3), ("medium".to_string(), 2)]),
        phases_completed: vec!["recon".to_string(), "fingerprint".to_string()],
        iterations_remaining: 2,
        defense_profile: "none".to_string(),
        last_iteration_new_findings: true,
        consecutive_zero_finding_rounds: 0,
        exploitation_tools: Vec::new(),
        critical_finding_ids: Vec::new(),
    }
}

#[test]
fn rule1_few_endpoints_triggers_discovery() {
    let mut state = base_state();
    state.endpoints_discovered = 5;

    let action = ScanStrategy::suggest_next_action(&state);
    assert_eq!(
        action,
        StrategyAction::DiscoverMore {
            discovery_type: DiscoveryType::DirectoryBruteForce,
        }
    );
}

#[test]
fn rule1_skipped_when_brute_force_already_done() {
    let mut state = base_state();
    state.endpoints_discovered = 5;
    state
        .phases_completed
        .push("DirectoryBruteForce".to_string());

    let action = ScanStrategy::suggest_next_action(&state);
    assert_ne!(
        action,
        StrategyAction::DiscoverMore {
            discovery_type: DiscoveryType::DirectoryBruteForce,
        }
    );
}

#[test]
fn rule1_skipped_when_enough_endpoints() {
    let mut state = base_state();
    state.endpoints_discovered = 10;

    let action = ScanStrategy::suggest_next_action(&state);
    assert_ne!(
        action,
        StrategyAction::DiscoverMore {
            discovery_type: DiscoveryType::DirectoryBruteForce,
        }
    );
}

#[test]
fn rule2_critical_finding_with_tool_triggers_exploitation() {
    let mut state = base_state();
    state.findings_by_severity.insert("critical".to_string(), 2);
    state.exploitation_tools = vec!["sqlmap".to_string()];
    state.critical_finding_ids = vec![42];

    let action = ScanStrategy::suggest_next_action(&state);
    assert_eq!(
        action,
        StrategyAction::RunExploitation {
            finding_id: 42,
            tool: "sqlmap".to_string(),
        }
    );
}

#[test]
fn rule2_skipped_without_tools() {
    let mut state = base_state();
    state.findings_by_severity.insert("critical".to_string(), 2);
    state.critical_finding_ids = vec![42];

    let action = ScanStrategy::suggest_next_action(&state);
    assert!(
        !matches!(action, StrategyAction::RunExploitation { .. }),
        "should not exploit without available tools"
    );
}

#[test]
fn rule2_skipped_without_critical_findings() {
    let mut state = base_state();
    state.exploitation_tools = vec!["sqlmap".to_string()];

    let action = ScanStrategy::suggest_next_action(&state);
    assert!(
        !matches!(action, StrategyAction::RunExploitation { .. }),
        "should not exploit without critical findings"
    );
}

#[test]
fn rule3_continue_fuzzing_when_productive() {
    let state = base_state();

    let action = ScanStrategy::suggest_next_action(&state);
    assert!(
        matches!(action, StrategyAction::ContinueFuzzing { .. }),
        "expected ContinueFuzzing, got {action:?}"
    );
}

#[test]
fn rule3_focused_on_active_severities() {
    let state = base_state();

    let action = ScanStrategy::suggest_next_action(&state);
    if let StrategyAction::ContinueFuzzing { focus_classes, .. } = action {
        assert!(
            focus_classes.contains(&"high".to_string()),
            "should focus on high severity"
        );
        assert!(
            focus_classes.contains(&"medium".to_string()),
            "should focus on medium severity"
        );
    } else {
        panic!("expected ContinueFuzzing");
    }
}

#[test]
fn rule4_report_when_no_iterations_left() {
    let mut state = base_state();
    state.iterations_remaining = 0;
    state.last_iteration_new_findings = false;

    let action = ScanStrategy::suggest_next_action(&state);
    assert_eq!(action, StrategyAction::GenerateReport);
}

#[test]
fn rule4_report_after_two_dry_rounds() {
    let mut state = base_state();
    state.consecutive_zero_finding_rounds = 2;
    state.last_iteration_new_findings = false;

    let action = ScanStrategy::suggest_next_action(&state);
    assert_eq!(action, StrategyAction::GenerateReport);
}

#[test]
fn rule5_default_continue_fuzzing_all_classes() {
    let mut state = base_state();
    state.iterations_remaining = 3;
    state.last_iteration_new_findings = false;
    state.consecutive_zero_finding_rounds = 1;

    let action = ScanStrategy::suggest_next_action(&state);
    if let StrategyAction::ContinueFuzzing {
        focus_classes,
        focus_endpoints,
    } = action
    {
        assert!(focus_classes.is_empty(), "default should not focus classes");
        assert!(
            focus_endpoints.is_empty(),
            "default should not focus endpoints"
        );
    } else {
        panic!("expected default ContinueFuzzing, got {action:?}");
    }
}

#[test]
fn rule1_takes_priority_over_rule2() {
    let mut state = base_state();
    state.endpoints_discovered = 3;
    state.findings_by_severity.insert("critical".to_string(), 1);
    state.exploitation_tools = vec!["sqlmap".to_string()];
    state.critical_finding_ids = vec![1];

    let action = ScanStrategy::suggest_next_action(&state);
    assert_eq!(
        action,
        StrategyAction::DiscoverMore {
            discovery_type: DiscoveryType::DirectoryBruteForce,
        },
        "discovery should take priority over exploitation"
    );
}

#[test]
fn rule2_takes_priority_over_rule3() {
    let mut state = base_state();
    state.findings_by_severity.insert("critical".to_string(), 1);
    state.exploitation_tools = vec!["nuclei".to_string()];
    state.critical_finding_ids = vec![7];
    state.last_iteration_new_findings = true;

    let action = ScanStrategy::suggest_next_action(&state);
    assert_eq!(
        action,
        StrategyAction::RunExploitation {
            finding_id: 7,
            tool: "nuclei".to_string(),
        },
        "exploitation should take priority over continued fuzzing"
    );
}

#[test]
fn context_contains_required_xml_elements() {
    let state = base_state();
    let context = ScanStrategy::build_strategy_context(&state);

    assert!(context.starts_with("<scan_state>"));
    assert!(context.ends_with("</scan_state>"));
    assert!(context.contains("<target>http://localhost:3000</target>"));
    assert!(context.contains("<technology>Express, Node.js</technology>"));
    assert!(context.contains("<endpoints_discovered>20</endpoints_discovered>"));
    assert!(context.contains("<findings>"));
    assert!(context.contains("</findings>"));
    assert!(context.contains("<defenses>none</defenses>"));
    assert!(context.contains("<iterations_remaining>2</iterations_remaining>"));
}

#[test]
fn context_findings_sorted_by_severity() {
    let mut state = base_state();
    state.findings_by_severity = HashMap::from([
        ("low".to_string(), 1),
        ("critical".to_string(), 5),
        ("high".to_string(), 3),
        ("medium".to_string(), 2),
    ]);

    let context = ScanStrategy::build_strategy_context(&state);
    let critical_pos = context.find("<critical>").expect("critical tag missing");
    let high_pos = context.find("<high>").expect("high tag missing");
    let medium_pos = context.find("<medium>").expect("medium tag missing");
    let low_pos = context.find("<low>").expect("low tag missing");

    assert!(critical_pos < high_pos, "critical should come before high");
    assert!(high_pos < medium_pos, "high should come before medium");
    assert!(medium_pos < low_pos, "medium should come before low");
}

#[test]
fn context_empty_tech_stack() {
    let mut state = base_state();
    state.tech_stack = Vec::new();

    let context = ScanStrategy::build_strategy_context(&state);
    assert!(context.contains("<technology></technology>"));
}

#[test]
fn context_empty_findings() {
    let mut state = base_state();
    state.findings_by_severity = HashMap::new();

    let context = ScanStrategy::build_strategy_context(&state);
    assert!(context.contains("<findings>\n    </findings>"));
}

#[test]
fn discovery_type_display() {
    assert_eq!(
        DiscoveryType::DirectoryBruteForce.to_string(),
        "Directory Brute Force"
    );
    assert_eq!(
        DiscoveryType::ParameterDiscovery.to_string(),
        "Parameter Discovery"
    );
    assert_eq!(
        DiscoveryType::JavaScriptAnalysis.to_string(),
        "JavaScript Analysis"
    );
    assert_eq!(
        DiscoveryType::VhostDiscovery.to_string(),
        "Virtual Host Discovery"
    );
}

#[test]
fn scan_state_serialization_roundtrip() {
    let state = base_state();
    let json = serde_json::to_string(&state).expect("serialize");
    let deserialized: ScanState = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(deserialized.target, state.target);
    assert_eq!(
        deserialized.endpoints_discovered,
        state.endpoints_discovered
    );
    assert_eq!(deserialized.findings_count, state.findings_count);
    assert_eq!(
        deserialized.iterations_remaining,
        state.iterations_remaining
    );
}

#[test]
fn strategy_action_serialization_roundtrip() {
    let actions = vec![
        StrategyAction::ContinueFuzzing {
            focus_classes: vec!["sqli".to_string()],
            focus_endpoints: vec!["/api/users".to_string()],
        },
        StrategyAction::RunExploitation {
            finding_id: 42,
            tool: "sqlmap".to_string(),
        },
        StrategyAction::DiscoverMore {
            discovery_type: DiscoveryType::ParameterDiscovery,
        },
        StrategyAction::DeepenAnalysis {
            vulnerability_class: "XSS".to_string(),
            technique: "DOM-based".to_string(),
        },
        StrategyAction::GenerateReport,
    ];

    for action in &actions {
        let json = serde_json::to_string(action).expect("serialize");
        let deserialized: StrategyAction = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&deserialized, action);
    }
}

#[test]
fn critical_zero_count_not_treated_as_present() {
    let mut state = base_state();
    state.findings_by_severity.insert("critical".to_string(), 0);
    state.exploitation_tools = vec!["sqlmap".to_string()];
    state.critical_finding_ids = vec![1];

    let action = ScanStrategy::suggest_next_action(&state);
    assert!(
        !matches!(action, StrategyAction::RunExploitation { .. }),
        "zero critical findings should not trigger exploitation"
    );
}

#[test]
fn exploitation_uses_first_tool_and_first_finding() {
    let mut state = base_state();
    state.findings_by_severity.insert("critical".to_string(), 3);
    state.exploitation_tools = vec!["tool_a".to_string(), "tool_b".to_string()];
    state.critical_finding_ids = vec![10, 20, 30];

    let action = ScanStrategy::suggest_next_action(&state);
    assert_eq!(
        action,
        StrategyAction::RunExploitation {
            finding_id: 10,
            tool: "tool_a".to_string(),
        }
    );
}
