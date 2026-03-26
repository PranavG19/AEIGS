use super::kill_chain_executor::*;

#[test]
fn all_phases_returns_nine_phases() {
    let phases = KillChainPhase::all_phases();
    assert_eq!(phases.len(), 9);
    assert_eq!(phases[0], KillChainPhase::Reconnaissance);
    assert_eq!(phases[8], KillChainPhase::Objective);
}

#[test]
fn next_phase_follows_chain_order() {
    assert_eq!(
        KillChainPhase::Reconnaissance.next_phase(),
        Some(KillChainPhase::InitialAccess)
    );
    assert_eq!(
        KillChainPhase::Execution.next_phase(),
        Some(KillChainPhase::Persistence)
    );
    assert_eq!(KillChainPhase::Objective.next_phase(), None);
}

#[test]
fn phase_display_formatting() {
    assert_eq!(
        KillChainPhase::PrivilegeEscalation.to_string(),
        "Privilege Escalation"
    );
    assert_eq!(
        KillChainPhase::LateralMovement.to_string(),
        "Lateral Movement"
    );
    assert_eq!(KillChainPhase::Reconnaissance.to_string(), "Reconnaissance");
}

#[test]
fn access_level_ordering() {
    assert!(AccessLevel::Root > AccessLevel::DomainAdmin);
    assert!(AccessLevel::DomainAdmin > AccessLevel::LocalAdmin);
    assert!(AccessLevel::LocalAdmin > AccessLevel::Privileged);
    assert!(AccessLevel::Privileged > AccessLevel::Authenticated);
    assert!(AccessLevel::Authenticated > AccessLevel::Anonymous);
    assert!(AccessLevel::Anonymous > AccessLevel::None);
}

#[test]
fn init_state_defaults() {
    let config = KillChainConfig {
        target_url: "http://target.local".to_string(),
        objective: "domain admin".to_string(),
        ..Default::default()
    };
    let state = init_state(&config);
    assert_eq!(state.phase, KillChainPhase::Reconnaissance);
    assert_eq!(state.access_level, AccessLevel::None);
    assert_eq!(state.iteration, 0);
    assert_eq!(state.max_iterations, 10);
    assert!(state.credentials.is_empty());
    assert!(state.phase_history.is_empty());
    assert!(!state.objective_achieved);
}

#[test]
fn parse_objective_domain_admin() {
    assert_eq!(parse_objective("domain admin"), ObjectiveCheck::DomainAdmin);
    assert_eq!(
        parse_objective("Domain Admin access"),
        ObjectiveCheck::DomainAdmin
    );
}

#[test]
fn parse_objective_file_read() {
    assert_eq!(
        parse_objective("file: /etc/shadow"),
        ObjectiveCheck::FileRead("/etc/shadow".to_string())
    );
}

#[test]
fn parse_objective_credential() {
    assert_eq!(
        parse_objective("credential: admin"),
        ObjectiveCheck::CredentialObtained("admin".to_string())
    );
}

#[test]
fn parse_objective_network() {
    assert_eq!(
        parse_objective("network: 10.0.0.0/8"),
        ObjectiveCheck::NetworkAccess("10.0.0.0/8".to_string())
    );
}

#[test]
fn parse_objective_database() {
    assert_eq!(
        parse_objective("database access"),
        ObjectiveCheck::DatabaseAccess
    );
}

#[test]
fn parse_objective_custom() {
    assert_eq!(
        parse_objective("something else"),
        ObjectiveCheck::Custom("something else".to_string())
    );
}

#[test]
fn evaluate_objective_domain_admin_not_achieved() {
    let config = KillChainConfig {
        target_url: "http://target.local".to_string(),
        objective: "domain admin".to_string(),
        ..Default::default()
    };
    let state = init_state(&config);
    let (achieved, progress) = evaluate_objective(&state);
    assert!(!achieved);
    assert_eq!(progress, 0.0);
}

#[test]
fn evaluate_objective_domain_admin_achieved_via_access_level() {
    let config = KillChainConfig {
        target_url: "http://target.local".to_string(),
        objective: "domain admin".to_string(),
        ..Default::default()
    };
    let mut state = init_state(&config);
    state.access_level = AccessLevel::DomainAdmin;
    let (achieved, progress) = evaluate_objective(&state);
    assert!(achieved);
    assert_eq!(progress, 100.0);
}

#[test]
fn evaluate_objective_domain_admin_achieved_via_credential() {
    let config = KillChainConfig {
        target_url: "http://target.local".to_string(),
        objective: "domain admin".to_string(),
        ..Default::default()
    };
    let mut state = init_state(&config);
    state.credentials.push(ObtainedCredential {
        username: "admin".to_string(),
        credential_type: CredentialType::Password,
        source_phase: KillChainPhase::PrivilegeEscalation,
        access_level: AccessLevel::DomainAdmin,
        target_host: None,
    });
    let (achieved, _progress) = evaluate_objective(&state);
    assert!(achieved);
}

#[test]
fn evaluate_objective_credential_obtained() {
    let config = KillChainConfig {
        target_url: "http://target.local".to_string(),
        objective: "credential: admin".to_string(),
        ..Default::default()
    };
    let mut state = init_state(&config);
    state.credentials.push(ObtainedCredential {
        username: "admin".to_string(),
        credential_type: CredentialType::Password,
        source_phase: KillChainPhase::Execution,
        access_level: AccessLevel::Authenticated,
        target_host: None,
    });
    let (achieved, progress) = evaluate_objective(&state);
    assert!(achieved);
    assert_eq!(progress, 100.0);
}

#[test]
fn evaluate_objective_network_access_partial() {
    let config = KillChainConfig {
        target_url: "http://target.local".to_string(),
        objective: "network: 10.0.0.0/8".to_string(),
        ..Default::default()
    };
    let mut state = init_state(&config);
    state.compromised_hosts.push("10.0.0.1".to_string());
    state.compromised_hosts.push("10.0.0.2".to_string());
    let (achieved, progress) = evaluate_objective(&state);
    assert!(!achieved);
    assert_eq!(progress, 50.0);
}

#[test]
fn check_phase_gate_recon_unmet() {
    let config = KillChainConfig {
        target_url: "http://target.local".to_string(),
        objective: "domain admin".to_string(),
        ..Default::default()
    };
    let state = init_state(&config);
    let gates = phase_gate_requirements();
    let recon_gate = &gates[0];
    assert!(!check_phase_gate(&state, recon_gate));
}

#[test]
fn check_phase_gate_recon_met() {
    let config = KillChainConfig {
        target_url: "http://target.local".to_string(),
        objective: "domain admin".to_string(),
        ..Default::default()
    };
    let mut state = init_state(&config);
    state.phase_history.push(PhaseRecord {
        phase: KillChainPhase::Reconnaissance,
        actions: vec![],
        findings: vec![
            "target_endpoints_discovered: 15 endpoints".to_string(),
            "tech_stack_identified: Express/Node.js".to_string(),
        ],
        access_gained: None,
        duration_ms: 5000,
        success: true,
        transition_reason: "Recon complete".to_string(),
    });
    let gates = phase_gate_requirements();
    let recon_gate = &gates[0];
    assert!(check_phase_gate(&state, recon_gate));
}

#[test]
fn decide_next_phase_returns_none_at_max_iterations() {
    let config = KillChainConfig {
        target_url: "http://target.local".to_string(),
        objective: "domain admin".to_string(),
        max_iterations: 5,
        ..Default::default()
    };
    let mut state = init_state(&config);
    state.iteration = 5;
    assert_eq!(decide_next_phase(&state, None, &config), None);
}

#[test]
fn decide_next_phase_follows_chain() {
    let config = KillChainConfig {
        target_url: "http://target.local".to_string(),
        objective: "domain admin".to_string(),
        ..Default::default()
    };
    let state = init_state(&config);
    let next = decide_next_phase(&state, None, &config);
    assert_eq!(next, Some(KillChainPhase::InitialAccess));
}

#[test]
fn decide_next_phase_skips_persistence() {
    let config = KillChainConfig {
        target_url: "http://target.local".to_string(),
        objective: "domain admin".to_string(),
        skip_persistence: true,
        ..Default::default()
    };
    let mut state = init_state(&config);
    state.phase = KillChainPhase::Execution;
    let next = decide_next_phase(&state, None, &config);
    assert_eq!(next, Some(KillChainPhase::PrivilegeEscalation));
}

#[test]
fn decide_next_phase_respects_llm_decision() {
    let config = KillChainConfig {
        target_url: "http://target.local".to_string(),
        objective: "domain admin".to_string(),
        ..Default::default()
    };
    let state = init_state(&config);
    let decision = LlmDecision {
        next_phase: KillChainPhase::Execution,
        reasoning: "Skip to execution".to_string(),
        confidence: 0.9,
        suggested_actions: vec![],
        abort: false,
    };
    let next = decide_next_phase(&state, Some(&decision), &config);
    assert_eq!(next, Some(KillChainPhase::Execution));
}

#[test]
fn decide_next_phase_aborts_on_llm_request() {
    let config = KillChainConfig {
        target_url: "http://target.local".to_string(),
        objective: "domain admin".to_string(),
        ..Default::default()
    };
    let state = init_state(&config);
    let decision = LlmDecision {
        next_phase: KillChainPhase::Execution,
        reasoning: "Target hardened, abort".to_string(),
        confidence: 0.95,
        suggested_actions: vec![],
        abort: true,
    };
    assert_eq!(decide_next_phase(&state, Some(&decision), &config), None);
}

#[test]
fn advance_phase_updates_state() {
    let config = KillChainConfig {
        target_url: "http://target.local".to_string(),
        objective: "credential: admin".to_string(),
        ..Default::default()
    };
    let mut state = init_state(&config);
    let record = PhaseRecord {
        phase: KillChainPhase::Reconnaissance,
        actions: vec![],
        findings: vec!["target_endpoints_discovered".to_string()],
        access_gained: Some(AccessLevel::Anonymous),
        duration_ms: 3000,
        success: true,
        transition_reason: "Proceeding to initial access".to_string(),
    };
    advance_phase(&mut state, record, &config);
    assert_eq!(state.access_level, AccessLevel::Anonymous);
    assert_eq!(state.iteration, 1);
    assert_eq!(state.phase_history.len(), 1);
}

#[test]
fn execute_kill_chain_reaches_objective() {
    let config = KillChainConfig {
        target_url: "http://target.local".to_string(),
        objective: "credential: admin".to_string(),
        max_iterations: 10,
        ..Default::default()
    };

    let mut call_count = 0u32;
    let phase_executor = |state: &KillChainState, phase: KillChainPhase| -> PhaseRecord {
        let mut actions = vec![];
        let mut findings = vec![];
        let mut access_gained = None;

        match phase {
            KillChainPhase::Reconnaissance => {
                findings.push("target_endpoints_discovered".to_string());
            }
            KillChainPhase::InitialAccess => {
                actions.push(PhaseAction {
                    description: "Exploit SQLi".to_string(),
                    action_type: PhaseActionType::Exploit,
                    target: Some("/api/login".to_string()),
                    result: ActionResult::Success,
                    evidence: Some("UNION SELECT".to_string()),
                });
                findings.push("vulnerability_confirmed".to_string());
                access_gained = Some(AccessLevel::Authenticated);
            }
            KillChainPhase::Execution => {
                findings.push("code_execution_confirmed".to_string());
                access_gained = Some(AccessLevel::Privileged);
            }
            _ => {}
        }

        PhaseRecord {
            phase,
            actions,
            findings,
            access_gained,
            duration_ms: 1000,
            success: true,
            transition_reason: format!("{phase} complete"),
        }
    };

    let llm_advisor = |state: &KillChainState| -> LlmDecision {
        let next = state
            .phase
            .next_phase()
            .unwrap_or(KillChainPhase::Objective);
        LlmDecision {
            next_phase: next,
            reasoning: "Proceeding to next phase".to_string(),
            confidence: 0.8,
            suggested_actions: vec![],
            abort: false,
        }
    };

    let report = execute_kill_chain(&config, phase_executor, llm_advisor);
    assert!(report.phases_completed.len() >= 2);
    assert!(report.total_iterations >= 2);
    assert_eq!(report.target_url, "http://target.local");
}

#[test]
fn execute_kill_chain_respects_max_iterations() {
    let config = KillChainConfig {
        target_url: "http://target.local".to_string(),
        objective: "domain admin".to_string(),
        max_iterations: 3,
        ..Default::default()
    };

    let phase_executor = |_: &KillChainState, phase: KillChainPhase| -> PhaseRecord {
        PhaseRecord {
            phase,
            actions: vec![],
            findings: vec![],
            access_gained: None,
            duration_ms: 500,
            success: true,
            transition_reason: "Next".to_string(),
        }
    };

    let llm_advisor = |state: &KillChainState| -> LlmDecision {
        let next = state.phase.next_phase().unwrap_or(state.phase);
        LlmDecision {
            next_phase: next,
            reasoning: "Continue".to_string(),
            confidence: 0.5,
            suggested_actions: vec![],
            abort: false,
        }
    };

    let report = execute_kill_chain(&config, phase_executor, llm_advisor);
    assert_eq!(report.total_iterations, 3);
    assert!(!report.objective_achieved);
}

#[test]
fn execute_kill_chain_tracks_pivots() {
    let config = KillChainConfig {
        target_url: "http://target.local".to_string(),
        objective: "network: 10.0.0.0/8".to_string(),
        max_iterations: 5,
        ..Default::default()
    };

    let phase_executor = |_: &KillChainState, phase: KillChainPhase| -> PhaseRecord {
        let mut actions = vec![];
        if phase == KillChainPhase::LateralMovement {
            actions.push(PhaseAction {
                description: "Pivot to 10.0.0.5".to_string(),
                action_type: PhaseActionType::Pivot,
                target: Some("10.0.0.5".to_string()),
                result: ActionResult::Success,
                evidence: None,
            });
        }
        PhaseRecord {
            phase,
            actions,
            findings: vec![],
            access_gained: Some(AccessLevel::Authenticated),
            duration_ms: 1000,
            success: true,
            transition_reason: "Next".to_string(),
        }
    };

    let llm_advisor = |state: &KillChainState| -> LlmDecision {
        let next = state.phase.next_phase().unwrap_or(state.phase);
        LlmDecision {
            next_phase: next,
            reasoning: "Continue".to_string(),
            confidence: 0.7,
            suggested_actions: vec![],
            abort: false,
        }
    };

    let report = execute_kill_chain(&config, phase_executor, llm_advisor);
    assert!(report.pivot_count >= 1);
    assert!(report.hosts_compromised.contains(&"10.0.0.5".to_string()));
}

#[test]
fn generate_report_executive_summary_achieved() {
    let config = KillChainConfig {
        target_url: "http://target.local".to_string(),
        objective: "domain admin".to_string(),
        ..Default::default()
    };
    let mut state = init_state(&config);
    state.access_level = AccessLevel::DomainAdmin;
    state.objective_achieved = true;
    state.objective_progress_pct = 100.0;
    state.credentials.push(ObtainedCredential {
        username: "admin".to_string(),
        credential_type: CredentialType::Hash,
        source_phase: KillChainPhase::PrivilegeEscalation,
        access_level: AccessLevel::DomainAdmin,
        target_host: None,
    });
    state.phase_history.push(PhaseRecord {
        phase: KillChainPhase::Reconnaissance,
        actions: vec![],
        findings: vec![],
        access_gained: None,
        duration_ms: 1000,
        success: true,
        transition_reason: "Done".to_string(),
    });

    let report = generate_report(&state);
    assert!(report.objective_achieved);
    assert!(report.executive_summary.contains("was achieved"));
    assert!(report.executive_summary.contains("credential"));
}

#[test]
fn generate_report_executive_summary_not_achieved() {
    let config = KillChainConfig {
        target_url: "http://target.local".to_string(),
        objective: "domain admin".to_string(),
        ..Default::default()
    };
    let mut state = init_state(&config);
    state.access_level = AccessLevel::LocalAdmin;
    state.objective_progress_pct = 75.0;

    let report = generate_report(&state);
    assert!(!report.objective_achieved);
    assert!(report.executive_summary.contains("not fully achieved"));
    assert!(report.executive_summary.contains("75%"));
}

#[test]
fn kill_chain_config_default() {
    let config = KillChainConfig::default();
    assert_eq!(config.max_iterations, 10);
    assert_eq!(config.objective, "domain admin");
    assert!(!config.skip_persistence);
    assert!(!config.skip_exfiltration);
    assert!(config.credential_reuse);
}

#[test]
fn phase_gate_requirements_count() {
    let gates = phase_gate_requirements();
    assert_eq!(gates.len(), 8);
    assert_eq!(gates[0].phase, KillChainPhase::Reconnaissance);
}
