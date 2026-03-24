use super::*;

fn build_chat_app_machine() -> WsStateMachine {
    let mut machine = WsStateMachine::new("connected");

    machine.add_state(WsState {
        id: "authenticated".into(),
        name: "authenticated".into(),
        is_initial: false,
        is_terminal: false,
        is_authenticated: true,
    });
    machine.add_state(WsState {
        id: "in_room".into(),
        name: "in_room".into(),
        is_initial: false,
        is_terminal: false,
        is_authenticated: true,
    });
    machine.add_state(WsState {
        id: "disconnected".into(),
        name: "disconnected".into(),
        is_initial: false,
        is_terminal: true,
        is_authenticated: false,
    });

    machine.add_message_type(WsMessageType {
        id: "login".into(),
        name: "login".into(),
        direction: MessageDirection::ClientToServer,
        schema: None,
        requires_auth: false,
        example_payload: r#"{"type":"login","username":"user","password":"pass"}"#.into(),
    });
    machine.add_message_type(WsMessageType {
        id: "join_room".into(),
        name: "join_room".into(),
        direction: MessageDirection::ClientToServer,
        schema: None,
        requires_auth: true,
        example_payload: r#"{"type":"join_room","room":"general"}"#.into(),
    });
    machine.add_message_type(WsMessageType {
        id: "send_message".into(),
        name: "send_message".into(),
        direction: MessageDirection::ClientToServer,
        schema: None,
        requires_auth: true,
        example_payload: r#"{"type":"send_message","text":"hello"}"#.into(),
    });
    machine.add_message_type(WsMessageType {
        id: "leave_room".into(),
        name: "leave_room".into(),
        direction: MessageDirection::ClientToServer,
        schema: None,
        requires_auth: true,
        example_payload: r#"{"type":"leave_room"}"#.into(),
    });
    machine.add_message_type(WsMessageType {
        id: "server_notification".into(),
        name: "server_notification".into(),
        direction: MessageDirection::ServerToClient,
        schema: None,
        requires_auth: false,
        example_payload: r#"{"type":"notification","text":"welcome"}"#.into(),
    });

    machine.add_transition(WsTransition {
        from_state: "connected".into(),
        to_state: "authenticated".into(),
        message_type: "login".into(),
        observed_count: 1,
        is_valid: true,
    });
    machine.add_transition(WsTransition {
        from_state: "authenticated".into(),
        to_state: "in_room".into(),
        message_type: "join_room".into(),
        observed_count: 1,
        is_valid: true,
    });
    machine.add_transition(WsTransition {
        from_state: "in_room".into(),
        to_state: "in_room".into(),
        message_type: "send_message".into(),
        observed_count: 5,
        is_valid: true,
    });
    machine.add_transition(WsTransition {
        from_state: "in_room".into(),
        to_state: "authenticated".into(),
        message_type: "leave_room".into(),
        observed_count: 1,
        is_valid: true,
    });

    machine
}

#[test]
fn ws_state_display() {
    let state = WsState {
        id: "s1".into(),
        name: "Connected".into(),
        is_initial: true,
        is_terminal: false,
        is_authenticated: false,
    };
    assert_eq!(state.to_string(), "Connected");
}

#[test]
fn message_direction_display() {
    assert_eq!(MessageDirection::ClientToServer.to_string(), "C→S");
    assert_eq!(MessageDirection::ServerToClient.to_string(), "S→C");
    assert_eq!(MessageDirection::Bidirectional.to_string(), "C↔S");
}

#[test]
fn ws_transition_display() {
    let t = WsTransition {
        from_state: "A".into(),
        to_state: "B".into(),
        message_type: "login".into(),
        observed_count: 3,
        is_valid: true,
    };
    let display = t.to_string();
    assert!(display.contains("A"));
    assert!(display.contains("B"));
    assert!(display.contains("login"));
    assert!(display.contains("3x"));
}

#[test]
fn state_machine_new() {
    let machine = WsStateMachine::new("init");
    assert_eq!(machine.states.len(), 1);
    assert_eq!(machine.initial_state, "init");
    assert!(machine.states[0].is_initial);
}

#[test]
fn state_machine_add_state_dedup() {
    let mut machine = WsStateMachine::new("init");
    machine.add_state(WsState {
        id: "s1".into(),
        name: "State1".into(),
        is_initial: false,
        is_terminal: false,
        is_authenticated: false,
    });
    machine.add_state(WsState {
        id: "s1".into(),
        name: "State1Dup".into(),
        is_initial: false,
        is_terminal: false,
        is_authenticated: false,
    });
    assert_eq!(machine.states.len(), 2);
}

#[test]
fn state_machine_add_transition_merges() {
    let mut machine = WsStateMachine::new("init");
    machine.add_transition(WsTransition {
        from_state: "A".into(),
        to_state: "B".into(),
        message_type: "msg".into(),
        observed_count: 1,
        is_valid: true,
    });
    machine.add_transition(WsTransition {
        from_state: "A".into(),
        to_state: "B".into(),
        message_type: "msg".into(),
        observed_count: 2,
        is_valid: true,
    });
    assert_eq!(machine.transitions.len(), 1);
    assert_eq!(machine.transitions[0].observed_count, 3);
}

#[test]
fn valid_messages_for_state() {
    let machine = build_chat_app_machine();
    let valid = machine.valid_messages_for_state("connected");
    assert_eq!(valid.len(), 1);
    assert_eq!(valid[0].message_type, "login");
}

#[test]
fn invalid_messages_for_state() {
    let machine = build_chat_app_machine();
    let invalid = machine.invalid_messages_for_state("connected");
    assert!(
        invalid.len() >= 2,
        "connected state should have 2+ invalid client messages"
    );
    assert!(invalid.iter().any(|m| m.id == "join_room"));
    assert!(invalid.iter().any(|m| m.id == "send_message"));
}

#[test]
fn invalid_messages_excludes_server_msgs() {
    let machine = build_chat_app_machine();
    let invalid = machine.invalid_messages_for_state("connected");
    assert!(
        !invalid.iter().any(|m| m.id == "server_notification"),
        "Should not include server-to-client messages in invalid list"
    );
}

#[test]
fn paths_to_state() {
    let machine = build_chat_app_machine();
    let paths = machine.paths_to_state("in_room", 5);
    assert!(!paths.is_empty());
    assert!(paths[0].contains(&"connected".to_string()));
    assert!(paths[0].contains(&"in_room".to_string()));
}

#[test]
fn paths_to_state_initial() {
    let machine = build_chat_app_machine();
    let paths = machine.paths_to_state("connected", 5);
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0], vec!["connected"]);
}

#[test]
fn unauthenticated_reachable() {
    let machine = build_chat_app_machine();
    let reachable = machine.unauthenticated_reachable();
    let reachable_ids: Vec<&str> = reachable.iter().map(|s| s.id.as_str()).collect();
    assert!(
        !reachable_ids.contains(&"in_room"),
        "in_room should not be reachable without auth"
    );
}

#[test]
fn state_machine_stats() {
    let machine = build_chat_app_machine();
    let stats = machine.stats();
    assert_eq!(stats.state_count, 4);
    assert_eq!(stats.transition_count, 4);
    assert_eq!(stats.message_type_count, 5);
    assert_eq!(stats.auth_state_count, 2);
    assert_eq!(stats.terminal_state_count, 1);
    assert!(stats.client_message_count >= 4);
    assert!(stats.auth_required_message_count >= 3);
}

#[test]
fn fuzz_category_all() {
    let categories = WsFuzzCategory::all();
    assert_eq!(categories.len(), 10);
    for c in categories {
        assert!(!c.to_string().is_empty());
    }
}

#[test]
fn severity_ordering() {
    assert!(Severity::Info < Severity::Low);
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

#[test]
fn expected_behavior_display() {
    assert!(!ExpectedBehavior::Rejected.to_string().is_empty());
    assert!(!ExpectedBehavior::ServerCrash.to_string().is_empty());
}

#[test]
fn generate_fuzz_cases_non_empty() {
    let machine = build_chat_app_machine();
    let cases = generate_fuzz_cases(&machine);
    assert!(
        cases.len() >= 20,
        "Should generate 20+ fuzz cases for chat app, got {}",
        cases.len()
    );
}

#[test]
fn generate_fuzz_cases_covers_categories() {
    let machine = build_chat_app_machine();
    let cases = generate_fuzz_cases(&machine);
    let categories: HashSet<String> = cases.iter().map(|c| c.category.to_string()).collect();
    assert!(categories.contains("Invalid Transition"));
    assert!(categories.contains("Message Injection"));
    assert!(categories.contains("Protocol Abuse"));
    assert!(categories.contains("Session Replay"));
}

#[test]
fn generate_fuzz_cases_unique_ids() {
    let machine = build_chat_app_machine();
    let cases = generate_fuzz_cases(&machine);
    let ids: Vec<&str> = cases.iter().map(|c| c.id.as_str()).collect();
    let unique: HashSet<&str> = ids.iter().copied().collect();
    assert_eq!(ids.len(), unique.len(), "Fuzz case IDs must be unique");
}

#[test]
fn generate_fuzz_cases_has_descriptions() {
    let machine = build_chat_app_machine();
    let cases = generate_fuzz_cases(&machine);
    for case in &cases {
        assert!(!case.description.is_empty());
    }
}

#[test]
fn generate_fuzz_cases_has_messages() {
    let machine = build_chat_app_machine();
    let cases = generate_fuzz_cases(&machine);
    for case in &cases {
        assert!(!case.message_sequence.is_empty());
    }
}

#[test]
fn invalid_transition_cases_target_right_state() {
    let machine = build_chat_app_machine();
    let cases = generate_fuzz_cases(&machine);
    let invalid: Vec<&WsFuzzCase> = cases
        .iter()
        .filter(|c| c.category == WsFuzzCategory::InvalidTransition)
        .collect();
    assert!(!invalid.is_empty());
    for case in &invalid {
        assert!(
            machine
                .states
                .iter()
                .any(|s| s.id == case.precondition_state),
            "Precondition state should exist in machine"
        );
    }
}

#[test]
fn session_replay_cases_critical() {
    let machine = build_chat_app_machine();
    let cases = generate_fuzz_cases(&machine);
    let session_replays: Vec<&WsFuzzCase> = cases
        .iter()
        .filter(|c| c.category == WsFuzzCategory::SessionReplay)
        .collect();
    assert!(session_replays.len() >= 2);
    for case in &session_replays {
        assert_eq!(case.severity, Severity::Critical);
    }
}

#[test]
fn protocol_abuse_standalone() {
    let machine = WsStateMachine::new("init");
    let cases = generate_fuzz_cases(&machine);
    let protocol: Vec<&WsFuzzCase> = cases
        .iter()
        .filter(|c| c.category == WsFuzzCategory::ProtocolAbuse)
        .collect();
    assert!(
        protocol.len() >= 4,
        "Protocol abuse should generate 4+ cases even with empty machine"
    );
}

#[test]
fn message_injection_includes_sqli_xss() {
    let machine = build_chat_app_machine();
    let cases = generate_fuzz_cases(&machine);
    let injections: Vec<&WsFuzzCase> = cases
        .iter()
        .filter(|c| c.category == WsFuzzCategory::MessageInjection)
        .collect();
    assert!(!injections.is_empty());
    assert!(injections.iter().any(|c| c.description.contains("sqli")));
    assert!(injections.iter().any(|c| c.description.contains("xss")));
    assert!(injections.iter().any(|c| c.description.contains("ssti")));
}

#[test]
fn race_condition_cases_generated() {
    let machine = build_chat_app_machine();
    let cases = generate_fuzz_cases(&machine);
    let races: Vec<&WsFuzzCase> = cases
        .iter()
        .filter(|c| c.category == WsFuzzCategory::RaceCondition)
        .collect();
    assert!(!races.is_empty());
    for case in &races {
        assert_eq!(case.message_sequence.len(), 2);
        assert_eq!(case.message_sequence[0].delay_ms, 0);
        assert_eq!(case.message_sequence[1].delay_ms, 0);
    }
}

#[test]
fn message_replay_double_send() {
    let machine = build_chat_app_machine();
    let cases = generate_fuzz_cases(&machine);
    let replays: Vec<&WsFuzzCase> = cases
        .iter()
        .filter(|c| c.category == WsFuzzCategory::MessageReplay)
        .collect();
    assert!(!replays.is_empty());
    for case in &replays {
        assert_eq!(case.message_sequence.len(), 2);
        assert_eq!(
            case.message_sequence[0].message_type,
            case.message_sequence[1].message_type
        );
    }
}

#[test]
fn infer_state_machine_single_sequence() {
    let sequences = vec![vec![
        ("connect".into(), MessageDirection::ClientToServer),
        ("auth".into(), MessageDirection::ClientToServer),
        ("subscribe".into(), MessageDirection::ClientToServer),
    ]];
    let machine = infer_state_machine(&sequences);
    assert!(machine.states.len() >= 4);
    assert!(machine.transitions.len() >= 3);
    assert_eq!(machine.message_types.len(), 3);
}

#[test]
fn infer_state_machine_multiple_sequences() {
    let sequences = vec![
        vec![
            ("login".into(), MessageDirection::ClientToServer),
            ("join".into(), MessageDirection::ClientToServer),
        ],
        vec![
            ("login".into(), MessageDirection::ClientToServer),
            ("list_rooms".into(), MessageDirection::ClientToServer),
        ],
    ];
    let machine = infer_state_machine(&sequences);
    assert!(machine.states.len() >= 3);
    let login_transitions: Vec<&WsTransition> = machine
        .transitions
        .iter()
        .filter(|t| t.message_type == "login")
        .collect();
    assert!(
        login_transitions.iter().any(|t| t.observed_count >= 2),
        "Login transition should be observed 2+ times"
    );
}

#[test]
fn infer_state_machine_merges_transitions() {
    let sequences = vec![
        vec![("ping".into(), MessageDirection::ClientToServer)],
        vec![("ping".into(), MessageDirection::ClientToServer)],
        vec![("ping".into(), MessageDirection::ClientToServer)],
    ];
    let machine = infer_state_machine(&sequences);
    let ping_transitions: Vec<&WsTransition> = machine
        .transitions
        .iter()
        .filter(|t| t.message_type == "ping")
        .collect();
    assert_eq!(ping_transitions.len(), 1);
    assert_eq!(ping_transitions[0].observed_count, 3);
}

#[test]
fn analyze_report_complete() {
    let machine = build_chat_app_machine();
    let report = analyze(&machine);
    assert_eq!(report.total_states, 4);
    assert_eq!(report.total_transitions, 4);
    assert!(report.total_fuzz_cases > 0);
    assert!(report.critical_cases > 0);
    assert!(report.high_cases > 0);
    assert!(!report.by_category.is_empty());
    assert!(!report.summary.is_empty());
    assert!(report.summary.contains("WebSocket"));
}

#[test]
fn analyze_empty_machine() {
    let machine = WsStateMachine::new("init");
    let report = analyze(&machine);
    assert_eq!(report.total_states, 1);
    assert!(
        report.total_fuzz_cases > 0,
        "Even empty machine gets protocol abuse cases"
    );
}

#[test]
fn connection_manipulation_targets_auth_msgs() {
    let machine = build_chat_app_machine();
    let cases = generate_fuzz_cases(&machine);
    let manipulations: Vec<&WsFuzzCase> = cases
        .iter()
        .filter(|c| c.category == WsFuzzCategory::ConnectionManipulation)
        .collect();
    assert!(!manipulations.is_empty());
    for case in &manipulations {
        assert!(
            case.message_sequence.len() >= 3,
            "Should have msg + disconnect + reconnect + msg"
        );
    }
}

#[test]
fn sequence_skip_from_initial() {
    let machine = build_chat_app_machine();
    let cases = generate_fuzz_cases(&machine);
    let skips: Vec<&WsFuzzCase> = cases
        .iter()
        .filter(|c| c.category == WsFuzzCategory::SequenceSkip)
        .collect();
    assert!(!skips.is_empty());
    for case in &skips {
        assert_eq!(case.precondition_state, "connected");
        assert_eq!(case.severity, Severity::High);
    }
}

#[test]
fn fuzz_case_severity_distribution() {
    let machine = build_chat_app_machine();
    let cases = generate_fuzz_cases(&machine);
    let report = analyze(&machine);
    let total = report.critical_cases
        + report.high_cases
        + report.medium_cases
        + report.low_cases
        + report.info_cases;
    assert_eq!(total, cases.len());
}
