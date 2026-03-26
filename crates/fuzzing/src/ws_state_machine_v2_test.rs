#[cfg(test)]
mod tests {
    use crate::ws_state_machine_v2::{
        build_fuzz_result, detect_anomaly, ExpectedBehavior, WsFuzzCase, WsMessage, WsState,
        WsStateMachine, WsStateMachineV2, WsTransition,
    };

    fn sample_text_binary_sequence() -> Vec<WsMessage> {
        vec![
            WsMessage::Text(r#"{"action":"auth","token":"abc"}"#.to_string()),
            WsMessage::Text(r#"{"action":"subscribe","channel":"ticker"}"#.to_string()),
            WsMessage::Binary(vec![0x01, 0x02, 0x03]),
            WsMessage::Binary(vec![0x04, 0x05, 0x06]),
            WsMessage::Text(r#"{"action":"unsubscribe","channel":"ticker"}"#.to_string()),
            WsMessage::Ping,
        ]
    }

    fn sample_channels() -> Vec<String> {
        vec![
            "market.btc".to_string(),
            "market.eth".to_string(),
            "private.orders".to_string(),
        ]
    }

    fn build_mock_state_machine() -> WsStateMachine {
        WsStateMachine {
            states: vec![
                WsState {
                    id: 0,
                    name: "state_0_text".to_string(),
                    observed_messages: vec![WsMessage::Text("auth".to_string())],
                },
                WsState {
                    id: 1,
                    name: "state_1_binary".to_string(),
                    observed_messages: vec![WsMessage::Binary(vec![0x01])],
                },
                WsState {
                    id: 2,
                    name: "state_2_text".to_string(),
                    observed_messages: vec![WsMessage::Text("done".to_string())],
                },
            ],
            transitions: vec![
                WsTransition {
                    from_state: 0,
                    to_state: 1,
                    trigger_message: WsMessage::Binary(vec![0x01]),
                },
                WsTransition {
                    from_state: 1,
                    to_state: 2,
                    trigger_message: WsMessage::Text("done".to_string()),
                },
            ],
            initial_state: 0,
        }
    }

    #[test]
    fn observe_empty_sequence_returns_single_empty_state() {
        let machine = WsStateMachineV2::observe(&[]);
        assert_eq!(machine.states.len(), 1);
        assert_eq!(machine.states[0].name, "empty");
        assert!(machine.transitions.is_empty());
        assert_eq!(machine.initial_state, 0);
    }

    #[test]
    fn observe_single_message_returns_single_state() {
        let messages = vec![WsMessage::Text("hello".to_string())];
        let machine = WsStateMachineV2::observe(&messages);
        assert_eq!(machine.states.len(), 1);
        assert!(machine.transitions.is_empty());
        assert_eq!(machine.states[0].observed_messages.len(), 1);
    }

    #[test]
    fn observe_same_type_messages_group_into_one_state() {
        let messages = vec![
            WsMessage::Text("a".to_string()),
            WsMessage::Text("b".to_string()),
            WsMessage::Text("c".to_string()),
        ];
        let machine = WsStateMachineV2::observe(&messages);
        assert_eq!(machine.states.len(), 1);
        assert_eq!(machine.states[0].observed_messages.len(), 3);
        assert!(machine.transitions.is_empty());
    }

    #[test]
    fn observe_type_change_creates_new_state_and_transition() {
        let messages = vec![
            WsMessage::Text("auth".to_string()),
            WsMessage::Binary(vec![0x01, 0x02]),
        ];
        let machine = WsStateMachineV2::observe(&messages);
        assert_eq!(machine.states.len(), 2);
        assert_eq!(machine.transitions.len(), 1);
        assert_eq!(machine.transitions[0].from_state, 0);
        assert_eq!(machine.transitions[0].to_state, 1);
    }

    #[test]
    fn observe_complex_sequence_correct_state_count() {
        let messages = sample_text_binary_sequence();
        let machine = WsStateMachineV2::observe(&messages);
        assert_eq!(machine.states.len(), 4);
        assert_eq!(machine.transitions.len(), 3);
    }

    #[test]
    fn observe_state_names_contain_type() {
        let messages = sample_text_binary_sequence();
        let machine = WsStateMachineV2::observe(&messages);
        assert!(machine.states[0].name.contains("text"));
        assert!(machine.states[1].name.contains("binary"));
    }

    #[test]
    fn observe_initial_state_is_zero() {
        let messages = sample_text_binary_sequence();
        let machine = WsStateMachineV2::observe(&messages);
        assert_eq!(machine.initial_state, 0);
    }

    #[test]
    fn state_machine_get_state_returns_correct_state() {
        let machine = build_mock_state_machine();
        let s = machine.get_state(1);
        assert!(s.is_some());
        assert_eq!(s.unwrap().name, "state_1_binary");
    }

    #[test]
    fn state_machine_get_state_missing_returns_none() {
        let machine = build_mock_state_machine();
        assert!(machine.get_state(99).is_none());
    }

    #[test]
    fn state_machine_transitions_from() {
        let machine = build_mock_state_machine();
        let from_0 = machine.transitions_from(0);
        assert_eq!(from_0.len(), 1);
        assert_eq!(from_0[0].to_state, 1);
        let from_2 = machine.transitions_from(2);
        assert!(from_2.is_empty());
    }

    #[test]
    fn state_machine_observed_message_types() {
        let machine = build_mock_state_machine();
        let types = machine.observed_message_types();
        assert!(types.contains(&"text".to_string()));
        assert!(types.contains(&"binary".to_string()));
    }

    #[test]
    fn transition_tests_cover_all_states() {
        let machine = build_mock_state_machine();
        let cases = WsStateMachineV2::generate_transition_tests(&machine);
        assert!(!cases.is_empty());
        for state in &machine.states {
            let has_case_for_state = cases.iter().any(|c| c.description.contains(&state.name));
            assert!(
                has_case_for_state,
                "no test case for state '{}'",
                state.name
            );
        }
    }

    #[test]
    fn transition_tests_include_wrong_type() {
        let machine = build_mock_state_machine();
        let cases = WsStateMachineV2::generate_transition_tests(&machine);
        let has_wrong_type = cases.iter().any(|c| c.description.contains("Wrong type"));
        assert!(has_wrong_type);
    }

    #[test]
    fn transition_tests_include_reversed_order() {
        let machine = build_mock_state_machine();
        let cases = WsStateMachineV2::generate_transition_tests(&machine);
        let has_reversed = cases.iter().any(|c| c.description.contains("Reversed"));
        assert!(has_reversed);
    }

    #[test]
    fn transition_tests_include_ping_injection() {
        let machine = build_mock_state_machine();
        let cases = WsStateMachineV2::generate_transition_tests(&machine);
        let has_ping = cases.iter().any(|c| c.description.contains("Ping"));
        assert!(has_ping);
    }

    #[test]
    fn confusion_tests_include_binary_when_text_expected() {
        let machine = build_mock_state_machine();
        let cases = WsStateMachineV2::generate_confusion_tests(&machine);
        let has_binary = cases
            .iter()
            .any(|c| c.description.contains("Binary frame when text"));
        assert!(has_binary);
    }

    #[test]
    fn confusion_tests_include_oversized_text() {
        let machine = build_mock_state_machine();
        let cases = WsStateMachineV2::generate_confusion_tests(&machine);
        let has_oversized = cases
            .iter()
            .any(|c| c.description.contains("Oversized text"));
        assert!(has_oversized);
        let oversized_case = cases
            .iter()
            .find(|c| c.description.contains("Oversized text"))
            .unwrap();
        if let WsMessage::Text(s) = &oversized_case.messages[0] {
            assert!(s.len() >= 1024 * 1024);
        } else {
            panic!("expected Text message");
        }
    }

    #[test]
    fn confusion_tests_include_oversized_binary() {
        let machine = build_mock_state_machine();
        let cases = WsStateMachineV2::generate_confusion_tests(&machine);
        let has_oversized = cases
            .iter()
            .any(|c| c.description.contains("Oversized binary"));
        assert!(has_oversized);
    }

    #[test]
    fn confusion_tests_include_null_bytes() {
        let machine = build_mock_state_machine();
        let cases = WsStateMachineV2::generate_confusion_tests(&machine);
        let has_null = cases.iter().any(|c| c.description.contains("Null bytes"));
        assert!(has_null);
    }

    #[test]
    fn confusion_tests_include_malformed_json() {
        let machine = build_mock_state_machine();
        let cases = WsStateMachineV2::generate_confusion_tests(&machine);
        let has_json = cases
            .iter()
            .any(|c| c.description.contains("Malformed JSON"));
        assert!(has_json);
    }

    #[test]
    fn confusion_tests_include_invalid_close_code() {
        let machine = build_mock_state_machine();
        let cases = WsStateMachineV2::generate_confusion_tests(&machine);
        let has_close = cases.iter().any(|c| c.description.contains("invalid code"));
        assert!(has_close);
    }

    #[test]
    fn subscription_abuse_empty_channels_returns_empty() {
        let cases = WsStateMachineV2::generate_subscription_abuse(&[]);
        assert!(cases.is_empty());
    }

    #[test]
    fn subscription_abuse_includes_mass_subscribe() {
        let channels = sample_channels();
        let cases = WsStateMachineV2::generate_subscription_abuse(&channels);
        let has_mass = cases
            .iter()
            .any(|c| c.description.contains("Over-subscribe"));
        assert!(has_mass);
    }

    #[test]
    fn subscription_abuse_mass_subscribe_count_matches_channels() {
        let channels = sample_channels();
        let cases = WsStateMachineV2::generate_subscription_abuse(&channels);
        let mass_case = cases
            .iter()
            .find(|c| c.description.contains("Over-subscribe"))
            .unwrap();
        assert_eq!(mass_case.messages.len(), channels.len());
    }

    #[test]
    fn subscription_abuse_includes_cross_subscriber_probes() {
        let channels = sample_channels();
        let cases = WsStateMachineV2::generate_subscription_abuse(&channels);
        let probe_count = cases
            .iter()
            .filter(|c| c.description.contains("Cross-subscriber"))
            .count();
        assert_eq!(probe_count, channels.len());
    }

    #[test]
    fn subscription_abuse_includes_wildcard_patterns() {
        let channels = sample_channels();
        let cases = WsStateMachineV2::generate_subscription_abuse(&channels);
        let has_wildcard = cases.iter().any(|c| c.description.contains("Wildcard"));
        assert!(has_wildcard);
        let wildcard_count = cases
            .iter()
            .filter(|c| c.description.contains("Wildcard"))
            .count();
        assert_eq!(wildcard_count, 4);
    }

    #[test]
    fn subscription_abuse_includes_unsubscribe_nonexistent() {
        let channels = sample_channels();
        let cases = WsStateMachineV2::generate_subscription_abuse(&channels);
        let has_unsub = cases
            .iter()
            .any(|c| c.description.contains("Unsubscribe from channel never"));
        assert!(has_unsub);
    }

    #[test]
    fn subscription_abuse_includes_rapid_cycle() {
        let channels = sample_channels();
        let cases = WsStateMachineV2::generate_subscription_abuse(&channels);
        let has_rapid = cases
            .iter()
            .any(|c| c.description.contains("Rapid subscribe/unsubscribe"));
        assert!(has_rapid);
    }

    #[test]
    fn race_tests_generated_for_multi_transition_machine() {
        let machine = build_mock_state_machine();
        let cases = WsStateMachineV2::generate_race_tests(&machine);
        assert!(!cases.is_empty());
        let has_simultaneous = cases.iter().any(|c| c.description.contains("Simultaneous"));
        assert!(has_simultaneous);
    }

    #[test]
    fn race_tests_include_rapid_fire_duplicates() {
        let machine = build_mock_state_machine();
        let cases = WsStateMachineV2::generate_race_tests(&machine);
        let has_rapid = cases.iter().any(|c| c.description.contains("Rapid-fire"));
        assert!(has_rapid);
    }

    #[test]
    fn race_tests_include_reverse_order() {
        let machine = build_mock_state_machine();
        let cases = WsStateMachineV2::generate_race_tests(&machine);
        let has_reverse = cases
            .iter()
            .any(|c| c.description.contains("Reverse-order"));
        assert!(has_reverse);
    }

    #[test]
    fn race_tests_single_transition_machine_still_produces_cases() {
        let machine = WsStateMachine {
            states: vec![WsState {
                id: 0,
                name: "init".to_string(),
                observed_messages: vec![WsMessage::Text("a".to_string())],
            }],
            transitions: vec![],
            initial_state: 0,
        };
        let cases = WsStateMachineV2::generate_race_tests(&machine);
        assert!(!cases.is_empty());
    }

    #[test]
    fn ws_message_display() {
        assert!(WsMessage::Text("hello world".to_string())
            .to_string()
            .contains("Text("));
        assert!(WsMessage::Binary(vec![0; 100])
            .to_string()
            .contains("100 bytes"));
        assert_eq!(WsMessage::Ping.to_string(), "Ping");
        assert_eq!(WsMessage::Pong.to_string(), "Pong");
        assert!(WsMessage::Close(1000, "normal".to_string())
            .to_string()
            .contains("1000"));
    }

    #[test]
    fn ws_message_type_tag() {
        assert_eq!(WsMessage::Text("x".to_string()).type_tag(), "text");
        assert_eq!(WsMessage::Binary(vec![]).type_tag(), "binary");
        assert_eq!(WsMessage::Ping.type_tag(), "ping");
        assert_eq!(WsMessage::Pong.type_tag(), "pong");
        assert_eq!(WsMessage::Close(1000, "ok".to_string()).type_tag(), "close");
    }

    #[test]
    fn ws_message_is_data() {
        assert!(WsMessage::Text("x".to_string()).is_data());
        assert!(WsMessage::Binary(vec![]).is_data());
        assert!(!WsMessage::Ping.is_data());
        assert!(!WsMessage::Pong.is_data());
        assert!(!WsMessage::Close(1000, "x".to_string()).is_data());
    }

    #[test]
    fn ws_message_equality() {
        assert_eq!(
            WsMessage::Text("a".to_string()),
            WsMessage::Text("a".to_string())
        );
        assert_ne!(
            WsMessage::Text("a".to_string()),
            WsMessage::Text("b".to_string())
        );
        assert_ne!(
            WsMessage::Text("a".to_string()),
            WsMessage::Binary(b"a".to_vec())
        );
        assert_eq!(WsMessage::Ping, WsMessage::Ping);
        assert_ne!(WsMessage::Ping, WsMessage::Pong);
    }

    #[test]
    fn expected_behavior_display() {
        assert_eq!(
            ExpectedBehavior::ErrorResponse.to_string(),
            "error-response"
        );
        assert_eq!(ExpectedBehavior::Disconnect.to_string(), "disconnect");
        assert_eq!(ExpectedBehavior::StateChange.to_string(), "state-change");
        assert_eq!(ExpectedBehavior::DataLeak.to_string(), "data-leak");
        assert_eq!(ExpectedBehavior::NoEffect.to_string(), "no-effect");
    }

    #[test]
    fn expected_behavior_equality() {
        assert_eq!(
            ExpectedBehavior::ErrorResponse,
            ExpectedBehavior::ErrorResponse
        );
        assert_ne!(
            ExpectedBehavior::ErrorResponse,
            ExpectedBehavior::Disconnect
        );
    }

    #[test]
    fn build_fuzz_result_anomaly_when_no_error_response() {
        let case = WsFuzzCase {
            description: "test".to_string(),
            messages: vec![WsMessage::Text("bad".to_string())],
            expected_behavior: ExpectedBehavior::ErrorResponse,
        };
        let actual = vec![WsMessage::Text("ok, no problem".to_string())];
        let result = build_fuzz_result(case, actual);
        assert!(result.anomaly_detected);
    }

    #[test]
    fn build_fuzz_result_no_anomaly_when_error_present() {
        let case = WsFuzzCase {
            description: "test".to_string(),
            messages: vec![WsMessage::Text("bad".to_string())],
            expected_behavior: ExpectedBehavior::ErrorResponse,
        };
        let actual = vec![WsMessage::Text("error: invalid input".to_string())];
        let result = build_fuzz_result(case, actual);
        assert!(!result.anomaly_detected);
    }

    #[test]
    fn build_fuzz_result_anomaly_when_disconnect_expected_but_response_received() {
        let case = WsFuzzCase {
            description: "test".to_string(),
            messages: vec![WsMessage::Text("oversized".to_string())],
            expected_behavior: ExpectedBehavior::Disconnect,
        };
        let actual = vec![WsMessage::Text("still connected".to_string())];
        let result = build_fuzz_result(case, actual);
        assert!(result.anomaly_detected);
    }

    #[test]
    fn build_fuzz_result_no_anomaly_when_disconnect_and_empty_response() {
        let case = WsFuzzCase {
            description: "test".to_string(),
            messages: vec![WsMessage::Text("oversized".to_string())],
            expected_behavior: ExpectedBehavior::Disconnect,
        };
        let result = build_fuzz_result(case, vec![]);
        assert!(!result.anomaly_detected);
    }

    #[test]
    fn build_fuzz_result_data_leak_detected() {
        let case = WsFuzzCase {
            description: "leak test".to_string(),
            messages: vec![WsMessage::Text("probe".to_string())],
            expected_behavior: ExpectedBehavior::DataLeak,
        };
        let actual = vec![WsMessage::Text("received: probe_{UNIQUE}".to_string())];
        let result = build_fuzz_result(case, actual);
        assert!(result.anomaly_detected);
    }

    #[test]
    fn detect_anomaly_delegates_to_result_flag() {
        let case = WsFuzzCase {
            description: "test".to_string(),
            messages: vec![],
            expected_behavior: ExpectedBehavior::NoEffect,
        };
        let result = build_fuzz_result(case, vec![]);
        assert_eq!(detect_anomaly(&result), result.anomaly_detected);
    }

    #[test]
    fn observe_ping_pong_sequence() {
        let messages = vec![WsMessage::Ping, WsMessage::Pong, WsMessage::Ping];
        let machine = WsStateMachineV2::observe(&messages);
        assert_eq!(machine.states.len(), 3);
        assert_eq!(machine.transitions.len(), 2);
    }

    #[test]
    fn observe_with_close_message() {
        let messages = vec![
            WsMessage::Text("hello".to_string()),
            WsMessage::Close(1000, "goodbye".to_string()),
        ];
        let machine = WsStateMachineV2::observe(&messages);
        assert_eq!(machine.states.len(), 2);
        assert_eq!(machine.transitions.len(), 1);
    }
}
