use std::fmt;

use serde::{Deserialize, Serialize};

/// A message in a WebSocket conversation used for state machine inference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WsMessage {
    Text(String),
    Binary(Vec<u8>),
    Ping,
    Pong,
    Close(u16, String),
}

impl fmt::Display for WsMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(s) => write!(f, "Text({}...)", &s[..s.len().min(32)]),
            Self::Binary(b) => write!(f, "Binary({} bytes)", b.len()),
            Self::Ping => write!(f, "Ping"),
            Self::Pong => write!(f, "Pong"),
            Self::Close(code, reason) => write!(f, "Close({code}, {reason})"),
        }
    }
}

impl WsMessage {
    /// Returns the message type tag as a string for comparison.
    pub fn type_tag(&self) -> &'static str {
        match self {
            Self::Text(_) => "text",
            Self::Binary(_) => "binary",
            Self::Ping => "ping",
            Self::Pong => "pong",
            Self::Close(_, _) => "close",
        }
    }

    /// Returns true if this is a data-carrying message (Text or Binary).
    pub fn is_data(&self) -> bool {
        matches!(self, Self::Text(_) | Self::Binary(_))
    }
}

/// A state in the inferred WebSocket protocol state machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsState {
    pub id: u32,
    pub name: String,
    pub observed_messages: Vec<WsMessage>,
}

/// A transition between states triggered by a specific message pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsTransition {
    pub from_state: u32,
    pub to_state: u32,
    pub trigger_message: WsMessage,
}

/// Inferred WebSocket protocol state machine from observed message sequences.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsStateMachine {
    pub states: Vec<WsState>,
    pub transitions: Vec<WsTransition>,
    pub initial_state: u32,
}

impl WsStateMachine {
    /// Returns the state with the given ID.
    pub fn get_state(&self, id: u32) -> Option<&WsState> {
        self.states.iter().find(|s| s.id == id)
    }

    /// Returns all transitions originating from the given state.
    pub fn transitions_from(&self, state_id: u32) -> Vec<&WsTransition> {
        self.transitions
            .iter()
            .filter(|t| t.from_state == state_id)
            .collect()
    }

    /// Returns the set of distinct message types observed across all states.
    pub fn observed_message_types(&self) -> Vec<String> {
        let mut types = std::collections::HashSet::new();
        for state in &self.states {
            for msg in &state.observed_messages {
                types.insert(msg.type_tag().to_string());
            }
        }
        let mut sorted: Vec<String> = types.into_iter().collect();
        sorted.sort();
        sorted
    }
}

/// Expected behavior of the server when a fuzz case is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExpectedBehavior {
    ErrorResponse,
    Disconnect,
    StateChange,
    DataLeak,
    NoEffect,
}

impl fmt::Display for ExpectedBehavior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ErrorResponse => "error-response",
            Self::Disconnect => "disconnect",
            Self::StateChange => "state-change",
            Self::DataLeak => "data-leak",
            Self::NoEffect => "no-effect",
        };
        write!(f, "{label}")
    }
}

/// A generated fuzz test case for a WebSocket protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsFuzzCase {
    pub description: String,
    pub messages: Vec<WsMessage>,
    pub expected_behavior: ExpectedBehavior,
}

/// Result of executing a WebSocket fuzz case against a live server.
#[derive(Debug, Clone)]
pub struct WsFuzzResult {
    pub case: WsFuzzCase,
    pub actual_response: Vec<WsMessage>,
    pub anomaly_detected: bool,
}

/// WebSocket state machine fuzzer v2 with protocol inference and targeted test generation.
///
/// Observes message sequences to infer a state machine, then generates
/// transition tests (wrong types, out-of-order), confusion tests (binary
/// when text expected, oversized frames), subscription abuse tests, and
/// race condition tests.
pub struct WsStateMachineV2;

impl WsStateMachineV2 {
    /// Infer a state machine from an observed message sequence.
    ///
    /// Groups consecutive messages into states based on type transitions.
    /// Each time the message type changes, a new state is created. Transitions
    /// are recorded between adjacent states with the triggering message.
    pub fn observe(messages: &[WsMessage]) -> WsStateMachine {
        if messages.is_empty() {
            return WsStateMachine {
                states: vec![WsState {
                    id: 0,
                    name: "empty".to_string(),
                    observed_messages: Vec::new(),
                }],
                transitions: Vec::new(),
                initial_state: 0,
            };
        }

        let mut states: Vec<WsState> = Vec::new();
        let mut transitions: Vec<WsTransition> = Vec::new();
        let mut current_type = messages[0].type_tag();
        let mut current_messages: Vec<WsMessage> = vec![messages[0].clone()];
        let mut state_id: u32 = 0;

        for msg in messages.iter().skip(1) {
            if msg.type_tag() != current_type {
                states.push(WsState {
                    id: state_id,
                    name: format!("state_{state_id}_{current_type}"),
                    observed_messages: current_messages.clone(),
                });

                let next_id = state_id + 1;
                transitions.push(WsTransition {
                    from_state: state_id,
                    to_state: next_id,
                    trigger_message: msg.clone(),
                });

                state_id = next_id;
                current_type = msg.type_tag();
                current_messages = vec![msg.clone()];
            } else {
                current_messages.push(msg.clone());
            }
        }

        states.push(WsState {
            id: state_id,
            name: format!("state_{state_id}_{current_type}"),
            observed_messages: current_messages,
        });

        WsStateMachine {
            states,
            transitions,
            initial_state: 0,
        }
    }

    /// Generate transition tests for each state in the machine.
    ///
    /// For each state, sends the wrong message type (binary when text expected
    /// and vice versa) and sends messages out of the expected order.
    pub fn generate_transition_tests(machine: &WsStateMachine) -> Vec<WsFuzzCase> {
        let mut cases = Vec::new();

        for state in &machine.states {
            if state.observed_messages.is_empty() {
                continue;
            }

            let expected_type = state.observed_messages[0].type_tag();

            let wrong_type_msg = match expected_type {
                "text" => WsMessage::Binary(vec![0xFF; 64]),
                "binary" => WsMessage::Text("{\"malformed\": true}".to_string()),
                _ => WsMessage::Text("unexpected".to_string()),
            };

            cases.push(WsFuzzCase {
                description: format!(
                    "Wrong type at state '{}': send {} when {} expected",
                    state.name,
                    wrong_type_msg.type_tag(),
                    expected_type,
                ),
                messages: vec![wrong_type_msg],
                expected_behavior: ExpectedBehavior::ErrorResponse,
            });

            if machine.transitions.len() >= 2 {
                let reversed: Vec<WsMessage> = machine
                    .transitions
                    .iter()
                    .rev()
                    .map(|t| t.trigger_message.clone())
                    .collect();

                cases.push(WsFuzzCase {
                    description: format!("Reversed transition order at state '{}'", state.name),
                    messages: reversed,
                    expected_behavior: ExpectedBehavior::ErrorResponse,
                });
            }

            cases.push(WsFuzzCase {
                description: format!("Ping during state '{}'", state.name),
                messages: vec![WsMessage::Ping],
                expected_behavior: ExpectedBehavior::NoEffect,
            });
        }

        cases
    }

    /// Generate confusion tests targeting parser and framing edge cases.
    ///
    /// Sends binary when text is expected, oversized frames, null bytes
    /// inside text messages, and malformed JSON.
    pub fn generate_confusion_tests(machine: &WsStateMachine) -> Vec<WsFuzzCase> {
        let mut cases = Vec::new();

        let has_text = machine
            .states
            .iter()
            .any(|s| s.observed_messages.iter().any(|m| m.type_tag() == "text"));

        if has_text {
            cases.push(WsFuzzCase {
                description: "Binary frame when text expected".to_string(),
                messages: vec![WsMessage::Binary(vec![0xDE, 0xAD, 0xBE, 0xEF])],
                expected_behavior: ExpectedBehavior::ErrorResponse,
            });
        }

        cases.push(WsFuzzCase {
            description: "Oversized text frame (1MB)".to_string(),
            messages: vec![WsMessage::Text("A".repeat(1024 * 1024))],
            expected_behavior: ExpectedBehavior::Disconnect,
        });

        cases.push(WsFuzzCase {
            description: "Oversized binary frame (1MB)".to_string(),
            messages: vec![WsMessage::Binary(vec![0x41; 1024 * 1024])],
            expected_behavior: ExpectedBehavior::Disconnect,
        });

        cases.push(WsFuzzCase {
            description: "Null bytes in text message".to_string(),
            messages: vec![WsMessage::Text("data\x00injected\x00payload".to_string())],
            expected_behavior: ExpectedBehavior::ErrorResponse,
        });

        cases.push(WsFuzzCase {
            description: "Malformed JSON in text message".to_string(),
            messages: vec![WsMessage::Text("{\"key\": \"value\"".to_string())],
            expected_behavior: ExpectedBehavior::ErrorResponse,
        });

        cases.push(WsFuzzCase {
            description: "Empty text message".to_string(),
            messages: vec![WsMessage::Text(String::new())],
            expected_behavior: ExpectedBehavior::NoEffect,
        });

        cases.push(WsFuzzCase {
            description: "Empty binary message".to_string(),
            messages: vec![WsMessage::Binary(Vec::new())],
            expected_behavior: ExpectedBehavior::NoEffect,
        });

        cases.push(WsFuzzCase {
            description: "Close with invalid code".to_string(),
            messages: vec![WsMessage::Close(9999, "invalid code".to_string())],
            expected_behavior: ExpectedBehavior::Disconnect,
        });

        cases
    }

    /// Generate subscription abuse tests for pub/sub WebSocket protocols.
    ///
    /// Tests over-subscription (subscribing to many channels), cross-subscriber
    /// data leakage, and wildcard subscription patterns.
    pub fn generate_subscription_abuse(channels: &[String]) -> Vec<WsFuzzCase> {
        let mut cases = Vec::new();

        if channels.is_empty() {
            return cases;
        }

        let mass_subscribe: Vec<WsMessage> = channels
            .iter()
            .map(|ch| WsMessage::Text(format!(r#"{{"action":"subscribe","channel":"{ch}"}}"#)))
            .collect();

        cases.push(WsFuzzCase {
            description: format!("Over-subscribe to all {} channels", channels.len()),
            messages: mass_subscribe,
            expected_behavior: ExpectedBehavior::ErrorResponse,
        });

        for ch in channels {
            cases.push(WsFuzzCase {
                description: format!("Cross-subscriber leakage probe on '{ch}'"),
                messages: vec![
                    WsMessage::Text(format!(r#"{{"action":"subscribe","channel":"{ch}"}}"#)),
                    WsMessage::Text(format!(
                        r#"{{"action":"publish","channel":"{ch}","data":"probe_{{UNIQUE}}"}}"#
                    )),
                ],
                expected_behavior: ExpectedBehavior::DataLeak,
            });
        }

        let wildcard_patterns = ["*", "#", "**", ".."];
        for pattern in wildcard_patterns {
            cases.push(WsFuzzCase {
                description: format!("Wildcard subscription '{pattern}'"),
                messages: vec![WsMessage::Text(format!(
                    r#"{{"action":"subscribe","channel":"{pattern}"}}"#
                ))],
                expected_behavior: ExpectedBehavior::ErrorResponse,
            });
        }

        cases.push(WsFuzzCase {
            description: "Unsubscribe from channel never subscribed to".to_string(),
            messages: vec![WsMessage::Text(
                r#"{"action":"unsubscribe","channel":"nonexistent_channel_xyz"}"#.to_string(),
            )],
            expected_behavior: ExpectedBehavior::NoEffect,
        });

        if let Some(first_ch) = channels.first() {
            let rapid_sub_unsub: Vec<WsMessage> = (0..20)
                .flat_map(|_| {
                    vec![
                        WsMessage::Text(format!(
                            r#"{{"action":"subscribe","channel":"{first_ch}"}}"#
                        )),
                        WsMessage::Text(format!(
                            r#"{{"action":"unsubscribe","channel":"{first_ch}"}}"#
                        )),
                    ]
                })
                .collect();
            cases.push(WsFuzzCase {
                description: format!("Rapid subscribe/unsubscribe cycling on '{first_ch}'"),
                messages: rapid_sub_unsub,
                expected_behavior: ExpectedBehavior::NoEffect,
            });
        }

        cases
    }

    /// Generate race condition tests with conflicting simultaneous transitions.
    ///
    /// Creates message pairs that trigger conflicting state changes when
    /// sent in rapid succession, testing server-side synchronization.
    pub fn generate_race_tests(machine: &WsStateMachine) -> Vec<WsFuzzCase> {
        let mut cases = Vec::new();

        if machine.transitions.len() < 2 {
            cases.push(WsFuzzCase {
                description: "Duplicate message race".to_string(),
                messages: vec![
                    WsMessage::Text("race_message_a".to_string()),
                    WsMessage::Text("race_message_a".to_string()),
                ],
                expected_behavior: ExpectedBehavior::NoEffect,
            });
            return cases;
        }

        for i in 0..machine.transitions.len() {
            for j in (i + 1)..machine.transitions.len() {
                let t1 = &machine.transitions[i];
                let t2 = &machine.transitions[j];

                cases.push(WsFuzzCase {
                    description: format!(
                        "Simultaneous transitions: state {} -> {} AND state {} -> {}",
                        t1.from_state, t1.to_state, t2.from_state, t2.to_state,
                    ),
                    messages: vec![t1.trigger_message.clone(), t2.trigger_message.clone()],
                    expected_behavior: ExpectedBehavior::StateChange,
                });
            }
        }

        for t in &machine.transitions {
            cases.push(WsFuzzCase {
                description: format!(
                    "Rapid-fire duplicate transition {} -> {}",
                    t.from_state, t.to_state,
                ),
                messages: vec![
                    t.trigger_message.clone(),
                    t.trigger_message.clone(),
                    t.trigger_message.clone(),
                ],
                expected_behavior: ExpectedBehavior::ErrorResponse,
            });
        }

        if let (Some(last_t), Some(first_t)) =
            (machine.transitions.last(), machine.transitions.first())
        {
            cases.push(WsFuzzCase {
                description: "Reverse-order transition race (last then first)".to_string(),
                messages: vec![
                    last_t.trigger_message.clone(),
                    first_t.trigger_message.clone(),
                ],
                expected_behavior: ExpectedBehavior::ErrorResponse,
            });
        }

        cases
    }
}

/// Detect anomalies in a fuzz result by comparing actual response to expected behavior.
pub fn detect_anomaly(result: &WsFuzzResult) -> bool {
    result.anomaly_detected
}

/// Build a `WsFuzzResult` from a case and the server's actual response.
pub fn build_fuzz_result(case: WsFuzzCase, actual_response: Vec<WsMessage>) -> WsFuzzResult {
    let anomaly = match case.expected_behavior {
        ExpectedBehavior::ErrorResponse => !actual_response.iter().any(|m| {
            if let WsMessage::Text(s) = m {
                s.to_lowercase().contains("error")
            } else {
                false
            }
        }),
        ExpectedBehavior::Disconnect => !actual_response.is_empty(),
        ExpectedBehavior::DataLeak => actual_response.iter().any(|m| {
            if let WsMessage::Text(s) = m {
                s.contains("probe_")
            } else {
                false
            }
        }),
        ExpectedBehavior::StateChange | ExpectedBehavior::NoEffect => false,
    };

    WsFuzzResult {
        case,
        actual_response,
        anomaly_detected: anomaly,
    }
}

#[cfg(test)]
#[path = "ws_state_machine_v2_test.rs"]
mod ws_state_machine_v2_test;
