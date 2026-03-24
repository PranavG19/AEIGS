use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// WebSocket state machine fuzzer.
//
// WebSocket-based applications maintain server-side state that changes
// as messages flow. This module models the state machine from observed
// message sequences, then systematically probes for:
//
// 1. Invalid state transitions (send a message that shouldn't be
//    allowed in the current state — e.g., "place_order" before "login")
// 2. Out-of-order message sequences that bypass business logic
// 3. Race conditions from parallel messages
// 4. Message mutation (valid structure, malicious content)
// 5. Authentication bypass via reconnection or session replay
//
// The key insight: most WebSocket APIs don't validate state transitions
// on the server. They assume the client will follow the expected flow.
// We don't follow the expected flow.

/// A unique state in the WebSocket protocol state machine.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WsState {
    pub id: String,
    pub name: String,
    pub is_initial: bool,
    pub is_terminal: bool,
    pub is_authenticated: bool,
}

impl fmt::Display for WsState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// A message type observed in the WebSocket protocol.
#[derive(Debug, Clone)]
pub struct WsMessageType {
    pub id: String,
    pub name: String,
    pub direction: MessageDirection,
    pub schema: Option<String>,
    pub requires_auth: bool,
    pub example_payload: String,
}

impl fmt::Display for WsMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.direction)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageDirection {
    ClientToServer,
    ServerToClient,
    Bidirectional,
}

impl fmt::Display for MessageDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientToServer => write!(f, "C→S"),
            Self::ServerToClient => write!(f, "S→C"),
            Self::Bidirectional => write!(f, "C↔S"),
        }
    }
}

/// A transition between states triggered by a message.
#[derive(Debug, Clone)]
pub struct WsTransition {
    pub from_state: String,
    pub to_state: String,
    pub message_type: String,
    pub observed_count: usize,
    pub is_valid: bool,
}

impl fmt::Display for WsTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} --[{}]--> {} (seen {}x)",
            self.from_state, self.message_type, self.to_state, self.observed_count
        )
    }
}

/// The inferred state machine model.
#[derive(Debug, Clone)]
pub struct WsStateMachine {
    pub states: Vec<WsState>,
    pub message_types: Vec<WsMessageType>,
    pub transitions: Vec<WsTransition>,
    pub initial_state: String,
}

impl WsStateMachine {
    pub fn new(initial_state: &str) -> Self {
        Self {
            states: vec![WsState {
                id: initial_state.to_string(),
                name: initial_state.to_string(),
                is_initial: true,
                is_terminal: false,
                is_authenticated: false,
            }],
            message_types: Vec::new(),
            transitions: Vec::new(),
            initial_state: initial_state.to_string(),
        }
    }

    pub fn add_state(&mut self, state: WsState) {
        if !self.states.iter().any(|s| s.id == state.id) {
            self.states.push(state);
        }
    }

    pub fn add_message_type(&mut self, msg: WsMessageType) {
        if !self.message_types.iter().any(|m| m.id == msg.id) {
            self.message_types.push(msg);
        }
    }

    pub fn add_transition(&mut self, transition: WsTransition) {
        if let Some(existing) = self.transitions.iter_mut().find(|t| {
            t.from_state == transition.from_state
                && t.to_state == transition.to_state
                && t.message_type == transition.message_type
        }) {
            existing.observed_count += transition.observed_count;
        } else {
            self.transitions.push(transition);
        }
    }

    /// All message types that should be valid in a given state.
    pub fn valid_messages_for_state(&self, state_id: &str) -> Vec<&WsTransition> {
        self.transitions
            .iter()
            .filter(|t| t.from_state == state_id && t.is_valid)
            .collect()
    }

    /// All message types that have NEVER been observed from a given state.
    pub fn invalid_messages_for_state(&self, state_id: &str) -> Vec<&WsMessageType> {
        let valid_msg_ids: HashSet<&str> = self
            .transitions
            .iter()
            .filter(|t| t.from_state == state_id)
            .map(|t| t.message_type.as_str())
            .collect();

        self.message_types
            .iter()
            .filter(|m| {
                m.direction != MessageDirection::ServerToClient
                    && !valid_msg_ids.contains(m.id.as_str())
            })
            .collect()
    }

    /// Find all paths from initial state to a target state.
    pub fn paths_to_state(&self, target: &str, max_depth: usize) -> Vec<Vec<String>> {
        let mut results = Vec::new();
        let mut queue: VecDeque<(String, Vec<String>)> = VecDeque::new();
        queue.push_back((self.initial_state.clone(), vec![self.initial_state.clone()]));

        while let Some((current, path)) = queue.pop_front() {
            if current == target {
                results.push(path);
                continue;
            }
            if path.len() > max_depth {
                continue;
            }

            for transition in self.transitions.iter().filter(|t| t.from_state == current) {
                if !path.contains(&transition.to_state) {
                    let mut new_path = path.clone();
                    new_path.push(transition.to_state.clone());
                    queue.push_back((transition.to_state.clone(), new_path));
                }
            }
        }

        results
    }

    /// Find states that can be reached without going through any
    /// authenticated state — potential auth bypasses.
    pub fn unauthenticated_reachable(&self) -> Vec<&WsState> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<String> = VecDeque::new();
        queue.push_back(self.initial_state.clone());

        while let Some(current) = queue.pop_front() {
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current.clone());

            let state = self.states.iter().find(|s| s.id == current);
            if let Some(s) = state
                && s.is_authenticated
            {
                continue;
            }

            for transition in self.transitions.iter().filter(|t| t.from_state == current) {
                if !visited.contains(&transition.to_state) {
                    queue.push_back(transition.to_state.clone());
                }
            }
        }

        self.states
            .iter()
            .filter(|s| visited.contains(&s.id) && !s.is_initial)
            .collect()
    }

    /// Count states and transitions for summary.
    pub fn stats(&self) -> StateMachineStats {
        let auth_states = self.states.iter().filter(|s| s.is_authenticated).count();
        let terminal_states = self.states.iter().filter(|s| s.is_terminal).count();
        let client_msgs = self
            .message_types
            .iter()
            .filter(|m| m.direction != MessageDirection::ServerToClient)
            .count();
        let auth_required_msgs = self
            .message_types
            .iter()
            .filter(|m| m.requires_auth)
            .count();

        StateMachineStats {
            state_count: self.states.len(),
            transition_count: self.transitions.len(),
            message_type_count: self.message_types.len(),
            auth_state_count: auth_states,
            terminal_state_count: terminal_states,
            client_message_count: client_msgs,
            auth_required_message_count: auth_required_msgs,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StateMachineStats {
    pub state_count: usize,
    pub transition_count: usize,
    pub message_type_count: usize,
    pub auth_state_count: usize,
    pub terminal_state_count: usize,
    pub client_message_count: usize,
    pub auth_required_message_count: usize,
}

/// Category of WebSocket fuzzing attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WsFuzzCategory {
    /// Send message that shouldn't be valid in current state
    InvalidTransition,
    /// Skip required steps (e.g., go straight to checkout)
    SequenceSkip,
    /// Replay a message from a previous state
    MessageReplay,
    /// Send concurrent messages to trigger race conditions
    RaceCondition,
    /// Reconnect without re-authenticating
    SessionReplay,
    /// Inject attack payload into message fields
    MessageInjection,
    /// Send binary frame where text expected (or vice versa)
    FrameTypeConfusion,
    /// Send oversized or malformed frames
    ProtocolAbuse,
    /// Close/reopen connection mid-transaction
    ConnectionManipulation,
    /// Send messages as different user/session
    AuthorizationBypass,
}

impl fmt::Display for WsFuzzCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition => write!(f, "Invalid Transition"),
            Self::SequenceSkip => write!(f, "Sequence Skip"),
            Self::MessageReplay => write!(f, "Message Replay"),
            Self::RaceCondition => write!(f, "Race Condition"),
            Self::SessionReplay => write!(f, "Session Replay"),
            Self::MessageInjection => write!(f, "Message Injection"),
            Self::FrameTypeConfusion => write!(f, "Frame Type Confusion"),
            Self::ProtocolAbuse => write!(f, "Protocol Abuse"),
            Self::ConnectionManipulation => write!(f, "Connection Manipulation"),
            Self::AuthorizationBypass => write!(f, "Authorization Bypass"),
        }
    }
}

impl WsFuzzCategory {
    pub fn all() -> &'static [Self] {
        &[
            Self::InvalidTransition,
            Self::SequenceSkip,
            Self::MessageReplay,
            Self::RaceCondition,
            Self::SessionReplay,
            Self::MessageInjection,
            Self::FrameTypeConfusion,
            Self::ProtocolAbuse,
            Self::ConnectionManipulation,
            Self::AuthorizationBypass,
        ]
    }
}

/// A generated WebSocket fuzz test case.
#[derive(Debug, Clone)]
pub struct WsFuzzCase {
    pub id: String,
    pub category: WsFuzzCategory,
    pub description: String,
    pub precondition_state: String,
    pub message_sequence: Vec<FuzzMessage>,
    pub expected_behavior: ExpectedBehavior,
    pub severity: Severity,
}

#[derive(Debug, Clone)]
pub struct FuzzMessage {
    pub message_type: String,
    pub payload: String,
    pub delay_ms: u64,
    pub expect_response: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedBehavior {
    Rejected,
    ErrorResponse,
    ConnectionClosed,
    ServerCrash,
    Allowed,
}

impl fmt::Display for ExpectedBehavior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected => write!(f, "Should be rejected"),
            Self::ErrorResponse => write!(f, "Should return error"),
            Self::ConnectionClosed => write!(f, "Should close connection"),
            Self::ServerCrash => write!(f, "May crash server"),
            Self::Allowed => write!(f, "May be allowed (vuln)"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "Info"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// Generate all fuzz test cases for a given state machine model.
pub fn generate_fuzz_cases(machine: &WsStateMachine) -> Vec<WsFuzzCase> {
    let mut cases = Vec::new();
    let mut case_id = 0;

    cases.extend(generate_invalid_transitions(machine, &mut case_id));
    cases.extend(generate_sequence_skips(machine, &mut case_id));
    cases.extend(generate_message_replays(machine, &mut case_id));
    cases.extend(generate_race_conditions(machine, &mut case_id));
    cases.extend(generate_session_replay(machine, &mut case_id));
    cases.extend(generate_message_injections(machine, &mut case_id));
    cases.extend(generate_protocol_abuse(&mut case_id));
    cases.extend(generate_connection_manipulation(machine, &mut case_id));

    cases
}

fn next_id(counter: &mut usize) -> String {
    *counter += 1;
    format!("ws-{:04}", counter)
}

fn generate_invalid_transitions(machine: &WsStateMachine, counter: &mut usize) -> Vec<WsFuzzCase> {
    let mut cases = Vec::new();

    for state in &machine.states {
        let invalid_msgs = machine.invalid_messages_for_state(&state.id);
        for msg in invalid_msgs {
            cases.push(WsFuzzCase {
                id: next_id(counter),
                category: WsFuzzCategory::InvalidTransition,
                description: format!(
                    "Send '{}' message in state '{}' where it's not expected",
                    msg.name, state.name
                ),
                precondition_state: state.id.clone(),
                message_sequence: vec![FuzzMessage {
                    message_type: msg.id.clone(),
                    payload: msg.example_payload.clone(),
                    delay_ms: 0,
                    expect_response: true,
                }],
                expected_behavior: ExpectedBehavior::Rejected,
                severity: if msg.requires_auth && !state.is_authenticated {
                    Severity::High
                } else {
                    Severity::Medium
                },
            });
        }
    }

    cases
}

fn generate_sequence_skips(machine: &WsStateMachine, counter: &mut usize) -> Vec<WsFuzzCase> {
    let mut cases = Vec::new();

    let terminal_states: Vec<&WsState> = machine
        .states
        .iter()
        .filter(|s| s.is_terminal || s.is_authenticated)
        .collect();

    for target in &terminal_states {
        let auth_messages: Vec<&WsMessageType> = machine
            .message_types
            .iter()
            .filter(|m| m.requires_auth && m.direction != MessageDirection::ServerToClient)
            .collect();

        for msg in &auth_messages {
            cases.push(WsFuzzCase {
                id: next_id(counter),
                category: WsFuzzCategory::SequenceSkip,
                description: format!(
                    "Skip directly to '{}' by sending '{}' from initial state",
                    target.name, msg.name
                ),
                precondition_state: machine.initial_state.clone(),
                message_sequence: vec![FuzzMessage {
                    message_type: msg.id.clone(),
                    payload: msg.example_payload.clone(),
                    delay_ms: 0,
                    expect_response: true,
                }],
                expected_behavior: ExpectedBehavior::Rejected,
                severity: Severity::High,
            });
        }
    }

    cases
}

fn generate_message_replays(machine: &WsStateMachine, counter: &mut usize) -> Vec<WsFuzzCase> {
    let mut cases = Vec::new();

    let client_msgs: Vec<&WsMessageType> = machine
        .message_types
        .iter()
        .filter(|m| m.direction != MessageDirection::ServerToClient)
        .collect();

    for msg in &client_msgs {
        cases.push(WsFuzzCase {
            id: next_id(counter),
            category: WsFuzzCategory::MessageReplay,
            description: format!("Replay '{}' message twice in sequence", msg.name),
            precondition_state: machine.initial_state.clone(),
            message_sequence: vec![
                FuzzMessage {
                    message_type: msg.id.clone(),
                    payload: msg.example_payload.clone(),
                    delay_ms: 0,
                    expect_response: true,
                },
                FuzzMessage {
                    message_type: msg.id.clone(),
                    payload: msg.example_payload.clone(),
                    delay_ms: 100,
                    expect_response: true,
                },
            ],
            expected_behavior: ExpectedBehavior::ErrorResponse,
            severity: Severity::Medium,
        });
    }

    cases
}

fn generate_race_conditions(machine: &WsStateMachine, counter: &mut usize) -> Vec<WsFuzzCase> {
    let mut cases = Vec::new();

    let client_msgs: Vec<&WsMessageType> = machine
        .message_types
        .iter()
        .filter(|m| m.direction != MessageDirection::ServerToClient)
        .collect();

    for i in 0..client_msgs.len() {
        for j in (i + 1)..client_msgs.len() {
            let msg_a = client_msgs[i];
            let msg_b = client_msgs[j];

            cases.push(WsFuzzCase {
                id: next_id(counter),
                category: WsFuzzCategory::RaceCondition,
                description: format!(
                    "Send '{}' and '{}' simultaneously (0ms delay) to detect TOCTOU",
                    msg_a.name, msg_b.name
                ),
                precondition_state: machine.initial_state.clone(),
                message_sequence: vec![
                    FuzzMessage {
                        message_type: msg_a.id.clone(),
                        payload: msg_a.example_payload.clone(),
                        delay_ms: 0,
                        expect_response: true,
                    },
                    FuzzMessage {
                        message_type: msg_b.id.clone(),
                        payload: msg_b.example_payload.clone(),
                        delay_ms: 0,
                        expect_response: true,
                    },
                ],
                expected_behavior: ExpectedBehavior::ErrorResponse,
                severity: Severity::High,
            });
        }
    }

    cases
}

fn generate_session_replay(machine: &WsStateMachine, counter: &mut usize) -> Vec<WsFuzzCase> {
    let mut cases = Vec::new();

    let has_auth = machine.states.iter().any(|s| s.is_authenticated);
    if !has_auth {
        return cases;
    }

    cases.push(WsFuzzCase {
        id: next_id(counter),
        category: WsFuzzCategory::SessionReplay,
        description: "Reconnect with previously captured session token without re-authenticating"
            .into(),
        precondition_state: machine.initial_state.clone(),
        message_sequence: vec![FuzzMessage {
            message_type: "reconnect_with_old_token".into(),
            payload: r#"{"type":"auth","token":"CAPTURED_SESSION_TOKEN"}"#.into(),
            delay_ms: 0,
            expect_response: true,
        }],
        expected_behavior: ExpectedBehavior::Rejected,
        severity: Severity::Critical,
    });

    cases.push(WsFuzzCase {
        id: next_id(counter),
        category: WsFuzzCategory::SessionReplay,
        description: "Connect with empty/null authentication token".into(),
        precondition_state: machine.initial_state.clone(),
        message_sequence: vec![FuzzMessage {
            message_type: "auth_null_token".into(),
            payload: r#"{"type":"auth","token":null}"#.into(),
            delay_ms: 0,
            expect_response: true,
        }],
        expected_behavior: ExpectedBehavior::Rejected,
        severity: Severity::Critical,
    });

    cases.push(WsFuzzCase {
        id: next_id(counter),
        category: WsFuzzCategory::SessionReplay,
        description: "Connect with JWT alg:none token".into(),
        precondition_state: machine.initial_state.clone(),
        message_sequence: vec![FuzzMessage {
            message_type: "auth_jwt_none".into(),
            payload: r#"{"type":"auth","token":"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."}"#.into(),
            delay_ms: 0,
            expect_response: true,
        }],
        expected_behavior: ExpectedBehavior::Rejected,
        severity: Severity::Critical,
    });

    cases
}

fn generate_message_injections(machine: &WsStateMachine, counter: &mut usize) -> Vec<WsFuzzCase> {
    let mut cases = Vec::new();

    let large_payload_str = format!(r#"{{"data":"{}"}}"#, "A".repeat(100000));
    let injection_payloads: Vec<(&str, &str, Severity)> = vec![
        ("sqli", r#"{"data":"' OR '1'='1' --"}"#, Severity::High),
        (
            "xss",
            r#"{"data":"<script>alert(document.cookie)</script>"}"#,
            Severity::High,
        ),
        ("ssti", r#"{"data":"{{7*7}}"}"#, Severity::High),
        (
            "cmdi",
            r#"{"data":"; cat /etc/passwd"}"#,
            Severity::Critical,
        ),
        ("nosql", r#"{"data":{"$gt":""}}"#, Severity::High),
        (
            "proto_pollution",
            r#"{"__proto__":{"admin":true}}"#,
            Severity::Critical,
        ),
        ("large_payload", &large_payload_str, Severity::Medium),
        (
            "null_bytes",
            r#"{"data":"test\u0000admin"}"#,
            Severity::Medium,
        ),
        (
            "unicode_overflow",
            r#"{"data":"\uFFFF\uFFFE\uFFFD"}"#,
            Severity::Low,
        ),
    ];

    let client_msgs: Vec<&WsMessageType> = machine
        .message_types
        .iter()
        .filter(|m| m.direction != MessageDirection::ServerToClient)
        .collect();

    for msg in &client_msgs {
        for (name, payload, severity) in &injection_payloads {
            cases.push(WsFuzzCase {
                id: next_id(counter),
                category: WsFuzzCategory::MessageInjection,
                description: format!("Inject {} payload into '{}' message", name, msg.name),
                precondition_state: machine.initial_state.clone(),
                message_sequence: vec![FuzzMessage {
                    message_type: msg.id.clone(),
                    payload: payload.to_string(),
                    delay_ms: 0,
                    expect_response: true,
                }],
                expected_behavior: ExpectedBehavior::ErrorResponse,
                severity: *severity,
            });
        }
    }

    cases
}

fn generate_protocol_abuse(counter: &mut usize) -> Vec<WsFuzzCase> {
    vec![
        WsFuzzCase {
            id: next_id(counter),
            category: WsFuzzCategory::ProtocolAbuse,
            description: "Send binary frame where text frame expected".into(),
            precondition_state: "any".into(),
            message_sequence: vec![FuzzMessage {
                message_type: "binary_frame".into(),
                payload: "\\x00\\x01\\x02\\x03\\xff\\xfe".into(),
                delay_ms: 0,
                expect_response: true,
            }],
            expected_behavior: ExpectedBehavior::ErrorResponse,
            severity: Severity::Low,
        },
        WsFuzzCase {
            id: next_id(counter),
            category: WsFuzzCategory::ProtocolAbuse,
            description: "Send ping flood (100 rapid pings)".into(),
            precondition_state: "any".into(),
            message_sequence: (0..100)
                .map(|i| FuzzMessage {
                    message_type: "ping".into(),
                    payload: format!("ping-{}", i),
                    delay_ms: 0,
                    expect_response: false,
                })
                .collect(),
            expected_behavior: ExpectedBehavior::ConnectionClosed,
            severity: Severity::Medium,
        },
        WsFuzzCase {
            id: next_id(counter),
            category: WsFuzzCategory::ProtocolAbuse,
            description: "Send close frame with invalid status code".into(),
            precondition_state: "any".into(),
            message_sequence: vec![FuzzMessage {
                message_type: "close".into(),
                payload: "9999".into(),
                delay_ms: 0,
                expect_response: true,
            }],
            expected_behavior: ExpectedBehavior::ConnectionClosed,
            severity: Severity::Low,
        },
        WsFuzzCase {
            id: next_id(counter),
            category: WsFuzzCategory::ProtocolAbuse,
            description: "Send 10MB text frame to test memory limits".into(),
            precondition_state: "any".into(),
            message_sequence: vec![FuzzMessage {
                message_type: "oversized_text".into(),
                payload: "X".repeat(10_000_000),
                delay_ms: 0,
                expect_response: false,
            }],
            expected_behavior: ExpectedBehavior::ConnectionClosed,
            severity: Severity::Medium,
        },
        WsFuzzCase {
            id: next_id(counter),
            category: WsFuzzCategory::ProtocolAbuse,
            description: "Send continuation frame without initial frame".into(),
            precondition_state: "any".into(),
            message_sequence: vec![FuzzMessage {
                message_type: "continuation".into(),
                payload: "orphan continuation".into(),
                delay_ms: 0,
                expect_response: true,
            }],
            expected_behavior: ExpectedBehavior::ConnectionClosed,
            severity: Severity::Low,
        },
    ]
}

fn generate_connection_manipulation(
    machine: &WsStateMachine,
    counter: &mut usize,
) -> Vec<WsFuzzCase> {
    let mut cases = Vec::new();

    let auth_msgs: Vec<&WsMessageType> = machine
        .message_types
        .iter()
        .filter(|m| m.requires_auth && m.direction != MessageDirection::ServerToClient)
        .collect();

    for msg in &auth_msgs {
        cases.push(WsFuzzCase {
            id: next_id(counter),
            category: WsFuzzCategory::ConnectionManipulation,
            description: format!(
                "Disconnect mid-'{}', reconnect, attempt to resume",
                msg.name
            ),
            precondition_state: machine.initial_state.clone(),
            message_sequence: vec![
                FuzzMessage {
                    message_type: msg.id.clone(),
                    payload: msg.example_payload.clone(),
                    delay_ms: 0,
                    expect_response: false,
                },
                FuzzMessage {
                    message_type: "disconnect".into(),
                    payload: String::new(),
                    delay_ms: 50,
                    expect_response: false,
                },
                FuzzMessage {
                    message_type: "reconnect".into(),
                    payload: String::new(),
                    delay_ms: 100,
                    expect_response: true,
                },
                FuzzMessage {
                    message_type: msg.id.clone(),
                    payload: msg.example_payload.clone(),
                    delay_ms: 0,
                    expect_response: true,
                },
            ],
            expected_behavior: ExpectedBehavior::Rejected,
            severity: Severity::High,
        });
    }

    cases
}

/// Infer a state machine model from observed message sequences.
/// Each sequence is a list of (message_type, direction) pairs observed
/// during a single WebSocket session.
pub fn infer_state_machine(sequences: &[Vec<(String, MessageDirection)>]) -> WsStateMachine {
    let mut machine = WsStateMachine::new("initial");
    let mut all_msgs: HashSet<String> = HashSet::new();
    let mut state_counter = 0;
    let mut state_map: HashMap<Vec<String>, String> = HashMap::new();
    state_map.insert(Vec::new(), "initial".into());

    for sequence in sequences {
        let mut current_state = "initial".to_string();
        let mut history: Vec<String> = Vec::new();

        for (msg_type, direction) in sequence {
            all_msgs.insert(msg_type.clone());

            machine.add_message_type(WsMessageType {
                id: msg_type.clone(),
                name: msg_type.clone(),
                direction: *direction,
                schema: None,
                requires_auth: false,
                example_payload: format!("{{\"type\":\"{}\"}}", msg_type),
            });

            history.push(msg_type.clone());
            let next_state = state_map
                .entry(history.clone())
                .or_insert_with(|| {
                    state_counter += 1;
                    format!("state_{}", state_counter)
                })
                .clone();

            if !machine.states.iter().any(|s| s.id == next_state) {
                machine.add_state(WsState {
                    id: next_state.clone(),
                    name: next_state.clone(),
                    is_initial: false,
                    is_terminal: false,
                    is_authenticated: false,
                });
            }

            machine.add_transition(WsTransition {
                from_state: current_state,
                to_state: next_state.clone(),
                message_type: msg_type.clone(),
                observed_count: 1,
                is_valid: true,
            });

            current_state = next_state;
        }
    }

    machine
}

/// Analyze the state machine for potential vulnerabilities.
#[derive(Debug, Clone)]
pub struct WsAnalysisReport {
    pub total_states: usize,
    pub total_transitions: usize,
    pub total_fuzz_cases: usize,
    pub critical_cases: usize,
    pub high_cases: usize,
    pub medium_cases: usize,
    pub low_cases: usize,
    pub info_cases: usize,
    pub unauthenticated_reachable: usize,
    pub by_category: HashMap<String, usize>,
    pub summary: String,
}

pub fn analyze(machine: &WsStateMachine) -> WsAnalysisReport {
    let cases = generate_fuzz_cases(machine);
    let stats = machine.stats();
    let unauth_reach = machine.unauthenticated_reachable().len();

    let critical = cases
        .iter()
        .filter(|c| c.severity == Severity::Critical)
        .count();
    let high = cases
        .iter()
        .filter(|c| c.severity == Severity::High)
        .count();
    let medium = cases
        .iter()
        .filter(|c| c.severity == Severity::Medium)
        .count();
    let low = cases.iter().filter(|c| c.severity == Severity::Low).count();
    let info = cases
        .iter()
        .filter(|c| c.severity == Severity::Info)
        .count();

    let mut by_category: HashMap<String, usize> = HashMap::new();
    for case in &cases {
        *by_category.entry(case.category.to_string()).or_insert(0) += 1;
    }

    let summary = format!(
        "WebSocket state machine: {} states, {} transitions, {} message types. \
         Generated {} fuzz cases ({} critical, {} high, {} medium, {} low). \
         {} states reachable without authentication.",
        stats.state_count,
        stats.transition_count,
        stats.message_type_count,
        cases.len(),
        critical,
        high,
        medium,
        low,
        unauth_reach
    );

    WsAnalysisReport {
        total_states: stats.state_count,
        total_transitions: stats.transition_count,
        total_fuzz_cases: cases.len(),
        critical_cases: critical,
        high_cases: high,
        medium_cases: medium,
        low_cases: low,
        info_cases: info,
        unauthenticated_reachable: unauth_reach,
        by_category,
        summary,
    }
}

#[cfg(test)]
#[path = "websocket_fuzzer_test.rs"]
mod tests;
