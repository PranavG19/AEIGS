/// WebSocket-based team collaboration protocol for live attack graph sharing,
/// instant finding broadcast, and chat/annotations across distributed AEGIS operators.
///
/// Enables multiple operators to observe and contribute to the same scan session
/// in real time. Messages are serialized as JSON for WebSocket transport. The
/// session enforces role-based access: Operators can broadcast findings and chat,
/// Observers have read-only access, and Admins can manage participants.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Hard ceiling on concurrent participants per session to bound memory and fan-out.
pub const MAX_PARTICIPANTS: usize = 32;

/// Discriminant for every message that flows through a collaboration session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollabMessageType {
    GraphUpdate,
    FindingBroadcast,
    ChatMessage,
    Annotation,
    CursorPosition,
    SessionJoin,
    SessionLeave,
    Ping,
    Pong,
}

/// A single collaboration message exchanged over the WebSocket channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollabMessage {
    pub msg_type: CollabMessageType,
    pub sender_id: String,
    pub session_id: String,
    pub timestamp_ms: u64,
    pub payload: Value,
}

impl CollabMessage {
    fn now_ms() -> u64 {
        std::time::SystemTime::UNIX_EPOCH
            .elapsed()
            .unwrap()
            .as_millis() as u64
    }
}

/// Role assigned to a participant controlling what actions they may perform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollabRole {
    /// Full read-write access: can broadcast findings, send chat, add annotations.
    Operator,
    /// Read-only presence: can observe the graph and findings but cannot modify state.
    Observer,
    /// Superset of Operator with participant management privileges.
    Admin,
}

/// A human (or automated agent) participating in a collaboration session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    pub user_id: String,
    pub display_name: String,
    pub role: CollabRole,
    pub cursor_position: Option<(f64, f64)>,
    pub joined_at: u64,
}

/// Classification of an annotation attached to a graph node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnnotationType {
    Note,
    Flag,
    Question,
    ActionItem,
}

/// A user-authored annotation pinned to a specific node in the attack graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub id: String,
    pub author_id: String,
    pub target_node_id: String,
    pub content: String,
    pub timestamp_ms: u64,
    pub annotation_type: AnnotationType,
}

/// Errors arising from collaboration session operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollabError {
    /// Session has reached `MAX_PARTICIPANTS`.
    SessionFull,
    /// A participant with the same `user_id` already exists in the session.
    DuplicateParticipant,
    /// The referenced participant was not found in the session roster.
    ParticipantNotFound,
    /// The participant's role does not permit the requested action.
    UnauthorizedAction,
    /// The message failed validation (empty payload, missing fields, etc.).
    InvalidMessage,
}

impl std::fmt::Display for CollabError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CollabError::SessionFull => write!(f, "session is full ({MAX_PARTICIPANTS} max)"),
            CollabError::DuplicateParticipant => write!(f, "participant already in session"),
            CollabError::ParticipantNotFound => write!(f, "participant not found"),
            CollabError::UnauthorizedAction => write!(f, "role does not permit this action"),
            CollabError::InvalidMessage => write!(f, "invalid message"),
        }
    }
}

impl std::error::Error for CollabError {}

/// A live collaboration session tying participants to a shared attack graph.
#[derive(Debug, Clone)]
pub struct CollabSession {
    pub session_id: String,
    pub participants: Vec<Participant>,
    pub shared_graph_id: String,
    pub message_log: Vec<CollabMessage>,
    pub created_at: u64,
    pub annotations: HashMap<String, Annotation>,
}

impl CollabSession {
    /// Create a fresh session bound to the given graph.
    pub fn new(session_id: impl Into<String>, graph_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            participants: Vec::new(),
            shared_graph_id: graph_id.into(),
            message_log: Vec::new(),
            created_at: CollabMessage::now_ms(),
            annotations: HashMap::new(),
        }
    }

    /// Register a participant, emitting a `SessionJoin` message on success.
    pub fn add_participant(&mut self, participant: Participant) -> Result<(), CollabError> {
        if self.participants.len() >= MAX_PARTICIPANTS {
            return Err(CollabError::SessionFull);
        }
        if self
            .participants
            .iter()
            .any(|p| p.user_id == participant.user_id)
        {
            return Err(CollabError::DuplicateParticipant);
        }
        let join_msg = CollabMessage {
            msg_type: CollabMessageType::SessionJoin,
            sender_id: participant.user_id.clone(),
            session_id: self.session_id.clone(),
            timestamp_ms: CollabMessage::now_ms(),
            payload: serde_json::json!({
                "display_name": participant.display_name,
                "role": participant.role,
            }),
        };
        self.participants.push(participant);
        self.message_log.push(join_msg);
        Ok(())
    }

    /// Remove a participant by user_id, emitting a `SessionLeave` message. Returns the removed participant.
    pub fn remove_participant(&mut self, user_id: &str) -> Result<Participant, CollabError> {
        let idx = self
            .participants
            .iter()
            .position(|p| p.user_id == user_id)
            .ok_or(CollabError::ParticipantNotFound)?;
        let removed = self.participants.remove(idx);
        let leave_msg = CollabMessage {
            msg_type: CollabMessageType::SessionLeave,
            sender_id: removed.user_id.clone(),
            session_id: self.session_id.clone(),
            timestamp_ms: CollabMessage::now_ms(),
            payload: serde_json::json!({
                "display_name": removed.display_name,
            }),
        };
        self.message_log.push(leave_msg);
        Ok(removed)
    }

    /// Broadcast a finding to all session participants and log the message.
    pub fn broadcast_finding(&mut self, sender_id: &str, finding_json: Value) -> CollabMessage {
        let msg = CollabMessage {
            msg_type: CollabMessageType::FindingBroadcast,
            sender_id: sender_id.to_owned(),
            session_id: self.session_id.clone(),
            timestamp_ms: CollabMessage::now_ms(),
            payload: finding_json,
        };
        self.message_log.push(msg.clone());
        msg
    }

    /// Broadcast a graph mutation (add node, add edge, etc.) to all participants.
    pub fn broadcast_graph_update(
        &mut self,
        sender_id: &str,
        operations_json: Value,
    ) -> CollabMessage {
        let msg = CollabMessage {
            msg_type: CollabMessageType::GraphUpdate,
            sender_id: sender_id.to_owned(),
            session_id: self.session_id.clone(),
            timestamp_ms: CollabMessage::now_ms(),
            payload: operations_json,
        };
        self.message_log.push(msg.clone());
        msg
    }

    /// Send a chat message. Observers are forbidden from chatting.
    pub fn send_chat(&mut self, sender_id: &str, text: &str) -> Result<CollabMessage, CollabError> {
        let participant = self
            .participants
            .iter()
            .find(|p| p.user_id == sender_id)
            .ok_or(CollabError::ParticipantNotFound)?;
        if participant.role == CollabRole::Observer {
            return Err(CollabError::UnauthorizedAction);
        }
        if text.is_empty() {
            return Err(CollabError::InvalidMessage);
        }
        let msg = CollabMessage {
            msg_type: CollabMessageType::ChatMessage,
            sender_id: sender_id.to_owned(),
            session_id: self.session_id.clone(),
            timestamp_ms: CollabMessage::now_ms(),
            payload: serde_json::json!({ "text": text }),
        };
        self.message_log.push(msg.clone());
        Ok(msg)
    }

    /// Attach an annotation to a graph node. The annotation id must be unique within the session.
    pub fn add_annotation(&mut self, annotation: Annotation) -> Result<(), CollabError> {
        if self.annotations.contains_key(&annotation.id) {
            return Err(CollabError::InvalidMessage);
        }
        let msg = CollabMessage {
            msg_type: CollabMessageType::Annotation,
            sender_id: annotation.author_id.clone(),
            session_id: self.session_id.clone(),
            timestamp_ms: CollabMessage::now_ms(),
            payload: serde_json::json!({
                "annotation_id": annotation.id,
                "target_node_id": annotation.target_node_id,
                "content": annotation.content,
                "annotation_type": annotation.annotation_type,
            }),
        };
        self.annotations.insert(annotation.id.clone(), annotation);
        self.message_log.push(msg);
        Ok(())
    }

    /// Retrieve all annotations pinned to a specific graph node.
    pub fn get_annotations_for_node(&self, node_id: &str) -> Vec<&Annotation> {
        self.annotations
            .values()
            .filter(|a| a.target_node_id == node_id)
            .collect()
    }

    /// Total messages exchanged in the session (joins, leaves, findings, chat, etc.).
    pub fn message_count(&self) -> usize {
        self.message_log.len()
    }

    /// Current number of participants.
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }

    /// Render a human-readable transcript of the entire session for archival or export.
    pub fn export_session_log(&self) -> String {
        let mut lines: Vec<String> = Vec::with_capacity(self.message_log.len() + 4);
        lines.push(format!(
            "=== Collaboration Session: {} ===",
            self.session_id
        ));
        lines.push(format!("Graph: {}", self.shared_graph_id));
        lines.push(format!(
            "Participants: {}",
            self.participants
                .iter()
                .map(|p| format!("{} ({:?})", p.display_name, p.role))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        lines.push(String::new());

        for msg in &self.message_log {
            let prefix = format!("[{}] {}", msg.timestamp_ms, msg.sender_id);
            let body = match &msg.msg_type {
                CollabMessageType::SessionJoin => {
                    let name = msg
                        .payload
                        .get("display_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    format!("{prefix} joined ({name})")
                }
                CollabMessageType::SessionLeave => {
                    let name = msg
                        .payload
                        .get("display_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    format!("{prefix} left ({name})")
                }
                CollabMessageType::ChatMessage => {
                    let text = msg
                        .payload
                        .get("text")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    format!("{prefix} [chat]: {text}")
                }
                CollabMessageType::FindingBroadcast => {
                    format!("{prefix} [finding]: {}", msg.payload)
                }
                CollabMessageType::GraphUpdate => {
                    format!("{prefix} [graph-update]: {}", msg.payload)
                }
                CollabMessageType::Annotation => {
                    let content = msg
                        .payload
                        .get("content")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    format!("{prefix} [annotation]: {content}")
                }
                CollabMessageType::CursorPosition => {
                    format!("{prefix} [cursor]")
                }
                CollabMessageType::Ping => format!("{prefix} [ping]"),
                CollabMessageType::Pong => format!("{prefix} [pong]"),
            };
            lines.push(body);
        }

        lines.push(String::new());
        lines.push(format!("Total messages: {}", self.message_log.len()));
        lines.join("\n")
    }
}
