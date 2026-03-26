use crate::collab_protocol::*;

fn make_participant(id: &str, name: &str, role: CollabRole) -> Participant {
    Participant {
        user_id: id.to_owned(),
        display_name: name.to_owned(),
        role,
        cursor_position: None,
        joined_at: 1_700_000_000_000,
    }
}

fn make_annotation(id: &str, author: &str, node: &str, atype: AnnotationType) -> Annotation {
    Annotation {
        id: id.to_owned(),
        author_id: author.to_owned(),
        target_node_id: node.to_owned(),
        content: format!("annotation content for {id}"),
        timestamp_ms: 1_700_000_000_000,
        annotation_type: atype,
    }
}

#[test]
fn session_creation_defaults() {
    let session = CollabSession::new("sess-001", "graph-alpha");
    assert_eq!(session.session_id, "sess-001");
    assert_eq!(session.shared_graph_id, "graph-alpha");
    assert!(session.participants.is_empty());
    assert!(session.message_log.is_empty());
    assert!(session.annotations.is_empty());
    assert!(session.created_at > 0);
}

#[test]
fn add_and_remove_participants() {
    let mut session = CollabSession::new("sess-002", "graph-beta");
    let op = make_participant("u-1", "Kazuki Tanaka", CollabRole::Operator);
    let admin = make_participant("u-2", "Ingrid Solberg", CollabRole::Admin);

    session.add_participant(op).unwrap();
    session.add_participant(admin).unwrap();
    assert_eq!(session.participant_count(), 2);
    assert_eq!(session.message_count(), 2);

    let removed = session.remove_participant("u-1").unwrap();
    assert_eq!(removed.user_id, "u-1");
    assert_eq!(removed.display_name, "Kazuki Tanaka");
    assert_eq!(session.participant_count(), 1);
    assert_eq!(session.message_count(), 3);
}

#[test]
fn duplicate_participant_rejected() {
    let mut session = CollabSession::new("sess-003", "graph-gamma");
    let p1 = make_participant("u-dup", "Renata Oliveira", CollabRole::Operator);
    let p2 = make_participant("u-dup", "Renata Clone", CollabRole::Observer);

    session.add_participant(p1).unwrap();
    let err = session.add_participant(p2).unwrap_err();
    assert_eq!(err, CollabError::DuplicateParticipant);
    assert_eq!(session.participant_count(), 1);
}

#[test]
fn max_participants_enforced() {
    let mut session = CollabSession::new("sess-004", "graph-delta");
    for i in 0..MAX_PARTICIPANTS {
        let p = make_participant(
            &format!("u-{i}"),
            &format!("User {i}"),
            CollabRole::Operator,
        );
        session.add_participant(p).unwrap();
    }
    assert_eq!(session.participant_count(), MAX_PARTICIPANTS);

    let overflow = make_participant("u-overflow", "Too Many", CollabRole::Observer);
    let err = session.add_participant(overflow).unwrap_err();
    assert_eq!(err, CollabError::SessionFull);
}

#[test]
fn broadcast_finding_logged() {
    let mut session = CollabSession::new("sess-005", "graph-epsilon");
    let op = make_participant("u-op", "Dmitri Volkov", CollabRole::Operator);
    session.add_participant(op).unwrap();

    let finding = serde_json::json!({
        "vulnerability_class": "SqlInjection",
        "endpoint": "/api/users",
        "severity": 9.1,
    });
    let msg = session.broadcast_finding("u-op", finding.clone());

    assert_eq!(msg.msg_type, CollabMessageType::FindingBroadcast);
    assert_eq!(msg.sender_id, "u-op");
    assert_eq!(msg.session_id, "sess-005");
    assert_eq!(msg.payload, finding);
    assert!(msg.timestamp_ms > 0);
    assert_eq!(session.message_count(), 2);
}

#[test]
fn broadcast_graph_update_logged() {
    let mut session = CollabSession::new("sess-006", "graph-zeta");
    let admin = make_participant("u-admin", "Yuki Nakamura", CollabRole::Admin);
    session.add_participant(admin).unwrap();

    let ops = serde_json::json!({
        "operations": [
            {"type": "AddNode", "node_type": "Endpoint", "url": "/login"},
            {"type": "AddEdge", "from": 1, "to": 2, "label": "Requests"},
        ]
    });
    let msg = session.broadcast_graph_update("u-admin", ops.clone());

    assert_eq!(msg.msg_type, CollabMessageType::GraphUpdate);
    assert_eq!(msg.payload, ops);
    assert_eq!(session.message_count(), 2);
}

#[test]
fn chat_message_success_and_observer_blocked() {
    let mut session = CollabSession::new("sess-007", "graph-eta");
    let op = make_participant("u-op", "Amara Diallo", CollabRole::Operator);
    let obs = make_participant("u-obs", "Lars Eriksen", CollabRole::Observer);
    session.add_participant(op).unwrap();
    session.add_participant(obs).unwrap();

    let msg = session
        .send_chat("u-op", "Found a blind SQLi on /search")
        .unwrap();
    assert_eq!(msg.msg_type, CollabMessageType::ChatMessage);
    assert_eq!(
        msg.payload.get("text").and_then(|v| v.as_str()),
        Some("Found a blind SQLi on /search")
    );

    let err = session
        .send_chat("u-obs", "I want to chat too")
        .unwrap_err();
    assert_eq!(err, CollabError::UnauthorizedAction);
}

#[test]
fn chat_rejects_empty_text() {
    let mut session = CollabSession::new("sess-008", "graph-theta");
    let op = make_participant("u-op", "Sofia Reyes", CollabRole::Operator);
    session.add_participant(op).unwrap();

    let err = session.send_chat("u-op", "").unwrap_err();
    assert_eq!(err, CollabError::InvalidMessage);
}

#[test]
fn chat_rejects_unknown_sender() {
    let mut session = CollabSession::new("sess-009", "graph-iota");
    let err = session.send_chat("u-ghost", "hello?").unwrap_err();
    assert_eq!(err, CollabError::ParticipantNotFound);
}

#[test]
fn annotations_crud_and_node_query() {
    let mut session = CollabSession::new("sess-010", "graph-kappa");
    let op = make_participant("u-op", "Cheng Wei", CollabRole::Operator);
    session.add_participant(op).unwrap();

    let a1 = make_annotation("ann-1", "u-op", "node-42", AnnotationType::Flag);
    let a2 = make_annotation("ann-2", "u-op", "node-42", AnnotationType::Question);
    let a3 = make_annotation("ann-3", "u-op", "node-99", AnnotationType::ActionItem);

    session.add_annotation(a1).unwrap();
    session.add_annotation(a2).unwrap();
    session.add_annotation(a3).unwrap();

    let node42 = session.get_annotations_for_node("node-42");
    assert_eq!(node42.len(), 2);
    assert!(node42.iter().all(|a| a.target_node_id == "node-42"));

    let node99 = session.get_annotations_for_node("node-99");
    assert_eq!(node99.len(), 1);
    assert_eq!(node99[0].annotation_type, AnnotationType::ActionItem);

    let empty = session.get_annotations_for_node("node-nonexistent");
    assert!(empty.is_empty());
}

#[test]
fn duplicate_annotation_id_rejected() {
    let mut session = CollabSession::new("sess-011", "graph-lambda");
    let a1 = make_annotation("ann-dup", "u-1", "node-1", AnnotationType::Note);
    let a2 = make_annotation("ann-dup", "u-2", "node-2", AnnotationType::Flag);

    session.add_annotation(a1).unwrap();
    let err = session.add_annotation(a2).unwrap_err();
    assert_eq!(err, CollabError::InvalidMessage);
}

#[test]
fn remove_nonexistent_participant_fails() {
    let mut session = CollabSession::new("sess-012", "graph-mu");
    let err = session.remove_participant("u-nobody").unwrap_err();
    assert_eq!(err, CollabError::ParticipantNotFound);
}

#[test]
fn export_session_log_contains_events() {
    let mut session = CollabSession::new("sess-013", "graph-nu");
    let op = make_participant("u-op", "Mei Lin Zhang", CollabRole::Operator);
    let obs = make_participant("u-obs", "Bjorn Haugen", CollabRole::Observer);
    session.add_participant(op).unwrap();
    session.add_participant(obs).unwrap();

    session.send_chat("u-op", "Kicking off recon").unwrap();
    session.broadcast_finding("u-op", serde_json::json!({"vuln": "XSS"}));
    let ann = make_annotation("ann-ex", "u-op", "node-7", AnnotationType::Note);
    session.add_annotation(ann).unwrap();
    session.remove_participant("u-obs").unwrap();

    let log = session.export_session_log();

    assert!(log.contains("Collaboration Session: sess-013"));
    assert!(log.contains("graph-nu"));
    assert!(log.contains("joined"));
    assert!(log.contains("[chat]: Kicking off recon"));
    assert!(log.contains("[finding]"));
    assert!(log.contains("[annotation]"));
    assert!(log.contains("left"));
    assert!(log.contains("Total messages:"));
}

#[test]
fn admin_can_send_chat() {
    let mut session = CollabSession::new("sess-014", "graph-xi");
    let admin = make_participant("u-admin", "Priya Sharma", CollabRole::Admin);
    session.add_participant(admin).unwrap();

    let msg = session.send_chat("u-admin", "Admin broadcast").unwrap();
    assert_eq!(msg.msg_type, CollabMessageType::ChatMessage);
}

#[test]
fn collab_message_type_serde_roundtrip() {
    let types = vec![
        CollabMessageType::GraphUpdate,
        CollabMessageType::FindingBroadcast,
        CollabMessageType::ChatMessage,
        CollabMessageType::Annotation,
        CollabMessageType::CursorPosition,
        CollabMessageType::SessionJoin,
        CollabMessageType::SessionLeave,
        CollabMessageType::Ping,
        CollabMessageType::Pong,
    ];
    for mt in types {
        let serialized = serde_json::to_string(&mt).unwrap();
        let deserialized: CollabMessageType = serde_json::from_str(&serialized).unwrap();
        assert_eq!(mt, deserialized);
    }
}

#[test]
fn collab_message_serde_roundtrip() {
    let msg = CollabMessage {
        msg_type: CollabMessageType::ChatMessage,
        sender_id: "u-1".to_owned(),
        session_id: "sess-rt".to_owned(),
        timestamp_ms: 1_700_000_000_000,
        payload: serde_json::json!({"text": "hello"}),
    };
    let json = serde_json::to_string(&msg).unwrap();
    let restored: CollabMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.msg_type, CollabMessageType::ChatMessage);
    assert_eq!(restored.sender_id, "u-1");
    assert_eq!(restored.session_id, "sess-rt");
    assert_eq!(restored.timestamp_ms, 1_700_000_000_000);
    assert_eq!(restored.payload, serde_json::json!({"text": "hello"}));
}

#[test]
fn collab_error_display() {
    assert_eq!(
        format!("{}", CollabError::SessionFull),
        "session is full (32 max)"
    );
    assert_eq!(
        format!("{}", CollabError::DuplicateParticipant),
        "participant already in session"
    );
    assert_eq!(
        format!("{}", CollabError::ParticipantNotFound),
        "participant not found"
    );
    assert_eq!(
        format!("{}", CollabError::UnauthorizedAction),
        "role does not permit this action"
    );
    assert_eq!(
        format!("{}", CollabError::InvalidMessage),
        "invalid message"
    );
}
