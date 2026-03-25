use crate::scan_protocol::{
    create_envelope, describe_message, deserialize_envelope, serialize_envelope, validate_message,
    MessageEnvelope, MessageId, ProtocolError, ProtocolMessage, PROTOCOL_VERSION,
};
use aegis_protocol::finding::{
    Confidence, EvidenceLevel, FindingConfidence, FindingData, VulnerabilityClass,
};
use aegis_protocol::operation::ModuleIdentifier;

fn sample_finding() -> FindingData {
    FindingData {
        id: 1,
        linked_node_ids: vec![10],
        vulnerability_class: VulnerabilityClass::SqlInjection,
        severity: 7.5,
        confidence: FindingConfidence::from_simple(Confidence::new(0.8).unwrap()),
        certificate: Vec::new(),
        provenance_module: ModuleIdentifier::Fuzzing,
        timestamp_unix_ms: crate::util::timestamp_ms(),
        evidence_level: EvidenceLevel::Statistical,
        stable_id: None,
    }
}

// --- Serialization round-trip ---

#[test]
fn serialize_deserialize_task_assignment() {
    let msg = ProtocolMessage::TaskAssignment {
        worker_id: "w1".to_string(),
        endpoints: vec!["/api/login".to_string()],
        modules: vec!["sqli".to_string()],
        priority: 0.9,
    };
    let envelope = create_envelope("coordinator", msg);
    let bytes = serialize_envelope(&envelope).unwrap();
    let decoded = deserialize_envelope(&bytes).unwrap();
    assert_eq!(decoded.version, PROTOCOL_VERSION);
    assert_eq!(decoded.sender, "coordinator");
}

#[test]
fn serialize_deserialize_heartbeat() {
    let msg = ProtocolMessage::Heartbeat {
        worker_id: "w1".to_string(),
        load_percent: 45.0,
        tasks_completed: 10,
        tasks_remaining: 5,
    };
    let envelope = create_envelope("w1", msg);
    let bytes = serialize_envelope(&envelope).unwrap();
    let decoded = deserialize_envelope(&bytes).unwrap();
    assert_eq!(decoded.sender, "w1");
}

#[test]
fn serialize_deserialize_task_result() {
    let msg = ProtocolMessage::TaskResult {
        worker_id: "w1".to_string(),
        task_id: "task-1".to_string(),
        findings: vec![sample_finding()],
        duration_ms: 1500,
    };
    let envelope = create_envelope("w1", msg);
    let bytes = serialize_envelope(&envelope).unwrap();
    let decoded = deserialize_envelope(&bytes).unwrap();
    assert_eq!(decoded.sender, "w1");
}

#[test]
fn serialize_deserialize_finding_broadcast() {
    let msg = ProtocolMessage::FindingBroadcast {
        finding: sample_finding(),
        source_worker: "w2".to_string(),
    };
    let envelope = create_envelope("coordinator", msg);
    let bytes = serialize_envelope(&envelope).unwrap();
    let decoded = deserialize_envelope(&bytes).unwrap();
    assert_eq!(decoded.sender, "coordinator");
}

#[test]
fn serialize_deserialize_state_sync() {
    let msg = ProtocolMessage::StateSync {
        phase: "fuzz".to_string(),
        active_workers: vec!["w1".to_string(), "w2".to_string()],
        total_findings: 42,
    };
    let envelope = create_envelope("coordinator", msg);
    let bytes = serialize_envelope(&envelope).unwrap();
    let decoded = deserialize_envelope(&bytes).unwrap();
    assert_eq!(decoded.sender, "coordinator");
}

#[test]
fn serialize_deserialize_phase_transition() {
    let msg = ProtocolMessage::PhaseTransition {
        from_phase: "recon".to_string(),
        to_phase: "crawl".to_string(),
    };
    let envelope = create_envelope("coordinator", msg);
    let bytes = serialize_envelope(&envelope).unwrap();
    let decoded = deserialize_envelope(&bytes).unwrap();
    assert_eq!(decoded.sender, "coordinator");
}

#[test]
fn serialize_deserialize_shutdown_request() {
    let msg = ProtocolMessage::ShutdownRequest {
        worker_id: "w3".to_string(),
        reason: "scan complete".to_string(),
    };
    let envelope = create_envelope("coordinator", msg);
    let bytes = serialize_envelope(&envelope).unwrap();
    let decoded = deserialize_envelope(&bytes).unwrap();
    assert_eq!(decoded.sender, "coordinator");
}

// --- Version validation ---

#[test]
fn version_mismatch_rejected() {
    let envelope = MessageEnvelope {
        version: 999,
        message_id: 1,
        timestamp_ms: crate::util::timestamp_ms(),
        sender: "test".to_string(),
        payload: ProtocolMessage::Heartbeat {
            worker_id: "w1".to_string(),
            load_percent: 0.0,
            tasks_completed: 0,
            tasks_remaining: 0,
        },
    };
    let bytes = serde_json::to_vec(&envelope).unwrap();
    let result = deserialize_envelope(&bytes);
    assert!(result.is_err());
}

// --- Message validation ---

#[test]
fn validate_task_assignment_valid() {
    let msg = ProtocolMessage::TaskAssignment {
        worker_id: "w1".to_string(),
        endpoints: vec!["/api".to_string()],
        modules: vec![],
        priority: 1.0,
    };
    assert!(validate_message(&msg).is_ok());
}

#[test]
fn validate_task_assignment_empty_worker_id() {
    let msg = ProtocolMessage::TaskAssignment {
        worker_id: "".to_string(),
        endpoints: vec!["/api".to_string()],
        modules: vec![],
        priority: 1.0,
    };
    assert!(validate_message(&msg).is_err());
}

#[test]
fn validate_task_assignment_empty_endpoints() {
    let msg = ProtocolMessage::TaskAssignment {
        worker_id: "w1".to_string(),
        endpoints: vec![],
        modules: vec![],
        priority: 1.0,
    };
    assert!(validate_message(&msg).is_err());
}

#[test]
fn validate_task_result_valid() {
    let msg = ProtocolMessage::TaskResult {
        worker_id: "w1".to_string(),
        task_id: "task-1".to_string(),
        findings: vec![],
        duration_ms: 100,
    };
    assert!(validate_message(&msg).is_ok());
}

#[test]
fn validate_task_result_empty_ids() {
    let msg = ProtocolMessage::TaskResult {
        worker_id: "".to_string(),
        task_id: "".to_string(),
        findings: vec![],
        duration_ms: 0,
    };
    assert!(validate_message(&msg).is_err());
}

#[test]
fn validate_heartbeat_valid() {
    let msg = ProtocolMessage::Heartbeat {
        worker_id: "w1".to_string(),
        load_percent: 50.0,
        tasks_completed: 5,
        tasks_remaining: 3,
    };
    assert!(validate_message(&msg).is_ok());
}

#[test]
fn validate_heartbeat_empty_worker_id() {
    let msg = ProtocolMessage::Heartbeat {
        worker_id: "".to_string(),
        load_percent: 0.0,
        tasks_completed: 0,
        tasks_remaining: 0,
    };
    assert!(validate_message(&msg).is_err());
}

#[test]
fn validate_shutdown_valid() {
    let msg = ProtocolMessage::ShutdownRequest {
        worker_id: "w1".to_string(),
        reason: "done".to_string(),
    };
    assert!(validate_message(&msg).is_ok());
}

#[test]
fn validate_shutdown_empty_worker_id() {
    let msg = ProtocolMessage::ShutdownRequest {
        worker_id: "".to_string(),
        reason: "done".to_string(),
    };
    assert!(validate_message(&msg).is_err());
}

#[test]
fn validate_state_sync_always_ok() {
    let msg = ProtocolMessage::StateSync {
        phase: "recon".to_string(),
        active_workers: vec![],
        total_findings: 0,
    };
    assert!(validate_message(&msg).is_ok());
}

#[test]
fn validate_finding_broadcast_always_ok() {
    let msg = ProtocolMessage::FindingBroadcast {
        finding: sample_finding(),
        source_worker: "w1".to_string(),
    };
    assert!(validate_message(&msg).is_ok());
}

// --- create_envelope ---

#[test]
fn create_envelope_auto_increments_id() {
    let msg1 = ProtocolMessage::Heartbeat {
        worker_id: "w1".to_string(),
        load_percent: 0.0,
        tasks_completed: 0,
        tasks_remaining: 0,
    };
    let msg2 = ProtocolMessage::Heartbeat {
        worker_id: "w2".to_string(),
        load_percent: 0.0,
        tasks_completed: 0,
        tasks_remaining: 0,
    };
    let e1 = create_envelope("w1", msg1);
    let e2 = create_envelope("w2", msg2);
    assert!(e2.message_id > e1.message_id);
}

#[test]
fn create_envelope_sets_version() {
    let msg = ProtocolMessage::Heartbeat {
        worker_id: "w1".to_string(),
        load_percent: 0.0,
        tasks_completed: 0,
        tasks_remaining: 0,
    };
    let envelope = create_envelope("w1", msg);
    assert_eq!(envelope.version, PROTOCOL_VERSION);
}

// --- describe_message ---

#[test]
fn describe_task_assignment() {
    let msg = ProtocolMessage::TaskAssignment {
        worker_id: "w1".to_string(),
        endpoints: vec!["/a".to_string(), "/b".to_string()],
        modules: vec![],
        priority: 1.0,
    };
    let desc = describe_message(&msg);
    assert!(desc.contains("2 endpoint(s)"));
    assert!(desc.contains("w1"));
}

#[test]
fn describe_heartbeat() {
    let msg = ProtocolMessage::Heartbeat {
        worker_id: "alpha".to_string(),
        load_percent: 50.0,
        tasks_completed: 0,
        tasks_remaining: 0,
    };
    let desc = describe_message(&msg);
    assert!(desc.contains("alpha"));
}

#[test]
fn describe_shutdown() {
    let msg = ProtocolMessage::ShutdownRequest {
        worker_id: "w1".to_string(),
        reason: "done".to_string(),
    };
    let desc = describe_message(&msg);
    assert!(desc.contains("w1"));
    assert!(desc.contains("done"));
}

// --- MessageId ---

#[test]
fn message_id_display() {
    let mid = MessageId { id: 42 };
    assert_eq!(format!("{mid}"), "msg-42");
}

// --- Error display ---

#[test]
fn error_display_serialization() {
    let e = ProtocolError::SerializationError("fail".to_string());
    assert!(format!("{e}").contains("serialization"));
}

#[test]
fn error_display_deserialization() {
    let e = ProtocolError::DeserializationError("bad json".to_string());
    assert!(format!("{e}").contains("deserialization"));
}

#[test]
fn error_display_version_mismatch() {
    let e = ProtocolError::VersionMismatch {
        expected: 1,
        got: 99,
    };
    let msg = format!("{e}");
    assert!(msg.contains("1") && msg.contains("99"));
}

#[test]
fn error_display_invalid_message() {
    let e = ProtocolError::InvalidMessage("missing field".to_string());
    assert!(format!("{e}").contains("missing field"));
}

// --- Protocol constant ---

#[test]
fn protocol_version_is_one() {
    assert_eq!(PROTOCOL_VERSION, 1);
}
