use crate::distributed::{WorkAssignment, WorkerId, WorkerRole};
use crate::distributed_transport::*;
use aegis_protocol::finding::{FindingData, VulnerabilityClass};
use aegis_protocol::operation::ModuleIdentifier;

fn make_worker_id(name: &str) -> WorkerId {
    WorkerId {
        id: name.to_string(),
    }
}

fn make_assignment() -> WorkAssignment {
    WorkAssignment {
        worker_id: make_worker_id("w1"),
        endpoints: vec!["/api/users".to_string()],
        vulnerability_classes: Vec::new(),
        priority_range: (0.0, 1.0),
    }
}

fn make_finding() -> FindingData {
    FindingData::new(
        1,
        VulnerabilityClass::SqlInjection,
        8.0,
        0.9,
        ModuleIdentifier::Fuzzing,
        1000,
    )
}

#[test]
fn coordinator_message_serialization_roundtrip() {
    let variants: Vec<CoordinatorMessage> = vec![
        CoordinatorMessage::AssignWork(make_assignment()),
        CoordinatorMessage::Pause,
        CoordinatorMessage::Resume,
        CoordinatorMessage::Shutdown,
    ];
    for msg in &variants {
        let json = serde_json::to_string(msg).unwrap();
        let deserialized: CoordinatorMessage = serde_json::from_str(&json).unwrap();
        let roundtrip_json = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(json, roundtrip_json);
    }
}

#[test]
fn worker_message_serialization_roundtrip() {
    let variants: Vec<WorkerMessage> = vec![
        WorkerMessage::Register {
            worker_id: make_worker_id("w1"),
            role: WorkerRole::FuzzWorker,
        },
        WorkerMessage::Heartbeat {
            worker_id: make_worker_id("w1"),
            targets_completed: 10,
            targets_remaining: 5,
            findings_count: 3,
        },
        WorkerMessage::FindingsBatch {
            worker_id: make_worker_id("w1"),
            findings: vec![make_finding()],
        },
        WorkerMessage::WorkComplete {
            worker_id: make_worker_id("w1"),
        },
        WorkerMessage::Error {
            worker_id: make_worker_id("w1"),
            message: "timeout".to_string(),
        },
    ];
    for msg in &variants {
        let json = serde_json::to_string(msg).unwrap();
        let deserialized: WorkerMessage = serde_json::from_str(&json).unwrap();
        let roundtrip_json = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(json, roundtrip_json);
    }
}

#[test]
fn transport_envelope_serialization_roundtrip() {
    let envelope = TransportEnvelope {
        message_id: 42,
        timestamp_ms: 1700000000000,
        payload: TransportPayload::FromCoordinator(CoordinatorMessage::Pause),
    };
    let json = serde_json::to_string(&envelope).unwrap();
    let deserialized: TransportEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.message_id, 42);
    assert_eq!(deserialized.timestamp_ms, 1700000000000);
}

#[test]
fn write_read_frame_roundtrip() {
    let envelope = TransportEnvelope {
        message_id: 1,
        timestamp_ms: 999,
        payload: TransportPayload::FromWorker(WorkerMessage::WorkComplete {
            worker_id: make_worker_id("w1"),
        }),
    };
    let mut buf: Vec<u8> = Vec::new();
    write_transport_frame(&mut buf, &envelope).unwrap();

    let mut cursor = std::io::Cursor::new(buf);
    let restored = read_transport_frame(&mut cursor, 64 * 1024 * 1024).unwrap();
    assert_eq!(restored.message_id, 1);
    assert_eq!(restored.timestamp_ms, 999);
}

#[test]
fn read_frame_rejects_oversized() {
    let envelope = TransportEnvelope {
        message_id: 1,
        timestamp_ms: 0,
        payload: TransportPayload::FromCoordinator(CoordinatorMessage::Pause),
    };
    let mut buf: Vec<u8> = Vec::new();
    write_transport_frame(&mut buf, &envelope).unwrap();

    let mut cursor = std::io::Cursor::new(buf);
    let result = read_transport_frame(&mut cursor, 1);
    assert!(result.is_err());
    let err = result.unwrap_err();
    let display = format!("{err}");
    assert!(display.contains("exceeds maximum"));
}

#[test]
fn transport_config_default() {
    let config = TransportConfig::default();
    assert_eq!(config.bind_address, "127.0.0.1");
    assert_eq!(config.port, 9100);
    assert_eq!(config.max_frame_size, 64 * 1024 * 1024);
    assert_eq!(config.connection_timeout_ms, 10_000);
}

#[test]
fn transport_config_builder() {
    let config = TransportConfig::default()
        .with_bind_address("0.0.0.0")
        .with_port(9200);
    assert_eq!(config.bind_address, "0.0.0.0");
    assert_eq!(config.port, 9200);
}

#[test]
fn transport_error_display() {
    let io_err = TransportError::Io(std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "broken",
    ));
    assert!(format!("{io_err}").contains("transport I/O error"));

    let ser_err = TransportError::Serialization("bad json".to_string());
    assert!(format!("{ser_err}").contains("serialization error"));

    let frame_err = TransportError::FrameTooLarge { size: 100, max: 50 };
    let display = format!("{frame_err}");
    assert!(display.contains("100"));
    assert!(display.contains("50"));

    let closed = TransportError::ConnectionClosed;
    assert!(format!("{closed}").contains("connection closed"));
}

#[test]
fn wrap_coordinator_message_auto_ids() {
    let env1 = wrap_coordinator_message(CoordinatorMessage::Pause);
    let env2 = wrap_coordinator_message(CoordinatorMessage::Resume);
    assert!(env2.message_id > env1.message_id);
}

#[test]
fn wrap_worker_message_has_timestamp() {
    let env = wrap_worker_message(WorkerMessage::WorkComplete {
        worker_id: make_worker_id("w1"),
    });
    assert!(env.timestamp_ms > 0);
}
