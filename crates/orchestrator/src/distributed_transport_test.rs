use crate::distributed::{AssignmentStrategy, default_distributed_config};
use crate::distributed::{WorkAssignment, WorkerId, WorkerRole, WorkerState};
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

fn make_coordinator() -> Coordinator {
    Coordinator::new(TransportConfig::default(), default_distributed_config(2))
}

#[test]
fn coordinator_new_creates_empty_state() {
    let coord = make_coordinator();
    assert!(coord.state().workers.is_empty());
    assert!(coord.collected_findings().is_empty());
}

#[test]
fn coordinator_handles_register() {
    let mut coord = make_coordinator();
    let msg = WorkerMessage::Register {
        worker_id: make_worker_id("w1"),
        role: WorkerRole::FuzzWorker,
    };
    let reply = coord.handle_message(&msg);
    assert!(reply.is_none());
    assert_eq!(coord.state().workers.len(), 1);
    assert_eq!(coord.state().workers[0].worker_id, make_worker_id("w1"));
    assert_eq!(coord.state().workers[0].state, WorkerState::Idle);
}

#[test]
fn coordinator_handles_heartbeat() {
    let mut coord = make_coordinator();
    coord.handle_message(&WorkerMessage::Register {
        worker_id: make_worker_id("w1"),
        role: WorkerRole::FuzzWorker,
    });
    let msg = WorkerMessage::Heartbeat {
        worker_id: make_worker_id("w1"),
        targets_completed: 5,
        targets_remaining: 10,
        findings_count: 2,
    };
    let reply = coord.handle_message(&msg);
    assert!(reply.is_none());
    assert_eq!(coord.state().workers[0].state, WorkerState::Working);
    assert_eq!(coord.state().workers[0].targets_completed, 5);
    assert_eq!(coord.state().workers[0].targets_remaining, 10);
}

#[test]
fn coordinator_handles_findings_batch() {
    let mut coord = make_coordinator();
    coord.handle_message(&WorkerMessage::Register {
        worker_id: make_worker_id("w1"),
        role: WorkerRole::FuzzWorker,
    });
    let msg = WorkerMessage::FindingsBatch {
        worker_id: make_worker_id("w1"),
        findings: vec![make_finding(), make_finding()],
    };
    let reply = coord.handle_message(&msg);
    assert!(reply.is_none());
    assert_eq!(coord.collected_findings().len(), 2);
    assert_eq!(coord.state().workers[0].findings_count, 2);
}

#[test]
fn coordinator_handles_work_complete() {
    let mut coord = make_coordinator();
    coord.handle_message(&WorkerMessage::Register {
        worker_id: make_worker_id("w1"),
        role: WorkerRole::FuzzWorker,
    });
    let msg = WorkerMessage::WorkComplete {
        worker_id: make_worker_id("w1"),
    };
    let reply = coord.handle_message(&msg);
    assert!(reply.is_none());
    assert_eq!(coord.state().workers[0].state, WorkerState::Completed);
}

#[test]
fn coordinator_handles_error_message() {
    let mut coord = make_coordinator();
    coord.handle_message(&WorkerMessage::Register {
        worker_id: make_worker_id("w1"),
        role: WorkerRole::FuzzWorker,
    });
    let msg = WorkerMessage::Error {
        worker_id: make_worker_id("w1"),
        message: "connection lost".to_string(),
    };
    let reply = coord.handle_message(&msg);
    assert!(reply.is_none());
    assert_eq!(coord.state().workers[0].state, WorkerState::Failed);
}

#[test]
fn coordinator_all_workers_complete_when_all_done() {
    let mut coord = make_coordinator();
    coord.handle_message(&WorkerMessage::Register {
        worker_id: make_worker_id("w1"),
        role: WorkerRole::FuzzWorker,
    });
    coord.handle_message(&WorkerMessage::Register {
        worker_id: make_worker_id("w2"),
        role: WorkerRole::FuzzWorker,
    });
    assert!(!coord.all_workers_complete());
    coord.handle_message(&WorkerMessage::WorkComplete {
        worker_id: make_worker_id("w1"),
    });
    coord.handle_message(&WorkerMessage::WorkComplete {
        worker_id: make_worker_id("w2"),
    });
    assert!(coord.all_workers_complete());
}

#[test]
fn coordinator_not_complete_with_active_workers() {
    let mut coord = make_coordinator();
    coord.handle_message(&WorkerMessage::Register {
        worker_id: make_worker_id("w1"),
        role: WorkerRole::FuzzWorker,
    });
    coord.handle_message(&WorkerMessage::Register {
        worker_id: make_worker_id("w2"),
        role: WorkerRole::FuzzWorker,
    });
    coord.handle_message(&WorkerMessage::WorkComplete {
        worker_id: make_worker_id("w1"),
    });
    assert!(!coord.all_workers_complete());
}

#[test]
fn coordinator_error_triggers_rebalance() {
    let mut coord = make_coordinator();
    coord.handle_message(&WorkerMessage::Register {
        worker_id: make_worker_id("w1"),
        role: WorkerRole::FuzzWorker,
    });
    coord.handle_message(&WorkerMessage::Register {
        worker_id: make_worker_id("w2"),
        role: WorkerRole::FuzzWorker,
    });
    let endpoints: Vec<String> = vec!["/a".to_string(), "/b".to_string(), "/c".to_string()];
    coord
        .state
        .assign_work(&endpoints, AssignmentStrategy::RoundRobin)
        .unwrap();
    coord
        .state
        .update_worker_status(&make_worker_id("w1"), WorkerState::Working, 0, 2, 0);
    coord
        .state
        .update_worker_status(&make_worker_id("w2"), WorkerState::Working, 0, 1, 0);

    let msg = WorkerMessage::Error {
        worker_id: make_worker_id("w2"),
        message: "crashed".to_string(),
    };
    let reply = coord.handle_message(&msg);
    assert!(reply.is_some());
    if let Some(CoordinatorMessage::AssignWork(assignment)) = reply {
        assert_eq!(assignment.worker_id, make_worker_id("w1"));
    } else {
        panic!("expected AssignWork response after rebalance");
    }
}

fn make_worker() -> Worker {
    Worker::new(make_worker_id("w1"), WorkerRole::FuzzWorker)
}

fn make_two_endpoint_assignment() -> WorkAssignment {
    WorkAssignment {
        worker_id: make_worker_id("w1"),
        endpoints: vec!["/api/users".to_string(), "/api/admin".to_string()],
        vulnerability_classes: Vec::new(),
        priority_range: (0.0, 1.0),
    }
}

#[test]
fn worker_new_starts_idle() {
    let w = make_worker();
    assert_eq!(w.state(), WorkerState::Idle);
    assert!(!w.is_paused());
    assert!(!w.is_shutdown());
    assert!(w.assigned_endpoints().is_empty());
}

#[test]
fn worker_register_message() {
    let w = make_worker();
    let msg = w.register_message();
    match msg {
        WorkerMessage::Register { worker_id, role } => {
            assert_eq!(worker_id, make_worker_id("w1"));
            assert_eq!(role, WorkerRole::FuzzWorker);
        }
        _ => panic!("expected Register message"),
    }
}

#[test]
fn worker_handles_assign_work() {
    let mut w = make_worker();
    let assignment = make_two_endpoint_assignment();
    let reply = w.handle_message(&CoordinatorMessage::AssignWork(assignment));
    assert!(reply.is_none());
    assert_eq!(w.assigned_endpoints().len(), 2);
    assert_eq!(w.assigned_endpoints()[0], "/api/users");
    assert_eq!(w.assigned_endpoints()[1], "/api/admin");
    assert_eq!(w.state(), WorkerState::Working);
}

#[test]
fn worker_handles_pause_resume() {
    let mut w = make_worker();
    w.handle_message(&CoordinatorMessage::AssignWork(
        make_two_endpoint_assignment(),
    ));
    assert_eq!(w.state(), WorkerState::Working);

    w.handle_message(&CoordinatorMessage::Pause);
    assert!(w.is_paused());
    assert_eq!(w.state(), WorkerState::Paused);

    w.handle_message(&CoordinatorMessage::Resume);
    assert!(!w.is_paused());
    assert_eq!(w.state(), WorkerState::Working);
}

#[test]
fn worker_handles_shutdown() {
    let mut w = make_worker();
    w.handle_message(&CoordinatorMessage::Shutdown);
    assert!(w.is_shutdown());
    assert_eq!(w.state(), WorkerState::Completed);
}

#[test]
fn worker_complete_target_with_findings() {
    let mut w = make_worker();
    w.handle_message(&CoordinatorMessage::AssignWork(
        make_two_endpoint_assignment(),
    ));
    let msg = w.complete_target(vec![make_finding()]);
    assert!(msg.is_some());
    match msg.unwrap() {
        WorkerMessage::FindingsBatch {
            worker_id,
            findings,
        } => {
            assert_eq!(worker_id, make_worker_id("w1"));
            assert_eq!(findings.len(), 1);
        }
        _ => panic!("expected FindingsBatch message"),
    }
}

#[test]
fn worker_complete_target_no_findings() {
    let mut w = make_worker();
    w.handle_message(&CoordinatorMessage::AssignWork(
        make_two_endpoint_assignment(),
    ));
    let msg = w.complete_target(vec![]);
    assert!(msg.is_none());
}

#[test]
fn worker_finish_returns_work_complete() {
    let mut w = make_worker();
    w.handle_message(&CoordinatorMessage::AssignWork(
        make_two_endpoint_assignment(),
    ));
    let msg = w.finish();
    match msg {
        WorkerMessage::WorkComplete { worker_id } => {
            assert_eq!(worker_id, make_worker_id("w1"));
        }
        _ => panic!("expected WorkComplete message"),
    }
    assert_eq!(w.state(), WorkerState::Completed);
}

#[test]
fn worker_heartbeat_reflects_progress() {
    let mut w = make_worker();
    w.handle_message(&CoordinatorMessage::AssignWork(
        make_two_endpoint_assignment(),
    ));
    w.complete_target(vec![]);
    let msg = w.heartbeat_message();
    match msg {
        WorkerMessage::Heartbeat {
            worker_id,
            targets_completed,
            targets_remaining,
            findings_count,
        } => {
            assert_eq!(worker_id, make_worker_id("w1"));
            assert_eq!(targets_completed, 1);
            assert_eq!(targets_remaining, 1);
            assert_eq!(findings_count, 0);
        }
        _ => panic!("expected Heartbeat message"),
    }
}

#[test]
fn worker_findings_accumulate_across_targets() {
    let mut w = make_worker();
    w.handle_message(&CoordinatorMessage::AssignWork(
        make_two_endpoint_assignment(),
    ));

    let batch1 = w.complete_target(vec![make_finding()]);
    assert!(batch1.is_some());

    let batch2 = w.complete_target(vec![make_finding(), make_finding()]);
    assert!(batch2.is_some());
    match batch2.unwrap() {
        WorkerMessage::FindingsBatch { findings, .. } => {
            assert_eq!(findings.len(), 2);
        }
        _ => panic!("expected FindingsBatch"),
    }
}

#[test]
fn integration_coordinator_worker_full_lifecycle() {
    let mut coord = make_coordinator();
    let mut w1 = Worker::new(make_worker_id("w1"), WorkerRole::FuzzWorker);
    let mut w2 = Worker::new(make_worker_id("w2"), WorkerRole::FuzzWorker);

    coord.handle_message(&w1.register_message());
    coord.handle_message(&w2.register_message());
    assert_eq!(coord.state().workers.len(), 2);

    let endpoints = vec!["/a".into(), "/b".into(), "/c".into(), "/d".into()];
    let assignments = coord
        .state
        .assign_work(&endpoints, AssignmentStrategy::RoundRobin)
        .unwrap();
    for a in &assignments {
        if a.worker_id == make_worker_id("w1") {
            w1.handle_message(&CoordinatorMessage::AssignWork(a.clone()));
        } else {
            w2.handle_message(&CoordinatorMessage::AssignWork(a.clone()));
        }
    }
    assert_eq!(w1.state(), WorkerState::Working);
    assert_eq!(w2.state(), WorkerState::Working);

    if let Some(batch) = w1.complete_target(vec![make_finding()]) {
        coord.handle_message(&batch);
    }
    w1.complete_target(vec![]);
    if let Some(batch) = w2.complete_target(vec![make_finding(), make_finding()]) {
        coord.handle_message(&batch);
    }
    w2.complete_target(vec![]);

    coord.handle_message(&w1.finish());
    coord.handle_message(&w2.finish());
    assert!(coord.all_workers_complete());
    assert_eq!(coord.collected_findings().len(), 3);
}

#[test]
fn integration_coordinator_detects_failed_worker() {
    let mut coord = make_coordinator();
    coord.handle_message(&WorkerMessage::Register {
        worker_id: make_worker_id("w1"),
        role: WorkerRole::FuzzWorker,
    });
    coord.handle_message(&WorkerMessage::Register {
        worker_id: make_worker_id("w2"),
        role: WorkerRole::FuzzWorker,
    });

    let endpoints = vec!["/a".into(), "/b".into()];
    coord
        .state
        .assign_work(&endpoints, AssignmentStrategy::RoundRobin)
        .unwrap();
    coord
        .state
        .update_worker_status(&make_worker_id("w1"), WorkerState::Working, 0, 1, 0);
    coord
        .state
        .update_worker_status(&make_worker_id("w2"), WorkerState::Working, 0, 1, 0);

    coord.handle_message(&WorkerMessage::Error {
        worker_id: make_worker_id("w1"),
        message: "segfault".to_string(),
    });

    let failed_count = coord
        .state()
        .workers
        .iter()
        .filter(|w| w.state == WorkerState::Failed)
        .count();
    assert_eq!(failed_count, 1);
    assert_eq!(coord.state().workers[0].state, WorkerState::Failed);
}

#[test]
fn integration_coordinator_rebalances_on_failure() {
    let mut coord = make_coordinator();
    coord.handle_message(&WorkerMessage::Register {
        worker_id: make_worker_id("w1"),
        role: WorkerRole::FuzzWorker,
    });
    coord.handle_message(&WorkerMessage::Register {
        worker_id: make_worker_id("w2"),
        role: WorkerRole::FuzzWorker,
    });

    let endpoints: Vec<String> = vec!["/a".into(), "/b".into(), "/c".into(), "/d".into()];
    coord
        .state
        .assign_work(&endpoints, AssignmentStrategy::RoundRobin)
        .unwrap();
    coord
        .state
        .update_worker_status(&make_worker_id("w1"), WorkerState::Working, 0, 2, 0);
    coord
        .state
        .update_worker_status(&make_worker_id("w2"), WorkerState::Working, 0, 2, 0);

    let reply = coord.handle_message(&WorkerMessage::Error {
        worker_id: make_worker_id("w2"),
        message: "crashed".to_string(),
    });
    assert!(reply.is_some());
    if let Some(CoordinatorMessage::AssignWork(assignment)) = reply {
        assert_eq!(assignment.worker_id, make_worker_id("w1"));
        assert_eq!(assignment.endpoints.len(), 2);
    } else {
        panic!("expected AssignWork after rebalance");
    }
}

#[test]
fn integration_worker_pause_resume_cycle() {
    let mut w = make_worker();
    w.handle_message(&CoordinatorMessage::AssignWork(
        make_two_endpoint_assignment(),
    ));
    assert_eq!(w.state(), WorkerState::Working);

    w.handle_message(&CoordinatorMessage::Pause);
    assert!(w.is_paused());
    assert_eq!(w.state(), WorkerState::Paused);

    w.handle_message(&CoordinatorMessage::Resume);
    assert!(!w.is_paused());
    assert_eq!(w.state(), WorkerState::Working);

    w.complete_target(vec![]);
    w.complete_target(vec![]);
    let done = w.finish();
    match done {
        WorkerMessage::WorkComplete { worker_id } => {
            assert_eq!(worker_id, make_worker_id("w1"));
        }
        _ => panic!("expected WorkComplete"),
    }
    assert_eq!(w.state(), WorkerState::Completed);
}

#[test]
fn integration_wire_protocol_coordinator_to_worker() {
    let messages: Vec<CoordinatorMessage> = vec![
        CoordinatorMessage::AssignWork(make_assignment()),
        CoordinatorMessage::Pause,
        CoordinatorMessage::Resume,
        CoordinatorMessage::Shutdown,
    ];
    for msg in messages {
        let envelope = wrap_coordinator_message(msg);
        let mut buf: Vec<u8> = Vec::new();
        write_transport_frame(&mut buf, &envelope).unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let restored = read_transport_frame(&mut cursor, 64 * 1024 * 1024).unwrap();
        assert_eq!(restored.message_id, envelope.message_id);
        let orig_json = serde_json::to_string(&envelope.payload).unwrap();
        let restored_json = serde_json::to_string(&restored.payload).unwrap();
        assert_eq!(orig_json, restored_json);
    }
}

#[test]
fn integration_wire_protocol_worker_to_coordinator() {
    let messages: Vec<WorkerMessage> = vec![
        WorkerMessage::Register {
            worker_id: make_worker_id("w1"),
            role: WorkerRole::FuzzWorker,
        },
        WorkerMessage::Heartbeat {
            worker_id: make_worker_id("w1"),
            targets_completed: 5,
            targets_remaining: 3,
            findings_count: 2,
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
    for msg in messages {
        let envelope = wrap_worker_message(msg);
        let mut buf: Vec<u8> = Vec::new();
        write_transport_frame(&mut buf, &envelope).unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let restored = read_transport_frame(&mut cursor, 64 * 1024 * 1024).unwrap();
        assert_eq!(restored.message_id, envelope.message_id);
        let orig_json = serde_json::to_string(&envelope.payload).unwrap();
        let restored_json = serde_json::to_string(&restored.payload).unwrap();
        assert_eq!(orig_json, restored_json);
    }
}

#[test]
fn integration_shutdown_after_all_complete() {
    let mut coord = make_coordinator();
    for name in ["w1", "w2", "w3"] {
        coord.handle_message(&WorkerMessage::Register {
            worker_id: make_worker_id(name),
            role: WorkerRole::FuzzWorker,
        });
    }
    assert!(!coord.all_workers_complete());

    for name in ["w1", "w2", "w3"] {
        coord.handle_message(&WorkerMessage::WorkComplete {
            worker_id: make_worker_id(name),
        });
    }
    assert!(coord.all_workers_complete());
    assert_eq!(coord.state().active_worker_count(), 0);
}

#[test]
fn integration_findings_accumulate_from_multiple_workers() {
    let mut coord = make_coordinator();
    for name in ["w1", "w2", "w3"] {
        coord.handle_message(&WorkerMessage::Register {
            worker_id: make_worker_id(name),
            role: WorkerRole::FuzzWorker,
        });
    }

    coord.handle_message(&WorkerMessage::FindingsBatch {
        worker_id: make_worker_id("w1"),
        findings: vec![make_finding(), make_finding()],
    });
    coord.handle_message(&WorkerMessage::FindingsBatch {
        worker_id: make_worker_id("w2"),
        findings: vec![make_finding()],
    });
    coord.handle_message(&WorkerMessage::FindingsBatch {
        worker_id: make_worker_id("w3"),
        findings: vec![make_finding(), make_finding(), make_finding()],
    });

    assert_eq!(coord.collected_findings().len(), 6);
    assert_eq!(coord.state().total_findings(), 6);
}

#[test]
fn integration_heartbeat_updates_worker_state() {
    let mut coord = make_coordinator();
    coord.handle_message(&WorkerMessage::Register {
        worker_id: make_worker_id("w1"),
        role: WorkerRole::FuzzWorker,
    });
    assert_eq!(coord.state().workers[0].state, WorkerState::Idle);

    coord.handle_message(&WorkerMessage::Heartbeat {
        worker_id: make_worker_id("w1"),
        targets_completed: 7,
        targets_remaining: 3,
        findings_count: 4,
    });

    let ws = &coord.state().workers[0];
    assert_eq!(ws.state, WorkerState::Working);
    assert_eq!(ws.targets_completed, 7);
    assert_eq!(ws.targets_remaining, 3);
    assert_eq!(ws.findings_count, 4);
}

#[test]
fn integration_worker_error_message_propagates() {
    let mut coord = make_coordinator();
    coord.handle_message(&WorkerMessage::Register {
        worker_id: make_worker_id("w1"),
        role: WorkerRole::FuzzWorker,
    });

    let endpoints = vec!["/api/test".into()];
    coord
        .state
        .assign_work(&endpoints, AssignmentStrategy::RoundRobin)
        .unwrap();
    coord
        .state
        .update_worker_status(&make_worker_id("w1"), WorkerState::Working, 0, 1, 0);

    let error_text = "connection refused to target".to_string();
    coord.handle_message(&WorkerMessage::Error {
        worker_id: make_worker_id("w1"),
        message: error_text,
    });

    assert_eq!(coord.state().workers[0].state, WorkerState::Failed);
    assert!(coord.all_workers_complete());
}
