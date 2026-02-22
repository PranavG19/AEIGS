use crate::checkpoint::{
    CheckpointError, ScanCheckpoint, checkpoint_path, delete_checkpoint, load_checkpoint,
    save_checkpoint, should_skip_phase,
};

fn sample_checkpoint() -> ScanCheckpoint {
    ScanCheckpoint {
        completed_phases: vec![
            "recon".to_string(),
            "fingerprint".to_string(),
            "fuzz:0".to_string(),
            "analyze:0".to_string(),
        ],
        current_iteration: 1,
        total_operations: 42,
        total_findings: 7,
        consecutive_zero_findings: 0,
        timestamp_unix_ms: 1700000000000,
    }
}

#[test]
fn save_and_load_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let graph_db = dir.path().join("graph.json");
    let cp = sample_checkpoint();

    save_checkpoint(&cp, &graph_db).unwrap();
    let loaded = load_checkpoint(&graph_db).unwrap().unwrap();

    assert_eq!(loaded.completed_phases, cp.completed_phases);
    assert_eq!(loaded.current_iteration, cp.current_iteration);
    assert_eq!(loaded.total_operations, cp.total_operations);
    assert_eq!(loaded.total_findings, cp.total_findings);
    assert_eq!(
        loaded.consecutive_zero_findings,
        cp.consecutive_zero_findings
    );
    assert_eq!(loaded.timestamp_unix_ms, cp.timestamp_unix_ms);
}

#[test]
fn load_nonexistent_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let graph_db = dir.path().join("does_not_exist.json");
    let result = load_checkpoint(&graph_db).unwrap();
    assert!(result.is_none());
}

#[test]
fn delete_removes_checkpoint_file() {
    let dir = tempfile::tempdir().unwrap();
    let graph_db = dir.path().join("graph.json");
    let cp = sample_checkpoint();

    save_checkpoint(&cp, &graph_db).unwrap();
    let cp_path = checkpoint_path(&graph_db);
    assert!(cp_path.exists());

    delete_checkpoint(&graph_db).unwrap();
    assert!(!cp_path.exists());
}

#[test]
fn delete_nonexistent_is_noop() {
    let dir = tempfile::tempdir().unwrap();
    let graph_db = dir.path().join("no_graph.json");
    let result = delete_checkpoint(&graph_db);
    assert!(result.is_ok());
}

#[test]
fn should_skip_phase_completed() {
    let cp = sample_checkpoint();
    assert!(should_skip_phase(&cp, "recon"));
    assert!(should_skip_phase(&cp, "fingerprint"));
    assert!(should_skip_phase(&cp, "fuzz:0"));
    assert!(should_skip_phase(&cp, "analyze:0"));
}

#[test]
fn should_skip_phase_not_completed() {
    let cp = sample_checkpoint();
    assert!(!should_skip_phase(&cp, "fuzz:1"));
    assert!(!should_skip_phase(&cp, "analyze:1"));
    assert!(!should_skip_phase(&cp, "report"));
}

#[test]
fn checkpoint_path_derivation() {
    let base = std::path::Path::new("/tmp/aegis-graph.json");
    let derived = checkpoint_path(base);
    assert_eq!(
        derived,
        std::path::PathBuf::from("/tmp/aegis-graph.json.checkpoint.json")
    );
}

#[test]
fn corrupted_file_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let graph_db = dir.path().join("graph.json");
    let cp_path = checkpoint_path(&graph_db);
    std::fs::write(&cp_path, b"not valid json {{ at all").unwrap();

    let result = load_checkpoint(&graph_db);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, CheckpointError::Corrupted(_)));
    let msg = format!("{err}");
    assert!(msg.contains("checkpoint corrupted"));
}

#[test]
fn checkpoint_error_display_io() {
    let err = CheckpointError::IoError("disk full".to_string());
    assert_eq!(format!("{err}"), "checkpoint I/O error: disk full");
}

#[test]
fn checkpoint_error_display_serialization() {
    let err = CheckpointError::SerializationError("bad data".to_string());
    assert_eq!(format!("{err}"), "checkpoint serialization error: bad data");
}

#[test]
fn checkpoint_error_is_std_error() {
    let err = CheckpointError::IoError("test".to_string());
    let _: &dyn std::error::Error = &err;
}

#[test]
fn scan_checkpoint_debug_format() {
    let cp = sample_checkpoint();
    let dbg = format!("{cp:?}");
    assert!(dbg.contains("ScanCheckpoint"));
    assert!(dbg.contains("completed_phases"));
}

#[test]
fn scan_checkpoint_clone() {
    let cp = sample_checkpoint();
    let cloned = cp.clone();
    assert_eq!(cloned.current_iteration, cp.current_iteration);
    assert_eq!(cloned.completed_phases, cp.completed_phases);
}

#[test]
fn empty_checkpoint_skips_nothing() {
    let cp = ScanCheckpoint {
        completed_phases: Vec::new(),
        current_iteration: 0,
        total_operations: 0,
        total_findings: 0,
        consecutive_zero_findings: 0,
        timestamp_unix_ms: 0,
    };
    assert!(!should_skip_phase(&cp, "recon"));
    assert!(!should_skip_phase(&cp, "fingerprint"));
}

#[test]
fn save_to_nonexistent_parent_returns_io_error() {
    let path = std::path::Path::new("/nonexistent/deep/dir/graph.json");
    let cp = sample_checkpoint();
    let result = save_checkpoint(&cp, path);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), CheckpointError::IoError(_)));
}

#[test]
fn checkpoint_resume_skips_completed_and_runs_remaining() {
    let cp = sample_checkpoint();

    assert!(should_skip_phase(&cp, "recon"));
    assert!(should_skip_phase(&cp, "fingerprint"));
    assert!(should_skip_phase(&cp, "fuzz:0"));
    assert!(should_skip_phase(&cp, "analyze:0"));

    assert!(!should_skip_phase(&cp, "fuzz:1"));
    assert!(!should_skip_phase(&cp, "analyze:1"));
    assert!(!should_skip_phase(&cp, "dom_verify"));
    assert!(!should_skip_phase(&cp, "report"));

    assert_eq!(cp.current_iteration, 1);
}

#[test]
fn checkpoint_deleted_on_completion_e2e() {
    let dir = tempfile::tempdir().unwrap();
    let graph_db = dir.path().join("graph.json");
    let cp = sample_checkpoint();

    save_checkpoint(&cp, &graph_db).unwrap();
    assert!(checkpoint_path(&graph_db).exists());

    let loaded = load_checkpoint(&graph_db).unwrap();
    assert!(loaded.is_some());

    delete_checkpoint(&graph_db).unwrap();
    assert!(!checkpoint_path(&graph_db).exists());

    let after_delete = load_checkpoint(&graph_db).unwrap();
    assert!(after_delete.is_none());
}

#[test]
fn checkpoint_preserves_graph_state_across_save_load() {
    let dir = tempfile::tempdir().unwrap();
    let graph_db = dir.path().join("graph.json");
    let cp = ScanCheckpoint {
        completed_phases: vec![
            "recon".to_string(),
            "crawl".to_string(),
            "fingerprint".to_string(),
            "fuzz:0".to_string(),
            "analyze:0".to_string(),
            "fuzz:1".to_string(),
            "analyze:1".to_string(),
        ],
        current_iteration: 2,
        total_operations: 150,
        total_findings: 12,
        consecutive_zero_findings: 1,
        timestamp_unix_ms: 1700000099999,
    };

    save_checkpoint(&cp, &graph_db).unwrap();
    let loaded = load_checkpoint(&graph_db).unwrap().unwrap();

    assert_eq!(loaded.completed_phases.len(), 7);
    assert_eq!(loaded.current_iteration, 2);
    assert_eq!(loaded.total_operations, 150);
    assert_eq!(loaded.total_findings, 12);
    assert_eq!(loaded.consecutive_zero_findings, 1);
    assert_eq!(loaded.timestamp_unix_ms, 1700000099999);

    for phase in &[
        "recon",
        "crawl",
        "fingerprint",
        "fuzz:0",
        "analyze:0",
        "fuzz:1",
        "analyze:1",
    ] {
        assert!(
            should_skip_phase(&loaded, phase),
            "phase {phase} should be skippable after load"
        );
    }
    assert!(!should_skip_phase(&loaded, "fuzz:2"));
    assert!(!should_skip_phase(&loaded, "report"));
}
