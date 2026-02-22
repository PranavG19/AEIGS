use aegis_knowledge_graph::graph::GraphError;

use crate::checkpoint::CheckpointError;
use crate::phase_error::PhaseError;

#[test]
fn display_graph_variant() {
    let err = PhaseError::Graph(GraphError::Io("bad edge".to_string()));
    let msg = format!("{err}");
    assert!(msg.starts_with("graph operation failed:"));
    assert!(msg.contains("bad edge"));
}

#[test]
fn display_io_variant() {
    let inner = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
    let err = PhaseError::Io(inner);
    let msg = format!("{err}");
    assert!(msg.starts_with("I/O error:"));
    assert!(msg.contains("file missing"));
}

#[test]
fn display_serialization_variant() {
    let bad_json: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
    let inner = bad_json.unwrap_err();
    let err = PhaseError::Serialization(inner);
    let msg = format!("{err}");
    assert!(msg.starts_with("serialization error:"));
}

#[test]
fn display_checkpoint_variant() {
    let inner = CheckpointError::IoError("disk full".to_string());
    let err = PhaseError::Checkpoint(inner);
    let msg = format!("{err}");
    assert!(msg.starts_with("checkpoint:"));
    assert!(msg.contains("disk full"));
}

#[test]
fn display_report_format_variant() {
    let err = PhaseError::ReportFormat("missing field".to_string());
    let msg = format!("{err}");
    assert!(msg.starts_with("report formatting failed:"));
    assert!(msg.contains("missing field"));
}

#[test]
fn display_unknown_export_format_variant() {
    let err = PhaseError::UnknownExportFormat("xml".to_string());
    let msg = format!("{err}");
    assert!(msg.starts_with("unknown graph export format:"));
    assert!(msg.contains("xml"));
}

#[test]
fn display_filesystem_walk_variant() {
    let err = PhaseError::FilesystemWalk("permission denied".to_string());
    let msg = format!("{err}");
    assert!(msg.starts_with("filesystem walk failed:"));
    assert!(msg.contains("permission denied"));
}

#[test]
fn debug_format_includes_variant_name() {
    let err = PhaseError::FilesystemWalk("test".to_string());
    let dbg = format!("{err:?}");
    assert!(dbg.contains("FilesystemWalk"));
}

#[test]
fn phase_error_is_std_error() {
    let err = PhaseError::FilesystemWalk("boom".to_string());
    let _: &dyn std::error::Error = &err;
}

#[test]
fn source_returns_inner_for_graph() {
    let err = PhaseError::Graph(GraphError::Io("test".to_string()));
    let source = std::error::Error::source(&err);
    assert!(source.is_some());
}

#[test]
fn source_returns_inner_for_io() {
    let inner = std::io::Error::new(std::io::ErrorKind::Other, "test");
    let err = PhaseError::Io(inner);
    assert!(std::error::Error::source(&err).is_some());
}

#[test]
fn source_returns_inner_for_serialization() {
    let bad: Result<serde_json::Value, _> = serde_json::from_str("{");
    let err = PhaseError::Serialization(bad.unwrap_err());
    assert!(std::error::Error::source(&err).is_some());
}

#[test]
fn source_returns_inner_for_checkpoint() {
    let err = PhaseError::Checkpoint(CheckpointError::Corrupted("bad data".to_string()));
    assert!(std::error::Error::source(&err).is_some());
}

#[test]
fn source_returns_none_for_string_variants() {
    assert!(std::error::Error::source(&PhaseError::ReportFormat("x".to_string())).is_none());
    assert!(std::error::Error::source(&PhaseError::UnknownExportFormat("x".to_string())).is_none());
    assert!(std::error::Error::source(&PhaseError::FilesystemWalk("x".to_string())).is_none());
}

#[test]
fn from_graph_error() {
    let graph_err = GraphError::Io("conversion test".to_string());
    let phase_err: PhaseError = graph_err.into();
    assert!(matches!(phase_err, PhaseError::Graph(_)));
}

#[test]
fn from_io_error() {
    let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
    let phase_err: PhaseError = io_err.into();
    assert!(matches!(phase_err, PhaseError::Io(_)));
}

#[test]
fn from_serde_json_error() {
    let json_err: serde_json::Error = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
    let phase_err: PhaseError = json_err.into();
    assert!(matches!(phase_err, PhaseError::Serialization(_)));
}

#[test]
fn from_checkpoint_error() {
    let cp_err = CheckpointError::IoError("write failed".to_string());
    let phase_err: PhaseError = cp_err.into();
    assert!(matches!(phase_err, PhaseError::Checkpoint(_)));
    let msg = format!("{phase_err}");
    assert!(msg.contains("write failed"));
}

#[test]
fn checkpoint_corrupted_converts_to_phase_error() {
    let cp_err = CheckpointError::Corrupted("truncated file".to_string());
    let phase_err: PhaseError = cp_err.into();
    assert!(matches!(phase_err, PhaseError::Checkpoint(_)));
    let msg = format!("{phase_err}");
    assert!(msg.contains("truncated file"));
}

#[test]
fn checkpoint_serialization_converts_to_phase_error() {
    let cp_err = CheckpointError::SerializationError("invalid utf8".to_string());
    let phase_err: PhaseError = cp_err.into();
    assert!(matches!(phase_err, PhaseError::Checkpoint(_)));
}
