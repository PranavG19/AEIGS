use aegis_knowledge_graph::graph::GraphError;

use crate::checkpoint::CheckpointError;

/// Structured error type for scan phase failures.
///
/// Replaces `Result<T, String>` across all pipeline phase functions. Each variant
/// wraps the original error type, preserving the source for programmatic matching
/// while implementing `Display` for human-readable messages.
#[derive(Debug)]
pub enum PhaseError {
    Graph(GraphError),
    Io(std::io::Error),
    Serialization(serde_json::Error),
    Checkpoint(CheckpointError),
    ReportFormat(String),
    UnknownExportFormat(String),
    FilesystemWalk(String),
}

impl std::fmt::Display for PhaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Graph(e) => write!(f, "graph operation failed: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Serialization(e) => write!(f, "serialization error: {e}"),
            Self::Checkpoint(e) => write!(f, "checkpoint: {e}"),
            Self::ReportFormat(e) => write!(f, "report formatting failed: {e}"),
            Self::UnknownExportFormat(fmt) => write!(f, "unknown graph export format: {fmt}"),
            Self::FilesystemWalk(e) => write!(f, "filesystem walk failed: {e}"),
        }
    }
}

impl std::error::Error for PhaseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Graph(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Serialization(e) => Some(e),
            Self::Checkpoint(e) => Some(e),
            _ => None,
        }
    }
}

impl From<GraphError> for PhaseError {
    fn from(e: GraphError) -> Self {
        Self::Graph(e)
    }
}

impl From<std::io::Error> for PhaseError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for PhaseError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e)
    }
}

impl From<CheckpointError> for PhaseError {
    fn from(e: CheckpointError) -> Self {
        Self::Checkpoint(e)
    }
}
