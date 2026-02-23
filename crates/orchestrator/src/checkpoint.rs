use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Tracks scan progress so interrupted scans can resume from the last completed phase.
///
/// Serialized to JSON alongside the graph database file. Deleted on successful completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCheckpoint {
    pub completed_phases: Vec<String>,
    pub current_iteration: u32,
    pub total_operations: u64,
    pub total_findings: u64,
    pub consecutive_zero_findings: u32,
    pub timestamp_unix_ms: u64,
}

#[derive(Debug)]
pub enum CheckpointError {
    IoError(String),
    SerializationError(String),
    Corrupted(String),
}

impl std::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(msg) => write!(f, "checkpoint I/O error: {msg}"),
            Self::SerializationError(msg) => write!(f, "checkpoint serialization error: {msg}"),
            Self::Corrupted(msg) => write!(f, "checkpoint corrupted: {msg}"),
        }
    }
}

impl std::error::Error for CheckpointError {}

/// Returns the checkpoint file path derived from the graph database path.
pub fn checkpoint_path(graph_db_path: &Path) -> PathBuf {
    let mut p = graph_db_path.as_os_str().to_owned();
    p.push(".checkpoint.json");
    PathBuf::from(p)
}

/// Persists a checkpoint to disk as JSON using atomic write (temp file + rename).
///
/// Writes to a `.tmp` sibling first, then renames to the final path. This ensures
/// a concurrent reader never sees a partially-written checkpoint file. On rename
/// failure the temp file is cleaned up on a best-effort basis.
pub async fn save_checkpoint(
    checkpoint: &ScanCheckpoint,
    graph_db_path: &Path,
) -> Result<(), CheckpointError> {
    let path = checkpoint_path(graph_db_path);
    let tmp_path = path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(checkpoint)
        .map_err(|e| CheckpointError::SerializationError(e.to_string()))?;
    tokio::fs::write(&tmp_path, &json)
        .await
        .map_err(|e| CheckpointError::IoError(e.to_string()))?;
    tokio::fs::rename(&tmp_path, &path).await.map_err(|e| {
        let tmp = tmp_path.clone();
        tokio::spawn(async move {
            let _ = tokio::fs::remove_file(&tmp).await;
        });
        CheckpointError::IoError(e.to_string())
    })
}

/// Loads a checkpoint from disk, returning `None` if the file does not exist.
pub async fn load_checkpoint(
    graph_db_path: &Path,
) -> Result<Option<ScanCheckpoint>, CheckpointError> {
    let path = checkpoint_path(graph_db_path);
    if !path.exists() {
        return Ok(None);
    }
    let contents = tokio::fs::read_to_string(&path)
        .await
        .map_err(|e| CheckpointError::IoError(e.to_string()))?;
    let checkpoint: ScanCheckpoint = serde_json::from_str(&contents).map_err(|e| {
        CheckpointError::Corrupted(format!("failed to parse {}: {e}", path.display()))
    })?;
    Ok(Some(checkpoint))
}

/// Removes the checkpoint file after a successful scan.
pub async fn delete_checkpoint(graph_db_path: &Path) -> Result<(), CheckpointError> {
    let path = checkpoint_path(graph_db_path);
    if path.exists() {
        tokio::fs::remove_file(&path)
            .await
            .map_err(|e| CheckpointError::IoError(e.to_string()))?;
    }
    Ok(())
}

/// Returns `true` if `phase_name` appears in the checkpoint's completed phases.
pub fn should_skip_phase(checkpoint: &ScanCheckpoint, phase_name: &str) -> bool {
    checkpoint.completed_phases.iter().any(|p| p == phase_name)
}
