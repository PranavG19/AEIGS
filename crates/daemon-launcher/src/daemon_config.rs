//! Daemon Configuration Module
//!
//! Defines the configuration structures for all daemon types.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub id: String,
    pub daemon_type: DaemonType,
    pub target_url: String,
    pub work_dir: PathBuf,
    pub verbose: bool,
    pub max_concurrent: usize,
    pub custom_params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DaemonType {
    GhostProtocol,
    CachePoisoning,
    SchemaGrammar,
    H2Continuation,
}

impl std::fmt::Display for DaemonType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaemonType::GhostProtocol => write!(f, "GhostProtocol"),
            DaemonType::CachePoisoning => write!(f, "CachePoisoning"),
            DaemonType::SchemaGrammar => write!(f, "SchemaGrammar"),
            DaemonType::H2Continuation => write!(f, "H2Continuation"),
        }
    }
}
