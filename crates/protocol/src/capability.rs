use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityToken {
    pub module: crate::operation::ModuleIdentifier,
    pub permissions: Vec<Permission>,
    pub expires_at_unix_ms: u64,
    pub token_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    ReadGraph,
    WriteGraph,
    ExecuteRequests,
    ReadFilesystem,
    WriteAuditLog,
}
