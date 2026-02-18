use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcMessage {
    OperationBatch {
        entries: Vec<crate::operation::OperationLogEntry>,
    },
    QueryRequest {
        request_id: u64,
        query: GraphQuery,
    },
    QueryResponse {
        request_id: u64,
        result: QueryResult,
    },
    ModuleReady {
        module: crate::operation::ModuleIdentifier,
    },
    ModuleShutdown {
        module: crate::operation::ModuleIdentifier,
    },
    Heartbeat {
        module: crate::operation::ModuleIdentifier,
        timestamp_unix_ms: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GraphQuery {
    PathsBetween {
        from_node_id: u64,
        to_node_id: u64,
        max_hops: u32,
    },
    ReachableFrom {
        node_id: u64,
        edge_labels: Vec<crate::edge::EdgeLabel>,
    },
    NodesByType {
        node_type: crate::node::NodeType,
    },
    FindingsByClass {
        vulnerability_class: crate::finding::VulnerabilityClass,
    },
    AllFindings,
    CutVertices,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryResult {
    Paths {
        paths: Vec<Vec<u64>>,
    },
    NodeIds {
        ids: Vec<u64>,
    },
    Findings {
        findings: Vec<crate::finding::FindingData>,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcFrame {
    pub message_length: u32,
    pub payload: Vec<u8>,
}

impl IpcFrame {
    pub fn encode(message: &IpcMessage) -> Result<Vec<u8>, serde_json::Error> {
        let payload = serde_json::to_vec(message)?;
        let length = payload.len() as u32;
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&length.to_le_bytes());
        frame.extend_from_slice(&payload);
        Ok(frame)
    }

    pub fn decode(data: &[u8]) -> Result<IpcMessage, IpcFrameDecodeError> {
        if data.len() < 4 {
            return Err(IpcFrameDecodeError::InsufficientData);
        }
        let length = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + length {
            return Err(IpcFrameDecodeError::InsufficientData);
        }
        serde_json::from_slice(&data[4..4 + length]).map_err(IpcFrameDecodeError::DeserializeError)
    }
}

#[derive(Debug)]
pub enum IpcFrameDecodeError {
    InsufficientData,
    DeserializeError(serde_json::Error),
}

impl std::fmt::Display for IpcFrameDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientData => write!(f, "insufficient data for frame"),
            Self::DeserializeError(e) => write!(f, "deserialization error: {e}"),
        }
    }
}

impl std::error::Error for IpcFrameDecodeError {}
