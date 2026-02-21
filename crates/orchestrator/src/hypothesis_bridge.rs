use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::process::{Command, Stdio};

/// Request sent to the Python hypothesis-engine CLI via stdin.
///
/// Serializes as `{"action": "generate", ...}` or `{"action": "compile", ...}`
/// using serde's internally-tagged representation.
#[derive(Debug, Serialize)]
#[serde(tag = "action", rename_all = "lowercase")]
pub enum HypothesisRequest {
    Generate {
        backend: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        backend_kwargs: Option<serde_json::Value>,
        context: serde_json::Value,
    },
    Compile {
        backend: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        backend_kwargs: Option<serde_json::Value>,
        hypotheses: Vec<serde_json::Value>,
    },
}

/// Response received from the Python hypothesis-engine CLI via stdout.
///
/// Fields use `#[serde(default)]` so partial responses deserialize without error.
/// If `error` is `Some`, the Python side reported a failure.
#[derive(Debug, Deserialize)]
pub struct HypothesisResult {
    #[serde(default)]
    pub hypotheses: Vec<serde_json::Value>,
    #[serde(default)]
    pub model_id: String,
    #[serde(default)]
    pub reasoning_trace: String,
    #[serde(default)]
    pub input_tokens: u64,
    #[serde(default)]
    pub output_tokens: u64,
    #[serde(default)]
    pub specifications: Vec<serde_json::Value>,
    pub error: Option<String>,
}

/// Errors from invoking the Python hypothesis-engine subprocess.
#[derive(Debug)]
pub enum HypothesisBridgeError {
    SpawnFailed(std::io::Error),
    WriteFailed(std::io::Error),
    ReadFailed(std::io::Error),
    DeserializeFailed(serde_json::Error),
    ProcessFailed {
        stderr: String,
        exit_code: Option<i32>,
    },
    PythonError(String),
    FrameWriteFailed(std::io::Error),
    FrameReadFailed(String),
}

impl std::fmt::Display for HypothesisBridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SpawnFailed(e) => write!(f, "failed to spawn hypothesis-engine process: {e}"),
            Self::WriteFailed(e) => write!(f, "failed to write request to hypothesis-engine: {e}"),
            Self::ReadFailed(e) => {
                write!(f, "failed to read response from hypothesis-engine: {e}")
            }
            Self::DeserializeFailed(e) => {
                write!(f, "failed to deserialize hypothesis-engine response: {e}")
            }
            Self::ProcessFailed { stderr, exit_code } => {
                let code_str = exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                write!(
                    f,
                    "hypothesis-engine process exited with code {code_str}: {stderr}"
                )
            }
            Self::PythonError(msg) => write!(f, "hypothesis-engine returned error: {msg}"),
            Self::FrameWriteFailed(e) => write!(f, "failed to write IPC frame: {e}"),
            Self::FrameReadFailed(msg) => write!(f, "failed to read IPC frame: {msg}"),
        }
    }
}

impl std::error::Error for HypothesisBridgeError {}

/// Invokes the Python hypothesis-engine CLI as a subprocess.
///
/// Serializes `request` to JSON, pipes it to `python_cmd -m hypothesis_engine.cli`
/// via stdin, and deserializes the JSON response from stdout. Returns
/// `HypothesisBridgeError` on spawn/IO/deserialization failures, non-zero exit,
/// or an `error` field in the response.
pub fn invoke_hypothesis_engine(
    request: &HypothesisRequest,
    python_cmd: &str,
) -> Result<HypothesisResult, HypothesisBridgeError> {
    let request_json =
        serde_json::to_string(request).map_err(|e| HypothesisBridgeError::WriteFailed(e.into()))?;

    let mut child = Command::new(python_cmd)
        .args(["-m", "hypothesis_engine.cli"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(HypothesisBridgeError::SpawnFailed)?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(request_json.as_bytes())
            .map_err(HypothesisBridgeError::WriteFailed)?;
    }

    let output = child
        .wait_with_output()
        .map_err(HypothesisBridgeError::ReadFailed)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(HypothesisBridgeError::ProcessFailed {
            stderr,
            exit_code: output.status.code(),
        });
    }

    let result: HypothesisResult =
        serde_json::from_slice(&output.stdout).map_err(HypothesisBridgeError::DeserializeFailed)?;

    if let Some(ref error_msg) = result.error {
        return Err(HypothesisBridgeError::PythonError(error_msg.clone()));
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// IPC message types for persistent Unix domain socket bridge (Task 8.x)
// ---------------------------------------------------------------------------

/// Scan context serialized for IPC transport to the Python bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanContextJson {
    pub technology_stack: Vec<String>,
    pub findings_summary: Vec<String>,
    pub high_centrality_nodes: Vec<String>,
    pub defense_posture: serde_json::Value,
}

/// Hypothesis serialized for IPC transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisJson {
    pub vulnerability_class: String,
    pub description: String,
    pub confidence: f64,
    pub test_specification: Option<String>,
}

/// Defense context serialized for IPC transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseContextJson {
    pub has_waf: bool,
    pub waf_vendor: Option<String>,
    pub rate_limit_rps: Option<f64>,
    pub bot_detection_present: bool,
}

/// Request sent from the Rust orchestrator to the Python bridge process
/// over a persistent Unix domain socket connection.
///
/// Uses serde's internally-tagged representation with `"type"` as the tag field.
#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum BridgeRequest {
    GenerateHypotheses {
        request_id: u64,
        scan_context: ScanContextJson,
        vulnerability_class: String,
        feedback_summary: Option<String>,
    },
    CompilePayloads {
        request_id: u64,
        hypotheses: Vec<HypothesisJson>,
    },
    EvasionGenerate {
        request_id: u64,
        defense_context: DefenseContextJson,
    },
    Shutdown,
}

/// Response received from the Python bridge process over the persistent
/// Unix domain socket connection.
///
/// Uses serde's internally-tagged representation with `"type"` as the tag field.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum BridgeResponse {
    Ready,
    Hypotheses {
        request_id: u64,
        hypotheses: Vec<HypothesisJson>,
        reasoning_trace: String,
        input_tokens: u64,
        output_tokens: u64,
    },
    CompiledPayloads {
        request_id: u64,
        payloads: Vec<String>,
        input_tokens: u64,
        output_tokens: u64,
    },
    EvasionPayloads {
        request_id: u64,
        payloads: Vec<String>,
        input_tokens: u64,
        output_tokens: u64,
    },
    Error {
        request_id: u64,
        message: String,
    },
}

/// Writes a length-prefixed JSON frame to the given writer.
///
/// Protocol: 4-byte little-endian u32 length prefix followed by the JSON payload.
pub fn write_ipc_frame<W: Write>(
    writer: &mut W,
    msg: &impl Serialize,
) -> Result<(), HypothesisBridgeError> {
    let payload =
        serde_json::to_vec(msg).map_err(|e| HypothesisBridgeError::FrameWriteFailed(e.into()))?;
    let len = u32::try_from(payload.len()).map_err(|_| {
        HypothesisBridgeError::FrameWriteFailed(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "IPC frame payload exceeds u32::MAX bytes",
        ))
    })?;
    writer
        .write_all(&len.to_le_bytes())
        .map_err(HypothesisBridgeError::FrameWriteFailed)?;
    writer
        .write_all(&payload)
        .map_err(HypothesisBridgeError::FrameWriteFailed)?;
    Ok(())
}

/// Maximum IPC frame size (64 MiB). Prevents OOM on corrupt length prefixes.
const MAX_IPC_FRAME_SIZE: usize = 64 * 1024 * 1024;

/// Reads a length-prefixed JSON frame from the given reader and deserializes it.
///
/// Protocol: 4-byte little-endian u32 length prefix followed by the JSON payload.
/// Rejects frames larger than `MAX_IPC_FRAME_SIZE` (64 MiB).
pub fn read_ipc_frame<R: Read, T: serde::de::DeserializeOwned>(
    reader: &mut R,
) -> Result<T, HypothesisBridgeError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).map_err(|e| {
        HypothesisBridgeError::FrameReadFailed(format!("reading length prefix: {e}"))
    })?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_IPC_FRAME_SIZE {
        return Err(HypothesisBridgeError::FrameReadFailed(format!(
            "frame size {len} exceeds maximum {MAX_IPC_FRAME_SIZE}"
        )));
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut payload).map_err(|e| {
            HypothesisBridgeError::FrameReadFailed(format!("reading payload ({len} bytes): {e}"))
        })?;
    }
    serde_json::from_slice(&payload)
        .map_err(|e| HypothesisBridgeError::FrameReadFailed(format!("deserializing payload: {e}")))
}
