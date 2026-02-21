use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

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
    HandshakeFailed(String),
    RequestIdMismatch {
        expected: u64,
        actual: u64,
    },
    Timeout(String),
    SocketCleanupFailed(std::io::Error),
    UnexpectedResponse(String),
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
            Self::HandshakeFailed(msg) => write!(f, "bridge handshake failed: {msg}"),
            Self::RequestIdMismatch { expected, actual } => {
                write!(f, "request ID mismatch: expected {expected}, got {actual}")
            }
            Self::Timeout(msg) => write!(f, "bridge timeout: {msg}"),
            Self::SocketCleanupFailed(e) => write!(f, "failed to clean up socket: {e}"),
            Self::UnexpectedResponse(msg) => {
                write!(f, "unexpected bridge response: {msg}")
            }
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
#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
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

// ---------------------------------------------------------------------------
// Result types for HypothesisBridge methods
// ---------------------------------------------------------------------------

/// Result of a hypothesis generation request.
#[derive(Debug)]
pub struct GenerateResult {
    pub hypotheses: Vec<HypothesisJson>,
    pub reasoning_trace: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// Result of a payload compilation request.
#[derive(Debug)]
pub struct CompileResult {
    pub payloads: Vec<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// Result of an evasion payload generation request.
#[derive(Debug)]
pub struct EvasionBridgeResult {
    pub payloads: Vec<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
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

// ---------------------------------------------------------------------------
// Persistent HypothesisBridge (Unix domain socket IPC)
// ---------------------------------------------------------------------------

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Persistent bridge to the Python hypothesis-engine process.
///
/// Keeps a long-lived Python child process communicating over a Unix domain
/// socket with length-prefixed JSON frames. Cleans up the socket file and
/// terminates the child on drop.
pub struct HypothesisBridge {
    pub(crate) child: Child,
    pub(crate) socket: UnixStream,
    pub(crate) request_counter: u64,
    pub(crate) socket_path: PathBuf,
    pub(crate) shutdown_called: bool,
}

impl HypothesisBridge {
    /// Spawns the Python bridge process and completes the Ready handshake.
    ///
    /// Creates a Unix socket at `/tmp/aegis-hypothesis-{pid}.sock`, spawns
    /// `python_cmd -m hypothesis_engine.bridge --socket <path>`, and waits
    /// up to 10 seconds for the Python side to connect and send `Ready`.
    pub fn start(python_cmd: &str) -> Result<Self, HypothesisBridgeError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let socket_path = PathBuf::from(format!(
            "/tmp/aegis-hypothesis-{}-{timestamp}.sock",
            std::process::id()
        ));
        Self::start_with_path(python_cmd, socket_path)
    }

    /// Like `start`, but accepts an explicit socket path (useful for testing).
    pub fn start_with_path(
        python_cmd: &str,
        socket_path: PathBuf,
    ) -> Result<Self, HypothesisBridgeError> {
        if socket_path.exists() {
            std::fs::remove_file(&socket_path)
                .map_err(HypothesisBridgeError::SocketCleanupFailed)?;
        }

        let listener =
            UnixListener::bind(&socket_path).map_err(HypothesisBridgeError::SpawnFailed)?;

        let child = Command::new(python_cmd)
            .args([
                "-m",
                "hypothesis_engine.bridge",
                "--socket",
                &socket_path.to_string_lossy(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(HypothesisBridgeError::SpawnFailed)?;

        let socket = accept_with_timeout(&listener, HANDSHAKE_TIMEOUT)?;

        socket
            .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(|e| {
                HypothesisBridgeError::Timeout(format!("setting handshake timeout: {e}"))
            })?;

        let mut bridge = Self {
            child,
            socket,
            request_counter: 0,
            socket_path,
            shutdown_called: false,
        };
        bridge.read_handshake()?;
        Ok(bridge)
    }

    pub(crate) fn read_handshake(&mut self) -> Result<(), HypothesisBridgeError> {
        let response: BridgeResponse = read_ipc_frame(&mut self.socket)?;
        match response {
            BridgeResponse::Ready => Ok(()),
            other => Err(HypothesisBridgeError::HandshakeFailed(format!(
                "expected Ready, got {other:?}"
            ))),
        }
    }

    /// Sends a GenerateHypotheses request and returns the parsed result.
    pub fn generate_hypotheses(
        &mut self,
        scan_context: ScanContextJson,
        vulnerability_class: String,
        feedback_summary: Option<String>,
    ) -> Result<GenerateResult, HypothesisBridgeError> {
        self.request_counter += 1;
        let request_id = self.request_counter;

        let request = BridgeRequest::GenerateHypotheses {
            request_id,
            scan_context,
            vulnerability_class,
            feedback_summary,
        };

        self.send_request(&request)?;
        self.set_read_timeout(REQUEST_TIMEOUT)?;
        let response: BridgeResponse = read_ipc_frame(&mut self.socket)?;

        match response {
            BridgeResponse::Hypotheses {
                request_id: resp_id,
                hypotheses,
                reasoning_trace,
                input_tokens,
                output_tokens,
            } => {
                Self::validate_request_id(request_id, resp_id)?;
                Ok(GenerateResult {
                    hypotheses,
                    reasoning_trace,
                    input_tokens,
                    output_tokens,
                })
            }
            BridgeResponse::Error {
                request_id: resp_id,
                message,
            } => {
                Self::validate_request_id(request_id, resp_id)?;
                Err(HypothesisBridgeError::PythonError(message))
            }
            other => Err(HypothesisBridgeError::UnexpectedResponse(format!(
                "expected Hypotheses or Error, got {other:?}"
            ))),
        }
    }

    /// Sends a CompilePayloads request and returns the parsed result.
    pub fn compile_payloads(
        &mut self,
        hypotheses: Vec<HypothesisJson>,
    ) -> Result<CompileResult, HypothesisBridgeError> {
        self.request_counter += 1;
        let request_id = self.request_counter;

        let request = BridgeRequest::CompilePayloads {
            request_id,
            hypotheses,
        };

        self.send_request(&request)?;
        self.set_read_timeout(REQUEST_TIMEOUT)?;
        let response: BridgeResponse = read_ipc_frame(&mut self.socket)?;

        match response {
            BridgeResponse::CompiledPayloads {
                request_id: resp_id,
                payloads,
                input_tokens,
                output_tokens,
            } => {
                Self::validate_request_id(request_id, resp_id)?;
                Ok(CompileResult {
                    payloads,
                    input_tokens,
                    output_tokens,
                })
            }
            BridgeResponse::Error {
                request_id: resp_id,
                message,
            } => {
                Self::validate_request_id(request_id, resp_id)?;
                Err(HypothesisBridgeError::PythonError(message))
            }
            other => Err(HypothesisBridgeError::UnexpectedResponse(format!(
                "expected CompiledPayloads or Error, got {other:?}"
            ))),
        }
    }

    /// Sends an EvasionGenerate request and returns the parsed result.
    pub fn generate_evasion(
        &mut self,
        defense_context: DefenseContextJson,
    ) -> Result<EvasionBridgeResult, HypothesisBridgeError> {
        self.request_counter += 1;
        let request_id = self.request_counter;

        let request = BridgeRequest::EvasionGenerate {
            request_id,
            defense_context,
        };

        self.send_request(&request)?;
        self.set_read_timeout(REQUEST_TIMEOUT)?;
        let response: BridgeResponse = read_ipc_frame(&mut self.socket)?;

        match response {
            BridgeResponse::EvasionPayloads {
                request_id: resp_id,
                payloads,
                input_tokens,
                output_tokens,
            } => {
                Self::validate_request_id(request_id, resp_id)?;
                Ok(EvasionBridgeResult {
                    payloads,
                    input_tokens,
                    output_tokens,
                })
            }
            BridgeResponse::Error {
                request_id: resp_id,
                message,
            } => {
                Self::validate_request_id(request_id, resp_id)?;
                Err(HypothesisBridgeError::PythonError(message))
            }
            other => Err(HypothesisBridgeError::UnexpectedResponse(format!(
                "expected EvasionPayloads or Error, got {other:?}"
            ))),
        }
    }

    /// Sends a Shutdown request, waits briefly for the child to exit, and cleans up.
    ///
    /// If the child does not exit within 2 seconds after receiving Shutdown,
    /// it is killed.
    pub fn shutdown(&mut self) -> Result<(), HypothesisBridgeError> {
        if self.shutdown_called {
            return Ok(());
        }
        self.shutdown_called = true;
        let _ = self.send_request(&BridgeRequest::Shutdown);
        self.wait_or_kill_child();
        self.cleanup_socket()
    }

    fn wait_or_kill_child(&mut self) {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        let _ = self.child.kill();
                        let _ = self.child.wait();
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => return,
            }
        }
    }

    fn send_request(&mut self, request: &BridgeRequest) -> Result<(), HypothesisBridgeError> {
        write_ipc_frame(&mut self.socket, request)
    }

    fn set_read_timeout(&self, timeout: Duration) -> Result<(), HypothesisBridgeError> {
        self.socket
            .set_read_timeout(Some(timeout))
            .map_err(|e| HypothesisBridgeError::Timeout(format!("setting read timeout: {e}")))
    }

    fn validate_request_id(expected: u64, actual: u64) -> Result<(), HypothesisBridgeError> {
        if expected != actual {
            return Err(HypothesisBridgeError::RequestIdMismatch { expected, actual });
        }
        Ok(())
    }

    fn cleanup_socket(&self) -> Result<(), HypothesisBridgeError> {
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)
                .map_err(HypothesisBridgeError::SocketCleanupFailed)?;
        }
        Ok(())
    }
}

impl Drop for HypothesisBridge {
    fn drop(&mut self) {
        if let Err(e) = self.shutdown() {
            eprintln!("warning: hypothesis bridge shutdown failed during drop: {e}");
        }
    }
}

/// Accepts a connection on the listener with a timeout.
///
/// Uses a polling loop with short sleeps since `UnixListener` does not
/// natively support accept timeouts in the standard library.
fn accept_with_timeout(
    listener: &UnixListener,
    timeout: Duration,
) -> Result<UnixStream, HypothesisBridgeError> {
    listener
        .set_nonblocking(true)
        .map_err(HypothesisBridgeError::SpawnFailed)?;

    let deadline = std::time::Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _addr)) => {
                stream
                    .set_nonblocking(false)
                    .map_err(HypothesisBridgeError::SpawnFailed)?;
                return Ok(stream);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return Err(HypothesisBridgeError::Timeout(
                        "timed out waiting for Python bridge to connect".to_string(),
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(HypothesisBridgeError::SpawnFailed(e)),
        }
    }
}
