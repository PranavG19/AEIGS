use serde::{Deserialize, Serialize};
use std::io::Write;
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
