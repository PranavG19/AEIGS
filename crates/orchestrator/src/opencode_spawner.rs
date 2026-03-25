use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Maximum output size in bytes before truncation (4 MiB).
const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

/// Configuration for spawning an `opencode run` child process.
///
/// Controls the model, timeout, token limits, workspace, and optional
/// system prompt injection via a file written to disk before launch.
#[derive(Debug, Clone)]
pub struct SpawnerConfig {
    pub binary_path: String,
    pub model: String,
    pub timeout: Duration,
    pub max_tokens: Option<u32>,
    pub workspace_dir: PathBuf,
    pub system_prompt_file: Option<PathBuf>,
    pub output_format: SpawnerOutputFormat,
    pub env_vars: Vec<(String, String)>,
}

impl Default for SpawnerConfig {
    fn default() -> Self {
        Self {
            binary_path: "opencode".to_string(),
            model: "anthropic:claude-sonnet-4-20250514".to_string(),
            timeout: Duration::from_secs(300),
            max_tokens: None,
            workspace_dir: PathBuf::from("."),
            system_prompt_file: None,
            output_format: SpawnerOutputFormat::Json,
            env_vars: Vec::new(),
        }
    }
}

/// Output format requested from the opencode process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnerOutputFormat {
    Json,
    Text,
}

impl SpawnerOutputFormat {
    fn as_arg(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Text => "text",
        }
    }
}

/// Captured output from a completed opencode process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpawnerOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub truncated: bool,
}

/// Errors from the spawner.
#[derive(Debug)]
pub enum SpawnerError {
    BinaryNotFound(String),
    SpawnFailed(std::io::Error),
    Timeout {
        partial_stdout: String,
        elapsed_ms: u64,
    },
    ProcessFailed {
        exit_code: i32,
        stderr: String,
    },
    OutputTruncated {
        output: SpawnerOutput,
    },
    Io(std::io::Error),
}

impl std::fmt::Display for SpawnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BinaryNotFound(bin) => write!(f, "opencode binary not found: {bin}"),
            Self::SpawnFailed(e) => write!(f, "failed to spawn opencode: {e}"),
            Self::Timeout { elapsed_ms, .. } => {
                write!(f, "opencode timed out after {elapsed_ms}ms")
            }
            Self::ProcessFailed { exit_code, stderr } => {
                write!(f, "opencode exited with code {exit_code}: {stderr}")
            }
            Self::OutputTruncated { output } => {
                write!(
                    f,
                    "output truncated at {} bytes (exit code {:?})",
                    output.stdout.len(),
                    output.exit_code,
                )
            }
            Self::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for SpawnerError {}

impl From<std::io::Error> for SpawnerError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Inject a system prompt into a temporary file for opencode consumption.
///
/// Writes the prompt content to the specified path so that `opencode run`
/// can read it as its system context. Returns the path written.
pub fn write_system_prompt(dir: &Path, prompt: &str) -> Result<PathBuf, std::io::Error> {
    let prompt_path = dir.join(".aegis-mind-prompt.md");
    std::fs::write(&prompt_path, prompt)?;
    Ok(prompt_path)
}

/// Build the argument vector for `opencode run`.
pub fn build_args(config: &SpawnerConfig, user_prompt: &str) -> Vec<String> {
    let mut args = vec![
        "run".to_string(),
        "--dir".to_string(),
        config.workspace_dir.to_string_lossy().to_string(),
        "--model".to_string(),
        config.model.clone(),
        "--format".to_string(),
        config.output_format.as_arg().to_string(),
    ];

    if let Some(max_tokens) = config.max_tokens {
        args.push("--max-tokens".to_string());
        args.push(max_tokens.to_string());
    }

    args.push(user_prompt.to_string());
    args
}

/// Spawn `opencode run` as a child process and capture its output.
///
/// The process runs with stdout/stderr piped. If the process exceeds the
/// configured timeout, it is killed and a `SpawnerError::Timeout` is
/// returned with whatever partial stdout was captured. Output exceeding
/// `MAX_OUTPUT_BYTES` is truncated and the `truncated` flag is set.
pub fn spawn_opencode(
    config: &SpawnerConfig,
    user_prompt: &str,
) -> Result<SpawnerOutput, SpawnerError> {
    let args = build_args(config, user_prompt);

    let mut cmd = Command::new(&config.binary_path);
    cmd.args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir(&config.workspace_dir);

    for (key, val) in &config.env_vars {
        cmd.env(key, val);
    }

    let start = Instant::now();

    let mut child = cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            SpawnerError::BinaryNotFound(config.binary_path.clone())
        } else {
            SpawnerError::SpawnFailed(e)
        }
    })?;

    let result = wait_with_timeout(&mut child, config.timeout, start);

    let elapsed_ms = start.elapsed().as_millis() as u64;

    match result {
        WaitResult::Completed(status) => {
            let (stdout, truncated) = read_capped(child.stdout.take(), MAX_OUTPUT_BYTES);
            let (stderr, _) = read_capped(child.stderr.take(), MAX_OUTPUT_BYTES);

            let exit_code = status.code();
            let output = SpawnerOutput {
                stdout,
                stderr,
                exit_code,
                duration_ms: elapsed_ms,
                truncated,
            };

            if let Some(code) = exit_code
                && code != 0
            {
                return Err(SpawnerError::ProcessFailed {
                    exit_code: code,
                    stderr: output.stderr.clone(),
                });
            }

            if truncated {
                return Err(SpawnerError::OutputTruncated { output });
            }

            Ok(output)
        }
        WaitResult::Timeout(partial) => {
            let _ = child.kill();
            Err(SpawnerError::Timeout {
                partial_stdout: partial,
                elapsed_ms,
            })
        }
    }
}

/// Parse structured JSON output from a successful spawner run.
///
/// Attempts to parse the stdout as JSON. Falls back to extracting a JSON
/// block from markdown fences if the raw parse fails.
pub fn parse_structured_output(output: &SpawnerOutput) -> Result<serde_json::Value, SpawnerError> {
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&output.stdout) {
        return Ok(val);
    }

    if let Some(block) = extract_json_block(&output.stdout)
        && let Ok(val) = serde_json::from_str::<serde_json::Value>(&block)
    {
        return Ok(val);
    }

    Err(SpawnerError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!(
            "could not parse structured output ({} bytes)",
            output.stdout.len()
        ),
    )))
}

/// Check whether the opencode binary is available.
pub fn is_binary_available(binary_path: &str) -> bool {
    Command::new("which")
        .arg(binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

enum WaitResult {
    Completed(std::process::ExitStatus),
    Timeout(String),
}

fn wait_with_timeout(child: &mut Child, timeout: Duration, start: Instant) -> WaitResult {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return WaitResult::Completed(status),
            Ok(None) => {
                if start.elapsed() > timeout {
                    let partial = child
                        .stdout
                        .as_mut()
                        .map(|s| {
                            let mut buf = String::new();
                            let _ = s.read_to_string(&mut buf);
                            buf
                        })
                        .unwrap_or_default();
                    return WaitResult::Timeout(partial);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                return WaitResult::Timeout(String::new());
            }
        }
    }
}

fn read_capped<R: Read>(reader: Option<R>, max_bytes: usize) -> (String, bool) {
    let Some(reader) = reader else {
        return (String::new(), false);
    };
    let mut buf = Vec::with_capacity(max_bytes.min(65536));
    let mut reader = BufReader::new(reader);
    let mut truncated = false;

    loop {
        let available = reader.fill_buf();
        match available {
            Ok([]) => break,
            Ok(data) => {
                let remaining = max_bytes.saturating_sub(buf.len());
                if remaining == 0 {
                    truncated = true;
                    break;
                }
                let take = data.len().min(remaining);
                buf.extend_from_slice(&data[..take]);
                let consumed = data.len();
                reader.consume(consumed);
                if take < consumed {
                    truncated = true;
                    break;
                }
            }
            Err(_) => break,
        }
    }

    (String::from_utf8_lossy(&buf).to_string(), truncated)
}

fn extract_json_block(text: &str) -> Option<String> {
    let fence_start = text.find("```json")?;
    let content_start = text[fence_start..].find('\n')? + fence_start + 1;
    let fence_end = text[content_start..].find("```")?;
    Some(
        text[content_start..content_start + fence_end]
            .trim()
            .to_string(),
    )
}

#[cfg(test)]
#[path = "opencode_spawner_test.rs"]
mod opencode_spawner_test;
