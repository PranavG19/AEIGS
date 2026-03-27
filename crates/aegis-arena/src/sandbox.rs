use regex::Regex;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Sandbox guard that isolates arena agent sessions from the host system.
///
/// Provides workspace jail, prompt guardrails, output sanitization,
/// process monitoring, network fencing, and filesystem snapshot/diff.
pub struct ArenaGuard {
    /// The isolated workspace directory for this arena session.
    pub workspace: PathBuf,
    /// The allowed port for localhost requests.
    pub allowed_port: u16,
    /// Snapshot of files present before a cycle starts.
    file_snapshot: HashSet<String>,
    /// PIDs recorded before spawning an agent.
    tracked_pids: Vec<u32>,
}

/// Result of an output sanitization pass.
#[derive(Debug, Clone)]
pub struct SanitizeResult {
    /// The sanitized output string.
    pub output: String,
    /// Warnings about stripped content.
    pub warnings: Vec<String>,
    /// Whether the output was blocked entirely.
    pub blocked: bool,
}

/// Result of a filesystem diff after a cycle.
#[derive(Debug, Clone)]
pub struct FilesystemDiff {
    /// Files that appeared since the snapshot.
    pub new_files: Vec<String>,
    /// Files that disappeared since the snapshot.
    pub removed_files: Vec<String>,
    /// Files flagged as unexpected (outside allowed set).
    pub flagged: Vec<String>,
}

impl ArenaGuard {
    /// Create a new ArenaGuard with an isolated temp workspace.
    pub fn new(port: u16) -> Self {
        let session_id = uuid_v4_hex();
        let workspace = PathBuf::from(format!("/tmp/aegis-arena-{session_id}/"));
        Self {
            workspace,
            allowed_port: port,
            file_snapshot: HashSet::new(),
            tracked_pids: Vec::new(),
        }
    }

    /// Create an ArenaGuard with a specific workspace path (for testing).
    pub fn with_workspace(workspace: PathBuf, port: u16) -> Self {
        Self {
            workspace,
            allowed_port: port,
            file_snapshot: HashSet::new(),
            tracked_pids: Vec::new(),
        }
    }

    /// Initialize the workspace directory on disk.
    pub async fn init_workspace(&self) -> std::io::Result<()> {
        tokio::fs::create_dir_all(&self.workspace).await?;
        // Write the arena-curl wrapper script
        let curl_script = self.generate_arena_curl_script();
        let curl_path = self.workspace.join("arena-curl");
        tokio::fs::write(&curl_path, curl_script).await?;
        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o755);
            tokio::fs::set_permissions(&curl_path, perms).await?;
        }
        Ok(())
    }

    /// Generate the prompt guardrail block that MUST be included in every agent prompt.
    pub fn prompt_guardrails(&self) -> String {
        format!(
            "SAFETY RULES (VIOLATION = IMMEDIATE TERMINATION):\n\
             - ONLY make HTTP requests to localhost:{port}. NO other hosts. NO internet access.\n\
             - ONLY read/write files in this directory. NO accessing /Users/, /etc/, /home/, or any parent dirs.\n\
             - ONLY use curl for HTTP testing. NO wget, nc, nmap, or any other network tools.\n\
             - Do NOT modify system files, install packages, or change system configuration.\n\
             - Do NOT access or reference any files outside this workspace.\n\
             This is a sandboxed CTF exercise on localhost ONLY.",
            port = self.allowed_port,
        )
    }

    /// Sanitize agent output: strip external paths, non-localhost URLs, and dangerous commands.
    pub fn sanitize_output(&self, raw_output: &str) -> SanitizeResult {
        let mut warnings = Vec::new();
        let mut blocked = false;

        // Check for dangerous commands that warrant total blocking
        let block_patterns = ["rm -rf", "sudo ", "chmod ", "chown "];
        for pattern in &block_patterns {
            if raw_output.contains(pattern) {
                warnings.push(format!("BLOCKED: output contains dangerous command '{pattern}'"));
                blocked = true;
            }
        }

        if blocked {
            return SanitizeResult {
                output: String::new(),
                warnings,
                blocked,
            };
        }

        let mut output = raw_output.to_string();

        // Strip real filesystem paths outside workspace
        let path_patterns = ["/Users/", "/home/", "/etc/passwd"];
        for pattern in &path_patterns {
            if output.contains(pattern) {
                // Only flag if it looks like a real path reference, not a test payload
                // Test payloads typically appear in curl commands or payload strings
                let is_payload = is_likely_payload(&output, pattern);
                if !is_payload {
                    warnings.push(format!(
                        "WARNING: stripped external path reference '{pattern}'"
                    ));
                    output = output.replace(pattern, "[REDACTED]/");
                }
            }
        }

        // Strip non-localhost URLs
        let url_re =
            Regex::new(r"https?://[a-zA-Z0-9._-]+(?::\d+)?[/\w.-]*")
                .unwrap();
        let cleaned = url_re.replace_all(&output, |caps: &regex::Captures| {
            let url = &caps[0];
            // Allow localhost and 127.0.0.1
            if url.contains("localhost") || url.contains("127.0.0.1") {
                return url.to_string();
            }
            warnings.push(format!("WARNING: stripped external URL '{url}'"));
            "[REDACTED_URL]".to_string()
        });
        output = cleaned.to_string();

        SanitizeResult {
            output,
            warnings,
            blocked,
        }
    }

    /// Generate the `arena-curl` shell script that restricts curl to localhost:{port}.
    pub fn generate_arena_curl_script(&self) -> String {
        format!(
            r#"#!/bin/bash
# arena-curl: sandboxed curl wrapper — ONLY allows requests to 127.0.0.1:{port}
# Any other destination is rejected.

ALLOWED="127.0.0.1:{port}"
ALLOWED_LOCALHOST="localhost:{port}"

for arg in "$@"; do
    # Check if argument looks like a URL to a non-allowed host
    if echo "$arg" | grep -qE '^https?://'; then
        if ! echo "$arg" | grep -qE "^https?://(127\.0\.0\.1|localhost):{port}"; then
            echo "ERROR: arena-curl only allows requests to $ALLOWED" >&2
            echo "Blocked request to: $arg" >&2
            exit 1
        fi
    fi
done

exec curl "$@"
"#,
            port = self.allowed_port,
        )
    }

    /// Take a snapshot of the current workspace file listing.
    pub fn snapshot_workspace(&mut self) -> std::io::Result<()> {
        self.file_snapshot.clear();
        if self.workspace.exists() {
            collect_files_recursive(&self.workspace, &mut self.file_snapshot)?;
        }
        Ok(())
    }

    /// Diff the current workspace against the last snapshot.
    pub fn diff_workspace(&self) -> std::io::Result<FilesystemDiff> {
        let mut current = HashSet::new();
        if self.workspace.exists() {
            collect_files_recursive(&self.workspace, &mut current)?;
        }

        let new_files: Vec<String> = current
            .difference(&self.file_snapshot)
            .cloned()
            .collect();
        let removed_files: Vec<String> = self
            .file_snapshot
            .difference(&current)
            .cloned()
            .collect();

        // Flag unexpected files (anything not a briefing, result, hint, or arena-curl)
        let allowed_prefixes = [
            "red_briefing", "blue_briefing", "red_hint", "blue_hint",
            "arena-curl", "arena_result", "arena_memory", "lessons",
        ];
        let flagged: Vec<String> = new_files
            .iter()
            .filter(|f| {
                let basename = Path::new(f)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");
                !allowed_prefixes.iter().any(|prefix| basename.starts_with(prefix))
            })
            .cloned()
            .collect();

        Ok(FilesystemDiff {
            new_files,
            removed_files,
            flagged,
        })
    }

    /// Record PIDs before spawning an agent process.
    pub fn record_pids_before(&mut self) {
        // In a real implementation this would snapshot /proc or use sysctl.
        // For safety, we track pids we know about.
        self.tracked_pids.clear();
    }

    /// After an agent finishes, check for orphan processes.
    /// Returns the list of PIDs that were killed.
    pub fn cleanup_orphan_processes(&self) -> Vec<u32> {
        // Placeholder — in production this would diff process tables
        // and kill orphans spawned within the workspace.
        Vec::new()
    }

    /// Clean up the workspace directory entirely.
    pub async fn cleanup(&self) -> std::io::Result<()> {
        if self.workspace.exists() {
            tokio::fs::remove_dir_all(&self.workspace).await?;
        }
        Ok(())
    }

    /// Validate that a path is within the workspace jail.
    pub fn is_path_allowed(&self, path: &Path) -> bool {
        match (path.canonicalize(), self.workspace.canonicalize()) {
            (Ok(canonical), Ok(workspace_canonical)) => {
                canonical.starts_with(&workspace_canonical)
            }
            _ => {
                // If we can't canonicalize, do a string prefix check
                let path_str = path.to_string_lossy();
                let ws_str = self.workspace.to_string_lossy();
                path_str.starts_with(ws_str.as_ref())
            }
        }
    }
}

/// Check if a pattern in the output is likely a test payload rather than a real path leak.
fn is_likely_payload(output: &str, pattern: &str) -> bool {
    // If the pattern appears inside a curl command or JSON payload, it's likely intentional
    if let Some(idx) = output.find(pattern) {
        let window_start = idx.saturating_sub(40);
        let window = &output[window_start..idx.min(output.len())];
        window.contains("curl")
            || window.contains("payload")
            || window.contains("path=")
            || window.contains("../")
    } else {
        false
    }
}

/// Collect all file paths recursively under a directory.
fn collect_files_recursive(dir: &Path, set: &mut HashSet<String>) -> std::io::Result<()> {
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                collect_files_recursive(&path, set)?;
            } else {
                set.insert(path.to_string_lossy().to_string());
            }
        }
    }
    Ok(())
}

/// Generate a simple hex UUID-v4-like string for workspace naming.
fn uuid_v4_hex() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let bytes: [u8; 16] = rng.random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "sandbox_test.rs"]
mod sandbox_test;
