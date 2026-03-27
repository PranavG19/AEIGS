use super::*;
use std::path::PathBuf;

#[test]
fn workspace_jail_creates_isolated_directory() {
    let guard = ArenaGuard::new(9999);
    assert!(guard.workspace.to_string_lossy().starts_with("/tmp/aegis-arena-"));
    assert!(guard.workspace.to_string_lossy().ends_with('/'));
}

#[test]
fn workspace_with_custom_path() {
    let ws = PathBuf::from("/tmp/test-arena-workspace");
    let guard = ArenaGuard::with_workspace(ws.clone(), 8080);
    assert_eq!(guard.workspace, ws);
    assert_eq!(guard.allowed_port, 8080);
}

#[test]
fn prompt_guardrails_present_in_output() {
    let guard = ArenaGuard::new(9999);
    let guardrails = guard.prompt_guardrails();

    assert!(guardrails.contains("SAFETY RULES"));
    assert!(guardrails.contains("localhost:9999"));
    assert!(guardrails.contains("ONLY make HTTP requests"));
    assert!(guardrails.contains("NO accessing /Users/"));
    assert!(guardrails.contains("NO wget, nc, nmap"));
    assert!(guardrails.contains("Do NOT modify system files"));
    assert!(guardrails.contains("sandboxed CTF exercise"));
}

#[test]
fn prompt_guardrails_include_correct_port() {
    let guard = ArenaGuard::new(4444);
    let guardrails = guard.prompt_guardrails();
    assert!(guardrails.contains("localhost:4444"));
}

#[test]
fn sanitize_catches_users_path() {
    let guard = ArenaGuard::new(9999);
    let output = "Found interesting data at /Users/admin/secrets.txt and more";
    let result = guard.sanitize_output(output);

    assert!(!result.blocked);
    assert!(result.output.contains("[REDACTED]"));
    assert!(!result.warnings.is_empty());
}

#[test]
fn sanitize_catches_home_path() {
    let guard = ArenaGuard::new(9999);
    let output = "Reading /home/deploy/.ssh/id_rsa";
    let result = guard.sanitize_output(output);

    assert!(result.output.contains("[REDACTED]"));
    assert!(result.warnings.iter().any(|w| w.contains("/home/")));
}

#[test]
fn sanitize_catches_external_urls() {
    let guard = ArenaGuard::new(9999);
    let output = "Sending data to https://evil.com/exfil and http://attacker.io/c2";
    let result = guard.sanitize_output(output);

    assert!(!result.blocked);
    assert!(result.output.contains("[REDACTED_URL]"));
    assert!(!result.output.contains("evil.com"));
    assert!(!result.output.contains("attacker.io"));
}

#[test]
fn sanitize_allows_localhost_urls() {
    let guard = ArenaGuard::new(9999);
    let output = "Testing http://localhost:9999/search?q=test and http://127.0.0.1:9999/flag";
    let result = guard.sanitize_output(output);

    assert!(result.output.contains("localhost:9999"));
    assert!(result.output.contains("127.0.0.1:9999"));
    assert!(result.warnings.is_empty());
}

#[test]
fn sanitize_blocks_rm_rf() {
    let guard = ArenaGuard::new(9999);
    let output = "rm -rf / is a fun command";
    let result = guard.sanitize_output(output);

    assert!(result.blocked);
    assert!(result.output.is_empty());
    assert!(result.warnings.iter().any(|w| w.contains("rm -rf")));
}

#[test]
fn sanitize_blocks_sudo() {
    let guard = ArenaGuard::new(9999);
    let output = "Running sudo apt-get install evil-package";
    let result = guard.sanitize_output(output);

    assert!(result.blocked);
    assert!(result.output.is_empty());
}

#[test]
fn sanitize_blocks_chmod() {
    let guard = ArenaGuard::new(9999);
    let output = "chmod 777 /etc/shadow";
    let result = guard.sanitize_output(output);
    assert!(result.blocked);
}

#[test]
fn sanitize_blocks_chown() {
    let guard = ArenaGuard::new(9999);
    let output = "chown root:root /tmp/backdoor";
    let result = guard.sanitize_output(output);
    assert!(result.blocked);
}

#[test]
fn sanitize_clean_output_passes_through() {
    let guard = ArenaGuard::new(9999);
    let output = "Testing SQL injection on localhost:9999/search with payload ' OR 1=1 --\nFLAG_CAPTURED:CTF{test_flag}";
    let result = guard.sanitize_output(output);

    assert!(!result.blocked);
    assert_eq!(result.output, output);
    assert!(result.warnings.is_empty());
}

#[test]
fn arena_curl_script_restricts_to_port() {
    let guard = ArenaGuard::new(7777);
    let script = guard.generate_arena_curl_script();

    assert!(script.contains("127.0.0.1:7777"));
    assert!(script.contains("localhost:7777"));
    assert!(script.contains("arena-curl only allows"));
    assert!(script.starts_with("#!/bin/bash"));
}

#[test]
fn arena_curl_rejects_non_localhost() {
    let guard = ArenaGuard::new(9999);
    let script = guard.generate_arena_curl_script();

    // The script should contain the logic to reject non-localhost URLs
    assert!(script.contains("grep -qE"));
    assert!(script.contains("exit 1"));
    assert!(script.contains("Blocked request"));
}

#[tokio::test]
async fn filesystem_snapshot_catches_new_files() {
    let tmp = std::env::temp_dir().join("aegis-sandbox-test-snapshot");
    let _ = tokio::fs::create_dir_all(&tmp).await;

    // Write an initial file
    tokio::fs::write(tmp.join("initial.txt"), "hello").await.unwrap();

    let mut guard = ArenaGuard::with_workspace(tmp.clone(), 9999);
    guard.snapshot_workspace().unwrap();

    // Create a new file after snapshot
    tokio::fs::write(tmp.join("unexpected_backdoor.sh"), "evil").await.unwrap();

    let diff = guard.diff_workspace().unwrap();
    assert!(!diff.new_files.is_empty());
    assert!(diff.new_files.iter().any(|f| f.contains("unexpected_backdoor")));
    assert!(!diff.flagged.is_empty());

    // Cleanup
    let _ = tokio::fs::remove_dir_all(&tmp).await;
}

#[tokio::test]
async fn filesystem_snapshot_allows_expected_files() {
    let tmp = std::env::temp_dir().join("aegis-sandbox-test-expected");
    let _ = tokio::fs::create_dir_all(&tmp).await;

    let mut guard = ArenaGuard::with_workspace(tmp.clone(), 9999);
    guard.snapshot_workspace().unwrap();

    // Create expected files
    tokio::fs::write(tmp.join("red_briefing.md"), "briefing").await.unwrap();
    tokio::fs::write(tmp.join("blue_briefing.md"), "briefing").await.unwrap();
    tokio::fs::write(tmp.join("arena_result.json"), "{}").await.unwrap();

    let diff = guard.diff_workspace().unwrap();
    // These should be new but NOT flagged (they're expected)
    assert!(!diff.new_files.is_empty());
    assert!(diff.flagged.is_empty());

    let _ = tokio::fs::remove_dir_all(&tmp).await;
}

#[tokio::test]
async fn init_workspace_creates_dir_and_curl() {
    let guard = ArenaGuard::new(9999);
    guard.init_workspace().await.unwrap();

    assert!(guard.workspace.exists());
    let curl_path = guard.workspace.join("arena-curl");
    assert!(curl_path.exists());

    // Verify arena-curl content
    let content = tokio::fs::read_to_string(&curl_path).await.unwrap();
    assert!(content.contains("arena-curl"));
    assert!(content.contains("9999"));

    // Cleanup
    guard.cleanup().await.unwrap();
    assert!(!guard.workspace.exists());
}

#[test]
fn path_allowed_inside_workspace() {
    let ws = PathBuf::from("/tmp/aegis-arena-test-jail");
    std::fs::create_dir_all(&ws).unwrap();
    let guard = ArenaGuard::with_workspace(ws.clone(), 9999);

    let inside = ws.join("briefing.md");
    std::fs::write(&inside, "test").unwrap();
    assert!(guard.is_path_allowed(&inside));

    let outside = PathBuf::from("/etc/passwd");
    assert!(!guard.is_path_allowed(&outside));

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn sanitize_payload_paths_not_stripped() {
    let guard = ArenaGuard::new(9999);
    // A curl command testing path traversal — the /etc/passwd here is a payload
    let output = "curl 'http://localhost:9999/file?path=../../../etc/passwd'";
    let result = guard.sanitize_output(output);

    // This should NOT be stripped because it appears after path= (payload context)
    // The is_likely_payload heuristic catches this
    assert!(!result.blocked);
}

#[test]
fn process_monitor_returns_empty_initially() {
    let guard = ArenaGuard::new(9999);
    let orphans = guard.cleanup_orphan_processes();
    assert!(orphans.is_empty());
}
