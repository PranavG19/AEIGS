use super::*;
use crate::arena_target::{build_arena_router, PatchRule};
use std::os::unix::process::ExitStatusExt;
use std::process::{ExitStatus, Output};

/// Spin up an arena target on a random port and return the URL.
async fn start_test_target(flag: &str, patches: Vec<PatchRule>) -> (String, tokio::task::JoinHandle<()>) {
    let (router, _log) = build_arena_router(flag.to_string(), patches);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (format!("http://127.0.0.1:{port}"), handle)
}

/// Mock opencode runner that returns predefined output.
struct MockOpencodeRunner {
    stdout: String,
    exit_code: i32,
}

impl MockOpencodeRunner {
    fn with_flag(flag: &str) -> Self {
        Self {
            stdout: format!("Running attack...\nFound vulnerability!\nFLAG_CAPTURED:{flag}\nDone."),
            exit_code: 0,
        }
    }

    fn with_no_flag() -> Self {
        Self {
            stdout: "Running attack...\nAll requests returned 403.\nNo flag found.".to_string(),
            exit_code: 0,
        }
    }

    fn with_findings() -> Self {
        Self {
            stdout: "Running attack...\nSQL Error in query: SELECT * FROM items\nroot:x:0:0 found in /etc/passwd\nRendered: some_value\nNo flag captured.".to_string(),
            exit_code: 0,
        }
    }

    fn with_failure() -> Self {
        Self {
            stdout: String::new(),
            exit_code: 1,
        }
    }
}

impl OpencodeRunner for MockOpencodeRunner {
    async fn run(&self, _workspace: &Path, _prompt: &str, _model: &str, _timeout: Duration) -> std::io::Result<Output> {
        Ok(Output {
            status: ExitStatus::from_raw(self.exit_code * 256),
            stdout: self.stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        })
    }
}

// ─── Briefing generation tests ──────────────────────────────────────────────

#[test]
fn briefing_contains_target_url() {
    let briefing = RedAgent::write_red_briefing(1, "http://localhost:9999", &[], &[]);
    assert!(briefing.contains("http://localhost:9999"));
    assert!(briefing.contains("Round 1"));
}

#[test]
fn briefing_contains_attack_vectors() {
    let briefing = RedAgent::write_red_briefing(1, "http://localhost:9999", &[], &[]);
    assert!(briefing.contains("/search"));
    assert!(briefing.contains("/file"));
    assert!(briefing.contains("/template"));
    assert!(briefing.contains("/admin"));
    assert!(briefing.contains("/flag"));
    assert!(briefing.contains("/profile"));
    assert!(briefing.contains("/login"));
    assert!(briefing.contains("SQL Injection"));
    assert!(briefing.contains("Path Traversal"));
    assert!(briefing.contains("SSTI"));
    assert!(briefing.contains("JWT"));
}

#[test]
fn briefing_includes_defenses() {
    let defenses = vec![
        PatchRule::new("/search", "OR ", false),
        PatchRule::new("/file", r"(\.\.|%2e)", true),
    ];
    let briefing = RedAgent::write_red_briefing(1, "http://localhost:9999", &[], &defenses);
    assert!(briefing.contains("Known Blue Team Defenses"));
    assert!(briefing.contains("OR "));
    assert!(briefing.contains("/search"));
    assert!(briefing.contains("evasion techniques"));
}

#[test]
fn briefing_includes_history() {
    let history = vec![RedRoundResult {
        flag_captured: false,
        flag_value: None,
        requests_sent: 5,
        vulns_found: vec!["sqli_search_0".to_string()],
        blocked_count: 2,
        request_log: vec![
            RequestLogEntry {
                method: "GET".to_string(),
                path: "/search".to_string(),
                query_string: "q=' OR 1=1".to_string(),
                body: String::new(),
                status: 403,
                response_body: "Blocked".to_string(),
            },
        ],
        techniques_used: vec!["sqli_search_0".to_string()],
        raw_output: String::new(),
    }];

    let briefing = RedAgent::write_red_briefing(2, "http://localhost:9999", &history, &[]);
    assert!(briefing.contains("Previous Round Results"));
    assert!(briefing.contains("Round 1"));
    assert!(briefing.contains("Blocked: 2"));
    assert!(briefing.contains("DO NOT repeat attacks"));
}

#[test]
fn briefing_includes_curl_examples() {
    let briefing = RedAgent::write_red_briefing(1, "http://localhost:9999", &[], &[]);
    assert!(briefing.contains("curl"));
    assert!(briefing.contains("FLAG_CAPTURED"));
}

// ─── Output parsing tests ───────────────────────────────────────────────────

#[test]
fn parse_flag_captured_output() {
    let output = "Attempting attack...\nFLAG_CAPTURED:CTF{test_abc_123}\nDone.";
    let result = parse_red_output(output, true);
    assert!(result.flag_captured);
    assert_eq!(result.flag_value.as_deref(), Some("CTF{test_abc_123}"));
    assert!(result.exit_success);
}

#[test]
fn parse_ctf_flag_in_output() {
    let output = "Response: secret_flag=CTF{embedded_flag_xyz}\nMore output";
    let result = parse_red_output(output, true);
    assert!(result.flag_captured);
    assert_eq!(result.flag_value.as_deref(), Some("CTF{embedded_flag_xyz}"));
}

#[test]
fn parse_no_flag_output() {
    let output = "All requests returned 403 Forbidden.\nNo vulnerabilities found.";
    let result = parse_red_output(output, true);
    assert!(!result.flag_captured);
    assert!(result.flag_value.is_none());
}

#[test]
fn parse_findings_without_flag() {
    let output = "SQL Error in query: SELECT * FROM items\nroot:x:0:0 found\nAdmin Control Panel accessible";
    let result = parse_red_output(output, true);
    assert!(!result.flag_captured);
    assert!(result.findings.len() >= 2);
}

#[test]
fn parse_failed_process() {
    let result = parse_red_output("", false);
    assert!(!result.flag_captured);
    assert!(!result.exit_success);
}

#[test]
fn parse_flag_captured_prefix_priority() {
    let output = "FLAG_CAPTURED:CTF{explicit_flag}\nSome other line with CTF{embedded_flag}";
    let result = parse_red_output(output, true);
    assert!(result.flag_captured);
    assert_eq!(result.flag_value.as_deref(), Some("CTF{explicit_flag}"));
}

// ─── Opencode integration tests (mocked) ────────────────────────────────────

#[tokio::test]
async fn mock_opencode_captures_flag() {
    let runner = MockOpencodeRunner::with_flag("CTF{mock_flag_abc}");
    let agent = RedAgent::new();
    let workspace = std::env::temp_dir().join("aegis_test_red");
    let _ = tokio::fs::create_dir_all(&workspace).await;

    let output = agent.spawn_red_opencode(
        &runner,
        &workspace.join("red_briefing.md"),
        &workspace,
        "http://localhost:9999",
    ).await;

    assert!(output.flag_captured);
    assert_eq!(output.flag_value.as_deref(), Some("CTF{mock_flag_abc}"));
}

#[tokio::test]
async fn mock_opencode_no_flag() {
    let runner = MockOpencodeRunner::with_no_flag();
    let agent = RedAgent::new();
    let workspace = std::env::temp_dir().join("aegis_test_red_noflag");
    let _ = tokio::fs::create_dir_all(&workspace).await;

    let output = agent.spawn_red_opencode(
        &runner,
        &workspace.join("red_briefing.md"),
        &workspace,
        "http://localhost:9999",
    ).await;

    assert!(!output.flag_captured);
    assert!(output.flag_value.is_none());
}

#[tokio::test]
async fn mock_opencode_with_findings() {
    let runner = MockOpencodeRunner::with_findings();
    let agent = RedAgent::new();
    let workspace = std::env::temp_dir().join("aegis_test_red_findings");
    let _ = tokio::fs::create_dir_all(&workspace).await;

    let output = agent.spawn_red_opencode(
        &runner,
        &workspace.join("red_briefing.md"),
        &workspace,
        "http://localhost:9999",
    ).await;

    assert!(!output.flag_captured);
    assert!(!output.findings.is_empty(), "Should collect findings from output");
}

#[tokio::test]
async fn execute_round_writes_briefing_and_parses() {
    let runner = MockOpencodeRunner::with_flag("CTF{round_test_xyz}");
    let mut agent = RedAgent::new();
    let workspace = std::env::temp_dir().join("aegis_test_red_round");
    let _ = tokio::fs::create_dir_all(&workspace).await;

    let result = agent.execute_round(
        &runner,
        &workspace,
        "http://localhost:9999",
        1,
        &[],
        &[],
    ).await;

    assert!(result.flag_captured);
    assert_eq!(result.flag_value.as_deref(), Some("CTF{round_test_xyz}"));

    // Verify briefing was written
    let briefing_path = workspace.join("red_briefing.md");
    let briefing_content = tokio::fs::read_to_string(&briefing_path).await.unwrap();
    assert!(briefing_content.contains("Red Team Briefing"));
    assert!(briefing_content.contains("http://localhost:9999"));
}

// ─── Fallback (hardcoded) attack tests ──────────────────────────────────────

#[tokio::test]
async fn fallback_captures_flag_from_unpatched_target() {
    let flag = "CTF{red_test_abc123}";
    let (url, handle) = start_test_target(flag, vec![]).await;

    let mut agent = RedAgent::new();
    let result = agent.attack_fallback(&url, 1, &[]).await;

    assert!(result.flag_captured, "Red should capture the flag from an unpatched target");
    assert_eq!(result.flag_value.as_deref(), Some(flag));
    assert!(result.requests_sent > 0);
    assert!(!result.vulns_found.is_empty());

    handle.abort();
}

#[tokio::test]
async fn fallback_reports_blocked_requests() {
    let flag = "CTF{blocked_test_456}";
    let patches = vec![
        PatchRule::new("/search", "OR ", false),
        PatchRule::new("/search", "UNION ", false),
        PatchRule::new("/search", "'", false),
    ];
    let (url, handle) = start_test_target(flag, patches).await;

    let mut agent = RedAgent::new();
    let result = agent.attack_fallback(&url, 1, &[]).await;

    assert!(result.blocked_count > 0, "Some attacks should be blocked");
    assert!(result.flag_captured, "Red should find alternate vectors");

    handle.abort();
}

#[test]
fn extract_flag_from_body() {
    assert_eq!(
        extract_flag("Error: secret_flag=CTF{hello_123}\nmore text"),
        Some("CTF{hello_123}".to_string())
    );
    assert_eq!(extract_flag("no flag here"), None);
    assert_eq!(extract_flag(""), None);
}

#[test]
fn red_generates_more_attacks_in_later_rounds() {
    let agent = RedAgent::new();
    let round1 = agent.generate_attacks("http://localhost:9999", 1);
    let round5 = agent.generate_attacks("http://localhost:9999", 5);
    let round10 = agent.generate_attacks("http://localhost:9999", 10);

    assert!(round5.len() > round1.len(), "Later rounds should have more attack variants");
    assert!(round10.len() > round5.len(), "Round 10+ should add deep evasion");
}

#[test]
fn urlencoded_handles_special_chars() {
    assert_eq!(urlencoded("hello"), "hello");
    assert_eq!(urlencoded("a b"), "a%20b");
    assert!(urlencoded("' OR 1=1").contains("%27"));
}
