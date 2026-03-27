use super::*;
use crate::arena_target::RequestLogEntry;
use crate::red_agent::OpencodeRunner;
use std::os::unix::process::ExitStatusExt;
use std::process::{ExitStatus, Output};
use std::time::Duration;

fn make_log_entry(
    method: &str,
    path: &str,
    query: &str,
    body: &str,
    status: u16,
    response_body: &str,
) -> RequestLogEntry {
    RequestLogEntry {
        method: method.to_string(),
        path: path.to_string(),
        query_string: query.to_string(),
        body: body.to_string(),
        status,
        response_body: response_body.to_string(),
    }
}

/// Mock opencode runner for blue agent tests.
struct MockBlueRunner {
    stdout: String,
}

impl MockBlueRunner {
    fn with_patches() -> Self {
        Self {
            stdout: "Analyzing red team traffic...\n\
                     BLOCK endpoint=/search pattern=OR 1=1\n\
                     BLOCK endpoint=/search pattern=UNION SELECT\n\
                     BLOCK endpoint=/file pattern=../\n\
                     BLOCK_REGEX endpoint=/template pattern=\\{\\{.*\\}\\}\n\
                     FIX endpoint=/search description=Use parameterized queries\n\
                     FIX endpoint=/file description=Validate path against allowlist\n\
                     Done."
                .to_string(),
        }
    }

    fn with_no_patches() -> Self {
        Self {
            stdout: "All attacks were already blocked by existing rules.\nNo new patches needed."
                .to_string(),
        }
    }

    fn with_single_patch() -> Self {
        Self {
            stdout: "BLOCK endpoint=/search pattern=' OR\nDone.".to_string(),
        }
    }
}

impl OpencodeRunner for MockBlueRunner {
    async fn run(
        &self,
        _workspace: &Path,
        _prompt: &str,
        _model: &str,
        _timeout: Duration,
    ) -> std::io::Result<Output> {
        Ok(Output {
            status: ExitStatus::from_raw(0),
            stdout: self.stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        })
    }
}

// ─── Briefing generation tests ──────────────────────────────────────────────

#[test]
fn briefing_contains_round_number() {
    let briefing = BlueAgent::write_blue_briefing(3, &[], &[], &[]);
    assert!(briefing.contains("Round 3"));
    assert!(briefing.contains("Blue Team Briefing"));
}

#[test]
fn briefing_contains_request_log() {
    let log = vec![HttpExchange {
        method: "GET".to_string(),
        path: "/search".to_string(),
        query_string: "q=' OR 1=1 --".to_string(),
        body: String::new(),
        status: 500,
        response_snippet: "SQL Error".to_string(),
    }];

    let briefing = BlueAgent::write_blue_briefing(1, &log, &[], &[]);
    assert!(briefing.contains("/search"));
    assert!(briefing.contains("500"));
    assert!(briefing.contains("GET"));
}

#[test]
fn briefing_contains_findings() {
    let findings = vec!["SQL injection on /search".to_string(), "LFI on /file".to_string()];
    let briefing = BlueAgent::write_blue_briefing(1, &[], &findings, &[]);
    assert!(briefing.contains("Successful Exploits"));
    assert!(briefing.contains("SQL injection on /search"));
    assert!(briefing.contains("LFI on /file"));
    assert!(briefing.contains("MUST be patched"));
}

#[test]
fn briefing_contains_current_patches() {
    let patches = vec![
        PatchRule::new("/search", "OR ", false),
        PatchRule::new("/file", r"(\.\.|%2e)", true),
    ];
    let briefing = BlueAgent::write_blue_briefing(1, &[], &[], &patches);
    assert!(briefing.contains("Current Defense Rules"));
    assert!(briefing.contains("OR "));
    assert!(briefing.contains("/search"));
    assert!(briefing.contains("Do NOT duplicate"));
}

#[test]
fn briefing_contains_instructions() {
    let briefing = BlueAgent::write_blue_briefing(1, &[], &[], &[]);
    assert!(briefing.contains("BLOCK endpoint="));
    assert!(briefing.contains("BLOCK_REGEX"));
    assert!(briefing.contains("/health"));
}

// ─── Output parsing tests ───────────────────────────────────────────────────

#[test]
fn parse_block_rules() {
    let output = "BLOCK endpoint=/search pattern=OR 1=1\nBLOCK endpoint=/file pattern=../";
    let result = parse_blue_output(output, true);
    assert_eq!(result.patches.len(), 2);
    assert_eq!(result.patches[0].endpoint, "/search");
    assert_eq!(result.patches[0].block_pattern, "OR 1=1");
    assert!(!result.patches[0].is_regex);
    assert_eq!(result.patches[1].endpoint, "/file");
    assert_eq!(result.patches[1].block_pattern, "../");
}

#[test]
fn parse_regex_block_rules() {
    let output = r"BLOCK_REGEX endpoint=/template pattern=\{\{.*\}\}";
    let result = parse_blue_output(output, true);
    assert_eq!(result.patches.len(), 1);
    assert!(result.patches[0].is_regex);
    assert_eq!(result.patches[0].endpoint, "/template");
}

#[test]
fn parse_fix_suggestions() {
    let output = "FIX endpoint=/search description=Use parameterized queries\nFIX endpoint=/file description=Validate path";
    let result = parse_blue_output(output, true);
    assert_eq!(result.code_fixes.len(), 2);
    assert!(result.code_fixes[0].contains("parameterized"));
}

#[test]
fn parse_mixed_output() {
    let output = "Analyzing traffic...\n\
                  BLOCK endpoint=/search pattern=' OR\n\
                  Some analysis text...\n\
                  BLOCK_REGEX endpoint=/file pattern=\\.\\..*\n\
                  FIX endpoint=/search description=Use prepared statements\n\
                  Done.";
    let result = parse_blue_output(output, true);
    assert_eq!(result.patches.len(), 2);
    assert_eq!(result.code_fixes.len(), 1);
}

#[test]
fn parse_empty_output() {
    let result = parse_blue_output("No patches needed.", true);
    assert!(result.patches.is_empty());
    assert!(result.code_fixes.is_empty());
}

#[test]
fn parse_block_with_quoted_pattern() {
    let output = "BLOCK endpoint=/search pattern='OR 1=1 --'";
    let result = parse_blue_output(output, true);
    assert_eq!(result.patches.len(), 1);
    assert_eq!(result.patches[0].block_pattern, "OR 1=1 --");
}

// ─── Opencode integration tests (mocked) ────────────────────────────────────

#[tokio::test]
async fn mock_opencode_generates_patches() {
    let runner = MockBlueRunner::with_patches();
    let agent = BlueAgent::new();
    let workspace = std::env::temp_dir().join("aegis_test_blue");
    let _ = tokio::fs::create_dir_all(&workspace).await;

    let output = agent
        .spawn_blue_opencode(
            &runner,
            &workspace.join("blue_briefing.md"),
            &workspace,
            "GET /search → 500; GET /file → 200",
        )
        .await;

    assert!(!output.patches.is_empty(), "Should generate patches");
    assert!(!output.code_fixes.is_empty(), "Should suggest code fixes");
}

#[tokio::test]
async fn mock_opencode_no_patches() {
    let runner = MockBlueRunner::with_no_patches();
    let agent = BlueAgent::new();
    let workspace = std::env::temp_dir().join("aegis_test_blue_empty");
    let _ = tokio::fs::create_dir_all(&workspace).await;

    let output = agent
        .spawn_blue_opencode(
            &runner,
            &workspace.join("blue_briefing.md"),
            &workspace,
            "all blocked",
        )
        .await;

    assert!(output.patches.is_empty());
}

#[tokio::test]
async fn execute_round_writes_briefing() {
    let runner = MockBlueRunner::with_single_patch();
    let mut agent = BlueAgent::new();
    let workspace = std::env::temp_dir().join("aegis_test_blue_round");
    let _ = tokio::fs::create_dir_all(&workspace).await;

    let red_log = vec![HttpExchange {
        method: "GET".to_string(),
        path: "/search".to_string(),
        query_string: "q=' OR 1=1".to_string(),
        body: String::new(),
        status: 500,
        response_snippet: "SQL Error".to_string(),
    }];

    let result = agent
        .execute_round(&runner, &workspace, 1, &red_log, &["sqli".to_string()], &[])
        .await;

    assert!(!result.patches_generated.is_empty());

    let briefing_path = workspace.join("blue_briefing.md");
    let content = tokio::fs::read_to_string(&briefing_path).await.unwrap();
    assert!(content.contains("Blue Team Briefing"));
    assert!(content.contains("/search"));
}

// ─── Fallback (hardcoded) defense tests ─────────────────────────────────────

#[test]
fn fallback_generates_patches_for_sqli() {
    let mut blue = BlueAgent::new();
    let log = vec![make_log_entry(
        "GET",
        "/search",
        "q=' OR 1=1 --",
        "",
        500,
        "SQL Error CTF{flag}",
    )];

    let result = blue.defend_fallback(&log, &["sqli_search_0".to_string()]);

    assert!(
        !result.patches_generated.is_empty(),
        "Should generate patches"
    );
    let has_sqli_patch = result.patches_generated.iter().any(|p| {
        p.endpoint == "/search" && (p.block_pattern.contains("OR") || p.block_pattern.contains("'"))
    });
    assert!(
        has_sqli_patch,
        "Should generate SQLi-blocking patches for /search"
    );
}

#[test]
fn fallback_generates_patches_for_lfi() {
    let mut blue = BlueAgent::new();
    let log = vec![make_log_entry(
        "GET",
        "/file",
        "path=../../../etc/passwd",
        "",
        200,
        "root:x:0 CTF{flag}",
    )];

    let result = blue.defend_fallback(&log, &["lfi_file_0".to_string()]);

    let has_lfi_patch = result
        .patches_generated
        .iter()
        .any(|p| p.endpoint == "/file" && p.block_pattern.contains(".."));
    assert!(
        has_lfi_patch,
        "Should generate LFI-blocking patches for /file"
    );
}

#[test]
fn fallback_generates_patches_for_ssti() {
    let mut blue = BlueAgent::new();
    let log = vec![make_log_entry(
        "POST",
        "/template",
        "",
        r#"{"template":"{{config}}"}"#,
        200,
        "Rendered: CTF{flag}",
    )];

    let result = blue.defend_fallback(&log, &["ssti_template_0".to_string()]);

    let has_ssti_patch = result.patches_generated.iter().any(|p| {
        p.endpoint == "/template"
            && (p.block_pattern.contains("{{") || p.block_pattern.contains("{%"))
    });
    assert!(
        has_ssti_patch,
        "Should generate SSTI-blocking patches for /template"
    );
}

#[test]
fn fallback_does_not_block_health() {
    let mut blue = BlueAgent::new();
    let log = vec![make_log_entry(
        "GET",
        "/search",
        "q=' OR 1=1",
        "",
        500,
        "SQL Error CTF{flag}",
    )];

    let result = blue.defend_fallback(&log, &[]);

    assert!(
        result.false_positive_check_passed,
        "Patches should not block /health"
    );
}

#[test]
fn fallback_avoids_duplicate_patches() {
    let mut blue = BlueAgent::new();
    let log = vec![make_log_entry(
        "GET",
        "/search",
        "q=' OR 1=1",
        "",
        500,
        "SQL Error CTF{flag}",
    )];

    let result1 = blue.defend_fallback(&log, &[]);
    let count1 = result1.patches_generated.len();

    let result2 = blue.defend_fallback(&log, &[]);
    assert_eq!(
        result2.patches_generated.len(),
        0,
        "Should not duplicate patches: got {} on second round",
        result2.patches_generated.len()
    );

    assert!(count1 > 0, "First round should generate patches");
}

#[test]
fn fallback_escalates_defenses_over_rounds() {
    let log = vec![make_log_entry(
        "GET",
        "/search",
        "q=' OR 1=1 --",
        "",
        500,
        "SQL Error CTF{flag}",
    )];

    let mut blue = BlueAgent::new();
    let r1 = blue.defend_fallback(&log, &[]);
    let basic_count = r1.patches_generated.len();

    let mut blue = BlueAgent::new();
    blue.rounds_defended = 4;

    let r5 = blue.defend_fallback(&log, &[]);

    assert!(
        r5.patches_generated.len() >= basic_count,
        "Advanced round should generate at least as many patches"
    );

    let has_regex = r5.patches_generated.iter().any(|p| p.is_regex);
    assert!(has_regex, "Advanced rounds should include regex patches");
}

#[test]
fn normalizes_endpoint_paths() {
    assert_eq!(normalize_endpoint("/profile/123"), "/profile");
    assert_eq!(normalize_endpoint("/search"), "/search");
    assert_eq!(normalize_endpoint("/file"), "/file");
    assert_eq!(normalize_endpoint("/api/v1/users/456"), "/api/v1/users");
}

#[test]
fn detects_vuln_classes() {
    assert_eq!(
        detect_vuln_class("/search", "q=' OR 1=1", ""),
        Some("sqli".to_string())
    );
    assert_eq!(
        detect_vuln_class("/file", "path=../etc/passwd", ""),
        Some("lfi".to_string())
    );
    assert_eq!(
        detect_vuln_class("/template", "", "{{config}}"),
        Some("ssti".to_string())
    );
    assert_eq!(detect_vuln_class("/admin", "", ""), Some("jwt".to_string()));
}

#[test]
fn http_exchange_from_log_entry() {
    let entry = make_log_entry("GET", "/search", "q=test", "", 200, "ok");
    let exchange = HttpExchange::from(&entry);
    assert_eq!(exchange.method, "GET");
    assert_eq!(exchange.path, "/search");
    assert_eq!(exchange.status, 200);
}

#[test]
fn http_exchange_truncates_long_response() {
    let long_body = "x".repeat(500);
    let entry = make_log_entry("GET", "/search", "", "", 200, &long_body);
    let exchange = HttpExchange::from(&entry);
    assert!(exchange.response_snippet.len() < 250);
    assert!(exchange.response_snippet.ends_with("..."));
}
