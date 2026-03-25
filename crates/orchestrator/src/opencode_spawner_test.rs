use super::*;
use std::path::PathBuf;
use std::time::Duration;

#[test]
fn default_config_uses_sane_defaults() {
    let cfg = SpawnerConfig::default();
    assert_eq!(cfg.binary_path, "opencode");
    assert_eq!(cfg.model, "anthropic:claude-sonnet-4-20250514");
    assert_eq!(cfg.timeout, Duration::from_secs(300));
    assert!(cfg.max_tokens.is_none());
    assert_eq!(cfg.output_format, SpawnerOutputFormat::Json);
    assert!(cfg.env_vars.is_empty());
}

#[test]
fn build_args_without_max_tokens() {
    let cfg = SpawnerConfig {
        binary_path: "opencode".to_string(),
        model: "anthropic:claude-sonnet-4-20250514".to_string(),
        timeout: Duration::from_secs(60),
        max_tokens: None,
        workspace_dir: PathBuf::from("/tmp/scan"),
        system_prompt_file: None,
        output_format: SpawnerOutputFormat::Json,
        env_vars: vec![],
    };
    let args = build_args(&cfg, "analyze this target");
    assert_eq!(args[0], "run");
    assert_eq!(args[1], "--dir");
    assert_eq!(args[2], "/tmp/scan");
    assert_eq!(args[3], "--model");
    assert_eq!(args[4], "anthropic:claude-sonnet-4-20250514");
    assert_eq!(args[5], "--format");
    assert_eq!(args[6], "json");
    assert_eq!(args[7], "analyze this target");
    assert_eq!(args.len(), 8);
}

#[test]
fn build_args_with_max_tokens() {
    let cfg = SpawnerConfig {
        max_tokens: Some(4096),
        ..SpawnerConfig::default()
    };
    let args = build_args(&cfg, "test prompt");
    assert!(args.contains(&"--max-tokens".to_string()));
    assert!(args.contains(&"4096".to_string()));
}

#[test]
fn output_format_as_arg() {
    assert_eq!(SpawnerOutputFormat::Json.as_arg(), "json");
    assert_eq!(SpawnerOutputFormat::Text.as_arg(), "text");
}

#[test]
fn write_system_prompt_creates_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_system_prompt(dir.path(), "You are AEGIS-MIND.").unwrap();
    assert!(path.exists());
    let content = std::fs::read_to_string(&path).unwrap();
    assert_eq!(content, "You are AEGIS-MIND.");
}

#[test]
fn write_system_prompt_overwrites_existing() {
    let dir = tempfile::tempdir().unwrap();
    write_system_prompt(dir.path(), "first").unwrap();
    let path = write_system_prompt(dir.path(), "second").unwrap();
    let content = std::fs::read_to_string(&path).unwrap();
    assert_eq!(content, "second");
}

#[test]
fn extract_json_block_from_markdown() {
    let text = "Some text\n```json\n{\"key\": \"value\"}\n```\nMore text";
    let block = extract_json_block(text);
    assert_eq!(block.unwrap(), "{\"key\": \"value\"}");
}

#[test]
fn extract_json_block_missing_fence() {
    let text = "No JSON here, just prose.";
    assert!(extract_json_block(text).is_none());
}

#[test]
fn parse_structured_output_from_raw_json() {
    let output = SpawnerOutput {
        stdout: r#"{"hypotheses": [], "reasoning_summary": "none"}"#.to_string(),
        stderr: String::new(),
        exit_code: Some(0),
        duration_ms: 100,
        truncated: false,
    };
    let val = parse_structured_output(&output).unwrap();
    assert!(val.get("hypotheses").unwrap().is_array());
}

#[test]
fn parse_structured_output_from_fenced_json() {
    let output = SpawnerOutput {
        stdout: "Here is the analysis:\n```json\n{\"key\": 42}\n```\n".to_string(),
        stderr: String::new(),
        exit_code: Some(0),
        duration_ms: 50,
        truncated: false,
    };
    let val = parse_structured_output(&output).unwrap();
    assert_eq!(val.get("key").unwrap().as_i64().unwrap(), 42);
}

#[test]
fn parse_structured_output_fails_on_garbage() {
    let output = SpawnerOutput {
        stdout: "this is not JSON at all".to_string(),
        stderr: String::new(),
        exit_code: Some(0),
        duration_ms: 10,
        truncated: false,
    };
    assert!(parse_structured_output(&output).is_err());
}

#[test]
fn spawn_opencode_returns_binary_not_found_for_missing_binary() {
    let cfg = SpawnerConfig {
        binary_path: "nonexistent-binary-abc123".to_string(),
        timeout: Duration::from_secs(5),
        ..SpawnerConfig::default()
    };
    let result = spawn_opencode(&cfg, "test");
    assert!(result.is_err());
    let err = result.unwrap_err();
    match err {
        SpawnerError::BinaryNotFound(bin) => {
            assert_eq!(bin, "nonexistent-binary-abc123");
        }
        SpawnerError::SpawnFailed(_) => {
            // also acceptable on some platforms
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn is_binary_available_returns_false_for_nonexistent() {
    assert!(!is_binary_available("totally-fake-binary-xyz"));
}

#[test]
fn spawner_output_serde_roundtrip() {
    let output = SpawnerOutput {
        stdout: "hello".to_string(),
        stderr: "warn".to_string(),
        exit_code: Some(0),
        duration_ms: 123,
        truncated: false,
    };
    let json = serde_json::to_string(&output).unwrap();
    let parsed: SpawnerOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.stdout, "hello");
    assert_eq!(parsed.duration_ms, 123);
    assert!(!parsed.truncated);
}

#[test]
fn read_capped_returns_empty_for_none() {
    let (s, truncated) = read_capped::<&[u8]>(None, 1024);
    assert!(s.is_empty());
    assert!(!truncated);
}

#[test]
fn read_capped_truncates_large_input() {
    let data: Vec<u8> = vec![b'A'; 1000];
    let (s, truncated) = read_capped(Some(data.as_slice()), 100);
    assert_eq!(s.len(), 100);
    assert!(truncated);
}

#[test]
fn read_capped_no_truncation_for_small_input() {
    let data = b"small";
    let (s, truncated) = read_capped(Some(data.as_slice()), 1024);
    assert_eq!(s, "small");
    assert!(!truncated);
}

#[test]
fn spawner_error_display() {
    let err = SpawnerError::BinaryNotFound("oc".to_string());
    assert!(err.to_string().contains("oc"));

    let err = SpawnerError::Timeout {
        partial_stdout: "partial".to_string(),
        elapsed_ms: 5000,
    };
    assert!(err.to_string().contains("5000"));

    let err = SpawnerError::ProcessFailed {
        exit_code: 1,
        stderr: "bad".to_string(),
    };
    assert!(err.to_string().contains("1"));
    assert!(err.to_string().contains("bad"));
}

#[test]
fn spawn_with_echo_captures_stdout() {
    let cfg = SpawnerConfig {
        binary_path: "echo".to_string(),
        model: "test".to_string(),
        timeout: Duration::from_secs(5),
        max_tokens: None,
        workspace_dir: PathBuf::from("."),
        system_prompt_file: None,
        output_format: SpawnerOutputFormat::Text,
        env_vars: vec![],
    };
    let result = spawn_opencode(&cfg, "hello-world");
    match result {
        Ok(output) => {
            assert!(output.stdout.contains("hello-world"));
            assert_eq!(output.exit_code, Some(0));
            assert!(!output.truncated);
        }
        Err(SpawnerError::ProcessFailed { .. }) => {
            // echo with extra args might produce non-zero on some systems
        }
        Err(e) => panic!("unexpected error: {e}"),
    }
}
