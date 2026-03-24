use super::*;
use std::path::PathBuf;

fn default_config() -> OpenCodeConfig {
    OpenCodeConfig {
        binary: "opencode".to_string(),
        workspace_dir: PathBuf::from("/tmp/aegis-test"),
        model: "anthropic:claude-sonnet-4-20250514".to_string(),
        timeout: Duration::from_secs(60),
        prompt_file: None,
        format: OutputFormat::Json,
    }
}

#[test]
fn build_prompt_with_mission_and_briefing() {
    let prompt = build_prompt(
        Some("You are AEGIS-MIND."),
        "# TARGET\n- url: http://127.0.0.1",
    );
    assert!(prompt.starts_with("You are AEGIS-MIND."));
    assert!(prompt.contains("---"));
    assert!(prompt.contains("# TARGET"));
}

#[test]
fn build_prompt_briefing_only() {
    let prompt = build_prompt(None, "# TARGET\n- url: http://127.0.0.1");
    assert!(prompt.starts_with("# TARGET"));
    assert!(!prompt.contains("---"));
}

#[test]
fn build_command_args_structure() {
    let config = default_config();
    let args = build_command_args(&config, "test prompt");

    assert_eq!(args[0], "run");
    assert_eq!(args[1], "--dir");
    assert_eq!(args[2], "/tmp/aegis-test");
    assert_eq!(args[3], "--model");
    assert_eq!(args[4], "anthropic:claude-sonnet-4-20250514");
    assert_eq!(args[5], "--format");
    assert_eq!(args[6], "json");
    assert_eq!(args[7], "test prompt");
}

#[test]
fn output_format_flags() {
    assert_eq!(OutputFormat::Json.as_flag(), "json");
    assert_eq!(OutputFormat::Text.as_flag(), "text");
}

#[test]
fn parse_valid_json_response() {
    let raw = r#"{
        "hypotheses": [
            {
                "endpoint": "/api/search",
                "vulnerability_class": "SQL Injection",
                "reasoning": "The search param is reflected in SQL query",
                "suggested_payloads": ["' OR 1=1--", "1 UNION SELECT NULL"],
                "confidence": 0.85,
                "priority": 1
            }
        ],
        "actions": [
            {
                "action_type": "fuzz",
                "target": "/api/search",
                "parameters": {"param": "q"},
                "rationale": "Test SQL injection on search parameter"
            }
        ],
        "reasoning_summary": "Target runs Express with EJS. Search endpoint reflects user input.",
        "raw_output": "",
        "tokens_used": 1500,
        "duration_ms": 0
    }"#;

    let resp = parse_agent_response(raw, 4200).unwrap();

    assert_eq!(resp.hypotheses.len(), 1);
    assert_eq!(resp.hypotheses[0].endpoint, "/api/search");
    assert_eq!(resp.hypotheses[0].vulnerability_class, "SQL Injection");
    assert_eq!(resp.hypotheses[0].suggested_payloads.len(), 2);
    assert!((resp.hypotheses[0].confidence - 0.85).abs() < f64::EPSILON);
    assert_eq!(resp.hypotheses[0].priority, 1);

    assert_eq!(resp.actions.len(), 1);
    assert_eq!(resp.actions[0].action_type, "fuzz");

    assert!(resp.reasoning_summary.contains("Express with EJS"));
    assert_eq!(resp.tokens_used, Some(1500));
    assert_eq!(resp.duration_ms, 4200);
    assert!(!resp.raw_output.is_empty());
}

#[test]
fn parse_json_in_code_fence() {
    let raw = r#"Here is my analysis:

```json
{
    "hypotheses": [
        {
            "endpoint": "/admin",
            "vulnerability_class": "Broken Authentication",
            "reasoning": "No rate limit on login",
            "suggested_payloads": ["admin:password123"],
            "confidence": 0.6,
            "priority": 2
        }
    ],
    "actions": [],
    "reasoning_summary": "Login endpoint lacks brute-force protection",
    "raw_output": "",
    "tokens_used": 800,
    "duration_ms": 0
}
```

That covers my findings."#;

    let resp = parse_agent_response(raw, 3000).unwrap();
    assert_eq!(resp.hypotheses.len(), 1);
    assert_eq!(resp.hypotheses[0].endpoint, "/admin");
    assert_eq!(resp.duration_ms, 3000);
}

#[test]
fn parse_partial_json_extracts_hypotheses() {
    let raw = r#"```json
{
    "hypotheses": [
        {
            "endpoint": "/api/data",
            "vulnerability_class": "SSRF",
            "reasoning": "URL parameter passed to fetch",
            "suggested_payloads": ["http://169.254.169.254/latest/meta-data/"],
            "confidence": 0.7,
            "priority": 1
        }
    ],
    "reasoning": "Found potential SSRF via URL param"
}
```"#;

    let resp = parse_agent_response(raw, 2000).unwrap();
    assert_eq!(resp.hypotheses.len(), 1);
    assert_eq!(resp.hypotheses[0].vulnerability_class, "SSRF");
    assert!(resp.reasoning_summary.contains("SSRF"));
}

#[test]
fn parse_plain_text_fallback() {
    let raw = "I analyzed the target and found no obvious vulnerabilities.\nThe WAF blocks most injection attempts.";

    let resp = parse_agent_response(raw, 1500).unwrap();
    assert!(resp.hypotheses.is_empty());
    assert!(resp.actions.is_empty());
    assert!(resp.reasoning_summary.contains("WAF blocks"));
    assert_eq!(resp.duration_ms, 1500);
}

#[test]
fn parse_empty_response() {
    let resp = parse_agent_response("", 100).unwrap();
    assert!(resp.hypotheses.is_empty());
    assert!(resp.actions.is_empty());
    assert_eq!(resp.reasoning_summary, "");
}

#[test]
fn parse_multiple_hypotheses_sorted_by_priority() {
    let raw = r#"{
        "hypotheses": [
            {
                "endpoint": "/api/users",
                "vulnerability_class": "IDOR",
                "reasoning": "Sequential user IDs",
                "suggested_payloads": ["id=2", "id=999"],
                "confidence": 0.9,
                "priority": 1
            },
            {
                "endpoint": "/api/export",
                "vulnerability_class": "Path Traversal",
                "reasoning": "File parameter in export endpoint",
                "suggested_payloads": ["../../etc/passwd"],
                "confidence": 0.75,
                "priority": 2
            },
            {
                "endpoint": "/api/search",
                "vulnerability_class": "XSS",
                "reasoning": "Reflected input in response",
                "suggested_payloads": ["<img src=x onerror=alert(1)>"],
                "confidence": 0.5,
                "priority": 3
            }
        ],
        "actions": [],
        "reasoning_summary": "Three attack vectors identified",
        "raw_output": "",
        "tokens_used": 2000,
        "duration_ms": 0
    }"#;

    let resp = parse_agent_response(raw, 5000).unwrap();
    assert_eq!(resp.hypotheses.len(), 3);
    assert_eq!(resp.hypotheses[0].priority, 1);
    assert_eq!(resp.hypotheses[1].priority, 2);
    assert_eq!(resp.hypotheses[2].priority, 3);
}

#[test]
fn parse_multiple_actions() {
    let raw = r#"{
        "hypotheses": [],
        "actions": [
            {
                "action_type": "crawl",
                "target": "/api",
                "parameters": {"depth": 3},
                "rationale": "Discover more endpoints"
            },
            {
                "action_type": "fingerprint",
                "target": "/",
                "parameters": {"check_waf": true},
                "rationale": "Identify WAF vendor"
            }
        ],
        "reasoning_summary": "Need more recon before attacking",
        "raw_output": "",
        "tokens_used": null,
        "duration_ms": 0
    }"#;

    let resp = parse_agent_response(raw, 1000).unwrap();
    assert_eq!(resp.actions.len(), 2);
    assert_eq!(resp.actions[0].action_type, "crawl");
    assert_eq!(resp.actions[1].action_type, "fingerprint");
    assert!(resp.tokens_used.is_none());
}

#[test]
fn extract_json_block_from_markdown() {
    let text = "Some text\n```json\n{\"key\": \"value\"}\n```\nMore text";
    let block = extract_json_block(text).unwrap();
    assert_eq!(block, "{\"key\": \"value\"}");
}

#[test]
fn extract_json_block_missing() {
    assert!(extract_json_block("no json here").is_none());
    assert!(extract_json_block("```python\nprint('hi')\n```").is_none());
}

#[test]
fn bridge_error_display() {
    let e = BridgeError::BinaryNotFound("oc".to_string());
    assert_eq!(format!("{e}"), "opencode binary not found: oc");

    let e = BridgeError::Timeout;
    assert_eq!(format!("{e}"), "opencode timed out");

    let e = BridgeError::ProcessFailed {
        exit_code: 1,
        stderr: "oops".to_string(),
    };
    assert!(format!("{e}").contains("oops"));

    let e = BridgeError::ParseFailed("bad json".to_string());
    assert!(format!("{e}").contains("bad json"));
}

#[test]
fn default_config_values() {
    let config = OpenCodeConfig::default();
    assert_eq!(config.binary, "opencode");
    assert_eq!(config.timeout, Duration::from_secs(300));
    assert_eq!(config.format, OutputFormat::Json);
}

#[test]
fn invoke_brain_builds_combined_prompt() {
    let prompt = build_prompt(
        Some("# AEGIS-MIND\nYou are an offensive security researcher."),
        "# TARGET\n- url: http://127.0.0.1:3000\n## FINDINGS\nNone yet.",
    );

    assert!(prompt.contains("AEGIS-MIND"));
    assert!(prompt.contains("offensive security"));
    assert!(prompt.contains("---"));
    assert!(prompt.contains("TARGET"));
    assert!(prompt.contains("127.0.0.1:3000"));
}

#[test]
fn parse_response_with_tokens_used_null() {
    let raw = r#"{
        "hypotheses": [],
        "actions": [],
        "reasoning_summary": "nothing found",
        "raw_output": "",
        "tokens_used": null,
        "duration_ms": 0
    }"#;

    let resp = parse_agent_response(raw, 500).unwrap();
    assert!(resp.tokens_used.is_none());
}

#[test]
fn partial_json_with_alternative_summary_key() {
    let raw = r#"```json
{
    "hypotheses": [],
    "summary": "Used alternative key name for reasoning"
}
```"#;

    let resp = parse_agent_response(raw, 100).unwrap();
    assert!(resp.reasoning_summary.contains("alternative key"));
}
