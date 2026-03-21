use crate::katana_wrapper::KatanaWrapper;
use crate::types::CrawlConfig;

#[test]
fn name_returns_katana() {
    assert_eq!(KatanaWrapper.name(), "katana");
}

#[test]
fn timeout_constant_is_300() {
    assert_eq!(super::katana_wrapper::KATANA_TIMEOUT_SECS, 300);
}

#[test]
fn build_command_basic() {
    let config = CrawlConfig::default();
    let cmd = KatanaWrapper.build_command("http://localhost:3000", &config, false);
    let args: Vec<_> = cmd
        .get_args()
        .map(|a| a.to_string_lossy().to_string())
        .collect();
    assert_eq!(cmd.get_program().to_string_lossy(), "katana");
    assert!(args.contains(&"-u".to_string()));
    assert!(args.contains(&"http://localhost:3000".to_string()));
    assert!(args.contains(&"-j".to_string()));
    assert!(args.contains(&"-silent".to_string()));
    assert!(args.contains(&"-jc".to_string()));
}

#[test]
fn build_command_headless() {
    let config = CrawlConfig::default();
    let cmd = KatanaWrapper.build_command("http://localhost:3000", &config, true);
    let args: Vec<_> = cmd
        .get_args()
        .map(|a| a.to_string_lossy().to_string())
        .collect();
    assert!(args.contains(&"-headless".to_string()));
    assert!(args.contains(&"-system-chrome".to_string()));
}

#[test]
fn build_command_with_scope_regex() {
    let config = CrawlConfig::default().with_scope_regex(r"localhost|127\.0\.0\.1");
    let cmd = KatanaWrapper.build_command("http://localhost:3000", &config, false);
    let args: Vec<_> = cmd
        .get_args()
        .map(|a| a.to_string_lossy().to_string())
        .collect();
    assert!(args.contains(&"-cs".to_string()));
    assert!(args.contains(&r"localhost|127\.0\.0\.1".to_string()));
}

#[test]
fn build_command_respects_max_depth() {
    let config = CrawlConfig::default().with_max_depth(5);
    let cmd = KatanaWrapper.build_command("http://localhost:3000", &config, false);
    let args: Vec<_> = cmd
        .get_args()
        .map(|a| a.to_string_lossy().to_string())
        .collect();
    assert!(args.contains(&"5".to_string()));
}

#[test]
fn parse_output_single_result() {
    let stdout = r#"{"timestamp":"2024-01-01","request":{"method":"GET","endpoint":"https://localhost:3000/api"},"response":{"status_code":200}}"#;
    let result = KatanaWrapper.parse_output(stdout);
    assert_eq!(result.discovered_endpoints.len(), 1);
    assert_eq!(
        result.discovered_endpoints[0].url,
        "https://localhost:3000/api"
    );
    assert_eq!(result.discovered_endpoints[0].method, "GET");
}

#[test]
fn parse_output_multiple_results() {
    let stdout = concat!(
        r#"{"request":{"method":"GET","endpoint":"https://localhost/a"}}"#,
        "\n",
        r#"{"request":{"method":"POST","endpoint":"https://localhost/b"}}"#,
        "\n",
    );
    let result = KatanaWrapper.parse_output(stdout);
    assert_eq!(result.discovered_endpoints.len(), 2);
}

#[test]
fn parse_output_empty_input() {
    let result = KatanaWrapper.parse_output("");
    assert!(result.discovered_endpoints.is_empty());
    assert_eq!(result.pages_visited, 0);
}

#[test]
fn parse_output_malformed_json_skipped() {
    let stdout = "not json\n{bad\n";
    let result = KatanaWrapper.parse_output(stdout);
    assert!(result.discovered_endpoints.is_empty());
}

#[test]
fn parse_output_mixed_valid_invalid() {
    let stdout = concat!(
        "bad\n",
        r#"{"request":{"method":"GET","endpoint":"https://localhost/ok"}}"#,
        "\n",
        "also bad\n",
    );
    let result = KatanaWrapper.parse_output(stdout);
    assert_eq!(result.discovered_endpoints.len(), 1);
}

#[test]
fn parse_output_missing_request_skipped() {
    let stdout = r#"{"timestamp":"2024-01-01"}"#;
    let result = KatanaWrapper.parse_output(stdout);
    assert!(result.discovered_endpoints.is_empty());
}

#[test]
fn parse_output_missing_endpoint_skipped() {
    let stdout = r#"{"request":{"method":"GET"}}"#;
    let result = KatanaWrapper.parse_output(stdout);
    assert!(result.discovered_endpoints.is_empty());
}

#[test]
fn parse_output_empty_endpoint_skipped() {
    let stdout = r#"{"request":{"method":"GET","endpoint":""}}"#;
    let result = KatanaWrapper.parse_output(stdout);
    assert!(result.discovered_endpoints.is_empty());
}

#[test]
fn parse_output_extra_fields_tolerated() {
    let stdout = r#"{"request":{"method":"GET","endpoint":"https://localhost/api"},"response":{"status_code":200,"technologies":["PHP"]},"extra":"field"}"#;
    let result = KatanaWrapper.parse_output(stdout);
    assert_eq!(result.discovered_endpoints.len(), 1);
}

#[test]
fn parse_output_default_method_is_get() {
    let stdout = r#"{"request":{"endpoint":"https://localhost/api"}}"#;
    let result = KatanaWrapper.parse_output(stdout);
    assert_eq!(result.discovered_endpoints.len(), 1);
    assert_eq!(result.discovered_endpoints[0].method, "GET");
}

#[test]
fn parse_output_pages_visited_matches_endpoint_count() {
    let stdout = concat!(
        r#"{"request":{"method":"GET","endpoint":"https://localhost/a"}}"#,
        "\n",
        r#"{"request":{"method":"GET","endpoint":"https://localhost/b"}}"#,
        "\n",
        r#"{"request":{"method":"GET","endpoint":"https://localhost/c"}}"#,
        "\n",
    );
    let result = KatanaWrapper.parse_output(stdout);
    assert_eq!(result.pages_visited, 3);
}
