use super::cli_builder::*;

fn args(strs: &[&str]) -> Vec<String> {
    strs.iter().map(|s| s.to_string()).collect()
}

#[test]
fn parse_minimal_args() {
    let result = parse_scan_args(&args(&["http://localhost:3000"]));
    assert!(result.is_ok());
    let parsed = result.unwrap();
    assert_eq!(parsed.target_url, "http://localhost:3000");
    assert_eq!(parsed.profile, ScanProfile::Standard);
    assert_eq!(parsed.output_format, OutputFormat::Sarif);
    assert!(!parsed.no_llm);
    assert!(!parsed.verbose);
}

#[test]
fn parse_full_args() {
    let result = parse_scan_args(&args(&[
        "https://example.com",
        "--profile",
        "deep",
        "--output",
        "json",
        "--scope",
        "*.example.com",
        "--auth",
        "bearer:token123",
        "--proxy",
        "socks5://127.0.0.1:9050",
        "--no-llm",
        "-v",
    ]));
    assert!(result.is_ok());
    let parsed = result.unwrap();
    assert_eq!(parsed.target_url, "https://example.com");
    assert_eq!(parsed.profile, ScanProfile::Deep);
    assert_eq!(parsed.output_format, OutputFormat::Json);
    assert_eq!(parsed.scope_patterns, vec!["*.example.com"]);
    assert_eq!(parsed.auth_credentials.as_deref(), Some("bearer:token123"));
    assert_eq!(
        parsed.proxy_chain.as_deref(),
        Some("socks5://127.0.0.1:9050")
    );
    assert!(parsed.no_llm);
    assert!(parsed.verbose);
}

#[test]
fn missing_target_is_error() {
    let result = parse_scan_args(&[]);
    assert!(matches!(result, Err(CliError::MissingTarget)));
}

#[test]
fn flag_as_first_arg_is_error() {
    let result = parse_scan_args(&args(&["--profile", "quick"]));
    assert!(matches!(result, Err(CliError::MissingTarget)));
}

#[test]
fn invalid_profile_is_error() {
    let result = parse_scan_args(&args(&["http://localhost", "--profile", "turbo"]));
    assert!(matches!(result, Err(CliError::InvalidProfile(_))));
}

#[test]
fn invalid_output_format_is_error() {
    let result = parse_scan_args(&args(&["http://localhost", "--output", "xml"]));
    assert!(matches!(result, Err(CliError::InvalidOutputFormat(_))));
}

#[test]
fn scan_profiles_properties() {
    assert_eq!(ScanProfile::Quick.max_iterations(), 1);
    assert!(!ScanProfile::Quick.use_llm());
    assert!(ScanProfile::Standard.use_llm());
    assert_eq!(ScanProfile::Deep.max_iterations(), 5);
    assert!(ScanProfile::Stealth.use_llm());
}

#[test]
fn output_format_extension() {
    assert_eq!(OutputFormat::Json.extension(), "json");
    assert_eq!(OutputFormat::Html.extension(), "html");
    assert_eq!(OutputFormat::Sarif.extension(), "sarif");
}

#[test]
fn validate_requires_http_scheme() {
    let args = CliScanArgs {
        target_url: "ftp://example.com".into(),
        profile: ScanProfile::Standard,
        output_format: OutputFormat::Sarif,
        output_path: None,
        scope_patterns: vec![],
        auth_credentials: None,
        proxy_chain: None,
        no_llm: false,
        verbose: false,
        extra_args: Default::default(),
    };
    assert!(validate_scan_args(&args).is_err());
}

#[test]
fn validate_accepts_https() {
    let args = CliScanArgs {
        target_url: "https://localhost:8080".into(),
        profile: ScanProfile::Quick,
        output_format: OutputFormat::Json,
        output_path: None,
        scope_patterns: vec![],
        auth_credentials: None,
        proxy_chain: None,
        no_llm: false,
        verbose: false,
        extra_args: Default::default(),
    };
    assert!(validate_scan_args(&args).is_ok());
}

#[test]
fn format_summary_includes_key_info() {
    let args = CliScanArgs {
        target_url: "http://localhost:3000".into(),
        profile: ScanProfile::Deep,
        output_format: OutputFormat::Json,
        output_path: None,
        scope_patterns: vec!["*.local".into()],
        auth_credentials: Some("token".into()),
        proxy_chain: None,
        no_llm: true,
        verbose: false,
        extra_args: Default::default(),
    };
    let summary = format_scan_summary(&args);
    assert!(summary.contains("localhost:3000"));
    assert!(summary.contains("deep"));
    assert!(summary.contains("json"));
    assert!(summary.contains("*.local"));
    assert!(summary.contains("Auth: configured"));
    assert!(summary.contains("LLM: disabled"));
}

#[test]
fn short_flags_work() {
    let result = parse_scan_args(&args(&[
        "http://localhost",
        "-p",
        "quick",
        "-o",
        "html",
        "-s",
        "*.test",
        "-a",
        "basic:admin:pass",
    ]));
    assert!(result.is_ok());
    let parsed = result.unwrap();
    assert_eq!(parsed.profile, ScanProfile::Quick);
    assert_eq!(parsed.output_format, OutputFormat::Html);
}

#[test]
fn extra_args_captured() {
    let result = parse_scan_args(&args(&[
        "http://localhost",
        "--custom-flag",
        "custom-value",
    ]));
    assert!(result.is_ok());
    let parsed = result.unwrap();
    assert_eq!(
        parsed.extra_args.get("custom-flag").map(|s| s.as_str()),
        Some("custom-value")
    );
}

#[test]
fn profile_display() {
    assert_eq!(format!("{}", ScanProfile::Quick), "quick");
    assert_eq!(format!("{}", ScanProfile::Stealth), "stealth");
}

#[test]
fn output_format_display() {
    assert_eq!(format!("{}", OutputFormat::Json), "json");
    assert_eq!(format!("{}", OutputFormat::Sarif), "sarif");
}
