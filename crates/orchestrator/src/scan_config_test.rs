use super::*;
use aegis_evasion_engine::PersonaId;
use clap::Parser;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

#[test]
fn validate_localhost_accepts_localhost_bare() {
    assert!(validate_localhost("localhost").is_ok());
}

#[test]
fn validate_localhost_accepts_localhost_with_scheme() {
    assert!(validate_localhost("http://localhost").is_ok());
}

#[test]
fn validate_localhost_accepts_localhost_with_port() {
    assert!(validate_localhost("http://localhost:8080").is_ok());
}

#[test]
fn validate_localhost_accepts_localhost_with_path() {
    assert!(validate_localhost("http://localhost:3000/api/v1").is_ok());
}

#[test]
fn validate_localhost_accepts_ipv4_loopback() {
    assert!(validate_localhost("http://127.0.0.1").is_ok());
}

#[test]
fn validate_localhost_accepts_ipv4_loopback_with_port() {
    assert!(validate_localhost("http://127.0.0.1:9090").is_ok());
}

#[test]
fn validate_localhost_accepts_ipv4_loopback_bare() {
    assert!(validate_localhost("127.0.0.1").is_ok());
}

#[test]
fn validate_localhost_accepts_ipv6_loopback() {
    assert!(validate_localhost("http://[::1]").is_ok());
}

#[test]
fn validate_localhost_accepts_ipv6_loopback_with_port() {
    assert!(validate_localhost("http://[::1]:8080").is_ok());
}

#[test]
fn validate_localhost_accepts_ipv6_loopback_bare() {
    assert!(validate_localhost("[::1]").is_ok());
}

#[test]
fn validate_localhost_accepts_https_scheme() {
    assert!(validate_localhost("https://localhost:443").is_ok());
}

#[test]
fn validate_localhost_rejects_remote_host() {
    let result = validate_localhost("http://example.com");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, ConfigError::NonLocalhost(host) if host == "example.com"));
}

#[test]
fn validate_localhost_rejects_remote_ip() {
    let result = validate_localhost("http://192.168.1.1:8080");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ConfigError::NonLocalhost(_)));
}

#[test]
fn validate_localhost_rejects_empty_string() {
    let result = validate_localhost("");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ConfigError::InvalidTarget(_)));
}

#[test]
fn validate_localhost_rejects_scheme_only() {
    let result = validate_localhost("http://");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ConfigError::InvalidTarget(_)));
}

#[test]
fn validate_localhost_rejects_remote_bare_host() {
    let result = validate_localhost("evil.com");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ConfigError::NonLocalhost(_)));
}

#[test]
fn validate_localhost_rejects_remote_bare_with_port() {
    let result = validate_localhost("evil.com:8080");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ConfigError::NonLocalhost(_)));
}

#[test]
fn parse_stealth_level_default() {
    assert_eq!(
        parse_stealth_level("default").unwrap(),
        StealthLevel::Default
    );
}

#[test]
fn parse_stealth_level_aggressive() {
    assert_eq!(
        parse_stealth_level("aggressive").unwrap(),
        StealthLevel::Aggressive
    );
}

#[test]
fn parse_stealth_level_paranoid() {
    assert_eq!(
        parse_stealth_level("paranoid").unwrap(),
        StealthLevel::Paranoid
    );
}

#[test]
fn parse_stealth_level_invalid_returns_error() {
    let result = parse_stealth_level("quiet");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ConfigError::InvalidStealthLevel(s) if s == "quiet"));
}

#[test]
fn parse_stealth_level_rejects_uppercase() {
    assert!(parse_stealth_level("Default").is_err());
}

#[test]
fn resolve_persona_chrome() {
    assert_eq!(
        resolve_persona_id("chrome").unwrap(),
        PersonaId::ChromeDesktop
    );
}

#[test]
fn resolve_persona_firefox() {
    assert_eq!(
        resolve_persona_id("firefox").unwrap(),
        PersonaId::FirefoxDesktop
    );
}

#[test]
fn resolve_persona_safari() {
    assert_eq!(
        resolve_persona_id("safari").unwrap(),
        PersonaId::SafariDesktop
    );
}

#[test]
fn resolve_persona_mobile() {
    assert_eq!(
        resolve_persona_id("mobile").unwrap(),
        PersonaId::ChromeMobile
    );
}

#[test]
fn resolve_persona_googlebot() {
    assert_eq!(
        resolve_persona_id("googlebot").unwrap(),
        PersonaId::Googlebot
    );
}

#[test]
fn resolve_persona_invalid_returns_error() {
    let result = resolve_persona_id("opera");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ConfigError::InvalidPersona(s) if s == "opera"));
}

#[test]
fn config_error_display_invalid_target() {
    let err = ConfigError::InvalidTarget("bad url".to_string());
    assert_eq!(err.to_string(), "invalid target: bad url");
}

#[test]
fn config_error_display_non_localhost() {
    let err = ConfigError::NonLocalhost("example.com".to_string());
    assert_eq!(
        err.to_string(),
        "target must be localhost, got: example.com"
    );
}

#[test]
fn config_error_display_invalid_stealth_level() {
    let err = ConfigError::InvalidStealthLevel("turbo".to_string());
    assert_eq!(err.to_string(), "unknown stealth level: turbo");
}

#[test]
fn config_error_display_invalid_persona() {
    let err = ConfigError::InvalidPersona("ie6".to_string());
    assert_eq!(err.to_string(), "unknown persona: ie6");
}

#[test]
fn config_error_implements_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(ConfigError::InvalidTarget("test".to_string()));
    assert!(!err.to_string().is_empty());
}

#[test]
fn stealth_level_debug_format() {
    assert_eq!(format!("{:?}", StealthLevel::Default), "Default");
    assert_eq!(format!("{:?}", StealthLevel::Aggressive), "Aggressive");
    assert_eq!(format!("{:?}", StealthLevel::Paranoid), "Paranoid");
}

#[test]
fn stealth_level_clone() {
    let original = StealthLevel::Aggressive;
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn stealth_level_partial_eq_same_variant() {
    assert_eq!(StealthLevel::Default, StealthLevel::Default);
}

#[test]
fn stealth_level_partial_eq_different_variants() {
    assert_ne!(StealthLevel::Default, StealthLevel::Aggressive);
    assert_ne!(StealthLevel::Aggressive, StealthLevel::Paranoid);
    assert_ne!(StealthLevel::Default, StealthLevel::Paranoid);
}

#[test]
fn validate_localhost_with_path_no_port() {
    assert!(validate_localhost("http://localhost/health").is_ok());
}

#[test]
fn validate_localhost_ipv4_with_path() {
    assert!(validate_localhost("127.0.0.1/api").is_ok());
}

#[test]
fn validate_localhost_ipv6_with_path() {
    assert!(validate_localhost("http://[::1]/api/v2").is_ok());
}

#[test]
fn scan_config_default_no_llm_is_false() {
    let config =
        ScanConfig::try_parse_from(["aegis", "--target", "http://localhost:8080"]).unwrap();
    assert!(!config.llm.no_llm);
}

#[test]
fn scan_config_no_llm_flag_sets_true() {
    let config =
        ScanConfig::try_parse_from(["aegis", "--target", "http://localhost:8080", "--no-llm"])
            .unwrap();
    assert!(config.llm.no_llm);
}

#[test]
fn scan_config_default_context_file_is_none() {
    let config =
        ScanConfig::try_parse_from(["aegis", "--target", "http://localhost:8080"]).unwrap();
    assert!(config.scope.context_file.is_none());
}

#[test]
fn business_context_default_has_empty_vecs() {
    let ctx = BusinessContext::default();
    assert!(ctx.excluded_endpoints.is_empty());
    assert!(ctx.critical_assets.is_empty());
    assert!(ctx.pii_endpoints.is_empty());
    assert!(ctx.known_issues.is_empty());
}

#[test]
fn load_business_context_valid_json() {
    use aegis_protocol::finding::VulnerabilityClass;
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(
        tmp,
        r#"{{
            "excluded_endpoints": ["/health"],
            "critical_assets": ["/api/payments"],
            "pii_endpoints": ["/api/users"],
            "known_issues": [
                {{"endpoint": "/api/users", "vulnerability_class": "SqlInjection"}}
            ]
        }}"#
    )
    .unwrap();
    let ctx = load_business_context(tmp.path()).unwrap();
    assert_eq!(ctx.excluded_endpoints, vec!["/health"]);
    assert_eq!(ctx.critical_assets, vec!["/api/payments"]);
    assert_eq!(ctx.pii_endpoints, vec!["/api/users"]);
    assert_eq!(ctx.known_issues.len(), 1);
    assert_eq!(ctx.known_issues[0].endpoint, "/api/users");
    assert_eq!(
        ctx.known_issues[0].vulnerability_class,
        VulnerabilityClass::SqlInjection
    );
}

#[test]
fn load_business_context_missing_file_returns_error() {
    let result = load_business_context(Path::new("/nonexistent/context.json"));
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ConfigError::ContextFileRead(_)
    ));
}

#[test]
fn phase_timings_default_is_empty() {
    let timings = PhaseTimings::default();
    assert!(timings.timings.is_empty());
}

#[test]
fn phase_timings_record_and_retrieve() {
    let mut timings = PhaseTimings::default();
    timings.record("recon", Duration::from_millis(500));
    timings.record("fuzz", Duration::from_secs(3));
    assert_eq!(timings.timings.len(), 2);
    assert_eq!(timings.timings["recon"], Duration::from_millis(500));
    assert_eq!(timings.timings["fuzz"], Duration::from_secs(3));
}

#[test]
fn llm_metrics_default_is_zero() {
    let metrics = LlmMetrics::default();
    assert_eq!(metrics.call_count, 0);
    assert_eq!(metrics.total_latency, Duration::ZERO);
    assert_eq!(metrics.tokens_used, 0);
}

#[test]
fn llm_metrics_accumulates_across_calls() {
    let mut metrics = LlmMetrics::default();
    metrics.record_call(Duration::from_millis(100), 500);
    metrics.record_call(Duration::from_millis(200), 300);
    assert_eq!(metrics.call_count, 2);
    assert_eq!(metrics.total_latency, Duration::from_millis(300));
    assert_eq!(metrics.tokens_used, 800);
}

#[test]
fn scan_metrics_default() {
    let metrics = ScanMetrics::default();
    assert!(metrics.phase_timings.timings.is_empty());
    assert_eq!(metrics.llm_metrics.call_count, 0);
}

#[test]
fn scan_config_default_max_iterations_is_one() {
    let config =
        ScanConfig::try_parse_from(["aegis", "--target", "http://localhost:8080"]).unwrap();
    assert_eq!(config.pipeline.max_iterations, 1);
}

#[test]
fn scan_config_default_convergence_threshold_is_two() {
    let config =
        ScanConfig::try_parse_from(["aegis", "--target", "http://localhost:8080"]).unwrap();
    assert_eq!(config.pipeline.convergence_threshold, 2);
}

#[test]
fn scan_config_max_iterations_overridable() {
    let config = ScanConfig::try_parse_from([
        "aegis",
        "--target",
        "http://localhost:8080",
        "--max-iterations",
        "5",
    ])
    .unwrap();
    assert_eq!(config.pipeline.max_iterations, 5);
}

#[test]
fn scan_config_convergence_threshold_overridable() {
    let config = ScanConfig::try_parse_from([
        "aegis",
        "--target",
        "http://localhost:8080",
        "--convergence-threshold",
        "3",
    ])
    .unwrap();
    assert_eq!(config.pipeline.convergence_threshold, 3);
}

#[test]
fn scan_config_default_no_audit_is_false() {
    let config =
        ScanConfig::try_parse_from(["aegis", "--target", "http://localhost:8080"]).unwrap();
    assert!(!config.audit.no_audit);
}

#[test]
fn scan_config_no_audit_flag_sets_true() {
    let config =
        ScanConfig::try_parse_from(["aegis", "--target", "http://localhost:8080", "--no-audit"])
            .unwrap();
    assert!(config.audit.no_audit);
}

#[test]
fn scan_config_default_include_endpoints_is_none() {
    let config =
        ScanConfig::try_parse_from(["aegis", "--target", "http://localhost:8080"]).unwrap();
    assert!(config.scope.include_endpoints.is_none());
}

#[test]
fn scan_config_default_exclude_endpoints_is_none() {
    let config =
        ScanConfig::try_parse_from(["aegis", "--target", "http://localhost:8080"]).unwrap();
    assert!(config.scope.exclude_endpoints.is_none());
}

#[test]
fn scan_config_include_endpoints_flag_parses() {
    let config = ScanConfig::try_parse_from([
        "aegis",
        "--target",
        "http://localhost:8080",
        "--include-endpoints",
        "/api/v1/users",
    ])
    .unwrap();
    assert_eq!(
        config.scope.include_endpoints.unwrap(),
        vec!["/api/v1/users".to_string()]
    );
}

#[test]
fn scan_config_exclude_endpoints_flag_parses() {
    let config = ScanConfig::try_parse_from([
        "aegis",
        "--target",
        "http://localhost:8080",
        "--exclude-endpoints",
        "/health",
    ])
    .unwrap();
    assert_eq!(
        config.scope.exclude_endpoints.unwrap(),
        vec!["/health".to_string()]
    );
}

#[test]
fn config_error_display_context_file_read() {
    let err = ConfigError::ContextFileRead("permission denied".to_string());
    assert_eq!(
        err.to_string(),
        "cannot read context file: permission denied"
    );
}

#[test]
fn config_error_display_context_file_parse() {
    let err = ConfigError::ContextFileParse("unexpected token at line 3".to_string());
    assert_eq!(
        err.to_string(),
        "cannot parse context file: unexpected token at line 3"
    );
}

#[test]
fn load_business_context_invalid_json_returns_parse_error() {
    use std::io::Write;
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{{ not valid json !!").unwrap();
    let result = load_business_context(tmp.path());
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ConfigError::ContextFileParse(_)
    ));
}

#[test]
fn scan_config_default_graph_db_is_none() {
    let config =
        ScanConfig::try_parse_from(["aegis", "--target", "http://localhost:8080"]).unwrap();
    assert!(config.scope.graph_db.is_none());
}

#[test]
fn scan_config_graph_db_flag_parses() {
    let config = ScanConfig::try_parse_from([
        "aegis",
        "--target",
        "http://localhost:8080",
        "--graph-db",
        "/tmp/test.json",
    ])
    .unwrap();
    assert_eq!(
        config.scope.graph_db.unwrap(),
        std::path::PathBuf::from("/tmp/test.json")
    );
}

#[test]
fn scope_options_with_graph_db_some() {
    let scope = ScopeOptions {
        include_endpoints: None,
        exclude_endpoints: None,
        context_file: None,
        graph_db: Some(std::path::PathBuf::from("/tmp/test.json")),
        history_db: None,
        export_graph: None,
    };
    assert_eq!(
        scope.graph_db.unwrap(),
        std::path::PathBuf::from("/tmp/test.json")
    );
}

#[test]
fn scan_config_default_accept_self_signed_is_false() {
    let config =
        ScanConfig::try_parse_from(["aegis", "--target", "http://localhost:8080"]).unwrap();
    assert!(!config.stealth.accept_self_signed);
}

#[test]
fn scan_config_accept_self_signed_flag_sets_true() {
    let config = ScanConfig::try_parse_from([
        "aegis",
        "--target",
        "http://localhost:8080",
        "--accept-self-signed",
    ])
    .unwrap();
    assert!(config.stealth.accept_self_signed);
}
