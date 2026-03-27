use super::*;
use crate::opsec_gate::OpsecEnvironment;

#[test]
fn default_creates_preflight() {
    let pf = OpsecPreFlight::default();
    assert!(pf.config().check_opsec_environment);
    assert!(pf.config().check_honeypot);
    assert!(pf.config().check_canaries);
}

#[test]
fn clean_environment_passes() {
    let pf = OpsecPreFlight::with_defaults();
    let env = OpsecEnvironment {
        hostname: "scan-node-1".to_string(),
        timezone: "UTC".to_string(),
        processes: vec!["cargo".to_string(), "rustc".to_string()],
        mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
        has_ipv6: false,
        dns_proxy_configured: true,
    };
    let result = pf.check_environment_only(&env);
    assert!(result.should_proceed);
    assert!(result.opsec_passed);
    assert!(result.abort_reason.is_none());
}

#[test]
fn dns_leak_fails_opsec() {
    let pf = OpsecPreFlight::with_defaults();
    let env = OpsecEnvironment {
        hostname: "scan-node-1".to_string(),
        timezone: "UTC".to_string(),
        processes: Vec::new(),
        mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
        has_ipv6: false,
        dns_proxy_configured: false,
    };
    let result = pf.check_environment_only(&env);
    assert!(!result.should_proceed);
    assert!(!result.opsec_passed);
    assert!(result.abort_reason.unwrap().contains("OPSEC gate failed"));
}

#[test]
fn ipv6_enabled_fails_opsec() {
    let pf = OpsecPreFlight::with_defaults();
    let env = OpsecEnvironment {
        hostname: "scan-node-1".to_string(),
        timezone: "UTC".to_string(),
        processes: Vec::new(),
        mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
        has_ipv6: true,
        dns_proxy_configured: true,
    };
    let result = pf.check_environment_only(&env);
    assert!(!result.should_proceed);
}

#[test]
fn non_utc_timezone_fails() {
    let pf = OpsecPreFlight::with_defaults();
    let env = OpsecEnvironment {
        hostname: "scan-node-1".to_string(),
        timezone: "America/New_York".to_string(),
        processes: Vec::new(),
        mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
        has_ipv6: false,
        dns_proxy_configured: true,
    };
    let result = pf.check_environment_only(&env);
    assert!(!result.should_proceed);
}

#[test]
fn check_with_no_probes_skips_honeypot_and_canary() {
    let pf = OpsecPreFlight::with_defaults();
    let env = OpsecEnvironment::default();
    let result = pf.check(&env, &[]);
    assert!(result.honeypot_score.is_none());
    assert!(result.canary_scan.is_none());
}

#[test]
fn check_with_normal_probe_passes() {
    let pf = OpsecPreFlight::with_defaults();
    let env = OpsecEnvironment {
        hostname: "scan-node-1".to_string(),
        timezone: "UTC".to_string(),
        processes: Vec::new(),
        mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
        has_ipv6: false,
        dns_proxy_configured: true,
    };
    let probes = vec![ProbeResponse {
        status_code: 200,
        response_time_ms: 150,
        body: "<html><body>Hello World</body></html>".to_string(),
        headers: HashMap::new(),
        server_header: Some("nginx/1.20".to_string()),
        content_type: Some("text/html".to_string()),
    }];
    let result = pf.check(&env, &probes);
    assert!(result.should_proceed);
    assert!(result.honeypot_score.is_some());
}

#[test]
fn disabled_opsec_check_always_passes_env() {
    let config = OpsecPreFlightConfig::default().with_check_opsec(false);
    let pf = OpsecPreFlight::new(config);
    let env = OpsecEnvironment {
        hostname: "scan-node-1".to_string(),
        timezone: "America/New_York".to_string(),
        processes: Vec::new(),
        mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
        has_ipv6: true,
        dns_proxy_configured: false,
    };
    let result = pf.check(&env, &[]);
    assert!(result.opsec_passed);
}

#[test]
fn config_builder_chain() {
    let config = OpsecPreFlightConfig::default()
        .with_honeypot_threshold(0.9)
        .with_canary_threshold(3)
        .with_check_opsec(false)
        .with_check_honeypot(false)
        .with_check_canaries(false);
    assert_eq!(config.honeypot_abort_threshold, 0.9);
    assert_eq!(config.canary_abort_threshold, 3);
    assert!(!config.check_opsec_environment);
    assert!(!config.check_honeypot);
    assert!(!config.check_canaries);
}
