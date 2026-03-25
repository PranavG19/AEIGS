use super::opsec_validator::*;

fn make_validator() -> OpsecValidator {
    OpsecValidator::new(OpsecValidatorConfig::default())
}

fn clean_dns_input() -> DnsLeakInput {
    DnsLeakInput {
        resolved_dns_servers: vec!["10.8.0.1".to_string()],
        expected_proxy_dns: vec!["10.8.0.1".to_string()],
    }
}

fn leaking_dns_input() -> DnsLeakInput {
    DnsLeakInput {
        resolved_dns_servers: vec!["8.8.8.8".to_string(), "10.8.0.1".to_string()],
        expected_proxy_dns: vec!["10.8.0.1".to_string()],
    }
}

fn clean_webrtc_input() -> WebRtcLeakInput {
    WebRtcLeakInput {
        local_candidates: vec!["10.8.0.2".to_string()],
        public_ip: "203.0.113.50".to_string(),
        proxy_ip: "203.0.113.50".to_string(),
    }
}

fn leaking_webrtc_input() -> WebRtcLeakInput {
    WebRtcLeakInput {
        local_candidates: vec!["192.168.1.100".to_string(), "198.51.100.10".to_string()],
        public_ip: "198.51.100.10".to_string(),
        proxy_ip: "203.0.113.50".to_string(),
    }
}

fn clean_ipv6_input() -> Ipv6LeakInput {
    Ipv6LeakInput {
        ipv6_addresses: vec![],
        ipv6_disabled: true,
    }
}

fn clean_kill_switch() -> KillSwitchInput {
    KillSwitchInput {
        vpn_connected: true,
        firewall_rules_set: true,
        default_route_via_vpn: true,
    }
}

fn clean_clock_input() -> ClockSkewInput {
    ClockSkewInput {
        local_timezone: "UTC".to_string(),
        expected_timezone: "UTC".to_string(),
        ntp_offset_ms: 50,
    }
}

fn clean_mac_input() -> MacAddressInput {
    MacAddressInput {
        current_mac: "AA:BB:CC:DD:EE:FF".to_string(),
        is_randomized: true,
        vendor_oui: None,
    }
}

fn clean_hostname_input() -> HostnameInput {
    HostnameInput {
        hostname: "scan-node-01".to_string(),
        contains_real_name: false,
        contains_org_name: false,
    }
}

fn clean_process_input() -> ProcessListInput {
    ProcessListInput {
        running_processes: vec![
            "systemd".to_string(),
            "sshd".to_string(),
            "bash".to_string(),
        ],
    }
}

#[test]
fn dns_leak_passes_when_all_through_proxy() {
    let v = make_validator();
    let result = v.check_dns_leak(&clean_dns_input());
    assert!(result.passed);
    assert_eq!(result.category, OpsecCheckCategory::DnsLeak);
}

#[test]
fn dns_leak_fails_when_non_proxy_dns() {
    let v = make_validator();
    let result = v.check_dns_leak(&leaking_dns_input());
    assert!(!result.passed);
    assert_eq!(result.severity, OpsecSeverity::Critical);
    assert!(result.detail.contains("8.8.8.8"));
}

#[test]
fn webrtc_leak_passes_when_ip_matches_proxy() {
    let v = make_validator();
    let result = v.check_webrtc_leak(&clean_webrtc_input());
    assert!(result.passed);
}

#[test]
fn webrtc_leak_fails_when_real_ip_exposed() {
    let v = make_validator();
    let result = v.check_webrtc_leak(&leaking_webrtc_input());
    assert!(!result.passed);
    assert_eq!(result.severity, OpsecSeverity::Critical);
}

#[test]
fn ipv6_leak_passes_when_disabled() {
    let v = make_validator();
    let result = v.check_ipv6_leak(&clean_ipv6_input());
    assert!(result.passed);
}

#[test]
fn ipv6_leak_fails_when_addresses_present() {
    let v = make_validator();
    let input = Ipv6LeakInput {
        ipv6_addresses: vec!["2001:db8::1".to_string()],
        ipv6_disabled: false,
    };
    let result = v.check_ipv6_leak(&input);
    assert!(!result.passed);
    assert_eq!(result.severity, OpsecSeverity::Critical);
}

#[test]
fn kill_switch_passes_when_all_good() {
    let v = make_validator();
    let result = v.check_kill_switch(&clean_kill_switch());
    assert!(result.passed);
}

#[test]
fn kill_switch_fails_blocking_when_vpn_down() {
    let v = make_validator();
    let input = KillSwitchInput {
        vpn_connected: false,
        firewall_rules_set: true,
        default_route_via_vpn: false,
    };
    let result = v.check_kill_switch(&input);
    assert!(!result.passed);
    assert_eq!(result.severity, OpsecSeverity::Blocking);
}

#[test]
fn clock_skew_passes_when_matching() {
    let v = make_validator();
    let result = v.check_clock_skew(&clean_clock_input());
    assert!(result.passed);
}

#[test]
fn clock_skew_fails_on_wrong_timezone() {
    let v = make_validator();
    let input = ClockSkewInput {
        local_timezone: "America/New_York".to_string(),
        expected_timezone: "UTC".to_string(),
        ntp_offset_ms: 100,
    };
    let result = v.check_clock_skew(&input);
    assert!(!result.passed);
    assert_eq!(result.severity, OpsecSeverity::Critical);
}

#[test]
fn mac_address_passes_when_randomized() {
    let v = make_validator();
    let result = v.check_mac_address(&clean_mac_input());
    assert!(result.passed);
}

#[test]
fn mac_address_fails_when_not_randomized() {
    let v = make_validator();
    let input = MacAddressInput {
        current_mac: "00:1A:2B:3C:4D:5E".to_string(),
        is_randomized: false,
        vendor_oui: Some("Dell".to_string()),
    };
    let result = v.check_mac_address(&input);
    assert!(!result.passed);
    assert!(result.detail.contains("Dell"));
}

#[test]
fn hostname_passes_when_generic() {
    let v = make_validator();
    let result = v.check_hostname(&clean_hostname_input());
    assert!(result.passed);
}

#[test]
fn hostname_fails_with_real_name() {
    let v = make_validator();
    let input = HostnameInput {
        hostname: "johns-macbook-pro".to_string(),
        contains_real_name: true,
        contains_org_name: false,
    };
    let result = v.check_hostname(&input);
    assert!(!result.passed);
    assert!(result.detail.contains("real name"));
}

#[test]
fn process_list_passes_clean() {
    let v = make_validator();
    let result = v.check_process_list(&clean_process_input());
    assert!(result.passed);
}

#[test]
fn process_list_fails_with_identifying_processes() {
    let v = make_validator();
    let input = ProcessListInput {
        running_processes: vec![
            "systemd".to_string(),
            "slack".to_string(),
            "outlook".to_string(),
            "bash".to_string(),
        ],
    };
    let result = v.check_process_list(&input);
    assert!(!result.passed);
    assert!(result.detail.contains("slack"));
    assert!(result.detail.contains("outlook"));
}

#[test]
fn process_list_detects_custom_processes() {
    let v = OpsecValidator::new(
        OpsecValidatorConfig::default().add_identifying_process("my-corporate-app"),
    );
    let input = ProcessListInput {
        running_processes: vec!["my-corporate-app".to_string()],
    };
    let result = v.check_process_list(&input);
    assert!(!result.passed);
}

#[test]
fn validate_all_passes_clean_system() {
    let mut v = make_validator();
    let result = v.validate_all(
        &clean_dns_input(),
        &clean_webrtc_input(),
        &clean_ipv6_input(),
        &clean_kill_switch(),
        &clean_clock_input(),
        &clean_mac_input(),
        &clean_hostname_input(),
        &clean_process_input(),
    );
    assert!(result.passed);
    assert_eq!(result.score, 100);
    assert!(result.blocking_issues.is_empty());
    assert!(result.score_pct() > 99.0);
}

#[test]
fn validate_all_fails_on_blocking_issue() {
    let mut v = make_validator();
    let bad_kill_switch = KillSwitchInput {
        vpn_connected: false,
        firewall_rules_set: false,
        default_route_via_vpn: false,
    };
    let result = v.validate_all(
        &clean_dns_input(),
        &clean_webrtc_input(),
        &clean_ipv6_input(),
        &bad_kill_switch,
        &clean_clock_input(),
        &clean_mac_input(),
        &clean_hostname_input(),
        &clean_process_input(),
    );
    assert!(!result.passed);
    assert!(!result.blocking_issues.is_empty());
}

#[test]
fn validate_all_fails_below_threshold() {
    let mut v = OpsecValidator::new(OpsecValidatorConfig::default().with_threshold(95));
    let result = v.validate_all(
        &leaking_dns_input(),
        &leaking_webrtc_input(),
        &clean_ipv6_input(),
        &clean_kill_switch(),
        &clean_clock_input(),
        &clean_mac_input(),
        &clean_hostname_input(),
        &clean_process_input(),
    );
    assert!(!result.passed);
    assert!(result.score < 95);
}

#[test]
fn score_pct_calculates_correctly() {
    let result = OpsecValidationResult {
        checks: vec![],
        score: 75,
        max_score: 100,
        passed: true,
        blocking_issues: vec![],
    };
    assert!((result.score_pct() - 75.0).abs() < f64::EPSILON);
}

#[test]
fn failed_checks_filters_correctly() {
    let mut v = make_validator();
    let result = v.validate_all(
        &leaking_dns_input(),
        &clean_webrtc_input(),
        &clean_ipv6_input(),
        &clean_kill_switch(),
        &clean_clock_input(),
        &clean_mac_input(),
        &clean_hostname_input(),
        &clean_process_input(),
    );
    let failed = result.failed_checks();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].category, OpsecCheckCategory::DnsLeak);
}

#[test]
fn last_result_stored_after_validate() {
    let mut v = make_validator();
    assert!(v.last_result().is_none());
    v.validate_all(
        &clean_dns_input(),
        &clean_webrtc_input(),
        &clean_ipv6_input(),
        &clean_kill_switch(),
        &clean_clock_input(),
        &clean_mac_input(),
        &clean_hostname_input(),
        &clean_process_input(),
    );
    assert!(v.last_result().is_some());
}

#[test]
fn opsec_check_category_display() {
    assert_eq!(format!("{}", OpsecCheckCategory::DnsLeak), "DNS Leak");
    assert_eq!(format!("{}", OpsecCheckCategory::WebRtcLeak), "WebRTC Leak");
    assert_eq!(format!("{}", OpsecCheckCategory::KillSwitch), "Kill Switch");
}

#[test]
fn opsec_severity_display() {
    assert_eq!(format!("{}", OpsecSeverity::Info), "INFO");
    assert_eq!(format!("{}", OpsecSeverity::Blocking), "BLOCK");
}

#[test]
fn config_builder_pattern() {
    let config = OpsecValidatorConfig::default()
        .with_threshold(80)
        .with_block_on_critical(false)
        .with_expected_timezone("Europe/London")
        .with_max_clock_offset(5000)
        .add_identifying_process("my-app");
    assert_eq!(config.min_score_threshold, 80);
    assert!(!config.block_on_critical);
    assert_eq!(config.expected_timezone, "Europe/London");
    assert_eq!(config.max_clock_offset_ms, 5000);
    assert_eq!(
        config.custom_identifying_processes,
        vec!["my-app".to_string()]
    );
}

#[test]
fn threshold_returns_configured_value() {
    let v = OpsecValidator::new(OpsecValidatorConfig::default().with_threshold(85));
    assert_eq!(v.threshold(), 85);
}
