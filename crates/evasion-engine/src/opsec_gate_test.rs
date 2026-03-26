use super::opsec_gate::*;

fn clean_environment() -> OpsecEnvironment {
    OpsecEnvironment {
        hostname: "scan-node-01".to_string(),
        timezone: "UTC".to_string(),
        processes: vec!["nginx".to_string(), "sshd".to_string(), "bash".to_string()],
        mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
        has_ipv6: false,
        dns_proxy_configured: true,
    }
}

#[test]
fn test_clean_environment_passes() {
    let gate = OpsecGate::new();
    let env = clean_environment();
    let result = gate.check(&env);
    assert!(
        result.is_ok(),
        "Clean environment should pass: {:?}",
        result.err()
    );
    let report = result.unwrap();
    assert!(report.passed);
    assert!(report.violations.is_empty());
    assert!(!report.checks_run.is_empty());
    assert!(report.timestamp_ms > 0);
}

#[test]
fn test_hostname_violation() {
    let gate = OpsecGate::new();

    let v = gate.check_hostname("johns-macbook-pro");
    assert!(v.is_some());
    let violation = v.unwrap();
    assert_eq!(violation.check, OpsecCheck::HostnameCheck);
    assert_eq!(violation.severity, OpsecGateSeverity::Warning);
    assert!(violation.description.contains("macbook"));

    let v2 = gate.check_hostname("dell-workstation-42");
    assert!(v2.is_some());
    assert!(v2.unwrap().description.contains("dell-"));

    let v3 = gate.check_hostname("scan-node-01");
    assert!(v3.is_none());

    let v4 = gate.check_hostname("localhost");
    assert!(v4.is_none());
}

#[test]
fn test_timezone_violation() {
    let gate = OpsecGate::new();

    assert!(gate.check_timezone("UTC").is_none());
    assert!(gate.check_timezone("GMT").is_none());

    let v = gate.check_timezone("America/New_York");
    assert!(v.is_some());
    let violation = v.unwrap();
    assert_eq!(violation.check, OpsecCheck::ClockCheck);
    assert_eq!(violation.severity, OpsecGateSeverity::Critical);
    assert!(violation.description.contains("America/New_York"));

    let v2 = gate.check_timezone("Europe/London");
    assert!(v2.is_some());

    let v3 = gate.check_timezone("Asia/Tokyo");
    assert!(v3.is_some());
}

#[test]
fn test_process_scan_detects_wireshark() {
    let gate = OpsecGate::new();

    let violations = gate.check_processes(&[
        "nginx".to_string(),
        "wireshark".to_string(),
        "bash".to_string(),
    ]);

    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].check, OpsecCheck::ProcessListScan);
    assert!(violations[0].description.contains("wireshark"));

    let multi_violations = gate.check_processes(&[
        "wireshark".to_string(),
        "burpsuite".to_string(),
        "ida64".to_string(),
        "ghidra".to_string(),
    ]);
    assert_eq!(multi_violations.len(), 4);

    let clean = gate.check_processes(&[
        "nginx".to_string(),
        "sshd".to_string(),
        "python3".to_string(),
    ]);
    assert!(clean.is_empty());
}

#[test]
fn test_mac_address_check() {
    let gate = OpsecGate::new();

    let vmware = gate.check_mac_address("00:0c:29:ab:cd:ef");
    assert!(vmware.is_some());
    assert!(vmware.unwrap().description.contains("00:0c:29"));

    let vbox = gate.check_mac_address("08:00:27:12:34:56");
    assert!(vbox.is_some());

    let hyperv = gate.check_mac_address("00:15:5d:aa:bb:cc");
    assert!(hyperv.is_some());

    let physical = gate.check_mac_address("aa:bb:cc:dd:ee:ff");
    assert!(physical.is_none());

    let upper_case = gate.check_mac_address("00:0C:29:AB:CD:EF");
    assert!(upper_case.is_some());
}

#[test]
fn test_ipv6_violation() {
    let gate = OpsecGate::new();

    let v = gate.check_ipv6(true);
    assert!(v.is_some());
    let violation = v.unwrap();
    assert_eq!(violation.check, OpsecCheck::Ipv6Suppression);
    assert_eq!(violation.severity, OpsecGateSeverity::Critical);

    let ok = gate.check_ipv6(false);
    assert!(ok.is_none());
}

#[test]
fn test_gate_blocks_on_critical() {
    let gate = OpsecGate::new();

    let mut env = clean_environment();
    env.has_ipv6 = true;

    let result = gate.check(&env);
    assert!(result.is_err());
    let violation = result.unwrap_err();
    assert_eq!(violation.severity, OpsecGateSeverity::Critical);
    assert_eq!(violation.check, OpsecCheck::Ipv6Suppression);
}

#[test]
fn test_gate_blocks_on_dns_leak() {
    let gate = OpsecGate::new();

    let mut env = clean_environment();
    env.dns_proxy_configured = false;

    let result = gate.check(&env);
    assert!(result.is_err());
    let violation = result.unwrap_err();
    assert_eq!(violation.check, OpsecCheck::DnsLeak);
    assert_eq!(violation.severity, OpsecGateSeverity::Critical);
}

#[test]
fn test_gate_blocks_on_non_utc_timezone() {
    let gate = OpsecGate::new();

    let mut env = clean_environment();
    env.timezone = "PST".to_string();

    let result = gate.check(&env);
    assert!(result.is_err());
    let violation = result.unwrap_err();
    assert_eq!(violation.check, OpsecCheck::ClockCheck);
}

#[test]
fn test_is_analysis_tool() {
    assert!(OpsecGate::is_analysis_tool("wireshark"));
    assert!(OpsecGate::is_analysis_tool("Wireshark.exe"));
    assert!(OpsecGate::is_analysis_tool("fiddler"));
    assert!(OpsecGate::is_analysis_tool("BurpSuite"));
    assert!(OpsecGate::is_analysis_tool("tcpdump"));
    assert!(OpsecGate::is_analysis_tool("strace"));
    assert!(OpsecGate::is_analysis_tool("ida64.exe"));
    assert!(OpsecGate::is_analysis_tool("x64dbg"));
    assert!(OpsecGate::is_analysis_tool("ghidra"));
    assert!(OpsecGate::is_analysis_tool("procmon"));
    assert!(!OpsecGate::is_analysis_tool("nginx"));
    assert!(!OpsecGate::is_analysis_tool("sshd"));
    assert!(!OpsecGate::is_analysis_tool("python3"));
}

#[test]
fn test_opsec_check_display() {
    assert_eq!(format!("{}", OpsecCheck::DnsLeak), "dns-leak");
    assert_eq!(format!("{}", OpsecCheck::WebRtcLeak), "webrtc-leak");
    assert_eq!(
        format!("{}", OpsecCheck::Ipv6Suppression),
        "ipv6-suppression"
    );
    assert_eq!(
        format!("{}", OpsecCheck::ProcessListScan),
        "process-list-scan"
    );
    assert_eq!(format!("{}", OpsecCheck::HostnameCheck), "hostname-check");
    assert_eq!(format!("{}", OpsecCheck::ClockCheck), "clock-check");
    assert_eq!(format!("{}", OpsecCheck::MacCheck), "mac-check");
}

#[test]
fn test_severity_display() {
    assert_eq!(format!("{}", OpsecGateSeverity::Critical), "CRITICAL");
    assert_eq!(format!("{}", OpsecGateSeverity::Warning), "WARNING");
}

#[test]
fn test_violation_display() {
    let v = OpsecViolation {
        check: OpsecCheck::DnsLeak,
        description: "DNS leaking".to_string(),
        severity: OpsecGateSeverity::Critical,
    };
    let displayed = format!("{}", v);
    assert!(displayed.contains("CRITICAL"));
    assert!(displayed.contains("dns-leak"));
    assert!(displayed.contains("DNS leaking"));
}

#[test]
fn test_warnings_dont_block() {
    let gate = OpsecGate::new();

    let mut env = clean_environment();
    env.hostname = "johns-laptop".to_string();
    env.mac_address = "08:00:27:aa:bb:cc".to_string();
    env.processes = vec!["wireshark".to_string()];

    let result = gate.check(&env);
    assert!(result.is_ok());
    let report = result.unwrap();
    assert!(report.passed);
    assert!(!report.violations.is_empty());
    assert!(report.violations.len() >= 2);
    assert!(report
        .violations
        .iter()
        .all(|v| v.severity == OpsecGateSeverity::Warning));
}
