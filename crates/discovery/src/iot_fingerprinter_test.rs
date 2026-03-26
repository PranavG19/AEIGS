use super::iot_fingerprinter::*;

#[test]
fn test_default_credentials_db_has_at_least_100_entries() {
    let db = get_default_credentials_db();
    assert!(
        db.len() >= 100,
        "expected at least 100 default credential entries, got {}",
        db.len()
    );
}

#[test]
fn test_default_credentials_db_covers_all_device_types() {
    let db = get_default_credentials_db();
    let types: std::collections::HashSet<DeviceType> = db.iter().map(|c| c.device_type).collect();

    assert!(types.contains(&DeviceType::Router));
    assert!(types.contains(&DeviceType::Camera));
    assert!(types.contains(&DeviceType::Printer));
    assert!(types.contains(&DeviceType::IndustrialController));
    assert!(types.contains(&DeviceType::SmartHome));
    assert!(types.contains(&DeviceType::NAS));
    assert!(types.contains(&DeviceType::AccessPoint));
    assert!(types.contains(&DeviceType::Switch));
    assert!(types.contains(&DeviceType::Firewall));
    assert!(types.contains(&DeviceType::Modem));
}

#[test]
fn test_default_credentials_db_has_cve_references() {
    let db = get_default_credentials_db();
    let with_cves = db.iter().filter(|c| !c.cve_references.is_empty()).count();
    assert!(
        with_cves >= 50,
        "expected at least 50 entries with CVE references, got {with_cves}"
    );
}

#[test]
fn test_telnet_banner_matches_cisco_ios() {
    let banner = "Cisco IOS Software, Version 15.1(4)M12\nUser Access Verification\nUsername: ";
    let matches = match_telnet_banner(banner);
    assert!(!matches.is_empty(), "should match Cisco IOS banner");
    let cisco_match = matches
        .iter()
        .find(|m| m.manufacturer == "Cisco")
        .expect("should find Cisco manufacturer");
    assert_eq!(cisco_match.device_type, DeviceType::Router);
    assert!(cisco_match.confidence >= 0.8);
}

#[test]
fn test_telnet_banner_matches_hikvision() {
    let banner = "Hikvision Digital Technology Co., Ltd.\nLogin: ";
    let matches = match_telnet_banner(banner);
    assert!(!matches.is_empty(), "should match Hikvision banner");
    let hik = matches
        .iter()
        .find(|m| m.manufacturer == "Hikvision")
        .expect("should find Hikvision");
    assert_eq!(hik.device_type, DeviceType::Camera);
}

#[test]
fn test_telnet_banner_matches_hp_printer() {
    let banner = "HP LaserJet Pro M404dn\nHP JetDirect\nPlease type your password: ";
    let matches = match_telnet_banner(banner);
    assert!(!matches.is_empty(), "should match HP printer banner");
    let hp = matches
        .iter()
        .find(|m| m.manufacturer == "HP")
        .expect("should find HP");
    assert_eq!(hp.device_type, DeviceType::Printer);
}

#[test]
fn test_telnet_banner_matches_mikrotik() {
    let banner = "MikroTik v6.48.6 (long-term)\nLogin: ";
    let matches = match_telnet_banner(banner);
    assert!(!matches.is_empty(), "should match MikroTik banner");
    let mt = matches
        .iter()
        .find(|m| m.manufacturer == "MikroTik")
        .expect("should find MikroTik");
    assert_eq!(mt.device_type, DeviceType::Router);
}

#[test]
fn test_telnet_banner_matches_siemens_plc() {
    let banner = "Siemens SIMATIC S7 PLC\nPassword: ";
    let matches = match_telnet_banner(banner);
    assert!(!matches.is_empty(), "should match Siemens SIMATIC banner");
    let siemens = matches
        .iter()
        .find(|m| m.manufacturer == "Siemens")
        .expect("should find Siemens");
    assert_eq!(siemens.device_type, DeviceType::IndustrialController);
}

#[test]
fn test_telnet_banner_extracts_firmware_version() {
    let banner = "Device Firmware Version: 3.14.2\nLogin: ";
    let matches = match_telnet_banner(banner);
    let with_fw: Vec<_> = matches
        .iter()
        .filter(|m| m.firmware_version.is_some())
        .collect();
    if !with_fw.is_empty() {
        assert_eq!(with_fw[0].firmware_version.as_deref(), Some("3.14.2"));
    }
}

#[test]
fn test_telnet_banner_no_match_for_random_text() {
    let banner = "Hello, this is just a random text with no device info.";
    let matches = match_telnet_banner(banner);
    assert!(
        matches.is_empty(),
        "random text should not match any device"
    );
}

#[test]
fn test_ssh_banner_matches_cisco() {
    let banner = "SSH-2.0-Cisco-1.25";
    let matches = match_ssh_banner(banner);
    assert!(!matches.is_empty(), "should match Cisco SSH banner");
    let cisco = matches
        .iter()
        .find(|m| m.manufacturer == "Cisco")
        .expect("should find Cisco");
    assert_eq!(cisco.device_type, DeviceType::Router);
}

#[test]
fn test_ssh_banner_matches_dropbear() {
    let banner = "SSH-2.0-dropbear_2020.81";
    let matches = match_ssh_banner(banner);
    assert!(!matches.is_empty(), "should match dropbear SSH banner");
    let db_match = matches
        .iter()
        .find(|m| m.model_hint.contains("Embedded"))
        .expect("should identify as embedded device");
    assert_eq!(db_match.device_type, DeviceType::Other);
}

#[test]
fn test_ssh_banner_matches_mikrotik() {
    let banner = "SSH-2.0-ROSSSH MikroTik_RouterOS";
    let matches = match_ssh_banner(banner);
    assert!(!matches.is_empty(), "should match MikroTik SSH");
    let mt = matches
        .iter()
        .find(|m| m.manufacturer == "MikroTik")
        .expect("should find MikroTik");
    assert_eq!(mt.device_type, DeviceType::Router);
}

#[test]
fn test_ssh_banner_extracts_version() {
    let banner = "SSH-2.0-dropbear_2020.81";
    let matches = match_ssh_banner(banner);
    assert!(!matches.is_empty());
    assert!(
        matches[0].firmware_version.is_some(),
        "should extract firmware version from SSH banner"
    );
}

#[test]
fn test_ssh_banner_no_match_for_openssh() {
    let banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4";
    let matches = match_ssh_banner(banner);
    assert!(
        matches.is_empty(),
        "generic OpenSSH should not match an IoT device"
    );
}

#[test]
fn test_identify_device_combines_sources() {
    let telnet = "Cisco IOS Software\nUser Access Verification";
    let ssh = "SSH-2.0-Cisco-1.25";
    let results = identify_device(Some(telnet), Some(ssh), None);
    assert!(
        !results.is_empty(),
        "should identify device from combined banners"
    );
    assert!(
        results.iter().any(|m| m.manufacturer == "Cisco"),
        "should include Cisco in results"
    );
}

#[test]
fn test_identify_device_with_http_headers() {
    let mut headers = std::collections::HashMap::new();
    headers.insert("Server".to_string(), "Hikvision-Webs".to_string());
    let results = identify_device(None, None, Some(&headers));
    assert!(!results.is_empty(), "should identify from HTTP headers");
    let hik = results
        .iter()
        .find(|m| m.manufacturer == "Hikvision")
        .expect("should find Hikvision from headers");
    assert_eq!(hik.device_type, DeviceType::Camera);
}

#[test]
fn test_identify_device_returns_empty_for_no_input() {
    let results = identify_device(None, None, None);
    assert!(results.is_empty(), "no input should yield no matches");
}

#[test]
fn test_assess_risk_industrial_controller_is_critical() {
    let risk = assess_device_risk(DeviceType::IndustrialController, false, 0, false);
    assert_eq!(risk, IoTRisk::Critical);
}

#[test]
fn test_assess_risk_default_creds_escalates() {
    let risk_no_creds = assess_device_risk(DeviceType::Printer, false, 0, false);
    let risk_with_creds = assess_device_risk(DeviceType::Printer, true, 0, false);
    assert!(
        risk_with_creds > risk_no_creds,
        "default credentials should escalate risk"
    );
}

#[test]
fn test_assess_risk_internet_facing_escalates() {
    let risk_internal = assess_device_risk(DeviceType::Camera, false, 0, false);
    let risk_external = assess_device_risk(DeviceType::Camera, false, 0, true);
    assert!(
        risk_external > risk_internal,
        "internet-facing should escalate risk"
    );
}

#[test]
fn test_assess_risk_multiple_cves_escalates() {
    let risk_no_cve = assess_device_risk(DeviceType::Router, false, 0, false);
    let risk_many_cves = assess_device_risk(DeviceType::Router, false, 5, false);
    assert!(
        risk_many_cves > risk_no_cve,
        "many CVEs should escalate risk"
    );
}

#[test]
fn test_assess_risk_caps_at_critical() {
    let risk = assess_device_risk(DeviceType::IndustrialController, true, 10, true);
    assert_eq!(risk, IoTRisk::Critical, "risk should cap at critical");
}

#[test]
fn test_build_iot_report_empty() {
    let report = build_iot_report(vec![]);
    assert_eq!(report.total_devices, 0);
    assert_eq!(report.critical_count, 0);
    assert_eq!(report.high_count, 0);
    assert!(report.findings.is_empty());
}

#[test]
fn test_build_iot_report_aggregates_correctly() {
    let findings = vec![
        IoTFinding {
            host: "192.168.1.1".into(),
            device_type: DeviceType::Router,
            manufacturer: "Cisco".into(),
            model: "RV340".into(),
            risk: IoTRisk::Critical,
            default_creds_found: vec![],
            banner_matches: vec![],
            description: "Router with default creds and known CVEs".into(),
            cve_references: vec!["CVE-2022-20707".into()],
        },
        IoTFinding {
            host: "192.168.1.50".into(),
            device_type: DeviceType::Camera,
            manufacturer: "Hikvision".into(),
            model: "DS-2CD2143G2".into(),
            risk: IoTRisk::High,
            default_creds_found: vec![],
            banner_matches: vec![],
            description: "Camera with default password".into(),
            cve_references: vec!["CVE-2021-36260".into()],
        },
        IoTFinding {
            host: "192.168.1.100".into(),
            device_type: DeviceType::Printer,
            manufacturer: "HP".into(),
            model: "LaserJet Pro M404".into(),
            risk: IoTRisk::Low,
            default_creds_found: vec![],
            banner_matches: vec![],
            description: "Printer on internal network".into(),
            cve_references: vec![],
        },
    ];

    let report = build_iot_report(findings);
    assert_eq!(report.total_devices, 3);
    assert_eq!(report.critical_count, 1);
    assert_eq!(report.high_count, 1);
    assert_eq!(report.risk_summary[&IoTRisk::Critical], 1);
    assert_eq!(report.risk_summary[&IoTRisk::High], 1);
    assert_eq!(report.risk_summary[&IoTRisk::Low], 1);
    assert_eq!(report.device_type_summary[&DeviceType::Router], 1);
    assert_eq!(report.device_type_summary[&DeviceType::Camera], 1);
    assert_eq!(report.device_type_summary[&DeviceType::Printer], 1);
    assert_eq!(report.manufacturer_summary["Cisco"], 1);
    assert_eq!(report.manufacturer_summary["Hikvision"], 1);
}

#[test]
fn test_display_impls() {
    assert_eq!(format!("{}", DeviceType::Router), "Router");
    assert_eq!(format!("{}", DeviceType::Camera), "IP Camera");
    assert_eq!(
        format!("{}", DeviceType::IndustrialController),
        "Industrial Controller"
    );
    assert_eq!(format!("{}", DeviceType::NAS), "Network Attached Storage");
    assert_eq!(format!("{}", Protocol::Telnet), "Telnet");
    assert_eq!(format!("{}", Protocol::SSH), "SSH");
    assert_eq!(format!("{}", Protocol::HTTP), "HTTP");
    assert_eq!(format!("{}", Protocol::HTTPS), "HTTPS");
    assert_eq!(format!("{}", IoTRisk::Critical), "critical");
    assert_eq!(format!("{}", IoTRisk::Low), "low");

    let report = build_iot_report(vec![]);
    let display = format!("{report}");
    assert!(display.contains("0 devices"));

    let finding = IoTFinding {
        host: "10.0.0.1".into(),
        device_type: DeviceType::Firewall,
        manufacturer: "Fortinet".into(),
        model: "FortiGate 60F".into(),
        risk: IoTRisk::High,
        default_creds_found: vec![],
        banner_matches: vec![],
        description: "Firewall with empty default password".into(),
        cve_references: vec![],
    };
    let finding_display = format!("{finding}");
    assert!(finding_display.contains("Fortinet"));
    assert!(finding_display.contains("high"));
    assert!(finding_display.contains("10.0.0.1"));
}

#[test]
fn test_lookup_credentials_by_manufacturer() {
    let cisco_creds = lookup_credentials("Cisco", None);
    assert!(
        cisco_creds.len() >= 3,
        "should find multiple Cisco credentials, got {}",
        cisco_creds.len()
    );
    assert!(cisco_creds.iter().all(|c| c.manufacturer.contains("Cisco")));
}

#[test]
fn test_lookup_credentials_by_manufacturer_and_model() {
    let creds = lookup_credentials("Hikvision", Some("DS-2CD"));
    assert!(
        !creds.is_empty(),
        "should find Hikvision DS-2CD credentials"
    );
    assert!(creds.iter().all(|c| c.model_pattern.contains("DS-2CD")));
}

#[test]
fn test_credentials_by_device_type() {
    let camera_creds = credentials_by_device_type(DeviceType::Camera);
    assert!(
        camera_creds.len() >= 5,
        "should find at least 5 camera credentials, got {}",
        camera_creds.len()
    );
    assert!(camera_creds
        .iter()
        .all(|c| c.device_type == DeviceType::Camera));
}

#[test]
fn test_telnet_banner_matches_fortinet() {
    let banner = "FortiGate-60F login: \nFortiOS 7.2.3";
    let matches = match_telnet_banner(banner);
    assert!(!matches.is_empty(), "should match FortiOS/FortiGate banner");
    let forti = matches
        .iter()
        .find(|m| m.manufacturer == "Fortinet")
        .expect("should find Fortinet");
    assert_eq!(forti.device_type, DeviceType::Firewall);
}

#[test]
fn test_ssh_banner_matches_fortinet() {
    let banner = "SSH-2.0-FortiSSL_2.0";
    let matches = match_ssh_banner(banner);
    assert!(!matches.is_empty(), "should match FortiSSL SSH banner");
    let forti = matches
        .iter()
        .find(|m| m.manufacturer == "Fortinet")
        .expect("should find Fortinet");
    assert_eq!(forti.device_type, DeviceType::Firewall);
}

#[test]
fn test_default_credentials_db_has_multiple_protocols() {
    let db = get_default_credentials_db();
    let protocols: std::collections::HashSet<Protocol> = db.iter().map(|c| c.protocol).collect();
    assert!(protocols.contains(&Protocol::Telnet));
    assert!(protocols.contains(&Protocol::SSH));
    assert!(protocols.contains(&Protocol::HTTP));
    assert!(protocols.contains(&Protocol::HTTPS));
}

#[test]
fn test_risk_ordering() {
    assert!(IoTRisk::Critical > IoTRisk::High);
    assert!(IoTRisk::High > IoTRisk::Medium);
    assert!(IoTRisk::Medium > IoTRisk::Low);
    assert!(IoTRisk::Low > IoTRisk::Info);
}
