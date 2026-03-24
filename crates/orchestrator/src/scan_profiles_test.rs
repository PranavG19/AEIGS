use super::scan_config::ScanConfig;
use super::scan_profiles::*;
use clap::Parser;
use std::time::Duration;

fn base_config() -> ScanConfig {
    ScanConfig::try_parse_from(["aegis", "--target", "http://localhost:8080"]).unwrap()
}

#[test]
fn quick_profile_settings() {
    let p = quick_profile();
    assert_eq!(p.max_threads, 1);
    assert_eq!(p.timeout, Some(Duration::from_secs(300)));
    assert_eq!(p.max_iterations, 1);
    assert!(!p.use_llm);
    assert!(p.skip_evasion);
}

#[test]
fn standard_profile_settings() {
    let p = standard_profile();
    assert_eq!(p.max_threads, 10);
    assert_eq!(p.max_iterations, 2);
    assert_eq!(p.max_rps, Some(20));
}

#[test]
fn deep_profile_settings() {
    let p = deep_profile();
    assert_eq!(p.max_threads, 50);
    assert!(p.timeout.is_none());
    assert_eq!(p.max_iterations, 5);
    assert!(p.use_llm);
}

#[test]
fn stealth_profile_settings() {
    let p = stealth_profile();
    assert_eq!(p.stealth_level, "paranoid");
    assert_eq!(p.max_rps, Some(2));
    assert_eq!(p.max_threads, 1);
}

#[test]
fn apply_quick_to_config() {
    let mut config = base_config();
    let p = quick_profile();
    p.apply_to(&mut config);
    assert_eq!(config.pipeline.max_iterations, 1);
    assert!(config.llm.no_llm);
    assert!(config.stealth.skip_evasion);
}

#[test]
fn apply_deep_to_config() {
    let mut config = base_config();
    let p = deep_profile();
    p.apply_to(&mut config);
    assert_eq!(config.pipeline.max_iterations, 5);
    assert!(!config.llm.no_llm);
    assert!(config.stealth.max_rps.is_none());
}

#[test]
fn apply_stealth_to_config() {
    let mut config = base_config();
    let p = stealth_profile();
    p.apply_to(&mut config);
    assert_eq!(config.stealth.stealth_level, "paranoid");
    assert_eq!(config.stealth.max_rps, Some(2));
}

#[test]
fn custom_profile_creation() {
    let p = custom_profile(
        25,
        Some(Duration::from_secs(600)),
        3,
        true,
        "aggressive",
        Some(15),
    );
    assert_eq!(p.profile, ScanProfile::Custom);
    assert_eq!(p.max_threads, 25);
    assert!(p.use_llm);
}

#[test]
fn get_profile_by_name() {
    assert!(get_profile("quick").is_some());
    assert!(get_profile("standard").is_some());
    assert!(get_profile("deep").is_some());
    assert!(get_profile("stealth").is_some());
    assert!(get_profile("nonexistent").is_none());
}

#[test]
fn get_profile_case_insensitive() {
    assert!(get_profile("QUICK").is_some());
    assert!(get_profile("Deep").is_some());
}

#[test]
fn list_profiles_returns_all() {
    let profiles = list_profiles();
    assert_eq!(profiles.len(), 4);
    let names: Vec<&str> = profiles.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"quick"));
    assert!(names.contains(&"standard"));
    assert!(names.contains(&"deep"));
    assert!(names.contains(&"stealth"));
}

#[test]
fn custom_no_evasion_for_default_stealth() {
    let p = custom_profile(5, None, 1, false, "default", None);
    assert!(p.skip_evasion);
}

#[test]
fn custom_evasion_for_paranoid() {
    let p = custom_profile(5, None, 1, false, "paranoid", None);
    assert!(!p.skip_evasion);
}
