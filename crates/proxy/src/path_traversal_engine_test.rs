use super::*;
use std::collections::HashSet;

#[test]
fn generates_at_least_50_unique_payloads_linux() {
    let config = TraversalConfig::default();
    let payloads = PathTraversalEngine::generate(&config);
    let unique: HashSet<&str> = payloads.iter().map(|p| p.value.as_str()).collect();
    assert!(
        unique.len() >= 50,
        "Expected ≥50 unique payloads, got {}",
        unique.len()
    );
}

#[test]
fn generates_at_least_50_unique_payloads_windows() {
    let config = TraversalConfig::default().with_os(TargetOs::Windows);
    let payloads = PathTraversalEngine::generate(&config);
    let unique: HashSet<&str> = payloads.iter().map(|p| p.value.as_str()).collect();
    assert!(
        unique.len() >= 50,
        "Expected ≥50 unique payloads for Windows, got {}",
        unique.len()
    );
}

#[test]
fn no_duplicate_values() {
    let config = TraversalConfig::default();
    let payloads = PathTraversalEngine::generate(&config);
    let mut seen = HashSet::new();
    for p in &payloads {
        assert!(
            seen.insert(&p.value),
            "Duplicate payload value: {}",
            p.value
        );
    }
}

#[test]
fn encoding_ladder_has_at_least_6_levels() {
    let ladder = PathTraversalEngine::encoding_ladder();
    assert!(
        ladder.len() >= 6,
        "Expected ≥6 encoding levels, got {}",
        ladder.len()
    );
}

#[test]
fn encoding_ladder_applied_to_directory_traversals() {
    let config = TraversalConfig::default();
    let payloads = PathTraversalEngine::generate(&config);
    let traversal_encodings: HashSet<EncodingLevel> = payloads
        .iter()
        .filter(|p| p.category == PayloadCategory::DirectoryTraversal)
        .map(|p| p.encoding)
        .collect();
    assert!(
        traversal_encodings.len() >= 6,
        "Expected ≥6 encoding variants in traversal payloads, got {}",
        traversal_encodings.len()
    );
}

#[test]
fn linux_payloads_contain_etc_passwd() {
    let config = TraversalConfig::default();
    let payloads = PathTraversalEngine::generate(&config);
    assert!(payloads.iter().any(|p| p.value.contains("etc/passwd")));
}

#[test]
fn linux_payloads_contain_proc_self_environ() {
    let config = TraversalConfig::default();
    let payloads = PathTraversalEngine::generate(&config);
    assert!(payloads
        .iter()
        .any(|p| p.value.contains("/proc/self/environ")));
}

#[test]
fn windows_payloads_contain_win_ini() {
    let config = TraversalConfig::default().with_os(TargetOs::Windows);
    let payloads = PathTraversalEngine::generate(&config);
    assert!(
        payloads.iter().any(|p| p.value.contains("win.ini")),
        "Windows payloads should target win.ini"
    );
}

#[test]
fn windows_payloads_contain_hosts() {
    let config = TraversalConfig::default().with_os(TargetOs::Windows);
    let payloads = PathTraversalEngine::generate(&config);
    assert!(payloads.iter().any(|p| p.value.contains("hosts")));
}

#[test]
fn php_wrappers_present_at_least_5_types() {
    let config = TraversalConfig::default();
    let payloads = PathTraversalEngine::generate(&config);
    let wrapper_values: Vec<&str> = payloads
        .iter()
        .filter(|p| p.category == PayloadCategory::PhpWrapper)
        .map(|p| p.value.as_str())
        .collect();
    assert!(
        wrapper_values.len() >= 5,
        "Expected ≥5 PHP wrapper payloads, got {}",
        wrapper_values.len()
    );
}

#[test]
fn php_filter_wrapper_present() {
    let config = TraversalConfig::default();
    let payloads = PathTraversalEngine::generate(&config);
    assert!(payloads.iter().any(|p| p.value.starts_with("php://filter")));
}

#[test]
fn php_input_wrapper_present() {
    let config = TraversalConfig::default();
    let payloads = PathTraversalEngine::generate(&config);
    assert!(payloads.iter().any(|p| p.value == "php://input"));
}

#[test]
fn expect_wrapper_present() {
    let config = TraversalConfig::default();
    let payloads = PathTraversalEngine::generate(&config);
    assert!(payloads.iter().any(|p| p.value.starts_with("expect://")));
}

#[test]
fn data_uri_wrapper_present() {
    let config = TraversalConfig::default();
    let payloads = PathTraversalEngine::generate(&config);
    assert!(payloads
        .iter()
        .any(|p| p.value.starts_with("data://text/plain")));
}

#[test]
fn zip_wrapper_present() {
    let config = TraversalConfig::default();
    let payloads = PathTraversalEngine::generate(&config);
    assert!(payloads.iter().any(|p| p.value.starts_with("zip://")));
}

#[test]
fn phar_wrapper_present() {
    let config = TraversalConfig::default();
    let payloads = PathTraversalEngine::generate(&config);
    assert!(payloads.iter().any(|p| p.value.starts_with("phar://")));
}

#[test]
fn filter_bypasses_generated() {
    let config = TraversalConfig::default();
    let payloads = PathTraversalEngine::generate(&config);
    let bypass_count = payloads
        .iter()
        .filter(|p| p.category == PayloadCategory::FilterBypass)
        .count();
    assert!(
        bypass_count >= 5,
        "Expected ≥5 filter bypasses, got {bypass_count}"
    );
}

#[test]
fn semicolon_bypass_present() {
    let config = TraversalConfig::default();
    let payloads = PathTraversalEngine::generate(&config);
    assert!(payloads.iter().any(|p| p.value.contains("..;/")));
}

#[test]
fn double_dot_double_slash_bypass_present() {
    let config = TraversalConfig::default();
    let payloads = PathTraversalEngine::generate(&config);
    assert!(payloads.iter().any(|p| p.value.contains("....//")));
}

#[test]
fn log_poisoning_payloads_present() {
    let config = TraversalConfig::default();
    let payloads = PathTraversalEngine::generate(&config);
    let log_count = payloads
        .iter()
        .filter(|p| p.category == PayloadCategory::LogPoisoning)
        .count();
    assert!(
        log_count >= 2,
        "Expected ≥2 log poisoning payloads, got {log_count}"
    );
}

#[test]
fn log_poisoning_includes_user_agent_injection() {
    let config = TraversalConfig::default();
    let payloads = PathTraversalEngine::generate(&config);
    assert!(payloads
        .iter()
        .any(|p| p.category == PayloadCategory::LogPoisoning && p.value.contains("<?php")));
}

#[test]
fn proc_self_payloads_linux_only() {
    let linux = PathTraversalEngine::generate(&TraversalConfig::default());
    let win = PathTraversalEngine::generate(&TraversalConfig::default().with_os(TargetOs::Windows));
    assert!(linux
        .iter()
        .any(|p| p.category == PayloadCategory::ProcSelf));
    assert!(!win.iter().any(|p| p.category == PayloadCategory::ProcSelf));
}

#[test]
fn proc_self_fd_present() {
    let config = TraversalConfig::default();
    let payloads = PathTraversalEngine::generate(&config);
    assert!(payloads.iter().any(|p| p.value.contains("/proc/self/fd/")));
}

#[test]
fn archive_traversal_contains_zip_slip() {
    let config = TraversalConfig::default();
    let payloads = PathTraversalEngine::generate(&config);
    assert!(payloads
        .iter()
        .any(|p| p.category == PayloadCategory::ArchiveTraversal && p.value.contains("cron.d")));
}

#[test]
fn path_normalization_windows_ntfs_ads() {
    let config = TraversalConfig::default().with_os(TargetOs::Windows);
    let payloads = PathTraversalEngine::generate(&config);
    assert!(
        payloads.iter().any(
            |p| p.category == PayloadCategory::PathNormalization && p.value.contains("::$DATA")
        ),
        "Windows path normalization should include NTFS ADS"
    );
}

#[test]
fn path_normalization_linux() {
    let config = TraversalConfig::default();
    let payloads = PathTraversalEngine::generate(&config);
    assert!(payloads
        .iter()
        .any(|p| p.category == PayloadCategory::PathNormalization));
}

#[test]
fn detect_os_linux_from_apache() {
    assert_eq!(
        PathTraversalEngine::detect_os("Apache/2.4.41 (Ubuntu)"),
        TargetOs::Linux
    );
}

#[test]
fn detect_os_windows_from_iis() {
    assert_eq!(
        PathTraversalEngine::detect_os("Microsoft-IIS/10.0"),
        TargetOs::Windows
    );
}

#[test]
fn detect_os_defaults_to_linux() {
    assert_eq!(
        PathTraversalEngine::detect_os("nginx/1.18.0"),
        TargetOs::Linux
    );
}

#[test]
fn config_builder_chain() {
    let config = TraversalConfig::default()
        .with_os(TargetOs::Windows)
        .with_depth(4)
        .with_php_wrappers(false)
        .with_log_poisoning(false)
        .with_proc_self(false)
        .with_archive_traversal(false)
        .with_path_normalization(false);
    assert_eq!(config.target_os, TargetOs::Windows);
    assert_eq!(config.traversal_depth, 4);
    assert!(!config.include_php_wrappers);
}

#[test]
fn minimal_config_still_produces_payloads() {
    let config = TraversalConfig::default()
        .with_php_wrappers(false)
        .with_log_poisoning(false)
        .with_proc_self(false)
        .with_archive_traversal(false)
        .with_path_normalization(false);
    let payloads = PathTraversalEngine::generate(&config);
    assert!(
        !payloads.is_empty(),
        "Even minimal config should produce traversal + bypass payloads"
    );
}

#[test]
fn all_payloads_have_nonempty_description() {
    let config = TraversalConfig::default();
    let payloads = PathTraversalEngine::generate(&config);
    for p in &payloads {
        assert!(
            !p.description.is_empty(),
            "Payload has empty description: {:?}",
            p.value
        );
    }
}

#[test]
fn all_payloads_have_nonempty_value() {
    let config = TraversalConfig::default();
    let payloads = PathTraversalEngine::generate(&config);
    for p in &payloads {
        assert!(!p.value.is_empty(), "Payload has empty value");
    }
}

#[test]
fn null_byte_encoding_appends_null() {
    let encoded = PathTraversalEngine::apply_encoding("../etc/passwd", EncodingLevel::NullByte);
    assert!(encoded.ends_with("%00"));
}

#[test]
fn url_encoded_replaces_slashes() {
    let encoded = PathTraversalEngine::apply_encoding("../", EncodingLevel::UrlEncoded);
    assert!(encoded.contains("%2e"));
    assert!(encoded.contains("%2f"));
}

#[test]
fn double_url_encoded_replaces_slashes() {
    let encoded = PathTraversalEngine::apply_encoding("../", EncodingLevel::DoubleUrlEncoded);
    assert!(encoded.contains("%252e"));
    assert!(encoded.contains("%252f"));
}

#[test]
fn custom_depth_affects_traversal_length() {
    let shallow = TraversalConfig::default().with_depth(2);
    let deep = TraversalConfig::default().with_depth(12);

    let shallow_payloads = PathTraversalEngine::generate(&shallow);
    let deep_payloads = PathTraversalEngine::generate(&deep);

    let shallow_plain = shallow_payloads
        .iter()
        .find(|p| {
            p.category == PayloadCategory::DirectoryTraversal
                && p.encoding == EncodingLevel::Plain
                && p.value.contains("etc/passwd")
        })
        .unwrap();
    let deep_plain = deep_payloads
        .iter()
        .find(|p| {
            p.category == PayloadCategory::DirectoryTraversal
                && p.encoding == EncodingLevel::Plain
                && p.value.contains("etc/passwd")
        })
        .unwrap();

    assert!(
        deep_plain.value.len() > shallow_plain.value.len(),
        "Deeper traversal should produce longer payloads"
    );
}
