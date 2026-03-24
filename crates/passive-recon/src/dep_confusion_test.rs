use crate::dep_confusion::*;
use crate::dependency_parser::{Ecosystem, ParsedDependency};

fn dep(name: &str, version: &str, ecosystem: Ecosystem) -> ParsedDependency {
    ParsedDependency {
        name: name.to_string(),
        version: version.to_string(),
        ecosystem,
    }
}

// ── MockRegistryChecker tests ───────────────────────────────────────────────

#[test]
fn mock_checker_returns_not_found_by_default() {
    let checker = MockRegistryChecker::new();
    let status = checker.check_package("anything", Ecosystem::Npm);
    assert_eq!(status, RegistryStatus::NotFound);
}

#[test]
fn mock_checker_returns_configured_response() {
    let checker = MockRegistryChecker::new().add_response(
        "express",
        Ecosystem::Npm,
        RegistryStatus::ExistsPublic {
            public_version: "4.18.0".to_string(),
        },
    );
    let status = checker.check_package("express", Ecosystem::Npm);
    assert_eq!(
        status,
        RegistryStatus::ExistsPublic {
            public_version: "4.18.0".to_string()
        }
    );
}

#[test]
fn mock_checker_custom_default() {
    let checker =
        MockRegistryChecker::new().with_default(RegistryStatus::LookupError("timeout".to_string()));
    let status = checker.check_package("unknown-pkg", Ecosystem::Cargo);
    assert_eq!(status, RegistryStatus::LookupError("timeout".to_string()));
}

// ── Risk scoring: NotFound packages ─────────────────────────────────────────

#[test]
fn unscoped_npm_not_found_is_critical() {
    let d = dep("my-internal-lib", "1.0.0", Ecosystem::Npm);
    let checker = MockRegistryChecker::new();
    let analysis = analyze_confusion(&[d], &checker);
    assert_eq!(
        analysis.findings[0].risk_level,
        ConfusionRiskLevel::Critical
    );
    assert_eq!(analysis.critical_risk_count, 1);
}

#[test]
fn scoped_npm_not_found_is_medium() {
    let d = dep("@myorg/internal-lib", "1.0.0", Ecosystem::Npm);
    let checker = MockRegistryChecker::new();
    let analysis = analyze_confusion(&[d], &checker);
    assert_eq!(analysis.findings[0].risk_level, ConfusionRiskLevel::Medium);
}

#[test]
fn cargo_not_found_is_critical() {
    let d = dep("our-secret-crate", "0.1.0", Ecosystem::Cargo);
    let checker = MockRegistryChecker::new();
    let analysis = analyze_confusion(&[d], &checker);
    assert_eq!(
        analysis.findings[0].risk_level,
        ConfusionRiskLevel::Critical
    );
}

#[test]
fn pypi_internal_prefix_not_found_is_critical() {
    let d = dep("internal-utils", "2.0.0", Ecosystem::PyPi);
    let checker = MockRegistryChecker::new();
    let analysis = analyze_confusion(&[d], &checker);
    assert_eq!(
        analysis.findings[0].risk_level,
        ConfusionRiskLevel::Critical
    );
}

#[test]
fn rubygems_not_found_is_critical() {
    let d = dep("corp-auth-gem", "3.0.0", Ecosystem::RubyGems);
    let checker = MockRegistryChecker::new();
    let analysis = analyze_confusion(&[d], &checker);
    assert_eq!(
        analysis.findings[0].risk_level,
        ConfusionRiskLevel::Critical
    );
}

#[test]
fn go_internal_module_not_found_is_critical() {
    let d = dep("mycompany/internal/auth", "1.2.0", Ecosystem::Go);
    let checker = MockRegistryChecker::new();
    let analysis = analyze_confusion(&[d], &checker);
    assert_eq!(
        analysis.findings[0].risk_level,
        ConfusionRiskLevel::Critical
    );
}

#[test]
fn go_external_module_not_found_is_medium() {
    let d = dep("github.com/org/private-lib", "1.0.0", Ecosystem::Go);
    let checker = MockRegistryChecker::new();
    let analysis = analyze_confusion(&[d], &checker);
    assert_eq!(analysis.findings[0].risk_level, ConfusionRiskLevel::Medium);
}

// ── Version priority confusion ──────────────────────────────────────────────

#[test]
fn public_version_higher_than_local_is_high_risk() {
    let d = dep("lodash", "4.17.0", Ecosystem::Npm);
    let checker = MockRegistryChecker::new().add_response(
        "lodash",
        Ecosystem::Npm,
        RegistryStatus::ExistsPublic {
            public_version: "4.18.0".to_string(),
        },
    );
    let analysis = analyze_confusion(&[d], &checker);
    assert_eq!(analysis.findings[0].risk_level, ConfusionRiskLevel::High);
    assert_eq!(analysis.high_risk_count, 1);
}

#[test]
fn local_version_higher_than_public_is_low_risk() {
    let d = dep("lodash", "4.20.0", Ecosystem::Npm);
    let checker = MockRegistryChecker::new().add_response(
        "lodash",
        Ecosystem::Npm,
        RegistryStatus::ExistsPublic {
            public_version: "4.18.0".to_string(),
        },
    );
    let analysis = analyze_confusion(&[d], &checker);
    assert_eq!(analysis.findings[0].risk_level, ConfusionRiskLevel::Low);
}

#[test]
fn equal_versions_is_low_risk() {
    let d = dep("serde", "1.0.200", Ecosystem::Cargo);
    let checker = MockRegistryChecker::new().add_response(
        "serde",
        Ecosystem::Cargo,
        RegistryStatus::ExistsPublic {
            public_version: "1.0.200".to_string(),
        },
    );
    let analysis = analyze_confusion(&[d], &checker);
    assert_eq!(analysis.findings[0].risk_level, ConfusionRiskLevel::Low);
}

// ── Version comparison edge cases ───────────────────────────────────────────

#[test]
fn version_comparison_two_component() {
    let d = dep("simple-pkg", "1.0", Ecosystem::PyPi);
    let checker = MockRegistryChecker::new().add_response(
        "simple-pkg",
        Ecosystem::PyPi,
        RegistryStatus::ExistsPublic {
            public_version: "2.0".to_string(),
        },
    );
    let analysis = analyze_confusion(&[d], &checker);
    assert_eq!(analysis.findings[0].risk_level, ConfusionRiskLevel::High);
}

#[test]
fn version_comparison_single_component() {
    let d = dep("tiny", "1", Ecosystem::RubyGems);
    let checker = MockRegistryChecker::new().add_response(
        "tiny",
        Ecosystem::RubyGems,
        RegistryStatus::ExistsPublic {
            public_version: "3".to_string(),
        },
    );
    let analysis = analyze_confusion(&[d], &checker);
    assert_eq!(analysis.findings[0].risk_level, ConfusionRiskLevel::High);
}

#[test]
fn version_with_v_prefix_handled() {
    let d = dep("go-mod", "v1.2.3", Ecosystem::Go);
    let checker = MockRegistryChecker::new().add_response(
        "go-mod",
        Ecosystem::Go,
        RegistryStatus::ExistsPublic {
            public_version: "v2.0.0".to_string(),
        },
    );
    let analysis = analyze_confusion(&[d], &checker);
    assert_eq!(analysis.findings[0].risk_level, ConfusionRiskLevel::High);
}

// ── Lookup error ────────────────────────────────────────────────────────────

#[test]
fn lookup_error_is_low_risk() {
    let d = dep("unknown", "1.0.0", Ecosystem::Npm);
    let checker = MockRegistryChecker::new()
        .with_default(RegistryStatus::LookupError("network timeout".to_string()));
    let analysis = analyze_confusion(&[d], &checker);
    assert_eq!(analysis.findings[0].risk_level, ConfusionRiskLevel::Low);
}

// ── Full analysis properties ────────────────────────────────────────────────

#[test]
fn analysis_counts_are_correct() {
    let deps = vec![
        dep("private-a", "1.0.0", Ecosystem::Npm),
        dep("private-b", "2.0.0", Ecosystem::Cargo),
        dep("public-c", "1.0.0", Ecosystem::PyPi),
    ];
    let checker = MockRegistryChecker::new().add_response(
        "public-c",
        Ecosystem::PyPi,
        RegistryStatus::ExistsPublic {
            public_version: "5.0.0".to_string(),
        },
    );
    let analysis = analyze_confusion(&deps, &checker);
    assert_eq!(analysis.total_packages_checked, 3);
    assert_eq!(analysis.critical_risk_count, 2);
    assert_eq!(analysis.high_risk_count, 1);
}

#[test]
fn findings_sorted_by_risk_descending() {
    let deps = vec![
        dep("low-risk", "1.0.0", Ecosystem::Npm),
        dep("critical-pkg", "1.0.0", Ecosystem::Cargo),
        dep("high-risk", "1.0.0", Ecosystem::PyPi),
    ];
    let checker = MockRegistryChecker::new()
        .add_response(
            "low-risk",
            Ecosystem::Npm,
            RegistryStatus::ExistsPublic {
                public_version: "1.0.0".to_string(),
            },
        )
        .add_response(
            "high-risk",
            Ecosystem::PyPi,
            RegistryStatus::ExistsPublic {
                public_version: "9.0.0".to_string(),
            },
        );
    let analysis = analyze_confusion(&deps, &checker);
    assert!(analysis.findings[0].risk_level >= analysis.findings[1].risk_level);
    assert!(analysis.findings[1].risk_level >= analysis.findings[2].risk_level);
}

#[test]
fn max_risk_returns_highest() {
    let deps = vec![
        dep("safe", "1.0.0", Ecosystem::Npm),
        dep("dangerous", "1.0.0", Ecosystem::Cargo),
    ];
    let checker = MockRegistryChecker::new().add_response(
        "safe",
        Ecosystem::Npm,
        RegistryStatus::ExistsPublic {
            public_version: "1.0.0".to_string(),
        },
    );
    let analysis = analyze_confusion(&deps, &checker);
    assert_eq!(analysis.max_risk(), Some(ConfusionRiskLevel::Critical));
}

#[test]
fn empty_deps_produces_empty_analysis() {
    let checker = MockRegistryChecker::new();
    let analysis = analyze_confusion(&[], &checker);
    assert_eq!(analysis.total_packages_checked, 0);
    assert_eq!(analysis.findings.len(), 0);
    assert_eq!(analysis.max_risk(), None);
}

// ── check_lockfile_confusion integration ────────────────────────────────────

#[test]
fn check_npm_lockfile_confusion() {
    let content = r#"{
        "packages": {
            "node_modules/express": { "version": "4.18.0" },
            "node_modules/my-internal-auth": { "version": "1.0.0" }
        }
    }"#;
    let checker = MockRegistryChecker::new().add_response(
        "express",
        Ecosystem::Npm,
        RegistryStatus::ExistsPublic {
            public_version: "4.18.0".to_string(),
        },
    );
    let analysis = check_lockfile_confusion("package-lock.json", content, &checker).unwrap();
    assert_eq!(analysis.total_packages_checked, 2);
    let critical: Vec<_> = analysis
        .findings
        .iter()
        .filter(|f| f.risk_level == ConfusionRiskLevel::Critical)
        .collect();
    assert_eq!(critical.len(), 1);
    assert_eq!(critical[0].package_name, "my-internal-auth");
}

#[test]
fn check_cargo_lockfile_confusion() {
    let content = r#"
[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "internal-tool"
version = "0.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
    let checker = MockRegistryChecker::new().add_response(
        "serde",
        Ecosystem::Cargo,
        RegistryStatus::ExistsPublic {
            public_version: "1.0.200".to_string(),
        },
    );
    let analysis = check_lockfile_confusion("Cargo.lock", content, &checker).unwrap();
    assert!(analysis.total_packages_checked >= 1);
}

#[test]
fn check_requirements_lockfile_confusion() {
    let content = "flask==2.3.0\ninternal-utils==1.0.0\nrequests>=2.28.0\n";
    let checker = MockRegistryChecker::new()
        .add_response(
            "flask",
            Ecosystem::PyPi,
            RegistryStatus::ExistsPublic {
                public_version: "2.3.0".to_string(),
            },
        )
        .add_response(
            "requests",
            Ecosystem::PyPi,
            RegistryStatus::ExistsPublic {
                public_version: "2.31.0".to_string(),
            },
        );
    let analysis = check_lockfile_confusion("requirements.txt", content, &checker).unwrap();
    assert_eq!(analysis.total_packages_checked, 3);
    let critical_findings: Vec<_> = analysis
        .findings
        .iter()
        .filter(|f| f.risk_level == ConfusionRiskLevel::Critical)
        .collect();
    assert_eq!(critical_findings.len(), 1);
    assert_eq!(critical_findings[0].package_name, "internal-utils");
}

#[test]
fn check_gemfile_lockfile_confusion() {
    let content = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n    corp-auth (1.0.0)\n\nPLATFORMS\n  ruby\n";
    let checker = MockRegistryChecker::new().add_response(
        "rails",
        Ecosystem::RubyGems,
        RegistryStatus::ExistsPublic {
            public_version: "7.0.0".to_string(),
        },
    );
    let analysis = check_lockfile_confusion("Gemfile.lock", content, &checker).unwrap();
    assert!(analysis.total_packages_checked >= 2);
    let critical: Vec<_> = analysis
        .findings
        .iter()
        .filter(|f| f.risk_level == ConfusionRiskLevel::Critical)
        .collect();
    assert!(critical.len() >= 1);
}

#[test]
fn check_gosum_lockfile_confusion() {
    let content = "github.com/gin-gonic/gin v1.9.0 h1:abc=\nmycompany/auth v1.0.0 h1:xyz=\n";
    let checker = MockRegistryChecker::new().add_response(
        "github.com/gin-gonic/gin",
        Ecosystem::Go,
        RegistryStatus::ExistsPublic {
            public_version: "1.9.0".to_string(),
        },
    );
    let analysis = check_lockfile_confusion("go.sum", content, &checker).unwrap();
    assert_eq!(analysis.total_packages_checked, 2);
}

// ── filter_by_risk ──────────────────────────────────────────────────────────

#[test]
fn filter_by_risk_returns_only_matching() {
    let deps = vec![
        dep("safe", "1.0.0", Ecosystem::Npm),
        dep("danger", "1.0.0", Ecosystem::Cargo),
        dep("risky", "1.0.0", Ecosystem::PyPi),
    ];
    let checker = MockRegistryChecker::new()
        .add_response(
            "safe",
            Ecosystem::Npm,
            RegistryStatus::ExistsPublic {
                public_version: "1.0.0".to_string(),
            },
        )
        .add_response(
            "risky",
            Ecosystem::PyPi,
            RegistryStatus::ExistsPublic {
                public_version: "9.0.0".to_string(),
            },
        );
    let analysis = analyze_confusion(&deps, &checker);
    let high_plus = filter_by_risk(&analysis, ConfusionRiskLevel::High);
    assert_eq!(high_plus.len(), 2);
    let critical_only = filter_by_risk(&analysis, ConfusionRiskLevel::Critical);
    assert_eq!(critical_only.len(), 1);
}

// ── summarize ───────────────────────────────────────────────────────────────

#[test]
fn summarize_includes_counts_and_findings() {
    let deps = vec![
        dep("internal-lib", "1.0.0", Ecosystem::Npm),
        dep("express", "4.18.0", Ecosystem::Npm),
    ];
    let checker = MockRegistryChecker::new().add_response(
        "express",
        Ecosystem::Npm,
        RegistryStatus::ExistsPublic {
            public_version: "4.18.0".to_string(),
        },
    );
    let analysis = analyze_confusion(&deps, &checker);
    let summary = summarize(&analysis);
    assert!(summary.contains("2 packages analyzed"));
    assert!(summary.contains("1 critical"));
    assert!(summary.contains("internal-lib"));
}

// ── Edge case: Python internal naming patterns ──────────────────────────────

#[test]
fn python_company_prefix_detected_as_internal() {
    let d = dep("company-ml-pipeline", "0.5.0", Ecosystem::PyPi);
    let checker = MockRegistryChecker::new();
    let analysis = analyze_confusion(&[d], &checker);
    assert_eq!(
        analysis.findings[0].risk_level,
        ConfusionRiskLevel::Critical
    );
}

#[test]
fn python_underscore_internal_detected() {
    let d = dep("data_internal_tools", "1.0.0", Ecosystem::PyPi);
    let checker = MockRegistryChecker::new();
    let analysis = analyze_confusion(&[d], &checker);
    assert_eq!(
        analysis.findings[0].risk_level,
        ConfusionRiskLevel::Critical
    );
}

// ── ConfusionRiskLevel ordering ─────────────────────────────────────────────

#[test]
fn risk_level_ordering() {
    assert!(ConfusionRiskLevel::Critical > ConfusionRiskLevel::High);
    assert!(ConfusionRiskLevel::High > ConfusionRiskLevel::Medium);
    assert!(ConfusionRiskLevel::Medium > ConfusionRiskLevel::Low);
}

// ── Display impls ───────────────────────────────────────────────────────────

#[test]
fn risk_level_display() {
    assert_eq!(ConfusionRiskLevel::Low.to_string(), "low");
    assert_eq!(ConfusionRiskLevel::Medium.to_string(), "medium");
    assert_eq!(ConfusionRiskLevel::High.to_string(), "high");
    assert_eq!(ConfusionRiskLevel::Critical.to_string(), "critical");
}
