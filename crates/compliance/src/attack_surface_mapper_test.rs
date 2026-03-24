use std::collections::HashSet;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::request::ParameterLocation;

use crate::attack_surface_mapper::*;

fn make_scan_state_20_findings() -> ScanState {
    let endpoints = vec![
        "/api/users",
        "/api/login",
        "/api/search",
        "/api/upload",
        "/api/admin",
    ];
    let methods = vec!["GET", "POST", "GET", "POST", "GET"];
    let vuln_classes = vec![
        VulnerabilityClass::SqlInjection,
        VulnerabilityClass::CrossSiteScripting,
        VulnerabilityClass::CommandInjection,
        VulnerabilityClass::PathTraversal,
        VulnerabilityClass::BrokenAuthentication,
        VulnerabilityClass::SecurityMisconfiguration,
        VulnerabilityClass::SensitiveDataExposure,
        VulnerabilityClass::InsecureDeserialization,
        VulnerabilityClass::HeaderInjection,
        VulnerabilityClass::OpenRedirect,
        VulnerabilityClass::CrlfInjection,
        VulnerabilityClass::InsufficientInputValidation,
        VulnerabilityClass::NoSqlInjection,
        VulnerabilityClass::MissingSecurityHeader,
        VulnerabilityClass::SqlInjection,
        VulnerabilityClass::CrossSiteScripting,
        VulnerabilityClass::CommandInjection,
        VulnerabilityClass::PathTraversal,
        VulnerabilityClass::SecurityMisconfiguration,
        VulnerabilityClass::HeaderInjection,
    ];

    let mut findings = Vec::new();
    for (i, vc) in vuln_classes.iter().enumerate() {
        let ep_idx = i % endpoints.len();
        findings.push(ScanFinding {
            endpoint: endpoints[ep_idx].to_string(),
            method: methods[ep_idx].to_string(),
            vulnerability_class: *vc,
            parameter: Some(format!("param{}", i)),
        });
    }

    let known_endpoints: Vec<KnownEndpoint> = endpoints
        .iter()
        .zip(methods.iter())
        .map(|(ep, m)| KnownEndpoint {
            endpoint: ep.to_string(),
            method: m.to_string(),
            parameters: vec!["q".into(), "id".into()],
        })
        .collect();

    ScanState {
        findings,
        known_endpoints,
    }
}

fn make_minimal_scan_state() -> ScanState {
    ScanState {
        findings: vec![ScanFinding {
            endpoint: "/api/users".into(),
            method: "GET".into(),
            vulnerability_class: VulnerabilityClass::SqlInjection,
            parameter: Some("id".into()),
        }],
        known_endpoints: vec![KnownEndpoint {
            endpoint: "/api/users".into(),
            method: "GET".into(),
            parameters: vec!["id".into()],
        }],
    }
}

fn make_empty_scan_state() -> ScanState {
    ScanState {
        findings: vec![],
        known_endpoints: vec![KnownEndpoint {
            endpoint: "/api/test".into(),
            method: "GET".into(),
            parameters: vec!["q".into()],
        }],
    }
}

#[test]
fn identifies_at_least_10_untested_requirements_from_20_findings() {
    let state = make_scan_state_20_findings();
    let analysis = analyze_attack_surface(&state);

    let untested_requirement_ids: HashSet<(&ComplianceFramework, &str)> = analysis
        .coverage_matrix
        .iter()
        .filter(|e| e.untested_classes > 0)
        .map(|e| (&e.framework, e.requirement_id.as_str()))
        .collect();

    assert!(
        untested_requirement_ids.len() >= 10,
        "Expected >=10 untested requirements, got {}",
        untested_requirement_ids.len()
    );
}

#[test]
fn generates_fuzz_targets_for_each_gap() {
    let state = make_scan_state_20_findings();
    let analysis = analyze_attack_surface(&state);

    assert!(
        !analysis.fuzz_targets.is_empty(),
        "Expected fuzz targets for compliance gaps"
    );

    for target in &analysis.fuzz_targets {
        assert!(!target.endpoint.is_empty());
        assert!(!target.method.is_empty());
        assert!(!target.compliance_source.is_empty());
        assert!(target.priority_score > 0.0);
    }
}

#[test]
fn fuzz_targets_are_sorted_by_priority_descending() {
    let state = make_scan_state_20_findings();
    let analysis = analyze_attack_surface(&state);

    for window in analysis.fuzz_targets.windows(2) {
        assert!(
            window[0].priority_score >= window[1].priority_score,
            "Fuzz targets not sorted: {} < {}",
            window[0].priority_score,
            window[1].priority_score,
        );
    }
}

#[test]
fn coverage_matrix_covers_all_three_frameworks() {
    let state = make_scan_state_20_findings();
    let analysis = analyze_attack_surface(&state);
    let by_fw = coverage_by_framework(&analysis);

    assert!(by_fw.contains_key(&ComplianceFramework::OwaspTop10_2021));
    assert!(by_fw.contains_key(&ComplianceFramework::PciDss));
    assert!(by_fw.contains_key(&ComplianceFramework::ApiSecurity2023));
}

#[test]
fn coverage_matrix_has_correct_entry_counts() {
    let state = make_scan_state_20_findings();
    let analysis = analyze_attack_surface(&state);
    let by_fw = coverage_by_framework(&analysis);

    assert_eq!(by_fw[&ComplianceFramework::OwaspTop10_2021].len(), 9);
    assert_eq!(by_fw[&ComplianceFramework::PciDss].len(), 7);
    assert_eq!(by_fw[&ComplianceFramework::ApiSecurity2023].len(), 7);
}

#[test]
fn total_requirements_equals_sum_of_coverage_categories() {
    let state = make_scan_state_20_findings();
    let analysis = analyze_attack_surface(&state);

    let sum = analysis.fully_covered_requirements
        + analysis.partially_covered_requirements
        + analysis.uncovered_requirements;
    assert_eq!(analysis.total_requirements, sum);
}

#[test]
fn empty_scan_state_finds_all_requirements_uncovered() {
    let state = make_empty_scan_state();
    let analysis = analyze_attack_surface(&state);

    assert_eq!(analysis.fully_covered_requirements, 0);
    assert!(analysis.uncovered_requirements > 0);
    assert!(!analysis.fuzz_targets.is_empty());
}

#[test]
fn minimal_scan_state_partially_covers_injection_requirements() {
    let state = make_minimal_scan_state();
    let analysis = analyze_attack_surface(&state);

    let a03 = analysis
        .coverage_matrix
        .iter()
        .find(|e| e.requirement_id == "A03:2021")
        .expect("A03:2021 should be in matrix");

    assert!(a03.tested_classes > 0, "SqlInjection should be tested");
    assert!(
        a03.untested_classes > 0,
        "Other injection classes should be untested"
    );
    assert!(a03.coverage_pct > 0.0);
    assert!(a03.coverage_pct < 100.0);
}

#[test]
fn fuzz_targets_have_no_duplicates() {
    let state = make_scan_state_20_findings();
    let analysis = analyze_attack_surface(&state);

    let mut seen: HashSet<(String, String, VulnerabilityClass)> = HashSet::new();
    for t in &analysis.fuzz_targets {
        let key = (t.endpoint.clone(), t.method.clone(), t.vulnerability_class);
        assert!(seen.insert(key.clone()), "Duplicate fuzz target: {:?}", key);
    }
}

#[test]
fn fuzz_targets_only_contain_untested_classes() {
    let state = make_scan_state_20_findings();
    let tested: HashSet<VulnerabilityClass> = state
        .findings
        .iter()
        .map(|f| f.vulnerability_class)
        .collect();

    let analysis = analyze_attack_surface(&state);

    for target in &analysis.fuzz_targets {
        assert!(
            !tested.contains(&target.vulnerability_class),
            "Fuzz target for already-tested class: {}",
            target.vulnerability_class
        );
    }
}

#[test]
fn coverage_pct_bounds() {
    let state = make_scan_state_20_findings();
    let analysis = analyze_attack_surface(&state);

    for entry in &analysis.coverage_matrix {
        assert!(entry.coverage_pct >= 0.0, "coverage_pct below 0");
        assert!(entry.coverage_pct <= 100.0, "coverage_pct above 100");
    }
}

#[test]
fn coverage_entry_tested_plus_untested_equals_total() {
    let state = make_scan_state_20_findings();
    let analysis = analyze_attack_surface(&state);

    for entry in &analysis.coverage_matrix {
        assert_eq!(
            entry.tested_classes + entry.untested_classes,
            entry.total_classes,
            "Mismatch for {} {}: {} + {} != {}",
            entry.framework,
            entry.requirement_id,
            entry.tested_classes,
            entry.untested_classes,
            entry.total_classes,
        );
    }
}

#[test]
fn all_compliance_requirements_non_empty() {
    let reqs = all_compliance_requirements();
    assert!(!reqs.is_empty());

    for req in &reqs {
        assert!(!req.requirement_id.is_empty());
        assert!(!req.description.is_empty());
        assert!(
            !req.required_vuln_classes.is_empty(),
            "Requirement {} has no vuln classes",
            req.requirement_id
        );
    }
}

#[test]
fn validate_requirement_mappings_passes() {
    let warnings = validate_requirement_mappings();
    assert!(
        warnings.is_empty(),
        "Requirement mapping validation warnings: {:?}",
        warnings
    );
}

#[test]
fn format_coverage_matrix_produces_markdown_table() {
    let state = make_scan_state_20_findings();
    let analysis = analyze_attack_surface(&state);
    let output = format_coverage_matrix(&analysis);

    assert!(output.contains("## Compliance Coverage Matrix"));
    assert!(output.contains("| Framework |"));
    assert!(output.contains("OWASP Top 10 2021"));
    assert!(output.contains("PCI-DSS"));
    assert!(output.contains("API Security 2023"));
    assert!(output.contains("**Summary:**"));
}

#[test]
fn compliance_framework_display() {
    assert_eq!(
        format!("{}", ComplianceFramework::OwaspTop10_2021),
        "OWASP Top 10 2021"
    );
    assert_eq!(format!("{}", ComplianceFramework::PciDss), "PCI-DSS");
    assert_eq!(
        format!("{}", ComplianceFramework::ApiSecurity2023),
        "API Security 2023"
    );
}

#[test]
fn gaps_sorted_by_priority_descending() {
    let state = make_scan_state_20_findings();
    let analysis = analyze_attack_surface(&state);

    for window in analysis.gaps.windows(2) {
        assert!(
            window[0].priority_score >= window[1].priority_score,
            "Gaps not sorted: {} < {}",
            window[0].priority_score,
            window[1].priority_score,
        );
    }
}

#[test]
fn gap_coverage_ratio_in_valid_range() {
    let state = make_scan_state_20_findings();
    let analysis = analyze_attack_surface(&state);

    for gap in &analysis.gaps {
        assert!(gap.coverage_ratio >= 0.0);
        assert!(gap.coverage_ratio <= 1.0);
    }
}

#[test]
fn fuzz_targets_have_default_attempts_and_max() {
    let state = make_minimal_scan_state();
    let analysis = analyze_attack_surface(&state);

    for target in &analysis.fuzz_targets {
        assert_eq!(target.attempts, 0);
        assert_eq!(target.max_attempts, 5);
    }
}

#[test]
fn fuzz_target_compliance_source_includes_framework_and_id() {
    let state = make_minimal_scan_state();
    let analysis = analyze_attack_surface(&state);

    for target in &analysis.fuzz_targets {
        let parts: Vec<&str> = target.compliance_source.splitn(2, ' ').collect();
        assert!(
            parts.len() >= 2,
            "compliance_source should have framework + id, got: {}",
            target.compliance_source
        );
    }
}

#[test]
fn multiple_endpoints_each_get_fuzz_targets() {
    let state = make_scan_state_20_findings();
    let analysis = analyze_attack_surface(&state);

    let unique_endpoints: HashSet<&str> = analysis
        .fuzz_targets
        .iter()
        .map(|t| t.endpoint.as_str())
        .collect();

    assert!(
        unique_endpoints.len() >= 2,
        "Expected fuzz targets spread across multiple endpoints, got {}",
        unique_endpoints.len()
    );
}

#[test]
fn parameter_location_defaults_to_query() {
    let state = make_minimal_scan_state();
    let analysis = analyze_attack_surface(&state);

    for target in &analysis.fuzz_targets {
        assert_eq!(target.parameter_location, ParameterLocation::Query);
    }
}

#[test]
fn coverage_by_framework_groups_correctly() {
    let state = make_scan_state_20_findings();
    let analysis = analyze_attack_surface(&state);
    let grouped = coverage_by_framework(&analysis);

    let total_entries: usize = grouped.values().map(|v| v.len()).sum();
    assert_eq!(total_entries, analysis.coverage_matrix.len());

    for (fw, entries) in &grouped {
        for entry in entries {
            assert_eq!(&entry.framework, fw);
        }
    }
}

#[test]
fn fully_covered_requirement_has_100_pct() {
    let state = make_scan_state_20_findings();
    let analysis = analyze_attack_surface(&state);

    for entry in &analysis.coverage_matrix {
        if entry.untested_classes == 0 {
            assert!(
                (entry.coverage_pct - 100.0).abs() < f64::EPSILON,
                "Fully covered requirement {} should have 100%, got {:.1}%",
                entry.requirement_id,
                entry.coverage_pct,
            );
        }
    }
}

#[test]
fn scan_state_with_all_34_classes_has_full_coverage() {
    let all_classes = vec![
        VulnerabilityClass::SqlInjection,
        VulnerabilityClass::CrossSiteScripting,
        VulnerabilityClass::CommandInjection,
        VulnerabilityClass::PathTraversal,
        VulnerabilityClass::ServerSideRequestForgery,
        VulnerabilityClass::InsecureDeserialization,
        VulnerabilityClass::BrokenAuthentication,
        VulnerabilityClass::BrokenAuthorization,
        VulnerabilityClass::SecurityMisconfiguration,
        VulnerabilityClass::SensitiveDataExposure,
        VulnerabilityClass::ServerSideTemplateInjection,
        VulnerabilityClass::HeaderInjection,
        VulnerabilityClass::OpenRedirect,
        VulnerabilityClass::CrlfInjection,
        VulnerabilityClass::KnownVulnerableDependency,
        VulnerabilityClass::InsufficientInputValidation,
        VulnerabilityClass::NoSqlInjection,
        VulnerabilityClass::XmlExternalEntity,
        VulnerabilityClass::CrossOriginMisconfiguration,
        VulnerabilityClass::MissingSecurityHeader,
        VulnerabilityClass::JwtVulnerability,
        VulnerabilityClass::HttpRequestSmuggling,
        VulnerabilityClass::RaceCondition,
        VulnerabilityClass::SubdomainTakeover,
        VulnerabilityClass::PrototypePollution,
        VulnerabilityClass::GraphQlAbuse,
        VulnerabilityClass::CloudMisconfiguration,
        VulnerabilityClass::Clickjacking,
        VulnerabilityClass::CachePoisoning,
        VulnerabilityClass::HostHeaderInjection,
        VulnerabilityClass::InsecureDirectObjectReference,
        VulnerabilityClass::InformationDisclosure,
        VulnerabilityClass::WeakCryptography,
        VulnerabilityClass::MassAssignment,
    ];

    let findings: Vec<ScanFinding> = all_classes
        .iter()
        .map(|vc| ScanFinding {
            endpoint: "/api/complete".into(),
            method: "POST".into(),
            vulnerability_class: *vc,
            parameter: None,
        })
        .collect();

    let state = ScanState {
        findings,
        known_endpoints: vec![KnownEndpoint {
            endpoint: "/api/complete".into(),
            method: "POST".into(),
            parameters: vec!["input".into()],
        }],
    };

    let analysis = analyze_attack_surface(&state);

    assert_eq!(
        analysis.fully_covered_requirements, analysis.total_requirements,
        "All requirements should be fully covered when all 34 classes are tested"
    );
    assert!(analysis.fuzz_targets.is_empty());
}

#[test]
fn gap_fuzz_target_uses_endpoint_parameter() {
    let state = ScanState {
        findings: vec![],
        known_endpoints: vec![KnownEndpoint {
            endpoint: "/api/special".into(),
            method: "POST".into(),
            parameters: vec!["token".into(), "data".into()],
        }],
    };

    let analysis = analyze_attack_surface(&state);

    for target in &analysis.fuzz_targets {
        if target.endpoint == "/api/special" {
            assert_eq!(target.parameter, "data");
        }
    }
}
