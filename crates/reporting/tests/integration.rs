use aegis_protocol::finding::VulnerabilityClass;
use aegis_reporting::certificate_serializer::{
    Certificate, ChainCertificate, ChainStep, ConfigCertificate, DependencyCertificate,
    EvasionCertificate, FuzzingCertificate, SourceSinkLocation, TaintCertificate, TaintPathStep,
    certificate_hash, deserialize_certificate, serialize_certificate,
};
use aegis_reporting::narrative::{
    NarrativeContext, generate_actionable_narrative, generate_executive_summary,
    generate_finding_narrative,
};
use aegis_reporting::report_format::{DefenseSummary, ReportFormat, ReportMetadata, format_report};
use aegis_reporting::risk_scorer::{RiskInput, compute_risk_score};
use aegis_reporting::sarif_emitter::{
    SarifFinding, SarifLevel, attack_technique_for, cwe_for, emit_sarif, sarif_to_json,
};

fn all_vuln_classes() -> Vec<VulnerabilityClass> {
    vec![
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
    ]
}

fn make_risk_input(vc: VulnerabilityClass) -> RiskInput {
    RiskInput {
        vulnerability_class: vc,
        cvss_exploitability: 7.0,
        is_authenticated: false,
        is_rate_limited: false,
        has_waf: false,
        attack_path_count: 5,
        reachable_critical_assets: 3,
        asset_pii_weight: 1.0,
        confidence: 0.8,
    }
}

fn make_sarif_finding(rule_id: &str, vc: VulnerabilityClass) -> SarifFinding {
    SarifFinding {
        rule_id: rule_id.to_string(),
        rule_description: format!("{vc} finding"),
        level: SarifLevel::Error,
        message: format!("Detected {vc}"),
        uri: Some("http://localhost:3000/api/test".to_string()),
        logical_location_name: Some("testHandler".to_string()),
        logical_location_kind: Some("function".to_string()),
        severity: 8.0,
        confidence: 0.9,
        composite_score: 75.0,
        vulnerability_class: Some(vc),
        related_locations: Vec::new(),
        defense_context: None,
        evidence_level: Some("Confirmed".to_string()),
        cve_id: None,
        mitigation_rank: None,
        confidence_score: Some(0.9),
        suppression_kind: None,
        suppression_message: None,
        endpoint: None,
        http_method: None,
        parameter_name: None,
    }
}

#[test]
fn risk_score_all_16_vuln_classes() {
    for vc in all_vuln_classes() {
        let input = make_risk_input(vc);
        let score = compute_risk_score(&input);
        assert!(
            score.composite >= 0.0 && score.composite <= 100.0,
            "{vc}: composite score {:.2} out of [0, 100] range",
            score.composite
        );
        assert!(
            score.exploitability >= 0.0 && score.exploitability <= 10.0,
            "{vc}: exploitability {:.2} out of [0, 10] range",
            score.exploitability
        );
    }
}

#[test]
fn risk_score_defense_aware_reduces_score() {
    let vc = VulnerabilityClass::SqlInjection;
    let no_defense = make_risk_input(vc);
    let with_waf = RiskInput {
        has_waf: true,
        ..make_risk_input(vc)
    };

    let score_no_defense = compute_risk_score(&no_defense);
    let score_with_waf = compute_risk_score(&with_waf);

    assert!(
        score_with_waf.composite < score_no_defense.composite,
        "WAF present should reduce composite: {:.2} should be < {:.2}",
        score_with_waf.composite,
        score_no_defense.composite
    );
}

#[test]
fn risk_score_confidence_weighted() {
    let low_confidence = RiskInput {
        confidence: 0.3,
        ..make_risk_input(VulnerabilityClass::SqlInjection)
    };
    let high_confidence = RiskInput {
        confidence: 0.95,
        ..make_risk_input(VulnerabilityClass::SqlInjection)
    };

    let low_score = compute_risk_score(&low_confidence);
    let high_score = compute_risk_score(&high_confidence);

    assert!(
        high_score.composite > low_score.composite,
        "higher confidence should yield higher score: {:.2} should be > {:.2}",
        high_score.composite,
        low_score.composite
    );
}

#[test]
fn sarif_emission_valid_json() {
    let findings = vec![make_sarif_finding(
        "SQLI-001",
        VulnerabilityClass::SqlInjection,
    )];
    let log = emit_sarif(&findings, "0.1.0");
    let json_str = sarif_to_json(&log).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    assert!(parsed.get("$schema").is_some(), "SARIF must have $schema");
    assert_eq!(parsed["version"].as_str().unwrap(), "2.1.0");
    assert!(parsed.get("runs").is_some(), "SARIF must have runs array");
    assert!(!parsed["runs"].as_array().unwrap().is_empty());
}

#[test]
fn sarif_has_correct_cwe_for_sqli() {
    let cwe = cwe_for(&VulnerabilityClass::SqlInjection);
    assert_eq!(cwe, "CWE-89");
}

#[test]
fn sarif_has_correct_cwe_for_xss() {
    let cwe = cwe_for(&VulnerabilityClass::CrossSiteScripting);
    assert_eq!(cwe, "CWE-79");
}

#[test]
fn sarif_has_attack_technique() {
    let technique = attack_technique_for(&VulnerabilityClass::SqlInjection);
    assert!(!technique.is_empty(), "ATT&CK technique should be present");
    assert!(
        technique.starts_with('T'),
        "technique ID should start with 'T'"
    );
}

#[test]
fn sarif_has_remediation() {
    let findings = vec![make_sarif_finding(
        "SQLI-001",
        VulnerabilityClass::SqlInjection,
    )];
    let log = emit_sarif(&findings, "0.1.0");
    let json_str = sarif_to_json(&log).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    let results = parsed["runs"][0]["results"].as_array().unwrap();
    let result = &results[0];
    let fixes = result.get("fixes").unwrap().as_array().unwrap();
    assert!(!fixes.is_empty(), "SARIF result should have fixes array");
}

#[test]
fn sarif_diff_mode_only_new() {
    let old_finding = make_sarif_finding("OLD-001", VulnerabilityClass::PathTraversal);

    let old_log = emit_sarif(&[old_finding], "0.1.0");
    let old_json: serde_json::Value = serde_json::to_value(&old_log).unwrap();
    let old_rule_ids: std::collections::HashSet<String> = old_json["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["ruleId"].as_str().map(String::from))
        .collect();

    let combined_findings = vec![
        make_sarif_finding("OLD-001", VulnerabilityClass::PathTraversal),
        make_sarif_finding("NEW-001", VulnerabilityClass::SqlInjection),
    ];
    let combined_log = emit_sarif(&combined_findings, "0.1.0");
    let combined_json: serde_json::Value = serde_json::to_value(&combined_log).unwrap();
    let all_results = combined_json["runs"][0]["results"].as_array().unwrap();

    let new_only: Vec<&serde_json::Value> = all_results
        .iter()
        .filter(|r| {
            let rule_id = r["ruleId"].as_str().unwrap_or_default();
            !old_rule_ids.contains(rule_id)
        })
        .collect();

    assert_eq!(new_only.len(), 1);
    assert_eq!(new_only[0]["ruleId"].as_str().unwrap(), "NEW-001");
}

#[test]
fn narrative_generates_for_all_classes() {
    for vc in all_vuln_classes() {
        let narrative = generate_finding_narrative("TEST-001", Some(&format!("{vc}")), 50.0, None);
        assert!(!narrative.is_empty(), "{vc}: narrative should not be empty");
        assert!(
            narrative.contains("TEST-001"),
            "{vc}: narrative should reference the rule ID"
        );
    }
}

#[test]
fn narrative_includes_remediation_advice() {
    let ctx = NarrativeContext {
        endpoint: "/api/users".to_string(),
        method: "POST".to_string(),
        parameter: "username".to_string(),
        vulnerability_class: "SQL Injection".to_string(),
        severity: 8.5,
        confidence: 0.9,
        is_authenticated: false,
        accesses_pii: true,
        defense_context: None,
        calibration_note: None,
    };

    let narrative = generate_actionable_narrative(&ctx);

    assert!(
        narrative.how_to_fix.contains("parameterized"),
        "SQL Injection remediation should mention parameterized queries, got: {}",
        narrative.how_to_fix
    );
}

#[test]
fn executive_summary_aggregates() {
    let defenses = vec!["WAF".to_string(), "Rate Limiting".to_string()];
    let summary = generate_executive_summary(10, 3, 5, &defenses);

    assert!(
        summary.contains("10 findings"),
        "should mention total findings"
    );
    assert!(
        summary.contains("3 critical"),
        "should mention critical count"
    );
    assert!(summary.contains("5 high"), "should mention high count");
    assert!(summary.contains("WAF"), "should mention detected defenses");
}

#[test]
fn certificate_serialize_deserialize_all_types() {
    let certificates = vec![
        Certificate::Fuzzing(FuzzingCertificate {
            request_method: "GET".to_string(),
            request_url: "http://localhost:3000/test".to_string(),
            request_headers: vec![("Host".to_string(), "localhost".to_string())],
            request_body: Vec::new(),
            response_status: 200,
            response_body: b"ok".to_vec(),
            anomaly_type: "status_code".to_string(),
            statistical_significance: 0.99,
        }),
        Certificate::Taint(TaintCertificate {
            source_location: SourceSinkLocation {
                file: "app.rs".to_string(),
                line: 10,
                function: "handle_request".to_string(),
                variable: "user_input".to_string(),
            },
            sink_location: SourceSinkLocation {
                file: "db.rs".to_string(),
                line: 42,
                function: "execute_query".to_string(),
                variable: "query".to_string(),
            },
            path_steps: vec![TaintPathStep {
                file: "app.rs".to_string(),
                line: 15,
                function: "process".to_string(),
                variable: "data".to_string(),
                operation: "concat".to_string(),
            }],
        }),
        Certificate::Chain(ChainCertificate {
            steps: vec![ChainStep {
                vulnerability_id: 1,
                description: "sqli leading to data exfil".to_string(),
                transition_condition: "authenticated".to_string(),
            }],
        }),
        Certificate::Config(ConfigCertificate {
            config_key: "debug_mode".to_string(),
            current_value: "true".to_string(),
            expected_value: "false".to_string(),
        }),
        Certificate::Dependency(DependencyCertificate {
            package_name: "serde".to_string(),
            installed_version: "1.0.0".to_string(),
            vulnerable_range: "<1.0.1".to_string(),
            cve_id: "CVE-2024-0001".to_string(),
        }),
        Certificate::Evasion(EvasionCertificate {
            original_payload: "' OR 1=1 --".to_string(),
            evasion_payload: "'%20OR%201%3D1%20--".to_string(),
            defense_vendor: "ModSecurity".to_string(),
            evasion_technique: "url_encoding".to_string(),
            block_response_status: 403,
            bypass_response_status: 200,
            anomaly_detected: true,
        }),
    ];

    for cert in &certificates {
        let serialized = serialize_certificate(cert).unwrap();
        let deserialized = deserialize_certificate(&serialized).unwrap();
        let reserialized = serialize_certificate(&deserialized).unwrap();
        assert_eq!(
            serialized, reserialized,
            "CBOR roundtrip should produce identical bytes"
        );
    }
}

#[test]
fn certificate_hash_deterministic() {
    let cert = Certificate::Config(ConfigCertificate {
        config_key: "test".to_string(),
        current_value: "a".to_string(),
        expected_value: "b".to_string(),
    });
    let data = serialize_certificate(&cert).unwrap();

    let hash1 = certificate_hash(&data);
    let hash2 = certificate_hash(&data);

    assert_eq!(hash1, hash2, "SHA3-256 hash must be deterministic");
}

#[test]
fn report_format_developer_sarif() {
    let findings = vec![make_sarif_finding(
        "DEV-001",
        VulnerabilityClass::CrossSiteScripting,
    )];
    let output = format_report(&findings, ReportFormat::Developer, "0.1.0", None, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

    assert_eq!(parsed["version"].as_str().unwrap(), "2.1.0");
    assert!(parsed.get("runs").is_some());
}

#[test]
fn report_format_security_enriched() {
    let findings = vec![make_sarif_finding(
        "SEC-001",
        VulnerabilityClass::CommandInjection,
    )];
    let output = format_report(&findings, ReportFormat::Security, "0.1.0", None, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

    let run_props = &parsed["runs"][0]["properties"];
    assert!(
        run_props.get("securityAnalysis").is_some(),
        "Security format should have securityAnalysis properties"
    );
    let attack_chains = run_props["securityAnalysis"]["attackChains"]
        .as_array()
        .unwrap();
    assert!(
        !attack_chains.is_empty(),
        "should have attack chain entries"
    );
}

#[test]
fn report_format_executive_summary() {
    let findings = vec![
        make_sarif_finding("EXEC-001", VulnerabilityClass::SqlInjection),
        make_sarif_finding("EXEC-002", VulnerabilityClass::CrossSiteScripting),
    ];
    let metadata = ReportMetadata {
        target_url: "http://localhost:3000".to_string(),
        total_duration_secs: 120.5,
        phases_completed: 4,
    };
    let defense = DefenseSummary {
        has_waf: true,
        waf_vendor: Some("ModSecurity".to_string()),
        has_rate_limiting: true,
        has_bot_detection: false,
    };
    let output = format_report(
        &findings,
        ReportFormat::Executive,
        "0.1.0",
        Some(&metadata),
        Some(&defense),
    )
    .unwrap();

    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

    assert_eq!(parsed["total_findings"].as_u64().unwrap(), 2);
    assert!(parsed.get("severity_counts").is_some());
    assert!(parsed.get("risk_summary").is_some());
    assert!(parsed.get("top_remediation_priorities").is_some());
    assert!(parsed.get("defense_posture_summary").is_some());
    assert!(parsed.get("scan_metadata").is_some());
    assert_eq!(
        parsed["scan_metadata"]["target"].as_str().unwrap(),
        "http://localhost:3000"
    );
}
