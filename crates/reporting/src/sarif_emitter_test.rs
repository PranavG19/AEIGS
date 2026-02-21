#[cfg(test)]
mod tests {
    use aegis_protocol::finding::VulnerabilityClass;

    use crate::sarif_emitter::{
        RelatedLocation, SarifDefenseContext, SarifFinding, SarifLevel, attack_technique_for,
        cwe_for, emit_sarif, sarif_to_json,
    };

    fn sample_finding() -> SarifFinding {
        SarifFinding {
            rule_id: "CWE-89".to_string(),
            rule_description: "SQL Injection".to_string(),
            level: SarifLevel::Error,
            message: "SQL injection detected in login endpoint".to_string(),
            uri: Some("src/handlers/auth.rs".to_string()),
            logical_location_name: Some("handle_login".to_string()),
            logical_location_kind: Some("function".to_string()),
            severity: 9.0,
            confidence: 0.95,
            composite_score: 85.0,
            vulnerability_class: None,
            related_locations: Vec::new(),
            defense_context: None,
            evidence_level: None,
            cve_id: None,
            mitigation_rank: None,
            confidence_score: None,
            suppression_kind: None,
            suppression_message: None,
            endpoint: None,
            http_method: None,
            parameter_name: None,
        }
    }

    fn finding_with_vuln_class() -> SarifFinding {
        SarifFinding {
            rule_id: "CWE-89".to_string(),
            rule_description: "SQL Injection".to_string(),
            level: SarifLevel::Error,
            message: "SQL injection in query builder".to_string(),
            uri: Some("src/db.rs".to_string()),
            logical_location_name: Some("build_query".to_string()),
            logical_location_kind: Some("function".to_string()),
            severity: 9.5,
            confidence: 0.99,
            composite_score: 92.0,
            vulnerability_class: Some(VulnerabilityClass::SqlInjection),
            related_locations: Vec::new(),
            defense_context: None,
            evidence_level: None,
            cve_id: None,
            mitigation_rank: None,
            confidence_score: None,
            suppression_kind: None,
            suppression_message: None,
            endpoint: None,
            http_method: None,
            parameter_name: None,
        }
    }

    fn finding_with_related_locations() -> SarifFinding {
        SarifFinding {
            rule_id: "CWE-79".to_string(),
            rule_description: "Cross-Site Scripting".to_string(),
            level: SarifLevel::Warning,
            message: "Reflected XSS in template".to_string(),
            uri: Some("src/views/profile.rs".to_string()),
            logical_location_name: Some("render_profile".to_string()),
            logical_location_kind: None,
            severity: 7.0,
            confidence: 0.85,
            composite_score: 60.0,
            vulnerability_class: Some(VulnerabilityClass::CrossSiteScripting),
            related_locations: vec![
                RelatedLocation {
                    uri: Some("src/routes/user.rs".to_string()),
                    message: "User input source".to_string(),
                },
                RelatedLocation {
                    uri: None,
                    message: "Template rendering sink".to_string(),
                },
            ],
            defense_context: None,
            evidence_level: None,
            cve_id: None,
            mitigation_rank: None,
            confidence_score: None,
            suppression_kind: None,
            suppression_message: None,
            endpoint: None,
            http_method: None,
            parameter_name: None,
        }
    }

    #[test]
    fn sarif_version_is_2_1() {
        let report = emit_sarif(&[sample_finding()], "0.1.0");
        assert_eq!(report.version, "2.1.0");
    }

    #[test]
    fn sarif_has_one_run() {
        let report = emit_sarif(&[sample_finding()], "0.1.0");
        assert_eq!(report.runs.len(), 1);
    }

    #[test]
    fn sarif_tool_name_is_aegis() {
        let report = emit_sarif(&[sample_finding()], "0.1.0");
        assert_eq!(report.runs[0].tool.driver.name, "AEGIS");
    }

    #[test]
    fn sarif_tool_version_matches() {
        let report = emit_sarif(&[sample_finding()], "1.2.3");
        assert_eq!(report.runs[0].tool.driver.version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn sarif_result_count_matches_findings() {
        let findings = vec![sample_finding(), sample_finding()];
        let report = emit_sarif(&findings, "0.1.0");
        assert_eq!(report.runs[0].results.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn sarif_result_has_correct_rule_id() {
        let report = emit_sarif(&[sample_finding()], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        assert_eq!(results[0].rule_id.as_deref(), Some("CWE-89"));
    }

    #[test]
    fn sarif_result_level_is_error() {
        let report = emit_sarif(&[sample_finding()], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        assert_eq!(results[0].level, Some(sarif_rust::types::Level::Error));
    }

    #[test]
    fn sarif_rules_deduped() {
        let findings = vec![sample_finding(), sample_finding()];
        let report = emit_sarif(&findings, "0.1.0");
        assert_eq!(report.runs[0].tool.driver.rules.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn sarif_multiple_different_rules() {
        let mut xss = sample_finding();
        xss.rule_id = "CWE-79".to_string();
        xss.rule_description = "Cross-Site Scripting".to_string();

        let report = emit_sarif(&[sample_finding(), xss], "0.1.0");
        assert_eq!(report.runs[0].tool.driver.rules.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn sarif_physical_location_present() {
        let report = emit_sarif(&[sample_finding()], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let locs = results[0].locations.as_ref().unwrap();
        let phys = locs[0].physical_location.as_ref().unwrap();
        assert_eq!(
            phys.artifact_location.as_ref().unwrap().uri.as_deref(),
            Some("src/handlers/auth.rs")
        );
    }

    #[test]
    fn sarif_logical_location_present() {
        let report = emit_sarif(&[sample_finding()], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let locs = results[0].locations.as_ref().unwrap();
        let logical = locs[0].logical_locations.as_ref().unwrap();
        assert_eq!(logical[0].name.as_deref(), Some("handle_login"));
        assert_eq!(logical[0].kind.as_deref(), Some("function"));
    }

    #[test]
    fn sarif_no_location_when_uri_and_logical_absent() {
        let mut finding = sample_finding();
        finding.uri = None;
        finding.logical_location_name = None;

        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        assert!(results[0].locations.is_none());
    }

    #[test]
    fn sarif_properties_preserved() {
        let report = emit_sarif(&[sample_finding()], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let props = results[0].properties.as_ref().unwrap();
        assert_eq!(props["severity"], serde_json::json!(9.0));
        assert_eq!(props["confidence"], serde_json::json!(0.95));
        assert_eq!(props["composite_score"], serde_json::json!(85.0));
    }

    #[test]
    fn sarif_serializes_to_valid_json() {
        let report = emit_sarif(&[sample_finding()], "0.1.0");
        let json = sarif_to_json(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
        assert!(parsed["$schema"].as_str().unwrap().contains("sarif"));
    }

    #[test]
    fn sarif_empty_findings() {
        let report = emit_sarif(&[], "0.1.0");
        assert!(report.runs[0].results.as_ref().unwrap().is_empty());
        assert!(report.runs[0].tool.driver.rules.is_none());
    }

    #[test]
    fn sarif_level_variants() {
        assert_eq!(SarifLevel::Error.as_str(), "error");
        assert_eq!(SarifLevel::Warning.as_str(), "warning");
        assert_eq!(SarifLevel::Note.as_str(), "note");
        assert_eq!(SarifLevel::None.as_str(), "none");
    }

    #[test]
    fn sarif_default_logical_location_kind() {
        let mut finding = sample_finding();
        finding.logical_location_kind = None;

        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let locs = results[0].locations.as_ref().unwrap();
        let logical = locs[0].logical_locations.as_ref().unwrap();
        assert_eq!(logical[0].kind.as_deref(), Some("function"));
    }

    #[test]
    fn cwe_for_all_vulnerability_classes() {
        assert_eq!(cwe_for(&VulnerabilityClass::SqlInjection), "CWE-89");
        assert_eq!(cwe_for(&VulnerabilityClass::CrossSiteScripting), "CWE-79");
        assert_eq!(cwe_for(&VulnerabilityClass::CommandInjection), "CWE-78");
        assert_eq!(cwe_for(&VulnerabilityClass::PathTraversal), "CWE-22");
        assert_eq!(
            cwe_for(&VulnerabilityClass::ServerSideRequestForgery),
            "CWE-918"
        );
        assert_eq!(
            cwe_for(&VulnerabilityClass::InsecureDeserialization),
            "CWE-502"
        );
        assert_eq!(
            cwe_for(&VulnerabilityClass::BrokenAuthentication),
            "CWE-287"
        );
        assert_eq!(cwe_for(&VulnerabilityClass::BrokenAuthorization), "CWE-863");
        assert_eq!(
            cwe_for(&VulnerabilityClass::SecurityMisconfiguration),
            "CWE-16"
        );
        assert_eq!(
            cwe_for(&VulnerabilityClass::SensitiveDataExposure),
            "CWE-200"
        );
        assert_eq!(
            cwe_for(&VulnerabilityClass::ServerSideTemplateInjection),
            "CWE-1336"
        );
        assert_eq!(cwe_for(&VulnerabilityClass::HeaderInjection), "CWE-113");
        assert_eq!(cwe_for(&VulnerabilityClass::OpenRedirect), "CWE-601");
        assert_eq!(cwe_for(&VulnerabilityClass::CrlfInjection), "CWE-93");
        assert_eq!(
            cwe_for(&VulnerabilityClass::KnownVulnerableDependency),
            "CWE-1395"
        );
        assert_eq!(
            cwe_for(&VulnerabilityClass::InsufficientInputValidation),
            "CWE-20"
        );
    }

    #[test]
    fn sarif_taxa_present_when_vulnerability_class_set() {
        let finding = finding_with_vuln_class();
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let taxa = results[0].taxa.as_ref().unwrap();
        assert_eq!(taxa.len(), 2);
        assert_eq!(taxa[0].id.as_deref(), Some("CWE-89"));
        let tc_ref = taxa[0].tool_component.as_ref().unwrap();
        assert_eq!(tc_ref.name.as_deref(), Some("CWE"));
        assert_eq!(tc_ref.index, Some(0));
        assert_eq!(taxa[1].id.as_deref(), Some("T1190"));
        let attack_ref = taxa[1].tool_component.as_ref().unwrap();
        assert_eq!(attack_ref.name.as_deref(), Some("MITRE ATT&CK"));
        assert_eq!(attack_ref.index, Some(1));
    }

    #[test]
    fn sarif_taxa_absent_when_vulnerability_class_none() {
        let finding = sample_finding();
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        assert!(results[0].taxa.is_none());
    }

    #[test]
    fn sarif_fixes_present_when_vulnerability_class_set() {
        let finding = finding_with_vuln_class();
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let fixes = results[0].fixes.as_ref().unwrap();
        assert_eq!(fixes.len(), 1);
        let desc = fixes[0].description.as_ref().unwrap();
        assert!(
            desc.text
                .as_deref()
                .unwrap()
                .contains("parameterized queries")
        );
    }

    #[test]
    fn sarif_fixes_absent_when_vulnerability_class_none() {
        let finding = sample_finding();
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        assert!(results[0].fixes.is_none());
    }

    #[test]
    fn sarif_related_locations_present() {
        let finding = finding_with_related_locations();
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let related = results[0].related_locations.as_ref().unwrap();
        assert_eq!(related.len(), 2);
        assert_eq!(related[0].id, Some(0));
        let phys = related[0].physical_location.as_ref().unwrap();
        assert_eq!(
            phys.artifact_location.as_ref().unwrap().uri.as_deref(),
            Some("src/routes/user.rs")
        );
        assert_eq!(
            related[0].message.as_ref().unwrap().text.as_deref(),
            Some("User input source")
        );
        assert!(related[1].physical_location.is_none());
        assert_eq!(
            related[1].message.as_ref().unwrap().text.as_deref(),
            Some("Template rendering sink")
        );
    }

    #[test]
    fn sarif_related_locations_absent_when_empty() {
        let finding = sample_finding();
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        assert!(results[0].related_locations.is_none());
    }

    #[test]
    fn sarif_cwe_taxonomy_in_run() {
        let report = emit_sarif(&[sample_finding()], "0.1.0");
        let taxonomies = report.runs[0].taxonomies.as_ref().unwrap();
        assert_eq!(taxonomies.len(), 2);
        assert_eq!(taxonomies[0].name, "CWE");
        assert_eq!(taxonomies[0].version.as_deref(), Some("4.13"));
        assert_eq!(taxonomies[0].organization.as_deref(), Some("MITRE"));
    }

    #[test]
    fn sarif_rule_help_uri_set_with_vuln_class() {
        let finding = finding_with_vuln_class();
        let report = emit_sarif(&[finding], "0.1.0");
        let rules = report.runs[0].tool.driver.rules.as_ref().unwrap();
        assert!(
            rules[0]
                .help_uri
                .as_ref()
                .unwrap()
                .contains("cwe.mitre.org/data/definitions/89")
        );
    }

    #[test]
    fn sarif_rule_help_uri_absent_without_vuln_class() {
        let finding = sample_finding();
        let report = emit_sarif(&[finding], "0.1.0");
        let rules = report.runs[0].tool.driver.rules.as_ref().unwrap();
        assert!(rules[0].help_uri.is_none());
    }

    #[test]
    fn sarif_level_to_sarif_warning() {
        let mut finding = sample_finding();
        finding.level = SarifLevel::Warning;
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        assert_eq!(results[0].level, Some(sarif_rust::types::Level::Warning));
    }

    #[test]
    fn sarif_level_to_sarif_note() {
        let mut finding = sample_finding();
        finding.level = SarifLevel::Note;
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        assert_eq!(results[0].level, Some(sarif_rust::types::Level::Note));
    }

    #[test]
    fn sarif_level_to_sarif_none() {
        let mut finding = sample_finding();
        finding.level = SarifLevel::None;
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        assert_eq!(results[0].level, Some(sarif_rust::types::Level::None));
    }

    #[test]
    fn sarif_fixes_remediation_for_all_classes() {
        let classes = [
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
        ];
        for class in &classes {
            let mut finding = sample_finding();
            finding.vulnerability_class = Some(*class);
            let report = emit_sarif(&[finding], "0.1.0");
            let results = report.runs[0].results.as_ref().unwrap();
            let fixes = results[0].fixes.as_ref().unwrap();
            assert!(fixes[0].description.as_ref().unwrap().text.is_some());
        }
    }

    #[test]
    fn sarif_rule_default_configuration_levels() {
        let levels = [
            SarifLevel::Error,
            SarifLevel::Warning,
            SarifLevel::Note,
            SarifLevel::None,
        ];
        for level in &levels {
            let mut finding = sample_finding();
            finding.level = *level;
            finding.rule_id = format!("rule-{}", level.as_str());
            let report = emit_sarif(&[finding], "0.1.0");
            let rules = report.runs[0].tool.driver.rules.as_ref().unwrap();
            assert!(rules[0].default_configuration.is_some());
        }
    }

    #[test]
    fn sarif_physical_only_location() {
        let mut finding = sample_finding();
        finding.logical_location_name = None;
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let locs = results[0].locations.as_ref().unwrap();
        assert!(locs[0].physical_location.is_some());
        assert!(locs[0].logical_locations.is_none());
    }

    #[test]
    fn sarif_logical_only_location() {
        let mut finding = sample_finding();
        finding.uri = None;
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let locs = results[0].locations.as_ref().unwrap();
        assert!(locs[0].physical_location.is_none());
        assert!(locs[0].logical_locations.is_some());
    }

    fn finding_with_defense() -> SarifFinding {
        SarifFinding {
            rule_id: "CWE-89".to_string(),
            rule_description: "SQL Injection".to_string(),
            level: SarifLevel::Error,
            message: "SQL injection bypassed WAF".to_string(),
            uri: Some("src/handlers/auth.rs".to_string()),
            logical_location_name: Some("handle_login".to_string()),
            logical_location_kind: Some("function".to_string()),
            severity: 9.0,
            confidence: 0.95,
            composite_score: 85.0,
            vulnerability_class: None,
            related_locations: Vec::new(),
            defense_context: Some(SarifDefenseContext {
                waf_vendor: Some("Cloudflare".to_string()),
                exploitable_despite_waf: true,
                evasion_technique: Some("chunked encoding".to_string()),
                defenses_detected: vec!["WAF".to_string(), "rate-limiter".to_string()],
                evasion_success_rate: Some(0.75),
                stealth_mode_used: true,
            }),
            evidence_level: None,
            cve_id: None,
            mitigation_rank: None,
            confidence_score: None,
            suppression_kind: None,
            suppression_message: None,
            endpoint: None,
            http_method: None,
            parameter_name: None,
        }
    }

    #[test]
    fn test_defense_context_default() {
        let dc = SarifDefenseContext::default();
        assert!(dc.waf_vendor.is_none());
        assert!(!dc.exploitable_despite_waf);
        assert!(dc.evasion_technique.is_none());
        assert!(dc.defenses_detected.is_empty());
        assert!(dc.evasion_success_rate.is_none());
        assert!(!dc.stealth_mode_used);
    }

    #[test]
    fn test_defense_context_derives() {
        let dc = SarifDefenseContext {
            waf_vendor: Some("Akamai".to_string()),
            exploitable_despite_waf: true,
            evasion_technique: None,
            defenses_detected: vec!["IDS".to_string()],
            evasion_success_rate: Some(0.5),
            stealth_mode_used: false,
        };
        let debug_str = format!("{:?}", dc);
        assert!(debug_str.contains("Akamai"));
        let cloned = dc.clone();
        assert_eq!(cloned.waf_vendor, dc.waf_vendor);
        assert_eq!(cloned.exploitable_despite_waf, dc.exploitable_despite_waf);
        assert_eq!(cloned.defenses_detected, dc.defenses_detected);
    }

    #[test]
    fn test_sarif_result_with_defense_context() {
        let finding = finding_with_defense();
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let props = results[0].properties.as_ref().unwrap();
        assert!(props.contains_key("defenseProfile"));
        let profile = &props["defenseProfile"];
        assert!(profile["defenses_detected"].is_array());
        assert!(props.contains_key("exploitableDespiteWaf"));
        assert_eq!(props["exploitableDespiteWaf"], serde_json::json!(true));
    }

    #[test]
    fn test_sarif_result_without_defense_context() {
        let finding = sample_finding();
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let props = results[0].properties.as_ref().unwrap();
        assert!(!props.contains_key("defenseProfile"));
        assert!(!props.contains_key("exploitableDespiteWaf"));
        assert!(!props.contains_key("evasionTechnique"));
        assert!(!props.contains_key("wafVendor"));
    }

    #[test]
    fn test_sarif_result_defense_evasion_technique() {
        let finding = finding_with_defense();
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let props = results[0].properties.as_ref().unwrap();
        assert_eq!(
            props["evasionTechnique"],
            serde_json::json!("chunked encoding")
        );
    }

    #[test]
    fn test_sarif_result_defense_waf_vendor() {
        let finding = finding_with_defense();
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let props = results[0].properties.as_ref().unwrap();
        assert_eq!(props["wafVendor"], serde_json::json!("Cloudflare"));
    }

    #[test]
    fn test_sarif_result_defense_defenses_detected() {
        let finding = finding_with_defense();
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let props = results[0].properties.as_ref().unwrap();
        let profile = &props["defenseProfile"];
        let defenses = profile["defenses_detected"].as_array().unwrap();
        assert_eq!(defenses.len(), 2);
        assert!(defenses.contains(&serde_json::json!("WAF")));
        assert!(defenses.contains(&serde_json::json!("rate-limiter")));
    }

    #[test]
    fn test_sarif_run_no_defense_properties() {
        let findings = vec![sample_finding()];
        let report = emit_sarif(&findings, "0.1.0");
        assert!(report.runs[0].properties.is_none());
    }

    #[test]
    fn test_sarif_run_with_defense_properties() {
        let findings = vec![finding_with_defense()];
        let report = emit_sarif(&findings, "0.1.0");
        let run_props = report.runs[0].properties.as_ref().unwrap();
        assert!(run_props.contains_key("defensesDetected"));
        assert!(run_props.contains_key("stealthModeUsed"));
    }

    #[test]
    fn test_sarif_run_defense_aggregation() {
        let mut f1 = finding_with_defense();
        f1.defense_context.as_mut().unwrap().defenses_detected =
            vec!["WAF".to_string(), "IDS".to_string()];

        let mut f2 = finding_with_defense();
        f2.rule_id = "CWE-79".to_string();
        f2.defense_context.as_mut().unwrap().defenses_detected =
            vec!["rate-limiter".to_string(), "WAF".to_string()];

        let report = emit_sarif(&[f1, f2], "0.1.0");
        let run_props = report.runs[0].properties.as_ref().unwrap();
        let defenses = run_props["defensesDetected"].as_array().unwrap();
        let defense_strings: Vec<&str> = defenses.iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(defense_strings, vec!["IDS", "WAF", "rate-limiter"]);
    }

    #[test]
    fn test_sarif_run_evasion_success_rate() {
        let mut f1 = finding_with_defense();
        f1.defense_context.as_mut().unwrap().evasion_success_rate = Some(0.6);

        let mut f2 = finding_with_defense();
        f2.rule_id = "CWE-79".to_string();
        f2.defense_context.as_mut().unwrap().evasion_success_rate = Some(0.8);

        let report = emit_sarif(&[f1, f2], "0.1.0");
        let run_props = report.runs[0].properties.as_ref().unwrap();
        let avg = run_props["evasionSuccessRate"].as_f64().unwrap();
        assert!((avg - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn test_sarif_run_stealth_mode_any() {
        let mut f1 = finding_with_defense();
        f1.defense_context.as_mut().unwrap().stealth_mode_used = false;

        let mut f2 = finding_with_defense();
        f2.rule_id = "CWE-79".to_string();
        f2.defense_context.as_mut().unwrap().stealth_mode_used = true;

        let report = emit_sarif(&[f1, f2], "0.1.0");
        let run_props = report.runs[0].properties.as_ref().unwrap();
        assert_eq!(run_props["stealthModeUsed"], serde_json::json!(true));

        let mut f3 = finding_with_defense();
        f3.defense_context.as_mut().unwrap().stealth_mode_used = false;
        let mut f4 = finding_with_defense();
        f4.rule_id = "CWE-79".to_string();
        f4.defense_context.as_mut().unwrap().stealth_mode_used = false;

        let report2 = emit_sarif(&[f3, f4], "0.1.0");
        let run_props2 = report2.runs[0].properties.as_ref().unwrap();
        assert_eq!(run_props2["stealthModeUsed"], serde_json::json!(false));
    }

    #[test]
    fn attack_technique_for_all_vulnerability_classes() {
        assert_eq!(
            attack_technique_for(&VulnerabilityClass::SqlInjection),
            "T1190"
        );
        assert_eq!(
            attack_technique_for(&VulnerabilityClass::CrossSiteScripting),
            "T1189"
        );
        assert_eq!(
            attack_technique_for(&VulnerabilityClass::CommandInjection),
            "T1059"
        );
        assert_eq!(
            attack_technique_for(&VulnerabilityClass::PathTraversal),
            "T1083"
        );
        assert_eq!(
            attack_technique_for(&VulnerabilityClass::ServerSideRequestForgery),
            "T1090"
        );
        assert_eq!(
            attack_technique_for(&VulnerabilityClass::InsecureDeserialization),
            "T1190"
        );
        assert_eq!(
            attack_technique_for(&VulnerabilityClass::BrokenAuthentication),
            "T1078"
        );
        assert_eq!(
            attack_technique_for(&VulnerabilityClass::BrokenAuthorization),
            "T1548"
        );
        assert_eq!(
            attack_technique_for(&VulnerabilityClass::SecurityMisconfiguration),
            "T1574"
        );
        assert_eq!(
            attack_technique_for(&VulnerabilityClass::SensitiveDataExposure),
            "T1005"
        );
        assert_eq!(
            attack_technique_for(&VulnerabilityClass::ServerSideTemplateInjection),
            "T1221"
        );
        assert_eq!(
            attack_technique_for(&VulnerabilityClass::HeaderInjection),
            "T1071"
        );
        assert_eq!(
            attack_technique_for(&VulnerabilityClass::OpenRedirect),
            "T1204"
        );
        assert_eq!(
            attack_technique_for(&VulnerabilityClass::CrlfInjection),
            "T1071"
        );
        assert_eq!(
            attack_technique_for(&VulnerabilityClass::KnownVulnerableDependency),
            "T1195"
        );
        assert_eq!(
            attack_technique_for(&VulnerabilityClass::InsufficientInputValidation),
            "T1190"
        );
    }

    #[test]
    fn sarif_attack_taxonomy_in_run() {
        let report = emit_sarif(&[sample_finding()], "0.1.0");
        let taxonomies = report.runs[0].taxonomies.as_ref().unwrap();
        assert_eq!(taxonomies[1].name, "MITRE ATT&CK");
        assert_eq!(taxonomies[1].version.as_deref(), Some("15.1"));
        assert_eq!(taxonomies[1].organization.as_deref(), Some("MITRE"));
        assert_eq!(
            taxonomies[1].information_uri.as_deref(),
            Some("https://attack.mitre.org/")
        );
    }

    #[test]
    fn sarif_both_taxonomies_present() {
        let report = emit_sarif(&[sample_finding()], "0.1.0");
        let taxonomies = report.runs[0].taxonomies.as_ref().unwrap();
        assert_eq!(taxonomies.len(), 2);
        assert_eq!(taxonomies[0].name, "CWE");
        assert_eq!(taxonomies[1].name, "MITRE ATT&CK");
    }

    #[test]
    fn sarif_evidence_level_present_in_properties() {
        let mut finding = sample_finding();
        finding.evidence_level = Some("confirmed".to_string());
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let props = results[0].properties.as_ref().unwrap();
        assert_eq!(props["evidenceLevel"], serde_json::json!("confirmed"));
    }

    #[test]
    fn sarif_evidence_level_absent_when_none() {
        let finding = sample_finding();
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let props = results[0].properties.as_ref().unwrap();
        assert!(!props.contains_key("evidenceLevel"));
    }

    #[test]
    fn sarif_cve_id_present_in_properties() {
        let mut finding = sample_finding();
        finding.cve_id = Some("CVE-2024-12345".to_string());
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let props = results[0].properties.as_ref().unwrap();
        assert_eq!(props["cveId"], serde_json::json!("CVE-2024-12345"));
    }

    #[test]
    fn sarif_cve_id_absent_from_properties_when_none() {
        let finding = sample_finding();
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let props = results[0].properties.as_ref().unwrap();
        assert!(!props.contains_key("cveId"));
    }

    #[test]
    fn sarif_mitigation_rank_present_in_properties() {
        let mut finding = sample_finding();
        finding.mitigation_rank = Some(3);
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let props = results[0].properties.as_ref().unwrap();
        assert_eq!(props["mitigationRank"], serde_json::json!(3));
    }

    #[test]
    fn sarif_mitigation_rank_absent_when_none() {
        let finding = sample_finding();
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let props = results[0].properties.as_ref().unwrap();
        assert!(!props.contains_key("mitigationRank"));
    }

    #[test]
    fn sarif_confidence_score_present_in_properties() {
        let mut finding = sample_finding();
        finding.confidence_score = Some(0.85);
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let props = results[0].properties.as_ref().unwrap();
        let score = props["confidenceScore"].as_f64().unwrap();
        assert!((score - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn sarif_confidence_score_absent_when_none() {
        let finding = sample_finding();
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let props = results[0].properties.as_ref().unwrap();
        assert!(!props.contains_key("confidenceScore"));
    }

    #[test]
    fn sarif_nvd_url_in_related_locations_when_cve_set() {
        let mut finding = sample_finding();
        finding.cve_id = Some("CVE-2024-12345".to_string());
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let related = results[0].related_locations.as_ref().unwrap();
        assert_eq!(related.len(), 1);
        assert_eq!(related[0].id, Some(0));
        let phys = related[0].physical_location.as_ref().unwrap();
        assert_eq!(
            phys.artifact_location.as_ref().unwrap().uri.as_deref(),
            Some("https://nvd.nist.gov/vuln/detail/CVE-2024-12345")
        );
        assert_eq!(
            related[0].message.as_ref().unwrap().text.as_deref(),
            Some("NVD entry for CVE-2024-12345")
        );
    }

    #[test]
    fn sarif_endpoint_properties_present_when_set() {
        let mut finding = sample_finding();
        finding.endpoint = Some("/api/users".to_string());
        finding.http_method = Some("POST".to_string());
        finding.parameter_name = Some("username".to_string());
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let props = results[0].properties.as_ref().unwrap();
        assert_eq!(props["endpoint"], serde_json::json!("/api/users"));
        assert_eq!(props["httpMethod"], serde_json::json!("POST"));
        assert_eq!(props["parameterName"], serde_json::json!("username"));
    }

    #[test]
    fn sarif_endpoint_properties_absent_when_none() {
        let finding = sample_finding();
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let props = results[0].properties.as_ref().unwrap();
        assert!(!props.contains_key("endpoint"));
        assert!(!props.contains_key("httpMethod"));
        assert!(!props.contains_key("parameterName"));
    }

    #[test]
    fn sarif_location_uri_falls_back_to_endpoint() {
        let mut finding = sample_finding();
        finding.uri = None;
        finding.logical_location_name = None;
        finding.endpoint = Some("/api/data".to_string());
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let locs = results[0].locations.as_ref().unwrap();
        let phys = locs[0].physical_location.as_ref().unwrap();
        assert_eq!(
            phys.artifact_location.as_ref().unwrap().uri.as_deref(),
            Some("/api/data")
        );
    }

    #[test]
    fn sarif_result_includes_vulnerability_class_name() {
        let finding = finding_with_vuln_class();
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let props = results[0].properties.as_ref().unwrap();
        assert_eq!(
            props["vulnerabilityClass"],
            serde_json::json!("SqlInjection")
        );
    }

    #[test]
    fn sarif_result_vulnerability_class_name_absent_when_none() {
        let finding = sample_finding();
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let props = results[0].properties.as_ref().unwrap();
        assert!(!props.contains_key("vulnerabilityClass"));
    }

    #[test]
    fn sarif_result_vulnerability_class_name_for_xss() {
        let finding = finding_with_related_locations();
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let props = results[0].properties.as_ref().unwrap();
        assert_eq!(
            props["vulnerabilityClass"],
            serde_json::json!("CrossSiteScripting")
        );
    }

    #[test]
    fn sarif_location_uri_prefers_uri_over_endpoint() {
        let mut finding = sample_finding();
        finding.uri = Some("src/handler.rs".to_string());
        finding.endpoint = Some("/api/data".to_string());
        let report = emit_sarif(&[finding], "0.1.0");
        let results = report.runs[0].results.as_ref().unwrap();
        let locs = results[0].locations.as_ref().unwrap();
        let phys = locs[0].physical_location.as_ref().unwrap();
        assert_eq!(
            phys.artifact_location.as_ref().unwrap().uri.as_deref(),
            Some("src/handler.rs")
        );
    }
}
