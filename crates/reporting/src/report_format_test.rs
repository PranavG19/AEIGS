#[cfg(test)]
mod tests {
    use aegis_protocol::finding::VulnerabilityClass;

    use crate::report_format::{
        DefenseSummary, ReportFormat, ReportMetadata, format_report, parse_report_format,
    };
    use crate::sarif_emitter::{SarifDefenseContext, SarifFinding, SarifLevel};

    fn sample_finding() -> SarifFinding {
        SarifFinding {
            rule_id: "AEGIS-1".to_string(),
            rule_description: "SQL Injection".to_string(),
            level: SarifLevel::Error,
            message: "SQL injection detected in login endpoint".to_string(),
            uri: Some("src/handlers/auth.rs".to_string()),
            logical_location_name: Some("handle_login".to_string()),
            logical_location_kind: Some("function".to_string()),
            severity: 9.0,
            confidence: 0.95,
            composite_score: 85.0,
            vulnerability_class: Some(VulnerabilityClass::SqlInjection),
            related_locations: Vec::new(),
            defense_context: None,
            evidence_level: None,
            cve_id: None,
            mitigation_rank: None,
            suppression_kind: None,
            suppression_message: None,
            endpoint: None,
            http_method: None,
            parameter_name: None,
        }
    }

    fn finding_with_defense() -> SarifFinding {
        SarifFinding {
            rule_id: "AEGIS-2".to_string(),
            rule_description: "Cross-Site Scripting".to_string(),
            level: SarifLevel::Warning,
            message: "XSS bypassed WAF".to_string(),
            uri: Some("src/views/profile.rs".to_string()),
            logical_location_name: None,
            logical_location_kind: None,
            severity: 7.0,
            confidence: 0.85,
            composite_score: 55.0,
            vulnerability_class: Some(VulnerabilityClass::CrossSiteScripting),
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
            suppression_kind: None,
            suppression_message: None,
            endpoint: None,
            http_method: None,
            parameter_name: None,
        }
    }

    fn low_severity_finding() -> SarifFinding {
        SarifFinding {
            rule_id: "AEGIS-3".to_string(),
            rule_description: "Open Redirect".to_string(),
            level: SarifLevel::Note,
            message: "Open redirect in callback endpoint".to_string(),
            uri: None,
            logical_location_name: None,
            logical_location_kind: None,
            severity: 3.0,
            confidence: 0.6,
            composite_score: 15.0,
            vulnerability_class: Some(VulnerabilityClass::OpenRedirect),
            related_locations: Vec::new(),
            defense_context: None,
            evidence_level: None,
            cve_id: None,
            mitigation_rank: None,
            suppression_kind: None,
            suppression_message: None,
            endpoint: None,
            http_method: None,
            parameter_name: None,
        }
    }

    // --- parse_report_format tests ---

    #[test]
    fn parse_developer_format() {
        assert_eq!(
            parse_report_format("developer").unwrap(),
            ReportFormat::Developer
        );
    }

    #[test]
    fn parse_security_format() {
        assert_eq!(
            parse_report_format("security").unwrap(),
            ReportFormat::Security
        );
    }

    #[test]
    fn parse_executive_format() {
        assert_eq!(
            parse_report_format("executive").unwrap(),
            ReportFormat::Executive
        );
    }

    #[test]
    fn parse_invalid_format_returns_error() {
        let result = parse_report_format("pdf");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("pdf"));
    }

    #[test]
    fn parse_empty_string_returns_error() {
        assert!(parse_report_format("").is_err());
    }

    // --- Developer format tests ---

    #[test]
    fn developer_format_produces_valid_sarif() {
        let findings = vec![sample_finding()];
        let result = format_report(&findings, ReportFormat::Developer, "0.1.0", None, None);
        assert!(result.is_ok());
        let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert_eq!(json["version"], "2.1.0");
        assert!(json["$schema"].as_str().unwrap().contains("sarif"));
    }

    #[test]
    fn developer_format_includes_cwe_references() {
        let findings = vec![sample_finding()];
        let result = format_report(&findings, ReportFormat::Developer, "0.1.0", None, None);
        let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        let results = json["runs"][0]["results"].as_array().unwrap();
        let taxa = results[0]["taxa"].as_array().unwrap();
        assert_eq!(taxa[0]["id"].as_str().unwrap(), "CWE-89");
    }

    #[test]
    fn developer_format_includes_fixes() {
        let findings = vec![sample_finding()];
        let result = format_report(&findings, ReportFormat::Developer, "0.1.0", None, None);
        let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        let results = json["runs"][0]["results"].as_array().unwrap();
        let fixes = results[0]["fixes"].as_array().unwrap();
        assert_eq!(fixes.len(), 1);
        let desc = fixes[0]["description"]["text"].as_str().unwrap();
        assert!(desc.contains("parameterized queries"));
    }

    #[test]
    fn developer_format_empty_findings_produces_valid_sarif() {
        let result = format_report(&[], ReportFormat::Developer, "0.1.0", None, None);
        assert!(result.is_ok());
        let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        let results = json["runs"][0]["results"].as_array().unwrap();
        assert!(results.is_empty());
    }

    // --- Security format tests ---

    #[test]
    fn security_format_produces_valid_sarif() {
        let findings = vec![sample_finding()];
        let result = format_report(&findings, ReportFormat::Security, "0.1.0", None, None);
        assert!(result.is_ok());
        let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert_eq!(json["version"], "2.1.0");
    }

    #[test]
    fn security_format_includes_attack_chain_properties() {
        let findings = vec![sample_finding()];
        let result = format_report(&findings, ReportFormat::Security, "0.1.0", None, None);
        let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        let props = &json["runs"][0]["properties"];
        let analysis = &props["securityAnalysis"];
        assert!(analysis["attackChains"].is_array());
        let chains = analysis["attackChains"].as_array().unwrap();
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0]["techniqueId"].as_str().unwrap(), "T1190");
        assert_eq!(chains[0]["cwe"].as_str().unwrap(), "CWE-89");
    }

    #[test]
    fn security_format_includes_defense_gaps() {
        let findings = vec![finding_with_defense()];
        let result = format_report(&findings, ReportFormat::Security, "0.1.0", None, None);
        let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        let analysis = &json["runs"][0]["properties"]["securityAnalysis"];
        let gaps = &analysis["defenseGaps"];
        let detected = gaps["defensesDetected"].as_array().unwrap();
        assert!(detected.contains(&serde_json::json!("WAF")));
        assert!(detected.contains(&serde_json::json!("rate-limiter")));
        let bypassed = gaps["defensesBypassed"].as_array().unwrap();
        assert!(bypassed.contains(&serde_json::json!("WAF (Cloudflare)")));
    }

    #[test]
    fn security_format_includes_finding_correlations() {
        let mut f2 = sample_finding();
        f2.rule_id = "AEGIS-4".to_string();
        let findings = vec![sample_finding(), f2];
        let result = format_report(&findings, ReportFormat::Security, "0.1.0", None, None);
        let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        let correlations =
            &json["runs"][0]["properties"]["securityAnalysis"]["findingCorrelations"];
        let groups = correlations.as_array().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0]["vulnerabilityClass"].as_str().unwrap(),
            "SQL Injection"
        );
        assert_eq!(groups[0]["count"].as_u64().unwrap(), 2);
    }

    #[test]
    fn security_format_no_correlations_for_unique_classes() {
        let findings = vec![sample_finding(), finding_with_defense()];
        let result = format_report(&findings, ReportFormat::Security, "0.1.0", None, None);
        let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        let correlations =
            &json["runs"][0]["properties"]["securityAnalysis"]["findingCorrelations"];
        let groups = correlations.as_array().unwrap();
        assert!(groups.is_empty());
    }

    // --- Executive format tests ---

    #[test]
    fn executive_format_produces_summary_json() {
        let findings = vec![sample_finding(), low_severity_finding()];
        let result = format_report(&findings, ReportFormat::Executive, "0.1.0", None, None);
        assert!(result.is_ok());
        let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert!(json.get("version").is_none());
        assert_eq!(json["total_findings"].as_u64().unwrap(), 2);
    }

    #[test]
    fn executive_format_counts_by_severity() {
        let findings = vec![
            sample_finding(),
            finding_with_defense(),
            low_severity_finding(),
        ];
        let result = format_report(&findings, ReportFormat::Executive, "0.1.0", None, None);
        let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        let counts = &json["severity_counts"];
        assert_eq!(counts["critical"].as_u64().unwrap(), 1);
        assert_eq!(counts["high"].as_u64().unwrap(), 1);
        assert_eq!(counts["low"].as_u64().unwrap(), 1);
    }

    #[test]
    fn executive_format_risk_summary_reflects_worst_finding() {
        let findings = vec![sample_finding()];
        let result = format_report(&findings, ReportFormat::Executive, "0.1.0", None, None);
        let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert_eq!(json["risk_summary"].as_str().unwrap(), "Critical");
    }

    #[test]
    fn executive_format_risk_summary_low_when_all_low() {
        let findings = vec![low_severity_finding()];
        let result = format_report(&findings, ReportFormat::Executive, "0.1.0", None, None);
        let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert_eq!(json["risk_summary"].as_str().unwrap(), "Low");
    }

    #[test]
    fn executive_format_top_remediation_priorities_max_five() {
        let mut findings = Vec::new();
        for i in 0..8 {
            let mut f = sample_finding();
            f.rule_id = format!("AEGIS-{i}");
            f.composite_score = 90.0 - (i as f64 * 5.0);
            findings.push(f);
        }
        let result = format_report(&findings, ReportFormat::Executive, "0.1.0", None, None);
        let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        let priorities = json["top_remediation_priorities"].as_array().unwrap();
        assert_eq!(priorities.len(), 5);
        let first_score = priorities[0]["composite_score"].as_f64().unwrap();
        let last_score = priorities[4]["composite_score"].as_f64().unwrap();
        assert!(first_score >= last_score);
    }

    #[test]
    fn executive_format_remediation_includes_fix_text() {
        let findings = vec![sample_finding()];
        let result = format_report(&findings, ReportFormat::Executive, "0.1.0", None, None);
        let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        let priorities = json["top_remediation_priorities"].as_array().unwrap();
        let remediation = priorities[0]["remediation"].as_str().unwrap();
        assert!(remediation.contains("parameterized queries"));
    }

    #[test]
    fn executive_format_defense_posture_summary() {
        let findings = vec![sample_finding()];
        let ds = DefenseSummary {
            has_waf: true,
            waf_vendor: Some("Cloudflare".to_string()),
            has_rate_limiting: true,
            has_bot_detection: false,
        };
        let result = format_report(&findings, ReportFormat::Executive, "0.1.0", None, Some(&ds));
        let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        let posture = &json["defense_posture_summary"];
        assert_eq!(posture["waf_active"], true);
        assert_eq!(posture["waf_vendor"].as_str().unwrap(), "Cloudflare");
        assert_eq!(posture["rate_limiting_active"], true);
        assert_eq!(posture["bot_detection_active"], false);
    }

    #[test]
    fn executive_format_scan_metadata() {
        let findings = vec![sample_finding()];
        let meta = ReportMetadata {
            target_url: "http://localhost:8080".to_string(),
            total_duration_secs: 12.5,
            phases_completed: 5,
        };
        let result = format_report(
            &findings,
            ReportFormat::Executive,
            "0.1.0",
            Some(&meta),
            None,
        );
        let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        let scan = &json["scan_metadata"];
        assert_eq!(scan["target"].as_str().unwrap(), "http://localhost:8080");
        assert!((scan["duration_secs"].as_f64().unwrap() - 12.5).abs() < f64::EPSILON);
        assert_eq!(scan["phases_completed"].as_u64().unwrap(), 5);
        assert_eq!(scan["tool_version"].as_str().unwrap(), "0.1.0");
    }

    #[test]
    fn executive_format_empty_findings() {
        let result = format_report(&[], ReportFormat::Executive, "0.1.0", None, None);
        assert!(result.is_ok());
        let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert_eq!(json["total_findings"].as_u64().unwrap(), 0);
        assert_eq!(json["risk_summary"].as_str().unwrap(), "Low");
        let priorities = json["top_remediation_priorities"].as_array().unwrap();
        assert!(priorities.is_empty());
    }

    #[test]
    fn executive_format_default_defense_posture_when_none() {
        let findings = vec![sample_finding()];
        let result = format_report(&findings, ReportFormat::Executive, "0.1.0", None, None);
        let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        let posture = &json["defense_posture_summary"];
        assert_eq!(posture["waf_active"], false);
        assert!(posture["waf_vendor"].is_null());
        assert_eq!(posture["rate_limiting_active"], false);
        assert_eq!(posture["bot_detection_active"], false);
    }

    // --- ReportFormat enum tests ---

    #[test]
    fn report_format_debug() {
        let f = ReportFormat::Developer;
        let dbg = format!("{f:?}");
        assert!(dbg.contains("Developer"));
    }

    #[test]
    fn report_format_clone() {
        let f = ReportFormat::Security;
        let cloned = f;
        assert_eq!(f, cloned);
    }

    #[test]
    fn report_format_eq() {
        assert_eq!(ReportFormat::Developer, ReportFormat::Developer);
        assert_ne!(ReportFormat::Developer, ReportFormat::Security);
        assert_ne!(ReportFormat::Security, ReportFormat::Executive);
    }

    // --- Default format is Developer ---

    #[test]
    fn default_format_is_developer() {
        let format = parse_report_format("developer").unwrap();
        assert_eq!(format, ReportFormat::Developer);
    }
}
