#[cfg(test)]
mod tests {
    use crate::sarif_emitter::{emit_sarif, sarif_to_json, SarifFinding, SarifLevel};

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
        assert_eq!(report.runs[0].tool.driver.version, "1.2.3");
    }

    #[test]
    fn sarif_result_count_matches_findings() {
        let findings = vec![sample_finding(), sample_finding()];
        let report = emit_sarif(&findings, "0.1.0");
        assert_eq!(report.runs[0].results.len(), 2);
    }

    #[test]
    fn sarif_result_has_correct_rule_id() {
        let report = emit_sarif(&[sample_finding()], "0.1.0");
        assert_eq!(report.runs[0].results[0].rule_id, "CWE-89");
    }

    #[test]
    fn sarif_result_level_is_error() {
        let report = emit_sarif(&[sample_finding()], "0.1.0");
        assert_eq!(report.runs[0].results[0].level, "error");
    }

    #[test]
    fn sarif_rules_deduped() {
        let findings = vec![sample_finding(), sample_finding()];
        let report = emit_sarif(&findings, "0.1.0");
        assert_eq!(report.runs[0].tool.driver.rules.len(), 1);
    }

    #[test]
    fn sarif_multiple_different_rules() {
        let mut xss = sample_finding();
        xss.rule_id = "CWE-79".to_string();
        xss.rule_description = "Cross-Site Scripting".to_string();

        let report = emit_sarif(&[sample_finding(), xss], "0.1.0");
        assert_eq!(report.runs[0].tool.driver.rules.len(), 2);
    }

    #[test]
    fn sarif_physical_location_present() {
        let report = emit_sarif(&[sample_finding()], "0.1.0");
        let loc = &report.runs[0].results[0].locations[0];
        let phys = loc.physical_location.as_ref().unwrap();
        assert_eq!(phys.artifact_location.uri, "src/handlers/auth.rs");
    }

    #[test]
    fn sarif_logical_location_present() {
        let report = emit_sarif(&[sample_finding()], "0.1.0");
        let loc = &report.runs[0].results[0].locations[0];
        assert_eq!(loc.logical_locations[0].name, "handle_login");
        assert_eq!(loc.logical_locations[0].kind, "function");
    }

    #[test]
    fn sarif_no_location_when_uri_and_logical_absent() {
        let mut finding = sample_finding();
        finding.uri = None;
        finding.logical_location_name = None;

        let report = emit_sarif(&[finding], "0.1.0");
        assert!(report.runs[0].results[0].locations.is_empty());
    }

    #[test]
    fn sarif_properties_preserved() {
        let report = emit_sarif(&[sample_finding()], "0.1.0");
        let props = &report.runs[0].results[0].properties;
        assert_eq!(props.severity, 9.0);
        assert_eq!(props.confidence, 0.95);
        assert_eq!(props.composite_score, 85.0);
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
        assert!(report.runs[0].results.is_empty());
        assert!(report.runs[0].tool.driver.rules.is_empty());
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
        let loc = &report.runs[0].results[0].locations[0];
        assert_eq!(loc.logical_locations[0].kind, "function");
    }
}
