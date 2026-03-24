#[cfg(test)]
mod tests {
    use crate::scan_comparison::{
        ScanComparison, ScanFinding, ScanResult, compare_scans, compute_risk_trend,
        detect_regressions, render_comparison_json, render_comparison_markdown,
    };

    fn make_finding(
        id: &str,
        endpoint: &str,
        class: &str,
        severity: &str,
        score: f64,
    ) -> ScanFinding {
        ScanFinding {
            id: id.to_string(),
            endpoint: endpoint.to_string(),
            vulnerability_class: class.to_string(),
            severity: severity.to_string(),
            composite_score: score,
            confidence: 0.9,
        }
    }

    fn empty_scan(id: &str) -> ScanResult {
        ScanResult {
            scan_id: id.to_string(),
            scan_date: "2025-01-01T00:00:00Z".to_string(),
            target_url: "http://localhost:3000".to_string(),
            findings: Vec::new(),
            endpoints_discovered: Vec::new(),
        }
    }

    fn baseline_scan() -> ScanResult {
        ScanResult {
            scan_id: "scan-001".to_string(),
            scan_date: "2025-01-01T00:00:00Z".to_string(),
            target_url: "http://localhost:3000".to_string(),
            findings: vec![
                make_finding("f1", "/api/users", "SqlInjection", "High", 75.0),
                make_finding("f2", "/api/login", "CrossSiteScripting", "Medium", 45.0),
                make_finding("f3", "/api/search", "CommandInjection", "Critical", 90.0),
            ],
            endpoints_discovered: vec![
                "/api/users".to_string(),
                "/api/login".to_string(),
                "/api/search".to_string(),
            ],
        }
    }

    #[test]
    fn new_findings_detected() {
        let previous = baseline_scan();
        let mut current = baseline_scan();
        current.scan_id = "scan-002".to_string();
        current.findings.push(make_finding(
            "f4",
            "/api/admin",
            "BrokenAuth",
            "Critical",
            85.0,
        ));

        let comparison = compare_scans(&previous, &current);

        assert_eq!(comparison.new_findings.len(), 1);
        assert_eq!(comparison.new_findings[0].endpoint, "/api/admin");
        assert_eq!(comparison.new_findings[0].vulnerability_class, "BrokenAuth");
        assert_eq!(comparison.delta_summary.findings_added, 1);
    }

    #[test]
    fn resolved_findings_detected() {
        let previous = baseline_scan();
        let mut current = baseline_scan();
        current.scan_id = "scan-002".to_string();
        current.findings.retain(|f| f.endpoint != "/api/search");

        let comparison = compare_scans(&previous, &current);

        assert_eq!(comparison.resolved_findings.len(), 1);
        assert_eq!(comparison.resolved_findings[0].endpoint, "/api/search");
        assert_eq!(
            comparison.resolved_findings[0].vulnerability_class,
            "CommandInjection"
        );
        assert_eq!(comparison.delta_summary.findings_resolved, 1);
    }

    #[test]
    fn changed_severity_detected() {
        let previous = baseline_scan();
        let mut current = baseline_scan();
        current.scan_id = "scan-002".to_string();
        current.findings[0] = make_finding("f1", "/api/users", "SqlInjection", "Critical", 92.0);

        let comparison = compare_scans(&previous, &current);

        assert_eq!(comparison.changed_findings.len(), 1);
        let changed = &comparison.changed_findings[0];
        assert_eq!(changed.endpoint, "/api/users");
        assert_eq!(changed.previous_severity, "High");
        assert_eq!(changed.current_severity, "Critical");
        assert_eq!(changed.previous_score, 75.0);
        assert_eq!(changed.current_score, 92.0);
        assert!((changed.score_delta - 17.0).abs() < f64::EPSILON);
        assert_eq!(comparison.delta_summary.findings_changed, 1);
    }

    #[test]
    fn regression_detection() {
        let previous = baseline_scan();
        let mut current = baseline_scan();
        current.scan_id = "scan-002".to_string();

        let resolved_history = vec![make_finding(
            "f-old",
            "/api/login",
            "CrossSiteScripting",
            "Medium",
            45.0,
        )];

        let regressions = detect_regressions(&previous, &current, &resolved_history);

        assert_eq!(regressions.len(), 1);
        assert_eq!(regressions[0].endpoint, "/api/login");
        assert_eq!(regressions[0].vulnerability_class, "CrossSiteScripting");
    }

    #[test]
    fn regression_not_detected_when_still_absent() {
        let previous = baseline_scan();
        let mut current = baseline_scan();
        current.scan_id = "scan-002".to_string();

        let resolved_history = vec![make_finding(
            "f-old",
            "/api/deleted",
            "PathTraversal",
            "High",
            60.0,
        )];

        let regressions = detect_regressions(&previous, &current, &resolved_history);
        assert!(regressions.is_empty());
    }

    #[test]
    fn new_endpoints_detected() {
        let previous = baseline_scan();
        let mut current = baseline_scan();
        current.scan_id = "scan-002".to_string();
        current.endpoints_discovered.push("/api/admin".to_string());
        current
            .endpoints_discovered
            .push("/api/dashboard".to_string());

        let comparison = compare_scans(&previous, &current);

        assert_eq!(comparison.new_endpoints.len(), 2);
        let new_eps: std::collections::HashSet<&str> = comparison
            .new_endpoints
            .iter()
            .map(String::as_str)
            .collect();
        assert!(new_eps.contains("/api/admin"));
        assert!(new_eps.contains("/api/dashboard"));
        assert_eq!(comparison.delta_summary.endpoints_added, 2);
    }

    #[test]
    fn removed_endpoints_detected() {
        let previous = baseline_scan();
        let mut current = baseline_scan();
        current.scan_id = "scan-002".to_string();
        current.endpoints_discovered.retain(|e| e != "/api/search");

        let comparison = compare_scans(&previous, &current);

        assert_eq!(comparison.removed_endpoints.len(), 1);
        assert_eq!(comparison.removed_endpoints[0], "/api/search");
        assert_eq!(comparison.delta_summary.endpoints_removed, 1);
    }

    #[test]
    fn risk_trend_degrading_more_findings() {
        let previous = baseline_scan();
        let mut current = baseline_scan();
        current
            .findings
            .push(make_finding("f4", "/api/new", "SSRF", "High", 70.0));

        let trend = compute_risk_trend(&previous, &current);
        assert_eq!(trend, "degrading");
    }

    #[test]
    fn risk_trend_degrading_higher_score() {
        let previous = baseline_scan();
        let mut current = baseline_scan();
        current.findings[2] =
            make_finding("f3", "/api/search", "CommandInjection", "Critical", 98.0);

        let trend = compute_risk_trend(&previous, &current);
        assert_eq!(trend, "degrading");
    }

    #[test]
    fn risk_trend_improving() {
        let previous = baseline_scan();
        let mut current = baseline_scan();
        current.findings.retain(|f| f.endpoint != "/api/search");

        let trend = compute_risk_trend(&previous, &current);
        assert_eq!(trend, "improving");
    }

    #[test]
    fn risk_trend_stable() {
        let previous = baseline_scan();
        let current = baseline_scan();

        let trend = compute_risk_trend(&previous, &current);
        assert_eq!(trend, "stable");
    }

    #[test]
    fn empty_scans_comparison() {
        let previous = empty_scan("scan-000");
        let current = empty_scan("scan-001");

        let comparison = compare_scans(&previous, &current);

        assert!(comparison.new_findings.is_empty());
        assert!(comparison.resolved_findings.is_empty());
        assert!(comparison.changed_findings.is_empty());
        assert!(comparison.new_endpoints.is_empty());
        assert!(comparison.removed_endpoints.is_empty());
        assert!(comparison.regressions.is_empty());
        assert_eq!(comparison.delta_summary.findings_added, 0);
        assert_eq!(comparison.delta_summary.risk_trend, "stable");
        assert!(comparison.delta_summary.summary_text.contains("No changes"));
    }

    #[test]
    fn markdown_rendering_contains_sections() {
        let previous = baseline_scan();
        let mut current = baseline_scan();
        current.scan_id = "scan-002".to_string();
        current.findings.push(make_finding(
            "f4",
            "/api/admin",
            "BrokenAuth",
            "Critical",
            85.0,
        ));
        current.findings.retain(|f| f.endpoint != "/api/search");
        current.endpoints_discovered.push("/api/admin".to_string());

        let comparison = compare_scans(&previous, &current);
        let md = render_comparison_markdown(&comparison);

        assert!(md.contains("# Scan Comparison: scan-001 → scan-002"));
        assert!(md.contains("## Summary"));
        assert!(md.contains("## New Findings"));
        assert!(md.contains("/api/admin"));
        assert!(md.contains("BrokenAuth"));
        assert!(md.contains("## Resolved Findings"));
        assert!(md.contains("/api/search"));
        assert!(md.contains("## Endpoint Changes"));
        assert!(md.contains("**New endpoints:**"));
    }

    #[test]
    fn json_rendering_is_valid_json() {
        let previous = baseline_scan();
        let current = baseline_scan();

        let comparison = compare_scans(&previous, &current);
        let json = render_comparison_json(&comparison);

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("previous_scan_id").is_some());
        assert!(parsed.get("current_scan_id").is_some());
        assert!(parsed.get("delta_summary").is_some());
    }

    #[test]
    fn comparison_ids_propagated() {
        let previous = baseline_scan();
        let mut current = baseline_scan();
        current.scan_id = "scan-002".to_string();

        let comparison = compare_scans(&previous, &current);

        assert_eq!(comparison.previous_scan_id, "scan-001");
        assert_eq!(comparison.current_scan_id, "scan-002");
    }

    #[test]
    fn summary_text_includes_counts() {
        let previous = baseline_scan();
        let mut current = baseline_scan();
        current.scan_id = "scan-002".to_string();
        current.findings.push(make_finding(
            "f4",
            "/api/admin",
            "BrokenAuth",
            "Critical",
            85.0,
        ));
        current.findings.retain(|f| f.endpoint != "/api/search");

        let comparison = compare_scans(&previous, &current);
        let text = &comparison.delta_summary.summary_text;

        assert!(text.contains("1 new finding(s)"));
        assert!(text.contains("1 resolved"));
        assert!(text.contains("Risk trend:"));
    }

    #[test]
    fn changed_finding_score_delta_negative() {
        let previous = baseline_scan();
        let mut current = baseline_scan();
        current.scan_id = "scan-002".to_string();
        current.findings[0] = make_finding("f1", "/api/users", "SqlInjection", "Medium", 40.0);

        let comparison = compare_scans(&previous, &current);

        assert_eq!(comparison.changed_findings.len(), 1);
        let changed = &comparison.changed_findings[0];
        assert!(changed.score_delta < 0.0);
        assert!((changed.score_delta - (-35.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn regression_uses_current_scan_data() {
        let previous = empty_scan("scan-000");
        let mut current = empty_scan("scan-001");
        current.findings.push(make_finding(
            "f-new",
            "/api/vuln",
            "SqlInjection",
            "Critical",
            95.0,
        ));

        let resolved_history = vec![make_finding(
            "f-old",
            "/api/vuln",
            "SqlInjection",
            "High",
            70.0,
        )];

        let regressions = detect_regressions(&previous, &current, &resolved_history);

        assert_eq!(regressions.len(), 1);
        assert_eq!(regressions[0].current_severity, "Critical");
        assert_eq!(regressions[0].current_score, 95.0);
    }

    #[test]
    fn markdown_omits_empty_sections() {
        let previous = baseline_scan();
        let current = baseline_scan();

        let comparison = compare_scans(&previous, &current);
        let md = render_comparison_markdown(&comparison);

        assert!(md.contains("## Summary"));
        assert!(!md.contains("## New Findings"));
        assert!(!md.contains("## Resolved Findings"));
        assert!(!md.contains("## Changed Findings"));
        assert!(!md.contains("## Regressions"));
        assert!(!md.contains("## Endpoint Changes"));
    }

    #[test]
    fn serialization_roundtrip() {
        let previous = baseline_scan();
        let mut current = baseline_scan();
        current.scan_id = "scan-002".to_string();
        current.findings.push(make_finding(
            "f4",
            "/api/admin",
            "BrokenAuth",
            "Critical",
            85.0,
        ));

        let comparison = compare_scans(&previous, &current);
        let json = serde_json::to_string(&comparison).unwrap();
        let roundtripped: ScanComparison = serde_json::from_str(&json).unwrap();

        assert_eq!(roundtripped.previous_scan_id, comparison.previous_scan_id);
        assert_eq!(roundtripped.current_scan_id, comparison.current_scan_id);
        assert_eq!(
            roundtripped.new_findings.len(),
            comparison.new_findings.len()
        );
        assert_eq!(
            roundtripped.delta_summary.risk_trend,
            comparison.delta_summary.risk_trend
        );
    }
}
