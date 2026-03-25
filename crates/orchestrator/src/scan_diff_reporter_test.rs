#[cfg(test)]
mod tests {
    use aegis_protocol::finding::VulnerabilityClass;

    use crate::scan_diff_reporter::{
        DiffFinding, FindingStatus, ScanDiffReporter, SeverityScore, TrendPoint,
    };

    fn make_finding(fp: &str, class: VulnerabilityClass, score: f64) -> DiffFinding {
        DiffFinding {
            fingerprint: fp.to_string(),
            endpoint: format!("/api/{fp}"),
            vulnerability_class: class,
            severity_score: SeverityScore(score),
            title: format!("Finding {fp}"),
            first_seen_ms: 1_000_000,
        }
    }

    #[test]
    fn empty_scans_produce_empty_report() {
        let reporter = ScanDiffReporter::new();
        let report = reporter.generate_diff("http://example.com", 1000, 2000, &[], &[], vec![]);
        assert!(report.entries.is_empty());
        assert_eq!(report.summary.total_current, 0);
        assert_eq!(report.summary.total_previous, 0);
        assert_eq!(report.summary.net_change, 0);
    }

    #[test]
    fn all_new_findings() {
        let reporter = ScanDiffReporter::new();
        let current = vec![
            make_finding("a", VulnerabilityClass::SqlInjection, 9.0),
            make_finding("b", VulnerabilityClass::CrossSiteScripting, 7.0),
        ];
        let report =
            reporter.generate_diff("http://example.com", 1000, 2000, &[], &current, vec![]);
        assert_eq!(report.summary.new_count, 2);
        assert_eq!(report.summary.resolved_count, 0);
        assert_eq!(report.summary.net_change, 2);
        assert!(report
            .entries
            .iter()
            .all(|e| e.status == FindingStatus::New));
    }

    #[test]
    fn all_resolved_findings() {
        let reporter = ScanDiffReporter::new();
        let baseline = vec![make_finding("x", VulnerabilityClass::CommandInjection, 8.0)];
        let report =
            reporter.generate_diff("http://example.com", 1000, 2000, &baseline, &[], vec![]);
        assert_eq!(report.summary.resolved_count, 1);
        assert_eq!(report.summary.new_count, 0);
        assert_eq!(report.summary.net_change, -1);
        assert_eq!(report.entries[0].status, FindingStatus::Resolved);
        assert!(report.entries[0].time_to_fix_ms.is_some());
    }

    #[test]
    fn unchanged_finding() {
        let reporter = ScanDiffReporter::new();
        let f = make_finding("same", VulnerabilityClass::PathTraversal, 6.5);
        let report =
            reporter.generate_diff("http://example.com", 1000, 2000, &[f.clone()], &[f], vec![]);
        assert_eq!(report.summary.unchanged_count, 1);
        assert_eq!(report.summary.net_change, 0);
    }

    #[test]
    fn severity_changed_finding() {
        let reporter = ScanDiffReporter::new();
        let baseline = make_finding("sev", VulnerabilityClass::SqlInjection, 7.0);
        let mut current = make_finding("sev", VulnerabilityClass::SqlInjection, 9.5);
        current.title = "Finding sev (upgraded)".to_string();

        let report = reporter.generate_diff(
            "http://example.com",
            1000,
            2000,
            &[baseline],
            &[current],
            vec![],
        );
        assert_eq!(report.summary.severity_changed_count, 1);
        let entry = &report.entries[0];
        assert_eq!(entry.status, FindingStatus::SeverityChanged);
        assert!(entry.previous_severity.is_some());
        assert!((entry.previous_severity.unwrap().0 - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    fn mixed_diff_report() {
        let reporter = ScanDiffReporter::new();
        let baseline = vec![
            make_finding("stays", VulnerabilityClass::SqlInjection, 8.0),
            make_finding("goes", VulnerabilityClass::CrossSiteScripting, 6.0),
            make_finding("changes", VulnerabilityClass::CommandInjection, 5.0),
        ];
        let current = vec![
            make_finding("stays", VulnerabilityClass::SqlInjection, 8.0),
            make_finding("changes", VulnerabilityClass::CommandInjection, 9.0),
            make_finding("arrives", VulnerabilityClass::PathTraversal, 7.0),
        ];
        let report = reporter.generate_diff(
            "http://example.com",
            1000,
            2000,
            &baseline,
            &current,
            vec![],
        );

        assert_eq!(report.summary.unchanged_count, 1);
        assert_eq!(report.summary.resolved_count, 1);
        assert_eq!(report.summary.severity_changed_count, 1);
        assert_eq!(report.summary.new_count, 1);
        assert_eq!(report.summary.net_change, 0);
        assert_eq!(report.summary.total_previous, 3);
        assert_eq!(report.summary.total_current, 3);
    }

    #[test]
    fn findings_by_class_breakdown() {
        let reporter = ScanDiffReporter::new();
        let current = vec![
            make_finding("a", VulnerabilityClass::SqlInjection, 9.0),
            make_finding("b", VulnerabilityClass::SqlInjection, 8.0),
            make_finding("c", VulnerabilityClass::CrossSiteScripting, 7.0),
        ];
        let report =
            reporter.generate_diff("http://example.com", 1000, 2000, &[], &current, vec![]);

        let sqli = report
            .summary
            .findings_by_class
            .get("SQL Injection")
            .unwrap();
        assert_eq!(sqli.new_count, 2);
        let xss = report
            .summary
            .findings_by_class
            .get("Cross-Site Scripting")
            .unwrap();
        assert_eq!(xss.new_count, 1);
    }

    #[test]
    fn time_to_fix_calculation() {
        let reporter = ScanDiffReporter::new();
        let mut baseline_finding = make_finding("fixed", VulnerabilityClass::SqlInjection, 9.0);
        baseline_finding.first_seen_ms = 1_000_000;

        let report = reporter.generate_diff(
            "http://example.com",
            1_000_000,
            5_000_000,
            &[baseline_finding],
            &[],
            vec![],
        );

        let ttf = report.entries[0].time_to_fix_ms.unwrap();
        assert_eq!(ttf, 4_000_000);
    }

    #[test]
    fn average_time_to_fix() {
        let reporter = ScanDiffReporter::new();
        let mut f1 = make_finding("a", VulnerabilityClass::SqlInjection, 9.0);
        f1.first_seen_ms = 1_000_000;
        let mut f2 = make_finding("b", VulnerabilityClass::CrossSiteScripting, 7.0);
        f2.first_seen_ms = 2_000_000;

        let report = reporter.generate_diff(
            "http://example.com",
            1_000_000,
            5_000_000,
            &[f1, f2],
            &[],
            vec![],
        );

        let avg = report.average_time_to_fix_ms().unwrap();
        assert_eq!(avg, (4_000_000 + 3_000_000) / 2);
    }

    #[test]
    fn average_time_to_fix_none_when_no_resolved() {
        let reporter = ScanDiffReporter::new();
        let current = vec![make_finding("a", VulnerabilityClass::SqlInjection, 9.0)];
        let report =
            reporter.generate_diff("http://example.com", 1000, 2000, &[], &current, vec![]);
        assert!(report.average_time_to_fix_ms().is_none());
    }

    #[test]
    fn entries_with_status_filter() {
        let reporter = ScanDiffReporter::new();
        let baseline = vec![make_finding("old", VulnerabilityClass::SqlInjection, 8.0)];
        let current = vec![make_finding(
            "new",
            VulnerabilityClass::CrossSiteScripting,
            7.0,
        )];
        let report = reporter.generate_diff(
            "http://example.com",
            1000,
            2000,
            &baseline,
            &current,
            vec![],
        );

        let new_entries = report.entries_with_status(FindingStatus::New);
        assert_eq!(new_entries.len(), 1);
        assert_eq!(new_entries[0].finding.fingerprint, "new");

        let resolved_entries = report.entries_with_status(FindingStatus::Resolved);
        assert_eq!(resolved_entries.len(), 1);
        assert_eq!(resolved_entries[0].finding.fingerprint, "old");
    }

    #[test]
    fn finding_status_color_labels() {
        assert_eq!(FindingStatus::New.color_label(), "red");
        assert_eq!(FindingStatus::Resolved.color_label(), "green");
        assert_eq!(FindingStatus::SeverityChanged.color_label(), "yellow");
        assert_eq!(FindingStatus::Unchanged.color_label(), "gray");
    }

    #[test]
    fn trend_data_passed_through() {
        let reporter = ScanDiffReporter::new();
        let trend = vec![
            TrendPoint {
                timestamp_ms: 1000,
                total_findings: 5,
                critical_count: 1,
                high_count: 2,
                medium_count: 1,
                low_count: 1,
            },
            TrendPoint {
                timestamp_ms: 2000,
                total_findings: 3,
                critical_count: 0,
                high_count: 1,
                medium_count: 1,
                low_count: 1,
            },
        ];
        let report = reporter.generate_diff("http://example.com", 1000, 2000, &[], &[], trend);
        assert_eq!(report.trend_data.len(), 2);
        assert_eq!(report.trend_data[0].total_findings, 5);
        assert_eq!(report.trend_data[1].total_findings, 3);
    }
}
