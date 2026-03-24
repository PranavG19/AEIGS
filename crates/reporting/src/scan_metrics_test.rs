#[cfg(test)]
mod tests {
    use crate::scan_metrics::{
        CoverageMetrics, ModuleFindings, PayloadEffectiveness, PhaseTiming, ResourceUsage,
        ScanMetricsBuilder, ScanMetricsDashboard, ScanTrendEntry, render_metrics_json,
        render_metrics_markdown,
    };

    fn sample_phase_recon() -> PhaseTiming {
        PhaseTiming {
            phase_name: "recon".to_string(),
            duration_secs: 2.5,
            started_at: Some("2025-01-15T10:00:00Z".to_string()),
            completed_at: Some("2025-01-15T10:00:02Z".to_string()),
        }
    }

    fn sample_phase_fuzz() -> PhaseTiming {
        PhaseTiming {
            phase_name: "fuzz".to_string(),
            duration_secs: 15.3,
            started_at: Some("2025-01-15T10:00:03Z".to_string()),
            completed_at: Some("2025-01-15T10:00:18Z".to_string()),
        }
    }

    fn sample_module_fuzzer() -> ModuleFindings {
        ModuleFindings {
            module_name: "fuzzer".to_string(),
            finding_count: 12,
            critical_count: 3,
            high_count: 5,
        }
    }

    fn sample_module_crawler() -> ModuleFindings {
        ModuleFindings {
            module_name: "crawler".to_string(),
            finding_count: 4,
            critical_count: 1,
            high_count: 2,
        }
    }

    fn sample_payload_sqli() -> PayloadEffectiveness {
        PayloadEffectiveness {
            payload_class: "sqli-template".to_string(),
            total_sent: 200,
            successful: 18,
            success_rate: 0.09,
        }
    }

    fn sample_payload_xss() -> PayloadEffectiveness {
        PayloadEffectiveness {
            payload_class: "xss-generative".to_string(),
            total_sent: 150,
            successful: 30,
            success_rate: 0.20,
        }
    }

    fn sample_coverage() -> CoverageMetrics {
        CoverageMetrics {
            total_endpoints: 50,
            tested_endpoints: 42,
            endpoint_coverage_pct: 84.0,
            total_vuln_classes: 34,
            tested_vuln_classes: 20,
            vuln_class_coverage_pct: 58.8,
        }
    }

    fn sample_resource_usage() -> ResourceUsage {
        ResourceUsage {
            total_requests: 3400,
            total_bytes_transferred: 1_250_000,
            avg_time_per_endpoint_ms: 45.2,
            peak_concurrent_requests: 8,
        }
    }

    fn sample_trend_entry() -> ScanTrendEntry {
        ScanTrendEntry {
            scan_date: "2025-01-15".to_string(),
            total_findings: 16,
            critical_count: 4,
            risk_score: 72.5,
        }
    }

    fn full_builder() -> ScanMetricsBuilder {
        ScanMetricsBuilder::new()
            .with_phase_timing(sample_phase_recon())
            .with_phase_timing(sample_phase_fuzz())
            .with_module_findings(sample_module_fuzzer())
            .with_module_findings(sample_module_crawler())
            .with_payload_effectiveness(sample_payload_sqli())
            .with_payload_effectiveness(sample_payload_xss())
            .with_coverage(sample_coverage())
            .with_resource_usage(sample_resource_usage())
            .with_trend_entry(sample_trend_entry())
    }

    #[test]
    fn builder_produces_correct_dashboard() {
        let dashboard = full_builder().build();

        assert_eq!(dashboard.phase_timings.len(), 2);
        assert_eq!(dashboard.module_findings.len(), 2);
        assert_eq!(dashboard.payload_effectiveness.len(), 2);
        assert_eq!(dashboard.trend.len(), 1);
        assert_eq!(dashboard.coverage.total_endpoints, 50);
        assert_eq!(dashboard.resource_usage.total_requests, 3400);
    }

    #[test]
    fn summary_computes_total_duration() {
        let dashboard = full_builder().build();
        let expected = 2.5 + 15.3;
        let epsilon = 1e-10;
        assert!((dashboard.summary.total_scan_duration_secs - expected).abs() < epsilon);
    }

    #[test]
    fn summary_computes_total_findings() {
        let dashboard = full_builder().build();
        assert_eq!(dashboard.summary.total_findings, 12 + 4);
    }

    #[test]
    fn summary_picks_most_effective_module() {
        let dashboard = full_builder().build();
        assert_eq!(dashboard.summary.most_effective_module, "fuzzer");
    }

    #[test]
    fn summary_picks_best_payload_class() {
        let dashboard = full_builder().build();
        assert_eq!(dashboard.summary.best_payload_class, "xss-generative");
    }

    #[test]
    fn summary_uses_endpoint_coverage_as_overall() {
        let dashboard = full_builder().build();
        let epsilon = 1e-10;
        assert!((dashboard.summary.overall_coverage_pct - 84.0).abs() < epsilon);
    }

    #[test]
    fn coverage_percentages_preserved() {
        let dashboard = full_builder().build();
        let epsilon = 1e-10;
        assert!((dashboard.coverage.endpoint_coverage_pct - 84.0).abs() < epsilon);
        assert!((dashboard.coverage.vuln_class_coverage_pct - 58.8).abs() < epsilon);
        assert_eq!(dashboard.coverage.tested_endpoints, 42);
        assert_eq!(dashboard.coverage.tested_vuln_classes, 20);
    }

    #[test]
    fn json_rendering_is_valid_json() {
        let dashboard = full_builder().build();
        let json_str = render_metrics_json(&dashboard);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert!(parsed.get("summary").is_some());
        assert!(parsed.get("phase_timings").is_some());
        assert!(parsed.get("module_findings").is_some());
        assert!(parsed.get("payload_effectiveness").is_some());
        assert!(parsed.get("coverage").is_some());
        assert!(parsed.get("resource_usage").is_some());
        assert!(parsed.get("trend").is_some());
    }

    #[test]
    fn json_roundtrip_preserves_data() {
        let original = full_builder().build();
        let json_str = render_metrics_json(&original);
        let restored: ScanMetricsDashboard = serde_json::from_str(&json_str).unwrap();

        assert_eq!(
            restored.summary.total_findings,
            original.summary.total_findings
        );
        assert_eq!(
            restored.summary.most_effective_module,
            original.summary.most_effective_module
        );
        assert_eq!(restored.phase_timings.len(), original.phase_timings.len());
        assert_eq!(restored.trend.len(), original.trend.len());
    }

    #[test]
    fn markdown_contains_key_sections() {
        let dashboard = full_builder().build();
        let md = render_metrics_markdown(&dashboard);

        assert!(md.contains("# Scan Metrics Dashboard"));
        assert!(md.contains("## Summary"));
        assert!(md.contains("## Phase Timings"));
        assert!(md.contains("## Module Findings"));
        assert!(md.contains("## Payload Effectiveness"));
        assert!(md.contains("## Coverage"));
        assert!(md.contains("## Resource Usage"));
        assert!(md.contains("## Scan Trend"));
    }

    #[test]
    fn markdown_contains_actual_data() {
        let dashboard = full_builder().build();
        let md = render_metrics_markdown(&dashboard);

        assert!(md.contains("recon"));
        assert!(md.contains("fuzz"));
        assert!(md.contains("fuzzer"));
        assert!(md.contains("crawler"));
        assert!(md.contains("sqli-template"));
        assert!(md.contains("xss-generative"));
        assert!(md.contains("84.0%"));
        assert!(md.contains("3400"));
    }

    #[test]
    fn empty_builder_produces_zeroed_dashboard() {
        let dashboard = ScanMetricsBuilder::new().build();

        assert!(dashboard.phase_timings.is_empty());
        assert!(dashboard.module_findings.is_empty());
        assert!(dashboard.payload_effectiveness.is_empty());
        assert!(dashboard.trend.is_empty());
        assert_eq!(dashboard.coverage.total_endpoints, 0);
        assert_eq!(dashboard.coverage.tested_endpoints, 0);
        let epsilon = 1e-10;
        assert!(dashboard.coverage.endpoint_coverage_pct.abs() < epsilon);
        assert_eq!(dashboard.resource_usage.total_requests, 0);
        assert_eq!(dashboard.resource_usage.total_bytes_transferred, 0);
        assert!(dashboard.summary.total_scan_duration_secs.abs() < epsilon);
        assert_eq!(dashboard.summary.total_findings, 0);
        assert!(dashboard.summary.most_effective_module.is_empty());
        assert!(dashboard.summary.best_payload_class.is_empty());
        assert!(dashboard.summary.overall_coverage_pct.abs() < epsilon);
    }

    #[test]
    fn single_module_is_most_effective() {
        let dashboard = ScanMetricsBuilder::new()
            .with_module_findings(ModuleFindings {
                module_name: "solo".to_string(),
                finding_count: 7,
                critical_count: 2,
                high_count: 3,
            })
            .build();

        assert_eq!(dashboard.summary.most_effective_module, "solo");
        assert_eq!(dashboard.summary.total_findings, 7);
    }

    #[test]
    fn single_payload_is_best() {
        let dashboard = ScanMetricsBuilder::new()
            .with_payload_effectiveness(PayloadEffectiveness {
                payload_class: "boundary-flip".to_string(),
                total_sent: 50,
                successful: 5,
                success_rate: 0.10,
            })
            .build();

        assert_eq!(dashboard.summary.best_payload_class, "boundary-flip");
    }

    #[test]
    fn multiple_trend_entries_preserved_in_order() {
        let early = ScanTrendEntry {
            scan_date: "2025-01-10".to_string(),
            total_findings: 20,
            critical_count: 5,
            risk_score: 80.0,
        };
        let late = ScanTrendEntry {
            scan_date: "2025-01-15".to_string(),
            total_findings: 12,
            critical_count: 2,
            risk_score: 55.0,
        };

        let dashboard = ScanMetricsBuilder::new()
            .with_trend_entry(early)
            .with_trend_entry(late)
            .build();

        assert_eq!(dashboard.trend.len(), 2);
        assert_eq!(dashboard.trend[0].scan_date, "2025-01-10");
        assert_eq!(dashboard.trend[1].scan_date, "2025-01-15");
    }

    #[test]
    fn phase_timing_optional_timestamps() {
        let timing = PhaseTiming {
            phase_name: "report".to_string(),
            duration_secs: 0.8,
            started_at: None,
            completed_at: None,
        };

        let dashboard = ScanMetricsBuilder::new().with_phase_timing(timing).build();

        assert!(dashboard.phase_timings[0].started_at.is_none());
        assert!(dashboard.phase_timings[0].completed_at.is_none());
        let epsilon = 1e-10;
        assert!((dashboard.summary.total_scan_duration_secs - 0.8).abs() < epsilon);
    }

    #[test]
    fn resource_usage_large_transfer() {
        let usage = ResourceUsage {
            total_requests: 100_000,
            total_bytes_transferred: 5_000_000_000,
            avg_time_per_endpoint_ms: 120.5,
            peak_concurrent_requests: 64,
        };

        let dashboard = ScanMetricsBuilder::new().with_resource_usage(usage).build();

        assert_eq!(
            dashboard.resource_usage.total_bytes_transferred,
            5_000_000_000
        );
        assert_eq!(dashboard.resource_usage.peak_concurrent_requests, 64);
    }
}
