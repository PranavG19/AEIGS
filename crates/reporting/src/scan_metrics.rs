use serde::{Deserialize, Serialize};

/// Wall-clock duration of a single scan phase.
///
/// `started_at` / `completed_at` use ISO 8601 strings so reports
/// stay human-readable without pulling in a datetime crate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseTiming {
    pub phase_name: String,
    pub duration_secs: f64,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
}

/// Finding counts attributed to a single detection module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleFindings {
    pub module_name: String,
    pub finding_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
}

/// Hit-rate statistics for one payload mutation class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadEffectiveness {
    pub payload_class: String,
    pub total_sent: usize,
    pub successful: usize,
    pub success_rate: f64,
}

/// Fraction of the attack surface actually exercised during a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageMetrics {
    pub total_endpoints: usize,
    pub tested_endpoints: usize,
    pub endpoint_coverage_pct: f64,
    pub total_vuln_classes: usize,
    pub tested_vuln_classes: usize,
    pub vuln_class_coverage_pct: f64,
}

/// Aggregate network and timing resource consumption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub total_requests: usize,
    pub total_bytes_transferred: u64,
    pub avg_time_per_endpoint_ms: f64,
    pub peak_concurrent_requests: usize,
}

/// Single data point in a multi-scan trend line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTrendEntry {
    pub scan_date: String,
    pub total_findings: usize,
    pub critical_count: usize,
    pub risk_score: f64,
}

/// Computed roll-up of the most important metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSummary {
    pub total_scan_duration_secs: f64,
    pub total_findings: usize,
    pub most_effective_module: String,
    pub best_payload_class: String,
    pub overall_coverage_pct: f64,
}

/// Top-level metrics dashboard aggregating every sub-metric.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetricsDashboard {
    pub phase_timings: Vec<PhaseTiming>,
    pub module_findings: Vec<ModuleFindings>,
    pub payload_effectiveness: Vec<PayloadEffectiveness>,
    pub coverage: CoverageMetrics,
    pub resource_usage: ResourceUsage,
    pub trend: Vec<ScanTrendEntry>,
    pub summary: MetricsSummary,
}

/// Incremental builder for assembling a `ScanMetricsDashboard`.
///
/// Collects sub-metrics via `with_*` methods, then `build()` computes
/// the `MetricsSummary` from the accumulated data.
pub struct ScanMetricsBuilder {
    phase_timings: Vec<PhaseTiming>,
    module_findings: Vec<ModuleFindings>,
    payload_effectiveness: Vec<PayloadEffectiveness>,
    coverage: Option<CoverageMetrics>,
    resource_usage: Option<ResourceUsage>,
    trend: Vec<ScanTrendEntry>,
}

impl Default for ScanMetricsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanMetricsBuilder {
    pub fn new() -> Self {
        Self {
            phase_timings: Vec::new(),
            module_findings: Vec::new(),
            payload_effectiveness: Vec::new(),
            coverage: None,
            resource_usage: None,
            trend: Vec::new(),
        }
    }

    pub fn with_phase_timing(mut self, timing: PhaseTiming) -> Self {
        self.phase_timings.push(timing);
        self
    }

    pub fn with_module_findings(mut self, mf: ModuleFindings) -> Self {
        self.module_findings.push(mf);
        self
    }

    pub fn with_payload_effectiveness(mut self, pe: PayloadEffectiveness) -> Self {
        self.payload_effectiveness.push(pe);
        self
    }

    pub fn with_coverage(mut self, coverage: CoverageMetrics) -> Self {
        self.coverage = Some(coverage);
        self
    }

    pub fn with_resource_usage(mut self, usage: ResourceUsage) -> Self {
        self.resource_usage = Some(usage);
        self
    }

    pub fn with_trend_entry(mut self, entry: ScanTrendEntry) -> Self {
        self.trend.push(entry);
        self
    }

    pub fn build(self) -> ScanMetricsDashboard {
        let summary = compute_summary(
            &self.phase_timings,
            &self.module_findings,
            &self.payload_effectiveness,
            &self.coverage,
        );

        let coverage = self.coverage.unwrap_or(CoverageMetrics {
            total_endpoints: 0,
            tested_endpoints: 0,
            endpoint_coverage_pct: 0.0,
            total_vuln_classes: 0,
            tested_vuln_classes: 0,
            vuln_class_coverage_pct: 0.0,
        });

        let resource_usage = self.resource_usage.unwrap_or(ResourceUsage {
            total_requests: 0,
            total_bytes_transferred: 0,
            avg_time_per_endpoint_ms: 0.0,
            peak_concurrent_requests: 0,
        });

        ScanMetricsDashboard {
            phase_timings: self.phase_timings,
            module_findings: self.module_findings,
            payload_effectiveness: self.payload_effectiveness,
            coverage,
            resource_usage,
            trend: self.trend,
            summary,
        }
    }
}

fn compute_summary(
    timings: &[PhaseTiming],
    modules: &[ModuleFindings],
    payloads: &[PayloadEffectiveness],
    coverage: &Option<CoverageMetrics>,
) -> MetricsSummary {
    let total_scan_duration_secs: f64 = timings.iter().map(|t| t.duration_secs).sum();

    let total_findings: usize = modules.iter().map(|m| m.finding_count).sum();

    let most_effective_module = modules
        .iter()
        .max_by_key(|m| m.finding_count)
        .map(|m| m.module_name.clone())
        .unwrap_or_default();

    let best_payload_class = payloads
        .iter()
        .max_by(|a, b| {
            a.success_rate
                .partial_cmp(&b.success_rate)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|p| p.payload_class.clone())
        .unwrap_or_default();

    let overall_coverage_pct = coverage
        .as_ref()
        .map(|c| c.endpoint_coverage_pct)
        .unwrap_or(0.0);

    MetricsSummary {
        total_scan_duration_secs,
        total_findings,
        most_effective_module,
        best_payload_class,
        overall_coverage_pct,
    }
}

/// Serialize the dashboard to pretty-printed JSON.
pub fn render_metrics_json(dashboard: &ScanMetricsDashboard) -> String {
    serde_json::to_string_pretty(dashboard).unwrap_or_default()
}

/// Render the dashboard as a human-readable Markdown report.
pub fn render_metrics_markdown(dashboard: &ScanMetricsDashboard) -> String {
    let mut md = String::with_capacity(2048);
    md.push_str("# Scan Metrics Dashboard\n\n");

    render_summary_section(&mut md, &dashboard.summary);
    render_phase_timings_section(&mut md, &dashboard.phase_timings);
    render_module_findings_section(&mut md, &dashboard.module_findings);
    render_payload_section(&mut md, &dashboard.payload_effectiveness);
    render_coverage_section(&mut md, &dashboard.coverage);
    render_resource_section(&mut md, &dashboard.resource_usage);
    render_trend_section(&mut md, &dashboard.trend);

    md
}

fn render_summary_section(md: &mut String, s: &MetricsSummary) {
    md.push_str("## Summary\n\n");
    md.push_str("| Metric | Value |\n|--------|-------|\n");
    md.push_str(&format!(
        "| Total Duration | {:.1}s |\n",
        s.total_scan_duration_secs
    ));
    md.push_str(&format!("| Total Findings | {} |\n", s.total_findings));
    md.push_str(&format!(
        "| Most Effective Module | {} |\n",
        s.most_effective_module
    ));
    md.push_str(&format!(
        "| Best Payload Class | {} |\n",
        s.best_payload_class
    ));
    md.push_str(&format!(
        "| Overall Coverage | {:.1}% |\n\n",
        s.overall_coverage_pct
    ));
}

fn render_phase_timings_section(md: &mut String, timings: &[PhaseTiming]) {
    md.push_str("## Phase Timings\n\n");
    md.push_str("| Phase | Duration (s) |\n|-------|-------------|\n");
    for t in timings {
        md.push_str(&format!("| {} | {:.2} |\n", t.phase_name, t.duration_secs));
    }
    md.push('\n');
}

fn render_module_findings_section(md: &mut String, modules: &[ModuleFindings]) {
    md.push_str("## Module Findings\n\n");
    md.push_str("| Module | Findings | Critical | High |\n");
    md.push_str("|--------|----------|----------|------|\n");
    for m in modules {
        md.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            m.module_name, m.finding_count, m.critical_count, m.high_count
        ));
    }
    md.push('\n');
}

fn render_payload_section(md: &mut String, payloads: &[PayloadEffectiveness]) {
    md.push_str("## Payload Effectiveness\n\n");
    md.push_str("| Class | Sent | Successful | Rate |\n");
    md.push_str("|-------|------|------------|------|\n");
    for p in payloads {
        md.push_str(&format!(
            "| {} | {} | {} | {:.1}% |\n",
            p.payload_class,
            p.total_sent,
            p.successful,
            p.success_rate * 100.0
        ));
    }
    md.push('\n');
}

fn render_coverage_section(md: &mut String, c: &CoverageMetrics) {
    md.push_str("## Coverage\n\n");
    md.push_str(&format!(
        "- Endpoints: {}/{} ({:.1}%)\n",
        c.tested_endpoints, c.total_endpoints, c.endpoint_coverage_pct
    ));
    md.push_str(&format!(
        "- Vulnerability Classes: {}/{} ({:.1}%)\n\n",
        c.tested_vuln_classes, c.total_vuln_classes, c.vuln_class_coverage_pct
    ));
}

fn render_resource_section(md: &mut String, r: &ResourceUsage) {
    md.push_str("## Resource Usage\n\n");
    md.push_str(&format!("- Total Requests: {}\n", r.total_requests));
    md.push_str(&format!(
        "- Data Transferred: {} bytes\n",
        r.total_bytes_transferred
    ));
    md.push_str(&format!(
        "- Avg Time/Endpoint: {:.1}ms\n",
        r.avg_time_per_endpoint_ms
    ));
    md.push_str(&format!(
        "- Peak Concurrency: {}\n\n",
        r.peak_concurrent_requests
    ));
}

fn render_trend_section(md: &mut String, trend: &[ScanTrendEntry]) {
    md.push_str("## Scan Trend\n\n");
    md.push_str("| Date | Findings | Critical | Risk Score |\n");
    md.push_str("|------|----------|----------|------------|\n");
    for e in trend {
        md.push_str(&format!(
            "| {} | {} | {} | {:.1} |\n",
            e.scan_date, e.total_findings, e.critical_count, e.risk_score
        ));
    }
    md.push('\n');
}

#[cfg(test)]
#[path = "scan_metrics_test.rs"]
mod scan_metrics_test;
