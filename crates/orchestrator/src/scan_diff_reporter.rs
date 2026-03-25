use aegis_protocol::finding::VulnerabilityClass;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Status of a finding between two scan runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingStatus {
    New,
    Resolved,
    SeverityChanged,
    Unchanged,
}

impl FindingStatus {
    /// Returns a color label for display/reporting.
    pub fn color_label(self) -> &'static str {
        match self {
            FindingStatus::New => "red",
            FindingStatus::Resolved => "green",
            FindingStatus::SeverityChanged => "yellow",
            FindingStatus::Unchanged => "gray",
        }
    }
}

/// A finding's severity score for diff comparison.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct SeverityScore(pub f64);

/// A normalized representation of a finding for comparison across scans.
///
/// Two `DiffFinding` values with the same `fingerprint` are considered the
/// same finding across runs, enabling new/resolved/changed tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffFinding {
    pub fingerprint: String,
    pub endpoint: String,
    pub vulnerability_class: VulnerabilityClass,
    pub severity_score: SeverityScore,
    pub title: String,
    pub first_seen_ms: u64,
}

/// A single entry in the diff report, pairing a finding with its status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    pub finding: DiffFinding,
    pub status: FindingStatus,
    pub previous_severity: Option<SeverityScore>,
    pub time_to_fix_ms: Option<u64>,
}

/// Summary statistics for a scan diff.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiffSummary {
    pub total_current: usize,
    pub total_previous: usize,
    pub new_count: usize,
    pub resolved_count: usize,
    pub severity_changed_count: usize,
    pub unchanged_count: usize,
    pub net_change: i64,
    pub findings_by_class: HashMap<String, ClassSummary>,
}

/// Per-vulnerability-class breakdown.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClassSummary {
    pub new_count: usize,
    pub resolved_count: usize,
    pub unchanged_count: usize,
    pub severity_changed_count: usize,
}

/// Trend data point for time-series visualization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendPoint {
    pub timestamp_ms: u64,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

/// The complete scan-over-scan diff report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDiffReport {
    pub target_url: String,
    pub baseline_scan_timestamp_ms: u64,
    pub current_scan_timestamp_ms: u64,
    pub entries: Vec<DiffEntry>,
    pub summary: DiffSummary,
    pub trend_data: Vec<TrendPoint>,
}

impl ScanDiffReport {
    /// Returns entries filtered to a specific status.
    pub fn entries_with_status(&self, status: FindingStatus) -> Vec<&DiffEntry> {
        self.entries.iter().filter(|e| e.status == status).collect()
    }

    /// Returns the average time-to-fix for resolved findings, if any.
    pub fn average_time_to_fix_ms(&self) -> Option<u64> {
        let fixes: Vec<u64> = self
            .entries
            .iter()
            .filter_map(|e| e.time_to_fix_ms)
            .collect();
        if fixes.is_empty() {
            return None;
        }
        Some(fixes.iter().sum::<u64>() / fixes.len() as u64)
    }
}

/// Generates diff reports between scan results.
pub struct ScanDiffReporter;

impl ScanDiffReporter {
    pub fn new() -> Self {
        Self
    }

    /// Compares baseline findings against current findings and produces a diff report.
    ///
    /// Findings are matched by their `fingerprint` field. Findings present in
    /// current but not baseline are `New`; present in baseline but not current
    /// are `Resolved`; present in both with different severity are `SeverityChanged`;
    /// otherwise `Unchanged`.
    pub fn generate_diff(
        &self,
        target_url: &str,
        baseline_timestamp_ms: u64,
        current_timestamp_ms: u64,
        baseline_findings: &[DiffFinding],
        current_findings: &[DiffFinding],
        historical_trend: Vec<TrendPoint>,
    ) -> ScanDiffReport {
        let baseline_map: HashMap<&str, &DiffFinding> = baseline_findings
            .iter()
            .map(|f| (f.fingerprint.as_str(), f))
            .collect();
        let current_map: HashMap<&str, &DiffFinding> = current_findings
            .iter()
            .map(|f| (f.fingerprint.as_str(), f))
            .collect();

        let baseline_fps: HashSet<&str> = baseline_map.keys().copied().collect();
        let current_fps: HashSet<&str> = current_map.keys().copied().collect();

        let mut entries = Vec::new();

        for fp in &current_fps {
            let current = current_map[*fp];
            if let Some(prev) = baseline_map.get(*fp) {
                if (current.severity_score.0 - prev.severity_score.0).abs() > f64::EPSILON {
                    entries.push(DiffEntry {
                        finding: current.clone(),
                        status: FindingStatus::SeverityChanged,
                        previous_severity: Some(prev.severity_score),
                        time_to_fix_ms: None,
                    });
                } else {
                    entries.push(DiffEntry {
                        finding: current.clone(),
                        status: FindingStatus::Unchanged,
                        previous_severity: None,
                        time_to_fix_ms: None,
                    });
                }
            } else {
                entries.push(DiffEntry {
                    finding: current.clone(),
                    status: FindingStatus::New,
                    previous_severity: None,
                    time_to_fix_ms: None,
                });
            }
        }

        for fp in baseline_fps.difference(&current_fps) {
            let prev = baseline_map[*fp];
            let ttf = current_timestamp_ms.saturating_sub(prev.first_seen_ms);
            entries.push(DiffEntry {
                finding: prev.clone(),
                status: FindingStatus::Resolved,
                previous_severity: Some(prev.severity_score),
                time_to_fix_ms: Some(ttf),
            });
        }

        let summary =
            self.compute_summary(&entries, baseline_findings.len(), current_findings.len());

        ScanDiffReport {
            target_url: target_url.to_string(),
            baseline_scan_timestamp_ms: baseline_timestamp_ms,
            current_scan_timestamp_ms: current_timestamp_ms,
            entries,
            summary,
            trend_data: historical_trend,
        }
    }

    fn compute_summary(
        &self,
        entries: &[DiffEntry],
        total_previous: usize,
        total_current: usize,
    ) -> DiffSummary {
        let mut summary = DiffSummary {
            total_current,
            total_previous,
            ..Default::default()
        };

        for entry in entries {
            let class_key = entry.finding.vulnerability_class.to_string();
            let class_summary = summary.findings_by_class.entry(class_key).or_default();

            match entry.status {
                FindingStatus::New => {
                    summary.new_count += 1;
                    class_summary.new_count += 1;
                }
                FindingStatus::Resolved => {
                    summary.resolved_count += 1;
                    class_summary.resolved_count += 1;
                }
                FindingStatus::SeverityChanged => {
                    summary.severity_changed_count += 1;
                    class_summary.severity_changed_count += 1;
                }
                FindingStatus::Unchanged => {
                    summary.unchanged_count += 1;
                    class_summary.unchanged_count += 1;
                }
            }
        }

        summary.net_change = total_current as i64 - total_previous as i64;
        summary
    }
}

impl Default for ScanDiffReporter {
    fn default() -> Self {
        Self::new()
    }
}
