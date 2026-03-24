use std::collections::HashMap;
use std::path::Path;

use aegis_protocol::finding::{EvidenceLevel, FindingData, FindingId, VulnerabilityClass};
use aegis_protocol::operation::ModuleIdentifier;
use serde::{Deserialize, Serialize};

/// A single finding snapshot stored in a regression baseline.
///
/// Contains only the content-addressed identity and the properties that
/// matter for regression comparison: vulnerability class, endpoint,
/// parameter, evidence level, and composite confidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BaselineFinding {
    pub finding_id: FindingId,
    pub endpoint: String,
    pub parameter: String,
    pub vulnerability_class: VulnerabilityClass,
    pub evidence_level: EvidenceLevel,
    pub confidence: f64,
}

/// Serialized snapshot of findings from a fixture scan, used as the
/// expected state for regression comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionBaseline {
    pub fixture_name: String,
    pub created_at_unix_ms: u64,
    pub aegis_version: String,
    pub findings: Vec<BaselineFinding>,
}

impl RegressionBaseline {
    /// Builds a baseline from raw scan findings.
    ///
    /// Each finding must already carry a `stable_id` (content-addressed).
    /// Findings without a stable_id are assigned one from the provided
    /// endpoint and parameter closures.
    pub fn from_findings(
        fixture_name: &str,
        findings: &[ScanFinding],
        aegis_version: &str,
    ) -> Self {
        let created_at_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let baseline_findings: Vec<BaselineFinding> = findings
            .iter()
            .map(|sf| {
                let finding_id = sf.finding.stable_id.unwrap_or_else(|| {
                    FindingId::from_parts(
                        &sf.endpoint,
                        sf.finding.vulnerability_class,
                        &sf.parameter,
                    )
                });
                BaselineFinding {
                    finding_id,
                    endpoint: sf.endpoint.clone(),
                    parameter: sf.parameter.clone(),
                    vulnerability_class: sf.finding.vulnerability_class,
                    evidence_level: sf.finding.evidence_level,
                    confidence: sf.finding.confidence.composite.value(),
                }
            })
            .collect();

        Self {
            fixture_name: fixture_name.to_string(),
            created_at_unix_ms,
            aegis_version: aegis_version.to_string(),
            findings: baseline_findings,
        }
    }

    /// Loads a baseline from a JSON file on disk.
    pub fn load(path: &Path) -> Result<Self, RegressionError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| RegressionError::Io(e.to_string()))?;
        serde_json::from_str(&content).map_err(|e| RegressionError::Parse(e.to_string()))
    }

    /// Saves the baseline as a JSON file to disk.
    pub fn save(&self, path: &Path) -> Result<(), RegressionError> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| RegressionError::Serialize(e.to_string()))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| RegressionError::Io(e.to_string()))?;
        }
        std::fs::write(path, json).map_err(|e| RegressionError::Io(e.to_string()))
    }

    /// Returns a lookup map from FindingId to the baseline finding.
    fn by_id(&self) -> HashMap<FindingId, &BaselineFinding> {
        self.findings.iter().map(|f| (f.finding_id, f)).collect()
    }
}

/// A finding paired with its endpoint and parameter context, ready for
/// baseline comparison.
#[derive(Debug, Clone)]
pub struct ScanFinding {
    pub finding: FindingData,
    pub endpoint: String,
    pub parameter: String,
}

/// Threshold configuration for confidence drift detection.
#[derive(Debug, Clone, Copy)]
pub struct DriftThreshold {
    pub absolute: f64,
}

impl Default for DriftThreshold {
    fn default() -> Self {
        Self { absolute: 0.1 }
    }
}

/// A finding that was present in the baseline but is missing from the
/// current scan — a regression.
#[derive(Debug, Clone)]
pub struct MissingFinding {
    pub finding_id: FindingId,
    pub endpoint: String,
    pub parameter: String,
    pub vulnerability_class: VulnerabilityClass,
    pub baseline_confidence: f64,
}

/// A finding present in the current scan but absent from the baseline.
#[derive(Debug, Clone)]
pub struct NewFinding {
    pub finding_id: FindingId,
    pub endpoint: String,
    pub parameter: String,
    pub vulnerability_class: VulnerabilityClass,
    pub confidence: f64,
}

/// A finding whose confidence score changed beyond the drift threshold.
#[derive(Debug, Clone)]
pub struct DriftedFinding {
    pub finding_id: FindingId,
    pub endpoint: String,
    pub vulnerability_class: VulnerabilityClass,
    pub baseline_confidence: f64,
    pub current_confidence: f64,
    pub delta: f64,
}

/// The structured diff between a baseline and a current scan.
#[derive(Debug, Clone)]
pub struct RegressionReport {
    pub fixture_name: String,
    pub baseline_count: usize,
    pub current_count: usize,
    pub missing: Vec<MissingFinding>,
    pub new: Vec<NewFinding>,
    pub drifted: Vec<DriftedFinding>,
    pub unchanged: usize,
}

impl RegressionReport {
    /// A regression is detected when any baseline finding is missing.
    pub fn has_regressions(&self) -> bool {
        !self.missing.is_empty()
    }

    /// Returns true if new findings were discovered not in the baseline.
    pub fn has_new_findings(&self) -> bool {
        !self.new.is_empty()
    }

    /// Returns true if any findings drifted beyond threshold.
    pub fn has_drift(&self) -> bool {
        !self.drifted.is_empty()
    }

    /// Formats the report as a human-readable string.
    pub fn format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("=== Regression Report: {} ===", self.fixture_name));
        lines.push(format!(
            "Baseline: {} findings, Current: {} findings",
            self.baseline_count, self.current_count
        ));
        lines.push(format!(
            "Unchanged: {}, Missing: {}, New: {}, Drifted: {}",
            self.unchanged,
            self.missing.len(),
            self.new.len(),
            self.drifted.len()
        ));

        if !self.missing.is_empty() {
            lines.push(String::new());
            lines.push("REGRESSIONS (missing findings):".to_string());
            for m in &self.missing {
                lines.push(format!(
                    "  [-] {} at {} (confidence: {:.2})",
                    m.vulnerability_class, m.endpoint, m.baseline_confidence
                ));
            }
        }

        if !self.new.is_empty() {
            lines.push(String::new());
            lines.push("NEW findings (not in baseline):".to_string());
            for n in &self.new {
                lines.push(format!(
                    "  [+] {} at {} (confidence: {:.2})",
                    n.vulnerability_class, n.endpoint, n.confidence
                ));
            }
        }

        if !self.drifted.is_empty() {
            lines.push(String::new());
            lines.push("CONFIDENCE DRIFT:".to_string());
            for d in &self.drifted {
                let direction = if d.delta > 0.0 { "+" } else { "" };
                lines.push(format!(
                    "  [~] {} at {}: {:.2} -> {:.2} ({}{:.2})",
                    d.vulnerability_class,
                    d.endpoint,
                    d.baseline_confidence,
                    d.current_confidence,
                    direction,
                    d.delta
                ));
            }
        }

        lines.join("\n")
    }
}

/// Compares current scan findings against a regression baseline.
///
/// Matching is performed by content-addressed `FindingId`. Findings
/// missing from the current scan are regressions. Findings in the
/// current scan but not the baseline are flagged as new. Matched
/// findings whose confidence moved beyond `drift_threshold` are
/// reported as drifted.
pub struct RegressionRunner {
    pub drift_threshold: DriftThreshold,
}

impl RegressionRunner {
    pub fn new(drift_threshold: DriftThreshold) -> Self {
        Self { drift_threshold }
    }

    pub fn with_default_threshold() -> Self {
        Self {
            drift_threshold: DriftThreshold::default(),
        }
    }

    /// Runs the regression comparison and produces a structured report.
    pub fn compare(
        &self,
        baseline: &RegressionBaseline,
        current_findings: &[ScanFinding],
    ) -> RegressionReport {
        let baseline_map = baseline.by_id();

        let current_map: HashMap<FindingId, &ScanFinding> = current_findings
            .iter()
            .map(|sf| {
                let id = sf.finding.stable_id.unwrap_or_else(|| {
                    FindingId::from_parts(
                        &sf.endpoint,
                        sf.finding.vulnerability_class,
                        &sf.parameter,
                    )
                });
                (id, sf)
            })
            .collect();

        let mut missing = Vec::new();
        let mut drifted = Vec::new();
        let mut unchanged = 0usize;

        for (id, baseline_finding) in &baseline_map {
            match current_map.get(id) {
                None => {
                    missing.push(MissingFinding {
                        finding_id: *id,
                        endpoint: baseline_finding.endpoint.clone(),
                        parameter: baseline_finding.parameter.clone(),
                        vulnerability_class: baseline_finding.vulnerability_class,
                        baseline_confidence: baseline_finding.confidence,
                    });
                }
                Some(current_sf) => {
                    let current_confidence = current_sf.finding.confidence.composite.value();
                    let delta = current_confidence - baseline_finding.confidence;
                    if delta.abs() > self.drift_threshold.absolute {
                        drifted.push(DriftedFinding {
                            finding_id: *id,
                            endpoint: baseline_finding.endpoint.clone(),
                            vulnerability_class: baseline_finding.vulnerability_class,
                            baseline_confidence: baseline_finding.confidence,
                            current_confidence,
                            delta,
                        });
                    } else {
                        unchanged += 1;
                    }
                }
            }
        }

        let mut new_findings = Vec::new();
        for (id, sf) in &current_map {
            if !baseline_map.contains_key(id) {
                new_findings.push(NewFinding {
                    finding_id: *id,
                    endpoint: sf.endpoint.clone(),
                    parameter: sf.parameter.clone(),
                    vulnerability_class: sf.finding.vulnerability_class,
                    confidence: sf.finding.confidence.composite.value(),
                });
            }
        }

        RegressionReport {
            fixture_name: baseline.fixture_name.clone(),
            baseline_count: baseline.findings.len(),
            current_count: current_findings.len(),
            missing,
            new: new_findings,
            drifted,
            unchanged,
        }
    }
}

#[derive(Debug)]
pub enum RegressionError {
    Io(String),
    Parse(String),
    Serialize(String),
}

impl std::fmt::Display for RegressionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::Parse(msg) => write!(f, "parse error: {msg}"),
            Self::Serialize(msg) => write!(f, "serialization error: {msg}"),
        }
    }
}

impl std::error::Error for RegressionError {}

/// Convenience helper: builds a `ScanFinding` from parts.
pub fn make_scan_finding(
    endpoint: &str,
    parameter: &str,
    vulnerability_class: VulnerabilityClass,
    confidence: f64,
    evidence_level: EvidenceLevel,
) -> ScanFinding {
    let finding = FindingData::new(
        0,
        vulnerability_class,
        7.0,
        confidence,
        ModuleIdentifier::Fuzzing,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
    )
    .with_evidence_level(evidence_level)
    .with_stable_id(endpoint, parameter);

    ScanFinding {
        finding,
        endpoint: endpoint.to_string(),
        parameter: parameter.to_string(),
    }
}

#[cfg(test)]
#[path = "scan_regression_test.rs"]
mod scan_regression_test;
