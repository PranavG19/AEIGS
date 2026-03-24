use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Represents a single finding for comparison purposes.
///
/// Two findings are "the same" if they share `endpoint` and `vulnerability_class`.
/// This identity rule drives new/resolved/changed/regression detection across scans.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub id: String,
    pub endpoint: String,
    pub vulnerability_class: String,
    pub severity: String,
    pub composite_score: f64,
    pub confidence: f64,
}

/// A complete scan result for comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: String,
    pub scan_date: String,
    pub target_url: String,
    pub findings: Vec<ScanFinding>,
    pub endpoints_discovered: Vec<String>,
}

/// A finding whose severity or score changed between scans.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangedFinding {
    pub endpoint: String,
    pub vulnerability_class: String,
    pub previous_severity: String,
    pub current_severity: String,
    pub previous_score: f64,
    pub current_score: f64,
    pub score_delta: f64,
}

/// A finding that was previously resolved but reappeared.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionFinding {
    pub endpoint: String,
    pub vulnerability_class: String,
    pub current_severity: String,
    pub current_score: f64,
}

/// Complete comparison between two scans.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanComparison {
    pub previous_scan_id: String,
    pub current_scan_id: String,
    pub new_findings: Vec<ScanFinding>,
    pub resolved_findings: Vec<ScanFinding>,
    pub changed_findings: Vec<ChangedFinding>,
    pub new_endpoints: Vec<String>,
    pub removed_endpoints: Vec<String>,
    pub regressions: Vec<RegressionFinding>,
    pub delta_summary: DeltaSummary,
}

/// Concise summary of what changed between two scans.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaSummary {
    pub findings_added: usize,
    pub findings_resolved: usize,
    pub findings_changed: usize,
    pub endpoints_added: usize,
    pub endpoints_removed: usize,
    pub regressions_detected: usize,
    pub risk_trend: String,
    pub summary_text: String,
}

/// Finding identity key: (endpoint, vulnerability_class).
fn finding_key(f: &ScanFinding) -> (String, String) {
    (f.endpoint.clone(), f.vulnerability_class.clone())
}

/// Compare two scan results and produce a full delta analysis.
pub fn compare_scans(previous: &ScanResult, current: &ScanResult) -> ScanComparison {
    let new_findings = compute_new_findings(previous, current);
    let resolved_findings = compute_resolved_findings(previous, current);
    let changed_findings = compute_changed_findings(previous, current);
    let (new_endpoints, removed_endpoints) = compute_endpoint_diff(previous, current);
    let regressions = detect_regressions(previous, current, &resolved_findings);
    let risk_trend = compute_risk_trend(previous, current);
    let summary_text = build_summary_text(
        &new_findings,
        &resolved_findings,
        &changed_findings,
        &regressions,
        &risk_trend,
    );

    let delta_summary = DeltaSummary {
        findings_added: new_findings.len(),
        findings_resolved: resolved_findings.len(),
        findings_changed: changed_findings.len(),
        endpoints_added: new_endpoints.len(),
        endpoints_removed: removed_endpoints.len(),
        regressions_detected: regressions.len(),
        risk_trend,
        summary_text,
    };

    ScanComparison {
        previous_scan_id: previous.scan_id.clone(),
        current_scan_id: current.scan_id.clone(),
        new_findings,
        resolved_findings,
        changed_findings,
        new_endpoints,
        removed_endpoints,
        regressions,
        delta_summary,
    }
}

/// Findings present in current but absent from previous.
fn compute_new_findings(previous: &ScanResult, current: &ScanResult) -> Vec<ScanFinding> {
    let prev_keys: HashSet<(String, String)> = previous.findings.iter().map(finding_key).collect();
    current
        .findings
        .iter()
        .filter(|f| !prev_keys.contains(&finding_key(f)))
        .cloned()
        .collect()
}

/// Findings present in previous but absent from current.
fn compute_resolved_findings(previous: &ScanResult, current: &ScanResult) -> Vec<ScanFinding> {
    let curr_keys: HashSet<(String, String)> = current.findings.iter().map(finding_key).collect();
    previous
        .findings
        .iter()
        .filter(|f| !curr_keys.contains(&finding_key(f)))
        .cloned()
        .collect()
}

/// Findings present in both scans but with different severity or score.
fn compute_changed_findings(previous: &ScanResult, current: &ScanResult) -> Vec<ChangedFinding> {
    let prev_map: std::collections::HashMap<(String, String), &ScanFinding> = previous
        .findings
        .iter()
        .map(|f| (finding_key(f), f))
        .collect();

    current
        .findings
        .iter()
        .filter_map(|curr| {
            let key = finding_key(curr);
            let prev = prev_map.get(&key)?;
            let severity_changed = prev.severity != curr.severity;
            let score_delta = curr.composite_score - prev.composite_score;
            let score_changed = score_delta.abs() > f64::EPSILON;
            if severity_changed || score_changed {
                Some(ChangedFinding {
                    endpoint: curr.endpoint.clone(),
                    vulnerability_class: curr.vulnerability_class.clone(),
                    previous_severity: prev.severity.clone(),
                    current_severity: curr.severity.clone(),
                    previous_score: prev.composite_score,
                    current_score: curr.composite_score,
                    score_delta,
                })
            } else {
                None
            }
        })
        .collect()
}

/// Compute endpoint additions and removals between scans.
fn compute_endpoint_diff(
    previous: &ScanResult,
    current: &ScanResult,
) -> (Vec<String>, Vec<String>) {
    let prev_set: HashSet<&str> = previous
        .endpoints_discovered
        .iter()
        .map(String::as_str)
        .collect();
    let curr_set: HashSet<&str> = current
        .endpoints_discovered
        .iter()
        .map(String::as_str)
        .collect();

    let new: Vec<String> = curr_set
        .difference(&prev_set)
        .map(|s| s.to_string())
        .collect();
    let removed: Vec<String> = prev_set
        .difference(&curr_set)
        .map(|s| s.to_string())
        .collect();
    (new, removed)
}

/// Detect regressions: findings that were in `resolved_history` but reappeared in current.
///
/// A regression occurs when a vulnerability was previously resolved (appeared in a prior
/// scan but not the subsequent one) yet surfaces again in the current scan.
pub fn detect_regressions(
    _previous: &ScanResult,
    current: &ScanResult,
    resolved_history: &[ScanFinding],
) -> Vec<RegressionFinding> {
    let current_keys: HashSet<(String, String)> =
        current.findings.iter().map(finding_key).collect();

    resolved_history
        .iter()
        .filter_map(|resolved| {
            let key = finding_key(resolved);
            if !current_keys.contains(&key) {
                return None;
            }
            let current_finding = current.findings.iter().find(|f| finding_key(f) == key)?;
            Some(RegressionFinding {
                endpoint: current_finding.endpoint.clone(),
                vulnerability_class: current_finding.vulnerability_class.clone(),
                current_severity: current_finding.severity.clone(),
                current_score: current_finding.composite_score,
            })
        })
        .collect()
}

/// Determine whether the security posture is improving, degrading, or stable.
///
/// Logic:
/// - More findings OR higher max composite score → "degrading"
/// - Fewer findings AND lower/equal max score → "improving"
/// - Same count AND similar max scores (within ±1.0) → "stable"
pub fn compute_risk_trend(previous: &ScanResult, current: &ScanResult) -> String {
    let prev_count = previous.findings.len();
    let curr_count = current.findings.len();
    let prev_max = max_composite_score(&previous.findings);
    let curr_max = max_composite_score(&current.findings);

    if curr_count > prev_count || curr_max > prev_max + 1.0 {
        return "degrading".to_string();
    }
    if curr_count < prev_count && curr_max <= prev_max + f64::EPSILON {
        return "improving".to_string();
    }
    if curr_count == prev_count && (curr_max - prev_max).abs() <= 1.0 {
        return "stable".to_string();
    }
    // Fewer findings but higher max score: net stable
    "stable".to_string()
}

fn max_composite_score(findings: &[ScanFinding]) -> f64 {
    findings
        .iter()
        .map(|f| f.composite_score)
        .fold(0.0_f64, f64::max)
}

fn build_summary_text(
    new: &[ScanFinding],
    resolved: &[ScanFinding],
    changed: &[ChangedFinding],
    regressions: &[RegressionFinding],
    risk_trend: &str,
) -> String {
    let mut parts: Vec<String> = Vec::new();

    if !new.is_empty() {
        parts.push(format!("{} new finding(s)", new.len()));
    }
    if !resolved.is_empty() {
        parts.push(format!("{} resolved", resolved.len()));
    }
    if !changed.is_empty() {
        parts.push(format!("{} changed", changed.len()));
    }
    if !regressions.is_empty() {
        parts.push(format!("{} regression(s)", regressions.len()));
    }

    if parts.is_empty() {
        return format!("No changes detected. Risk trend: {risk_trend}.");
    }

    format!("{}. Risk trend: {risk_trend}.", parts.join(", "))
}

/// Serialize a `ScanComparison` to pretty-printed JSON.
pub fn render_comparison_json(comparison: &ScanComparison) -> String {
    serde_json::to_string_pretty(comparison)
        .unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {e}\"}}"))
}

/// Render a `ScanComparison` as a human-readable Markdown report.
pub fn render_comparison_markdown(comparison: &ScanComparison) -> String {
    let mut md = String::new();
    md.push_str(&format!(
        "# Scan Comparison: {} → {}\n\n",
        comparison.previous_scan_id, comparison.current_scan_id
    ));

    append_summary_section(&mut md, &comparison.delta_summary);
    append_new_findings_section(&mut md, &comparison.new_findings);
    append_resolved_findings_section(&mut md, &comparison.resolved_findings);
    append_changed_findings_section(&mut md, &comparison.changed_findings);
    append_regressions_section(&mut md, &comparison.regressions);
    append_endpoints_section(
        &mut md,
        &comparison.new_endpoints,
        &comparison.removed_endpoints,
    );

    md
}

fn append_summary_section(md: &mut String, summary: &DeltaSummary) {
    md.push_str("## Summary\n\n");
    md.push_str(&format!("- **Risk trend:** {}\n", summary.risk_trend));
    md.push_str(&format!("- **New findings:** {}\n", summary.findings_added));
    md.push_str(&format!("- **Resolved:** {}\n", summary.findings_resolved));
    md.push_str(&format!("- **Changed:** {}\n", summary.findings_changed));
    md.push_str(&format!(
        "- **Regressions:** {}\n",
        summary.regressions_detected
    ));
    md.push_str(&format!(
        "- **Endpoints added:** {}\n",
        summary.endpoints_added
    ));
    md.push_str(&format!(
        "- **Endpoints removed:** {}\n\n",
        summary.endpoints_removed
    ));
    md.push_str(&format!("{}\n\n", summary.summary_text));
}

fn append_new_findings_section(md: &mut String, findings: &[ScanFinding]) {
    if findings.is_empty() {
        return;
    }
    md.push_str("## New Findings\n\n");
    md.push_str("| Endpoint | Vulnerability | Severity | Score |\n");
    md.push_str("|----------|--------------|----------|-------|\n");
    for f in findings {
        md.push_str(&format!(
            "| {} | {} | {} | {:.1} |\n",
            f.endpoint, f.vulnerability_class, f.severity, f.composite_score
        ));
    }
    md.push('\n');
}

fn append_resolved_findings_section(md: &mut String, findings: &[ScanFinding]) {
    if findings.is_empty() {
        return;
    }
    md.push_str("## Resolved Findings\n\n");
    md.push_str("| Endpoint | Vulnerability | Previous Severity |\n");
    md.push_str("|----------|--------------|-------------------|\n");
    for f in findings {
        md.push_str(&format!(
            "| {} | {} | {} |\n",
            f.endpoint, f.vulnerability_class, f.severity
        ));
    }
    md.push('\n');
}

fn append_changed_findings_section(md: &mut String, findings: &[ChangedFinding]) {
    if findings.is_empty() {
        return;
    }
    md.push_str("## Changed Findings\n\n");
    md.push_str("| Endpoint | Vulnerability | Severity | Score Delta |\n");
    md.push_str("|----------|--------------|----------|-------------|\n");
    for f in findings {
        md.push_str(&format!(
            "| {} | {} | {} → {} | {:+.1} |\n",
            f.endpoint,
            f.vulnerability_class,
            f.previous_severity,
            f.current_severity,
            f.score_delta
        ));
    }
    md.push('\n');
}

fn append_regressions_section(md: &mut String, regressions: &[RegressionFinding]) {
    if regressions.is_empty() {
        return;
    }
    md.push_str("## Regressions\n\n");
    md.push_str("| Endpoint | Vulnerability | Severity | Score |\n");
    md.push_str("|----------|--------------|----------|-------|\n");
    for r in regressions {
        md.push_str(&format!(
            "| {} | {} | {} | {:.1} |\n",
            r.endpoint, r.vulnerability_class, r.current_severity, r.current_score
        ));
    }
    md.push('\n');
}

fn append_endpoints_section(md: &mut String, new_eps: &[String], removed_eps: &[String]) {
    if new_eps.is_empty() && removed_eps.is_empty() {
        return;
    }
    md.push_str("## Endpoint Changes\n\n");
    if !new_eps.is_empty() {
        md.push_str("**New endpoints:**\n");
        for ep in new_eps {
            md.push_str(&format!("- {ep}\n"));
        }
        md.push('\n');
    }
    if !removed_eps.is_empty() {
        md.push_str("**Removed endpoints:**\n");
        for ep in removed_eps {
            md.push_str(&format!("- {ep}\n"));
        }
        md.push('\n');
    }
}

#[cfg(test)]
#[path = "scan_comparison_test.rs"]
mod scan_comparison_test;
