use serde::Serialize;

use crate::sarif_emitter::{
    SarifFinding, attack_technique_for, cwe_for, emit_sarif, remediation_for, sarif_to_json,
};

/// Report output format, selectable per user persona.
///
/// Each variant emphasizes different aspects of the same findings:
/// - `Developer` — IDE-compatible SARIF with inline fix suggestions
/// - `Security` — SARIF enriched with ATT&CK chains and defense gap analysis
/// - `Executive` — High-level summary JSON with risk ratings and remediation priorities
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Developer,
    Security,
    Executive,
}

/// Defense posture summary passed into executive reports.
#[derive(Debug, Clone, Default)]
pub struct DefenseSummary {
    pub has_waf: bool,
    pub waf_vendor: Option<String>,
    pub has_rate_limiting: bool,
    pub has_bot_detection: bool,
}

/// Lightweight scan metadata for report generation.
///
/// Decoupled from orchestrator's `ScanMetrics` so the reporting crate
/// does not depend on the orchestrator.
#[derive(Debug, Clone, Default)]
pub struct ReportMetadata {
    pub target_url: String,
    pub total_duration_secs: f64,
    pub phases_completed: u32,
}

/// Format findings according to the selected report persona.
///
/// Returns the formatted report as a JSON string. Developer and Security
/// formats produce SARIF 2.1.0 JSON; Executive format produces a simpler
/// summary JSON document.
pub fn format_report(
    findings: &[SarifFinding],
    format: ReportFormat,
    tool_version: &str,
    metadata: Option<&ReportMetadata>,
    defense_summary: Option<&DefenseSummary>,
) -> Result<String, String> {
    match format {
        ReportFormat::Developer => format_developer(findings, tool_version),
        ReportFormat::Security => format_security(findings, tool_version),
        ReportFormat::Executive => {
            format_executive(findings, tool_version, metadata, defense_summary)
        }
    }
}

/// Parse a CLI string into a `ReportFormat`.
pub fn parse_report_format(s: &str) -> Result<ReportFormat, String> {
    match s {
        "developer" => Ok(ReportFormat::Developer),
        "security" => Ok(ReportFormat::Security),
        "executive" => Ok(ReportFormat::Executive),
        _ => Err(format!(
            "unknown report format '{s}': expected developer, security, or executive"
        )),
    }
}

fn format_developer(findings: &[SarifFinding], tool_version: &str) -> Result<String, String> {
    let sarif_log = emit_sarif(findings, tool_version);
    sarif_to_json(&sarif_log).map_err(|e| e.to_string())
}

fn format_security(findings: &[SarifFinding], tool_version: &str) -> Result<String, String> {
    let sarif_log = emit_sarif(findings, tool_version);
    let mut json_value: serde_json::Value =
        serde_json::to_value(&sarif_log).map_err(|e| e.to_string())?;
    inject_security_properties(&mut json_value, findings);
    serde_json::to_string_pretty(&json_value).map_err(|e| e.to_string())
}

fn inject_security_properties(sarif_json: &mut serde_json::Value, findings: &[SarifFinding]) {
    let Some(run) = sarif_json
        .get_mut("runs")
        .and_then(|r| r.as_array_mut())
        .and_then(|a| a.first_mut())
    else {
        return;
    };

    let Some(run_obj) = run.as_object_mut() else {
        return;
    };
    let entry = run_obj
        .entry("properties")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    let Some(props) = entry.as_object_mut() else {
        return;
    };

    props.insert(
        "securityAnalysis".to_string(),
        build_security_analysis(findings),
    );
}

fn build_security_analysis(findings: &[SarifFinding]) -> serde_json::Value {
    let attack_chains = build_attack_chains(findings);
    let defense_gaps = build_defense_gaps(findings);
    let finding_correlations = build_finding_correlations(findings);

    serde_json::json!({
        "attackChains": attack_chains,
        "defenseGaps": defense_gaps,
        "findingCorrelations": finding_correlations,
    })
}

fn build_attack_chains(findings: &[SarifFinding]) -> Vec<serde_json::Value> {
    findings
        .iter()
        .filter_map(|f| {
            let vc = f.vulnerability_class.as_ref()?;
            Some(serde_json::json!({
                "ruleId": f.rule_id,
                "techniqueId": attack_technique_for(vc),
                "cwe": cwe_for(vc),
                "exploitabilityScore": f.severity,
                "compositeScore": f.composite_score,
            }))
        })
        .collect()
}

fn build_defense_gaps(findings: &[SarifFinding]) -> serde_json::Value {
    let mut defenses_detected: Vec<String> = Vec::new();
    let mut defenses_bypassed: Vec<String> = Vec::new();

    for f in findings {
        let Some(dc) = &f.defense_context else {
            continue;
        };
        for defense in &dc.defenses_detected {
            if !defenses_detected.contains(defense) {
                defenses_detected.push(defense.clone());
            }
        }
        if dc.exploitable_despite_waf
            && let Some(vendor) = &dc.waf_vendor
        {
            let label = format!("WAF ({vendor})");
            if !defenses_bypassed.contains(&label) {
                defenses_bypassed.push(label);
            }
        }
    }
    defenses_detected.sort();
    defenses_bypassed.sort();

    serde_json::json!({
        "defensesDetected": defenses_detected,
        "defensesBypassed": defenses_bypassed,
    })
}

fn build_finding_correlations(findings: &[SarifFinding]) -> Vec<serde_json::Value> {
    use std::collections::HashMap;
    let mut by_class: HashMap<String, Vec<&str>> = HashMap::new();
    for f in findings {
        if let Some(vc) = &f.vulnerability_class {
            by_class
                .entry(format!("{vc}"))
                .or_default()
                .push(&f.rule_id);
        }
    }
    let mut groups: Vec<serde_json::Value> = by_class
        .into_iter()
        .filter(|(_, ids)| ids.len() > 1)
        .map(|(class, ids)| {
            serde_json::json!({
                "vulnerabilityClass": class,
                "relatedFindings": ids,
                "count": ids.len(),
            })
        })
        .collect();
    groups.sort_by(|a, b| {
        b["count"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["count"].as_u64().unwrap_or(0))
    });
    groups
}

/// Severity rating string from composite score.
fn severity_rating(composite: f64) -> &'static str {
    if composite >= 70.0 {
        "Critical"
    } else if composite >= 40.0 {
        "High"
    } else if composite >= 20.0 {
        "Medium"
    } else {
        "Low"
    }
}

fn format_executive(
    findings: &[SarifFinding],
    tool_version: &str,
    metadata: Option<&ReportMetadata>,
    defense_summary: Option<&DefenseSummary>,
) -> Result<String, String> {
    let summary = build_executive_summary(findings, tool_version, metadata, defense_summary);
    serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())
}

fn build_executive_summary(
    findings: &[SarifFinding],
    tool_version: &str,
    metadata: Option<&ReportMetadata>,
    defense_summary: Option<&DefenseSummary>,
) -> ExecutiveSummary {
    let severity_counts = count_by_severity(findings);
    let overall = overall_risk_rating(findings);
    let top_priorities = top_remediation_priorities(findings);
    let defense_posture = build_defense_posture(defense_summary);
    let scan_meta = build_scan_metadata(tool_version, metadata);

    ExecutiveSummary {
        total_findings: findings.len(),
        severity_counts,
        risk_summary: overall,
        top_remediation_priorities: top_priorities,
        defense_posture_summary: defense_posture,
        scan_metadata: scan_meta,
    }
}

#[derive(Debug, Serialize)]
struct ExecutiveSummary {
    total_findings: usize,
    severity_counts: SeverityCounts,
    risk_summary: String,
    top_remediation_priorities: Vec<RemediationPriority>,
    defense_posture_summary: DefensePosture,
    scan_metadata: ExecutiveScanMetadata,
}

#[derive(Debug, Serialize)]
struct SeverityCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
}

#[derive(Debug, Serialize)]
struct RemediationPriority {
    rule_id: String,
    description: String,
    severity_rating: String,
    composite_score: f64,
    remediation: String,
}

#[derive(Debug, Serialize)]
struct DefensePosture {
    waf_active: bool,
    waf_vendor: Option<String>,
    rate_limiting_active: bool,
    bot_detection_active: bool,
}

#[derive(Debug, Serialize)]
struct ExecutiveScanMetadata {
    tool_version: String,
    target: String,
    duration_secs: f64,
    phases_completed: u32,
}

fn count_by_severity(findings: &[SarifFinding]) -> SeverityCounts {
    let mut counts = SeverityCounts {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
    };
    for f in findings {
        match severity_rating(f.composite_score) {
            "Critical" => counts.critical += 1,
            "High" => counts.high += 1,
            "Medium" => counts.medium += 1,
            _ => counts.low += 1,
        }
    }
    counts
}

fn overall_risk_rating(findings: &[SarifFinding]) -> String {
    let max_composite = findings
        .iter()
        .map(|f| f.composite_score)
        .fold(0.0_f64, f64::max);
    severity_rating(max_composite).to_string()
}

fn top_remediation_priorities(findings: &[SarifFinding]) -> Vec<RemediationPriority> {
    let mut sorted: Vec<&SarifFinding> = findings.iter().collect();
    sorted.sort_by(|a, b| {
        b.composite_score
            .partial_cmp(&a.composite_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Top 5 highest-severity findings with plain-English descriptions
    sorted
        .into_iter()
        .take(5)
        .map(|f| {
            let remediation_text = f
                .vulnerability_class
                .as_ref()
                .map(|vc| remediation_for(vc).to_string())
                .unwrap_or_else(|| "Review and apply defense-in-depth principles.".to_string());

            RemediationPriority {
                rule_id: f.rule_id.clone(),
                description: f.message.clone(),
                severity_rating: severity_rating(f.composite_score).to_string(),
                composite_score: f.composite_score,
                remediation: remediation_text,
            }
        })
        .collect()
}

fn build_defense_posture(defense_summary: Option<&DefenseSummary>) -> DefensePosture {
    match defense_summary {
        Some(ds) => DefensePosture {
            waf_active: ds.has_waf,
            waf_vendor: ds.waf_vendor.clone(),
            rate_limiting_active: ds.has_rate_limiting,
            bot_detection_active: ds.has_bot_detection,
        },
        None => DefensePosture {
            waf_active: false,
            waf_vendor: None,
            rate_limiting_active: false,
            bot_detection_active: false,
        },
    }
}

fn build_scan_metadata(
    tool_version: &str,
    metadata: Option<&ReportMetadata>,
) -> ExecutiveScanMetadata {
    match metadata {
        Some(m) => ExecutiveScanMetadata {
            tool_version: tool_version.to_string(),
            target: m.target_url.clone(),
            duration_secs: m.total_duration_secs,
            phases_completed: m.phases_completed,
        },
        None => ExecutiveScanMetadata {
            tool_version: tool_version.to_string(),
            target: String::new(),
            duration_secs: 0.0,
            phases_completed: 0,
        },
    }
}
