use aegis_chain_synthesis::attack_graph::AttackGraph;
use aegis_chain_synthesis::graph_export;
use aegis_protocol::finding::{FindingData, FindingId, VulnerabilityClass};
use aegis_reporting::report_format::{DefenseSummary, ReportFormat, ReportMetadata, format_report};
use aegis_reporting::risk_scorer::{RiskInput, compute_risk_score};
use aegis_reporting::sarif_emitter::{SarifFinding, SarifLevel};

use crate::pipeline::{PhaseResult, ScanContext};
use crate::scan_config::{
    BusinessContext, KnownIssue, ScanMetrics, load_business_context, resolve_report_format,
};

/// Returns only findings not present in `previous_findings` (by stable_id).
///
/// Findings with `stable_id == None` are always considered new, as they cannot
/// be matched against a previous scan. This preserves all findings when no
/// stable identity has been computed.
///
/// NOTE: stable_id is not populated by the fuzz executor (findings are created via
/// `GraphOperation::AddFinding`, not `FindingData::new`). Findings produced by the
/// fuzz phase are therefore always treated as new in diff mode.
pub fn compute_new_findings<'a>(
    current: &'a [FindingData],
    previous: &[FindingData],
) -> Vec<&'a FindingData> {
    use std::collections::HashSet;
    let previous_ids: HashSet<FindingId> = previous.iter().filter_map(|f| f.stable_id).collect();
    current
        .iter()
        .filter(|f| f.stable_id.is_none_or(|id| !previous_ids.contains(&id)))
        .collect()
}

pub fn run_report(
    ctx: &mut ScanContext,
    metrics: Option<&ScanMetrics>,
) -> Result<PhaseResult, String> {
    run_report_with_previous(ctx, metrics, None)
}

/// Runs the report phase, optionally filtering to only new findings vs a previous scan.
///
/// When `previous_findings` is `Some`, only findings not found in the previous set
/// (by stable_id) are emitted to the SARIF output. When `None`, all findings are emitted.
pub fn run_report_with_previous(
    ctx: &mut ScanContext,
    metrics: Option<&ScanMetrics>,
    previous_findings: Option<&[FindingData]>,
) -> Result<PhaseResult, String> {
    let finding_ids = all_finding_ids(ctx);
    let mut sarif_findings = Vec::new();

    let biz_ctx = ctx
        .config
        .scope
        .context_file
        .as_ref()
        .and_then(|p| load_business_context(p).ok());

    let all_current: Vec<FindingData> = finding_ids
        .iter()
        .filter_map(|&fid| ctx.graph.get_finding(fid).ok().flatten())
        .collect();

    let previously_known_count = previous_findings.map(|prev| {
        use std::collections::HashSet;
        let prev_ids: HashSet<_> = prev.iter().filter_map(|f| f.stable_id).collect();
        all_current
            .iter()
            .filter(|f| f.stable_id.is_some_and(|id| prev_ids.contains(&id)))
            .count() as u64
    });

    let findings_to_emit: Vec<&FindingData> = match previous_findings {
        Some(prev) => compute_new_findings(&all_current, prev),
        None => all_current.iter().collect(),
    };

    for finding in findings_to_emit {
        let fid = finding.id;
        let risk_input = RiskInput {
            vulnerability_class: finding.vulnerability_class,
            cvss_exploitability: finding.severity,
            is_authenticated: false,
            is_rate_limited: ctx
                .defense_profile
                .as_ref()
                .is_some_and(|p| p.rate_limit.is_some()),
            has_waf: ctx
                .defense_profile
                .as_ref()
                .is_some_and(|p| p.waf.is_some()),
            attack_path_count: 1,
            reachable_critical_assets: 1,
            asset_pii_weight: 0.5,
            confidence: finding.confidence,
        };

        let base_score = compute_risk_score(&risk_input);
        let endpoint = endpoint_for_finding(&finding.linked_node_ids, ctx);
        let composite = if let Some(ref biz) = biz_ctx {
            apply_business_context_multipliers(base_score.composite, &endpoint, biz)
        } else {
            base_score.composite
        };

        let (suppression_kind, suppression_message) = if let Some(ref biz) = biz_ctx
            && is_known_issue(&endpoint, finding.vulnerability_class, &biz.known_issues)
        {
            (
                Some("inSource".to_string()),
                Some("known-issue".to_string()),
            )
        } else {
            (None, None)
        };

        let endpoint_opt = if endpoint.is_empty() {
            None
        } else {
            Some(endpoint.clone())
        };
        let http_method = method_for_finding(&finding.linked_node_ids, ctx);

        sarif_findings.push(SarifFinding {
            rule_id: format!("AEGIS-{fid}"),
            rule_description: format!("{:?}", finding.vulnerability_class),
            level: severity_to_level(composite),
            message: format!(
                "{:?} finding (score: {:.2})",
                finding.vulnerability_class, composite
            ),
            uri: None,
            logical_location_name: None,
            logical_location_kind: None,
            severity: finding.severity,
            confidence: finding.confidence,
            composite_score: composite,
            vulnerability_class: Some(finding.vulnerability_class),
            related_locations: vec![],
            defense_context: None,
            evidence_level: None,
            cve_id: None,
            mitigation_rank: None,
            confidence_score: None,
            suppression_kind,
            suppression_message,
            endpoint: endpoint_opt,
            http_method,
            parameter_name: None,
        });
    }

    let report_format =
        resolve_report_format(&ctx.config.report_format).unwrap_or(ReportFormat::Developer);
    let json = build_formatted_output(
        &sarif_findings,
        report_format,
        metrics,
        previously_known_count,
        ctx,
    )?;
    std::fs::write(&ctx.config.output, json).map_err(|e| e.to_string())?;

    Ok(PhaseResult {
        operations_applied: 0,
        findings_count: sarif_findings.len() as u64,
    })
}

fn build_formatted_output(
    sarif_findings: &[SarifFinding],
    report_format: ReportFormat,
    metrics: Option<&ScanMetrics>,
    previously_known_count: Option<u64>,
    ctx: &ScanContext,
) -> Result<String, String> {
    match report_format {
        ReportFormat::Executive => {
            let report_metadata = metrics.map(|m| {
                let total_secs = m
                    .phase_timings
                    .timings
                    .values()
                    .map(|d| d.as_secs_f64())
                    .sum();
                ReportMetadata {
                    target_url: ctx.config.target.clone(),
                    total_duration_secs: total_secs,
                    phases_completed: m.phase_timings.timings.len() as u32,
                }
            });
            let defense_summary = ctx.defense_profile.as_ref().map(|dp| DefenseSummary {
                has_waf: dp.waf.is_some(),
                waf_vendor: dp.waf.as_ref().map(|w| format!("{:?}", w.vendor)),
                has_rate_limiting: dp.rate_limit.is_some(),
                has_bot_detection: dp.bot_detection.is_some(),
            });
            format_report(
                sarif_findings,
                report_format,
                "0.1.0",
                report_metadata.as_ref(),
                defense_summary.as_ref(),
            )
        }
        _ => {
            let json_str = format_report(sarif_findings, report_format, "0.1.0", None, None)?;
            let mut json_value: serde_json::Value =
                serde_json::from_str(&json_str).map_err(|e| e.to_string())?;
            if let Some(m) = metrics {
                inject_metrics_into_sarif(&mut json_value, m);
            }
            if let Some(known) = previously_known_count {
                inject_diff_stats_into_sarif(&mut json_value, sarif_findings.len() as u64, known);
            }
            serde_json::to_string_pretty(&json_value).map_err(|e| e.to_string())
        }
    }
}

pub(crate) fn all_finding_ids(ctx: &ScanContext) -> Vec<u64> {
    let classes = [
        VulnerabilityClass::SqlInjection,
        VulnerabilityClass::CrossSiteScripting,
        VulnerabilityClass::CommandInjection,
        VulnerabilityClass::PathTraversal,
        VulnerabilityClass::ServerSideRequestForgery,
        VulnerabilityClass::InsecureDeserialization,
        VulnerabilityClass::BrokenAuthentication,
        VulnerabilityClass::BrokenAuthorization,
        VulnerabilityClass::SecurityMisconfiguration,
        VulnerabilityClass::SensitiveDataExposure,
        VulnerabilityClass::ServerSideTemplateInjection,
        VulnerabilityClass::HeaderInjection,
        VulnerabilityClass::OpenRedirect,
        VulnerabilityClass::CrlfInjection,
        VulnerabilityClass::KnownVulnerableDependency,
        VulnerabilityClass::InsufficientInputValidation,
    ];
    let mut ids = Vec::new();
    for class in &classes {
        ids.extend(ctx.graph.findings_by_class(*class).unwrap_or_default());
    }
    ids.sort_unstable();
    ids.dedup();
    ids
}

pub(crate) fn severity_to_level(composite: f64) -> SarifLevel {
    if composite >= 70.0 {
        SarifLevel::Error
    } else if composite >= 40.0 {
        SarifLevel::Warning
    } else {
        SarifLevel::Note
    }
}

pub(crate) fn apply_business_context_multipliers(
    score: f64,
    endpoint: &str,
    biz_ctx: &BusinessContext,
) -> f64 {
    let mut multiplied = score;
    if biz_ctx.critical_assets.iter().any(|a| a == endpoint) {
        multiplied = (multiplied * 1.5).min(100.0);
    }
    if biz_ctx.pii_endpoints.iter().any(|p| p == endpoint) {
        multiplied = (multiplied * 1.5).min(100.0);
    }
    multiplied
}

/// Returns true if the given endpoint and vulnerability class match any entry in the known-issues list.
pub(crate) fn is_known_issue(
    endpoint: &str,
    vulnerability_class: VulnerabilityClass,
    known_issues: &[KnownIssue],
) -> bool {
    known_issues
        .iter()
        .any(|k| k.endpoint == endpoint && k.vulnerability_class == vulnerability_class)
}

pub(crate) fn endpoint_for_finding(linked_node_ids: &[u64], ctx: &ScanContext) -> String {
    for &node_id in linked_node_ids {
        if let Some(node) = ctx.graph.get_node(node_id).ok().flatten()
            && let Some(path) = node.properties.get("path")
        {
            return path.clone();
        }
    }
    String::new()
}

pub(crate) fn method_for_finding(linked_node_ids: &[u64], ctx: &ScanContext) -> Option<String> {
    for &node_id in linked_node_ids {
        if let Some(node) = ctx.graph.get_node(node_id).ok().flatten()
            && let Some(method) = node.properties.get("method")
        {
            return Some(method.clone());
        }
    }
    None
}

pub(crate) fn inject_metrics_into_sarif(sarif_json: &mut serde_json::Value, metrics: &ScanMetrics) {
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

    let mut timing_map = serde_json::Map::new();
    for (phase, duration) in &metrics.phase_timings.timings {
        timing_map.insert(
            phase.clone(),
            serde_json::Value::from(format!("{:.3}s", duration.as_secs_f64())),
        );
    }

    let mut llm_map = serde_json::Map::new();
    llm_map.insert(
        "callCount".to_string(),
        serde_json::Value::from(metrics.llm_metrics.call_count),
    );
    llm_map.insert(
        "totalLatency".to_string(),
        serde_json::Value::from(format!(
            "{:.3}s",
            metrics.llm_metrics.total_latency.as_secs_f64()
        )),
    );
    llm_map.insert(
        "tokensUsed".to_string(),
        serde_json::Value::from(metrics.llm_metrics.tokens_used),
    );

    props.insert(
        "phaseTimings".to_string(),
        serde_json::Value::Object(timing_map),
    );
    props.insert("llmMetrics".to_string(), serde_json::Value::Object(llm_map));
}

/// Injects diff-mode statistics into the SARIF properties of the first run.
///
/// Added when a previous scan is available for comparison. Records new finding
/// count and previously-known count so consumers can track scan-over-scan trends.
pub(crate) fn inject_diff_stats_into_sarif(
    sarif_json: &mut serde_json::Value,
    new_findings: u64,
    previously_known: u64,
) {
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

    let mut diff_map = serde_json::Map::new();
    diff_map.insert(
        "newFindings".to_string(),
        serde_json::Value::from(new_findings),
    );
    diff_map.insert(
        "previouslyKnown".to_string(),
        serde_json::Value::from(previously_known),
    );
    props.insert("diffStats".to_string(), serde_json::Value::Object(diff_map));
}

/// Writes attack graph export files alongside the SARIF output when `--export-graph` is set.
///
/// Supported formats: `"dot"` (Graphviz DOT) and `"d3json"` (D3.js-compatible JSON).
/// Returns `Err` if the format is unrecognized or the file cannot be written.
pub(crate) fn export_attack_graph(
    ctx: &ScanContext,
    attack_graph: &AttackGraph,
) -> Result<(), String> {
    let Some(ref format) = ctx.config.scope.export_graph else {
        return Ok(());
    };

    let output_base = ctx.config.output.with_extension("");

    match format.as_str() {
        "dot" => {
            let dot = graph_export::export_dot(attack_graph);
            let path = output_base.with_extension("dot");
            std::fs::write(&path, dot).map_err(|e| format!("write DOT export: {e}"))?;
        }
        "d3json" => {
            let json = graph_export::export_d3_json(attack_graph);
            let path = output_base.with_extension("d3.json");
            std::fs::write(&path, json).map_err(|e| format!("write D3 JSON export: {e}"))?;
        }
        other => return Err(format!("unknown graph export format: {other}")),
    }

    Ok(())
}
