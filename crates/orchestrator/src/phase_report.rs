use aegis_protocol::finding::VulnerabilityClass;
use aegis_reporting::risk_scorer::{RiskInput, compute_risk_score};
use aegis_reporting::sarif_emitter::{SarifFinding, SarifLevel, emit_sarif};

use crate::pipeline::{PhaseResult, ScanContext};
use crate::scan_config::ScanMetrics;

pub fn run_report(
    ctx: &mut ScanContext,
    metrics: Option<&ScanMetrics>,
) -> Result<PhaseResult, String> {
    let finding_ids = all_finding_ids(ctx);
    let mut sarif_findings = Vec::new();

    for &fid in &finding_ids {
        if let Some(finding) = ctx.graph.get_finding(fid).ok().flatten() {
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

            let score = compute_risk_score(&risk_input);
            sarif_findings.push(SarifFinding {
                rule_id: format!("AEGIS-{fid}"),
                rule_description: format!("{:?}", finding.vulnerability_class),
                level: severity_to_level(score.composite),
                message: format!(
                    "{:?} finding (score: {:.2})",
                    finding.vulnerability_class, score.composite
                ),
                uri: None,
                logical_location_name: None,
                logical_location_kind: None,
                severity: finding.severity,
                confidence: finding.confidence,
                composite_score: score.composite,
                vulnerability_class: Some(finding.vulnerability_class),
                related_locations: vec![],
                defense_context: None,
                evidence_level: None,
                cve_id: None,
                mitigation_rank: None,
                confidence_score: None,
            });
        }
    }

    let sarif_log = emit_sarif(&sarif_findings, "0.1.0");
    let mut json_value: serde_json::Value =
        serde_json::to_value(&sarif_log).map_err(|e| e.to_string())?;
    if let Some(m) = metrics {
        inject_metrics_into_sarif(&mut json_value, m);
    }
    let json = serde_json::to_string_pretty(&json_value).map_err(|e| e.to_string())?;
    std::fs::write(&ctx.config.output, json).map_err(|e| e.to_string())?;

    Ok(PhaseResult {
        operations_applied: 0,
        findings_count: sarif_findings.len() as u64,
    })
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
    if composite >= 0.7 {
        SarifLevel::Error
    } else if composite >= 0.4 {
        SarifLevel::Warning
    } else {
        SarifLevel::Note
    }
}

pub(crate) fn inject_metrics_into_sarif(sarif_json: &mut serde_json::Value, metrics: &ScanMetrics) {
    let Some(run) = sarif_json
        .get_mut("runs")
        .and_then(|r| r.as_array_mut())
        .and_then(|a| a.first_mut())
    else {
        return;
    };

    let props = run
        .as_object_mut()
        .unwrap()
        .entry("properties")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .unwrap();

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
