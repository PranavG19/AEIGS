use super::*;

use aegis_knowledge_graph::graph::KnowledgeGraph;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};
use aegis_reporting::sarif_emitter::SarifLevel;
use clap::Parser;

fn make_biz_ctx(critical_assets: &[&str], pii_endpoints: &[&str]) -> scan_config::BusinessContext {
    scan_config::BusinessContext {
        excluded_endpoints: vec![],
        critical_assets: critical_assets.iter().map(|s| s.to_string()).collect(),
        pii_endpoints: pii_endpoints.iter().map(|s| s.to_string()).collect(),
        known_issues: vec![],
    }
}

fn test_config(output_path: &std::path::Path) -> ScanConfig {
    ScanConfig::try_parse_from([
        "aegis",
        "--target",
        "http://localhost:8080",
        "--output",
        output_path.to_str().unwrap(),
    ])
    .unwrap()
}

fn test_context(output_path: &std::path::Path) -> ScanContext {
    ScanContext {
        config: test_config(output_path),
        graph: KnowledgeGraph::new(),
        defense_profile: None,
    }
}

fn add_finding_entry(seq: u64, class: VulnerabilityClass, severity: f64) -> OperationLogEntry {
    OperationLogEntry {
        sequence_number: seq,
        module: ModuleIdentifier::Fuzzing,
        operation: GraphOperation::AddFinding {
            linked_node_ids: vec![],
            vulnerability_class: class,
            severity,
            confidence: 0.9,
            certificate: vec![],
        },
        timestamp_unix_ms: 1000 + seq,
    }
}

fn sarif_output(output_path: &std::path::Path) -> String {
    std::fs::read_to_string(output_path).unwrap()
}

#[test]
fn run_report_empty_graph_writes_empty_sarif() {
    let output = std::env::temp_dir().join("test_report_empty.sarif");
    let mut ctx = test_context(&output);

    let result = phase_report::run_report(&mut ctx, None).unwrap();

    assert_eq!(result.findings_count, 0);
    assert_eq!(result.operations_applied, 0);
    let json: serde_json::Value = serde_json::from_str(&sarif_output(&output)).unwrap();
    let results = json["runs"][0]["results"].as_array().unwrap();
    assert!(results.is_empty());
    let _ = std::fs::remove_file(&output);
}

#[test]
fn run_report_with_findings_produces_sarif_results() {
    let output = std::env::temp_dir().join("test_report_findings.sarif");
    let mut ctx = test_context(&output);

    let entries = vec![
        add_finding_entry(0, VulnerabilityClass::SqlInjection, 0.9),
        add_finding_entry(1, VulnerabilityClass::CrossSiteScripting, 0.6),
    ];
    ctx.graph.apply_operations(&entries).unwrap();

    let result = phase_report::run_report(&mut ctx, None).unwrap();

    assert_eq!(result.findings_count, 2);
    let json: serde_json::Value = serde_json::from_str(&sarif_output(&output)).unwrap();
    let results = json["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn all_finding_ids_returns_sorted_unique() {
    let output = std::env::temp_dir().join("test_report_ids.sarif");
    let ctx = test_context(&output);
    let entries = vec![
        add_finding_entry(0, VulnerabilityClass::SqlInjection, 0.8),
        add_finding_entry(1, VulnerabilityClass::PathTraversal, 0.7),
        add_finding_entry(2, VulnerabilityClass::SqlInjection, 0.5),
    ];
    ctx.graph.apply_operations(&entries).unwrap();

    let ids = phase_report::all_finding_ids(&ctx);

    assert_eq!(ids, vec![0, 1, 2]);
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(ids, sorted);
}

#[test]
fn all_finding_ids_empty_graph_returns_empty() {
    let output = std::env::temp_dir().join("test_report_empty_ids.sarif");
    let ctx = test_context(&output);

    let ids = phase_report::all_finding_ids(&ctx);

    assert!(ids.is_empty());
}

#[test]
fn severity_to_level_error_at_0_7() {
    assert_eq!(phase_report::severity_to_level(0.7), SarifLevel::Error);
    assert_eq!(phase_report::severity_to_level(0.85), SarifLevel::Error);
    assert_eq!(phase_report::severity_to_level(1.0), SarifLevel::Error);
}

#[test]
fn severity_to_level_warning_at_0_4() {
    assert_eq!(phase_report::severity_to_level(0.4), SarifLevel::Warning);
    assert_eq!(phase_report::severity_to_level(0.5), SarifLevel::Warning);
    assert_eq!(phase_report::severity_to_level(0.69), SarifLevel::Warning);
}

#[test]
fn severity_to_level_note_below_0_4() {
    assert_eq!(phase_report::severity_to_level(0.39), SarifLevel::Note);
    assert_eq!(phase_report::severity_to_level(0.1), SarifLevel::Note);
    assert_eq!(phase_report::severity_to_level(0.0), SarifLevel::Note);
}

#[test]
fn run_report_with_metrics_includes_phase_timings_in_sarif() {
    let output = std::env::temp_dir().join("test_report_timings.sarif");
    let mut ctx = test_context(&output);
    let mut metrics = scan_config::ScanMetrics::default();
    metrics
        .phase_timings
        .record("recon", std::time::Duration::from_millis(150));
    metrics
        .phase_timings
        .record("fuzz", std::time::Duration::from_millis(420));

    let result = phase_report::run_report(&mut ctx, Some(&metrics)).unwrap();

    assert_eq!(result.findings_count, 0);
    let json: serde_json::Value = serde_json::from_str(&sarif_output(&output)).unwrap();
    let props = &json["runs"][0]["properties"];
    assert!(props["phaseTimings"].is_object());
    assert!(
        props["phaseTimings"]["recon"]
            .as_str()
            .unwrap()
            .contains("0.150")
    );
    assert!(
        props["phaseTimings"]["fuzz"]
            .as_str()
            .unwrap()
            .contains("0.420")
    );
    let _ = std::fs::remove_file(&output);
}

#[test]
fn run_report_with_metrics_includes_llm_metrics_in_sarif() {
    let output = std::env::temp_dir().join("test_report_llm_metrics.sarif");
    let mut ctx = test_context(&output);
    let mut metrics = scan_config::ScanMetrics::default();
    metrics
        .llm_metrics
        .record_call(std::time::Duration::from_secs(2), 500);
    metrics
        .llm_metrics
        .record_call(std::time::Duration::from_secs(3), 300);

    let _result = phase_report::run_report(&mut ctx, Some(&metrics)).unwrap();

    let json: serde_json::Value = serde_json::from_str(&sarif_output(&output)).unwrap();
    let llm = &json["runs"][0]["properties"]["llmMetrics"];
    assert_eq!(llm["callCount"].as_u64().unwrap(), 2);
    assert_eq!(llm["tokensUsed"].as_u64().unwrap(), 800);
    assert!(llm["totalLatency"].as_str().unwrap().contains("5.000"));
    let _ = std::fs::remove_file(&output);
}

#[test]
fn apply_business_context_multipliers_critical_asset_multiplies_by_1_5() {
    let biz = make_biz_ctx(&["/api/payments"], &[]);
    let result = apply_business_context_multipliers(4.0, "/api/payments", &biz);
    assert!((result - 6.0).abs() < 1e-9);
}

#[test]
fn apply_business_context_multipliers_pii_endpoint_multiplies_by_1_5() {
    let biz = make_biz_ctx(&[], &["/api/users"]);
    let result = apply_business_context_multipliers(4.0, "/api/users", &biz);
    assert!((result - 6.0).abs() < 1e-9);
}

#[test]
fn apply_business_context_multipliers_stacking_caps_at_10() {
    let biz = make_biz_ctx(&["/api/payments"], &["/api/payments"]);
    // 5.0 × 1.5 = 7.5 (critical_assets), then 7.5 × 1.5 = 11.25 → capped at 10.0 (pii_endpoints)
    let result = apply_business_context_multipliers(5.0, "/api/payments", &biz);
    assert!((result - 10.0).abs() < 1e-9);
}

#[test]
fn apply_business_context_multipliers_unmatched_endpoint_unchanged() {
    let biz = make_biz_ctx(&["/api/payments"], &["/api/users"]);
    let result = apply_business_context_multipliers(7.0, "/api/other", &biz);
    assert!((result - 7.0).abs() < 1e-9);
}
