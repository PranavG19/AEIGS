use super::*;

use aegis_knowledge_graph::graph::KnowledgeGraph;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::node::NodeType;
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
    let mut capabilities =
        aegis_supervisor::capability_manager::CapabilityManager::new(vec![0u8; 32]);
    pipeline::register_default_policies(&mut capabilities);
    ScanContext {
        config: test_config(output_path),
        graph: Box::new(KnowledgeGraph::new()),
        defense_profile: None,
        capabilities,
        refuted: convergence::RefutedTracker::new(),
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
    let mut ctx = test_context(&output);
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
fn severity_to_level_error_at_70() {
    assert_eq!(phase_report::severity_to_level(70.0), SarifLevel::Error);
    assert_eq!(phase_report::severity_to_level(85.0), SarifLevel::Error);
    assert_eq!(phase_report::severity_to_level(100.0), SarifLevel::Error);
}

#[test]
fn severity_to_level_warning_at_40() {
    assert_eq!(phase_report::severity_to_level(40.0), SarifLevel::Warning);
    assert_eq!(phase_report::severity_to_level(50.0), SarifLevel::Warning);
    assert_eq!(phase_report::severity_to_level(69.9), SarifLevel::Warning);
}

#[test]
fn severity_to_level_note_below_40() {
    assert_eq!(phase_report::severity_to_level(39.9), SarifLevel::Note);
    assert_eq!(phase_report::severity_to_level(10.0), SarifLevel::Note);
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
    // 50.0 × 1.5 = 75.0
    let result = apply_business_context_multipliers(50.0, "/api/payments", &biz);
    assert!((result - 75.0).abs() < 1e-9);
}

#[test]
fn apply_business_context_multipliers_pii_endpoint_multiplies_by_1_5() {
    let biz = make_biz_ctx(&[], &["/api/users"]);
    // 70.0 × 1.5 = 105.0 → capped at 100.0
    let result = apply_business_context_multipliers(70.0, "/api/users", &biz);
    assert!((result - 100.0).abs() < 1e-9);
}

#[test]
fn apply_business_context_multipliers_stacking_caps_at_100() {
    let biz = make_biz_ctx(&["/api/payments"], &["/api/payments"]);
    // 50.0 × 1.5 = 75.0 (critical_assets), then 75.0 × 1.5 = 112.5 → capped at 100.0 (pii_endpoints)
    let result = apply_business_context_multipliers(50.0, "/api/payments", &biz);
    assert!((result - 100.0).abs() < 1e-9);
}

#[test]
fn apply_business_context_multipliers_unmatched_endpoint_unchanged() {
    let biz = make_biz_ctx(&["/api/payments"], &["/api/users"]);
    let result = apply_business_context_multipliers(70.0, "/api/other", &biz);
    assert!((result - 70.0).abs() < 1e-9);
}

#[test]
fn is_known_issue_returns_true_when_endpoint_and_class_match() {
    let known = vec![scan_config::KnownIssue {
        endpoint: "/api/users".to_string(),
        vulnerability_class: VulnerabilityClass::SqlInjection,
    }];
    assert!(phase_report::is_known_issue(
        "/api/users",
        VulnerabilityClass::SqlInjection,
        &known
    ));
}

#[test]
fn is_known_issue_returns_false_when_class_differs() {
    let known = vec![scan_config::KnownIssue {
        endpoint: "/api/users".to_string(),
        vulnerability_class: VulnerabilityClass::SqlInjection,
    }];
    assert!(!phase_report::is_known_issue(
        "/api/users",
        VulnerabilityClass::CrossSiteScripting,
        &known
    ));
}

#[test]
fn is_known_issue_returns_false_when_endpoint_differs() {
    let known = vec![scan_config::KnownIssue {
        endpoint: "/api/users".to_string(),
        vulnerability_class: VulnerabilityClass::SqlInjection,
    }];
    assert!(!phase_report::is_known_issue(
        "/api/admin",
        VulnerabilityClass::SqlInjection,
        &known
    ));
}

#[test]
fn is_known_issue_returns_false_for_empty_list() {
    assert!(!phase_report::is_known_issue(
        "/api/users",
        VulnerabilityClass::SqlInjection,
        &[]
    ));
}

fn add_node_entry(seq: u64, path: &str) -> OperationLogEntry {
    OperationLogEntry {
        sequence_number: seq,
        module: ModuleIdentifier::Fuzzing,
        operation: GraphOperation::AddNode {
            node_type: NodeType::Endpoint,
            properties: vec![("path".to_string(), path.to_string())],
        },
        timestamp_unix_ms: 1000 + seq,
    }
}

fn add_linked_finding_entry(
    seq: u64,
    class: VulnerabilityClass,
    severity: f64,
    node_id: u64,
) -> OperationLogEntry {
    OperationLogEntry {
        sequence_number: seq,
        module: ModuleIdentifier::Fuzzing,
        operation: GraphOperation::AddFinding {
            linked_node_ids: vec![node_id],
            vulnerability_class: class,
            severity,
            confidence: 0.9,
            certificate: vec![],
        },
        timestamp_unix_ms: 1000 + seq,
    }
}

#[test]
fn run_report_known_issue_finding_has_sarif_suppression() {
    let output = std::env::temp_dir().join("test_report_known_issue.sarif");
    let mut ctx = test_context(&output);

    // node 0 at /api/users, finding 1 linked to it
    let entries = vec![
        add_node_entry(0, "/api/users"),
        add_linked_finding_entry(1, VulnerabilityClass::SqlInjection, 0.8, 0),
    ];
    ctx.graph.apply_operations(&entries).unwrap();

    // Inject business context with the matching known issue directly
    // (bypasses file I/O — we override the loaded context inside the context_file path
    // by writing a temp JSON file).
    let biz_json = serde_json::json!({
        "known_issues": [
            {"endpoint": "/api/users", "vulnerability_class": "SqlInjection"}
        ]
    });
    let ctx_path = std::env::temp_dir().join("test_biz_ctx_known.json");
    std::fs::write(&ctx_path, serde_json::to_string(&biz_json).unwrap()).unwrap();
    ctx.config.scope.context_file = Some(ctx_path.clone());

    phase_report::run_report(&mut ctx, None).unwrap();

    let json: serde_json::Value = serde_json::from_str(&sarif_output(&output)).unwrap();
    let results = json["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    let suppressions = results[0]["suppressions"].as_array().unwrap();
    assert_eq!(suppressions.len(), 1);
    assert_eq!(suppressions[0]["kind"].as_str().unwrap(), "inSource");
    assert_eq!(
        suppressions[0]["justification"].as_str().unwrap(),
        "known-issue"
    );

    let _ = std::fs::remove_file(&output);
    let _ = std::fs::remove_file(&ctx_path);
}

#[test]
fn run_report_non_known_issue_finding_has_no_suppression() {
    let output = std::env::temp_dir().join("test_report_not_known_issue.sarif");
    let mut ctx = test_context(&output);

    let entries = vec![add_finding_entry(0, VulnerabilityClass::SqlInjection, 0.8)];
    ctx.graph.apply_operations(&entries).unwrap();

    let biz_json = serde_json::json!({
        "known_issues": [
            {"endpoint": "/api/other", "vulnerability_class": "SqlInjection"}
        ]
    });
    let ctx_path = std::env::temp_dir().join("test_biz_ctx_not_known.json");
    std::fs::write(&ctx_path, serde_json::to_string(&biz_json).unwrap()).unwrap();
    ctx.config.scope.context_file = Some(ctx_path.clone());

    phase_report::run_report(&mut ctx, None).unwrap();

    let json: serde_json::Value = serde_json::from_str(&sarif_output(&output)).unwrap();
    let results = json["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0]["suppressions"].is_null());

    let _ = std::fs::remove_file(&output);
    let _ = std::fs::remove_file(&ctx_path);
}

// --- endpoint_for_finding tests ---

#[test]
fn endpoint_for_finding_returns_path_for_linked_node_with_path_property() {
    let output = std::env::temp_dir().join("test_endpoint_for_finding.sarif");
    let mut ctx = test_context(&output);

    let entries = vec![add_node_entry(0, "/api/payments")];
    ctx.graph.apply_operations(&entries).unwrap();

    let result = phase_report::endpoint_for_finding(&[0], &ctx);
    assert_eq!(result, "/api/payments");
}

#[test]
fn endpoint_for_finding_returns_empty_string_for_empty_ids() {
    let output = std::env::temp_dir().join("test_endpoint_empty_ids.sarif");
    let ctx = test_context(&output);
    let result = phase_report::endpoint_for_finding(&[], &ctx);
    assert!(result.is_empty());
}

#[test]
fn endpoint_for_finding_returns_empty_string_for_nonexistent_node_id() {
    let output = std::env::temp_dir().join("test_endpoint_nonexistent_node.sarif");
    let ctx = test_context(&output);
    let result = phase_report::endpoint_for_finding(&[999], &ctx);
    assert!(result.is_empty());
}

#[test]
fn run_report_with_linked_finding_uses_endpoint_path() {
    let output = std::env::temp_dir().join("test_report_linked_endpoint.sarif");
    let mut ctx = test_context(&output);

    let entries = vec![
        add_node_entry(0, "/api/data"),
        add_linked_finding_entry(1, VulnerabilityClass::SqlInjection, 0.9, 0),
    ];
    ctx.graph.apply_operations(&entries).unwrap();

    let result = phase_report::run_report(&mut ctx, None).unwrap();
    assert_eq!(result.findings_count, 1);

    let json: serde_json::Value = serde_json::from_str(&sarif_output(&output)).unwrap();
    let results = json["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    let _ = std::fs::remove_file(&output);
}

// --- inject_metrics_into_sarif with no runs ---

#[test]
fn inject_metrics_into_sarif_no_runs_returns_early() {
    let mut json_value = serde_json::json!({"version": "2.1.0"});
    let metrics = scan_config::ScanMetrics::default();
    phase_report::inject_metrics_into_sarif(&mut json_value, &metrics);
    // No "properties" key added since there are no runs — early-return path executed.
    assert!(json_value.get("properties").is_none());
}

// --- compute_new_findings diff-mode tests ---

fn make_finding_with_stable_id(
    id: u64,
    class: VulnerabilityClass,
    endpoint: &str,
    parameter: &str,
) -> aegis_protocol::finding::FindingData {
    aegis_protocol::finding::FindingData::new(
        id,
        class,
        5.0,
        0.7,
        aegis_protocol::operation::ModuleIdentifier::Fuzzing,
        1700000000000,
    )
    .with_stable_id(endpoint, parameter)
}

#[test]
fn compute_new_findings_no_previous_returns_all() {
    use aegis_protocol::finding::FindingData;
    let current: Vec<FindingData> = vec![
        make_finding_with_stable_id(0, VulnerabilityClass::SqlInjection, "/api/users", "id"),
        make_finding_with_stable_id(
            1,
            VulnerabilityClass::CrossSiteScripting,
            "/api/search",
            "q",
        ),
    ];
    let result = phase_report::compute_new_findings(&current, &[]);
    assert_eq!(result.len(), 2);
}

#[test]
fn compute_new_findings_filters_known() {
    use aegis_protocol::finding::FindingData;
    let f1 = make_finding_with_stable_id(0, VulnerabilityClass::SqlInjection, "/api/users", "id");
    let f2 = make_finding_with_stable_id(
        1,
        VulnerabilityClass::CrossSiteScripting,
        "/api/search",
        "q",
    );

    let previous: Vec<FindingData> = vec![f1.clone()];
    let current: Vec<FindingData> = vec![f1, f2];

    let result = phase_report::compute_new_findings(&current, &previous);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].id, 1);
}

#[test]
fn compute_new_findings_no_stable_id_always_new() {
    use aegis_protocol::finding::FindingData;
    let no_stable_id = FindingData::new(
        0,
        VulnerabilityClass::PathTraversal,
        5.0,
        0.7,
        aegis_protocol::operation::ModuleIdentifier::Fuzzing,
        1700000000000,
    );
    let some_finding =
        make_finding_with_stable_id(1, VulnerabilityClass::SqlInjection, "/api/users", "id");

    let previous = vec![some_finding.clone()];
    let current = vec![no_stable_id, some_finding];

    let result = phase_report::compute_new_findings(&current, &previous);
    // The one without stable_id is always new; the one with stable_id matching previous is filtered
    assert_eq!(result.len(), 1);
    assert!(result[0].stable_id.is_none());
}

#[test]
fn compute_new_findings_all_known_returns_empty() {
    let f1 = make_finding_with_stable_id(0, VulnerabilityClass::SqlInjection, "/api/users", "id");
    let f2 = make_finding_with_stable_id(
        1,
        VulnerabilityClass::CrossSiteScripting,
        "/api/search",
        "q",
    );
    let previous = vec![f1.clone(), f2.clone()];
    let current = vec![f1, f2];
    let result = phase_report::compute_new_findings(&current, &previous);
    assert!(result.is_empty());
}

#[test]
fn run_report_with_previous_filters_known_findings() {
    let output = std::env::temp_dir().join("test_report_diff_mode.sarif");
    let mut ctx = test_context(&output);

    let entries = vec![
        add_finding_entry(0, VulnerabilityClass::SqlInjection, 0.9),
        add_finding_entry(1, VulnerabilityClass::CrossSiteScripting, 0.6),
    ];
    ctx.graph.apply_operations(&entries).unwrap();

    let all_findings = ctx.graph.all_findings().unwrap();
    let previous: Vec<aegis_protocol::finding::FindingData> = vec![all_findings[0].clone()];

    let result = phase_report::run_report_with_previous(&mut ctx, None, Some(&previous)).unwrap();
    // findings without stable_id: both are "new" because stable_id is None → always new
    assert_eq!(result.findings_count, 2);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn inject_diff_stats_into_sarif_no_runs_returns_early() {
    let mut json_value = serde_json::json!({"version": "2.1.0"});
    phase_report::inject_diff_stats_into_sarif(&mut json_value, 3, 1);
    assert!(json_value.get("properties").is_none());
}
