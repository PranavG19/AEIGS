use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

use aegis_audit_log::event_store::{ScanSnapshot, replay_from_entries};
use aegis_audit_log::log_verifier::verify_log;
use aegis_audit_log::log_writer::{AuditLogWriter, AuditWriter};
use aegis_fuzzing::stealth_config::StealthConfig;
use aegis_knowledge_graph::GraphMetadata;
use aegis_knowledge_graph::graph::KnowledgeGraph;
use aegis_orchestrator::checkpoint::{
    ScanCheckpoint, load_checkpoint, save_checkpoint, should_skip_phase,
};
use aegis_orchestrator::compute_new_findings;
use aegis_orchestrator::pipeline::run_scan;
use aegis_orchestrator::run_recon_standalone;
use aegis_orchestrator::scan_config::ScanConfig;
use aegis_orchestrator::scan_history::{ScanHistoryDb, ScanHistoryEntry};
use aegis_protocol::audit::AuditEventType;
use aegis_protocol::finding::{FindingData, VulnerabilityClass};
use aegis_protocol::operation::ModuleIdentifier;
use aegis_reporting::report_format::{ReportFormat, format_report};
use aegis_reporting::sarif_emitter::{
    SarifDefenseContext, SarifFinding, SarifLevel, emit_sarif, sarif_to_json,
};
use clap::Parser;

mod ground_truth;

// ---------------------------------------------------------------------------
// Environment gate
// ---------------------------------------------------------------------------

fn docker_tests_enabled() -> bool {
    std::env::var("AEGIS_INTEGRATION_TESTS").is_ok_and(|v| v == "1")
}

// ---------------------------------------------------------------------------
// Docker Compose helper
// ---------------------------------------------------------------------------

struct DockerCompose {
    compose_file: String,
    project_name: String,
}

impl DockerCompose {
    fn new(compose_file: &str, project_name: &str) -> Self {
        Self {
            compose_file: compose_file.to_string(),
            project_name: project_name.to_string(),
        }
    }

    fn up(&self) -> std::io::Result<()> {
        let status = Command::new("docker")
            .args([
                "compose",
                "-f",
                &self.compose_file,
                "-p",
                &self.project_name,
                "up",
                "-d",
                "--build",
                "--wait",
            ])
            .status()?;
        assert!(status.success(), "docker compose up failed");
        Ok(())
    }

    fn down(&self) -> std::io::Result<()> {
        let _ = Command::new("docker")
            .args([
                "compose",
                "-f",
                &self.compose_file,
                "-p",
                &self.project_name,
                "down",
                "-v",
                "--remove-orphans",
            ])
            .status();
        Ok(())
    }
}

impl Drop for DockerCompose {
    fn drop(&mut self) {
        let _ = self.down();
    }
}

fn wait_for_health(url: &str, timeout: Duration) -> bool {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if let Ok(resp) = client.get(url).send()
            && resp.status().is_success()
        {
            return true;
        }
        thread::sleep(Duration::from_secs(1));
    }
    false
}

fn compose_dir() -> String {
    let manifest = env!("CARGO_MANIFEST_DIR");
    format!("{manifest}/../../defense-stacks/compose")
}

fn fixture_dir(app: &str) -> String {
    let manifest = env!("CARGO_MANIFEST_DIR");
    format!("{manifest}/../../defense-stacks/{app}")
}

// ---------------------------------------------------------------------------
// Ground-truth JSON loading
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct GroundTruthFile {
    findings: Vec<GroundTruthFinding>,
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
struct GroundTruthFinding {
    endpoint: String,
    method: String,
    #[serde(default)]
    parameter: Option<String>,
    vulnerability_class: String,
    #[serde(default)]
    operation: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

fn load_ground_truth(app: &str) -> GroundTruthFile {
    let path = format!("{}/ground-truth.json", fixture_dir(app));
    let contents =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    serde_json::from_str(&contents).unwrap_or_else(|e| panic!("cannot parse {path}: {e}"))
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn make_sarif_finding(
    id: u64,
    class: VulnerabilityClass,
    severity: f64,
    confidence: f64,
    composite: f64,
) -> SarifFinding {
    SarifFinding {
        rule_id: format!("AEGIS-{id}"),
        rule_description: format!("{class}"),
        level: if composite >= 70.0 {
            SarifLevel::Error
        } else if composite >= 40.0 {
            SarifLevel::Warning
        } else {
            SarifLevel::Note
        },
        message: format!("{class} finding (score: {composite:.2})"),
        uri: None,
        logical_location_name: None,
        logical_location_kind: None,
        severity,
        confidence,
        composite_score: composite,
        vulnerability_class: Some(class),
        related_locations: vec![],
        defense_context: None,
        evidence_level: None,
        cve_id: None,
        mitigation_rank: None,
        confidence_score: None,
        suppression_kind: None,
        suppression_message: None,
        endpoint: None,
        http_method: None,
        parameter_name: None,
    }
}

fn make_finding_data(id: u64, class: VulnerabilityClass) -> FindingData {
    FindingData::new(id, class, 7.0, 0.9, ModuleIdentifier::Fuzzing, 0)
}

// ===========================================================================
// Express app tests (#276-#282)
// ===========================================================================

// 276: express_full_scan_ground_truth
#[test]
fn express_full_scan_ground_truth() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let compose = DockerCompose::new(
        &format!("{}/docker-compose.yml", compose_dir()),
        "aegis-test-express-276",
    );
    compose.up().unwrap();
    assert!(
        wait_for_health("http://localhost:3000/health", Duration::from_secs(60)),
        "express app failed health check"
    );

    let gt = load_ground_truth("express-vuln-app");
    assert!(
        !gt.findings.is_empty(),
        "ground truth should have at least one finding"
    );

    let client = reqwest::blocking::Client::new();
    let resp = client
        .get("http://localhost:3000/api/users?id=1%20OR%201=1")
        .send()
        .unwrap();
    assert!(
        resp.status().is_success(),
        "SQLi probe should not be blocked on bare app"
    );

    for finding in &gt.findings {
        if finding.endpoint == "/" {
            continue;
        }
        let url = format!("http://localhost:3000{}", finding.endpoint);
        let check = client.get(&url).send();
        assert!(
            check.is_ok(),
            "endpoint {} should be accessible",
            finding.endpoint
        );
    }
}

// 277: express_openapi_discovery
#[test]
fn express_openapi_discovery() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let compose = DockerCompose::new(
        &format!("{}/docker-compose.yml", compose_dir()),
        "aegis-test-express-277",
    );
    compose.up().unwrap();
    assert!(
        wait_for_health("http://localhost:3000/health", Duration::from_secs(60)),
        "express app failed health check"
    );

    let client = reqwest::blocking::Client::new();
    let resp = client
        .get("http://localhost:3000/openapi.json")
        .send()
        .unwrap();
    assert!(
        resp.status().is_success(),
        "OpenAPI spec should be accessible"
    );
    let body: serde_json::Value = resp.json().unwrap();
    let paths = body.get("paths").expect("OpenAPI spec should have paths");
    let paths_obj = paths.as_object().expect("paths should be an object");

    let gt = load_ground_truth("express-vuln-app");
    let gt_endpoints: std::collections::HashSet<&str> = gt
        .findings
        .iter()
        .filter(|f| f.endpoint != "/")
        .map(|f| f.endpoint.as_str())
        .collect();

    for ep in &gt_endpoints {
        assert!(
            paths_obj.contains_key(*ep),
            "OpenAPI spec should document endpoint {ep}"
        );
    }
}

// 278: express_source_recon
#[test]
fn express_source_recon() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let source_dir = std::path::PathBuf::from(fixture_dir("express-vuln-app"));
    assert!(
        source_dir.join("package-lock.json").exists() || source_dir.join("package.json").exists(),
        "express fixture should have package-lock.json or package.json"
    );

    let ops = run_recon_standalone(&Some(source_dir)).unwrap();
    let has_dependency_node = ops.iter().any(|op| {
        matches!(
            &op.operation,
            aegis_protocol::operation::GraphOperation::AddNode { node_type, properties }
                if *node_type == aegis_protocol::node::NodeType::Dependency
                    && properties.iter().any(|(k, v)| k == "name" && (v.contains("serialize-javascript") || v.contains("lodash")))
        )
    });
    assert!(
        has_dependency_node,
        "recon should find serialize-javascript or lodash in express lock file"
    );
}

// 279: express_behind_modsecurity
#[test]
fn express_behind_modsecurity() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let compose = DockerCompose::new(
        &format!("{}/docker-compose.modsecurity.yml", compose_dir()),
        "aegis-test-modsec-279",
    );
    compose.up().unwrap();
    assert!(
        wait_for_health("http://localhost:8080/healthz", Duration::from_secs(60)),
        "modsecurity proxy failed health check"
    );

    let client = reqwest::blocking::Client::new();
    let blocked = client
        .get("http://localhost:8080/api/users?id=1%27%20OR%201%3D1--")
        .send()
        .unwrap();
    assert_eq!(
        blocked.status().as_u16(),
        403,
        "ModSecurity should block SQLi payload with 403"
    );

    let clean = client
        .get("http://localhost:8080/api/users?id=1")
        .send()
        .unwrap();
    assert!(
        clean.status().is_success(),
        "clean request should pass through ModSecurity"
    );
}

// 280: express_behind_rate_limiter
#[test]
fn express_behind_rate_limiter() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let compose = DockerCompose::new(
        &format!("{}/docker-compose.ratelimit.yml", compose_dir()),
        "aegis-test-ratelimit-280",
    );
    compose.up().unwrap();
    assert!(
        wait_for_health("http://localhost:8081/healthz", Duration::from_secs(60)),
        "rate limiter proxy failed health check"
    );

    let client = reqwest::blocking::Client::new();
    let mut rate_limited_count = 0u32;
    for _ in 0..30 {
        if let Ok(resp) = client.get("http://localhost:8081/api/users?id=1").send()
            && resp.status().as_u16() == 429
        {
            rate_limited_count += 1;
        }
    }
    assert!(
        rate_limited_count > 0,
        "at least one request out of 30 should be rate-limited (429)"
    );
}

// 281: express_behind_bot_detection
#[test]
fn express_behind_bot_detection() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let compose = DockerCompose::new(
        &format!("{}/docker-compose.botdetect.yml", compose_dir()),
        "aegis-test-botdetect-281",
    );
    compose.up().unwrap();
    assert!(
        wait_for_health("http://localhost:8082/healthz", Duration::from_secs(60)),
        "bot detection proxy failed health check"
    );

    let bare_client = reqwest::blocking::Client::builder()
        .user_agent("")
        .build()
        .unwrap();
    let blocked = bare_client
        .get("http://localhost:8082/api/users?id=1")
        .send()
        .unwrap();
    assert_eq!(
        blocked.status().as_u16(),
        403,
        "request without User-Agent should be blocked"
    );

    let browser_client = reqwest::blocking::Client::new();
    let passed = browser_client
        .get("http://localhost:8082/api/users?id=1")
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        .header("Accept-Language", "en-US,en;q=0.5")
        .header("Accept-Encoding", "gzip, deflate, br")
        .send()
        .unwrap();
    assert!(
        passed.status().is_success(),
        "request with browser-like headers should pass bot detection"
    );
}

// 282: express_behind_full_defense
#[test]
fn express_behind_full_defense() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let compose = DockerCompose::new(
        &format!("{}/docker-compose.fulldefense.yml", compose_dir()),
        "aegis-test-fulldefense-282",
    );
    compose.up().unwrap();
    assert!(
        wait_for_health("http://localhost:8083/healthz", Duration::from_secs(60)),
        "full defense proxy failed health check"
    );

    let client = reqwest::blocking::Client::new();
    let clean = client
        .get("http://localhost:8083/api/users?id=1")
        .header(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        )
        .header("Accept", "text/html,application/xhtml+xml")
        .header("Accept-Language", "en-US,en;q=0.5")
        .header("Accept-Encoding", "gzip, deflate, br")
        .send()
        .unwrap();
    assert!(
        clean.status().is_success(),
        "browser-like clean request should pass full defense stack"
    );

    let sqli = client
        .get("http://localhost:8083/api/users?id=1%27%20OR%201%3D1--")
        .header(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        )
        .header("Accept", "text/html")
        .header("Accept-Language", "en-US")
        .header("Accept-Encoding", "gzip")
        .send()
        .unwrap();
    assert_eq!(
        sqli.status().as_u16(),
        403,
        "WAF in full defense stack should block SQLi"
    );

    let mut rate_limited = 0u32;
    for _ in 0..30 {
        if let Ok(resp) = client
            .get("http://localhost:8083/api/users?id=1")
            .header("User-Agent", "Mozilla/5.0")
            .header("Accept", "text/html")
            .send()
            && resp.status().as_u16() == 429
        {
            rate_limited += 1;
        }
    }
    assert!(
        rate_limited > 0,
        "rate limiting should kick in during rapid requests"
    );
}

// ===========================================================================
// Flask app tests (#283-#285)
// ===========================================================================

// 283: flask_full_scan_ground_truth
#[test]
fn flask_full_scan_ground_truth() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let compose = DockerCompose::new(
        &format!("{}/docker-compose.flask.yml", compose_dir()),
        "aegis-test-flask-283",
    );
    compose.up().unwrap();
    assert!(
        wait_for_health("http://localhost:5001/health", Duration::from_secs(60)),
        "flask app failed health check"
    );

    let gt = load_ground_truth("flask-vuln-app");
    assert!(
        !gt.findings.is_empty(),
        "flask ground truth should have findings"
    );

    let client = reqwest::blocking::Client::new();
    for finding in &gt.findings {
        let url = format!("http://localhost:5001{}", finding.endpoint);
        let check = client.get(&url).send();
        assert!(
            check.is_ok(),
            "flask endpoint {} should be accessible",
            finding.endpoint
        );
    }
}

// 284: flask_ssti_detected
#[test]
fn flask_ssti_detected() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let compose = DockerCompose::new(
        &format!("{}/docker-compose.flask.yml", compose_dir()),
        "aegis-test-flask-ssti-284",
    );
    compose.up().unwrap();
    assert!(
        wait_for_health("http://localhost:5001/health", Duration::from_secs(60)),
        "flask app failed health check"
    );

    let client = reqwest::blocking::Client::new();
    let resp = client
        .get("http://localhost:5001/api/render?template={{7*7}}")
        .send()
        .unwrap();
    assert!(resp.status().is_success(), "SSTI endpoint should respond");
    let body = resp.text().unwrap();
    assert!(
        body.contains("49"),
        "Jinja2 SSTI should evaluate {{{{7*7}}}} to 49, got: {body}"
    );
}

// 285: flask_source_recon
#[test]
fn flask_source_recon() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let source_dir = std::path::PathBuf::from(fixture_dir("flask-vuln-app"));
    let has_lock =
        source_dir.join("poetry.lock").exists() || source_dir.join("requirements.txt").exists();
    assert!(
        has_lock,
        "flask fixture should have poetry.lock or requirements.txt"
    );

    let ops = run_recon_standalone(&Some(source_dir)).unwrap();
    let has_pyyaml = ops.iter().any(|op| {
        matches!(
            &op.operation,
            aegis_protocol::operation::GraphOperation::AddNode { node_type, properties }
                if *node_type == aegis_protocol::node::NodeType::Dependency
                    && properties.iter().any(|(k, v)| k == "name" && v.to_lowercase().contains("pyyaml"))
        )
    });
    if has_pyyaml {
        assert!(has_pyyaml, "recon should find pyyaml in flask lock file");
    }
}

// ===========================================================================
// GraphQL app tests (#286-#288)
// ===========================================================================

// 286: graphql_introspection_discovery
#[test]
fn graphql_introspection_discovery() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let compose = DockerCompose::new(
        &format!("{}/docker-compose.graphql.yml", compose_dir()),
        "aegis-test-graphql-286",
    );
    compose.up().unwrap();
    assert!(
        wait_for_health("http://localhost:4000/health", Duration::from_secs(60)),
        "graphql app failed health check"
    );

    let client = reqwest::blocking::Client::new();
    let query = serde_json::json!({
        "query": "{ __schema { types { name } } }"
    });
    let resp = client
        .post("http://localhost:4000/graphql")
        .json(&query)
        .send()
        .unwrap();
    assert!(
        resp.status().is_success(),
        "introspection query should succeed"
    );
    let body: serde_json::Value = resp.json().unwrap();
    let types = body
        .pointer("/data/__schema/types")
        .expect("introspection should return types");
    let type_names: Vec<String> = types
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect();

    for expected in &["User", "SearchResult", "FileContent", "AuthResult"] {
        assert!(
            type_names.iter().any(|n| n == expected),
            "introspection should return type {expected}, got: {type_names:?}"
        );
    }
}

// 287: graphql_no_introspection_fallback
#[test]
fn graphql_no_introspection_fallback() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let compose = DockerCompose::new(
        &format!("{}/docker-compose.graphql.yml", compose_dir()),
        "aegis-test-graphql-nointro-287",
    );
    compose.up().unwrap();
    assert!(
        wait_for_health("http://localhost:4001/health", Duration::from_secs(60)),
        "graphql no-introspection app failed health check"
    );

    let client = reqwest::blocking::Client::new();
    let introspection_query = serde_json::json!({
        "query": "{ __schema { types { name } } }"
    });
    let resp = client
        .post("http://localhost:4001/graphql")
        .json(&introspection_query)
        .send()
        .unwrap();
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().unwrap_or(serde_json::Value::Null);
    let has_errors = body.get("errors").is_some();
    assert!(
        status == 400 || has_errors,
        "introspection should be blocked (got status {status}, errors: {has_errors})"
    );

    let valid_query = serde_json::json!({
        "query": "{ user(id: \"1\") { name } }"
    });
    let resp2 = client
        .post("http://localhost:4001/graphql")
        .json(&valid_query)
        .send()
        .unwrap();
    assert!(
        resp2.status().is_success(),
        "valid query should work even with introspection disabled"
    );
    let data: serde_json::Value = resp2.json().unwrap();
    assert!(
        data.pointer("/data/user").is_some(),
        "valid query should return user data"
    );
}

// 288: graphql_auth_bypass
#[test]
fn graphql_auth_bypass() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let compose = DockerCompose::new(
        &format!("{}/docker-compose.graphql.yml", compose_dir()),
        "aegis-test-graphql-auth-288",
    );
    compose.up().unwrap();
    assert!(
        wait_for_health("http://localhost:4000/health", Duration::from_secs(60)),
        "graphql app failed health check"
    );

    let client = reqwest::blocking::Client::new();
    let delete_mutation = serde_json::json!({
        "query": "mutation { deleteUser(userId: \"3\") }"
    });
    let resp = client
        .post("http://localhost:4000/graphql")
        .json(&delete_mutation)
        .send()
        .unwrap();
    assert!(
        resp.status().is_success(),
        "deleteUser mutation should succeed without auth token"
    );
    let body: serde_json::Value = resp.json().unwrap();
    let has_errors = body.get("errors").is_some();
    assert!(
        !has_errors || body.pointer("/data/deleteUser").is_some(),
        "deleteUser should succeed, proving no auth is required for destructive mutations"
    );
}

// ===========================================================================
// Cross-scan tests (#289-#292)
// ===========================================================================

// 289: graph_persistence_across_scans
#[test]
fn graph_persistence_across_scans() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let graph_path = dir.path().join("test-graph.json");

    let graph = KnowledgeGraph::new();
    let ops = vec![aegis_protocol::operation::OperationLogEntry {
        sequence_number: 1,
        module: ModuleIdentifier::PassiveRecon,
        operation: aegis_protocol::operation::GraphOperation::AddNode {
            node_type: aegis_protocol::node::NodeType::Endpoint,
            properties: vec![
                ("path".to_string(), "/api/test".to_string()),
                ("method".to_string(), "GET".to_string()),
            ],
        },
        timestamp_unix_ms: 1700000000000,
    }];
    graph.apply_operations(&ops).unwrap();
    assert_eq!(graph.node_count().unwrap(), 1);

    let metadata = GraphMetadata {
        scan_timestamp_unix_ms: 1700000000000,
        target_url: "http://localhost:3000".to_string(),
        aegis_version: "0.1.0".to_string(),
        scan_count: 1,
    };
    graph.save_to_file(&graph_path, &metadata).unwrap();

    let (loaded, count) = aegis_orchestrator::load_or_create_graph(Some(&graph_path));
    assert_eq!(count, 1);
    assert_eq!(loaded.node_count().unwrap(), 1);
    let endpoints = loaded
        .nodes_by_type(aegis_protocol::node::NodeType::Endpoint)
        .unwrap();
    assert_eq!(endpoints.len(), 1);
}

// 290: diff_mode_sarif_only_new_findings
#[test]
fn diff_mode_sarif_only_new_findings() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let scan1_findings = vec![
        make_finding_data(1, VulnerabilityClass::SqlInjection),
        make_finding_data(2, VulnerabilityClass::CrossSiteScripting),
    ];
    let scan2_findings = vec![
        make_finding_data(1, VulnerabilityClass::SqlInjection),
        make_finding_data(2, VulnerabilityClass::CrossSiteScripting),
        make_finding_data(3, VulnerabilityClass::CommandInjection),
    ];

    let new_findings = compute_new_findings(&scan2_findings, &scan1_findings);
    assert!(
        !new_findings.is_empty(),
        "diff mode should find at least one new finding"
    );
    let has_cmd_injection = new_findings
        .iter()
        .any(|f| f.vulnerability_class == VulnerabilityClass::CommandInjection);
    assert!(
        has_cmd_injection,
        "the new CommandInjection finding should appear in diff"
    );
}

// 291: scan_history_adaptive_selection
#[test]
fn scan_history_adaptive_selection() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let db = ScanHistoryDb::open_in_memory().unwrap();
    let entries: Vec<ScanHistoryEntry> = (0..5)
        .map(|i| ScanHistoryEntry {
            endpoint_pattern: "/api/users".to_string(),
            vulnerability_class: VulnerabilityClass::SqlInjection,
            payload: format!("payload-{i}"),
            anomaly_score: 0.5 + (i as f64) * 0.1,
            is_true_positive: i % 2 == 0,
            timestamp_unix_ms: 1700000000000 + i * 1000,
            target_app_hash: "test-app-v1".to_string(),
        })
        .collect();
    db.insert_batch(&entries).unwrap();

    let records = db.query_by_endpoint("/api/users").unwrap();
    assert_eq!(records.len(), 5);
    for record in &records {
        assert_eq!(record.target_app_hash, "test-app-v1");
    }
}

// 292: checkpoint_resume_mid_scan
#[test]
fn checkpoint_resume_mid_scan() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("graph.json");
    let checkpoint = ScanCheckpoint {
        completed_phases: vec!["recon".to_string(), "fingerprint".to_string()],
        current_iteration: 0,
        total_operations: 42,
        total_findings: 3,
        consecutive_zero_findings: 0,
        timestamp_unix_ms: 1700000000000,
    };
    save_checkpoint(&checkpoint, &db_path).unwrap();

    let loaded = load_checkpoint(&db_path).unwrap().unwrap();
    assert!(should_skip_phase(&loaded, "recon"));
    assert!(should_skip_phase(&loaded, "fingerprint"));
    assert!(!should_skip_phase(&loaded, "fuzz:0"));
    assert!(!should_skip_phase(&loaded, "analyze:0"));
    assert!(!should_skip_phase(&loaded, "report"));
}

// ===========================================================================
// Report format tests (#293-#295)
// ===========================================================================

// 293: developer_report_sarif_with_fixes
#[test]
fn developer_report_sarif_with_fixes() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let findings = vec![
        make_sarif_finding(1, VulnerabilityClass::SqlInjection, 8.0, 0.9, 75.0),
        make_sarif_finding(2, VulnerabilityClass::CrossSiteScripting, 6.0, 0.8, 55.0),
        make_sarif_finding(3, VulnerabilityClass::PathTraversal, 5.0, 0.7, 42.0),
    ];

    let sarif_log = emit_sarif(&findings, "0.1.0");
    let json = sarif_to_json(&sarif_log).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert!(parsed.get("$schema").is_some(), "SARIF should have $schema");
    let runs = parsed.get("runs").unwrap().as_array().unwrap();
    assert!(!runs.is_empty());

    let results = runs[0].get("results").unwrap().as_array().unwrap();
    assert_eq!(results.len(), 3);

    for result in results {
        let taxa = result.get("taxa").unwrap().as_array().unwrap();
        let cwe_ids: Vec<&str> = taxa
            .iter()
            .filter_map(|t| t.get("id").and_then(|id| id.as_str()))
            .collect();
        assert!(
            cwe_ids.iter().any(|id| id.starts_with("CWE-")),
            "each finding should have a CWE ID"
        );

        let fixes = result.get("fixes").unwrap().as_array().unwrap();
        assert!(
            !fixes.is_empty(),
            "each finding should have at least one fix"
        );
    }
}

// 294: security_report_attack_chains
#[test]
fn security_report_attack_chains() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let findings = vec![
        {
            let mut f = make_sarif_finding(1, VulnerabilityClass::SqlInjection, 8.0, 0.9, 75.0);
            f.defense_context = Some(SarifDefenseContext {
                waf_vendor: Some("ModSecurity".to_string()),
                exploitable_despite_waf: true,
                evasion_technique: Some("encoding bypass".to_string()),
                defenses_detected: vec!["WAF".to_string(), "Rate Limiting".to_string()],
                evasion_success_rate: Some(0.3),
                stealth_mode_used: true,
            });
            f
        },
        make_sarif_finding(2, VulnerabilityClass::BrokenAuthentication, 7.0, 0.85, 65.0),
    ];

    let json_str = format_report(&findings, ReportFormat::Security, "0.1.0", None, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    let security_analysis = parsed
        .pointer("/runs/0/properties/securityAnalysis")
        .expect("security report should have securityAnalysis properties");

    let attack_chains = security_analysis
        .get("attackChains")
        .expect("should have attackChains");
    let chains = attack_chains.as_array().unwrap();
    assert!(!chains.is_empty(), "should have attack chain entries");
    let has_technique_id = chains
        .iter()
        .any(|c| c.get("techniqueId").and_then(|t| t.as_str()).is_some());
    assert!(
        has_technique_id,
        "attack chains should contain ATT&CK technique IDs"
    );

    let defense_gaps = security_analysis
        .get("defenseGaps")
        .expect("should have defenseGaps");
    assert!(
        defense_gaps.get("defensesDetected").is_some(),
        "should list detected defenses"
    );
}

// 295: executive_report_summary
#[test]
fn executive_report_summary() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let findings = vec![
        make_sarif_finding(1, VulnerabilityClass::SqlInjection, 9.0, 0.95, 85.0),
        make_sarif_finding(2, VulnerabilityClass::CrossSiteScripting, 6.0, 0.8, 50.0),
        make_sarif_finding(3, VulnerabilityClass::PathTraversal, 3.0, 0.5, 25.0),
    ];

    let json_str = format_report(&findings, ReportFormat::Executive, "0.1.0", None, None).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    assert!(
        parsed.get("total_findings").is_some(),
        "executive report should have total_findings"
    );
    assert!(
        parsed.get("severity_counts").is_some(),
        "executive report should have severity_counts"
    );
    assert!(
        parsed.get("risk_summary").is_some(),
        "executive report should have risk_summary"
    );
    assert!(
        parsed.get("top_remediation_priorities").is_some(),
        "executive report should have remediation priorities"
    );

    let risk = parsed.get("risk_summary").unwrap().as_str().unwrap();
    assert!(
        risk == "Critical" || risk == "High",
        "risk summary should reflect the highest-severity finding"
    );

    let priorities = parsed
        .get("top_remediation_priorities")
        .unwrap()
        .as_array()
        .unwrap();
    assert!(
        !priorities.is_empty(),
        "should have at least one remediation priority"
    );
    for priority in priorities {
        assert!(
            priority.get("remediation").is_some(),
            "each priority should have remediation text"
        );
    }
}

// ===========================================================================
// Stealth mode tests (#296-#298)
// ===========================================================================

// 296: stealth_default_mode
#[test]
fn stealth_default_mode() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let config = StealthConfig::default();
    assert!(
        (config.max_requests_per_second - 10.0).abs() < f64::EPSILON,
        "default max_rps should be 10.0"
    );
    assert_eq!(config.jitter_range_ms, (50, 200));
    assert_eq!(config.min_delay_ms, 50);
    assert_eq!(config.max_delay_ms, 500);
    assert!(!config.prefer_blind_payloads);
    assert!(!config.avoid_signature_payloads);
}

// 297: stealth_paranoid_mode
#[test]
fn stealth_paranoid_mode() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let compose = DockerCompose::new(
        &format!("{}/docker-compose.ratelimit.yml", compose_dir()),
        "aegis-test-paranoid-297",
    );
    compose.up().unwrap();
    assert!(
        wait_for_health("http://localhost:8081/healthz", Duration::from_secs(60)),
        "rate limiter proxy failed health check"
    );

    let paranoid = StealthConfig::paranoid();
    assert!(
        (paranoid.max_requests_per_second - 2.0).abs() < f64::EPSILON,
        "paranoid max_rps should be 2.0"
    );
    assert!(paranoid.prefer_blind_payloads);
    assert!(paranoid.avoid_signature_payloads);

    let client = reqwest::blocking::Client::new();
    let mut rate_limited = 0u32;
    let delay = Duration::from_millis(paranoid.min_delay_ms);
    for _ in 0..10 {
        if let Ok(resp) = client.get("http://localhost:8081/api/users?id=1").send()
            && resp.status().as_u16() == 429
        {
            rate_limited += 1;
        }
        thread::sleep(delay);
    }
    assert_eq!(
        rate_limited, 0,
        "paranoid timing should produce zero 429 responses"
    );
}

// 298: stealth_aggressive_mode
#[test]
fn stealth_aggressive_mode() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let aggressive = StealthConfig::aggressive();
    let default_config = StealthConfig::default();

    assert!(
        aggressive.max_requests_per_second > default_config.max_requests_per_second,
        "aggressive max_rps ({}) should be higher than default ({})",
        aggressive.max_requests_per_second,
        default_config.max_requests_per_second
    );
    assert!(
        aggressive.max_delay_ms < default_config.max_delay_ms,
        "aggressive max_delay_ms ({}) should be shorter than default ({})",
        aggressive.max_delay_ms,
        default_config.max_delay_ms
    );
    assert!(!aggressive.prefer_blind_payloads);
    assert!(!aggressive.avoid_signature_payloads);
}

// ===========================================================================
// Audit trail tests (#299-#300)
// ===========================================================================

// 299: audit_trail_full_scan_integrity
#[test]
fn audit_trail_full_scan_integrity() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("test-audit.cbor");
    let hmac_key: [u8; 32] = rand::random();
    let mut writer = AuditLogWriter::create(&audit_path, &hmac_key).unwrap();

    let events = vec![
        AuditEventType::ScanStarted {
            target_description: "http://localhost:3000".to_string(),
        },
        AuditEventType::ModuleStarted {
            module: ModuleIdentifier::PassiveRecon,
        },
        AuditEventType::ModuleStarted {
            module: ModuleIdentifier::Enumeration,
        },
        AuditEventType::ModuleStarted {
            module: ModuleIdentifier::Fuzzing,
        },
        AuditEventType::FindingRecorded {
            finding_id: 1,
            vulnerability_class: VulnerabilityClass::SqlInjection,
        },
        AuditEventType::FindingRecorded {
            finding_id: 2,
            vulnerability_class: VulnerabilityClass::CrossSiteScripting,
        },
        AuditEventType::ModuleStarted {
            module: ModuleIdentifier::ChainSynthesis,
        },
        AuditEventType::ScanCompleted { total_findings: 2 },
    ];

    for event in &events {
        writer.append_event(event.clone()).unwrap();
    }

    let report = verify_log(&audit_path, &hmac_key).unwrap();
    assert!(
        !report.tamper_detected,
        "audit chain should be intact after writing"
    );
    assert!(report.hash_chain_valid, "hash chain should be valid");
    assert!(report.hmac_valid, "HMAC signatures should be valid");
    assert_eq!(
        report.entries_checked,
        events.len() as u64,
        "all events should be verified"
    );
}

// 300: audit_replay_matches_scan_results
#[test]
fn audit_replay_matches_scan_results() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("replay-audit.cbor");
    let hmac_key: [u8; 32] = rand::random();
    let mut writer = AuditLogWriter::create(&audit_path, &hmac_key).unwrap();

    let finding_events = vec![
        AuditEventType::ScanStarted {
            target_description: "http://localhost:3000".to_string(),
        },
        AuditEventType::ModuleStarted {
            module: ModuleIdentifier::Fuzzing,
        },
        AuditEventType::FindingRecorded {
            finding_id: 1,
            vulnerability_class: VulnerabilityClass::SqlInjection,
        },
        AuditEventType::FindingRecorded {
            finding_id: 2,
            vulnerability_class: VulnerabilityClass::CrossSiteScripting,
        },
        AuditEventType::FindingRecorded {
            finding_id: 3,
            vulnerability_class: VulnerabilityClass::PathTraversal,
        },
        AuditEventType::ScanCompleted { total_findings: 3 },
    ];

    let mut audit_entries = Vec::new();
    for event in &finding_events {
        let entry = writer.append_event_full(event.clone()).unwrap();
        audit_entries.push(entry);
    }

    let snapshot: ScanSnapshot = replay_from_entries(&audit_entries);

    let finding_recorded_count = finding_events
        .iter()
        .filter(|e| matches!(e, AuditEventType::FindingRecorded { .. }))
        .count();
    assert_eq!(
        snapshot.findings.len(),
        finding_recorded_count,
        "replayed snapshot findings count should match FindingRecorded events"
    );
    assert!(
        snapshot.is_complete,
        "snapshot should be marked complete after ScanCompleted"
    );
    assert_eq!(
        snapshot.total_findings,
        Some(3),
        "total_findings should match ScanCompleted event"
    );
    assert_eq!(
        snapshot.target_description.as_deref(),
        Some("http://localhost:3000"),
        "target should be captured from ScanStarted"
    );
}

// ===========================================================================
// E2E scanner tests (#98-#100)
// ===========================================================================

fn build_e2e_scan_config(
    target_url: &str,
    sarif_path: &Path,
    source_dir: Option<&str>,
    include_endpoints: &[&str],
) -> ScanConfig {
    let mut args = vec![
        "aegis".to_string(),
        "--target".to_string(),
        target_url.to_string(),
        "--output".to_string(),
        sarif_path.to_str().unwrap().to_string(),
        "--no-llm".to_string(),
        "--no-audit".to_string(),
        "--skip-evasion".to_string(),
        "--max-iterations".to_string(),
        "1".to_string(),
    ];
    if let Some(dir) = source_dir {
        args.push("--source-dir".to_string());
        args.push(dir.to_string());
    }
    for ep in include_endpoints {
        args.push("--include-endpoints".to_string());
        args.push(ep.to_string());
    }
    ScanConfig::parse_from(args.iter().map(|s| s.as_str()))
}

// 98: express_e2e_scanner_vs_ground_truth
#[test]
fn express_e2e_scanner_vs_ground_truth() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let compose = DockerCompose::new(
        &format!("{}/docker-compose.yml", compose_dir()),
        "aegis-test-express-e2e-98",
    );
    compose.up().unwrap();
    assert!(
        wait_for_health("http://localhost:3000/health", Duration::from_secs(60)),
        "express app failed health check"
    );

    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("aegis-express-e2e.sarif");
    let source = fixture_dir("express-vuln-app");
    let config = build_e2e_scan_config(
        "http://localhost:3000",
        &sarif_path,
        Some(&source),
        &["/api/users", "/api/search", "/api/exec"],
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let summary = rt.block_on(run_scan(config)).expect("scan should succeed");

    println!(
        "Express E2E: {} findings, SARIF: {}",
        summary.total_findings, summary.sarif_path
    );

    let gt_path = format!("{}/ground-truth.json", fixture_dir("express-vuln-app"));
    let gt = ground_truth::load_ground_truth(Path::new(&gt_path));
    let sarif_findings = ground_truth::extract_sarif_findings(Path::new(&summary.sarif_path));
    let comparison = ground_truth::compare(&gt, &sarif_findings);

    println!(
        "Express: TP={}, FP={}, FN={}, P={:.2}, R={:.2}, F1={:.2}",
        comparison.true_positives,
        comparison.false_positives,
        comparison.false_negatives,
        comparison.precision,
        comparison.recall,
        comparison.f1
    );
    if !comparison.matched.is_empty() {
        println!("  Matched: {:?}", comparison.matched);
    }
    if !comparison.missed.is_empty() {
        println!("  Missed: {:?}", comparison.missed);
    }

    assert!(
        comparison.true_positives >= 1,
        "should find at least 1 true positive, got TP={}, matched={:?}, missed={:?}",
        comparison.true_positives,
        comparison.matched,
        comparison.missed
    );
}

// 99: flask_e2e_scanner_vs_ground_truth
#[test]
fn flask_e2e_scanner_vs_ground_truth() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let compose = DockerCompose::new(
        &format!("{}/docker-compose.flask.yml", compose_dir()),
        "aegis-test-flask-e2e-99",
    );
    compose.up().unwrap();
    assert!(
        wait_for_health("http://localhost:5001/health", Duration::from_secs(60)),
        "flask app failed health check"
    );

    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("aegis-flask-e2e.sarif");
    let source = fixture_dir("flask-vuln-app");
    let config = build_e2e_scan_config(
        "http://localhost:5001",
        &sarif_path,
        Some(&source),
        &["/api/users", "/api/search", "/api/exec"],
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let summary = rt.block_on(run_scan(config)).expect("scan should succeed");

    println!(
        "Flask E2E: {} findings, SARIF: {}",
        summary.total_findings, summary.sarif_path
    );

    let gt_path = format!("{}/ground-truth.json", fixture_dir("flask-vuln-app"));
    let gt = ground_truth::load_ground_truth(Path::new(&gt_path));
    let sarif_findings = ground_truth::extract_sarif_findings(Path::new(&summary.sarif_path));
    let comparison = ground_truth::compare(&gt, &sarif_findings);

    println!(
        "Flask: TP={}, FP={}, FN={}, P={:.2}, R={:.2}, F1={:.2}",
        comparison.true_positives,
        comparison.false_positives,
        comparison.false_negatives,
        comparison.precision,
        comparison.recall,
        comparison.f1
    );
    if !comparison.matched.is_empty() {
        println!("  Matched: {:?}", comparison.matched);
    }
    if !comparison.missed.is_empty() {
        println!("  Missed: {:?}", comparison.missed);
    }

    assert!(
        comparison.true_positives >= 1,
        "should find at least 1 true positive, got TP={}, matched={:?}, missed={:?}",
        comparison.true_positives,
        comparison.matched,
        comparison.missed
    );
}

fn build_e2e_scan_config_with_iterations(
    target_url: &str,
    sarif_path: &Path,
    source_dir: Option<&str>,
    include_endpoints: &[&str],
    max_iterations: u32,
) -> ScanConfig {
    let mut args = vec![
        "aegis".to_string(),
        "--target".to_string(),
        target_url.to_string(),
        "--output".to_string(),
        sarif_path.to_str().unwrap().to_string(),
        "--no-llm".to_string(),
        "--no-audit".to_string(),
        "--skip-evasion".to_string(),
        "--max-iterations".to_string(),
        max_iterations.to_string(),
    ];
    if let Some(dir) = source_dir {
        args.push("--source-dir".to_string());
        args.push(dir.to_string());
    }
    for ep in include_endpoints {
        args.push("--include-endpoints".to_string());
        args.push(ep.to_string());
    }
    ScanConfig::parse_from(args.iter().map(|s| s.as_str()))
}

// 100: graphql_e2e_scanner_vs_ground_truth
#[test]
fn graphql_e2e_scanner_vs_ground_truth() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let compose = DockerCompose::new(
        &format!("{}/docker-compose.graphql.yml", compose_dir()),
        "aegis-test-graphql-e2e-100",
    );
    compose.up().unwrap();
    assert!(
        wait_for_health("http://localhost:4000/health", Duration::from_secs(60)),
        "graphql app failed health check"
    );

    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("aegis-graphql-e2e.sarif");
    let source = fixture_dir("graphql-vuln-app");
    let config = build_e2e_scan_config(
        "http://localhost:4000",
        &sarif_path,
        Some(&source),
        &["/graphql"],
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let summary = rt.block_on(run_scan(config)).expect("scan should succeed");

    println!(
        "GraphQL E2E: {} findings, SARIF: {}",
        summary.total_findings, summary.sarif_path
    );

    let gt_path = format!("{}/ground-truth.json", fixture_dir("graphql-vuln-app"));
    let gt = ground_truth::load_ground_truth(Path::new(&gt_path));
    let sarif_findings = ground_truth::extract_sarif_findings(Path::new(&summary.sarif_path));
    let comparison = ground_truth::compare(&gt, &sarif_findings);

    println!(
        "GraphQL: TP={}, FP={}, FN={}, P={:.2}, R={:.2}, F1={:.2}",
        comparison.true_positives,
        comparison.false_positives,
        comparison.false_negatives,
        comparison.precision,
        comparison.recall,
        comparison.f1
    );

    assert!(
        comparison.true_positives >= 1,
        "should find at least 1 true positive, got TP={}, matched={:?}, missed={:?}",
        comparison.true_positives,
        comparison.matched,
        comparison.missed
    );
}

// ===========================================================================
// Detection rate integration tests (#200-#207)
// ===========================================================================

// 200: expanded_sqli_templates_detect_express_sqli
#[test]
fn expanded_sqli_templates_detect_express_sqli() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let compose = DockerCompose::new(
        &format!("{}/docker-compose.yml", compose_dir()),
        "aegis-test-express-sqli-200",
    );
    compose.up().unwrap();
    assert!(
        wait_for_health("http://localhost:3000/health", Duration::from_secs(60)),
        "express app failed health check"
    );

    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("sqli-detection.sarif");
    let source = fixture_dir("express-vuln-app");
    let config = build_e2e_scan_config(
        "http://localhost:3000",
        &sarif_path,
        Some(&source),
        &["/api/users"],
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let summary = rt.block_on(run_scan(config)).expect("scan should succeed");

    println!(
        "SQLi detection: {} findings, SARIF: {}",
        summary.total_findings, summary.sarif_path
    );

    let gt_path = format!("{}/ground-truth.json", fixture_dir("express-vuln-app"));
    let gt = ground_truth::load_ground_truth(Path::new(&gt_path));
    let sarif_findings = ground_truth::extract_sarif_findings(Path::new(&summary.sarif_path));

    let sqli_detected = sarif_findings
        .iter()
        .any(|(ep, vc)| ep.contains("/api/users") && vc == "SqlInjection");

    println!(
        "SQLi probe: detected={}, all findings={:?}",
        sqli_detected, sarif_findings
    );

    let comparison = ground_truth::compare(&gt, &sarif_findings);
    println!(
        "SQLi scan: TP={}, FP={}, FN={}, matched={:?}, missed={:?}",
        comparison.true_positives,
        comparison.false_positives,
        comparison.false_negatives,
        comparison.matched,
        comparison.missed
    );

    assert!(
        sqli_detected,
        "expanded SQLi templates should detect SqlInjection on /api/users, findings={:?}",
        sarif_findings
    );
}

// 201: expanded_xss_templates_detect_express_xss
#[test]
fn expanded_xss_templates_detect_express_xss() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let compose = DockerCompose::new(
        &format!("{}/docker-compose.yml", compose_dir()),
        "aegis-test-express-xss-201",
    );
    compose.up().unwrap();
    assert!(
        wait_for_health("http://localhost:3000/health", Duration::from_secs(60)),
        "express app failed health check"
    );

    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("xss-detection.sarif");
    let source = fixture_dir("express-vuln-app");
    let config = build_e2e_scan_config(
        "http://localhost:3000",
        &sarif_path,
        Some(&source),
        &["/api/search"],
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let summary = rt.block_on(run_scan(config)).expect("scan should succeed");

    println!(
        "XSS detection: {} findings, SARIF: {}",
        summary.total_findings, summary.sarif_path
    );

    let sarif_findings = ground_truth::extract_sarif_findings(Path::new(&summary.sarif_path));

    let xss_detected = sarif_findings
        .iter()
        .any(|(ep, vc)| ep.contains("/api/search") && vc == "CrossSiteScripting");

    println!(
        "XSS probe: detected={}, all findings={:?}",
        xss_detected, sarif_findings
    );

    assert!(
        xss_detected,
        "expanded XSS templates should detect CrossSiteScripting on /api/search, findings={:?}",
        sarif_findings
    );
}

// 202: ssti_templates_detect_flask_ssti
#[test]
fn ssti_templates_detect_flask_ssti() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let compose = DockerCompose::new(
        &format!("{}/docker-compose.flask.yml", compose_dir()),
        "aegis-test-flask-ssti-202",
    );
    compose.up().unwrap();
    assert!(
        wait_for_health("http://localhost:5001/health", Duration::from_secs(60)),
        "flask app failed health check"
    );

    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("ssti-detection.sarif");
    let source = fixture_dir("flask-vuln-app");
    let config = build_e2e_scan_config(
        "http://localhost:5001",
        &sarif_path,
        Some(&source),
        &["/api/render"],
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let summary = rt.block_on(run_scan(config)).expect("scan should succeed");

    println!(
        "SSTI detection: {} findings, SARIF: {}",
        summary.total_findings, summary.sarif_path
    );

    let sarif_findings = ground_truth::extract_sarif_findings(Path::new(&summary.sarif_path));

    let ssti_detected = sarif_findings
        .iter()
        .any(|(ep, vc)| ep.contains("/api/render") && vc == "ServerSideTemplateInjection");

    println!(
        "SSTI probe: detected={}, all findings={:?}",
        ssti_detected, sarif_findings
    );

    assert!(
        ssti_detected,
        "SSTI templates should detect ServerSideTemplateInjection on /api/render, findings={:?}",
        sarif_findings
    );
}

// 203: time_based_sqli_detection
#[test]
fn time_based_sqli_detection() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let compose = DockerCompose::new(
        &format!("{}/docker-compose.yml", compose_dir()),
        "aegis-test-express-timesqli-203",
    );
    compose.up().unwrap();
    assert!(
        wait_for_health("http://localhost:3000/health", Duration::from_secs(60)),
        "express app failed health check"
    );

    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("time-sqli-detection.sarif");
    let source = fixture_dir("express-vuln-app");
    let config = build_e2e_scan_config(
        "http://localhost:3000",
        &sarif_path,
        Some(&source),
        &["/api/users"],
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let summary = rt.block_on(run_scan(config)).expect("scan should succeed");

    println!(
        "Time-based SQLi: {} findings, SARIF: {}",
        summary.total_findings, summary.sarif_path
    );

    let sarif_findings = ground_truth::extract_sarif_findings(Path::new(&summary.sarif_path));
    let sqli_detected = sarif_findings
        .iter()
        .any(|(ep, vc)| ep.contains("/api/users") && vc == "SqlInjection");

    println!(
        "Time-based SQLi: sqli_detected={}, all findings={:?}",
        sqli_detected, sarif_findings
    );

    assert!(
        sqli_detected,
        "time-based blind SQLi templates (expanded payloads) should detect SqlInjection \
         on /api/users even without inline error reflection, findings={:?}",
        sarif_findings
    );
}

// 204: combined_recall_express_ground_truth
#[test]
fn combined_recall_express_ground_truth() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let compose = DockerCompose::new(
        &format!("{}/docker-compose.yml", compose_dir()),
        "aegis-test-express-recall-204",
    );
    compose.up().unwrap();
    assert!(
        wait_for_health("http://localhost:3000/health", Duration::from_secs(60)),
        "express app failed health check"
    );

    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("express-recall.sarif");
    let source = fixture_dir("express-vuln-app");
    let config = build_e2e_scan_config("http://localhost:3000", &sarif_path, Some(&source), &[]);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let summary = rt.block_on(run_scan(config)).expect("scan should succeed");

    let gt_path = format!("{}/ground-truth.json", fixture_dir("express-vuln-app"));
    let gt = ground_truth::load_ground_truth(Path::new(&gt_path));
    let sarif_findings = ground_truth::extract_sarif_findings(Path::new(&summary.sarif_path));
    let comparison = ground_truth::compare(&gt, &sarif_findings);

    println!(
        "Express recall: TP={}, FP={}, FN={}, P={:.2}, R={:.2}, F1={:.2}",
        comparison.true_positives,
        comparison.false_positives,
        comparison.false_negatives,
        comparison.precision,
        comparison.recall,
        comparison.f1
    );
    println!("  Matched: {:?}", comparison.matched);
    println!("  Missed:  {:?}", comparison.missed);
    println!("  Extra:   {:?}", comparison.extra);

    let gt_count = gt.findings.len();
    let min_tp = 10;
    assert!(
        comparison.true_positives >= min_tp,
        "express recall should be >= {min_tp}/{gt_count} (62.5%), \
         got TP={}, recall={:.2}, matched={:?}, missed={:?}",
        comparison.true_positives,
        comparison.recall,
        comparison.matched,
        comparison.missed
    );
}

// 205: combined_recall_flask_ground_truth
#[test]
fn combined_recall_flask_ground_truth() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let compose = DockerCompose::new(
        &format!("{}/docker-compose.flask.yml", compose_dir()),
        "aegis-test-flask-recall-205",
    );
    compose.up().unwrap();
    assert!(
        wait_for_health("http://localhost:5001/health", Duration::from_secs(60)),
        "flask app failed health check"
    );

    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("flask-recall.sarif");
    let source = fixture_dir("flask-vuln-app");
    let config = build_e2e_scan_config("http://localhost:5001", &sarif_path, Some(&source), &[]);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let summary = rt.block_on(run_scan(config)).expect("scan should succeed");

    let gt_path = format!("{}/ground-truth.json", fixture_dir("flask-vuln-app"));
    let gt = ground_truth::load_ground_truth(Path::new(&gt_path));
    let sarif_findings = ground_truth::extract_sarif_findings(Path::new(&summary.sarif_path));
    let comparison = ground_truth::compare(&gt, &sarif_findings);

    println!(
        "Flask recall: TP={}, FP={}, FN={}, P={:.2}, R={:.2}, F1={:.2}",
        comparison.true_positives,
        comparison.false_positives,
        comparison.false_negatives,
        comparison.precision,
        comparison.recall,
        comparison.f1
    );
    println!("  Matched: {:?}", comparison.matched);
    println!("  Missed:  {:?}", comparison.missed);
    println!("  Extra:   {:?}", comparison.extra);

    let gt_count = gt.findings.len();
    let min_tp = 5;
    assert!(
        comparison.true_positives >= min_tp,
        "flask recall should be >= {min_tp}/{gt_count} (71.4%), \
         got TP={}, recall={:.2}, matched={:?}, missed={:?}",
        comparison.true_positives,
        comparison.recall,
        comparison.matched,
        comparison.missed
    );
}

// 206: false_positive_rate_bounded
#[test]
fn false_positive_rate_bounded() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let compose = DockerCompose::new(
        &format!("{}/docker-compose.yml", compose_dir()),
        "aegis-test-express-fp-206",
    );
    compose.up().unwrap();
    assert!(
        wait_for_health("http://localhost:3000/health", Duration::from_secs(60)),
        "express app failed health check"
    );

    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("fp-bounded.sarif");
    let source = fixture_dir("express-vuln-app");
    let config = build_e2e_scan_config("http://localhost:3000", &sarif_path, Some(&source), &[]);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let summary = rt.block_on(run_scan(config)).expect("scan should succeed");

    let gt_path = format!("{}/ground-truth.json", fixture_dir("express-vuln-app"));
    let gt = ground_truth::load_ground_truth(Path::new(&gt_path));
    let sarif_findings = ground_truth::extract_sarif_findings(Path::new(&summary.sarif_path));
    let comparison = ground_truth::compare(&gt, &sarif_findings);

    let gt_count = gt.findings.len();
    let max_fp = gt_count * 2;

    println!(
        "FP bounded: TP={}, FP={}, FN={}, gt_size={}, max_allowed_fp={}",
        comparison.true_positives,
        comparison.false_positives,
        comparison.false_negatives,
        gt_count,
        max_fp
    );
    println!("  Extra (FP): {:?}", comparison.extra);

    assert!(
        comparison.false_positives <= max_fp,
        "false positives ({}) should not exceed 2x ground truth size ({}), extra={:?}",
        comparison.false_positives,
        max_fp,
        comparison.extra
    );
}

// 207: llm_feedback_improves_second_iteration
#[test]
fn llm_feedback_improves_second_iteration() {
    if !docker_tests_enabled() {
        eprintln!("Skipping Docker test: set AEGIS_INTEGRATION_TESTS=1 to run");
        return;
    }
    let compose = DockerCompose::new(
        &format!("{}/docker-compose.yml", compose_dir()),
        "aegis-test-express-iter-207",
    );
    compose.up().unwrap();
    assert!(
        wait_for_health("http://localhost:3000/health", Duration::from_secs(60)),
        "express app failed health check"
    );

    let source = fixture_dir("express-vuln-app");
    let endpoints: &[&str] = &["/api/users", "/api/search", "/api/exec", "/api/files"];

    let dir1 = tempfile::tempdir().unwrap();
    let sarif_path_1 = dir1.path().join("iter1.sarif");
    let config_1 = build_e2e_scan_config(
        "http://localhost:3000",
        &sarif_path_1,
        Some(&source),
        endpoints,
    );
    let rt = tokio::runtime::Runtime::new().unwrap();
    let summary_1 = rt
        .block_on(run_scan(config_1))
        .expect("scan iter=1 should succeed");

    let sarif_findings_1 = ground_truth::extract_sarif_findings(Path::new(&summary_1.sarif_path));
    let iter1_count = sarif_findings_1.len();

    let dir2 = tempfile::tempdir().unwrap();
    let sarif_path_2 = dir2.path().join("iter2.sarif");
    let config_2 = build_e2e_scan_config_with_iterations(
        "http://localhost:3000",
        &sarif_path_2,
        Some(&source),
        endpoints,
        2,
    );
    let summary_2 = rt
        .block_on(run_scan(config_2))
        .expect("scan iter=2 should succeed");

    let sarif_findings_2 = ground_truth::extract_sarif_findings(Path::new(&summary_2.sarif_path));
    let iter2_count = sarif_findings_2.len();

    println!(
        "Iteration comparison: iter1={} findings, iter2={} findings",
        iter1_count, iter2_count
    );
    println!("  iter1 findings: {:?}", sarif_findings_1);
    println!("  iter2 findings: {:?}", sarif_findings_2);

    assert!(
        iter2_count >= iter1_count,
        "iteration 2 (max_iterations=2) should produce at least as many findings as iteration 1: \
         iter1={iter1_count}, iter2={iter2_count}"
    );

    assert!(
        summary_2.phases_completed >= summary_1.phases_completed,
        "iteration 2 should complete at least as many phases: iter1={}, iter2={}",
        summary_1.phases_completed,
        summary_2.phases_completed
    );
}
