use std::time::Duration;

use crate::graph_api::GraphEvent;
use crate::state::{AppState, Finding, GraphEdge, GraphNode, ScanStatus};

/// Starts the demo scan — a pre-scripted sequence of events that simulates
/// a realistic AEGIS scan lifecycle.
pub fn start_demo_scan(state: AppState) {
    tokio::spawn(async move {
        run_demo_sequence(state).await;
    });
}

async fn run_demo_sequence(state: AppState) {
    {
        let mut status = state.scan_status.write();
        *status = ScanStatus {
            phase: "recon".to_string(),
            progress_pct: 0.0,
            is_running: true,
            is_paused: false,
            total_findings: 0,
            risk_score: 0.0,
            duration_ms: 0,
            target: "https://demo.example.com".to_string(),
        };
    }

    emit(&state, GraphEvent::LogMessage {
        level: "info".to_string(),
        message: "Starting recon on https://demo.example.com...".to_string(),
    });
    emit(&state, GraphEvent::PhaseChanged {
        phase: "Reconnaissance".to_string(),
        progress_pct: 5.0,
    });

    sleep_unless_stopped(&state, Duration::from_secs(3)).await;
    if !is_running(&state) { return; }

    // Discover 5 endpoints
    let endpoints = [
        ("ep-1", "/api/search", "GET"),
        ("ep-2", "/api/users/{id}", "GET"),
        ("ep-3", "/api/login", "POST"),
        ("ep-4", "/comments", "POST"),
        ("ep-5", "/api/admin/config", "GET"),
    ];

    for (id, path, method) in &endpoints {
        emit(&state, GraphEvent::NodeAdded {
            id: id.to_string(),
            node_type: "endpoint".to_string(),
            label: format!("{} {}", method, path),
            severity: None,
            data: serde_json::json!({"method": method, "path": path, "params": 3}),
        });
        add_node(&state, id, "endpoint", &format!("{} {}", method, path), None);
        tokio::time::sleep(Duration::from_millis(400)).await;
    }

    emit(&state, GraphEvent::LogMessage {
        level: "info".to_string(),
        message: "5 endpoints discovered".to_string(),
    });
    emit(&state, GraphEvent::PhaseChanged {
        phase: "Reconnaissance".to_string(),
        progress_pct: 20.0,
    });

    // Tech stack identified
    sleep_unless_stopped(&state, Duration::from_secs(5)).await;
    if !is_running(&state) { return; }

    emit(&state, GraphEvent::NodeAdded {
        id: "asset-db".to_string(),
        node_type: "asset".to_string(),
        label: "PostgreSQL".to_string(),
        severity: None,
        data: serde_json::json!({"type": "database", "version": "14.2"}),
    });
    add_node(&state, "asset-db", "asset", "PostgreSQL", None);

    emit(&state, GraphEvent::LogMessage {
        level: "info".to_string(),
        message: "Tech stack identified: Rails 6.1, PostgreSQL 14.2".to_string(),
    });

    emit(&state, GraphEvent::PhaseChanged {
        phase: "Fingerprinting".to_string(),
        progress_pct: 30.0,
    });
    update_phase(&state, "fingerprint", 30.0);

    // Fuzzing phase — find SQLi
    sleep_unless_stopped(&state, Duration::from_secs(7)).await;
    if !is_running(&state) { return; }

    emit(&state, GraphEvent::PhaseChanged {
        phase: "Fuzzing".to_string(),
        progress_pct: 45.0,
    });
    update_phase(&state, "fuzzing", 45.0);

    emit(&state, GraphEvent::LogMessage {
        level: "warn".to_string(),
        message: "Anomaly detected on /api/search — testing SQL injection...".to_string(),
    });

    tokio::time::sleep(Duration::from_secs(2)).await;

    // SQLi confirmed
    emit(&state, GraphEvent::NodeAdded {
        id: "vuln-sqli".to_string(),
        node_type: "vulnerability".to_string(),
        label: "SQL Injection".to_string(),
        severity: Some("critical".to_string()),
        data: serde_json::json!({"cwe": "CWE-89", "payload": "' OR 1=1 --"}),
    });
    add_node(&state, "vuln-sqli", "vulnerability", "SQL Injection", Some("critical"));

    emit(&state, GraphEvent::EdgeAdded {
        source: "ep-1".to_string(),
        target: "vuln-sqli".to_string(),
        label: "exploits".to_string(),
    });
    add_edge(&state, "ep-1", "vuln-sqli", "exploits");

    emit(&state, GraphEvent::NodeUpdated {
        id: "vuln-sqli".to_string(),
        status: "vulnerable".to_string(),
        confidence: Some(0.95),
    });

    emit(&state, GraphEvent::FindingConfirmed {
        node_id: "ep-1".to_string(),
        vuln_class: "SQL Injection".to_string(),
        severity: "Critical".to_string(),
        evidence_preview: "Parameter 'q' in /api/search: payload `' OR 1=1 --` returned 200 with 847 extra rows".to_string(),
    });
    add_finding(&state, "f-1", "SQL Injection", "Critical", "/api/search", 0.95,
        "Parameter 'q': payload `' OR 1=1 --` returned 200 with 847 extra rows");

    emit(&state, GraphEvent::LogMessage {
        level: "error".to_string(),
        message: "[CRITICAL] SQL Injection confirmed on /api/search (confidence: 95%)".to_string(),
    });

    // IDOR
    sleep_unless_stopped(&state, Duration::from_secs(5)).await;
    if !is_running(&state) { return; }

    emit(&state, GraphEvent::NodeAdded {
        id: "vuln-idor".to_string(),
        node_type: "vulnerability".to_string(),
        label: "IDOR".to_string(),
        severity: Some("high".to_string()),
        data: serde_json::json!({"cwe": "CWE-639"}),
    });
    add_node(&state, "vuln-idor", "vulnerability", "IDOR", Some("high"));

    emit(&state, GraphEvent::EdgeAdded {
        source: "ep-2".to_string(),
        target: "vuln-idor".to_string(),
        label: "exploits".to_string(),
    });
    add_edge(&state, "ep-2", "vuln-idor", "exploits");

    emit(&state, GraphEvent::FindingConfirmed {
        node_id: "ep-2".to_string(),
        vuln_class: "Insecure Direct Object Reference".to_string(),
        severity: "High".to_string(),
        evidence_preview: "GET /api/users/1 with user_id=2 token returns user 1 data — no authz check".to_string(),
    });
    add_finding(&state, "f-2", "IDOR", "High", "/api/users/{id}", 0.88,
        "GET /api/users/1 with user_id=2 token returns user 1 data");

    emit(&state, GraphEvent::LogMessage {
        level: "error".to_string(),
        message: "[HIGH] IDOR on /api/users/{id} (confidence: 88%)".to_string(),
    });

    emit(&state, GraphEvent::PhaseChanged {
        phase: "Chain Analysis".to_string(),
        progress_pct: 65.0,
    });
    update_phase(&state, "chain-analysis", 65.0);

    // Chain: SQLi → DB → Credentials
    sleep_unless_stopped(&state, Duration::from_secs(8)).await;
    if !is_running(&state) { return; }

    emit(&state, GraphEvent::EdgeAdded {
        source: "vuln-sqli".to_string(),
        target: "asset-db".to_string(),
        label: "exposes".to_string(),
    });
    add_edge(&state, "vuln-sqli", "asset-db", "exposes");

    emit(&state, GraphEvent::NodeAdded {
        id: "vuln-cred".to_string(),
        node_type: "vulnerability".to_string(),
        label: "Credential Extraction".to_string(),
        severity: Some("critical".to_string()),
        data: serde_json::json!({"chain": true}),
    });
    add_node(&state, "vuln-cred", "vulnerability", "Credential Extraction", Some("critical"));

    emit(&state, GraphEvent::EdgeAdded {
        source: "asset-db".to_string(),
        target: "vuln-cred".to_string(),
        label: "chains_to".to_string(),
    });
    add_edge(&state, "asset-db", "vuln-cred", "chains_to");

    emit(&state, GraphEvent::LogMessage {
        level: "error".to_string(),
        message: "Attack chain: SQLi → DB dump → credential extraction".to_string(),
    });

    emit(&state, GraphEvent::PhaseChanged {
        phase: "Fuzzing".to_string(),
        progress_pct: 80.0,
    });

    // XSS
    sleep_unless_stopped(&state, Duration::from_secs(7)).await;
    if !is_running(&state) { return; }

    emit(&state, GraphEvent::NodeAdded {
        id: "vuln-xss".to_string(),
        node_type: "vulnerability".to_string(),
        label: "Stored XSS".to_string(),
        severity: Some("medium".to_string()),
        data: serde_json::json!({"cwe": "CWE-79", "payload": "<img src=x onerror=alert(1)>"}),
    });
    add_node(&state, "vuln-xss", "vulnerability", "Stored XSS", Some("medium"));

    emit(&state, GraphEvent::EdgeAdded {
        source: "ep-4".to_string(),
        target: "vuln-xss".to_string(),
        label: "exploits".to_string(),
    });
    add_edge(&state, "ep-4", "vuln-xss", "exploits");

    emit(&state, GraphEvent::FindingConfirmed {
        node_id: "ep-4".to_string(),
        vuln_class: "Cross-Site Scripting".to_string(),
        severity: "Medium".to_string(),
        evidence_preview: "POST /comments body: <img src=x onerror=alert(1)> reflected in response without encoding".to_string(),
    });
    add_finding(&state, "f-3", "Stored XSS", "Medium", "/comments", 0.82,
        "POST /comments: <img src=x onerror=alert(1)> reflected without encoding");

    emit(&state, GraphEvent::LogMessage {
        level: "warn".to_string(),
        message: "[MEDIUM] Stored XSS on /comments (confidence: 82%)".to_string(),
    });

    emit(&state, GraphEvent::PhaseChanged {
        phase: "Reporting".to_string(),
        progress_pct: 95.0,
    });
    update_phase(&state, "reporting", 95.0);

    // Scan complete
    sleep_unless_stopped(&state, Duration::from_secs(5)).await;

    emit(&state, GraphEvent::ScanComplete {
        total_findings: 5,
        risk_score: 78.0,
        duration_ms: 40_000,
    });

    {
        let mut status = state.scan_status.write();
        status.phase = "complete".to_string();
        status.progress_pct = 100.0;
        status.is_running = false;
        status.total_findings = 5;
        status.risk_score = 78.0;
        status.duration_ms = 40_000;
    }
}

fn emit(state: &AppState, event: GraphEvent) {
    {
        let mut graph = state.graph.write();
        graph.events.push(event.clone());
    }
    let _ = state.event_tx.send(event);
}

fn add_node(state: &AppState, id: &str, ntype: &str, label: &str, severity: Option<&str>) {
    let mut graph = state.graph.write();
    graph.nodes.insert(id.to_string(), GraphNode {
        id: id.to_string(),
        node_type: ntype.to_string(),
        label: label.to_string(),
        severity: severity.map(|s| s.to_string()),
        status: "discovered".to_string(),
        confidence: None,
        data: serde_json::Value::Null,
    });
}

fn add_edge(state: &AppState, source: &str, target: &str, label: &str) {
    let mut graph = state.graph.write();
    graph.edges.push(GraphEdge {
        source: source.to_string(),
        target: target.to_string(),
        label: label.to_string(),
    });
}

fn add_finding(
    state: &AppState, id: &str, vuln_class: &str, severity: &str,
    endpoint: &str, confidence: f64, evidence: &str,
) {
    let mut graph = state.graph.write();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    graph.findings.push(Finding {
        id: id.to_string(),
        vuln_class: vuln_class.to_string(),
        severity: severity.to_string(),
        endpoint: endpoint.to_string(),
        confidence,
        evidence_preview: evidence.to_string(),
        timestamp_ms: ts,
    });
    let mut status = state.scan_status.write();
    status.total_findings = graph.findings.len() as u64;
}

fn update_phase(state: &AppState, phase: &str, pct: f64) {
    let mut status = state.scan_status.write();
    status.phase = phase.to_string();
    status.progress_pct = pct;
}

fn is_running(state: &AppState) -> bool {
    state.scan_status.read().is_running
}

async fn sleep_unless_stopped(state: &AppState, dur: Duration) {
    let steps = 10;
    let step_dur = dur / steps;
    for _ in 0..steps {
        if !is_running(state) { return; }
        // Wait while paused
        while state.scan_status.read().is_paused {
            tokio::time::sleep(Duration::from_millis(200)).await;
            if !is_running(state) { return; }
        }
        tokio::time::sleep(step_dur).await;
    }
}

#[cfg(test)]
#[path = "scan_bridge_test.rs"]
mod scan_bridge_test;
