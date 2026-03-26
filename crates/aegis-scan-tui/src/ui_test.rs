use crate::app::{App, ScanProfile};

#[test]
fn truncate_str_short() {
    let result = super::truncate_str("hello", 10);
    assert_eq!(result, "hello");
}

#[test]
fn truncate_str_exact() {
    let result = super::truncate_str("hello", 5);
    assert_eq!(result, "hello");
}

#[test]
fn truncate_str_long() {
    let result = super::truncate_str("hello world", 6);
    assert_eq!(result, "hello…");
}

#[test]
fn dashboard_renders_without_panic() {
    let app = App::new("http://example.com".to_string(), ScanProfile::Standard);
    let backend = ratatui::backend::TestBackend::new(120, 40);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| super::render_dashboard(frame, &app))
        .unwrap();
}

#[test]
fn dashboard_renders_with_findings() {
    let mut app = App::new("http://example.com".to_string(), ScanProfile::Deep);
    let f = crate::app::Finding {
        id: 0,
        severity: crate::app::Severity::Critical,
        vuln_type: "SQL Injection".to_string(),
        endpoint: "/api/login".to_string(),
        method: "POST".to_string(),
        confidence: 0.95,
        discovered_at: std::time::Instant::now(),
        description: "test".to_string(),
        evidence_request: "GET /".to_string(),
        evidence_response: "200 OK".to_string(),
        curl_command: "curl http://x".to_string(),
        remediation: "fix it".to_string(),
        cvss_score: 9.8,
        cvss_vector: "AV:N".to_string(),
        cwe_id: "CWE-89".to_string(),
        attack_technique: "T1190".to_string(),
    };
    app.findings.push(f);

    let chain = crate::app::AttackChain {
        nodes: vec![
            crate::app::ChainNode {
                label: "SQLi".to_string(),
                finding_id: 0,
            },
            crate::app::ChainNode {
                label: "RCE".to_string(),
                finding_id: 1,
            },
        ],
        total_severity: 19.0,
    };
    app.attack_chains.push(chain);

    app.active_modules.push(crate::app::ActiveModule {
        name: "Fuzzer".to_string(),
        spinner_tick: 2,
    });

    let backend = ratatui::backend::TestBackend::new(120, 40);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| super::render_dashboard(frame, &app))
        .unwrap();
}
