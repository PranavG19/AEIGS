use crate::app::{App, Finding, ScanProfile, Severity};

#[test]
fn stats_renders_empty() {
    let app = App::new("http://example.com".to_string(), ScanProfile::Standard);
    let backend = ratatui::backend::TestBackend::new(120, 40);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| super::render_stats(frame, &app))
        .unwrap();
}

#[test]
fn stats_renders_with_findings() {
    let mut app = App::new("http://example.com".to_string(), ScanProfile::Standard);
    app.endpoints_discovered = 20;
    app.endpoints_tested = 15;

    for (i, sev) in [Severity::Critical, Severity::High, Severity::Medium]
        .iter()
        .enumerate()
    {
        let f = Finding {
            id: i as u64,
            severity: *sev,
            vuln_type: format!("Vuln-{i}"),
            endpoint: "/api".to_string(),
            method: "GET".to_string(),
            confidence: 0.8,
            discovered_at: std::time::Instant::now(),
            description: String::new(),
            evidence_request: String::new(),
            evidence_response: String::new(),
            curl_command: String::new(),
            remediation: String::new(),
            cvss_score: 7.0,
            cvss_vector: String::new(),
            cwe_id: String::new(),
            attack_technique: String::new(),
        };
        app.findings.push(f);
    }

    let backend = ratatui::backend::TestBackend::new(120, 40);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| super::render_stats(frame, &app))
        .unwrap();
}
