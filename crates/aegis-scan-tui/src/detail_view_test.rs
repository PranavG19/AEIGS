use crate::app::{App, ScanProfile};

#[test]
fn detail_renders_without_findings() {
    let app = App::new("http://example.com".to_string(), ScanProfile::Standard);
    let backend = ratatui::backend::TestBackend::new(120, 40);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| super::render_detail(frame, &app))
        .unwrap();
}

#[test]
fn detail_renders_with_finding() {
    let mut app = App::new("http://example.com".to_string(), ScanProfile::Standard);
    let f = crate::app::Finding {
        id: 0,
        severity: crate::app::Severity::High,
        vuln_type: "XSS".to_string(),
        endpoint: "/search".to_string(),
        method: "GET".to_string(),
        confidence: 0.91,
        discovered_at: std::time::Instant::now(),
        description: "Reflected XSS in search parameter".to_string(),
        evidence_request: "GET /search?q=<script>alert(1)</script>".to_string(),
        evidence_response: "HTTP/1.1 200 OK\n<script>alert(1)</script>".to_string(),
        curl_command: "curl 'http://target/search?q=<script>'".to_string(),
        remediation: "Encode output and apply CSP headers.".to_string(),
        cvss_score: 7.5,
        cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N".to_string(),
        cwe_id: "CWE-79".to_string(),
        attack_technique: "T1189".to_string(),
    };
    app.findings.push(f);
    app.selected_finding = 0;

    let backend = ratatui::backend::TestBackend::new(120, 40);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| super::render_detail(frame, &app))
        .unwrap();
}
