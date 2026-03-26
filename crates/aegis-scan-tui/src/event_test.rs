use super::*;
use crate::app::{ActiveView, App, ScanProfile};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::empty())
}

fn key_ctrl(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::CONTROL)
}

#[test]
fn map_key_quit() {
    assert_eq!(map_key(key(KeyCode::Char('q'))), Action::Quit);
}

#[test]
fn map_key_ctrl_c_quit() {
    assert_eq!(map_key(key_ctrl(KeyCode::Char('c'))), Action::Quit);
}

#[test]
fn map_key_pause() {
    assert_eq!(map_key(key(KeyCode::Char('p'))), Action::Pause);
}

#[test]
fn map_key_stats() {
    assert_eq!(map_key(key(KeyCode::Char('s'))), Action::ShowStats);
}

#[test]
fn map_key_export() {
    assert_eq!(map_key(key(KeyCode::Char('e'))), Action::Export);
}

#[test]
fn map_key_navigation() {
    assert_eq!(map_key(key(KeyCode::Up)), Action::ScrollUp);
    assert_eq!(map_key(key(KeyCode::Down)), Action::ScrollDown);
    assert_eq!(map_key(key(KeyCode::Char('k'))), Action::ScrollUp);
    assert_eq!(map_key(key(KeyCode::Char('j'))), Action::ScrollDown);
    assert_eq!(map_key(key(KeyCode::Enter)), Action::Enter);
    assert_eq!(map_key(key(KeyCode::Esc)), Action::Escape);
    assert_eq!(map_key(key(KeyCode::Tab)), Action::SelectNext);
    assert_eq!(map_key(key(KeyCode::BackTab)), Action::SelectPrev);
}

#[test]
fn map_key_unknown() {
    assert_eq!(map_key(key(KeyCode::Char('z'))), Action::None);
}

#[test]
fn handle_quit_returns_false() {
    let mut app = App::new("http://x.com".to_string(), ScanProfile::Quick);
    let cont = handle_action(&mut app, Action::Quit);
    assert!(!cont);
    assert!(app.should_quit);
}

#[test]
fn handle_pause_toggles() {
    let mut app = App::new("http://x.com".to_string(), ScanProfile::Quick);
    assert!(!app.is_paused);
    handle_action(&mut app, Action::Pause);
    assert!(app.is_paused);
    handle_action(&mut app, Action::Pause);
    assert!(!app.is_paused);
}

#[test]
fn handle_enter_opens_detail_when_findings_exist() {
    let mut app = App::new("http://x.com".to_string(), ScanProfile::Quick);
    handle_action(&mut app, Action::Enter);
    assert_eq!(app.active_view, ActiveView::Dashboard);

    let f = crate::app::Finding {
        id: 0,
        severity: crate::app::Severity::High,
        vuln_type: "test".to_string(),
        endpoint: "/".to_string(),
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
    handle_action(&mut app, Action::Enter);
    assert_eq!(app.active_view, ActiveView::FindingDetail);
}

#[test]
fn handle_escape_returns_to_dashboard() {
    let mut app = App::new("http://x.com".to_string(), ScanProfile::Quick);
    app.active_view = ActiveView::Stats;
    handle_action(&mut app, Action::Escape);
    assert_eq!(app.active_view, ActiveView::Dashboard);
}

#[test]
fn handle_stats_toggles() {
    let mut app = App::new("http://x.com".to_string(), ScanProfile::Quick);
    handle_action(&mut app, Action::ShowStats);
    assert_eq!(app.active_view, ActiveView::Stats);
    handle_action(&mut app, Action::ShowStats);
    assert_eq!(app.active_view, ActiveView::Dashboard);
}

#[test]
fn scroll_up_down_in_dashboard() {
    let mut app = App::new("http://x.com".to_string(), ScanProfile::Quick);
    for i in 0..5 {
        let f = crate::app::Finding {
            id: i,
            severity: crate::app::Severity::Medium,
            vuln_type: format!("vuln-{i}"),
            endpoint: "/".to_string(),
            method: "GET".to_string(),
            confidence: 0.5,
            discovered_at: std::time::Instant::now(),
            description: String::new(),
            evidence_request: String::new(),
            evidence_response: String::new(),
            curl_command: String::new(),
            remediation: String::new(),
            cvss_score: 5.0,
            cvss_vector: String::new(),
            cwe_id: String::new(),
            attack_technique: String::new(),
        };
        app.findings.push(f);
    }
    handle_action(&mut app, Action::ScrollDown);
    assert_eq!(app.findings_scroll_offset, 1);
    handle_action(&mut app, Action::ScrollUp);
    assert_eq!(app.findings_scroll_offset, 0);
    handle_action(&mut app, Action::ScrollUp);
    assert_eq!(app.findings_scroll_offset, 0);
}

#[test]
fn select_next_prev_in_detail_view() {
    let mut app = App::new("http://x.com".to_string(), ScanProfile::Quick);
    for i in 0..3 {
        let f = crate::app::Finding {
            id: i,
            severity: crate::app::Severity::Low,
            vuln_type: format!("vuln-{i}"),
            endpoint: "/".to_string(),
            method: "GET".to_string(),
            confidence: 0.5,
            discovered_at: std::time::Instant::now(),
            description: String::new(),
            evidence_request: String::new(),
            evidence_response: String::new(),
            curl_command: String::new(),
            remediation: String::new(),
            cvss_score: 3.0,
            cvss_vector: String::new(),
            cwe_id: String::new(),
            attack_technique: String::new(),
        };
        app.findings.push(f);
    }
    app.active_view = ActiveView::FindingDetail;
    assert_eq!(app.selected_finding, 0);

    handle_action(&mut app, Action::ScrollDown);
    assert_eq!(app.selected_finding, 1);
    handle_action(&mut app, Action::ScrollDown);
    assert_eq!(app.selected_finding, 2);
    handle_action(&mut app, Action::ScrollDown);
    assert_eq!(app.selected_finding, 2);
    handle_action(&mut app, Action::ScrollUp);
    assert_eq!(app.selected_finding, 1);
}
