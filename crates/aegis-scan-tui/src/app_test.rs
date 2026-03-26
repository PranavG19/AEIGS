use super::*;
use crate::event::TuiEvent;
use std::time::Instant;

#[test]
fn new_app_has_correct_defaults() {
    let app = App::new("http://example.com".to_string(), ScanProfile::Standard);
    assert_eq!(app.target_url, "http://example.com");
    assert_eq!(app.profile, ScanProfile::Standard);
    assert_eq!(app.current_phase, ScanPhase::Recon);
    assert_eq!(app.findings.len(), 0);
    assert_eq!(app.attack_chains.len(), 0);
    assert_eq!(app.request_count, 0);
    assert!(!app.should_quit);
    assert!(!app.is_paused);
    assert!(!app.is_scan_complete);
    assert_eq!(app.stealth_score, 95);
    assert_eq!(app.active_view, ActiveView::Dashboard);
}

#[test]
fn phase_labels_are_all_uppercase() {
    for phase in ScanPhase::ALL {
        let label = phase.label();
        assert_eq!(
            label,
            label.to_uppercase(),
            "phase label not uppercase: {label}"
        );
    }
}

#[test]
fn phase_indices_are_sequential() {
    for (i, phase) in ScanPhase::ALL.iter().enumerate() {
        assert_eq!(phase.index(), i);
    }
}

#[test]
fn severity_ordering() {
    assert!(Severity::Critical < Severity::High);
    assert!(Severity::High < Severity::Medium);
    assert!(Severity::Medium < Severity::Low);
    assert!(Severity::Low < Severity::Info);
}

#[test]
fn severity_from_score_boundaries() {
    assert_eq!(Severity::from_score(10.0), Severity::Critical);
    assert_eq!(Severity::from_score(9.0), Severity::Critical);
    assert_eq!(Severity::from_score(8.9), Severity::High);
    assert_eq!(Severity::from_score(7.0), Severity::High);
    assert_eq!(Severity::from_score(6.9), Severity::Medium);
    assert_eq!(Severity::from_score(4.0), Severity::Medium);
    assert_eq!(Severity::from_score(3.9), Severity::Low);
    assert_eq!(Severity::from_score(0.1), Severity::Low);
    assert_eq!(Severity::from_score(0.0), Severity::Info);
}

#[test]
fn apply_phase_changed_updates_state() {
    let mut app = App::new("http://x.com".to_string(), ScanProfile::Quick);
    app.apply_event(TuiEvent::PhaseChanged {
        phase: ScanPhase::Fuzz,
        progress: 0.5,
    });
    assert_eq!(app.current_phase, ScanPhase::Fuzz);
    assert!((app.phase_progress[3] - 0.5).abs() < f64::EPSILON);
}

#[test]
fn apply_phase_progress_clamps_at_phase_array() {
    let mut app = App::new("http://x.com".to_string(), ScanProfile::Quick);
    app.apply_event(TuiEvent::PhaseProgress {
        phase: ScanPhase::Report,
        progress: 0.75,
    });
    assert!((app.phase_progress[6] - 0.75).abs() < f64::EPSILON);
}

#[test]
fn apply_endpoint_discovered_increments_count() {
    let mut app = App::new("http://x.com".to_string(), ScanProfile::Quick);
    assert_eq!(app.endpoints_discovered, 0);
    app.apply_event(TuiEvent::EndpointDiscovered {
        endpoint: "/api/test".to_string(),
        method: "GET".to_string(),
    });
    assert_eq!(app.endpoints_discovered, 1);
    assert_eq!(app.log_lines.len(), 1);
}

#[test]
fn apply_finding_sorts_by_severity() {
    let mut app = App::new("http://x.com".to_string(), ScanProfile::Quick);

    let low_finding = Finding {
        id: 0,
        severity: Severity::Low,
        vuln_type: "Low Issue".to_string(),
        endpoint: "/a".to_string(),
        method: "GET".to_string(),
        confidence: 0.5,
        discovered_at: Instant::now(),
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
    let critical_finding = Finding {
        id: 1,
        severity: Severity::Critical,
        vuln_type: "Critical Issue".to_string(),
        endpoint: "/b".to_string(),
        method: "POST".to_string(),
        confidence: 0.9,
        discovered_at: Instant::now(),
        description: String::new(),
        evidence_request: String::new(),
        evidence_response: String::new(),
        curl_command: String::new(),
        remediation: String::new(),
        cvss_score: 9.5,
        cvss_vector: String::new(),
        cwe_id: String::new(),
        attack_technique: String::new(),
    };

    app.apply_event(TuiEvent::FindingConfirmed(Box::new(low_finding)));
    app.apply_event(TuiEvent::FindingConfirmed(Box::new(critical_finding)));

    assert_eq!(app.findings.len(), 2);
    assert_eq!(app.findings[0].severity, Severity::Critical);
    assert_eq!(app.findings[1].severity, Severity::Low);
}

#[test]
fn apply_chain_discovered_adds_chain() {
    let mut app = App::new("http://x.com".to_string(), ScanProfile::Quick);
    let chain = AttackChain {
        nodes: vec![
            ChainNode {
                label: "SQLi".to_string(),
                finding_id: 0,
            },
            ChainNode {
                label: "RCE".to_string(),
                finding_id: 1,
            },
        ],
        total_severity: 20.0,
    };
    app.apply_event(TuiEvent::ChainDiscovered(chain));
    assert_eq!(app.attack_chains.len(), 1);
    assert_eq!(app.attack_chains[0].nodes.len(), 2);
}

#[test]
fn module_start_stop() {
    let mut app = App::new("http://x.com".to_string(), ScanProfile::Quick);
    app.apply_event(TuiEvent::ModuleStarted {
        name: "Fuzzer".to_string(),
    });
    assert_eq!(app.active_modules.len(), 1);
    assert_eq!(app.active_modules[0].name, "Fuzzer");

    app.apply_event(TuiEvent::ModuleStopped {
        name: "Fuzzer".to_string(),
    });
    assert_eq!(app.active_modules.len(), 0);
}

#[test]
fn request_made_increments() {
    let mut app = App::new("http://x.com".to_string(), ScanProfile::Quick);
    app.apply_event(TuiEvent::RequestMade);
    app.apply_event(TuiEvent::RequestMade);
    app.apply_event(TuiEvent::RequestMade);
    assert_eq!(app.request_count, 3);
}

#[test]
fn stealth_update() {
    let mut app = App::new("http://x.com".to_string(), ScanProfile::Quick);
    app.apply_event(TuiEvent::StealthUpdate { score: 42 });
    assert_eq!(app.stealth_score, 42);
}

#[test]
fn scan_complete_sets_done() {
    let mut app = App::new("http://x.com".to_string(), ScanProfile::Quick);
    app.apply_event(TuiEvent::ScanComplete);
    assert!(app.is_scan_complete);
    assert_eq!(app.current_phase, ScanPhase::Done);
}

#[test]
fn tick_advances_spinners() {
    let mut app = App::new("http://x.com".to_string(), ScanProfile::Quick);
    app.apply_event(TuiEvent::ModuleStarted {
        name: "Test".to_string(),
    });
    let initial_tick = app.active_modules[0].spinner_tick;
    app.apply_event(TuiEvent::Tick);
    assert_eq!(app.active_modules[0].spinner_tick, initial_tick + 1);
}

#[test]
fn log_buffer_caps_at_500() {
    let mut app = App::new("http://x.com".to_string(), ScanProfile::Quick);
    for i in 0..600 {
        app.apply_event(TuiEvent::Log {
            level: LogLevel::Info,
            message: format!("msg {i}"),
        });
    }
    assert!(app.log_lines.len() <= 500);
}

#[test]
fn risk_score_calculation() {
    let mut app = App::new("http://x.com".to_string(), ScanProfile::Quick);
    let f = Finding {
        id: 0,
        severity: Severity::Critical,
        vuln_type: "test".to_string(),
        endpoint: "/".to_string(),
        method: "GET".to_string(),
        confidence: 0.9,
        discovered_at: Instant::now(),
        description: String::new(),
        evidence_request: String::new(),
        evidence_response: String::new(),
        curl_command: String::new(),
        remediation: String::new(),
        cvss_score: 9.5,
        cvss_vector: String::new(),
        cwe_id: String::new(),
        attack_technique: String::new(),
    };
    app.apply_event(TuiEvent::FindingConfirmed(Box::new(f)));
    assert!((app.risk_score - 25.0).abs() < f64::EPSILON);
    assert_eq!(app.risk_grade(), "B");
}

#[test]
fn severity_counts() {
    let mut app = App::new("http://x.com".to_string(), ScanProfile::Quick);
    for (i, sev) in [
        Severity::Critical,
        Severity::High,
        Severity::High,
        Severity::Low,
    ]
    .iter()
    .enumerate()
    {
        let f = Finding {
            id: i as u64,
            severity: *sev,
            vuln_type: "test".to_string(),
            endpoint: "/".to_string(),
            method: "GET".to_string(),
            confidence: 0.9,
            discovered_at: Instant::now(),
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
        app.apply_event(TuiEvent::FindingConfirmed(Box::new(f)));
    }
    let counts = app.severity_counts();
    assert_eq!(counts[0], 1); // critical
    assert_eq!(counts[1], 2); // high
    assert_eq!(counts[3], 1); // low
}

#[test]
fn scan_profile_from_str() {
    assert_eq!("quick".parse::<ScanProfile>().unwrap(), ScanProfile::Quick);
    assert_eq!(
        "standard".parse::<ScanProfile>().unwrap(),
        ScanProfile::Standard
    );
    assert_eq!("deep".parse::<ScanProfile>().unwrap(), ScanProfile::Deep);
    assert_eq!(
        "stealth".parse::<ScanProfile>().unwrap(),
        ScanProfile::Stealth
    );
    assert_eq!("QUICK".parse::<ScanProfile>().unwrap(), ScanProfile::Quick);
    assert!("bogus".parse::<ScanProfile>().is_err());
}

#[test]
fn active_module_spinner_cycles() {
    let mut m = ActiveModule {
        name: "test".to_string(),
        spinner_tick: 0,
    };
    let chars: Vec<char> = (0..8)
        .map(|_| {
            let c = m.spinner_char();
            m.tick();
            c
        })
        .collect();
    assert_eq!(chars, vec!['|', '/', '-', '\\', '|', '/', '-', '\\']);
}

#[test]
fn elapsed_display_format() {
    let app = App::new("http://x.com".to_string(), ScanProfile::Quick);
    let display = app.elapsed_display();
    assert!(display.contains(':'));
    assert_eq!(display.len(), 5);
}
