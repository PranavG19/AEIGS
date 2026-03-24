use super::interactive::*;

fn sample_finding(id: u64) -> FindingSummary {
    FindingSummary {
        id,
        endpoint: "/api/users".to_string(),
        vulnerability_class: "SQL Injection".to_string(),
        severity: 8.5,
        confidence: 0.92,
    }
}

// --- parse_command tests ---

#[test]
fn parse_pause() {
    assert_eq!(parse_command("pause").unwrap(), InteractiveCommand::Pause);
}

#[test]
fn parse_resume() {
    assert_eq!(parse_command("resume").unwrap(), InteractiveCommand::Resume);
}

#[test]
fn parse_status() {
    assert_eq!(parse_command("status").unwrap(), InteractiveCommand::Status);
}

#[test]
fn parse_findings() {
    assert_eq!(
        parse_command("findings").unwrap(),
        InteractiveCommand::ListFindings
    );
}

#[test]
fn parse_endpoints() {
    assert_eq!(
        parse_command("endpoints").unwrap(),
        InteractiveCommand::ListEndpoints
    );
}

#[test]
fn parse_priority() {
    assert_eq!(
        parse_command("priority /api/users 1.5").unwrap(),
        InteractiveCommand::AdjustPriority {
            endpoint: "/api/users".to_string(),
            boost: 1.5,
        }
    );
}

#[test]
fn parse_skip() {
    assert_eq!(
        parse_command("skip").unwrap(),
        InteractiveCommand::SkipPhase
    );
}

#[test]
fn parse_quit() {
    assert_eq!(parse_command("quit").unwrap(), InteractiveCommand::Quit);
}

#[test]
fn parse_exit() {
    assert_eq!(parse_command("exit").unwrap(), InteractiveCommand::Quit);
}

#[test]
fn parse_q() {
    assert_eq!(parse_command("q").unwrap(), InteractiveCommand::Quit);
}

#[test]
fn parse_case_insensitive_pause() {
    assert_eq!(parse_command("PAUSE").unwrap(), InteractiveCommand::Pause);
}

#[test]
fn parse_case_insensitive_mixed() {
    assert_eq!(parse_command("StAtUs").unwrap(), InteractiveCommand::Status);
}

#[test]
fn parse_leading_trailing_whitespace() {
    assert_eq!(
        parse_command("  pause  ").unwrap(),
        InteractiveCommand::Pause
    );
}

#[test]
fn parse_unknown_command_error() {
    let err = parse_command("fly").unwrap_err();
    assert!(matches!(err, CommandParseError::UnknownCommand(ref s) if s == "fly"));
}

#[test]
fn parse_empty_input_error() {
    let err = parse_command("").unwrap_err();
    assert!(matches!(err, CommandParseError::UnknownCommand(_)));
}

#[test]
fn parse_whitespace_only_error() {
    let err = parse_command("   ").unwrap_err();
    assert!(matches!(err, CommandParseError::UnknownCommand(_)));
}

#[test]
fn parse_priority_missing_args_error() {
    let err = parse_command("priority").unwrap_err();
    assert!(matches!(err, CommandParseError::MissingArgument(_)));
}

#[test]
fn parse_priority_missing_boost_error() {
    let err = parse_command("priority /api/users").unwrap_err();
    assert!(matches!(err, CommandParseError::MissingArgument(_)));
}

#[test]
fn parse_priority_invalid_boost_error() {
    let err = parse_command("priority /api/users abc").unwrap_err();
    assert!(matches!(err, CommandParseError::InvalidArgument(_)));
}

#[test]
fn parse_priority_negative_boost() {
    let cmd = parse_command("priority /api/login -2.0").unwrap();
    assert_eq!(
        cmd,
        InteractiveCommand::AdjustPriority {
            endpoint: "/api/login".to_string(),
            boost: -2.0,
        }
    );
}

#[test]
fn parse_priority_preserves_endpoint_case() {
    let cmd = parse_command("priority /Api/Users 1.0").unwrap();
    if let InteractiveCommand::AdjustPriority { endpoint, .. } = cmd {
        assert_eq!(endpoint, "/Api/Users");
    } else {
        panic!("expected AdjustPriority");
    }
}

// --- InteractiveSession tests ---

#[test]
fn new_session_not_paused() {
    let session = InteractiveSession::new();
    assert!(!session.is_paused());
}

#[test]
fn new_session_not_quit() {
    let session = InteractiveSession::new();
    assert!(!session.should_quit());
}

#[test]
fn new_session_not_skip() {
    let session = InteractiveSession::new();
    assert!(!session.should_skip_phase());
}

#[test]
fn handle_pause_sets_paused() {
    let mut session = InteractiveSession::new();
    let resp = session.handle_command(&InteractiveCommand::Pause);
    assert!(session.is_paused());
    assert!(matches!(resp, InteractiveResponse::Acknowledged(_)));
}

#[test]
fn handle_resume_unsets_paused() {
    let mut session = InteractiveSession::new();
    session.handle_command(&InteractiveCommand::Pause);
    assert!(session.is_paused());
    session.handle_command(&InteractiveCommand::Resume);
    assert!(!session.is_paused());
}

#[test]
fn handle_status_returns_report() {
    let mut session = InteractiveSession::new();
    session.set_current_phase("fuzz");
    let resp = session.handle_command(&InteractiveCommand::Status);
    if let InteractiveResponse::StatusReport(status) = resp {
        assert_eq!(status.current_phase, "fuzz");
        assert!(!status.is_paused);
    } else {
        panic!("expected StatusReport");
    }
}

#[test]
fn handle_list_findings_returns_findings() {
    let mut session = InteractiveSession::new();
    session.add_finding(sample_finding(1));
    let resp = session.handle_command(&InteractiveCommand::ListFindings);
    if let InteractiveResponse::FindingsList(findings) = resp {
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, 1);
    } else {
        panic!("expected FindingsList");
    }
}

#[test]
fn handle_list_endpoints_returns_endpoints() {
    let mut session = InteractiveSession::new();
    session.add_endpoint("/api/users".to_string());
    session.add_endpoint("/api/login".to_string());
    let resp = session.handle_command(&InteractiveCommand::ListEndpoints);
    if let InteractiveResponse::EndpointsList(endpoints) = resp {
        assert_eq!(endpoints.len(), 2);
    } else {
        panic!("expected EndpointsList");
    }
}

#[test]
fn handle_adjust_priority_records_adjustment() {
    let mut session = InteractiveSession::new();
    let cmd = InteractiveCommand::AdjustPriority {
        endpoint: "/api/admin".to_string(),
        boost: 3.0,
    };
    session.handle_command(&cmd);
    assert_eq!(session.priority_adjustments().len(), 1);
    assert_eq!(session.priority_adjustments()[0].0, "/api/admin");
    assert!((session.priority_adjustments()[0].1 - 3.0).abs() < f64::EPSILON);
}

#[test]
fn handle_skip_phase_sets_flag() {
    let mut session = InteractiveSession::new();
    session.handle_command(&InteractiveCommand::SkipPhase);
    assert!(session.should_skip_phase());
}

#[test]
fn handle_quit_sets_flag() {
    let mut session = InteractiveSession::new();
    session.handle_command(&InteractiveCommand::Quit);
    assert!(session.should_quit());
}

#[test]
fn clear_skip_flag_resets() {
    let mut session = InteractiveSession::new();
    session.handle_command(&InteractiveCommand::SkipPhase);
    assert!(session.should_skip_phase());
    session.clear_skip_flag();
    assert!(!session.should_skip_phase());
}

#[test]
fn add_finding_increments_count() {
    let mut session = InteractiveSession::new();
    session.add_finding(sample_finding(1));
    session.add_finding(sample_finding(2));
    let resp = session.handle_command(&InteractiveCommand::Status);
    if let InteractiveResponse::StatusReport(status) = resp {
        assert_eq!(status.findings_count, 2);
    } else {
        panic!("expected StatusReport");
    }
}

#[test]
fn add_endpoint_increments_count() {
    let mut session = InteractiveSession::new();
    session.add_endpoint("/a".to_string());
    session.add_endpoint("/b".to_string());
    session.add_endpoint("/c".to_string());
    let resp = session.handle_command(&InteractiveCommand::Status);
    if let InteractiveResponse::StatusReport(status) = resp {
        assert_eq!(status.endpoints_count, 3);
    } else {
        panic!("expected StatusReport");
    }
}

#[test]
fn set_current_phase_updates_status() {
    let mut session = InteractiveSession::new();
    session.set_current_phase("analyze");
    let resp = session.handle_command(&InteractiveCommand::Status);
    if let InteractiveResponse::StatusReport(status) = resp {
        assert_eq!(status.current_phase, "analyze");
    } else {
        panic!("expected StatusReport");
    }
}

#[test]
fn set_elapsed_ms_updates_status() {
    let mut session = InteractiveSession::new();
    session.set_elapsed_ms(5000);
    let resp = session.handle_command(&InteractiveCommand::Status);
    if let InteractiveResponse::StatusReport(status) = resp {
        assert_eq!(status.elapsed_ms, 5000);
    } else {
        panic!("expected StatusReport");
    }
}

#[test]
fn set_iterations_updates_status() {
    let mut session = InteractiveSession::new();
    session.set_iterations(3);
    let resp = session.handle_command(&InteractiveCommand::Status);
    if let InteractiveResponse::StatusReport(status) = resp {
        assert_eq!(status.iterations_completed, 3);
    } else {
        panic!("expected StatusReport");
    }
}

#[test]
fn priority_adjustments_returns_correct_list() {
    let mut session = InteractiveSession::new();
    session.handle_command(&InteractiveCommand::AdjustPriority {
        endpoint: "/a".to_string(),
        boost: 1.0,
    });
    session.handle_command(&InteractiveCommand::AdjustPriority {
        endpoint: "/b".to_string(),
        boost: -0.5,
    });
    let adjustments = session.priority_adjustments();
    assert_eq!(adjustments.len(), 2);
    assert_eq!(adjustments[0].0, "/a");
    assert_eq!(adjustments[1].0, "/b");
}

// --- format_status tests ---

#[test]
fn format_status_includes_phase_name() {
    let status = ScanStatus {
        current_phase: "recon".to_string(),
        is_paused: false,
        findings_count: 5,
        endpoints_count: 10,
        elapsed_ms: 1234,
        iterations_completed: 2,
    };
    let output = format_status(&status);
    assert!(output.contains("recon"));
    assert!(output.contains("5"));
    assert!(output.contains("10"));
    assert!(output.contains("1234"));
}

#[test]
fn format_status_shows_paused_label() {
    let status = ScanStatus {
        current_phase: "fuzz".to_string(),
        is_paused: true,
        findings_count: 0,
        endpoints_count: 0,
        elapsed_ms: 0,
        iterations_completed: 0,
    };
    let output = format_status(&status);
    assert!(output.contains("[PAUSED]"));
}

#[test]
fn format_status_no_paused_label_when_running() {
    let status = ScanStatus {
        current_phase: "fuzz".to_string(),
        is_paused: false,
        findings_count: 0,
        endpoints_count: 0,
        elapsed_ms: 0,
        iterations_completed: 0,
    };
    let output = format_status(&status);
    assert!(!output.contains("[PAUSED]"));
}

// --- format_finding_summary tests ---

#[test]
fn format_finding_summary_includes_endpoint_and_severity() {
    let finding = sample_finding(42);
    let output = format_finding_summary(&finding);
    assert!(output.contains("/api/users"));
    assert!(output.contains("8.5"));
    assert!(output.contains("SQL Injection"));
    assert!(output.contains("42"));
}

// --- FindingSummary serialization ---

#[test]
fn finding_summary_serializes_to_json() {
    let finding = sample_finding(7);
    let json = serde_json::to_string(&finding).unwrap();
    assert!(json.contains("\"id\":7"));
    assert!(json.contains("/api/users"));
    assert!(json.contains("SQL Injection"));
}

// --- ScanStatus serialization ---

#[test]
fn scan_status_serializes_to_json() {
    let status = ScanStatus {
        current_phase: "fuzz".to_string(),
        is_paused: true,
        findings_count: 3,
        endpoints_count: 7,
        elapsed_ms: 999,
        iterations_completed: 1,
    };
    let json = serde_json::to_string(&status).unwrap();
    assert!(json.contains("\"is_paused\":true"));
    assert!(json.contains("\"findings_count\":3"));
}

// --- CommandParseError Display ---

#[test]
fn command_parse_error_display_unknown() {
    let err = CommandParseError::UnknownCommand("fly".to_string());
    assert_eq!(format!("{err}"), "unknown command: fly");
}

#[test]
fn command_parse_error_display_missing() {
    let err = CommandParseError::MissingArgument("need boost".to_string());
    assert_eq!(format!("{err}"), "missing argument: need boost");
}

#[test]
fn command_parse_error_display_invalid() {
    let err = CommandParseError::InvalidArgument("not a number".to_string());
    assert_eq!(format!("{err}"), "invalid argument: not a number");
}

#[test]
fn command_parse_error_is_std_error() {
    let err = CommandParseError::UnknownCommand("x".to_string());
    let _: &dyn std::error::Error = &err;
}

// --- InteractiveCommand equality ---

#[test]
fn interactive_command_eq() {
    assert_eq!(InteractiveCommand::Pause, InteractiveCommand::Pause);
    assert_ne!(InteractiveCommand::Pause, InteractiveCommand::Resume);
}

// --- InteractiveSession Debug ---

#[test]
fn interactive_session_debug() {
    let session = InteractiveSession::new();
    let dbg = format!("{session:?}");
    assert!(dbg.contains("InteractiveSession"));
}

// --- pause then status shows paused ---

#[test]
fn status_after_pause_shows_paused() {
    let mut session = InteractiveSession::new();
    session.handle_command(&InteractiveCommand::Pause);
    let resp = session.handle_command(&InteractiveCommand::Status);
    if let InteractiveResponse::StatusReport(status) = resp {
        assert!(status.is_paused);
    } else {
        panic!("expected StatusReport");
    }
}

// --- help command tests ---

#[test]
fn parse_help() {
    assert_eq!(parse_command("help").unwrap(), InteractiveCommand::Help);
}

#[test]
fn parse_question_mark_as_help() {
    assert_eq!(parse_command("?").unwrap(), InteractiveCommand::Help);
}

#[test]
fn handle_help_returns_acknowledged() {
    let mut session = InteractiveSession::new();
    let resp = session.handle_command(&InteractiveCommand::Help);
    if let InteractiveResponse::Acknowledged(msg) = resp {
        assert!(msg.contains("status"));
        assert!(msg.contains("findings"));
        assert!(msg.contains("pause"));
        assert!(msg.contains("quit"));
    } else {
        panic!("expected Acknowledged with help text");
    }
}

// --- findings_count / endpoints_count tests ---

#[test]
fn findings_count_tracks_additions() {
    let mut session = InteractiveSession::new();
    assert_eq!(session.findings_count(), 0);
    session.add_finding(sample_finding(1));
    session.add_finding(sample_finding(2));
    assert_eq!(session.findings_count(), 2);
}

#[test]
fn endpoints_count_tracks_additions() {
    let mut session = InteractiveSession::new();
    assert_eq!(session.endpoints_count(), 0);
    session.add_endpoint("/a".to_string());
    assert_eq!(session.endpoints_count(), 1);
}

// --- replace_findings / replace_endpoints tests ---

#[test]
fn replace_findings_overwrites_list() {
    let mut session = InteractiveSession::new();
    session.add_finding(sample_finding(1));
    session.add_finding(sample_finding(2));
    assert_eq!(session.findings_count(), 2);

    session.replace_findings(vec![sample_finding(10)]);
    assert_eq!(session.findings_count(), 1);
    let resp = session.handle_command(&InteractiveCommand::ListFindings);
    if let InteractiveResponse::FindingsList(findings) = resp {
        assert_eq!(findings[0].id, 10);
    } else {
        panic!("expected FindingsList");
    }
}

#[test]
fn replace_endpoints_overwrites_list() {
    let mut session = InteractiveSession::new();
    session.add_endpoint("/old".to_string());
    session.replace_endpoints(vec!["/new".to_string()]);
    assert_eq!(session.endpoints_count(), 1);
    let resp = session.handle_command(&InteractiveCommand::ListEndpoints);
    if let InteractiveResponse::EndpointsList(endpoints) = resp {
        assert_eq!(endpoints[0], "/new");
    } else {
        panic!("expected EndpointsList");
    }
}

#[test]
fn parse_command_with_extra_whitespace() {
    assert_eq!(
        parse_command("  pause  ").unwrap(),
        InteractiveCommand::Pause
    );
    assert_eq!(
        parse_command("  resume  ").unwrap(),
        InteractiveCommand::Resume
    );
    assert_eq!(
        parse_command("  status  ").unwrap(),
        InteractiveCommand::Status
    );
}

#[test]
fn parse_command_case_insensitive() {
    assert_eq!(parse_command("PAUSE").unwrap(), InteractiveCommand::Pause);
    assert_eq!(parse_command("Quit").unwrap(), InteractiveCommand::Quit);
    assert_eq!(parse_command("STATUS").unwrap(), InteractiveCommand::Status);
}

#[test]
fn double_pause_is_idempotent() {
    let mut session = InteractiveSession::new();
    let resp1 = session.handle_command(&InteractiveCommand::Pause);
    let resp2 = session.handle_command(&InteractiveCommand::Pause);
    assert!(matches!(resp1, InteractiveResponse::Acknowledged(_)));
    assert!(matches!(resp2, InteractiveResponse::Acknowledged(_)));
    assert!(session.is_paused());
}

#[test]
fn resume_without_pause_acknowledged() {
    let mut session = InteractiveSession::new();
    let resp = session.handle_command(&InteractiveCommand::Resume);
    assert!(matches!(resp, InteractiveResponse::Acknowledged(_)));
    assert!(!session.is_paused());
}

#[test]
fn add_many_findings() {
    let mut session = InteractiveSession::new();
    for i in 0..100 {
        session.add_finding(sample_finding(i));
    }
    assert_eq!(session.findings_count(), 100);
}

#[test]
fn add_many_endpoints() {
    let mut session = InteractiveSession::new();
    for i in 0..100 {
        session.add_endpoint(format!("/endpoint-{i}"));
    }
    assert_eq!(session.endpoints_count(), 100);
}
