use super::progress_reporter::*;
use std::time::Duration;

#[test]
fn initial_snapshot() {
    let reporter = ProgressReporter::new(8);
    let snap = reporter.snapshot();
    assert_eq!(snap.phases_total, 8);
    assert_eq!(snap.phases_completed, 0);
    assert_eq!(snap.findings_so_far, 0);
    assert_eq!(snap.current_phase, "initializing");
    assert_eq!(snap.percent_complete, 0.0);
    assert!(snap.active_modules.is_empty());
}

#[test]
fn phase_lifecycle() {
    let mut reporter = ProgressReporter::new(4);
    reporter.begin_phase("recon");
    assert_eq!(reporter.snapshot().current_phase, "recon");

    reporter.complete_phase("recon", 3);
    let snap = reporter.snapshot();
    assert_eq!(snap.phases_completed, 1);
    assert_eq!(snap.findings_so_far, 3);
    assert_eq!(snap.percent_complete, 25.0);
}

#[test]
fn module_tracking() {
    let mut reporter = ProgressReporter::new(2);
    reporter.start_module("sql_injection");
    reporter.start_module("xss");

    let snap = reporter.snapshot();
    assert_eq!(snap.active_modules.len(), 2);

    reporter.complete_module("sql_injection", 5);
    let snap = reporter.snapshot();
    assert_eq!(snap.active_modules.len(), 1);
    assert!(snap.active_modules.contains(&"xss".to_string()));

    let sql_detail = snap
        .module_details
        .iter()
        .find(|m| m.name == "sql_injection")
        .unwrap();
    assert_eq!(sql_detail.status, ModuleStatus::Completed);
    assert_eq!(sql_detail.findings_count, 5);
    assert!(sql_detail.duration.is_some());
}

#[test]
fn fail_module() {
    let mut reporter = ProgressReporter::new(1);
    reporter.start_module("broken_scanner");
    reporter.fail_module("broken_scanner");

    let snap = reporter.snapshot();
    let module = snap
        .module_details
        .iter()
        .find(|m| m.name == "broken_scanner")
        .unwrap();
    assert_eq!(module.status, ModuleStatus::Failed);
}

#[test]
fn terminal_format_contains_bar() {
    let mut reporter = ProgressReporter::new(4);
    reporter.begin_phase("crawl");
    reporter.complete_phase("crawl", 2);

    if let ProgressOutput::Terminal(text) = reporter.format_terminal() {
        assert!(text.contains('['));
        assert!(text.contains(']'));
        assert!(text.contains("crawl") || text.contains("25.0%"));
        assert!(text.contains("Findings: 2"));
    } else {
        panic!("expected Terminal output");
    }
}

#[test]
fn json_format_is_valid() {
    let mut reporter = ProgressReporter::new(2);
    reporter.begin_phase("fuzz");
    reporter.start_module("xss");

    if let ProgressOutput::Json(json) = reporter.format_json() {
        assert!(json.starts_with('{'));
        assert!(json.ends_with('}'));
        assert!(json.contains("\"phase\":\"fuzz\""));
        assert!(json.contains("\"xss\""));
    } else {
        panic!("expected Json output");
    }
}

#[test]
fn webhook_format() {
    let reporter = ProgressReporter::new(1);
    if let ProgressOutput::Webhook { url, payload } =
        reporter.format_webhook("https://hooks.example.com/scan")
    {
        assert_eq!(url, "https://hooks.example.com/scan");
        assert!(payload.starts_with('{'));
    } else {
        panic!("expected Webhook output");
    }
}

#[test]
fn eta_not_available_at_start() {
    let reporter = ProgressReporter::new(4);
    let snap = reporter.snapshot();
    assert!(snap.estimated_remaining.is_none());
}

#[test]
fn eta_available_after_first_phase() {
    let mut reporter = ProgressReporter::new(4);
    reporter.begin_phase("recon");
    std::thread::sleep(Duration::from_millis(10));
    reporter.complete_phase("recon", 0);

    let snap = reporter.snapshot();
    assert!(snap.estimated_remaining.is_some());
}

#[test]
fn add_findings_increments_total() {
    let mut reporter = ProgressReporter::new(2);
    reporter.add_findings(5);
    reporter.add_findings(3);
    assert_eq!(reporter.snapshot().findings_so_far, 8);
}

#[test]
fn complete_all_phases_shows_100_percent() {
    let mut reporter = ProgressReporter::new(2);
    reporter.begin_phase("a");
    reporter.complete_phase("a", 0);
    reporter.begin_phase("b");
    reporter.complete_phase("b", 0);

    let snap = reporter.snapshot();
    assert_eq!(snap.percent_complete, 100.0);
    assert_eq!(snap.current_phase, "done");
}

#[test]
fn set_phase_estimate() {
    let mut reporter = ProgressReporter::new(2);
    reporter.set_phase_estimate("fuzz", Duration::from_secs(60));
    // Verify it doesn't panic — estimates are used internally for future ETA refinement
}
