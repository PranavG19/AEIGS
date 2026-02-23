use aegis_proxy::{
    AttackMode, GrepExtract, GrepMatch, ModifiedRequest, PayloadEncoding, PayloadPipeline,
    PayloadSource, PipelineIntruderResult, RecordedExchange,
};

use super::*;

fn make_exchange(id: u64) -> RecordedExchange {
    RecordedExchange {
        id,
        request_method: "GET".to_string(),
        request_url: "http://localhost/api".to_string(),
        request_headers: vec![],
        request_body: vec![],
        response_status: 200,
        response_headers: vec![],
        response_body: vec![],
        timestamp_ms: 0,
        duration_ms: 0,
        in_scope: true,
        tags: vec![],
    }
}

fn make_result(status: u16, grep_matches: Vec<String>) -> PipelineIntruderResult {
    PipelineIntruderResult {
        payload: vec!["test".to_string()],
        status_code: status,
        body_length: 10,
        duration_ms: 5,
        response_body: vec![],
        grep_match_results: grep_matches,
        grep_extract_results: vec![],
    }
}

#[test]
fn new_view_defaults() {
    let view = IntruderView::new();
    assert_eq!(view.phase, IntruderPhase::Config);
    assert!(view.template.is_none());
    assert!(view.positions.is_empty());
    assert_eq!(view.mode, AttackMode::Sniper);
    assert!(view.pipelines.is_empty());
    assert!(view.grep_matches.is_empty());
    assert!(view.grep_extracts.is_empty());
    assert!(view.results.is_empty());
    assert!(!view.running);
}

#[test]
fn load_exchange_sets_template() {
    let mut view = IntruderView::new();
    let exchange = make_exchange(42);
    view.load_exchange(&exchange);
    let tpl = view.template.as_ref().expect("template should be set");
    assert_eq!(tpl.method, "GET");
    assert_eq!(tpl.url, "http://localhost/api");
}

#[test]
fn load_exchange_resets_positions_and_results() {
    let mut view = IntruderView::new();
    view.positions.push("§0§".to_string());
    view.add_result(make_result(200, vec![]));
    let exchange = make_exchange(1);
    view.load_exchange(&exchange);
    assert!(view.positions.is_empty());
    assert!(view.results.is_empty());
}

#[test]
fn set_mode_updates() {
    let mut view = IntruderView::new();
    view.set_mode(AttackMode::ClusterBomb);
    assert_eq!(view.mode, AttackMode::ClusterBomb);
}

#[test]
fn add_position_appends() {
    let mut view = IntruderView::new();
    view.add_position("§0§".to_string());
    view.add_position("§1§".to_string());
    assert_eq!(view.position_count(), 2);
    assert_eq!(view.positions[0], "§0§");
    assert_eq!(view.positions[1], "§1§");
}

#[test]
fn clear_positions_empties() {
    let mut view = IntruderView::new();
    view.add_position("§0§".to_string());
    view.clear_positions();
    assert_eq!(view.position_count(), 0);
}

#[test]
fn add_result_increments_count() {
    let mut view = IntruderView::new();
    view.add_result(make_result(200, vec![]));
    view.add_result(make_result(404, vec![]));
    assert_eq!(view.result_count(), 2);
}

#[test]
fn add_result_adds_row_to_table() {
    let mut view = IntruderView::new();
    view.add_result(make_result(200, vec![]));
    assert_eq!(view.results_table.rows.len(), 1);
    let row = &view.results_table.rows[0];
    assert_eq!(row[0], "test");
    assert_eq!(row[1], "200");
    assert_eq!(row[2], "10");
    assert_eq!(row[3], "5");
    assert_eq!(row[4], "");
}

#[test]
fn stats_counts_correctly() {
    let mut view = IntruderView::new();
    view.add_result(make_result(200, vec![]));
    view.add_result(make_result(404, vec![]));
    let stats = view.stats();
    assert_eq!(stats.total, 2);
    assert_eq!(stats.completed, 2);
}

#[test]
fn stats_counts_matches() {
    let mut view = IntruderView::new();
    view.add_result(make_result(200, vec![]));
    view.add_result(make_result(200, vec!["error".to_string()]));
    view.add_result(make_result(
        200,
        vec!["found".to_string(), "extra".to_string()],
    ));
    let stats = view.stats();
    assert_eq!(stats.matches, 2);
}

#[test]
fn stats_counts_errors() {
    let mut view = IntruderView::new();
    view.add_result(make_result(200, vec![]));
    view.add_result(make_result(0, vec![]));
    view.add_result(make_result(0, vec![]));
    let stats = view.stats();
    assert_eq!(stats.errors, 2);
}

#[test]
fn start_attack_sets_running() {
    let mut view = IntruderView::new();
    view.start_attack();
    assert!(view.running);
    assert_eq!(view.phase, IntruderPhase::Results);
}

#[test]
fn stop_attack_clears_running() {
    let mut view = IntruderView::new();
    view.start_attack();
    view.stop_attack();
    assert!(!view.running);
}

#[test]
fn start_attack_clears_previous_results() {
    let mut view = IntruderView::new();
    view.add_result(make_result(200, vec![]));
    view.add_result(make_result(404, vec![]));
    view.start_attack();
    assert_eq!(view.result_count(), 0);
    assert!(view.results_table.rows.is_empty());
}

#[allow(dead_code)]
fn _uses_imports() {
    let _: Vec<GrepMatch> = vec![];
    let _: Vec<GrepExtract> = vec![];
    let _: Vec<PayloadPipeline> = vec![PayloadPipeline {
        source: PayloadSource::SimpleList(vec![]),
        processors: vec![],
        encoding: PayloadEncoding::None,
    }];
    let _: Option<ModifiedRequest> = None;
}
