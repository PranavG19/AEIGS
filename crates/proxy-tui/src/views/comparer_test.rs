use aegis_proxy::RecordedExchange;

use super::ComparerView;

fn make_exchange(id: u64, status: u16) -> RecordedExchange {
    RecordedExchange {
        id,
        request_method: "GET".to_string(),
        request_url: format!("http://localhost/api/{id}"),
        request_headers: vec![],
        request_body: vec![],
        response_status: status,
        response_headers: vec![],
        response_body: format!("body_{id}").into_bytes(),
        timestamp_ms: 0,
        duration_ms: 10,
        in_scope: true,
        tags: vec![],
    }
}

#[test]
fn new_has_no_sides() {
    let view = ComparerView::new();
    assert!(!view.has_left());
    assert!(!view.has_right());
    assert!(!view.has_both_sides());
    assert!(view.diff_view.diff.is_none());
}

#[test]
fn set_left_populates() {
    let mut view = ComparerView::new();
    view.set_left(&make_exchange(1, 200));
    assert!(view.has_left());
    assert!(!view.has_right());
}

#[test]
fn set_right_populates() {
    let mut view = ComparerView::new();
    view.set_right(&make_exchange(2, 404));
    assert!(!view.has_left());
    assert!(view.has_right());
}

#[test]
fn has_both_false_with_one_side() {
    let mut view = ComparerView::new();
    view.set_left(&make_exchange(1, 200));
    assert!(!view.has_both_sides());
}

#[test]
fn has_both_true_with_both() {
    let mut view = ComparerView::new();
    view.set_left(&make_exchange(1, 200));
    view.set_right(&make_exchange(2, 200));
    assert!(view.has_both_sides());
}

#[test]
fn compute_diff_sets_diff_view() {
    let mut view = ComparerView::new();
    view.set_left(&make_exchange(1, 200));
    view.set_right(&make_exchange(2, 404));
    assert!(view.diff_view.diff.is_none());
    view.compute_and_store_diff();
    assert!(view.diff_view.diff.is_some());
    let diff = view.diff_view.diff.as_ref().unwrap();
    assert!(diff.status_changed);
}

#[test]
fn compute_diff_noop_without_both() {
    let mut view = ComparerView::new();
    view.set_left(&make_exchange(1, 200));
    view.compute_and_store_diff();
    assert!(view.diff_view.diff.is_none());
}

#[test]
fn summary_delegates_to_diff_view() {
    let mut view = ComparerView::new();
    assert!(view.summary().is_empty());
    view.set_left(&make_exchange(1, 200));
    view.set_right(&make_exchange(2, 200));
    view.compute_and_store_diff();
    let lines = view.summary();
    assert!(!lines.is_empty());
    assert!(lines[0].contains("200"));
}

#[test]
fn left_info_format() {
    let mut view = ComparerView::new();
    assert!(view.left_info().is_none());
    assert!(view.right_info().is_none());
    view.set_left(&make_exchange(3, 200));
    let info = view.left_info().unwrap();
    assert_eq!(info, "GET http://localhost/api/3 (200)");
    view.set_right(&make_exchange(4, 500));
    let rinfo = view.right_info().unwrap();
    assert_eq!(rinfo, "GET http://localhost/api/4 (500)");
}

#[test]
fn clear_removes_side() {
    let mut view = ComparerView::new();
    view.set_left(&make_exchange(1, 200));
    view.set_right(&make_exchange(2, 200));
    assert!(view.has_both_sides());
    view.clear_left();
    assert!(!view.has_left());
    assert!(view.has_right());
    view.clear_right();
    assert!(!view.has_right());
}
