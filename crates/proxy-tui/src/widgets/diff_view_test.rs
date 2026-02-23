use aegis_proxy::{DiffChunk, DiffResult, HeaderDiff};

use crate::widgets::diff_view::{DiffMode, DiffView};

fn make_diff(status_changed: bool, chunks: Vec<DiffChunk>) -> DiffResult {
    DiffResult {
        status_changed,
        old_status: 200,
        new_status: if status_changed { 404 } else { 200 },
        header_diffs: vec![],
        body_diff: chunks,
        body_length_delta: 0,
        duration_delta_ms: 0,
    }
}

#[test]
fn new_has_no_diff() {
    let view = DiffView::new();
    assert!(view.diff.is_none());
    assert!(!view.has_changes());
}

#[test]
fn set_diff_populates() {
    let mut view = DiffView::new();
    let diff = make_diff(false, vec![DiffChunk::Added("hello".to_string())]);
    view.set_diff(diff);
    assert!(view.diff.is_some());
    assert!(view.has_changes());
}

#[test]
fn change_count_correct() {
    let mut view = DiffView::new();
    let chunks = vec![
        DiffChunk::Equal("same".to_string()),
        DiffChunk::Added("new".to_string()),
        DiffChunk::Removed("old".to_string()),
        DiffChunk::Added("another".to_string()),
    ];
    view.set_diff(make_diff(false, chunks));
    assert_eq!(view.change_count(), 3);
}

#[test]
fn toggle_mode_cycles() {
    let mut view = DiffView::new();
    assert_eq!(view.mode, DiffMode::Line);
    view.toggle_mode();
    assert_eq!(view.mode, DiffMode::Word);
    view.toggle_mode();
    assert_eq!(view.mode, DiffMode::Hex);
    view.toggle_mode();
    assert_eq!(view.mode, DiffMode::Line);
}

#[test]
fn summary_status_changed() {
    let mut view = DiffView::new();
    view.set_diff(make_diff(true, vec![]));
    let summary = view.summary_lines();
    assert!(
        summary
            .iter()
            .any(|l| l.contains("200") && l.contains("404") && l.contains("changed"))
    );
}

#[test]
fn summary_status_unchanged() {
    let mut view = DiffView::new();
    view.set_diff(make_diff(false, vec![]));
    let summary = view.summary_lines();
    assert!(
        summary
            .iter()
            .any(|l| l.contains("200") && l.contains("unchanged"))
    );
}

#[test]
fn summary_header_added() {
    let mut view = DiffView::new();
    let mut diff = make_diff(false, vec![]);
    diff.header_diffs = vec![HeaderDiff::Added("x-foo".to_string(), "bar".to_string())];
    view.set_diff(diff);
    let summary = view.summary_lines();
    assert!(
        summary
            .iter()
            .any(|l| l.starts_with("+ ") && l.contains("x-foo") && l.contains("bar"))
    );
}

#[test]
fn summary_header_removed() {
    let mut view = DiffView::new();
    let mut diff = make_diff(false, vec![]);
    diff.header_diffs = vec![HeaderDiff::Removed("x-foo".to_string(), "bar".to_string())];
    view.set_diff(diff);
    let summary = view.summary_lines();
    assert!(
        summary
            .iter()
            .any(|l| l.starts_with("- ") && l.contains("x-foo") && l.contains("bar"))
    );
}

#[test]
fn summary_header_changed() {
    let mut view = DiffView::new();
    let mut diff = make_diff(false, vec![]);
    diff.header_diffs = vec![HeaderDiff::Changed(
        "content-type".to_string(),
        "text/html".to_string(),
        "application/json".to_string(),
    )];
    view.set_diff(diff);
    let summary = view.summary_lines();
    assert!(summary.iter().any(|l| l.starts_with("~ ")
        && l.contains("content-type")
        && l.contains("text/html")
        && l.contains("application/json")));
}

#[test]
fn left_lines_equal_chunks() {
    let mut view = DiffView::new();
    view.set_diff(make_diff(
        false,
        vec![DiffChunk::Equal("same line".to_string())],
    ));
    let left = view.left_lines();
    assert_eq!(left, vec!["same line"]);
}

#[test]
fn left_lines_removed_prefixed() {
    let mut view = DiffView::new();
    view.set_diff(make_diff(
        false,
        vec![DiffChunk::Removed("gone".to_string())],
    ));
    let left = view.left_lines();
    assert_eq!(left, vec!["- gone"]);
}

#[test]
fn left_lines_added_empty_placeholder() {
    let mut view = DiffView::new();
    view.set_diff(make_diff(false, vec![DiffChunk::Added("new".to_string())]));
    let left = view.left_lines();
    assert_eq!(left, vec![""]);
}

#[test]
fn right_lines_added_prefixed() {
    let mut view = DiffView::new();
    view.set_diff(make_diff(
        false,
        vec![DiffChunk::Added("fresh".to_string())],
    ));
    let right = view.right_lines();
    assert_eq!(right, vec!["+ fresh"]);
}

#[test]
fn clear_resets_state() {
    let mut view = DiffView::new();
    view.set_diff(make_diff(true, vec![DiffChunk::Added("x".to_string())]));
    assert!(view.diff.is_some());
    view.clear();
    assert!(view.diff.is_none());
    assert!(!view.has_changes());
}

#[test]
fn scroll_clamps_at_zero() {
    let mut view = DiffView::new();
    assert_eq!(view.scroll_offset, 0);
    view.scroll_up(5);
    assert_eq!(view.scroll_offset, 0);
}
