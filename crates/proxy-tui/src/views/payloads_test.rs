use aegis_proxy::PayloadListRecord;

use super::PayloadsView;

fn make_record(id: i64, name: &str, entries: &[&str]) -> PayloadListRecord {
    let entries_json = serde_json::to_string(&entries).unwrap();
    PayloadListRecord {
        id,
        name: name.to_string(),
        source: "manual".to_string(),
        entries: entries_json,
    }
}

#[test]
fn new_has_no_lists() {
    let view = PayloadsView::new();
    assert_eq!(view.list_count(), 0);
    assert_eq!(view.table.rows.len(), 0);
}

#[test]
fn load_lists_populates() {
    let mut view = PayloadsView::new();
    let lists = vec![
        make_record(1, "sqli", &["' OR 1=1--", "1; DROP TABLE"]),
        make_record(2, "xss", &["<script>alert(1)</script>"]),
    ];
    view.load_lists(lists);
    assert_eq!(view.table.rows.len(), 2);
}

#[test]
fn list_count_correct() {
    let mut view = PayloadsView::new();
    view.load_lists(vec![
        make_record(1, "a", &["x"]),
        make_record(2, "b", &["y", "z"]),
    ]);
    assert_eq!(view.list_count(), 2);
}

#[test]
fn selected_list_none_when_empty() {
    let view = PayloadsView::new();
    assert!(view.selected_list().is_none());
}

#[test]
fn selected_list_after_load() {
    let mut view = PayloadsView::new();
    view.load_lists(vec![make_record(1, "sqli", &["payload"])]);
    let rec = view.selected_list().unwrap();
    assert_eq!(rec.name, "sqli");
}

#[test]
fn preview_entries_returns_limited() {
    let mut view = PayloadsView::new();
    view.load_lists(vec![make_record(1, "list", &["a", "b", "c", "d", "e"])]);
    let preview = view.preview_entries(3);
    assert_eq!(preview, vec!["a", "b", "c"]);
}

#[test]
fn select_next_moves() {
    let mut view = PayloadsView::new();
    view.load_lists(vec![
        make_record(1, "first", &[]),
        make_record(2, "second", &[]),
    ]);
    assert_eq!(view.selected, 0);
    view.select_next();
    assert_eq!(view.selected, 1);
    view.select_next();
    assert_eq!(view.selected, 1);
}

#[test]
fn select_prev_clamps() {
    let mut view = PayloadsView::new();
    view.load_lists(vec![make_record(1, "only", &[])]);
    view.select_prev();
    assert_eq!(view.selected, 0);
}
