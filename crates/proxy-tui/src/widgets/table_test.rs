use super::{ColumnDef, SortDir, TableWidget};

fn make_columns() -> Vec<ColumnDef> {
    vec![
        ColumnDef {
            title: "Method".into(),
            width: 8,
            sortable: true,
        },
        ColumnDef {
            title: "Path".into(),
            width: 40,
            sortable: true,
        },
        ColumnDef {
            title: "Status".into(),
            width: 6,
            sortable: false,
        },
    ]
}

fn make_rows() -> Vec<Vec<String>> {
    vec![
        vec!["GET".into(), "/beta".into(), "200".into()],
        vec!["POST".into(), "/alpha".into(), "201".into()],
        vec!["DELETE".into(), "/gamma".into(), "404".into()],
    ]
}

#[test]
fn new_table_has_no_rows() {
    let t = TableWidget::new(make_columns());
    assert!(t.rows.is_empty());
}

#[test]
fn set_rows_updates_rows() {
    let mut t = TableWidget::new(make_columns());
    t.set_rows(make_rows());
    assert_eq!(t.rows.len(), 3);
}

#[test]
fn filtered_rows_returns_all_without_filter() {
    let mut t = TableWidget::new(make_columns());
    t.set_rows(make_rows());
    assert_eq!(t.filtered_rows().len(), 3);
}

#[test]
fn filter_by_pattern_narrows_rows() {
    let mut t = TableWidget::new(make_columns());
    t.set_rows(make_rows());
    t.set_filter(Some("alpha".into()));
    assert_eq!(t.filtered_rows().len(), 1);
    assert_eq!(t.filtered_rows()[0][1], "/alpha");
}

#[test]
fn filter_clears_to_all() {
    let mut t = TableWidget::new(make_columns());
    t.set_rows(make_rows());
    t.set_filter(Some("alpha".into()));
    assert_eq!(t.filtered_rows().len(), 1);
    t.set_filter(None);
    assert_eq!(t.filtered_rows().len(), 3);
}

#[test]
fn sort_asc_by_column() {
    let mut t = TableWidget::new(make_columns());
    t.set_rows(make_rows());
    t.sort_by(0);
    assert_eq!(t.sort_dir, SortDir::Asc);
    let rows = t.filtered_rows();
    assert_eq!(rows[0][0], "DELETE");
    assert_eq!(rows[1][0], "GET");
    assert_eq!(rows[2][0], "POST");
}

#[test]
fn sort_desc_toggle() {
    let mut t = TableWidget::new(make_columns());
    t.set_rows(make_rows());
    t.sort_by(0);
    t.sort_by(0);
    assert_eq!(t.sort_dir, SortDir::Desc);
    let rows = t.filtered_rows();
    assert_eq!(rows[0][0], "POST");
    assert_eq!(rows[1][0], "GET");
    assert_eq!(rows[2][0], "DELETE");
}

#[test]
fn sort_different_column_resets_to_asc() {
    let mut t = TableWidget::new(make_columns());
    t.set_rows(make_rows());
    t.sort_by(0);
    t.sort_by(0);
    assert_eq!(t.sort_dir, SortDir::Desc);
    t.sort_by(1);
    assert_eq!(t.sort_dir, SortDir::Asc);
    assert_eq!(t.sort_column, Some(1));
}

#[test]
fn select_next_advances() {
    let mut t = TableWidget::new(make_columns());
    t.set_rows(make_rows());
    assert_eq!(t.selected, 0);
    t.select_next();
    assert_eq!(t.selected, 1);
}

#[test]
fn select_prev_moves_up() {
    let mut t = TableWidget::new(make_columns());
    t.set_rows(make_rows());
    t.select_next();
    t.select_next();
    assert_eq!(t.selected, 2);
    t.select_prev();
    assert_eq!(t.selected, 1);
}

#[test]
fn selection_clamps_at_bounds() {
    let mut t = TableWidget::new(make_columns());
    t.set_rows(make_rows());
    t.select_prev();
    assert_eq!(t.selected, 0);
    t.select_next();
    t.select_next();
    t.select_next();
    t.select_next();
    assert_eq!(t.selected, 2);
}

#[test]
fn selected_row_returns_correct() {
    let mut t = TableWidget::new(make_columns());
    t.set_rows(make_rows());
    t.sort_by(0);
    let rows = t.filtered_rows();
    let expected = rows[0].clone();
    assert_eq!(t.selected_row(), Some(&expected));
}

#[test]
fn selected_row_none_when_empty() {
    let t = TableWidget::new(make_columns());
    assert_eq!(t.selected_row(), None);
}
