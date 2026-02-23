use super::ScopeView;

#[test]
fn new_has_no_rules() {
    let view = ScopeView::new();
    assert_eq!(view.rule_count(), 0);
    assert_eq!(view.table.rows.len(), 0);
}

#[test]
fn add_include_rule() {
    let mut view = ScopeView::new();
    let id = view.add_rule("example\\.com", true).unwrap();
    assert_eq!(view.rule_count(), 1);
    let rules = view.rules();
    assert_eq!(rules[0].id, id);
    assert!(rules[0].is_include);
    assert_eq!(rules[0].pattern, "example\\.com");
}

#[test]
fn add_exclude_rule() {
    let mut view = ScopeView::new();
    view.add_rule("/static/", false).unwrap();
    let rules = view.rules();
    assert!(!rules[0].is_include);
}

#[test]
fn invalid_regex_returns_error() {
    let mut view = ScopeView::new();
    let result = view.add_rule("[unclosed", true);
    assert!(result.is_err());
    assert_eq!(view.rule_count(), 0);
}

#[test]
fn remove_rule_works() {
    let mut view = ScopeView::new();
    let id = view.add_rule("example\\.com", true).unwrap();
    assert!(view.remove_rule(id));
    assert_eq!(view.rule_count(), 0);
    assert_eq!(view.table.rows.len(), 0);
    assert!(!view.remove_rule(id));
}

#[test]
fn toggle_rule_works() {
    let mut view = ScopeView::new();
    let id = view.add_rule("example\\.com", true).unwrap();
    assert!(view.rules()[0].enabled);
    assert!(view.toggle_rule(id));
    assert!(!view.rules()[0].enabled);
    assert!(view.toggle_rule(id));
    assert!(view.rules()[0].enabled);
    assert!(!view.toggle_rule(999));
}

#[test]
fn test_url_delegates() {
    let mut view = ScopeView::new();
    view.add_rule("example\\.com", true).unwrap();
    assert!(view.test_url("http://example.com/path"));
    assert!(!view.test_url("http://other.com/path"));
}

#[test]
fn table_row_count_matches_rules() {
    let mut view = ScopeView::new();
    view.add_rule("example\\.com", true).unwrap();
    view.add_rule("/admin/", false).unwrap();
    assert_eq!(view.table.rows.len(), 2);

    let first = &view.table.rows[0];
    assert_eq!(first[1], "Include");
    assert_eq!(first[3], "Yes");

    let second = &view.table.rows[1];
    assert_eq!(second[1], "Exclude");

    let id = view.rules()[0].id;
    view.remove_rule(id);
    assert_eq!(view.table.rows.len(), 1);
}
