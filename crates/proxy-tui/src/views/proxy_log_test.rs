use super::{ProxyLogEvent, ProxyLogFocus, ProxyLogView};
use crate::keybinds::Action;
use aegis_proxy::RecordedExchange;

fn make_exchange(id: u64, method: &str, url: &str, status: u16) -> RecordedExchange {
    RecordedExchange {
        id,
        request_method: method.to_string(),
        request_url: url.to_string(),
        request_headers: vec![],
        request_body: vec![],
        response_status: status,
        response_headers: vec![],
        response_body: b"response".to_vec(),
        timestamp_ms: 1700000000000,
        duration_ms: 42,
        in_scope: true,
        tags: vec![],
    }
}

#[test]
fn new_view_has_empty_exchanges() {
    let view = ProxyLogView::new();
    assert_eq!(view.exchange_count(), 0);
}

#[test]
fn load_exchanges_populates_table() {
    let mut view = ProxyLogView::new();
    view.load_exchanges(vec![
        make_exchange(1, "GET", "http://localhost/a", 200),
        make_exchange(2, "POST", "http://localhost/b", 201),
    ]);
    assert_eq!(view.table.rows.len(), 2);
}

#[test]
fn exchange_count_matches_loaded() {
    let mut view = ProxyLogView::new();
    view.load_exchanges(vec![
        make_exchange(1, "GET", "http://localhost/a", 200),
        make_exchange(2, "POST", "http://localhost/b", 201),
        make_exchange(3, "DELETE", "http://localhost/c", 204),
    ]);
    assert_eq!(view.exchange_count(), 3);
}

#[test]
fn selected_exchange_none_when_empty() {
    let view = ProxyLogView::new();
    assert!(view.selected_exchange().is_none());
}

#[test]
fn selected_exchange_after_load() {
    let mut view = ProxyLogView::new();
    view.load_exchanges(vec![make_exchange(1, "GET", "http://localhost/a", 200)]);
    let ex = view.selected_exchange();
    assert!(ex.is_some());
    assert_eq!(ex.unwrap().id, 1);
}

#[test]
fn apply_filter_narrows_exchanges() {
    let mut view = ProxyLogView::new();
    view.load_exchanges(vec![
        make_exchange(1, "GET", "http://localhost/alpha", 200),
        make_exchange(2, "POST", "http://localhost/beta", 201),
    ]);
    view.apply_filter(Some("alpha".to_string()));
    assert_eq!(view.table.filtered_rows().len(), 1);
}

#[test]
fn handle_nav_up_moves_selection() {
    let mut view = ProxyLogView::new();
    view.load_exchanges(vec![
        make_exchange(1, "GET", "http://localhost/a", 200),
        make_exchange(2, "POST", "http://localhost/b", 201),
    ]);
    view.table.select_next();
    assert_eq!(view.table.selected, 1);
    view.handle_action(Action::NavUp);
    assert_eq!(view.table.selected, 0);
}

#[test]
fn handle_nav_down_moves_selection() {
    let mut view = ProxyLogView::new();
    view.load_exchanges(vec![
        make_exchange(1, "GET", "http://localhost/a", 200),
        make_exchange(2, "POST", "http://localhost/b", 201),
    ]);
    assert_eq!(view.table.selected, 0);
    view.handle_action(Action::NavDown);
    assert_eq!(view.table.selected, 1);
}

#[test]
fn handle_send_to_repeater_returns_event() {
    let mut view = ProxyLogView::new();
    view.load_exchanges(vec![make_exchange(1, "GET", "http://localhost/a", 200)]);
    let event = view.handle_action(Action::SendToRepeater);
    assert!(matches!(event, ProxyLogEvent::SendToRepeater(_)));
}

#[test]
fn handle_send_to_intruder_returns_event() {
    let mut view = ProxyLogView::new();
    view.load_exchanges(vec![make_exchange(1, "GET", "http://localhost/a", 200)]);
    let event = view.handle_action(Action::SendToIntruder);
    assert!(matches!(event, ProxyLogEvent::SendToIntruder(_)));
}

#[test]
fn handle_save_returns_event() {
    let mut view = ProxyLogView::new();
    view.load_exchanges(vec![make_exchange(1, "GET", "http://localhost/a", 200)]);
    let event = view.handle_action(Action::Save);
    assert!(matches!(event, ProxyLogEvent::Save(_)));
}

#[test]
fn handle_action_on_empty_returns_none() {
    let mut view = ProxyLogView::new();
    assert!(matches!(
        view.handle_action(Action::SendToRepeater),
        ProxyLogEvent::None
    ));
    assert!(matches!(
        view.handle_action(Action::SendToIntruder),
        ProxyLogEvent::None
    ));
    assert!(matches!(
        view.handle_action(Action::Save),
        ProxyLogEvent::None
    ));
}

#[test]
fn cycle_focus_rotates() {
    let mut view = ProxyLogView::new();
    assert_eq!(view.focus, ProxyLogFocus::List);
    view.cycle_focus();
    assert_eq!(view.focus, ProxyLogFocus::Request);
    view.cycle_focus();
    assert_eq!(view.focus, ProxyLogFocus::Response);
    view.cycle_focus();
    assert_eq!(view.focus, ProxyLogFocus::List);
}
