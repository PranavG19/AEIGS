use aegis_proxy::{ModifiedRequest, RecordedExchange};

use super::*;

fn make_exchange(status: u16) -> RecordedExchange {
    RecordedExchange {
        id: 1,
        request_method: "GET".to_string(),
        request_url: "http://localhost/api".to_string(),
        request_headers: vec![],
        request_body: vec![],
        response_status: status,
        response_headers: vec![],
        response_body: b"body".to_vec(),
        timestamp_ms: 0,
        duration_ms: 10,
        in_scope: true,
        tags: vec![],
    }
}

fn make_request(url: &str) -> ModifiedRequest {
    ModifiedRequest {
        method: "GET".to_string(),
        url: url.to_string(),
        headers: vec![],
        body: vec![],
    }
}

#[test]
fn new_is_empty() {
    let view = RepeaterView::new();
    assert_eq!(view.history_len(), 0);
    assert!(!view.show_diff);
    assert_eq!(view.history_index, 0);
    assert!(view.current_status().is_none());
}

#[test]
fn load_exchange_sets_request() {
    let mut view = RepeaterView::new();
    let exchange = make_exchange(200);
    view.load_exchange(&exchange);
    assert_eq!(view.current_request.url, "http://localhost/api");
    assert_eq!(view.current_request.method, "GET");
}

#[test]
fn record_response_grows_history() {
    let mut view = RepeaterView::new();
    view.load_exchange(&make_exchange(200));
    view.record_response(200, vec![], b"ok".to_vec(), 10);
    assert_eq!(view.history_len(), 1);
    view.record_response(404, vec![], b"not found".to_vec(), 5);
    assert_eq!(view.history_len(), 2);
}

#[test]
fn history_index_resets_on_new_response() {
    let mut view = RepeaterView::new();
    view.load_exchange(&make_exchange(200));
    view.record_response(200, vec![], b"first".to_vec(), 10);
    view.record_response(201, vec![], b"second".to_vec(), 10);
    view.navigate_history(-1);
    assert_eq!(view.history_index, 1);
    view.record_response(202, vec![], b"third".to_vec(), 10);
    assert_eq!(view.history_index, 0);
}

#[test]
fn navigate_history_back() {
    let mut view = RepeaterView::new();
    view.load_exchange(&make_exchange(200));
    view.record_response(200, vec![], b"first".to_vec(), 10);
    view.record_response(201, vec![], b"second".to_vec(), 10);
    view.navigate_history(-1);
    assert_eq!(view.history_index, 1);
}

#[test]
fn navigate_history_forward() {
    let mut view = RepeaterView::new();
    view.load_exchange(&make_exchange(200));
    view.record_response(200, vec![], b"first".to_vec(), 10);
    view.record_response(201, vec![], b"second".to_vec(), 10);
    view.navigate_history(-1);
    assert_eq!(view.history_index, 1);
    view.navigate_history(1);
    assert_eq!(view.history_index, 0);
}

#[test]
fn navigate_history_clamps() {
    let mut view = RepeaterView::new();
    view.load_exchange(&make_exchange(200));
    view.record_response(200, vec![], b"only".to_vec(), 10);
    view.navigate_history(-10);
    assert_eq!(view.history_index, 0);
    view.navigate_history(10);
    assert_eq!(view.history_index, 0);
}

#[test]
fn handle_enter_sends_request() {
    let mut view = RepeaterView::new();
    view.current_request = make_request("http://localhost/test");
    let event = view.handle_action(crate::keybinds::Action::Enter);
    match event {
        RepeaterEvent::SendRequest(req) => assert_eq!(req.url, "http://localhost/test"),
        RepeaterEvent::None => panic!("expected SendRequest"),
    }
}

#[test]
fn handle_nav_left_navigates() {
    let mut view = RepeaterView::new();
    view.load_exchange(&make_exchange(200));
    view.record_response(200, vec![], b"a".to_vec(), 10);
    view.record_response(201, vec![], b"b".to_vec(), 10);
    view.handle_action(crate::keybinds::Action::NavLeft);
    assert_eq!(view.history_index, 1);
}

#[test]
fn diff_with_original_computes() {
    let mut view = RepeaterView::new();
    view.load_exchange(&make_exchange(200));
    view.record_response(404, vec![], b"different".to_vec(), 20);
    view.diff_with_original();
    assert!(view.show_diff);
    assert!(view.diff_view.diff.is_some());
}

#[test]
fn current_status_none_when_empty() {
    let view = RepeaterView::new();
    assert!(view.current_status().is_none());
}

#[test]
fn current_status_after_response() {
    let mut view = RepeaterView::new();
    view.load_exchange(&make_exchange(200));
    view.record_response(403, vec![], b"forbidden".to_vec(), 5);
    assert_eq!(view.current_status(), Some(403));
}
