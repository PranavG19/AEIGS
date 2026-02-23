use aegis_proxy::{ModifiedRequest, RecordedExchange};

use super::{EditorField, RequestEditorEvent, RequestEditorView};
use crate::keybinds::Action;

fn make_exchange(method: &str, url: &str, body: &[u8]) -> RecordedExchange {
    RecordedExchange {
        id: 1,
        request_method: method.to_string(),
        request_url: url.to_string(),
        request_headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
        request_body: body.to_vec(),
        response_status: 200,
        response_headers: vec![],
        response_body: vec![],
        timestamp_ms: 0,
        duration_ms: 0,
        in_scope: true,
        tags: vec![],
    }
}

fn make_modified_request(method: &str, url: &str, body: &[u8]) -> ModifiedRequest {
    ModifiedRequest {
        method: method.to_string(),
        url: url.to_string(),
        headers: vec![("Authorization".to_string(), "Bearer token".to_string())],
        body: body.to_vec(),
    }
}

#[test]
fn new_has_defaults() {
    let view = RequestEditorView::new();
    assert_eq!(view.method, "GET");
    assert_eq!(view.url, "");
    assert!(view.headers.is_empty());
    assert!(view.body.is_empty());
    assert_eq!(view.focused_field, EditorField::Method);
}

#[test]
fn load_request_populates_fields() {
    let mut view = RequestEditorView::new();
    let req = make_modified_request("POST", "http://localhost/api", b"hello");
    view.load_request(req);
    assert_eq!(view.method, "POST");
    assert_eq!(view.url, "http://localhost/api");
    assert_eq!(
        view.headers,
        vec![("Authorization".to_string(), "Bearer token".to_string())]
    );
    assert_eq!(view.body, b"hello");
}

#[test]
fn load_exchange_populates_fields() {
    let mut view = RequestEditorView::new();
    let ex = make_exchange("DELETE", "http://localhost/item/1", b"");
    view.load_exchange(&ex);
    assert_eq!(view.method, "DELETE");
    assert_eq!(view.url, "http://localhost/item/1");
    assert_eq!(
        view.headers,
        vec![("Content-Type".to_string(), "text/plain".to_string())]
    );
    assert!(view.body.is_empty());
}

#[test]
fn current_request_reflects_state() {
    let mut view = RequestEditorView::new();
    view.method = "PUT".to_string();
    view.url = "http://localhost/update".to_string();
    view.headers = vec![("X-Custom".to_string(), "value".to_string())];
    view.body = b"data".to_vec();
    let req = view.current_request();
    assert_eq!(req.method, "PUT");
    assert_eq!(req.url, "http://localhost/update");
    assert_eq!(
        req.headers,
        vec![("X-Custom".to_string(), "value".to_string())]
    );
    assert_eq!(req.body, b"data");
}

#[test]
fn as_curl_get_no_body() {
    let mut view = RequestEditorView::new();
    view.url = "http://localhost/api".to_string();
    let curl = view.as_curl();
    assert_eq!(curl, "curl -X GET 'http://localhost/api'");
}

#[test]
fn as_curl_post_with_body() {
    let mut view = RequestEditorView::new();
    view.method = "POST".to_string();
    view.url = "http://localhost/api".to_string();
    view.body = b"key=value".to_vec();
    let curl = view.as_curl();
    assert_eq!(curl, "curl -X POST 'http://localhost/api' -d 'key=value'");
}

#[test]
fn as_curl_with_headers() {
    let mut view = RequestEditorView::new();
    view.method = "POST".to_string();
    view.url = "http://localhost/api".to_string();
    view.headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("Authorization".to_string(), "Bearer abc".to_string()),
    ];
    view.body = b"{\"x\":1}".to_vec();
    let curl = view.as_curl();
    assert_eq!(
        curl,
        "curl -X POST 'http://localhost/api' -H 'Content-Type: application/json' -H 'Authorization: Bearer abc' -d '{\"x\":1}'"
    );
}

#[test]
fn handle_enter_sends_request() {
    let mut view = RequestEditorView::new();
    view.method = "GET".to_string();
    view.url = "http://localhost/ping".to_string();
    let event = view.handle_action(Action::Enter);
    let RequestEditorEvent::SendRequest(req) = event else {
        panic!("expected SendRequest");
    };
    assert_eq!(req.method, "GET");
    assert_eq!(req.url, "http://localhost/ping");
}

#[test]
fn handle_save_copies_curl() {
    let mut view = RequestEditorView::new();
    view.url = "http://localhost/test".to_string();
    let event = view.handle_action(Action::Save);
    let RequestEditorEvent::CopyAsCurl(curl) = event else {
        panic!("expected CopyAsCurl");
    };
    assert!(curl.starts_with("curl -X GET 'http://localhost/test'"));
}

#[test]
fn cycle_field_rotates() {
    let mut view = RequestEditorView::new();
    assert_eq!(view.focused_field, EditorField::Method);
    view.cycle_field();
    assert_eq!(view.focused_field, EditorField::Url);
    view.cycle_field();
    assert_eq!(view.focused_field, EditorField::Headers);
    view.cycle_field();
    assert_eq!(view.focused_field, EditorField::Body);
    view.cycle_field();
    assert_eq!(view.focused_field, EditorField::Method);
}
