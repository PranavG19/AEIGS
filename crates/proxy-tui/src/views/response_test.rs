use super::*;

#[test]
fn new_is_empty() {
    let view = ResponseView::new();
    assert!(view.is_empty());
}

#[test]
fn load_response_populates() {
    let mut view = ResponseView::new();
    view.load_response(
        200,
        vec![("content-type".to_string(), "application/json".to_string())],
        b"{\"ok\":true}".to_vec(),
        42,
    );
    assert!(!view.is_empty());
    assert_eq!(view.status_code, 200);
    assert_eq!(view.duration_ms, 42);
    assert_eq!(view.headers.len(), 1);
    assert_eq!(view.body_length(), 11);
}

#[test]
fn status_summary_format() {
    let mut view = ResponseView::new();
    view.load_response(200, vec![], b"".to_vec(), 123);
    assert_eq!(view.status_summary(), "200 (123ms)");
}

#[test]
fn header_lines_format() {
    let mut view = ResponseView::new();
    view.load_response(
        200,
        vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("x-powered-by".to_string(), "Express".to_string()),
        ],
        b"".to_vec(),
        0,
    );
    let lines = view.header_lines();
    assert_eq!(lines[1], "content-type: application/json");
    assert_eq!(lines[2], "x-powered-by: Express");
}

#[test]
fn header_lines_first_line_http_status() {
    let mut view = ResponseView::new();
    view.load_response(404, vec![], b"".to_vec(), 0);
    let lines = view.header_lines();
    assert_eq!(lines[0], "HTTP/1.1 404 Not Found");
}

#[test]
fn body_lines_delegates_to_hex_view() {
    let mut view = ResponseView::new();
    view.load_response(200, vec![], b"line1\nline2".to_vec(), 0);
    let lines = view.body_lines();
    assert_eq!(lines, vec!["line1", "line2"]);
}

#[test]
fn toggle_mode_cycles() {
    use crate::widgets::hex_view::BodyViewMode;
    let mut view = ResponseView::new();
    assert_eq!(view.mode(), BodyViewMode::Raw);
    view.toggle_mode();
    assert_eq!(view.mode(), BodyViewMode::Hex);
    view.toggle_mode();
    assert_eq!(view.mode(), BodyViewMode::Pretty);
    view.toggle_mode();
    assert_eq!(view.mode(), BodyViewMode::Raw);
}

#[test]
fn body_length_correct() {
    let mut view = ResponseView::new();
    view.load_response(200, vec![], b"hello world".to_vec(), 0);
    assert_eq!(view.body_length(), 11);
}

#[test]
fn clear_resets_to_empty() {
    let mut view = ResponseView::new();
    view.load_response(200, vec![], b"data".to_vec(), 50);
    view.clear();
    assert!(view.is_empty());
    assert_eq!(view.body_length(), 0);
    assert_eq!(view.duration_ms, 0);
    assert!(view.headers.is_empty());
}

#[test]
fn known_status_reasons() {
    let cases = [
        (200, "OK"),
        (201, "Created"),
        (204, "No Content"),
        (301, "Moved Permanently"),
        (302, "Found"),
        (304, "Not Modified"),
        (400, "Bad Request"),
        (401, "Unauthorized"),
        (403, "Forbidden"),
        (404, "Not Found"),
        (405, "Method Not Allowed"),
        (500, "Internal Server Error"),
        (502, "Bad Gateway"),
        (503, "Service Unavailable"),
    ];
    for (code, expected_reason) in cases {
        let mut view = ResponseView::new();
        view.load_response(code, vec![], b"".to_vec(), 0);
        let first = view.header_lines().into_iter().next().unwrap();
        assert_eq!(
            first,
            format!("HTTP/1.1 {code} {expected_reason}"),
            "code {code}"
        );
    }
}

#[test]
fn unknown_status_reason_empty() {
    let mut view = ResponseView::new();
    view.load_response(418, vec![], b"".to_vec(), 0);
    let first = view.header_lines().into_iter().next().unwrap();
    assert_eq!(first, "HTTP/1.1 418 ");
}
