use crate::websocket_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_html_for_websockets("");
    assert!(issues.is_empty());
}

#[test]
fn no_websocket_references() {
    let body = "<html><script>var x = 'https://example.com';</script></html>";
    let issues = analyze_html_for_websockets(body);
    assert!(issues.is_empty());
}

#[test]
fn insecure_ws_detected() {
    let body = r#"<script>var sock = new WebSocket("ws://example.com/ws");</script>"#;
    let issues = analyze_html_for_websockets(body);
    assert!(issues
        .iter()
        .any(|i| matches!(i, WebSocketIssue::InsecureWsScheme { .. })));
    assert!(issues
        .iter()
        .any(|i| matches!(i, WebSocketIssue::WsInHtmlSource { .. })));
}

#[test]
fn secure_wss_detected_as_source() {
    let body = r#"<script>new WebSocket("wss://example.com/live");</script>"#;
    let issues = analyze_html_for_websockets(body);
    assert!(issues
        .iter()
        .any(|i| matches!(i, WebSocketIssue::WsInHtmlSource { url } if url.starts_with("wss://"))));
    assert!(!issues
        .iter()
        .any(|i| matches!(i, WebSocketIssue::InsecureWsScheme { .. })));
}

#[test]
fn multiple_ws_urls_detected() {
    let body = r#"
        <script>
            var a = "ws://example.com/chat";
            var b = "wss://example.com/stream";
        </script>
    "#;
    let issues = analyze_html_for_websockets(body);
    let ws_sources = issues
        .iter()
        .filter(|i| matches!(i, WebSocketIssue::WsInHtmlSource { .. }))
        .count();
    assert_eq!(ws_sources, 2);
}

#[test]
fn ws_url_terminated_by_single_quote() {
    let body = "var x = 'ws://example.com/sock';";
    let issues = analyze_html_for_websockets(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        WebSocketIssue::WsInHtmlSource { url } if url == "ws://example.com/sock"
    )));
}

#[test]
fn ws_url_terminated_by_parenthesis() {
    let body = "connect(ws://localhost/ws)";
    let issues = analyze_html_for_websockets(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        WebSocketIssue::WsInHtmlSource { url } if url == "ws://localhost/ws"
    )));
}

#[test]
fn severity_ordering() {
    assert!(
        websocket_severity(&WebSocketIssue::MissingOriginValidation {
            endpoint: "/ws".into()
        }) > websocket_severity(&WebSocketIssue::InsecureWsScheme {
            endpoint: "/ws".into()
        })
    );
    assert!(
        websocket_severity(&WebSocketIssue::InsecureWsScheme {
            endpoint: "/ws".into()
        }) > websocket_severity(&WebSocketIssue::WsEndpointDiscovered {
            endpoint: "/ws".into()
        })
    );
}

#[test]
fn to_operations_produces_entries() {
    let issues = vec![
        WebSocketIssue::WsEndpointDiscovered {
            endpoint: "/ws".into(),
        },
        WebSocketIssue::MissingOriginValidation {
            endpoint: "/ws".into(),
        },
    ];
    let mut seq = 10;
    let ops = websocket_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 12);
}

#[test]
fn display_variants() {
    let issue = WebSocketIssue::InsecureWsScheme {
        endpoint: "ws://x.com/ws".into(),
    };
    assert_eq!(issue.to_string(), "insecure_ws:ws://x.com/ws");

    let issue = WebSocketIssue::MissingOriginValidation {
        endpoint: "/ws".into(),
    };
    assert_eq!(issue.to_string(), "ws_no_origin_check:/ws");
}

#[test]
fn ws_in_socket_io_pattern() {
    let body = r#"<script src="https://cdn.socket.io/socket.io.js"></script>
    <script>var socket = io("ws://example.com/socket.io/");</script>"#;
    let issues = analyze_html_for_websockets(body);
    assert!(issues
        .iter()
        .any(|i| matches!(i, WebSocketIssue::InsecureWsScheme { .. })));
}
