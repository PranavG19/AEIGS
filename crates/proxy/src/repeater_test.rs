use std::net::SocketAddr;

use axum::Router;
use axum::routing::{get, post};

use super::*;
use crate::types::RecordedExchange;

async fn spawn_test_server() -> SocketAddr {
    let app = Router::new()
        .route("/hello", get(|| async { "world" }))
        .route("/echo", post(|body: axum::body::Bytes| async move { body }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

fn make_exchange(method: &str, url: &str, body: &[u8]) -> RecordedExchange {
    RecordedExchange {
        id: 1,
        request_method: method.to_string(),
        request_url: url.to_string(),
        request_headers: vec![],
        request_body: body.to_vec(),
        response_status: 200,
        response_headers: vec![],
        response_body: b"original response".to_vec(),
        timestamp_ms: 1_700_000_000_000,
        duration_ms: 10,
        in_scope: true,
        tags: vec![],
    }
}

#[test]
fn modified_request_from_exchange_copies_fields() {
    let ex = make_exchange("POST", "http://localhost/test", b"body data");
    let req = ModifiedRequest::from_exchange(&ex);
    assert_eq!(req.method, "POST");
    assert_eq!(req.url, "http://localhost/test");
    assert_eq!(req.body, b"body data");
}

#[tokio::test]
async fn repeat_sends_original_when_no_modifications() {
    let target = spawn_test_server().await;
    let url = format!("http://{target}/hello");
    let exchange = make_exchange("GET", &url, b"");

    let repeater = Repeater::new();
    let result = repeater.repeat(&exchange, None).await.unwrap();

    assert_eq!(result.response_status, 200);
    assert_eq!(result.response_body, b"world");
    assert_eq!(result.modified_request.method, "GET");
    assert_eq!(result.modified_request.url, url);
}

#[tokio::test]
async fn repeat_sends_modified_request() {
    let target = spawn_test_server().await;
    let original_url = format!("http://{target}/hello");
    let exchange = make_exchange("GET", &original_url, b"");

    let modified = ModifiedRequest {
        method: "POST".to_string(),
        url: format!("http://{target}/echo"),
        headers: vec![],
        body: b"modified body".to_vec(),
    };

    let repeater = Repeater::new();
    let result = repeater.repeat(&exchange, Some(modified)).await.unwrap();

    assert_eq!(result.response_status, 200);
    assert_eq!(result.response_body, b"modified body");
    assert_eq!(result.modified_request.method, "POST");
    assert_eq!(result.original.request_method, "GET");
}

#[tokio::test]
async fn repeat_measures_duration() {
    let target = spawn_test_server().await;
    let url = format!("http://{target}/hello");
    let exchange = make_exchange("GET", &url, b"");

    let repeater = Repeater::new();
    let result = repeater.repeat(&exchange, None).await.unwrap();

    assert!(result.duration_ms < 5_000);
}

#[tokio::test]
async fn repeat_preserves_original_exchange() {
    let target = spawn_test_server().await;
    let url = format!("http://{target}/hello");
    let exchange = make_exchange("GET", &url, b"");

    let repeater = Repeater::new();
    let result = repeater.repeat(&exchange, None).await.unwrap();

    assert_eq!(result.original.id, 1);
    assert_eq!(result.original.response_body, b"original response");
    assert_eq!(result.original.request_method, "GET");
}

#[tokio::test]
async fn repeat_returns_response_headers() {
    let target = spawn_test_server().await;
    let url = format!("http://{target}/hello");
    let exchange = make_exchange("GET", &url, b"");

    let repeater = Repeater::new();
    let result = repeater.repeat(&exchange, None).await.unwrap();

    let has_content_type = result
        .response_headers
        .iter()
        .any(|(k, _)| k == "content-type");
    assert!(has_content_type);
}
