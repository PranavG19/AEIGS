use std::net::SocketAddr;

use axum::Router;
use axum::routing::{get, post};

use super::*;

async fn spawn_target_server() -> SocketAddr {
    let app = Router::new()
        .route("/hello", get(|| async { "world" }))
        .route("/echo", post(|body: axum::body::Bytes| async move { body }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

async fn spawn_proxy() -> ProxyHandle {
    let config = ProxyConfig::default().with_listen_addr(([127, 0, 0, 1], 0).into());
    start_proxy(config).await.unwrap()
}

#[tokio::test]
async fn proxy_records_get_request() {
    let target = spawn_target_server().await;
    let proxy = spawn_proxy().await;
    let proxy_addr = proxy.listen_addr();

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}")).unwrap())
        .build()
        .unwrap();

    let resp = client
        .get(format!("http://{target}/hello"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "world");

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    assert_eq!(proxy.exchange_count().await, 1);
    let exchanges = proxy.exchanges().await;
    assert_eq!(exchanges[0].request_method, "GET");
    assert!(exchanges[0].request_url.contains("/hello"));
    assert_eq!(exchanges[0].response_status, 200);
    assert_eq!(exchanges[0].response_body, b"world");

    proxy.shutdown().await;
}

#[tokio::test]
async fn proxy_records_post_with_body() {
    let target = spawn_target_server().await;
    let proxy = spawn_proxy().await;
    let proxy_addr = proxy.listen_addr();

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}")).unwrap())
        .build()
        .unwrap();

    let payload = b"test payload data";
    let resp = client
        .post(format!("http://{target}/echo"))
        .body(payload.to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), payload);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let exchanges = proxy.exchanges().await;
    assert_eq!(exchanges.len(), 1);
    assert_eq!(exchanges[0].request_method, "POST");
    assert_eq!(exchanges[0].request_body, payload);
    assert_eq!(exchanges[0].response_body, payload);

    proxy.shutdown().await;
}

#[tokio::test]
async fn exchange_by_id_returns_correct_entry() {
    let target = spawn_target_server().await;
    let proxy = spawn_proxy().await;
    let proxy_addr = proxy.listen_addr();

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}")).unwrap())
        .build()
        .unwrap();

    let _ = client
        .get(format!("http://{target}/hello"))
        .send()
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let exchanges = proxy.exchanges().await;
    let id = exchanges[0].id;
    let found = proxy.exchange_by_id(id).await;
    assert!(found.is_some());
    assert_eq!(found.unwrap().request_method, "GET");

    let missing = proxy.exchange_by_id(999_999).await;
    assert!(missing.is_none());

    proxy.shutdown().await;
}

#[tokio::test]
async fn clear_log_removes_all_entries() {
    let target = spawn_target_server().await;
    let proxy = spawn_proxy().await;
    let proxy_addr = proxy.listen_addr();

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}")).unwrap())
        .build()
        .unwrap();

    let _ = client
        .get(format!("http://{target}/hello"))
        .send()
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(proxy.exchange_count().await, 1);

    proxy.clear_log().await;
    assert_eq!(proxy.exchange_count().await, 0);
    assert!(proxy.exchanges().await.is_empty());

    proxy.shutdown().await;
}

#[tokio::test]
async fn max_log_size_evicts_oldest() {
    let target = spawn_target_server().await;
    let config = ProxyConfig::default()
        .with_listen_addr(([127, 0, 0, 1], 0).into())
        .with_max_log_size(2);
    let proxy = start_proxy(config).await.unwrap();
    let proxy_addr = proxy.listen_addr();

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}")).unwrap())
        .build()
        .unwrap();

    for _ in 0..3 {
        let _ = client
            .get(format!("http://{target}/hello"))
            .send()
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    }

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let exchanges = proxy.exchanges().await;
    assert_eq!(exchanges.len(), 2);

    proxy.shutdown().await;
}

#[tokio::test]
async fn proxy_returns_502_for_unreachable_target() {
    let proxy = spawn_proxy().await;
    let proxy_addr = proxy.listen_addr();

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}")).unwrap())
        .build()
        .unwrap();

    let resp = client
        .get("http://127.0.0.1:1/nonexistent")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 502);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let exchanges = proxy.exchanges().await;
    assert_eq!(exchanges.len(), 1);
    assert_eq!(exchanges[0].response_status, 502);

    proxy.shutdown().await;
}

#[tokio::test]
async fn proxy_records_duration_ms() {
    let target = spawn_target_server().await;
    let proxy = spawn_proxy().await;
    let proxy_addr = proxy.listen_addr();

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}")).unwrap())
        .build()
        .unwrap();

    let _ = client
        .get(format!("http://{target}/hello"))
        .send()
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let exchanges = proxy.exchanges().await;
    assert!(exchanges[0].timestamp_ms > 0);
    assert!(exchanges[0].duration_ms < 5_000);

    proxy.shutdown().await;
}

#[tokio::test]
async fn proxy_records_response_headers() {
    let target = spawn_target_server().await;
    let proxy = spawn_proxy().await;
    let proxy_addr = proxy.listen_addr();

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}")).unwrap())
        .build()
        .unwrap();

    let _ = client
        .get(format!("http://{target}/hello"))
        .send()
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let exchanges = proxy.exchanges().await;
    let has_content_type = exchanges[0]
        .response_headers
        .iter()
        .any(|(k, _)| k == "content-type");
    assert!(has_content_type);

    proxy.shutdown().await;
}

#[tokio::test]
async fn multiple_requests_get_unique_ids() {
    let target = spawn_target_server().await;
    let proxy = spawn_proxy().await;
    let proxy_addr = proxy.listen_addr();

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}")).unwrap())
        .build()
        .unwrap();

    for _ in 0..3 {
        let _ = client
            .get(format!("http://{target}/hello"))
            .send()
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let exchanges = proxy.exchanges().await;
    assert_eq!(exchanges.len(), 3);
    let ids: std::collections::HashSet<u64> = exchanges.iter().map(|e| e.id).collect();
    assert_eq!(ids.len(), 3);

    proxy.shutdown().await;
}
