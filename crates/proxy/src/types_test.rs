use super::*;

#[test]
fn default_config_listens_on_localhost_8080() {
    let config = ProxyConfig::default();
    assert_eq!(config.listen_addr, ([127, 0, 0, 1], 8080).into());
    assert_eq!(config.max_log_size, 10_000);
}

#[test]
fn config_builder_overrides() {
    let addr: SocketAddr = ([127, 0, 0, 1], 9090).into();
    let config = ProxyConfig::default()
        .with_listen_addr(addr)
        .with_max_log_size(500);
    assert_eq!(config.listen_addr, addr);
    assert_eq!(config.max_log_size, 500);
}

#[test]
fn recorded_exchange_serializes_to_json() {
    let exchange = RecordedExchange {
        id: 1,
        request_method: "GET".into(),
        request_url: "http://localhost:3000/api/test".into(),
        request_headers: vec![("Host".into(), "localhost:3000".into())],
        request_body: vec![],
        response_status: 200,
        response_headers: vec![("Content-Type".into(), "application/json".into())],
        response_body: b"{\"ok\":true}".to_vec(),
        timestamp_ms: 1700000000000,
        duration_ms: 42,
        in_scope: true,
        tags: vec![],
    };
    let json = serde_json::to_string(&exchange).unwrap();
    let deser: RecordedExchange = serde_json::from_str(&json).unwrap();
    assert_eq!(deser.id, 1);
    assert_eq!(deser.request_method, "GET");
    assert_eq!(deser.response_status, 200);
}
