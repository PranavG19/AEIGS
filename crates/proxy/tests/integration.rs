use aegis_proxy::*;
use tempfile::TempDir;

async fn start_test_server() -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new()
        .route(
            "/api/users",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({"users": ["alice", "bob"]}))
            }),
        )
        .route(
            "/api/items",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({"items": [1, 2, 3]}))
            }),
        )
        .route(
            "/api/status",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({"ok": true}))
            }),
        )
        .route(
            "/admin/settings",
            axum::routing::get(|| async { "admin panel" }),
        )
        .route(
            "/static/app.js",
            axum::routing::get(|| async { "console.log('app')" }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), handle)
}

#[tokio::test]
async fn test_proxy_persistence_round_trip() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("proxy.db");

    let proxy_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = ProxyConfig::default()
        .with_db_path(db_path)
        .with_listen_addr(proxy_addr);

    let handle = start_proxy(config).await.unwrap();
    let proxy_url = format!("http://{}", handle.listen_addr());

    let (server_url, _server_handle) = start_test_server().await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let paths = ["/api/users", "/api/items", "/api/status"];
    for path in &paths {
        let target = format!("{server_url}{path}");
        let resp = client.get(&target).header("host", "test").send().await;
        // The proxy forwards to the URL as-is, so we send requests
        // through the proxy by pointing reqwest at the target URL
        // while the proxy listens on a different port. Instead, we
        // send the request TO the proxy with the full target URL.
        drop(resp);
    }

    // Send requests through the proxy: the proxy forwards the URI as-is to the target.
    for path in &paths {
        let target_url = format!("{server_url}{path}");
        let resp = client
            .get(&target_url)
            .header("host", "localhost")
            .send()
            .await;
        // Actually, the recording proxy intercepts all incoming HTTP.
        // The client must send requests TO the proxy address, with the
        // full target URL in the request line.
        drop(resp);
    }

    // The correct pattern: send requests to the proxy address with
    // the full upstream URL as the request target (HTTP/1.1 absolute-form).
    for path in &paths {
        let url = format!("{server_url}{path}");
        // hyper proxy expects absolute-URI in request line
        let resp = client
            .get(&url)
            .header("host", "test-host")
            .send()
            .await;
        drop(resp);
    }

    // Give the proxy a moment to process (the forwarding happens asynchronously
    // in the accept loop). Instead, the proxy listens on its own port and we
    // must send requests directly to it.
    //
    // The proxy is an HTTP forward proxy: the client sends an absolute-form
    // request to the proxy's listen address. The proxy extracts the URI and
    // forwards it to the upstream. reqwest does not natively do this, so we
    // need to configure it with a proxy setting or craft raw requests. But
    // looking at the proxy code, `handle_request` just takes the URI from the
    // request and forwards it via reqwest. So we send a request to the proxy
    // addr with the full target URL.
    let proxy_client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(&proxy_url).unwrap())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    for path in &paths {
        let url = format!("{server_url}{path}");
        let resp = proxy_client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    // Allow a brief moment for async persistence writes.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Verify in-memory log has 3 exchanges.
    assert_eq!(handle.exchange_count().await, 3);
    let exchanges = handle.exchanges().await;
    assert_eq!(exchanges.len(), 3);

    // Verify SQLite has 3 exchanges. Scope the MutexGuard so it is
    // dropped before the shutdown().await below.
    {
        let db_arc = handle.db().expect("db should be configured");
        let db = db_arc.lock().unwrap();
        assert_eq!(db.exchange_count().unwrap(), 3);

        // Verify DB row fields.
        let db_exchanges = db.list_exchanges(10, 0).unwrap();
        assert_eq!(db_exchanges.len(), 3);
        for db_ex in &db_exchanges {
            assert_eq!(db_ex.request_method, "GET");
            assert_eq!(db_ex.response_status, 200);
        }
    }

    // Verify exchange fields match what we sent/received.
    for (i, path) in paths.iter().enumerate() {
        let ex = &exchanges[i];
        assert_eq!(ex.request_method, "GET");
        assert!(
            ex.request_url.contains(path),
            "exchange URL {} should contain {}",
            ex.request_url,
            path
        );
        assert_eq!(ex.response_status, 200);
        assert!(!ex.response_body.is_empty());
    }

    handle.shutdown().await;
}

#[test]
fn test_scope_filters_exchanges() {
    let mut scope = ScopeEngine::new();
    scope.add_rule(r"^.*/api/.*", true).unwrap();
    scope.add_rule(r".*/admin/.*", false).unwrap();

    assert!(scope.is_in_scope("http://localhost/api/users"));
    assert!(!scope.is_in_scope("http://localhost/admin/settings"));
    assert!(!scope.is_in_scope("http://localhost/static/app.js"));
    // Edge case: /api/admin/ should match include but be excluded.
    assert!(!scope.is_in_scope("http://localhost/api/admin/config"));
}

#[tokio::test]
async fn test_payload_pipeline_to_intruder() {
    let (server_url, _server_handle) = start_test_server().await;

    let pipeline = PayloadPipeline {
        source: PayloadSource::NumberRange {
            start: 1,
            end: 3,
            step: 1,
        },
        processors: vec![PayloadProcessor::AddPrefix("id=".to_string())],
        encoding: PayloadEncoding::UrlEncode,
    };

    let payloads = pipeline.generate().unwrap();
    assert_eq!(payloads, vec!["id%3D1", "id%3D2", "id%3D3"]);

    let template = ModifiedRequest {
        method: "GET".to_string(),
        url: format!("{server_url}/api/users?__PAYLOAD__"),
        headers: vec![],
        body: vec![],
    };

    let config = PipelineIntruderConfig {
        template,
        positions: vec!["__PAYLOAD__".to_string()],
        pipelines: vec![pipeline],
        mode: AttackMode::BatteringRam,
        concurrency: 2,
        grep_matches: vec![],
        grep_extracts: vec![],
    };

    let results = run_pipeline_intruder(config).await.unwrap();
    assert_eq!(results.len(), 3);
    for result in &results {
        assert_eq!(result.status_code, 200);
        assert!(result.body_length > 0);
    }
}

#[tokio::test]
async fn test_grep_on_intruder_results() {
    let app = axum::Router::new().route(
        "/data",
        axum::routing::get(|| async {
            axum::Json(serde_json::json!({"token":"abc123","status":"success"}))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let server_url = format!("http://{addr}");

    let pipeline = PayloadPipeline {
        source: PayloadSource::SimpleList(vec!["a".to_string(), "b".to_string()]),
        processors: vec![],
        encoding: PayloadEncoding::None,
    };

    let template = ModifiedRequest {
        method: "GET".to_string(),
        url: format!("{server_url}/data?v=__P__"),
        headers: vec![],
        body: vec![],
    };

    let config = PipelineIntruderConfig {
        template,
        positions: vec!["__P__".to_string()],
        pipelines: vec![pipeline],
        mode: AttackMode::BatteringRam,
        concurrency: 1,
        grep_matches: vec![GrepMatch {
            pattern: "success".to_string(),
            search_in: SearchTarget::Body,
            negate: false,
        }],
        grep_extracts: vec![GrepExtract {
            pattern: r#""token":"([^"]+)""#.to_string(),
            group: 1,
            search_in: SearchTarget::Body,
        }],
    };

    let results = run_pipeline_intruder(config).await.unwrap();
    assert_eq!(results.len(), 2);
    for result in &results {
        assert_eq!(result.status_code, 200);
        assert!(
            result.grep_match_results.contains(&"success".to_string()),
            "grep_match_results should contain 'success': {:?}",
            result.grep_match_results
        );
        assert!(
            result.grep_extract_results.contains(&"abc123".to_string()),
            "grep_extract_results should contain 'abc123': {:?}",
            result.grep_extract_results
        );
    }
}

#[test]
fn test_diff_between_responses() {
    let old_headers = vec![
        ("content-type".to_string(), "text/html".to_string()),
        ("x-custom".to_string(), "old-val".to_string()),
        ("x-removed".to_string(), "gone".to_string()),
    ];
    let new_headers = vec![
        ("content-type".to_string(), "text/html".to_string()),
        ("x-custom".to_string(), "new-val".to_string()),
        ("x-added".to_string(), "fresh".to_string()),
    ];
    let old_body = b"line1\nline2\nline3";
    let new_body = b"line1\nmodified\nline3\nline4";

    let diff = compare_responses(200, &old_headers, old_body, 50, 404, &new_headers, new_body, 75);

    assert!(diff.status_changed);
    assert_eq!(diff.old_status, 200);
    assert_eq!(diff.new_status, 404);

    // Header diffs: x-custom changed, x-removed removed, x-added added.
    assert!(
        diff.header_diffs
            .iter()
            .any(|h| matches!(h, HeaderDiff::Changed(name, _, _) if name == "x-custom")),
        "expected x-custom changed: {:?}",
        diff.header_diffs
    );
    assert!(
        diff.header_diffs
            .iter()
            .any(|h| matches!(h, HeaderDiff::Removed(name, _) if name == "x-removed")),
        "expected x-removed removed: {:?}",
        diff.header_diffs
    );
    assert!(
        diff.header_diffs
            .iter()
            .any(|h| matches!(h, HeaderDiff::Added(name, _) if name == "x-added")),
        "expected x-added added: {:?}",
        diff.header_diffs
    );

    // Body diff should have chunks.
    assert!(!diff.body_diff.is_empty());
    let has_added = diff
        .body_diff
        .iter()
        .any(|c| matches!(c, DiffChunk::Added(_)));
    let has_removed = diff
        .body_diff
        .iter()
        .any(|c| matches!(c, DiffChunk::Removed(_)));
    assert!(has_added, "body diff should have Added chunks");
    assert!(has_removed, "body diff should have Removed chunks");

    // Body length delta.
    assert_eq!(
        diff.body_length_delta,
        new_body.len() as i64 - old_body.len() as i64
    );

    // Duration delta.
    assert_eq!(diff.duration_delta_ms, 25);
}

#[test]
fn test_session_jar_tracks_cookies() {
    let mut jar = SessionJar::new();

    let response_headers = vec![
        (
            "set-cookie".to_string(),
            "session_id=abc123; Path=/; HttpOnly".to_string(),
        ),
        (
            "set-cookie".to_string(),
            "csrf_token=xyz789; Path=/api".to_string(),
        ),
    ];

    jar.update_from_response("http://example.com/login", &response_headers);

    assert_eq!(jar.cookies().len(), 2);

    // Inject cookies for a matching URL.
    let cookie_header = jar.inject_cookies("http://example.com/api/data");
    assert!(cookie_header.is_some());
    let (name, value) = cookie_header.unwrap();
    assert_eq!(name, "cookie");
    assert!(
        value.contains("session_id=abc123"),
        "should contain session_id: {value}"
    );
    assert!(
        value.contains("csrf_token=xyz789"),
        "should contain csrf_token: {value}"
    );

    // Inject cookies for root path: only session_id matches (path=/).
    let root_header = jar.inject_cookies("http://example.com/other");
    assert!(root_header.is_some());
    let (_, root_value) = root_header.unwrap();
    assert!(
        root_value.contains("session_id=abc123"),
        "root path should get session_id: {root_value}"
    );
    // csrf_token has path=/api, so /other should not match.
    assert!(
        !root_value.contains("csrf_token"),
        "root path should not get csrf_token: {root_value}"
    );

    // No cookies for a different domain.
    let other_domain = jar.inject_cookies("http://other.com/api/data");
    assert!(other_domain.is_none());

    // Verify session cookie detection.
    assert!(SessionJar::is_session_cookie("session_id"));
    assert!(SessionJar::is_session_cookie("csrf_token"));
    assert!(!SessionJar::is_session_cookie("tracking_pixel"));
}

#[test]
fn test_modification_rules_transform_traffic() {
    let mut engine = ModificationEngine::new();
    engine
        .add_rule(
            MatchTarget::ResponseHeader,
            r"(?i)^x-frame-options:.*$",
            "",
        )
        .unwrap();

    let mut headers = vec![
        ("content-type".to_string(), "text/html".to_string()),
        ("x-frame-options".to_string(), "DENY".to_string()),
        ("x-content-type-options".to_string(), "nosniff".to_string()),
    ];
    let mut body = b"<html>hello</html>".to_vec();

    apply_response_modifications(engine.rules(), &mut headers, &mut body);

    // x-frame-options should be removed (regex replaces entire header line with empty string).
    assert!(
        !headers.iter().any(|(k, _)| k == "x-frame-options"),
        "x-frame-options should be removed: {:?}",
        headers
    );
    // Other headers should remain.
    assert!(headers.iter().any(|(k, _)| k == "content-type"));
    assert!(headers
        .iter()
        .any(|(k, _)| k == "x-content-type-options"));
    // Body should be untouched.
    assert_eq!(body, b"<html>hello</html>");
}

#[test]
fn test_graph_sync_from_proxy_exchanges() {
    let exchanges = vec![
        RecordedExchange {
            id: 1,
            request_method: "GET".to_string(),
            request_url: "http://localhost/api/users?page=1&limit=10".to_string(),
            request_headers: vec![],
            request_body: vec![],
            response_status: 200,
            response_headers: vec![
                ("server".to_string(), "nginx".to_string()),
                (
                    "x-powered-by".to_string(),
                    "Express".to_string(),
                ),
            ],
            response_body: b"ok".to_vec(),
            timestamp_ms: 1000,
            duration_ms: 50,
            in_scope: true,
            tags: vec![],
        },
        RecordedExchange {
            id: 2,
            request_method: "POST".to_string(),
            request_url: "http://localhost/api/login".to_string(),
            request_headers: vec![(
                "content-type".to_string(),
                "application/json".to_string(),
            )],
            request_body: br#"{"username":"admin","password":"secret"}"#.to_vec(),
            response_status: 200,
            response_headers: vec![],
            response_body: b"ok".to_vec(),
            timestamp_ms: 2000,
            duration_ms: 100,
            in_scope: true,
            tags: vec![],
        },
        RecordedExchange {
            id: 3,
            request_method: "GET".to_string(),
            request_url: "http://localhost/api/users?page=2&limit=10".to_string(),
            request_headers: vec![],
            request_body: vec![],
            response_status: 200,
            response_headers: vec![],
            response_body: b"ok".to_vec(),
            timestamp_ms: 3000,
            duration_ms: 30,
            in_scope: true,
            tags: vec![],
        },
    ];

    let result = sync_exchanges_to_graph(&exchanges);

    // 3 exchanges but /api/users GET is deduplicated -> 2 unique endpoints.
    assert_eq!(
        result.endpoints_added, 2,
        "should be 2 unique (path, method) pairs"
    );

    // Parameters: /api/users?page=1&limit=10 -> 2 query params,
    // POST /api/login JSON body -> 2 keys (username, password).
    // Deduplicated /api/users GET is skipped, so total = 2 + 2 = 4.
    assert_eq!(
        result.parameters_discovered, 4,
        "should discover 4 parameters"
    );

    assert_eq!(result.operations.len(), 2);

    // Verify operations are AddNode with Endpoint type.
    for op in &result.operations {
        match &op.operation {
            aegis_protocol::operation::GraphOperation::AddNode {
                node_type,
                properties,
            } => {
                assert_eq!(*node_type, aegis_protocol::node::NodeType::Endpoint);
                assert!(
                    properties.iter().any(|(k, _)| k == "path"),
                    "should have path property"
                );
                assert!(
                    properties.iter().any(|(k, _)| k == "method"),
                    "should have method property"
                );
                assert!(
                    properties
                        .iter()
                        .any(|(k, v)| k == "discovery_source" && v == "proxy"),
                    "should have discovery_source=proxy"
                );
            }
            other => panic!("expected AddNode, got {:?}", other),
        }
    }

    // Verify the first operation (GET /api/users) has server metadata.
    let first_props = match &result.operations[0].operation {
        aegis_protocol::operation::GraphOperation::AddNode { properties, .. } => properties,
        _ => unreachable!(),
    };
    assert!(
        first_props.iter().any(|(k, v)| k == "server" && v == "nginx"),
        "first endpoint should have server=nginx"
    );
    assert!(
        first_props
            .iter()
            .any(|(k, v)| k == "technology" && v == "Express"),
        "first endpoint should have technology=Express"
    );

    // Verify the second operation (POST /api/login) has parameters.
    let second_props = match &result.operations[1].operation {
        aegis_protocol::operation::GraphOperation::AddNode { properties, .. } => properties,
        _ => unreachable!(),
    };
    let params_json = second_props
        .iter()
        .find(|(k, _)| k == "parameters")
        .map(|(_, v)| v.clone())
        .expect("POST /api/login should have parameters");
    let params: Vec<(String, String)> = serde_json::from_str(&params_json).unwrap();
    assert!(
        params.iter().any(|(k, _)| k == "username"),
        "should extract username parameter"
    );
    assert!(
        params.iter().any(|(k, _)| k == "password"),
        "should extract password parameter"
    );
}
