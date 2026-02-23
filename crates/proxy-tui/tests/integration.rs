use aegis_knowledge_graph::{GraphMetadata, KnowledgeGraph};
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};
use aegis_proxy::{
    PayloadListRecord, PipelineIntruderResult, ProxyConfig, RecordedExchange, ScopeEngine,
    start_proxy,
};
use aegis_proxy_tui::graph_import::import_from_graph;
use aegis_proxy_tui::views::{
    comparer::ComparerView, intruder::IntruderView, payloads::PayloadsView,
    proxy_log::ProxyLogView, repeater::RepeaterView, request_editor::RequestEditorView,
    response::ResponseView, scope::ScopeView,
};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Shared helper: constructs a minimal RecordedExchange for tests.
// ---------------------------------------------------------------------------

fn make_exchange(id: u64, method: &str, url: &str, status: u16, body: &[u8]) -> RecordedExchange {
    RecordedExchange {
        id,
        request_method: method.to_string(),
        request_url: url.to_string(),
        request_headers: vec![
            ("host".to_string(), "localhost".to_string()),
            ("content-type".to_string(), "text/plain".to_string()),
        ],
        request_body: b"req-body".to_vec(),
        response_status: status,
        response_headers: vec![("content-type".to_string(), "application/json".to_string())],
        response_body: body.to_vec(),
        timestamp_ms: 1_700_000_000_000,
        duration_ms: 42,
        in_scope: true,
        tags: vec![],
    }
}

// ---------------------------------------------------------------------------
// T1: ProxyLogView wiring
// ---------------------------------------------------------------------------

#[test]
fn proxy_log_view_wiring() {
    let mut view = ProxyLogView::new();

    // No exchanges loaded yet — table is empty and nothing is selected.
    assert_eq!(view.exchange_count(), 0);
    assert!(view.selected_exchange().is_none());

    // Load two exchanges — table rows must be populated.
    view.load_exchanges(vec![
        make_exchange(1, "GET", "http://localhost/api/users", 200, b"[]"),
        make_exchange(2, "POST", "http://localhost/api/users", 201, b"{\"id\":1}"),
    ]);
    assert_eq!(view.exchange_count(), 2);
    assert_eq!(view.table.rows.len(), 2);

    // Filter by "users" — both rows match.
    view.apply_filter(Some("users".to_string()));
    assert_eq!(view.table.filtered_rows().len(), 2);

    // Filter by "POST" — only the POST row survives.
    view.apply_filter(Some("POST".to_string()));
    assert_eq!(view.table.filtered_rows().len(), 1);

    // Remove filter — both rows visible again.
    view.apply_filter(None);
    assert_eq!(view.table.filtered_rows().len(), 2);

    // SendToRepeater fires with the selected (first) exchange.
    use aegis_proxy_tui::views::proxy_log::ProxyLogEvent;
    let event = view.handle_action(aegis_proxy_tui::keybinds::Action::SendToRepeater);
    assert!(
        matches!(event, ProxyLogEvent::SendToRepeater(ex) if ex.id == 1),
        "expected SendToRepeater with id=1"
    );
}

// ---------------------------------------------------------------------------
// T2: RequestEditorView wiring
// ---------------------------------------------------------------------------

#[test]
fn request_editor_wiring() {
    let exchange = make_exchange(
        5,
        "POST",
        "http://localhost/api/login",
        200,
        b"{\"token\":\"abc\"}",
    );

    let mut view = RequestEditorView::new();
    view.load_exchange(&exchange);

    // current_request() must mirror the loaded exchange.
    let req = view.current_request();
    assert_eq!(req.method, "POST");
    assert_eq!(req.url, "http://localhost/api/login");
    assert_eq!(req.headers.len(), 2);
    assert_eq!(req.body, b"req-body".to_vec());

    // as_curl() must include method, url, and all headers.
    let curl = view.as_curl();
    assert!(curl.starts_with("curl -X POST 'http://localhost/api/login'"));
    assert!(curl.contains("-H 'host: localhost'"));
    assert!(curl.contains("-H 'content-type: text/plain'"));
    // Body is non-empty so -d should be present.
    assert!(curl.contains("-d '"));
}

// ---------------------------------------------------------------------------
// T3: ResponseView wiring
// ---------------------------------------------------------------------------

#[test]
fn response_view_wiring() {
    let mut view = ResponseView::new();
    assert!(view.is_empty());

    let headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("x-request-id".to_string(), "xyz-123".to_string()),
    ];
    let body = b"hello world".to_vec();
    view.load_response(200, headers.clone(), body.clone(), 55);

    // header_lines() must include the HTTP status line and all headers.
    let header_lines = view.header_lines();
    assert!(!header_lines.is_empty());
    assert_eq!(header_lines[0], "HTTP/1.1 200 OK");
    assert!(header_lines.iter().any(|l| l.contains("content-type")));
    assert!(header_lines.iter().any(|l| l.contains("x-request-id")));

    // body_lines() in Raw mode returns the text content.
    let body_lines = view.body_lines();
    assert!(!body_lines.is_empty());
    assert!(body_lines[0].contains("hello world"));

    // toggle_mode() cycles Raw → Hex → Pretty → Raw.
    use aegis_proxy_tui::widgets::hex_view::BodyViewMode;
    assert_eq!(view.mode(), BodyViewMode::Raw);
    view.toggle_mode();
    assert_eq!(view.mode(), BodyViewMode::Hex);
    // In Hex mode body_lines() must produce hex dump lines.
    let hex_lines = view.body_lines();
    assert!(!hex_lines.is_empty());
    assert!(hex_lines[0].contains("68 65 6c 6c 6f"), "expected hex dump");

    view.toggle_mode();
    assert_eq!(view.mode(), BodyViewMode::Pretty);
    view.toggle_mode();
    assert_eq!(view.mode(), BodyViewMode::Raw);
}

// ---------------------------------------------------------------------------
// T4: RepeaterView wiring
// ---------------------------------------------------------------------------

#[test]
fn repeater_view_wiring() {
    let exchange = make_exchange(10, "GET", "http://localhost/api/items", 200, b"items");
    let mut view = RepeaterView::new();
    view.load_exchange(&exchange);

    // Record two responses.
    view.record_response(
        200,
        vec![("x-ver".to_string(), "1".to_string())],
        b"first".to_vec(),
        10,
    );
    view.record_response(
        404,
        vec![("x-ver".to_string(), "2".to_string())],
        b"not found".to_vec(),
        15,
    );

    // history_len() must equal two.
    assert_eq!(view.history_len(), 2);
    // Most recent entry is at index 0; navigate_history(-1) moves to older.
    assert_eq!(view.history_index, 0);
    view.navigate_history(-1);
    assert_eq!(view.history_index, 1);
    view.navigate_history(1);
    assert_eq!(view.history_index, 0);

    // diff_with_original compares original (200) vs latest (404) — status changed.
    view.diff_with_original();
    assert!(view.show_diff);
    let diff = view.diff_view.diff.as_ref().expect("diff must be set");
    assert!(diff.status_changed);
    assert_eq!(diff.old_status, 200);
    assert_eq!(diff.new_status, 404);
}

// ---------------------------------------------------------------------------
// T5: IntruderView wiring
// ---------------------------------------------------------------------------

#[test]
fn intruder_view_wiring() {
    let exchange = make_exchange(
        20,
        "GET",
        "http://localhost/search?q=§FUZZ§",
        200,
        b"results",
    );
    let mut view = IntruderView::new();

    view.load_exchange(&exchange);
    assert!(view.template.is_some());

    view.add_position("§FUZZ§".to_string());
    assert_eq!(view.position_count(), 1);

    view.start_attack();
    assert!(view.running);
    assert_eq!(view.result_count(), 0);

    // Add two results: one match, one error.
    let match_result = PipelineIntruderResult {
        payload: vec!["<script>".to_string()],
        status_code: 200,
        body_length: 100,
        duration_ms: 5,
        response_body: b"ok".to_vec(),
        grep_match_results: vec!["XSS".to_string()],
        grep_extract_results: vec![],
    };
    let error_result = PipelineIntruderResult {
        payload: vec!["' OR 1=1--".to_string()],
        status_code: 0,
        body_length: 0,
        duration_ms: 1,
        response_body: vec![],
        grep_match_results: vec![],
        grep_extract_results: vec![],
    };
    view.add_result(match_result);
    view.add_result(error_result);

    let stats = view.stats();
    assert_eq!(stats.total, 2);
    assert_eq!(stats.completed, 2);
    assert_eq!(stats.matches, 1);
    assert_eq!(stats.errors, 1);
}

// ---------------------------------------------------------------------------
// T6: ScopeView wiring
// ---------------------------------------------------------------------------

#[test]
fn scope_view_wiring() {
    let mut view = ScopeView::new();

    // Add include and exclude rules.
    let id1 = view
        .add_rule("http://localhost/.*", true)
        .expect("valid include pattern");
    let id2 = view
        .add_rule(".*/admin/.*", false)
        .expect("valid exclude pattern");

    assert_eq!(view.rule_count(), 2);
    assert_eq!(view.table.rows.len(), 2);

    // test_url() delegates correctly to the underlying engine.
    assert!(view.test_url("http://localhost/api/users"));
    assert!(!view.test_url("http://localhost/admin/panel"));

    // Table rows must reflect rule ids and types.
    let rows = &view.table.rows;
    assert_eq!(rows[0][0], id1.to_string());
    assert_eq!(rows[0][1], "Include");
    assert_eq!(rows[1][0], id2.to_string());
    assert_eq!(rows[1][1], "Exclude");
}

// ---------------------------------------------------------------------------
// T7: PayloadsView wiring
// ---------------------------------------------------------------------------

#[test]
fn payloads_view_wiring() {
    let mut view = PayloadsView::new();

    let records = vec![
        PayloadListRecord {
            id: 1,
            name: "sqli".to_string(),
            source: "manual".to_string(),
            entries: serde_json::to_string(&vec!["' OR 1=1--", "'; DROP TABLE--"]).unwrap(),
        },
        PayloadListRecord {
            id: 2,
            name: "xss".to_string(),
            source: "builtin".to_string(),
            entries: serde_json::to_string(&vec!["<script>alert(1)</script>", "<img src=x>"])
                .unwrap(),
        },
    ];
    view.load_lists(records);

    assert_eq!(view.list_count(), 2);
    // Default selection is 0 (sqli list).
    let preview = view.preview_entries(10);
    assert_eq!(preview.len(), 2);
    assert!(preview[0].contains("OR 1=1"));

    // Move to next list and preview xss entries.
    view.select_next();
    assert_eq!(view.selected, 1);
    let xss_preview = view.preview_entries(1);
    assert_eq!(xss_preview.len(), 1);
    assert!(xss_preview[0].contains("<script>"));
}

// ---------------------------------------------------------------------------
// T8: ComparerView wiring
// ---------------------------------------------------------------------------

#[test]
fn comparer_view_wiring() {
    let left = make_exchange(30, "GET", "http://localhost/api/v1/thing", 200, b"old body");
    let right = make_exchange(31, "GET", "http://localhost/api/v1/thing", 404, b"new body");

    let mut view = ComparerView::new();
    assert!(!view.has_both_sides());

    view.set_left(&left);
    view.set_right(&right);
    assert!(view.has_both_sides());

    view.compute_and_store_diff();

    // The diff widget must have detected the status change.
    let diff = view.diff_view.diff.as_ref().expect("diff must be set");
    assert!(diff.status_changed);
    assert_eq!(diff.old_status, 200);
    assert_eq!(diff.new_status, 404);

    // has_changes() delegates to diff_view.
    assert!(view.diff_view.has_changes() || diff.status_changed);

    // summary() must be non-empty after diff is computed.
    let summary = view.summary();
    assert!(!summary.is_empty());
    assert!(summary.iter().any(|l| l.contains("404")));
}

// ---------------------------------------------------------------------------
// T9: graph_import wiring
// ---------------------------------------------------------------------------

#[test]
fn graph_import_wiring() {
    let _tmp = TempDir::new().expect("tempdir");
    let db_file = _tmp.path().join("test_graph.json");

    // Build a graph with two Endpoint nodes.
    let graph = KnowledgeGraph::new();
    let ops = vec![
        OperationLogEntry {
            sequence_number: 0,
            module: ModuleIdentifier::Enumeration,
            operation: GraphOperation::AddNode {
                node_type: NodeType::Endpoint,
                properties: vec![
                    ("path".to_string(), "/api/users".to_string()),
                    ("method".to_string(), "GET".to_string()),
                ],
            },
            timestamp_unix_ms: 0,
        },
        OperationLogEntry {
            sequence_number: 1,
            module: ModuleIdentifier::Enumeration,
            operation: GraphOperation::AddNode {
                node_type: NodeType::Endpoint,
                properties: vec![
                    ("path".to_string(), "/api/admin".to_string()),
                    ("method".to_string(), "POST".to_string()),
                ],
            },
            timestamp_unix_ms: 0,
        },
    ];
    graph.apply_operations(&ops).expect("apply ops");

    let metadata = GraphMetadata {
        scan_timestamp_unix_ms: 0,
        target_url: "http://localhost".to_string(),
        aegis_version: "test".to_string(),
        scan_count: 0,
    };
    graph.save_to_file(&db_file, &metadata).expect("save graph");

    // Import into a fresh ScopeEngine.
    let mut scope = ScopeEngine::new();
    let result = import_from_graph(&db_file, &mut scope).expect("import");

    assert_eq!(result.endpoints_found, 2);
    assert_eq!(result.scope_rules_added, 2);
    assert_eq!(result.saved_requests_created, 0);

    // The scope engine must now include both paths.
    assert!(scope.is_in_scope("http://localhost/api/users"));
    assert!(scope.is_in_scope("http://localhost/api/admin"));
}

// ---------------------------------------------------------------------------
// T10: full pipeline — real proxy → load into ProxyLogView
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_pipeline_view_to_proxy() {
    use axum::{Router, routing::get};

    // Spin up a trivial target server.
    let app = Router::new().route("/data", get(|| async { "ok" }));
    let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind target");
    let target_addr = target_listener.local_addr().expect("target addr");
    tokio::spawn(async move {
        axum::serve(target_listener, app)
            .await
            .expect("target serve");
    });

    // Start the recording proxy.
    let config = ProxyConfig::default().with_listen_addr(([127, 0, 0, 1], 0).into());
    let proxy = start_proxy(config).await.expect("start proxy");
    let proxy_addr = proxy.listen_addr();

    // Send two requests through the proxy.
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}")).expect("proxy url"))
        .build()
        .expect("build client");

    for _ in 0..2 {
        let resp = client
            .get(format!("http://{target_addr}/data"))
            .send()
            .await
            .expect("send request");
        assert_eq!(resp.status(), 200);
    }

    // Give the proxy a moment to record.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Collect exchanges from the proxy and load into the view.
    let exchanges = proxy.exchanges().await;
    assert_eq!(exchanges.len(), 2, "proxy must have recorded 2 exchanges");

    let mut view = ProxyLogView::new();
    view.load_exchanges(exchanges);
    assert_eq!(view.exchange_count(), 2);
    assert_eq!(view.table.rows.len(), 2);

    // Both rows must show GET method.
    assert!(view.table.rows.iter().all(|row| row[1] == "GET"));

    proxy.shutdown().await;
}
