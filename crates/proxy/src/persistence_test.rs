use super::*;

fn test_db() -> ProxyDb {
    ProxyDb::open_in_memory().expect("open in-memory db")
}

fn sample_exchange() -> RecordedExchange {
    RecordedExchange {
        id: 0,
        request_method: "GET".into(),
        request_url: "http://localhost:3000/api/users".into(),
        request_headers: vec![
            ("Host".into(), "localhost:3000".into()),
            ("Accept".into(), "application/json".into()),
        ],
        request_body: vec![],
        response_status: 200,
        response_headers: vec![("Content-Type".into(), "application/json".into())],
        response_body: b"{\"users\":[]}".to_vec(),
        timestamp_ms: 1700000000000,
        duration_ms: 42,
    }
}

// --- Schema ---

#[test]
fn open_creates_schema_without_error() {
    let _db = test_db();
}

#[test]
fn open_is_idempotent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("proxy.db");
    let _db1 = ProxyDb::open(&path).expect("first open");
    let _db2 = ProxyDb::open(&path).expect("second open");
}

// --- Exchange CRUD ---

#[test]
fn insert_and_retrieve_exchange() {
    let db = test_db();
    let ex = sample_exchange();
    let id = db.insert_exchange(&ex).expect("insert");
    assert!(id > 0);

    let loaded = db.exchange_by_id(id).expect("query").expect("found");
    assert_eq!(loaded.id, id as u64);
    assert_eq!(loaded.request_method, "GET");
    assert_eq!(loaded.request_url, "http://localhost:3000/api/users");
    assert_eq!(loaded.request_headers.len(), 2);
    assert_eq!(loaded.response_status, 200);
    assert_eq!(loaded.response_body, b"{\"users\":[]}");
    assert_eq!(loaded.timestamp_ms, 1700000000000);
    assert_eq!(loaded.duration_ms, 42);
}

#[test]
fn exchange_by_id_returns_none_for_missing() {
    let db = test_db();
    let result = db.exchange_by_id(999).expect("query");
    assert!(result.is_none());
}

#[test]
fn list_exchanges_with_limit_and_offset() {
    let db = test_db();
    for i in 0..5 {
        let mut ex = sample_exchange();
        ex.timestamp_ms = 1700000000000 + i;
        db.insert_exchange(&ex).expect("insert");
    }
    let page1 = db.list_exchanges(3, 0).expect("page1");
    assert_eq!(page1.len(), 3);

    let page2 = db.list_exchanges(3, 3).expect("page2");
    assert_eq!(page2.len(), 2);

    let empty = db.list_exchanges(3, 10).expect("empty");
    assert!(empty.is_empty());
}

#[test]
fn list_exchanges_ordered_by_timestamp_desc() {
    let db = test_db();
    for ts in [100u64, 300, 200] {
        let mut ex = sample_exchange();
        ex.timestamp_ms = ts;
        db.insert_exchange(&ex).expect("insert");
    }
    let all = db.list_exchanges(10, 0).expect("list");
    assert_eq!(all[0].timestamp_ms, 300);
    assert_eq!(all[1].timestamp_ms, 200);
    assert_eq!(all[2].timestamp_ms, 100);
}

#[test]
fn search_exchanges_by_url_pattern() {
    let db = test_db();
    let mut ex1 = sample_exchange();
    ex1.request_url = "http://localhost:3000/api/users".into();
    db.insert_exchange(&ex1).expect("insert");

    let mut ex2 = sample_exchange();
    ex2.request_url = "http://localhost:3000/api/posts".into();
    db.insert_exchange(&ex2).expect("insert");

    let results = db.search_exchanges_by_url("%users%").expect("search");
    assert_eq!(results.len(), 1);
    assert!(results[0].request_url.contains("users"));

    let all = db.search_exchanges_by_url("%api%").expect("search all");
    assert_eq!(all.len(), 2);
}

#[test]
fn filter_exchanges_with_where_clause() {
    let db = test_db();
    let mut ex1 = sample_exchange();
    ex1.request_method = "GET".into();
    db.insert_exchange(&ex1).expect("insert");

    let mut ex2 = sample_exchange();
    ex2.request_method = "POST".into();
    db.insert_exchange(&ex2).expect("insert");

    let gets = db.filter_exchanges("method = 'GET'").expect("filter");
    assert_eq!(gets.len(), 1);
    assert_eq!(gets[0].request_method, "GET");
}

#[test]
fn delete_exchange() {
    let db = test_db();
    let id = db.insert_exchange(&sample_exchange()).expect("insert");
    assert_eq!(db.exchange_count().expect("count"), 1);

    let deleted = db.delete_exchange(id).expect("delete");
    assert!(deleted);
    assert_eq!(db.exchange_count().expect("count"), 0);

    let not_deleted = db.delete_exchange(id).expect("delete again");
    assert!(!not_deleted);
}

#[test]
fn clear_exchanges() {
    let db = test_db();
    for _ in 0..3 {
        db.insert_exchange(&sample_exchange()).expect("insert");
    }
    assert_eq!(db.exchange_count().expect("count"), 3);

    db.clear_exchanges().expect("clear");
    assert_eq!(db.exchange_count().expect("count"), 0);
}

#[test]
fn exchange_count() {
    let db = test_db();
    assert_eq!(db.exchange_count().expect("count"), 0);
    db.insert_exchange(&sample_exchange()).expect("insert");
    assert_eq!(db.exchange_count().expect("count"), 1);
}

#[test]
fn binary_body_round_trip() {
    let db = test_db();
    let binary_body: Vec<u8> = (0..=255).collect();
    let mut ex = sample_exchange();
    ex.request_body = binary_body.clone();
    ex.response_body = binary_body.clone();

    let id = db.insert_exchange(&ex).expect("insert");
    let loaded = db.exchange_by_id(id).expect("query").expect("found");
    assert_eq!(loaded.request_body, binary_body);
    assert_eq!(loaded.response_body, binary_body);
}

// --- Saved Requests ---

#[test]
fn insert_and_retrieve_saved_request() {
    let db = test_db();
    let saved = SavedRequest {
        id: 0,
        name: "Login request".into(),
        method: "POST".into(),
        url: "http://localhost:3000/login".into(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: b"{\"user\":\"admin\"}".to_vec(),
        notes: "Test the login endpoint".into(),
        created_at: 1700000000000,
        exchange_id: None,
    };
    let id = db.insert_saved_request(&saved).expect("insert");
    let loaded = db.saved_request_by_id(id).expect("query").expect("found");
    assert_eq!(loaded.name, "Login request");
    assert_eq!(loaded.method, "POST");
    assert_eq!(loaded.url, "http://localhost:3000/login");
    assert_eq!(loaded.headers.len(), 1);
    assert_eq!(loaded.body, b"{\"user\":\"admin\"}");
    assert_eq!(loaded.notes, "Test the login endpoint");
    assert!(loaded.exchange_id.is_none());
}

#[test]
fn saved_request_with_exchange_id() {
    let db = test_db();
    let eid = db
        .insert_exchange(&sample_exchange())
        .expect("insert exchange");
    let saved = SavedRequest {
        id: 0,
        name: "Bookmarked".into(),
        method: "GET".into(),
        url: "http://localhost:3000/api/users".into(),
        headers: vec![],
        body: vec![],
        notes: String::new(),
        created_at: 1700000000000,
        exchange_id: Some(eid),
    };
    let id = db.insert_saved_request(&saved).expect("insert");
    let loaded = db.saved_request_by_id(id).expect("query").expect("found");
    assert_eq!(loaded.exchange_id, Some(eid));
}

#[test]
fn list_saved_requests() {
    let db = test_db();
    for i in 0..3 {
        let saved = SavedRequest {
            id: 0,
            name: format!("req-{i}"),
            method: "GET".into(),
            url: "http://localhost/".into(),
            headers: vec![],
            body: vec![],
            notes: String::new(),
            created_at: 1700000000000 + i,
            exchange_id: None,
        };
        db.insert_saved_request(&saved).expect("insert");
    }
    let list = db.list_saved_requests().expect("list");
    assert_eq!(list.len(), 3);
}

// --- Intruder Runs ---

#[test]
fn insert_and_retrieve_intruder_run() {
    let db = test_db();
    let run = IntruderRunRecord {
        id: 0,
        name: "SQLi fuzz".into(),
        mode: "Sniper".into(),
        template_json: r#"{"url":"http://localhost/"}"#.into(),
        positions_json: r#"["§param§"]"#.into(),
        concurrency: 10,
        started_at: 1700000000000,
        completed_at: None,
        total_requests: None,
    };
    let id = db.insert_intruder_run(&run).expect("insert");
    let loaded = db.intruder_run_by_id(id).expect("query").expect("found");
    assert_eq!(loaded.name, "SQLi fuzz");
    assert_eq!(loaded.mode, "Sniper");
    assert_eq!(loaded.concurrency, 10);
    assert!(loaded.completed_at.is_none());
    assert!(loaded.total_requests.is_none());
}

#[test]
fn update_intruder_run_completed() {
    let db = test_db();
    let run = IntruderRunRecord {
        id: 0,
        name: "test".into(),
        mode: "BatteringRam".into(),
        template_json: "{}".into(),
        positions_json: "[]".into(),
        concurrency: 5,
        started_at: 1700000000000,
        completed_at: None,
        total_requests: None,
    };
    let id = db.insert_intruder_run(&run).expect("insert");

    db.update_intruder_run_completed(id, 1700000001000, 42)
        .expect("update");
    let loaded = db.intruder_run_by_id(id).expect("query").expect("found");
    assert_eq!(loaded.completed_at, Some(1700000001000));
    assert_eq!(loaded.total_requests, Some(42));
}

// --- Intruder Results ---

#[test]
fn insert_and_query_intruder_results() {
    let db = test_db();
    let run = IntruderRunRecord {
        id: 0,
        name: "run".into(),
        mode: "Sniper".into(),
        template_json: "{}".into(),
        positions_json: "[]".into(),
        concurrency: 1,
        started_at: 100,
        completed_at: None,
        total_requests: None,
    };
    let run_id = db.insert_intruder_run(&run).expect("insert run");

    for i in 0..3 {
        let result = IntruderResultRecord {
            id: 0,
            run_id,
            payload_json: format!(r#"["payload{i}"]"#),
            status_code: 200 + i as u16,
            body_length: 100 + i as u32,
            duration_ms: 10 + i as u64,
            response_body: format!("body-{i}").into_bytes(),
            grep_matches: "[]".into(),
        };
        db.insert_intruder_result(&result).expect("insert result");
    }

    let results = db.intruder_results_for_run(run_id).expect("query");
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].status_code, 200);
    assert_eq!(results[2].response_body, b"body-2");
}

// --- Payload Lists ---

#[test]
fn insert_and_retrieve_payload_list() {
    let db = test_db();
    let pl = PayloadListRecord {
        id: 0,
        name: "sqli-basics".into(),
        source: "manual".into(),
        entries: r#"["' OR 1=1--","admin'--"]"#.into(),
    };
    let id = db.insert_payload_list(&pl).expect("insert");
    let loaded = db
        .payload_list_by_name("sqli-basics")
        .expect("query")
        .expect("found");
    assert_eq!(loaded.id, id);
    assert_eq!(loaded.source, "manual");
    assert!(loaded.entries.contains("OR 1=1"));
}

#[test]
fn payload_list_unique_name() {
    let db = test_db();
    let pl = PayloadListRecord {
        id: 0,
        name: "dup".into(),
        source: "a".into(),
        entries: "[]".into(),
    };
    db.insert_payload_list(&pl).expect("first insert");
    let result = db.insert_payload_list(&pl);
    assert!(result.is_err());
}

#[test]
fn list_payload_lists() {
    let db = test_db();
    for i in 0..3 {
        let pl = PayloadListRecord {
            id: 0,
            name: format!("list-{i}"),
            source: "test".into(),
            entries: "[]".into(),
        };
        db.insert_payload_list(&pl).expect("insert");
    }
    let list = db.list_payload_lists().expect("list");
    assert_eq!(list.len(), 3);
}

#[test]
fn payload_list_by_name_returns_none_for_missing() {
    let db = test_db();
    let result = db.payload_list_by_name("nonexistent").expect("query");
    assert!(result.is_none());
}

// --- Persistence (reopen) ---

#[test]
fn reopen_preserves_data() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("proxy.db");

    {
        let db = ProxyDb::open(&path).expect("open");
        db.insert_exchange(&sample_exchange()).expect("insert");
        let saved = SavedRequest {
            id: 0,
            name: "persist-test".into(),
            method: "GET".into(),
            url: "http://localhost/".into(),
            headers: vec![],
            body: vec![],
            notes: String::new(),
            created_at: 100,
            exchange_id: None,
        };
        db.insert_saved_request(&saved).expect("insert saved");
    }

    {
        let db = ProxyDb::open(&path).expect("reopen");
        assert_eq!(db.exchange_count().expect("count"), 1);
        let saved_list = db.list_saved_requests().expect("list");
        assert_eq!(saved_list.len(), 1);
        assert_eq!(saved_list[0].name, "persist-test");
    }
}

// --- Edge cases ---

#[test]
fn empty_headers_round_trip() {
    let db = test_db();
    let mut ex = sample_exchange();
    ex.request_headers = vec![];
    ex.response_headers = vec![];
    let id = db.insert_exchange(&ex).expect("insert");
    let loaded = db.exchange_by_id(id).expect("query").expect("found");
    assert!(loaded.request_headers.is_empty());
    assert!(loaded.response_headers.is_empty());
}

#[test]
fn exchange_with_in_scope_and_tags() {
    let db = test_db();
    let ex = sample_exchange();
    let id = db.insert_exchange(&ex).expect("insert");
    let loaded = db.exchange_by_id(id).expect("query").expect("found");
    // Default values from schema: in_scope=1, tags='[]'
    // These are stored in DB but not surfaced in RecordedExchange currently.
    // We verify the insert/read cycle works regardless.
    assert_eq!(loaded.request_method, "GET");
}
