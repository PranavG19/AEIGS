use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier};

use crate::types::RecordedExchange;

use super::*;

fn make_exchange(
    method: &str,
    url: &str,
    req_headers: Vec<(String, String)>,
    req_body: &[u8],
    status: u16,
    resp_headers: Vec<(String, String)>,
) -> RecordedExchange {
    RecordedExchange {
        id: 1,
        request_method: method.to_string(),
        request_url: url.to_string(),
        request_headers: req_headers,
        request_body: req_body.to_vec(),
        response_status: status,
        response_headers: resp_headers,
        response_body: Vec::new(),
        timestamp_ms: 1000,
        duration_ms: 50,
        in_scope: true,
        tags: vec![],
    }
}

#[test]
fn get_with_query_params() {
    let exchange = make_exchange(
        "GET",
        "http://localhost:3000/api/users?page=1&limit=10",
        vec![],
        b"",
        200,
        vec![],
    );
    let result = sync_exchanges_to_graph(&[exchange]);

    assert_eq!(result.endpoints_added, 1);
    assert_eq!(result.parameters_discovered, 2);
    assert_eq!(result.operations.len(), 1);

    let op = &result.operations[0];
    assert_eq!(op.sequence_number, 1);
    assert_eq!(op.module, ModuleIdentifier::Proxy);

    if let GraphOperation::AddNode {
        node_type,
        properties,
    } = &op.operation
    {
        assert_eq!(*node_type, NodeType::Endpoint);
        let props: std::collections::HashMap<&str, &str> = properties
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(props["path"], "/api/users");
        assert_eq!(props["method"], "GET");
        assert_eq!(props["discovery_source"], "proxy");
        assert!(props.contains_key("parameters"));
    } else {
        panic!("expected AddNode operation");
    }
}

#[test]
fn post_with_json_body() {
    let body = br#"{"username": "admin", "password": "secret"}"#;
    let exchange = make_exchange(
        "POST",
        "http://localhost:3000/api/login",
        vec![("Content-Type".to_string(), "application/json".to_string())],
        body,
        200,
        vec![],
    );
    let result = sync_exchanges_to_graph(&[exchange]);

    assert_eq!(result.endpoints_added, 1);
    assert_eq!(result.parameters_discovered, 2);

    let params = extract_parameters_from_exchange(&RecordedExchange {
        id: 1,
        request_method: "POST".to_string(),
        request_url: "http://localhost:3000/api/login".to_string(),
        request_headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        request_body: body.to_vec(),
        response_status: 200,
        response_headers: vec![],
        response_body: Vec::new(),
        timestamp_ms: 1000,
        duration_ms: 50,
        in_scope: true,
        tags: vec![],
    });
    assert_eq!(params.len(), 2);
    assert!(params.iter().any(|(k, v)| k == "username" && v == "admin"));
    assert!(params.iter().any(|(k, v)| k == "password" && v == "secret"));
}

#[test]
fn post_with_form_body() {
    let body = b"email=test%40example.com&action=subscribe";
    let exchange = make_exchange(
        "POST",
        "http://localhost:3000/subscribe",
        vec![(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )],
        body,
        302,
        vec![],
    );
    let result = sync_exchanges_to_graph(&[exchange]);

    assert_eq!(result.endpoints_added, 1);
    assert_eq!(result.parameters_discovered, 2);
}

#[test]
fn deduplication_same_path_method() {
    let ex1 = make_exchange(
        "GET",
        "http://localhost:3000/api/items?page=1",
        vec![],
        b"",
        200,
        vec![],
    );
    let ex2 = make_exchange(
        "GET",
        "http://localhost:3000/api/items?page=2",
        vec![],
        b"",
        200,
        vec![],
    );
    let result = sync_exchanges_to_graph(&[ex1, ex2]);

    assert_eq!(result.endpoints_added, 1);
    assert_eq!(result.operations.len(), 1);
}

#[test]
fn different_methods_not_deduplicated() {
    let get = make_exchange(
        "GET",
        "http://localhost:3000/api/items",
        vec![],
        b"",
        200,
        vec![],
    );
    let post = make_exchange(
        "POST",
        "http://localhost:3000/api/items",
        vec![],
        b"",
        201,
        vec![],
    );
    let result = sync_exchanges_to_graph(&[get, post]);

    assert_eq!(result.endpoints_added, 2);
    assert_eq!(result.operations.len(), 2);
}

#[test]
fn empty_exchanges() {
    let result = sync_exchanges_to_graph(&[]);

    assert_eq!(result.endpoints_added, 0);
    assert_eq!(result.parameters_discovered, 0);
    assert!(result.operations.is_empty());
}

#[test]
fn response_metadata_extracted() {
    let exchange = make_exchange(
        "GET",
        "http://localhost:3000/",
        vec![],
        b"",
        200,
        vec![
            ("Server".to_string(), "nginx/1.21".to_string()),
            ("X-Powered-By".to_string(), "Express".to_string()),
        ],
    );
    let result = sync_exchanges_to_graph(&[exchange]);

    if let GraphOperation::AddNode { properties, .. } = &result.operations[0].operation {
        let props: std::collections::HashMap<&str, &str> = properties
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(props["server"], "nginx/1.21");
        assert_eq!(props["technology"], "Express");
    } else {
        panic!("expected AddNode");
    }
}

#[test]
fn extract_params_combined_query_and_json_body() {
    let body = br#"{"action": "create"}"#;
    let exchange = make_exchange(
        "POST",
        "http://localhost:3000/api/items?format=json",
        vec![("Content-Type".to_string(), "application/json".to_string())],
        body,
        201,
        vec![],
    );
    let params = extract_parameters_from_exchange(&exchange);

    assert_eq!(params.len(), 2);
    assert!(params.iter().any(|(k, _)| k == "format"));
    assert!(params.iter().any(|(k, _)| k == "action"));
}

#[test]
fn json_body_with_nested_values() {
    let body = br#"{"name": "test", "count": 42, "items": [1,2], "meta": {"x": 1}}"#;
    let exchange = make_exchange(
        "POST",
        "http://localhost:3000/api/data",
        vec![("Content-Type".to_string(), "application/json".to_string())],
        body,
        200,
        vec![],
    );
    let params = extract_parameters_from_exchange(&exchange);

    assert_eq!(params.len(), 4);
    assert!(params.iter().any(|(k, v)| k == "name" && v == "test"));
    assert!(params.iter().any(|(k, v)| k == "count" && v == "42"));
    assert!(params.iter().any(|(k, v)| k == "items" && v == "[array]"));
    assert!(params.iter().any(|(k, v)| k == "meta" && v == "{object}"));
}

#[test]
fn no_body_params_without_content_type() {
    let exchange = make_exchange(
        "POST",
        "http://localhost:3000/api/data",
        vec![],
        b"some raw data",
        200,
        vec![],
    );
    let params = extract_parameters_from_exchange(&exchange);

    assert!(params.is_empty());
}

#[test]
fn sequence_numbers_are_sequential() {
    let exchanges: Vec<RecordedExchange> = (0..5)
        .map(|i| {
            make_exchange(
                "GET",
                &format!("http://localhost:3000/path/{i}"),
                vec![],
                b"",
                200,
                vec![],
            )
        })
        .collect();
    let result = sync_exchanges_to_graph(&exchanges);

    assert_eq!(result.operations.len(), 5);
    for (i, op) in result.operations.iter().enumerate() {
        assert_eq!(op.sequence_number, i as u64 + 1);
    }
}
