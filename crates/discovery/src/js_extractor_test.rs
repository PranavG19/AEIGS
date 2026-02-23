use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier};

use crate::graph_ops::extracted_endpoints_to_operations;
use crate::js_extractor::{ExtractedEndpoint, JsEndpointExtractor};

fn extractor() -> JsEndpointExtractor {
    JsEndpointExtractor::new("http://localhost:3000")
}

#[test]
fn fetch_call_detected() {
    let js = r#"const data = fetch("/api/users").then(r => r.json());"#;
    let results = extractor().extract_from_js(js);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "http://localhost:3000/api/users");
    assert!(results[0].method.is_none());
    assert_eq!(results[0].source_pattern, "fetch");
}

#[test]
fn fetch_with_absolute_url() {
    let js = r#"fetch("http://localhost:3000/api/items")"#;
    let results = extractor().extract_from_js(js);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "http://localhost:3000/api/items");
}

#[test]
fn axios_get_with_method() {
    let js = r#"axios.get("/api/products")"#;
    let results = extractor().extract_from_js(js);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "http://localhost:3000/api/products");
    assert_eq!(results[0].method.as_deref(), Some("GET"));
    assert_eq!(results[0].source_pattern, "axios");
}

#[test]
fn axios_post_with_method() {
    let js = r#"axios.post("/api/orders", body)"#;
    let results = extractor().extract_from_js(js);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].method.as_deref(), Some("POST"));
}

#[test]
fn axios_delete_with_method() {
    let js = r#"axios.delete("/api/users/123")"#;
    let results = extractor().extract_from_js(js);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].method.as_deref(), Some("DELETE"));
}

#[test]
fn jquery_ajax_detected() {
    let js = r#"$.ajax({url: "/api/search", method: "POST"})"#;
    let results = extractor().extract_from_js(js);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "http://localhost:3000/api/search");
    assert_eq!(results[0].source_pattern, "jquery_ajax");
}

#[test]
fn xmlhttprequest_with_method() {
    let js = r#"xhr.open("POST", "/api/submit")"#;
    let results = extractor().extract_from_js(js);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "http://localhost:3000/api/submit");
    assert_eq!(results[0].method.as_deref(), Some("POST"));
    assert_eq!(results[0].source_pattern, "xmlhttprequest");
}

#[test]
fn xmlhttprequest_get() {
    let js = r#"xhr.open("GET", "/api/data")"#;
    let results = extractor().extract_from_js(js);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].method.as_deref(), Some("GET"));
}

#[test]
fn route_definition_app_get() {
    let js = r#"app.get("/users/:id", handler)"#;
    let results = extractor().extract_from_js(js);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "http://localhost:3000/users/:id");
    assert_eq!(results[0].method.as_deref(), Some("GET"));
    assert_eq!(results[0].source_pattern, "route_definition");
}

#[test]
fn route_definition_router_post() {
    let js = r#"router.post("/auth/login", middleware, controller)"#;
    let results = extractor().extract_from_js(js);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].method.as_deref(), Some("POST"));
}

#[test]
fn full_url_same_host() {
    let js = r#"const url = "http://localhost:3000/api/v2/resource";"#;
    let results = extractor().extract_from_js(js);
    assert!(!results.is_empty());
    assert!(results.iter().any(|e| e.url.contains("/api/v2/resource")));
}

#[test]
fn full_url_different_host_filtered() {
    let js = r#"const cdn = "https://cdn.example.com/assets/bundle.js";"#;
    let results = extractor().extract_from_js(js);
    assert!(
        results.is_empty(),
        "URLs from different hosts should be filtered"
    );
}

#[test]
fn api_path_literal_detected() {
    let js = r#"const endpoint = "/api/v1/health";"#;
    let results = extractor().extract_from_js(js);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "http://localhost:3000/api/v1/health");
    assert_eq!(results[0].source_pattern, "api_path_literal");
}

#[test]
fn api_path_literal_with_single_quotes() {
    let js = "const endpoint = '/api/users/profile';";
    let results = extractor().extract_from_js(js);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "http://localhost:3000/api/users/profile");
}

#[test]
fn query_string_stripped() {
    let js = r#"fetch("/api/search?q=test&page=1")"#;
    let results = extractor().extract_from_js(js);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "http://localhost:3000/api/search");
}

#[test]
fn fragment_stripped() {
    let js = r#"fetch("/api/docs#section")"#;
    let results = extractor().extract_from_js(js);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "http://localhost:3000/api/docs");
}

#[test]
fn duplicate_urls_deduplicated() {
    let js = r#"
        fetch("/api/users");
        axios.get("/api/users");
        const url = "/api/users";
    "#;
    let results = extractor().extract_from_js(js);
    let user_results: Vec<_> = results
        .iter()
        .filter(|e| e.url == "http://localhost:3000/api/users")
        .collect();
    assert_eq!(
        user_results.len(),
        1,
        "duplicate URLs should be deduplicated"
    );
}

#[test]
fn dedup_preserves_first_pattern_match() {
    let js = r#"
        axios.post("/api/items");
        fetch("/api/items");
    "#;
    let results = extractor().extract_from_js(js);
    let item_results: Vec<_> = results
        .iter()
        .filter(|e| e.url == "http://localhost:3000/api/items")
        .collect();
    assert_eq!(item_results.len(), 1);
    assert_eq!(item_results[0].source_pattern, "fetch");
}

#[test]
fn no_false_positives_on_plain_text() {
    let js = r#"
        const name = "hello world";
        const count = 42;
        console.log("nothing to see here");
        var x = {key: "value"};
    "#;
    let results = extractor().extract_from_js(js);
    assert!(results.is_empty(), "plain text should produce no results");
}

#[test]
fn no_false_positives_on_css_imports() {
    let js = r#"
        import "./styles.css";
        require("./components/Button");
    "#;
    let results = extractor().extract_from_js(js);
    assert!(
        results.is_empty(),
        "relative non-API imports should be excluded"
    );
}

#[test]
fn multiple_patterns_in_same_js() {
    let js = r#"
        fetch("/api/users");
        axios.post("/api/orders");
        xhr.open("DELETE", "/api/items/5");
        app.get("/health", handler);
    "#;
    let results = extractor().extract_from_js(js);
    assert!(results.len() >= 4);
}

#[test]
fn trailing_slash_normalized() {
    let ext = JsEndpointExtractor::new("http://localhost:3000/");
    let js = r#"fetch("/api/test")"#;
    let results = ext.extract_from_js(js);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "http://localhost:3000/api/test");
}

#[test]
fn base_url_with_port() {
    let ext = JsEndpointExtractor::new("http://127.0.0.1:8080");
    let js = r#"fetch("/api/data")"#;
    let results = ext.extract_from_js(js);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "http://127.0.0.1:8080/api/data");
}

#[test]
fn empty_js_returns_empty() {
    let results = extractor().extract_from_js("");
    assert!(results.is_empty());
}

#[test]
fn graph_ops_empty_endpoints() {
    let ops = extracted_endpoints_to_operations(&[], 0);
    assert!(ops.is_empty());
}

#[test]
fn graph_ops_single_endpoint_without_method() {
    let endpoints = vec![ExtractedEndpoint {
        url: "http://localhost:3000/api/users".to_string(),
        method: None,
        source_pattern: "fetch".to_string(),
    }];

    let ops = extracted_endpoints_to_operations(&endpoints, 0);
    assert_eq!(ops.len(), 1);

    let entry = &ops[0];
    assert_eq!(entry.sequence_number, 1);
    assert_eq!(entry.module, ModuleIdentifier::Discovery);

    if let GraphOperation::AddNode {
        node_type,
        properties,
    } = &entry.operation
    {
        assert_eq!(*node_type, NodeType::Endpoint);
        let props: std::collections::HashMap<&str, &str> = properties
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(props["path"], "http://localhost:3000/api/users");
        assert_eq!(props["discovery_source"], "javascript_analysis");
        assert!(!props.contains_key("method"));
    } else {
        panic!("expected AddNode operation");
    }
}

#[test]
fn graph_ops_single_endpoint_with_method() {
    let endpoints = vec![ExtractedEndpoint {
        url: "http://localhost:3000/api/orders".to_string(),
        method: Some("POST".to_string()),
        source_pattern: "axios".to_string(),
    }];

    let ops = extracted_endpoints_to_operations(&endpoints, 0);
    assert_eq!(ops.len(), 1);

    if let GraphOperation::AddNode { properties, .. } = &ops[0].operation {
        let props: std::collections::HashMap<&str, &str> = properties
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(props["method"], "POST");
    } else {
        panic!("expected AddNode operation");
    }
}

#[test]
fn graph_ops_sequence_numbers_consecutive() {
    let endpoints = vec![
        ExtractedEndpoint {
            url: "http://localhost:3000/api/a".to_string(),
            method: None,
            source_pattern: "fetch".to_string(),
        },
        ExtractedEndpoint {
            url: "http://localhost:3000/api/b".to_string(),
            method: Some("GET".to_string()),
            source_pattern: "axios".to_string(),
        },
        ExtractedEndpoint {
            url: "http://localhost:3000/api/c".to_string(),
            method: None,
            source_pattern: "api_path_literal".to_string(),
        },
    ];

    let ops = extracted_endpoints_to_operations(&endpoints, 10);
    assert_eq!(ops[0].sequence_number, 11);
    assert_eq!(ops[1].sequence_number, 12);
    assert_eq!(ops[2].sequence_number, 13);
}

#[test]
fn graph_ops_timestamps_nonzero() {
    let endpoints = vec![ExtractedEndpoint {
        url: "http://localhost:3000/api/test".to_string(),
        method: None,
        source_pattern: "fetch".to_string(),
    }];

    let ops = extracted_endpoints_to_operations(&endpoints, 0);
    assert!(ops[0].timestamp_unix_ms > 0);
}
