use super::*;
use std::collections::HashMap;

fn make_exchange(
    method: &str,
    path: &str,
    query: &[(&str, &str)],
    req_headers: &[(&str, &str)],
    req_body: Option<&str>,
    status: u16,
    resp_body: Option<&str>,
) -> ObservedExchange {
    ObservedExchange {
        request: ObservedRequest {
            method: method.to_string(),
            path: path.to_string(),
            query_params: query
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            headers: req_headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: req_body.map(String::from),
            content_type: req_body.map(|_| "application/json".to_string()),
        },
        response: ObservedResponse {
            status_code: status,
            headers: HashMap::new(),
            body: resp_body.map(String::from),
            content_type: Some("application/json".to_string()),
        },
    }
}

#[test]
fn infer_type_integer() {
    assert_eq!(infer_type("123"), InferredType::Integer);
    assert_eq!(infer_type("0"), InferredType::Integer);
    assert_eq!(infer_type("-42"), InferredType::Integer);
}

#[test]
fn infer_type_float() {
    assert_eq!(infer_type("3.14"), InferredType::Float);
    assert_eq!(infer_type("-0.5"), InferredType::Float);
}

#[test]
fn infer_type_uuid() {
    assert_eq!(
        infer_type("550e8400-e29b-41d4-a716-446655440000"),
        InferredType::Uuid
    );
}

#[test]
fn infer_type_email() {
    assert_eq!(infer_type("user@example.com"), InferredType::Email);
}

#[test]
fn infer_type_date() {
    assert_eq!(infer_type("2024-01-15"), InferredType::Date);
}

#[test]
fn infer_type_datetime() {
    assert_eq!(infer_type("2024-01-15T10:30:00Z"), InferredType::DateTime);
}

#[test]
fn infer_type_boolean() {
    assert_eq!(infer_type("true"), InferredType::Boolean);
    assert_eq!(infer_type("false"), InferredType::Boolean);
}

#[test]
fn infer_type_slug() {
    assert_eq!(infer_type("my-awesome-post"), InferredType::Slug);
    assert_eq!(infer_type("hello-world-123"), InferredType::Slug);
}

#[test]
fn infer_type_hex() {
    assert_eq!(infer_type("a1b2c3d4e5f6a7b8c9d0"), InferredType::HexString);
}

#[test]
fn infer_type_jwt() {
    assert_eq!(
        infer_type("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature-here"),
        InferredType::JwtToken
    );
}

#[test]
fn infer_type_string_fallback() {
    assert_eq!(infer_type("hello world"), InferredType::String);
    assert_eq!(infer_type(""), InferredType::String);
}

#[test]
fn infer_type_display() {
    assert_eq!(InferredType::Integer.to_string(), "integer");
    assert_eq!(InferredType::Uuid.to_string(), "uuid");
    assert_eq!(InferredType::JwtToken.to_string(), "jwt");
}

#[test]
fn detect_auth_bearer() {
    let mut headers = HashMap::new();
    headers.insert("Authorization".to_string(), "Bearer eyJ...".to_string());
    assert_eq!(detect_auth_type(&headers), Some(AuthType::BearerToken));
}

#[test]
fn detect_auth_basic() {
    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        "Basic dXNlcjpwYXNz".to_string(),
    );
    assert_eq!(detect_auth_type(&headers), Some(AuthType::BasicAuth));
}

#[test]
fn detect_auth_api_key() {
    let mut headers = HashMap::new();
    headers.insert("X-API-Key".to_string(), "abc123".to_string());
    assert_eq!(detect_auth_type(&headers), Some(AuthType::ApiKey));
}

#[test]
fn detect_auth_cookie() {
    let mut headers = HashMap::new();
    headers.insert(
        "Cookie".to_string(),
        "session=abc123; other=val".to_string(),
    );
    assert_eq!(detect_auth_type(&headers), Some(AuthType::Cookie));
}

#[test]
fn detect_auth_none() {
    let headers = HashMap::new();
    assert_eq!(detect_auth_type(&headers), None);
}

#[test]
fn auth_type_display() {
    assert_eq!(AuthType::BearerToken.to_string(), "Bearer Token");
    assert_eq!(AuthType::OAuth2.to_string(), "OAuth 2.0");
}

#[test]
fn infer_path_templates_simple() {
    let paths = vec![
        "/api/users/1".to_string(),
        "/api/users/2".to_string(),
        "/api/users/3".to_string(),
    ];
    let templates = infer_path_templates(&paths);
    assert_eq!(templates.len(), 1);
    assert!(templates[0].template.contains("{"));
    assert_eq!(templates[0].observed_count, 3);
}

#[test]
fn infer_path_templates_mixed() {
    let paths = vec![
        "/api/users/1".to_string(),
        "/api/users/2".to_string(),
        "/api/products/10".to_string(),
        "/api/products/20".to_string(),
    ];
    let templates = infer_path_templates(&paths);
    assert_eq!(templates.len(), 2);
}

#[test]
fn infer_path_templates_uuid() {
    let paths = vec![
        "/api/items/550e8400-e29b-41d4-a716-446655440000".to_string(),
        "/api/items/6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string(),
    ];
    let templates = infer_path_templates(&paths);
    assert_eq!(templates.len(), 1);
    assert!(templates[0].template.contains("{"));
}

#[test]
fn infer_path_templates_no_variables() {
    let paths = vec!["/api/health".to_string(), "/api/health".to_string()];
    let templates = infer_path_templates(&paths);
    assert_eq!(templates.len(), 1);
    assert!(!templates[0].template.contains("{"));
}

#[test]
fn extract_json_fields_simple() {
    let json = r#"{"name": "John", "age": 30, "active": true}"#;
    let fields = extract_json_fields(json);
    assert_eq!(fields.len(), 3);
    assert!(fields.iter().any(|f| f.name == "name"));
    assert!(
        fields
            .iter()
            .any(|f| f.name == "age" && f.inferred_type == InferredType::Integer)
    );
    assert!(
        fields
            .iter()
            .any(|f| f.name == "active" && f.inferred_type == InferredType::Boolean)
    );
}

#[test]
fn extract_json_fields_nullable() {
    let json = r#"{"value": null}"#;
    let fields = extract_json_fields(json);
    assert_eq!(fields.len(), 1);
    assert!(fields[0].nullable);
}

#[test]
fn extract_json_fields_array() {
    let json = r#"{"items": [1, 2, 3]}"#;
    let fields = extract_json_fields(json);
    assert_eq!(fields.len(), 1);
    assert!(fields[0].is_array);
}

#[test]
fn extract_json_fields_nested() {
    let json = r#"{"user": {"name": "John", "age": 30}}"#;
    let fields = extract_json_fields(json);
    assert_eq!(fields.len(), 1);
    assert!(!fields[0].nested_fields.is_empty());
}

#[test]
fn extract_json_fields_empty() {
    let fields = extract_json_fields("{}");
    assert!(fields.is_empty());
}

#[test]
fn extract_json_fields_not_json() {
    let fields = extract_json_fields("not json");
    assert!(fields.is_empty());
}

#[test]
fn extract_json_fields_string_types() {
    let json = r#"{"email": "user@test.com", "id": "550e8400-e29b-41d4-a716-446655440000"}"#;
    let fields = extract_json_fields(json);
    assert_eq!(fields.len(), 2);
    let email_field = fields.iter().find(|f| f.name == "email").unwrap();
    assert_eq!(email_field.inferred_type, InferredType::Email);
    let id_field = fields.iter().find(|f| f.name == "id").unwrap();
    assert_eq!(id_field.inferred_type, InferredType::Uuid);
}

#[test]
fn relationship_type_display() {
    assert_eq!(RelationType::ParentChild.to_string(), "parent→child");
    assert_eq!(RelationType::SiblingCrud.to_string(), "CRUD siblings");
}

#[test]
fn detect_relationships_parent_child() {
    let endpoints = vec![
        InferredEndpoint {
            method: "GET".into(),
            path_template: InferredPathTemplate {
                template: "/api/users".into(),
                segments: vec![
                    PathSegment::Literal("api".into()),
                    PathSegment::Literal("users".into()),
                ],
                observed_count: 1,
                example_paths: vec!["/api/users".into()],
            },
            query_params: vec![],
            request_body_fields: vec![],
            response_body_fields: vec![],
            requires_auth: false,
            auth_type: None,
            response_codes: vec![200],
            content_types: vec!["application/json".into()],
        },
        InferredEndpoint {
            method: "GET".into(),
            path_template: InferredPathTemplate {
                template: "/api/users/{user_id}".into(),
                segments: vec![],
                observed_count: 1,
                example_paths: vec![],
            },
            query_params: vec![],
            request_body_fields: vec![],
            response_body_fields: vec![],
            requires_auth: false,
            auth_type: None,
            response_codes: vec![200],
            content_types: vec![],
        },
    ];
    let rels = detect_relationships(&endpoints);
    assert!(!rels.is_empty());
    assert!(
        rels.iter()
            .any(|r| r.relationship_type == RelationType::ParentChild)
    );
}

#[test]
fn detect_relationships_crud_siblings() {
    let make_ep = |method: &str| InferredEndpoint {
        method: method.into(),
        path_template: InferredPathTemplate {
            template: "/api/users".into(),
            segments: vec![],
            observed_count: 1,
            example_paths: vec![],
        },
        query_params: vec![],
        request_body_fields: vec![],
        response_body_fields: vec![],
        requires_auth: false,
        auth_type: None,
        response_codes: vec![200],
        content_types: vec![],
    };
    let endpoints = vec![make_ep("GET"), make_ep("POST")];
    let rels = detect_relationships(&endpoints);
    assert!(
        rels.iter()
            .any(|r| r.relationship_type == RelationType::SiblingCrud)
    );
}

#[test]
fn infer_schema_basic() {
    let exchanges = vec![
        make_exchange(
            "GET",
            "/api/users/1",
            &[],
            &[],
            None,
            200,
            Some(r#"{"id": 1, "name": "Alice"}"#),
        ),
        make_exchange(
            "GET",
            "/api/users/2",
            &[],
            &[],
            None,
            200,
            Some(r#"{"id": 2, "name": "Bob"}"#),
        ),
        make_exchange(
            "POST",
            "/api/users",
            &[],
            &[("Authorization", "Bearer token123")],
            Some(r#"{"name": "Charlie"}"#),
            201,
            None,
        ),
    ];
    let schema = infer_schema(&exchanges);
    assert!(schema.endpoints.len() >= 2);
    assert_eq!(schema.total_exchanges_analyzed, 3);
    assert!(!schema.summary.is_empty());
}

#[test]
fn infer_schema_detects_auth() {
    let exchanges = vec![make_exchange(
        "GET",
        "/api/secret",
        &[],
        &[("Authorization", "Bearer abc")],
        None,
        200,
        None,
    )];
    let schema = infer_schema(&exchanges);
    assert!(!schema.auth_types_detected.is_empty());
    assert!(schema.endpoints.iter().any(|e| e.requires_auth));
}

#[test]
fn infer_schema_query_params() {
    let exchanges = vec![
        make_exchange(
            "GET",
            "/api/search",
            &[("q", "hello"), ("page", "1")],
            &[],
            None,
            200,
            None,
        ),
        make_exchange(
            "GET",
            "/api/search",
            &[("q", "world"), ("page", "2")],
            &[],
            None,
            200,
            None,
        ),
    ];
    let schema = infer_schema(&exchanges);
    let search_ep = schema
        .endpoints
        .iter()
        .find(|e| e.path_template.template.contains("search"))
        .unwrap();
    assert!(search_ep.query_params.len() >= 2);
    let q = search_ep
        .query_params
        .iter()
        .find(|p| p.name == "q")
        .unwrap();
    assert_eq!(q.inferred_type, InferredType::String);
    let page = search_ep
        .query_params
        .iter()
        .find(|p| p.name == "page")
        .unwrap();
    assert_eq!(page.inferred_type, InferredType::Integer);
}

#[test]
fn infer_schema_response_codes() {
    let exchanges = vec![
        make_exchange("GET", "/api/items/1", &[], &[], None, 200, None),
        make_exchange("GET", "/api/items/999", &[], &[], None, 404, None),
    ];
    let schema = infer_schema(&exchanges);
    let ep = schema.endpoints.iter().find(|e| e.method == "GET").unwrap();
    assert!(ep.response_codes.contains(&200));
    assert!(ep.response_codes.contains(&404));
}

#[test]
fn infer_schema_empty() {
    let schema = infer_schema(&[]);
    assert!(schema.endpoints.is_empty());
    assert_eq!(schema.total_exchanges_analyzed, 0);
}

#[test]
fn path_template_display() {
    let t = InferredPathTemplate {
        template: "/api/users/{id}".into(),
        segments: vec![],
        observed_count: 5,
        example_paths: vec![],
    };
    assert_eq!(t.to_string(), "/api/users/{id} (5x)");
}

#[test]
fn inferred_param_type_inference() {
    let exchanges = vec![
        make_exchange("GET", "/api/data", &[("limit", "10")], &[], None, 200, None),
        make_exchange("GET", "/api/data", &[("limit", "20")], &[], None, 200, None),
    ];
    let schema = infer_schema(&exchanges);
    let ep = &schema.endpoints[0];
    let limit = ep.query_params.iter().find(|p| p.name == "limit").unwrap();
    assert_eq!(limit.inferred_type, InferredType::Integer);
    assert!(limit.required);
}

#[test]
fn path_template_param_naming() {
    let paths = vec![
        "/api/users/1/orders/100".to_string(),
        "/api/users/2/orders/200".to_string(),
    ];
    let templates = infer_path_templates(&paths);
    assert_eq!(templates.len(), 1);
    let t = &templates[0];
    assert!(t.template.contains("{"));
    let param_segments: Vec<&PathSegment> = t
        .segments
        .iter()
        .filter(|s| matches!(s, PathSegment::Parameter { .. }))
        .collect();
    assert_eq!(param_segments.len(), 2);
}
