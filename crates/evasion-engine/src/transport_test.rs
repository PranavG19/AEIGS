use super::*;
use crate::persona::{JitterDistribution, PersonaId, persona_catalog};
use aegis_protocol::request::{FuzzRequest, ParameterLocation};

#[tokio::test]
async fn send_rejects_non_localhost_url() {
    let mut transport = EvasionTransport::builder().with_timing_seed(0).build();

    let request = FuzzRequest {
        request_id: 100,
        endpoint: "http://example.com/api".to_string(),
        method: "GET".to_string(),
        parameter_name: "q".to_string(),
        parameter_location: ParameterLocation::Query,
        payload: "test".to_string(),
        headers: vec![],
    };

    let result = transport.send(&request).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, TransportError::TargetNotAllowed(_)));
    assert!(
        err.to_string()
            .contains("target host is not localhost: example.com")
    );
}

#[tokio::test]
async fn send_rejects_external_ip() {
    let mut transport = EvasionTransport::builder().with_timing_seed(0).build();

    let request = FuzzRequest {
        request_id: 101,
        endpoint: "http://8.8.8.8/dns".to_string(),
        method: "GET".to_string(),
        parameter_name: "q".to_string(),
        parameter_location: ParameterLocation::Query,
        payload: "test".to_string(),
        headers: vec![],
    };

    let result = transport.send(&request).await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        TransportError::TargetNotAllowed(_)
    ));
}

#[tokio::test]
async fn send_allows_localhost_url() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;

    let mut transport = EvasionTransport::builder().with_timing_seed(0).build();

    let request = FuzzRequest {
        request_id: 102,
        endpoint: format!("{}/test", server.uri()),
        method: "GET".to_string(),
        parameter_name: "q".to_string(),
        parameter_location: ParameterLocation::Query,
        payload: "test".to_string(),
        headers: vec![],
    };

    let response = transport.send(&request).await.unwrap();
    assert_eq!(response.status_code, 200);
}

#[test]
fn network_error_display() {
    let err = TransportError::NetworkError("connection refused".to_string());
    assert_eq!(err.to_string(), "network error: connection refused");
}

#[test]
fn timeout_display() {
    let err = TransportError::Timeout("exceeded 30s".to_string());
    assert_eq!(err.to_string(), "timeout: exceeded 30s");
}

#[test]
fn build_error_display() {
    let err = TransportError::BuildError("invalid url".to_string());
    assert_eq!(err.to_string(), "build error: invalid url");
}

#[test]
fn target_not_allowed_display() {
    let err =
        TransportError::TargetNotAllowed("target host is not localhost: evil.com".to_string());
    assert_eq!(
        err.to_string(),
        "target not allowed: target host is not localhost: evil.com"
    );
}

#[test]
fn transport_error_implements_error_trait() {
    let err: Box<dyn std::error::Error> =
        Box::new(TransportError::NetworkError("test".to_string()));
    assert_eq!(err.to_string(), "network error: test");
}

#[test]
fn default_builder_creates_valid_transport() {
    let transport = EvasionTransport::builder().build();
    assert_eq!(transport.session_id(), 0);
}

#[test]
fn builder_with_persona_sets_timing_from_persona() {
    let persona = Persona::custom(PersonaId::Googlebot)
        .with_user_agent("TestBot/1.0")
        .with_accept_header("text/html")
        .with_request_interval(5000, 10000)
        .with_jitter_distribution(JitterDistribution::Exponential)
        .build();

    let transport = EvasionTransport::builder()
        .with_persona(&persona)
        .with_timing_seed(42)
        .build();

    assert_eq!(transport.session_id(), 0);
}

#[test]
fn builder_with_max_requests_per_session() {
    let mut transport = EvasionTransport::builder()
        .with_max_requests_per_session(100)
        .build();

    assert_eq!(transport.session_id(), 0);
    transport.reset_session();
    assert_eq!(transport.session_id(), 1);
}

#[test]
fn builder_with_timing_seed() {
    let transport = EvasionTransport::builder().with_timing_seed(12345).build();

    assert_eq!(transport.session_id(), 0);
}

#[test]
fn builder_chaining_all_options() {
    let persona = Persona::custom(PersonaId::FirefoxDesktop)
        .with_user_agent("Firefox/Test")
        .with_accept_header("*/*")
        .build();

    let transport = EvasionTransport::builder()
        .with_persona(&persona)
        .with_max_requests_per_session(25)
        .with_timing_seed(999)
        .build();

    assert_eq!(transport.session_id(), 0);
}

#[test]
fn session_id_returns_initial_value() {
    let transport = EvasionTransport::builder().build();
    assert_eq!(transport.session_id(), 0);
}

#[test]
fn reset_session_increments_session_id() {
    let mut transport = EvasionTransport::builder().build();
    assert_eq!(transport.session_id(), 0);
    transport.reset_session();
    assert_eq!(transport.session_id(), 1);
    transport.reset_session();
    assert_eq!(transport.session_id(), 2);
}

#[test]
fn merge_headers_combines_without_duplicates() {
    let request_headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("Accept".to_string(), "text/html".to_string()),
    ];
    let session_headers = vec![
        ("Cookie".to_string(), "session=abc".to_string()),
        ("accept".to_string(), "application/xml".to_string()),
    ];

    let merged = merge_headers(&request_headers, &session_headers);

    assert_eq!(merged.len(), 3);
    assert!(merged.contains(&("Content-Type".to_string(), "application/json".to_string())));
    assert!(merged.contains(&("Accept".to_string(), "text/html".to_string())));
    assert!(merged.contains(&("Cookie".to_string(), "session=abc".to_string())));
}

#[test]
fn merge_headers_empty_request_headers() {
    let request_headers: Vec<(String, String)> = vec![];
    let session_headers = vec![("Referer".to_string(), "https://example.com".to_string())];

    let merged = merge_headers(&request_headers, &session_headers);

    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].0, "Referer");
}

#[test]
fn merge_headers_empty_session_headers() {
    let request_headers = vec![("Host".to_string(), "example.com".to_string())];
    let session_headers: Vec<(String, String)> = vec![];

    let merged = merge_headers(&request_headers, &session_headers);

    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].0, "Host");
}

#[test]
fn merge_headers_both_empty() {
    let merged = merge_headers(&[], &[]);
    assert!(merged.is_empty());
}

#[test]
fn merge_headers_case_insensitive_dedup() {
    let request_headers = vec![("content-type".to_string(), "text/plain".to_string())];
    let session_headers = vec![("Content-Type".to_string(), "application/json".to_string())];

    let merged = merge_headers(&request_headers, &session_headers);

    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].1, "text/plain");
}

#[test]
fn parse_method_get() {
    let method = parse_method("GET").unwrap();
    assert_eq!(method, reqwest::Method::GET);
}

#[test]
fn parse_method_post() {
    let method = parse_method("POST").unwrap();
    assert_eq!(method, reqwest::Method::POST);
}

#[test]
fn parse_method_put() {
    let method = parse_method("PUT").unwrap();
    assert_eq!(method, reqwest::Method::PUT);
}

#[test]
fn parse_method_delete() {
    let method = parse_method("DELETE").unwrap();
    assert_eq!(method, reqwest::Method::DELETE);
}

#[test]
fn parse_method_patch() {
    let method = parse_method("PATCH").unwrap();
    assert_eq!(method, reqwest::Method::PATCH);
}

#[test]
fn parse_method_head() {
    let method = parse_method("HEAD").unwrap();
    assert_eq!(method, reqwest::Method::HEAD);
}

#[test]
fn parse_method_options() {
    let method = parse_method("OPTIONS").unwrap();
    assert_eq!(method, reqwest::Method::OPTIONS);
}

#[test]
fn parse_method_case_insensitive() {
    let method = parse_method("get").unwrap();
    assert_eq!(method, reqwest::Method::GET);

    let method = parse_method("Post").unwrap();
    assert_eq!(method, reqwest::Method::POST);
}

#[test]
fn parse_method_unsupported_returns_error() {
    let result = parse_method("CONNECT");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(
        err.to_string(),
        "build error: unsupported HTTP method: CONNECT"
    );
}

#[test]
fn build_reqwest_request_get_with_query() {
    let transport = EvasionTransport::builder().build();
    let request = FuzzRequest {
        request_id: 1,
        endpoint: "http://localhost:9999/test".to_string(),
        method: "GET".to_string(),
        parameter_name: "q".to_string(),
        parameter_location: ParameterLocation::Query,
        payload: "search term".to_string(),
        headers: vec![],
    };
    let transformed = vec![("Accept".to_string(), "text/html".to_string())];
    let built = transport
        .build_reqwest_request(&request, &transformed)
        .unwrap();
    assert_eq!(*built.method(), reqwest::Method::GET);
    assert!(built.url().as_str().contains("q=search"));
    assert_eq!(built.headers().get("Accept").unwrap(), "text/html");
}

#[test]
fn build_reqwest_request_post_with_query_location_uses_query_string() {
    let transport = EvasionTransport::builder().build();
    let request = FuzzRequest {
        request_id: 2,
        endpoint: "http://localhost:9999/submit".to_string(),
        method: "POST".to_string(),
        parameter_name: "name".to_string(),
        parameter_location: ParameterLocation::Query,
        payload: "value".to_string(),
        headers: vec![],
    };
    let built = transport.build_reqwest_request(&request, &[]).unwrap();
    assert_eq!(*built.method(), reqwest::Method::POST);
    assert!(built.url().as_str().contains("name=value"));
    assert!(built.body().is_none());
}

#[test]
fn build_reqwest_request_post_with_body_location_sets_json_body() {
    let transport = EvasionTransport::builder().build();
    let request = FuzzRequest {
        request_id: 2,
        endpoint: "http://localhost:9999/submit".to_string(),
        method: "POST".to_string(),
        parameter_name: "name".to_string(),
        parameter_location: ParameterLocation::Body,
        payload: "value".to_string(),
        headers: vec![],
    };
    let built = transport.build_reqwest_request(&request, &[]).unwrap();
    assert_eq!(*built.method(), reqwest::Method::POST);
    assert!(built.body().is_some());
    let body_bytes = built.body().unwrap().as_bytes().unwrap();
    let body_str = std::str::from_utf8(body_bytes).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(body_str).unwrap();
    assert_eq!(parsed["name"], "value");
    assert_eq!(
        built.headers().get("Content-Type").unwrap(),
        "application/json"
    );
}

#[test]
fn build_reqwest_request_invalid_method_returns_error() {
    let transport = EvasionTransport::builder().build();
    let request = FuzzRequest {
        request_id: 3,
        endpoint: "http://localhost:9999/test".to_string(),
        method: "INVALID".to_string(),
        parameter_name: "x".to_string(),
        parameter_location: ParameterLocation::Query,
        payload: "y".to_string(),
        headers: vec![],
    };
    let result = transport.build_reqwest_request(&request, &[]);
    assert!(result.is_err());
}

#[test]
fn build_reqwest_request_put_with_query_location_uses_query_string() {
    let transport = EvasionTransport::builder().build();
    let request = FuzzRequest {
        request_id: 4,
        endpoint: "http://localhost:9999/update".to_string(),
        method: "PUT".to_string(),
        parameter_name: "field".to_string(),
        parameter_location: ParameterLocation::Query,
        payload: "data".to_string(),
        headers: vec![],
    };
    let built = transport.build_reqwest_request(&request, &[]).unwrap();
    assert_eq!(*built.method(), reqwest::Method::PUT);
    assert!(built.url().as_str().contains("field=data"));
    assert!(built.body().is_none());
}

#[test]
fn build_reqwest_request_delete_uses_query() {
    let transport = EvasionTransport::builder().build();
    let request = FuzzRequest {
        request_id: 5,
        endpoint: "http://localhost:9999/remove".to_string(),
        method: "DELETE".to_string(),
        parameter_name: "id".to_string(),
        parameter_location: ParameterLocation::Query,
        payload: "42".to_string(),
        headers: vec![],
    };
    let built = transport.build_reqwest_request(&request, &[]).unwrap();
    assert_eq!(*built.method(), reqwest::Method::DELETE);
    assert!(built.url().as_str().contains("id=42"));
}

#[test]
fn build_reqwest_request_multiple_headers() {
    let transport = EvasionTransport::builder().build();
    let request = FuzzRequest {
        request_id: 6,
        endpoint: "http://localhost:9999/api".to_string(),
        method: "GET".to_string(),
        parameter_name: "p".to_string(),
        parameter_location: ParameterLocation::Query,
        payload: "v".to_string(),
        headers: vec![],
    };
    let transformed = vec![
        ("X-Custom".to_string(), "custom-val".to_string()),
        ("Authorization".to_string(), "Bearer tok".to_string()),
    ];
    let built = transport
        .build_reqwest_request(&request, &transformed)
        .unwrap();
    assert_eq!(built.headers().get("X-Custom").unwrap(), "custom-val");
    assert_eq!(built.headers().get("Authorization").unwrap(), "Bearer tok");
}

#[test]
fn resolve_query_location_appends_query_string() {
    let request = FuzzRequest {
        request_id: 1,
        endpoint: "http://localhost:9999/test".to_string(),
        method: "GET".to_string(),
        parameter_name: "key".to_string(),
        parameter_location: ParameterLocation::Query,
        payload: "val".to_string(),
        headers: vec![],
    };
    let (url, body, extra_headers) = resolve_parameter_injection(&request);
    assert_eq!(url, "http://localhost:9999/test?key=val");
    assert!(body.is_none());
    assert!(extra_headers.is_empty());
}

#[test]
fn resolve_query_location_empty_param_leaves_url_unchanged() {
    let request = FuzzRequest {
        request_id: 1,
        endpoint: "http://localhost:9999/test".to_string(),
        method: "GET".to_string(),
        parameter_name: String::new(),
        parameter_location: ParameterLocation::Query,
        payload: "val".to_string(),
        headers: vec![],
    };
    let (url, body, extra_headers) = resolve_parameter_injection(&request);
    assert_eq!(url, "http://localhost:9999/test");
    assert!(body.is_none());
    assert!(extra_headers.is_empty());
}

#[test]
fn resolve_body_location_sets_json_body_and_content_type() {
    let request = FuzzRequest {
        request_id: 1,
        endpoint: "http://localhost:9999/submit".to_string(),
        method: "POST".to_string(),
        parameter_name: "field".to_string(),
        parameter_location: ParameterLocation::Body,
        payload: "injected".to_string(),
        headers: vec![],
    };
    let (url, body, extra_headers) = resolve_parameter_injection(&request);
    assert_eq!(url, "http://localhost:9999/submit");
    let body_str = body.expect("body should be set for Body location");
    let parsed: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(parsed["field"], "injected");
    assert_eq!(extra_headers.len(), 1);
    assert_eq!(extra_headers[0].0, "Content-Type");
    assert_eq!(extra_headers[0].1, "application/json");
}

#[test]
fn resolve_body_location_empty_param_uses_raw_payload() {
    let request = FuzzRequest {
        request_id: 1,
        endpoint: "http://localhost:9999/submit".to_string(),
        method: "POST".to_string(),
        parameter_name: String::new(),
        parameter_location: ParameterLocation::Body,
        payload: "{\"raw\":true}".to_string(),
        headers: vec![],
    };
    let (url, body, extra_headers) = resolve_parameter_injection(&request);
    assert_eq!(url, "http://localhost:9999/submit");
    assert_eq!(body.unwrap(), "{\"raw\":true}");
    assert_eq!(extra_headers[0].0, "Content-Type");
}

#[test]
fn resolve_path_location_replaces_placeholder_in_url() {
    let request = FuzzRequest {
        request_id: 1,
        endpoint: "http://localhost:9999/users/{id}/profile".to_string(),
        method: "GET".to_string(),
        parameter_name: "id".to_string(),
        parameter_location: ParameterLocation::Path,
        payload: "42".to_string(),
        headers: vec![],
    };
    let (url, body, extra_headers) = resolve_parameter_injection(&request);
    assert_eq!(url, "http://localhost:9999/users/42/profile");
    assert!(body.is_none());
    assert!(extra_headers.is_empty());
}

#[test]
fn resolve_header_location_adds_header() {
    let request = FuzzRequest {
        request_id: 1,
        endpoint: "http://localhost:9999/api".to_string(),
        method: "GET".to_string(),
        parameter_name: "X-Api-Key".to_string(),
        parameter_location: ParameterLocation::Header,
        payload: "secret".to_string(),
        headers: vec![],
    };
    let (url, body, extra_headers) = resolve_parameter_injection(&request);
    assert_eq!(url, "http://localhost:9999/api");
    assert!(body.is_none());
    assert_eq!(extra_headers.len(), 1);
    assert_eq!(extra_headers[0].0, "X-Api-Key");
    assert_eq!(extra_headers[0].1, "secret");
}

#[test]
fn resolve_cookie_location_adds_cookie_header() {
    let request = FuzzRequest {
        request_id: 1,
        endpoint: "http://localhost:9999/api".to_string(),
        method: "GET".to_string(),
        parameter_name: "session".to_string(),
        parameter_location: ParameterLocation::Cookie,
        payload: "abc123".to_string(),
        headers: vec![],
    };
    let (url, body, extra_headers) = resolve_parameter_injection(&request);
    assert_eq!(url, "http://localhost:9999/api");
    assert!(body.is_none());
    assert_eq!(extra_headers.len(), 1);
    assert_eq!(extra_headers[0].0, "Cookie");
    assert_eq!(extra_headers[0].1, "session=abc123");
}

#[test]
fn transform_headers_without_referer() {
    let persona = Persona::custom(PersonaId::ChromeDesktop)
        .with_user_agent("TestUA")
        .with_accept_header("text/html")
        .build();
    let transport = EvasionTransport::builder().with_persona(&persona).build();
    let headers = vec![("X-Test".to_string(), "value".to_string())];
    let transformed = transport.transform_headers(&headers);
    assert!(
        transformed
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
    );
}

#[test]
fn transform_headers_with_referer_in_session() {
    let persona = Persona::custom(PersonaId::ChromeDesktop)
        .with_user_agent("TestUA")
        .with_accept_header("text/html")
        .build();
    let mut transport = EvasionTransport::builder().with_persona(&persona).build();
    transport.session.record_request("https://example.com/prev");
    let headers = vec![];
    let transformed = transport.transform_headers(&headers);
    assert!(transformed.iter().any(|(k, _)| k == "Referer"));
}

#[tokio::test]
async fn send_get_request_returns_response() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;

    let mut transport = EvasionTransport::builder().with_timing_seed(0).build();

    let request = FuzzRequest {
        request_id: 10,
        endpoint: format!("{}/path", server.uri()),
        method: "GET".to_string(),
        parameter_name: "q".to_string(),
        parameter_location: ParameterLocation::Query,
        payload: "test".to_string(),
        headers: vec![],
    };

    let response = transport.send(&request).await.unwrap();
    assert_eq!(response.status_code, 200);
    assert_eq!(response.body, "ok");
    assert_eq!(response.request_id, 10);
    assert!(response.body_size_bytes > 0);
}

#[tokio::test]
async fn send_post_request_returns_response() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(201).set_body_string("created"))
        .mount(&server)
        .await;

    let mut transport = EvasionTransport::builder().with_timing_seed(0).build();

    let request = FuzzRequest {
        request_id: 20,
        endpoint: format!("{}/submit", server.uri()),
        method: "POST".to_string(),
        parameter_name: "name".to_string(),
        parameter_location: ParameterLocation::Query,
        payload: "value".to_string(),
        headers: vec![],
    };

    let response = transport.send(&request).await.unwrap();
    assert_eq!(response.status_code, 201);
    assert_eq!(response.body, "created");
}

#[tokio::test]
async fn send_records_request_in_session() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::any())
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let mut transport = EvasionTransport::builder().with_timing_seed(0).build();

    let endpoint = format!("{}/page", server.uri());
    let request = FuzzRequest {
        request_id: 30,
        endpoint: endpoint.clone(),
        method: "GET".to_string(),
        parameter_name: "x".to_string(),
        parameter_location: ParameterLocation::Query,
        payload: "y".to_string(),
        headers: vec![],
    };

    transport.send(&request).await.unwrap();
    assert_eq!(transport.session.last_url(), Some(endpoint.as_str()));
}

#[tokio::test]
async fn send_processes_set_cookie_header() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::any())
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_string("")
                .append_header("Set-Cookie", "sid=abc123; Path=/"),
        )
        .mount(&server)
        .await;

    let mut transport = EvasionTransport::builder().with_timing_seed(0).build();

    let request = FuzzRequest {
        request_id: 40,
        endpoint: format!("{}/login", server.uri()),
        method: "POST".to_string(),
        parameter_name: "user".to_string(),
        parameter_location: ParameterLocation::Query,
        payload: "admin".to_string(),
        headers: vec![],
    };

    transport.send(&request).await.unwrap();
    let session_hdrs = transport.session.session_headers();
    let cookie = session_hdrs.iter().find(|(k, _)| k == "Cookie");
    assert!(cookie.is_some());
    assert!(cookie.unwrap().1.contains("sid=abc123"));
}

#[tokio::test]
async fn send_with_custom_headers() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::any())
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let mut transport = EvasionTransport::builder().with_timing_seed(0).build();

    let request = FuzzRequest {
        request_id: 50,
        endpoint: format!("{}/api", server.uri()),
        method: "GET".to_string(),
        parameter_name: "k".to_string(),
        parameter_location: ParameterLocation::Query,
        payload: "v".to_string(),
        headers: vec![("X-Custom".to_string(), "myval".to_string())],
    };

    let response = transport.send(&request).await.unwrap();
    assert_eq!(response.status_code, 200);
}

#[tokio::test]
async fn send_to_nonexistent_server_returns_network_error() {
    let mut transport = EvasionTransport::builder().with_timing_seed(0).build();

    let request = FuzzRequest {
        request_id: 60,
        endpoint: "http://127.0.0.1:1/unreachable".to_string(),
        method: "GET".to_string(),
        parameter_name: "x".to_string(),
        parameter_location: ParameterLocation::Query,
        payload: "y".to_string(),
        headers: vec![],
    };

    let result = transport.send(&request).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, TransportError::NetworkError(_)));
}

#[tokio::test]
async fn send_returns_response_headers() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::any())
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_string("body")
                .append_header("X-Response-Id", "resp-42"),
        )
        .mount(&server)
        .await;

    let mut transport = EvasionTransport::builder().with_timing_seed(0).build();

    let request = FuzzRequest {
        request_id: 70,
        endpoint: format!("{}/headers", server.uri()),
        method: "GET".to_string(),
        parameter_name: "a".to_string(),
        parameter_location: ParameterLocation::Query,
        payload: "b".to_string(),
        headers: vec![],
    };

    let response = transport.send(&request).await.unwrap();
    assert!(
        response
            .headers
            .iter()
            .any(|(k, v)| k == "x-response-id" && v == "resp-42")
    );
}

#[tokio::test]
async fn send_measures_response_time() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::any())
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("quick"))
        .mount(&server)
        .await;

    let mut transport = EvasionTransport::builder().with_timing_seed(0).build();

    let request = FuzzRequest {
        request_id: 80,
        endpoint: format!("{}/timing", server.uri()),
        method: "GET".to_string(),
        parameter_name: "t".to_string(),
        parameter_location: ParameterLocation::Query,
        payload: "1".to_string(),
        headers: vec![],
    };

    let response = transport.send(&request).await.unwrap();
    assert!(response.response_time.as_nanos() > 0);
}

#[tokio::test]
async fn send_auto_rotates_session_at_threshold() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::any())
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let mut transport = EvasionTransport::builder()
        .with_max_requests_per_session(2)
        .with_timing_seed(0)
        .build();

    assert_eq!(transport.session_id(), 0);

    let make_request = |id: u64| FuzzRequest {
        request_id: id,
        endpoint: format!("{}/r", server.uri()),
        method: "GET".to_string(),
        parameter_name: "n".to_string(),
        parameter_location: ParameterLocation::Query,
        payload: id.to_string(),
        headers: vec![],
    };

    transport.send(&make_request(1)).await.unwrap();
    assert_eq!(transport.session_id(), 0);
    transport.send(&make_request(2)).await.unwrap();
    assert_eq!(transport.session_id(), 1);
}

#[test]
fn persona_rotation_disabled_by_default() {
    let transport = EvasionTransport::builder().build();
    assert!(transport.persona_rotation_interval.is_none());
    assert_eq!(transport.sessions_since_rotation, 0);
}

#[test]
fn with_persona_rotation_sets_interval() {
    let transport = EvasionTransport::builder().with_persona_rotation(3).build();
    assert_eq!(transport.persona_rotation_interval, Some(3));
    assert_eq!(transport.sessions_since_rotation, 0);
    assert!(!transport.persona_catalog.is_empty());
}

#[tokio::test]
async fn persona_changes_after_rotation_interval() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::any())
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let catalog = persona_catalog();
    let first_persona_id = catalog[0].id;
    let second_persona_id = catalog[1].id;

    let mut transport = EvasionTransport::builder()
        .with_max_requests_per_session(1)
        .with_persona_rotation(2)
        .with_timing_seed(0)
        .build();

    assert_eq!(transport.persona_id(), first_persona_id);

    let make_request = |id: u64| FuzzRequest {
        request_id: id,
        endpoint: format!("{}/r", server.uri()),
        method: "GET".to_string(),
        parameter_name: "n".to_string(),
        parameter_location: ParameterLocation::Query,
        payload: id.to_string(),
        headers: vec![],
    };

    transport.send(&make_request(1)).await.unwrap();
    assert_eq!(transport.session_id(), 1);
    assert_eq!(transport.persona_id(), first_persona_id);

    transport.send(&make_request(2)).await.unwrap();
    assert_eq!(transport.session_id(), 2);
    assert_eq!(transport.persona_id(), second_persona_id);
}

#[test]
fn builder_with_accept_self_signed_false_builds_successfully() {
    let transport = EvasionTransport::builder()
        .with_accept_self_signed(false)
        .build();
    assert_eq!(transport.session_id(), 0);
}

#[test]
fn builder_with_accept_self_signed_true_builds_successfully() {
    let transport = EvasionTransport::builder()
        .with_accept_self_signed(true)
        .build();
    assert_eq!(transport.session_id(), 0);
}

#[test]
fn builder_accept_self_signed_chains_with_other_options() {
    let persona = Persona::custom(PersonaId::FirefoxDesktop)
        .with_user_agent("Firefox/Test")
        .with_accept_header("*/*")
        .build();

    let transport = EvasionTransport::builder()
        .with_persona(&persona)
        .with_max_requests_per_session(25)
        .with_timing_seed(999)
        .with_accept_self_signed(true)
        .build();

    assert_eq!(transport.session_id(), 0);
}

#[tokio::test]
async fn send_body_location_delivers_json_payload() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::header(
            "content-type",
            "application/json",
        ))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;

    let mut transport = EvasionTransport::builder().with_timing_seed(0).build();

    let request = FuzzRequest {
        request_id: 200,
        endpoint: format!("{}/submit", server.uri()),
        method: "POST".to_string(),
        parameter_name: "username".to_string(),
        parameter_location: ParameterLocation::Body,
        payload: "admin".to_string(),
        headers: vec![],
    };

    let response = transport.send(&request).await.unwrap();
    assert_eq!(response.status_code, 200);
    assert_eq!(response.body, "ok");
}

#[tokio::test]
async fn send_query_location_appends_query_string() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::query_param("search", "test"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("found"))
        .mount(&server)
        .await;

    let mut transport = EvasionTransport::builder().with_timing_seed(0).build();

    let request = FuzzRequest {
        request_id: 201,
        endpoint: format!("{}/api", server.uri()),
        method: "GET".to_string(),
        parameter_name: "search".to_string(),
        parameter_location: ParameterLocation::Query,
        payload: "test".to_string(),
        headers: vec![],
    };

    let response = transport.send(&request).await.unwrap();
    assert_eq!(response.status_code, 200);
    assert_eq!(response.body, "found");
}

#[test]
fn build_reqwest_request_path_location_replaces_placeholder() {
    let transport = EvasionTransport::builder().build();
    let request = FuzzRequest {
        request_id: 7,
        endpoint: "http://localhost:9999/users/{id}".to_string(),
        method: "GET".to_string(),
        parameter_name: "id".to_string(),
        parameter_location: ParameterLocation::Path,
        payload: "42".to_string(),
        headers: vec![],
    };
    let built = transport.build_reqwest_request(&request, &[]).unwrap();
    assert_eq!(built.url().path(), "/users/42");
    assert!(built.body().is_none());
}

#[test]
fn build_reqwest_request_header_location_adds_header() {
    let transport = EvasionTransport::builder().build();
    let request = FuzzRequest {
        request_id: 8,
        endpoint: "http://localhost:9999/api".to_string(),
        method: "GET".to_string(),
        parameter_name: "X-Api-Key".to_string(),
        parameter_location: ParameterLocation::Header,
        payload: "secret".to_string(),
        headers: vec![],
    };
    let built = transport.build_reqwest_request(&request, &[]).unwrap();
    assert_eq!(built.headers().get("X-Api-Key").unwrap(), "secret");
    assert!(built.body().is_none());
}

#[test]
fn build_reqwest_request_cookie_location_adds_cookie_header() {
    let transport = EvasionTransport::builder().build();
    let request = FuzzRequest {
        request_id: 9,
        endpoint: "http://localhost:9999/api".to_string(),
        method: "GET".to_string(),
        parameter_name: "session".to_string(),
        parameter_location: ParameterLocation::Cookie,
        payload: "abc123".to_string(),
        headers: vec![],
    };
    let built = transport.build_reqwest_request(&request, &[]).unwrap();
    assert_eq!(built.headers().get("Cookie").unwrap(), "session=abc123");
    assert!(built.body().is_none());
}
