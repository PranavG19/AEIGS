use super::*;
use crate::persona::{JitterDistribution, PersonaId, persona_catalog};
use aegis_protocol::request::FuzzRequest;

#[tokio::test]
async fn send_rejects_non_localhost_url() {
    let mut transport = EvasionTransport::builder().with_timing_seed(0).build();

    let request = FuzzRequest {
        request_id: 100,
        endpoint: "http://example.com/api".to_string(),
        method: "GET".to_string(),
        parameter_name: "q".to_string(),
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
fn is_body_method_post() {
    assert!(is_body_method(&reqwest::Method::POST));
}

#[test]
fn is_body_method_put() {
    assert!(is_body_method(&reqwest::Method::PUT));
}

#[test]
fn is_body_method_patch() {
    assert!(is_body_method(&reqwest::Method::PATCH));
}

#[test]
fn is_body_method_get_returns_false() {
    assert!(!is_body_method(&reqwest::Method::GET));
}

#[test]
fn is_body_method_delete_returns_false() {
    assert!(!is_body_method(&reqwest::Method::DELETE));
}

#[test]
fn is_body_method_head_returns_false() {
    assert!(!is_body_method(&reqwest::Method::HEAD));
}

#[test]
fn is_body_method_options_returns_false() {
    assert!(!is_body_method(&reqwest::Method::OPTIONS));
}

#[test]
fn build_reqwest_request_get_with_query() {
    let transport = EvasionTransport::builder().build();
    let request = FuzzRequest {
        request_id: 1,
        endpoint: "http://localhost:9999/test".to_string(),
        method: "GET".to_string(),
        parameter_name: "q".to_string(),
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
fn build_reqwest_request_post_with_body() {
    let transport = EvasionTransport::builder().build();
    let request = FuzzRequest {
        request_id: 2,
        endpoint: "http://localhost:9999/submit".to_string(),
        method: "POST".to_string(),
        parameter_name: "name".to_string(),
        payload: "value".to_string(),
        headers: vec![],
    };
    let transformed = vec![];
    let built = transport
        .build_reqwest_request(&request, &transformed)
        .unwrap();
    assert_eq!(*built.method(), reqwest::Method::POST);
    assert!(built.body().is_some());
}

#[test]
fn build_reqwest_request_invalid_method_returns_error() {
    let transport = EvasionTransport::builder().build();
    let request = FuzzRequest {
        request_id: 3,
        endpoint: "http://localhost:9999/test".to_string(),
        method: "INVALID".to_string(),
        parameter_name: "x".to_string(),
        payload: "y".to_string(),
        headers: vec![],
    };
    let result = transport.build_reqwest_request(&request, &[]);
    assert!(result.is_err());
}

#[test]
fn build_reqwest_request_put_attaches_body() {
    let transport = EvasionTransport::builder().build();
    let request = FuzzRequest {
        request_id: 4,
        endpoint: "http://localhost:9999/update".to_string(),
        method: "PUT".to_string(),
        parameter_name: "field".to_string(),
        payload: "data".to_string(),
        headers: vec![],
    };
    let built = transport.build_reqwest_request(&request, &[]).unwrap();
    assert_eq!(*built.method(), reqwest::Method::PUT);
    assert!(built.body().is_some());
}

#[test]
fn build_reqwest_request_delete_uses_query() {
    let transport = EvasionTransport::builder().build();
    let request = FuzzRequest {
        request_id: 5,
        endpoint: "http://localhost:9999/remove".to_string(),
        method: "DELETE".to_string(),
        parameter_name: "id".to_string(),
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
fn attach_payload_get_uses_query() {
    let client = reqwest::Client::new();
    let builder = client.get("http://localhost:9999/test");
    let request = FuzzRequest {
        request_id: 1,
        endpoint: "http://localhost:9999/test".to_string(),
        method: "GET".to_string(),
        parameter_name: "key".to_string(),
        payload: "val".to_string(),
        headers: vec![],
    };
    let result = attach_payload(builder, &reqwest::Method::GET, &request);
    let built = result.build().unwrap();
    assert!(built.url().query().unwrap().contains("key=val"));
}

#[test]
fn attach_payload_post_uses_form() {
    let client = reqwest::Client::new();
    let builder = client.post("http://localhost:9999/test");
    let request = FuzzRequest {
        request_id: 1,
        endpoint: "http://localhost:9999/test".to_string(),
        method: "POST".to_string(),
        parameter_name: "key".to_string(),
        payload: "val".to_string(),
        headers: vec![],
    };
    let result = attach_payload(builder, &reqwest::Method::POST, &request);
    let built = result.build().unwrap();
    assert!(built.body().is_some());
}

#[test]
fn attach_payload_patch_uses_form() {
    let client = reqwest::Client::new();
    let builder = client.patch("http://localhost:9999/test");
    let request = FuzzRequest {
        request_id: 1,
        endpoint: "http://localhost:9999/test".to_string(),
        method: "PATCH".to_string(),
        parameter_name: "field".to_string(),
        payload: "updated".to_string(),
        headers: vec![],
    };
    let result = attach_payload(builder, &reqwest::Method::PATCH, &request);
    let built = result.build().unwrap();
    assert!(built.body().is_some());
}

#[test]
fn attach_payload_head_uses_query() {
    let client = reqwest::Client::new();
    let builder = client.head("http://localhost:9999/test");
    let request = FuzzRequest {
        request_id: 1,
        endpoint: "http://localhost:9999/test".to_string(),
        method: "HEAD".to_string(),
        parameter_name: "check".to_string(),
        payload: "true".to_string(),
        headers: vec![],
    };
    let result = attach_payload(builder, &reqwest::Method::HEAD, &request);
    let built = result.build().unwrap();
    assert!(built.url().query().unwrap().contains("check=true"));
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
