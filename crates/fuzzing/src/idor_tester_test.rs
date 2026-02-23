#[cfg(test)]
mod tests {
    use std::net::TcpListener as StdTcpListener;

    use axum::Router;
    use axum::extract::Path;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::get;

    use crate::idor_tester::{
        IdLocation, IdType, IdorTester, detect_id_parameters, generate_test_ids,
    };

    fn start_server_background(app: Router) -> String {
        let std_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let port = std_listener.local_addr().unwrap().port();
        std_listener.set_nonblocking(true).unwrap();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(std_listener).unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        });

        std::thread::sleep(std::time::Duration::from_millis(50));
        format!("http://127.0.0.1:{port}")
    }

    async fn user_by_id_handler(Path(id): Path<u64>) -> impl IntoResponse {
        let body = format!(r#"{{"id":{id},"name":"user_{id}","email":"user_{id}@test.com"}}"#);
        (StatusCode::OK, body)
    }

    async fn static_list_handler() -> impl IntoResponse {
        (StatusCode::OK, r#"[{"id":1},{"id":2},{"id":3}]"#)
    }

    async fn not_found_handler(Path(_id): Path<u64>) -> impl IntoResponse {
        (StatusCode::NOT_FOUND, "not found")
    }

    async fn auth_required_handler(headers: HeaderMap, Path(id): Path<u64>) -> impl IntoResponse {
        if headers.get("authorization").is_none() {
            return (StatusCode::UNAUTHORIZED, "unauthorized".to_string());
        }
        let body = format!(r#"{{"id":{id},"name":"user_{id}"}}"#);
        (StatusCode::OK, body)
    }

    #[test]
    fn detect_numeric_id_in_path() {
        let params = detect_id_parameters("http://127.0.0.1:3000/api/users/123/profile", "GET");
        assert!(!params.is_empty());
        let id_param = params.iter().find(|p| p.value == "123").unwrap();
        assert_eq!(id_param.id_type, IdType::SequentialInteger);
        assert_eq!(id_param.location, IdLocation::PathSegment(2));
    }

    #[test]
    fn detect_numeric_id_at_end_of_path() {
        let params = detect_id_parameters("http://127.0.0.1:3000/api/orders/456", "GET");
        assert!(!params.is_empty());
        let id_param = params.iter().find(|p| p.value == "456").unwrap();
        assert_eq!(id_param.id_type, IdType::SequentialInteger);
        assert_eq!(id_param.name, "orders");
    }

    #[test]
    fn detect_uuid_in_path() {
        let params = detect_id_parameters(
            "http://127.0.0.1:3000/api/users/550e8400-e29b-41d4-a716-446655440000",
            "GET",
        );
        assert!(!params.is_empty());
        let uuid_param = params
            .iter()
            .find(|p| p.value == "550e8400-e29b-41d4-a716-446655440000")
            .unwrap();
        assert_eq!(uuid_param.id_type, IdType::Uuid);
    }

    #[test]
    fn detect_id_in_query_param() {
        let params = detect_id_parameters("http://127.0.0.1:3000/api/users?user_id=42", "GET");
        assert!(!params.is_empty());
        let qp = params.iter().find(|p| p.name == "user_id").unwrap();
        assert_eq!(qp.value, "42");
        assert_eq!(qp.id_type, IdType::SequentialInteger);
        assert_eq!(qp.location, IdLocation::QueryParam);
    }

    #[test]
    fn detect_account_id_in_query() {
        let params = detect_id_parameters("http://127.0.0.1:3000/api/data?account_id=100", "GET");
        let qp = params.iter().find(|p| p.name == "account_id").unwrap();
        assert_eq!(qp.value, "100");
    }

    #[test]
    fn detect_order_id_in_query() {
        let params = detect_id_parameters("http://127.0.0.1:3000/api/data?order_id=789", "GET");
        let qp = params.iter().find(|p| p.name == "order_id").unwrap();
        assert_eq!(qp.value, "789");
    }

    #[test]
    fn no_id_detected_in_plain_path() {
        let params = detect_id_parameters("http://127.0.0.1:3000/api/users", "GET");
        assert!(params.is_empty());
    }

    #[test]
    fn no_id_detected_in_non_id_query_params() {
        let params = detect_id_parameters("http://127.0.0.1:3000/api/search?q=hello&page=1", "GET");
        assert!(params.is_empty());
    }

    #[test]
    fn detect_multiple_ids_in_path() {
        let params = detect_id_parameters("http://127.0.0.1:3000/api/users/5/orders/10", "GET");
        assert_eq!(params.len(), 2);
        assert!(params.iter().any(|p| p.value == "5"));
        assert!(params.iter().any(|p| p.value == "10"));
    }

    #[test]
    fn generate_sequential_test_ids() {
        let ids = generate_test_ids("123", IdType::SequentialInteger);
        assert!(ids.contains(&"124".to_string()));
        assert!(ids.contains(&"122".to_string()));
        assert!(ids.contains(&"133".to_string()));
        assert!(ids.contains(&"113".to_string()));
        assert!(ids.contains(&"0".to_string()));
        assert!(ids.contains(&"1".to_string()));
        assert!(ids.contains(&"9999999".to_string()));
    }

    #[test]
    fn generate_sequential_ids_from_zero() {
        let ids = generate_test_ids("0", IdType::SequentialInteger);
        assert!(ids.contains(&"1".to_string()));
        assert!(ids.contains(&"-1".to_string()));
        assert!(!ids.iter().any(|i| i == "0"));
    }

    #[test]
    fn generate_sequential_ids_from_one() {
        let ids = generate_test_ids("1", IdType::SequentialInteger);
        assert!(ids.contains(&"2".to_string()));
        assert!(ids.contains(&"0".to_string()));
        assert!(!ids.iter().filter(|i| i.as_str() == "1").count() > 0);
    }

    #[test]
    fn generate_uuid_test_ids_is_empty() {
        let ids = generate_test_ids("550e8400-e29b-41d4-a716-446655440000", IdType::Uuid);
        assert!(ids.is_empty());
    }

    #[test]
    fn generate_encoded_test_ids() {
        use base64::Engine;
        let original = base64::engine::general_purpose::STANDARD.encode("42");
        let ids = generate_test_ids(&original, IdType::EncodedId);
        assert!(!ids.is_empty());

        let engine = &base64::engine::general_purpose::STANDARD;
        let decoded_first = engine.decode(&ids[0]).unwrap();
        let decoded_str = String::from_utf8(decoded_first).unwrap();
        assert_eq!(decoded_str, "43");
    }

    #[test]
    fn id_type_display() {
        assert_eq!(IdType::SequentialInteger.to_string(), "sequential-integer");
        assert_eq!(IdType::Uuid.to_string(), "uuid");
        assert_eq!(IdType::EncodedId.to_string(), "encoded-id");
    }

    #[test]
    fn id_location_display() {
        assert_eq!(IdLocation::PathSegment(2).to_string(), "path-segment(2)");
        assert_eq!(IdLocation::QueryParam.to_string(), "query-param");
    }

    #[test]
    fn rejects_non_localhost_target() {
        let tester = IdorTester::new();
        let findings = tester.test_idor("https://example.com/api/users/1", "GET", None);
        assert!(findings.is_empty());
    }

    #[test]
    fn rejects_empty_endpoint() {
        let tester = IdorTester::new();
        let findings = tester.test_idor("", "GET", None);
        assert!(findings.is_empty());
    }

    #[test]
    fn no_findings_when_no_ids_in_path() {
        let app = Router::new().route("/api/health", get(static_list_handler));
        let base = start_server_background(app);

        let tester = IdorTester::new();
        let findings = tester.test_idor(&format!("{base}/api/health"), "GET", None);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_idor_when_different_user_data_returned() {
        let app = Router::new().route("/api/users/{id}", get(user_by_id_handler));
        let base = start_server_background(app);

        let tester = IdorTester::new();
        let findings = tester.test_idor(&format!("{base}/api/users/123"), "GET", None);

        assert!(
            !findings.is_empty(),
            "should detect IDOR when different user data is returned for different IDs"
        );
        let f = &findings[0];
        assert_eq!(f.original_id, "123");
        assert_eq!(f.id_type, IdType::SequentialInteger);
    }

    #[test]
    fn no_idor_when_static_response() {
        let app = Router::new().route("/api/items/{id}", get(static_list_handler));
        let base = start_server_background(app);

        let tester = IdorTester::new();
        let findings = tester.test_idor(&format!("{base}/api/items/1"), "GET", None);

        assert!(
            findings.is_empty(),
            "should not flag IDOR when response body is identical for different IDs"
        );
    }

    #[test]
    fn no_idor_when_404_on_other_ids() {
        let app = Router::new().route("/api/users/{id}", get(not_found_handler));
        let base = start_server_background(app);

        let tester = IdorTester::new();
        let findings = tester.test_idor(&format!("{base}/api/users/123"), "GET", None);
        assert!(findings.is_empty());
    }

    #[test]
    fn severity_unauthenticated_is_critical() {
        let app = Router::new().route("/api/users/{id}", get(user_by_id_handler));
        let base = start_server_background(app);

        let tester = IdorTester::new();
        let findings = tester.test_idor(&format!("{base}/api/users/123"), "GET", None);

        assert!(!findings.is_empty());
        assert!((findings[0].severity - 9.0).abs() < f64::EPSILON);
    }

    #[test]
    fn severity_authenticated_is_high() {
        let app = Router::new().route("/api/users/{id}", get(auth_required_handler));
        let base = start_server_background(app);

        let tester = IdorTester::new();
        let findings = tester.test_idor(
            &format!("{base}/api/users/123"),
            "GET",
            Some("Bearer test-token"),
        );

        assert!(!findings.is_empty());
        assert!((findings[0].severity - 8.0).abs() < f64::EPSILON);
    }

    #[test]
    fn evidence_contains_relevant_details() {
        let app = Router::new().route("/api/users/{id}", get(user_by_id_handler));
        let base = start_server_background(app);

        let tester = IdorTester::new();
        let findings = tester.test_idor(&format!("{base}/api/users/123"), "GET", None);

        assert!(!findings.is_empty());
        let evidence = &findings[0].evidence;
        assert!(evidence.contains("123"));
        assert!(evidence.contains("sequential-integer"));
        assert!(evidence.contains("200"));
    }

    #[test]
    fn with_client_constructor_works() {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let tester = IdorTester::with_client(client);

        let app = Router::new().route("/api/health", get(static_list_handler));
        let base = start_server_background(app);

        let findings = tester.test_idor(&format!("{base}/api/health"), "GET", None);
        assert!(findings.is_empty());
    }

    #[test]
    fn default_constructor_works() {
        let tester = IdorTester::default();
        let findings = tester.test_idor("http://127.0.0.1:9999/no-server", "GET", None);
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_id_returns_correct_name_from_preceding_segment() {
        let params = detect_id_parameters("http://127.0.0.1:3000/api/accounts/55", "GET");
        let p = params.iter().find(|p| p.value == "55").unwrap();
        assert_eq!(p.name, "accounts");
    }

    #[test]
    fn detect_encoded_id_in_path() {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode("user_42");
        let url = format!("http://127.0.0.1:3000/api/tokens/{encoded}");
        let params = detect_id_parameters(&url, "GET");

        let enc_param = params.iter().find(|p| p.id_type == IdType::EncodedId);
        assert!(
            enc_param.is_some(),
            "should detect base64-encoded ID in path"
        );
    }

    #[test]
    fn invalid_url_returns_no_params() {
        let params = detect_id_parameters("not-a-url", "GET");
        assert!(params.is_empty());
    }

    #[test]
    fn query_param_with_id_suffix_detected() {
        let params = detect_id_parameters("http://127.0.0.1:3000/api/data?record_id=77", "GET");
        assert!(!params.is_empty());
        let p = params.iter().find(|p| p.name == "record_id").unwrap();
        assert_eq!(p.value, "77");
    }
}
