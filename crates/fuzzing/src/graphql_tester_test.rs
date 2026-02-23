#[cfg(test)]
mod tests {
    use std::net::TcpListener as StdTcpListener;

    use axum::Router;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::post;
    use tokio::net::TcpListener;

    use crate::graphql_tester::{
        GraphQlAttack, GraphQlTester, build_alias_query, build_batch_query, build_depth_query,
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
                let listener = TcpListener::from_std(std_listener).unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        });

        std::thread::sleep(std::time::Duration::from_millis(50));
        format!("http://127.0.0.1:{port}")
    }

    async fn batching_handler(body: String) -> impl IntoResponse {
        let parsed: serde_json::Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid json".to_string()),
        };

        if let Some(arr) = parsed.as_array() {
            let results: Vec<serde_json::Value> = arr
                .iter()
                .map(|_| serde_json::json!({"data": {"__typename": "Query"}}))
                .collect();
            return (StatusCode::OK, serde_json::to_string(&results).unwrap());
        }

        (
            StatusCode::OK,
            serde_json::json!({"data": {"__typename": "Query"}}).to_string(),
        )
    }

    async fn no_batching_handler(body: String) -> impl IntoResponse {
        let parsed: serde_json::Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid json".to_string()),
        };

        if parsed.is_array() {
            return (
                StatusCode::BAD_REQUEST,
                serde_json::json!({"errors": [{"message": "Batching is not allowed"}]}).to_string(),
            );
        }

        (
            StatusCode::OK,
            serde_json::json!({"data": {"__typename": "Query"}}).to_string(),
        )
    }

    async fn depth_accepting_handler(body: String) -> impl IntoResponse {
        let parsed: serde_json::Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid json".to_string()),
        };

        if parsed.get("query").is_some() {
            return (
                StatusCode::OK,
                serde_json::json!({"data": {"a": {"a": {"__typename": "Query"}}}}).to_string(),
            );
        }

        (StatusCode::BAD_REQUEST, "missing query".to_string())
    }

    async fn depth_limited_handler(body: String) -> impl IntoResponse {
        let parsed: serde_json::Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid json".to_string()),
        };

        let query = parsed.get("query").and_then(|q| q.as_str()).unwrap_or("");

        let depth = query.matches(" a {").count() + query.matches("{ a {").count();
        if depth > 5 {
            return (
                StatusCode::OK,
                serde_json::json!({"errors": [{"message": "Query depth limit exceeded"}]})
                    .to_string(),
            );
        }

        (
            StatusCode::OK,
            serde_json::json!({"data": {"__typename": "Query"}}).to_string(),
        )
    }

    async fn alias_accepting_handler(body: String) -> impl IntoResponse {
        let parsed: serde_json::Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid json".to_string()),
        };

        let query = parsed.get("query").and_then(|q| q.as_str()).unwrap_or("");

        let mut data = serde_json::Map::new();
        for i in 1..=50 {
            let alias = format!("a{i}");
            if query.contains(&format!("{alias}: __typename")) {
                data.insert(alias, serde_json::json!("Query"));
            }
        }

        (
            StatusCode::OK,
            serde_json::json!({"data": data}).to_string(),
        )
    }

    async fn alias_limited_handler(body: String) -> impl IntoResponse {
        let parsed: serde_json::Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid json".to_string()),
        };

        let query = parsed.get("query").and_then(|q| q.as_str()).unwrap_or("");

        let alias_count = query.matches("__typename").count();
        if alias_count > 5 {
            return (
                StatusCode::OK,
                serde_json::json!({"errors": [{"message": "Too many aliases"}]}).to_string(),
            );
        }

        (
            StatusCode::OK,
            serde_json::json!({"data": {"a1": "Query"}}).to_string(),
        )
    }

    async fn introspection_enabled_handler(body: String) -> impl IntoResponse {
        let parsed: serde_json::Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid json".to_string()),
        };

        let query = parsed.get("query").and_then(|q| q.as_str()).unwrap_or("");

        if query.contains("__schema") {
            let types = serde_json::json!([
                {"name": "Query"},
                {"name": "Mutation"},
                {"name": "String"},
                {"name": "__Schema"},
                {"name": "__Type"},
            ]);
            return (
                StatusCode::OK,
                serde_json::json!({"data": {"__schema": {"types": types}}}).to_string(),
            );
        }

        (
            StatusCode::OK,
            serde_json::json!({"data": {"__typename": "Query"}}).to_string(),
        )
    }

    async fn introspection_disabled_handler(body: String) -> impl IntoResponse {
        let parsed: serde_json::Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid json".to_string()),
        };

        let query = parsed.get("query").and_then(|q| q.as_str()).unwrap_or("");

        if query.contains("__schema") {
            return (
                StatusCode::OK,
                serde_json::json!({"errors": [{"message": "Introspection is not allowed"}]})
                    .to_string(),
            );
        }

        (
            StatusCode::OK,
            serde_json::json!({"data": {"__typename": "Query"}}).to_string(),
        )
    }

    async fn field_suggestion_handler(body: String) -> impl IntoResponse {
        let parsed: serde_json::Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid json".to_string()),
        };

        let query = parsed.get("query").and_then(|q| q.as_str()).unwrap_or("");

        if query.contains("__typoname") {
            return (
                StatusCode::OK,
                serde_json::json!({
                    "errors": [{
                        "message": "Cannot query field \"__typoname\" on type \"Query\". Did you mean \"__typename\"?"
                    }]
                })
                .to_string(),
            );
        }

        (
            StatusCode::OK,
            serde_json::json!({"data": {"__typename": "Query"}}).to_string(),
        )
    }

    async fn no_suggestion_handler(body: String) -> impl IntoResponse {
        let parsed: serde_json::Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid json".to_string()),
        };

        let query = parsed.get("query").and_then(|q| q.as_str()).unwrap_or("");

        if query.contains("__typoname") {
            return (
                StatusCode::OK,
                serde_json::json!({
                    "errors": [{"message": "Unknown field"}]
                })
                .to_string(),
            );
        }

        (
            StatusCode::OK,
            serde_json::json!({"data": {"__typename": "Query"}}).to_string(),
        )
    }

    async fn compliant_graphql_handler(body: String) -> impl IntoResponse {
        let parsed: serde_json::Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid json".to_string()),
        };

        if parsed.is_array() {
            return (
                StatusCode::BAD_REQUEST,
                serde_json::json!({"errors": [{"message": "Batching disabled"}]}).to_string(),
            );
        }

        let query = parsed.get("query").and_then(|q| q.as_str()).unwrap_or("");

        if query.contains("__schema") {
            return (
                StatusCode::OK,
                serde_json::json!({"errors": [{"message": "Introspection disabled"}]}).to_string(),
            );
        }

        let depth = query.matches(" a {").count() + query.matches("{ a {").count();
        if depth > 3 {
            return (
                StatusCode::OK,
                serde_json::json!({"errors": [{"message": "Depth limit exceeded"}]}).to_string(),
            );
        }

        let alias_count = query.matches("__typename").count();
        if alias_count > 5 {
            return (
                StatusCode::OK,
                serde_json::json!({"errors": [{"message": "Alias limit exceeded"}]}).to_string(),
            );
        }

        if query.contains("__typoname") {
            return (
                StatusCode::OK,
                serde_json::json!({"errors": [{"message": "Unknown field"}]}).to_string(),
            );
        }

        (
            StatusCode::OK,
            serde_json::json!({"data": {"__typename": "Query"}}).to_string(),
        )
    }

    #[test]
    fn attack_severity_batching() {
        assert!((GraphQlAttack::BatchingAbuse.severity() - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn attack_severity_depth() {
        assert!((GraphQlAttack::DepthDenialOfService.severity() - 5.5).abs() < f64::EPSILON);
    }

    #[test]
    fn attack_severity_alias() {
        assert!((GraphQlAttack::AliasBruteForce.severity() - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    fn attack_severity_introspection() {
        assert!((GraphQlAttack::IntrospectionEnabled.severity() - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn attack_severity_field_suggestion() {
        assert!((GraphQlAttack::FieldSuggestionLeak.severity() - 2.5).abs() < f64::EPSILON);
    }

    #[test]
    fn attack_display_batching() {
        assert_eq!(GraphQlAttack::BatchingAbuse.to_string(), "batching-abuse");
    }

    #[test]
    fn attack_display_depth() {
        assert_eq!(
            GraphQlAttack::DepthDenialOfService.to_string(),
            "depth-denial-of-service"
        );
    }

    #[test]
    fn attack_display_alias() {
        assert_eq!(
            GraphQlAttack::AliasBruteForce.to_string(),
            "alias-brute-force"
        );
    }

    #[test]
    fn attack_display_introspection() {
        assert_eq!(
            GraphQlAttack::IntrospectionEnabled.to_string(),
            "introspection-enabled"
        );
    }

    #[test]
    fn attack_display_field_suggestion() {
        assert_eq!(
            GraphQlAttack::FieldSuggestionLeak.to_string(),
            "field-suggestion-leak"
        );
    }

    #[test]
    fn build_batch_query_produces_correct_count() {
        let batch = build_batch_query(3);
        let parsed: serde_json::Value = serde_json::from_str(&batch).unwrap();
        assert_eq!(parsed.as_array().unwrap().len(), 3);
    }

    #[test]
    fn build_batch_query_each_item_has_query_field() {
        let batch = build_batch_query(2);
        let parsed: serde_json::Value = serde_json::from_str(&batch).unwrap();
        for item in parsed.as_array().unwrap() {
            assert!(item.get("query").is_some());
        }
    }

    #[test]
    fn build_depth_query_has_correct_nesting() {
        let query = build_depth_query(3);
        assert_eq!(query, "{ a { a { a { __typename } } } }");
    }

    #[test]
    fn build_depth_query_single_level() {
        let query = build_depth_query(1);
        assert_eq!(query, "{ a { __typename } }");
    }

    #[test]
    fn build_alias_query_has_correct_aliases() {
        let query = build_alias_query(3);
        assert!(query.contains("a1: __typename"));
        assert!(query.contains("a2: __typename"));
        assert!(query.contains("a3: __typename"));
    }

    #[test]
    fn build_alias_query_is_valid_graphql_shape() {
        let query = build_alias_query(2);
        assert!(query.starts_with("{ "));
        assert!(query.ends_with(" }"));
    }

    #[test]
    fn detects_batching_abuse() {
        let app = Router::new().route("/graphql", post(batching_handler));
        let base = start_server_background(app);

        let tester = GraphQlTester::new();
        let finding = tester.test_batching(&format!("{base}/graphql"));

        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.attack_type, GraphQlAttack::BatchingAbuse);
        assert!((f.severity - 5.0).abs() < f64::EPSILON);
        assert!(f.evidence.contains("50"));
    }

    #[test]
    fn no_batching_when_server_rejects() {
        let app = Router::new().route("/graphql", post(no_batching_handler));
        let base = start_server_background(app);

        let tester = GraphQlTester::new();
        let finding = tester.test_batching(&format!("{base}/graphql"));
        assert!(finding.is_none());
    }

    #[test]
    fn detects_depth_dos() {
        let app = Router::new().route("/graphql", post(depth_accepting_handler));
        let base = start_server_background(app);

        let tester = GraphQlTester::new();
        let finding = tester.test_depth(&format!("{base}/graphql"));

        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.attack_type, GraphQlAttack::DepthDenialOfService);
        assert!((f.severity - 5.5).abs() < f64::EPSILON);
    }

    #[test]
    fn no_depth_finding_when_limited() {
        let app = Router::new().route("/graphql", post(depth_limited_handler));
        let base = start_server_background(app);

        let tester = GraphQlTester::new();
        let finding = tester.test_depth(&format!("{base}/graphql"));
        assert!(finding.is_none());
    }

    #[test]
    fn detects_alias_bruteforce() {
        let app = Router::new().route("/graphql", post(alias_accepting_handler));
        let base = start_server_background(app);

        let tester = GraphQlTester::new();
        let finding = tester.test_alias_bruteforce(&format!("{base}/graphql"));

        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.attack_type, GraphQlAttack::AliasBruteForce);
        assert!((f.severity - 7.0).abs() < f64::EPSILON);
        assert!(f.evidence.contains("20"));
    }

    #[test]
    fn no_alias_finding_when_limited() {
        let app = Router::new().route("/graphql", post(alias_limited_handler));
        let base = start_server_background(app);

        let tester = GraphQlTester::new();
        let finding = tester.test_alias_bruteforce(&format!("{base}/graphql"));
        assert!(finding.is_none());
    }

    #[test]
    fn detects_introspection_enabled() {
        let app = Router::new().route("/graphql", post(introspection_enabled_handler));
        let base = start_server_background(app);

        let tester = GraphQlTester::new();
        let finding = tester.test_introspection(&format!("{base}/graphql"));

        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.attack_type, GraphQlAttack::IntrospectionEnabled);
        assert!((f.severity - 3.0).abs() < f64::EPSILON);
        assert!(f.evidence.contains("__Schema"));
    }

    #[test]
    fn no_introspection_finding_when_disabled() {
        let app = Router::new().route("/graphql", post(introspection_disabled_handler));
        let base = start_server_background(app);

        let tester = GraphQlTester::new();
        let finding = tester.test_introspection(&format!("{base}/graphql"));
        assert!(finding.is_none());
    }

    #[test]
    fn detects_field_suggestion_leak() {
        let app = Router::new().route("/graphql", post(field_suggestion_handler));
        let base = start_server_background(app);

        let tester = GraphQlTester::new();
        let finding = tester.test_field_suggestion(&format!("{base}/graphql"));

        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.attack_type, GraphQlAttack::FieldSuggestionLeak);
        assert!((f.severity - 2.5).abs() < f64::EPSILON);
        assert!(f.evidence.contains("Did you mean"));
    }

    #[test]
    fn no_suggestion_finding_when_generic_error() {
        let app = Router::new().route("/graphql", post(no_suggestion_handler));
        let base = start_server_background(app);

        let tester = GraphQlTester::new();
        let finding = tester.test_field_suggestion(&format!("{base}/graphql"));
        assert!(finding.is_none());
    }

    #[test]
    fn no_findings_on_compliant_server() {
        let app = Router::new().route("/graphql", post(compliant_graphql_handler));
        let base = start_server_background(app);

        let tester = GraphQlTester::new();
        let findings = tester.test_all(&format!("{base}/graphql"));
        assert!(
            findings.is_empty(),
            "compliant server should produce no findings, got: {findings:?}"
        );
    }

    #[test]
    fn rejects_non_localhost_target() {
        let tester = GraphQlTester::new();
        let findings = tester.test_all("https://example.com/graphql");
        assert!(findings.is_empty());
    }

    #[test]
    fn rejects_empty_endpoint() {
        let tester = GraphQlTester::new();
        let findings = tester.test_all("");
        assert!(findings.is_empty());
    }

    #[test]
    fn rejects_non_localhost_batching() {
        let tester = GraphQlTester::new();
        assert!(
            tester
                .test_batching("https://example.com/graphql")
                .is_none()
        );
    }

    #[test]
    fn rejects_non_localhost_depth() {
        let tester = GraphQlTester::new();
        assert!(tester.test_depth("https://example.com/graphql").is_none());
    }

    #[test]
    fn rejects_non_localhost_alias() {
        let tester = GraphQlTester::new();
        assert!(
            tester
                .test_alias_bruteforce("https://example.com/graphql")
                .is_none()
        );
    }

    #[test]
    fn rejects_non_localhost_introspection() {
        let tester = GraphQlTester::new();
        assert!(
            tester
                .test_introspection("https://example.com/graphql")
                .is_none()
        );
    }

    #[test]
    fn rejects_non_localhost_field_suggestion() {
        let tester = GraphQlTester::new();
        assert!(
            tester
                .test_field_suggestion("https://example.com/graphql")
                .is_none()
        );
    }

    #[test]
    fn test_all_collects_multiple_findings() {
        let app = Router::new().route("/graphql", post(introspection_enabled_handler));
        let base = start_server_background(app);

        let tester = GraphQlTester::new();
        let findings = tester.test_all(&format!("{base}/graphql"));

        let has_introspection = findings
            .iter()
            .any(|f| f.attack_type == GraphQlAttack::IntrospectionEnabled);
        assert!(has_introspection);
    }

    #[test]
    fn finding_endpoint_matches_input() {
        let app = Router::new().route("/graphql", post(batching_handler));
        let base = start_server_background(app);

        let tester = GraphQlTester::new();
        let endpoint = format!("{base}/graphql");
        let finding = tester.test_batching(&endpoint);

        assert!(finding.is_some());
        assert_eq!(finding.unwrap().endpoint, endpoint);
    }

    #[test]
    fn with_client_constructor_works() {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let tester = GraphQlTester::with_client(client);

        let findings = tester.test_all("http://127.0.0.1:9999/no-server");
        assert!(findings.is_empty());
    }

    #[test]
    fn default_constructor_works() {
        let tester = GraphQlTester::default();
        let findings = tester.test_all("http://127.0.0.1:9999/no-server");
        assert!(findings.is_empty());
    }

    #[test]
    fn no_finding_when_server_unreachable() {
        let tester = GraphQlTester::new();
        assert!(
            tester
                .test_batching("http://127.0.0.1:9999/graphql")
                .is_none()
        );
        assert!(tester.test_depth("http://127.0.0.1:9999/graphql").is_none());
        assert!(
            tester
                .test_alias_bruteforce("http://127.0.0.1:9999/graphql")
                .is_none()
        );
        assert!(
            tester
                .test_introspection("http://127.0.0.1:9999/graphql")
                .is_none()
        );
        assert!(
            tester
                .test_field_suggestion("http://127.0.0.1:9999/graphql")
                .is_none()
        );
    }
}
