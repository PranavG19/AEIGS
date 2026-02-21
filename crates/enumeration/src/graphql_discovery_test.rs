#[cfg(test)]
mod tests {
    use crate::graphql_discovery::{
        COMMON_ARGUMENTS, COMMON_MUTATION_FIELDS, COMMON_QUERY_FIELDS, DiscoveryError,
        DiscoveryMethod, GraphQlDiscoveryResult, build_probe_queries, discover_common_fields,
        discover_from_error_responses, extract_fields_from_error, merge_discovery_results,
    };
    use crate::introspection::ParameterLocation;

    #[test]
    fn extract_fields_did_you_mean_single() {
        let error = r#"{
            "errors": [
                {
                    "message": "Did you mean \"users\"?"
                }
            ]
        }"#;
        let fields = extract_fields_from_error(error);
        assert_eq!(fields, vec!["users"]);
    }

    #[test]
    fn extract_fields_cannot_query_field_pattern() {
        let error = r#"{
            "errors": [
                {
                    "message": "Cannot query field \"profile\" on type \"Query\""
                }
            ]
        }"#;
        let fields = extract_fields_from_error(error);
        assert!(fields.contains(&"profile".to_string()));
    }

    #[test]
    fn extract_fields_multiple_suggestions() {
        let error = r#"{
            "errors": [
                {
                    "message": "Unknown field \"usr\". Did you mean \"user\" or \"users\"?"
                }
            ]
        }"#;
        let fields = extract_fields_from_error(error);
        assert!(fields.contains(&"user".to_string()));
        assert!(fields.contains(&"users".to_string()));
        assert!(fields.contains(&"usr".to_string()));
    }

    #[test]
    fn extract_fields_invalid_json_returns_empty() {
        let fields = extract_fields_from_error("not json at all {{{");
        assert!(fields.is_empty());
    }

    #[test]
    fn extract_fields_no_suggestions_returns_empty() {
        let error = r#"{
            "errors": [
                {
                    "message": "Internal server error"
                }
            ]
        }"#;
        let fields = extract_fields_from_error(error);
        assert!(fields.is_empty());
    }

    #[test]
    fn extract_fields_deduplicates() {
        let error = r#"{
            "errors": [
                { "message": "Did you mean \"users\"?" },
                { "message": "Cannot query field \"users\" on type \"Query\"" }
            ]
        }"#;
        let fields = extract_fields_from_error(error);
        assert_eq!(fields.iter().filter(|f| *f == "users").count(), 1);
    }

    #[test]
    fn extract_fields_multiple_errors() {
        let error = r#"{
            "errors": [
                { "message": "Cannot query field \"alpha\" on type \"Query\"" },
                { "message": "Cannot query field \"beta\" on type \"Query\"" }
            ]
        }"#;
        let fields = extract_fields_from_error(error);
        assert!(fields.contains(&"alpha".to_string()));
        assert!(fields.contains(&"beta".to_string()));
    }

    #[test]
    fn extract_fields_ignores_non_identifier_strings() {
        let error = r#"{
            "errors": [
                { "message": "Did you mean \"hello world\"?" }
            ]
        }"#;
        let fields = extract_fields_from_error(error);
        assert!(fields.is_empty());
    }

    #[test]
    fn build_probe_queries_generates_per_field_queries() {
        let fields = &["users", "me"];
        let queries = build_probe_queries(fields);
        assert!(queries.contains(&"{ users }".to_string()));
        assert!(queries.contains(&"{ me }".to_string()));
    }

    #[test]
    fn build_probe_queries_generates_batch_alias_query() {
        let fields = &["users", "me"];
        let queries = build_probe_queries(fields);
        let batch = queries.last().unwrap();
        assert!(batch.contains("f0_users: __typename"));
        assert!(batch.contains("f1_me: __typename"));
        assert!(batch.starts_with("{ "));
        assert!(batch.ends_with(" }"));
    }

    #[test]
    fn build_probe_queries_handles_empty_input() {
        let queries = build_probe_queries(&[]);
        assert!(queries.is_empty());
    }

    #[test]
    fn build_probe_queries_count_is_fields_plus_one() {
        let fields = &["a", "b", "c"];
        let queries = build_probe_queries(fields);
        assert_eq!(queries.len(), fields.len() + 1);
    }

    #[test]
    fn discover_from_error_responses_produces_endpoints() {
        let error1 =
            r#"{ "errors": [{ "message": "Cannot query field \"users\" on type \"Query\"" }] }"#;
        let error2 =
            r#"{ "errors": [{ "message": "Cannot query field \"posts\" on type \"Query\"" }] }"#;
        let result = discover_from_error_responses(&[error1, error2]);
        assert_eq!(result.endpoints.len(), 2);
        assert!(result.endpoints.iter().all(|e| e.path == "/graphql"));
        assert!(result.endpoints.iter().all(|e| e.method == "POST"));
    }

    #[test]
    fn discover_from_error_responses_confidence_is_06() {
        let error =
            r#"{ "errors": [{ "message": "Cannot query field \"users\" on type \"Query\"" }] }"#;
        let result = discover_from_error_responses(&[error]);
        assert!((result.confidence - 0.6).abs() < f64::EPSILON);
    }

    #[test]
    fn discover_from_error_responses_method_is_error_based() {
        let error =
            r#"{ "errors": [{ "message": "Cannot query field \"x\" on type \"Query\"" }] }"#;
        let result = discover_from_error_responses(&[error]);
        assert_eq!(result.method, DiscoveryMethod::ErrorBased);
    }

    #[test]
    fn discover_from_error_responses_no_useful_errors_returns_empty() {
        let error = r#"{ "errors": [{ "message": "Internal server error" }] }"#;
        let result = discover_from_error_responses(&[error]);
        assert!(result.endpoints.is_empty());
    }

    #[test]
    fn discover_common_fields_produces_query_endpoints() {
        let result = discover_common_fields();
        let query_endpoints: Vec<_> = result
            .endpoints
            .iter()
            .filter(|e| {
                e.description
                    .as_ref()
                    .is_some_and(|d| d.starts_with("Query:"))
            })
            .collect();
        assert_eq!(query_endpoints.len(), COMMON_QUERY_FIELDS.len());
    }

    #[test]
    fn discover_common_fields_produces_mutation_endpoints() {
        let result = discover_common_fields();
        let mutation_endpoints: Vec<_> = result
            .endpoints
            .iter()
            .filter(|e| {
                e.description
                    .as_ref()
                    .is_some_and(|d| d.starts_with("Mutation:"))
            })
            .collect();
        assert_eq!(mutation_endpoints.len(), COMMON_MUTATION_FIELDS.len());
    }

    #[test]
    fn discover_common_fields_confidence_is_03() {
        let result = discover_common_fields();
        assert!((result.confidence - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn discover_common_fields_method_is_common_field_brute() {
        let result = discover_common_fields();
        assert_eq!(result.method, DiscoveryMethod::CommonFieldBrute);
    }

    #[test]
    fn discover_common_fields_query_endpoints_have_arguments() {
        let result = discover_common_fields();
        let query_endpoint = result
            .endpoints
            .iter()
            .find(|e| {
                e.description
                    .as_ref()
                    .is_some_and(|d| d.starts_with("Query:"))
            })
            .unwrap();
        assert_eq!(query_endpoint.parameters.len(), COMMON_ARGUMENTS.len());
        assert!(
            query_endpoint
                .parameters
                .iter()
                .all(|p| p.location == ParameterLocation::Body)
        );
    }

    #[test]
    fn discover_common_fields_mutation_endpoints_have_input_argument() {
        let result = discover_common_fields();
        let mutation_endpoint = result
            .endpoints
            .iter()
            .find(|e| {
                e.description
                    .as_ref()
                    .is_some_and(|d| d.starts_with("Mutation:"))
            })
            .unwrap();
        assert_eq!(mutation_endpoint.parameters.len(), 1);
        assert_eq!(mutation_endpoint.parameters[0].name, "input");
        assert_eq!(mutation_endpoint.parameters[0].param_type, "JSON");
    }

    #[test]
    fn merge_discovery_results_deduplicates() {
        let result_a = GraphQlDiscoveryResult {
            method: DiscoveryMethod::ErrorBased,
            endpoints: vec![make_endpoint("Query: users")],
            confidence: 0.6,
        };
        let result_b = GraphQlDiscoveryResult {
            method: DiscoveryMethod::CommonFieldBrute,
            endpoints: vec![make_endpoint("Query: users"), make_endpoint("Query: me")],
            confidence: 0.3,
        };
        let merged = merge_discovery_results(&[result_a, result_b]);
        assert_eq!(merged.endpoints.len(), 2);
    }

    #[test]
    fn merge_discovery_results_picks_max_confidence() {
        let result_a = GraphQlDiscoveryResult {
            method: DiscoveryMethod::ErrorBased,
            endpoints: vec![make_endpoint("Query: users")],
            confidence: 0.6,
        };
        let result_b = GraphQlDiscoveryResult {
            method: DiscoveryMethod::CommonFieldBrute,
            endpoints: vec![make_endpoint("Query: me")],
            confidence: 0.3,
        };
        let merged = merge_discovery_results(&[result_a, result_b]);
        assert!((merged.confidence - 0.6).abs() < f64::EPSILON);
    }

    #[test]
    fn merge_discovery_results_empty_input_returns_empty() {
        let merged = merge_discovery_results(&[]);
        assert!(merged.endpoints.is_empty());
        assert!((merged.confidence - 0.0).abs() < f64::EPSILON);
        assert_eq!(merged.method, DiscoveryMethod::Combined);
    }

    #[test]
    fn merge_discovery_results_method_is_combined() {
        let result = GraphQlDiscoveryResult {
            method: DiscoveryMethod::ErrorBased,
            endpoints: Vec::new(),
            confidence: 0.6,
        };
        let merged = merge_discovery_results(&[result]);
        assert_eq!(merged.method, DiscoveryMethod::Combined);
    }

    #[test]
    fn discovery_error_display_parse() {
        let err = DiscoveryError::Parse("bad response".to_string());
        assert_eq!(err.to_string(), "parse error: bad response");
    }

    #[test]
    fn discovery_error_display_no_fields() {
        let err = DiscoveryError::NoFieldsDiscovered;
        assert_eq!(err.to_string(), "no fields discovered");
    }

    #[test]
    fn discovery_method_debug_derives() {
        assert_eq!(format!("{:?}", DiscoveryMethod::ErrorBased), "ErrorBased");
        assert_eq!(
            format!("{:?}", DiscoveryMethod::CommonFieldBrute),
            "CommonFieldBrute"
        );
        assert_eq!(format!("{:?}", DiscoveryMethod::Combined), "Combined");
    }

    #[test]
    fn discovery_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(DiscoveryError::Parse("test".to_string()));
        assert!(err.to_string().contains("parse error"));
    }

    #[test]
    fn extract_fields_unknown_field_without_suggestions() {
        let error = r#"{
            "errors": [
                { "message": "Unknown field \"bogus\". No suggestions available." }
            ]
        }"#;
        let fields = extract_fields_from_error(error);
        assert!(fields.contains(&"bogus".to_string()));
    }

    #[test]
    fn discover_common_fields_total_endpoint_count() {
        let result = discover_common_fields();
        let expected = COMMON_QUERY_FIELDS.len() + COMMON_MUTATION_FIELDS.len();
        assert_eq!(result.endpoints.len(), expected);
    }

    #[test]
    fn discover_common_fields_required_flag_matches_type_suffix() {
        let result = discover_common_fields();
        let query_endpoint = result
            .endpoints
            .iter()
            .find(|e| {
                e.description
                    .as_ref()
                    .is_some_and(|d| d.starts_with("Query:"))
            })
            .unwrap();
        for param in &query_endpoint.parameters {
            let expected_required = param.param_type.ends_with('!');
            assert_eq!(param.required, expected_required);
        }
    }

    fn make_endpoint(description: &str) -> crate::introspection::IntrospectedEndpoint {
        crate::introspection::IntrospectedEndpoint {
            path: "/graphql".to_string(),
            method: "POST".to_string(),
            parameters: Vec::new(),
            response_type: None,
            description: Some(description.to_string()),
            security_schemes: Vec::new(),
            request_content_types: Vec::new(),
            response_status_codes: Vec::new(),
        }
    }
}
