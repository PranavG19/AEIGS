use super::idor_analyzer::*;
use aegis_protocol::finding::VulnerabilityClass;

fn ep(path: &str, method: &str, params: &[&str]) -> (String, String, Vec<String>) {
    (
        path.to_string(),
        method.to_string(),
        params.iter().map(|s| s.to_string()).collect(),
    )
}

#[test]
fn rule1_numeric_path_segment_high_likelihood() {
    let endpoints = vec![ep("/api/users/123/orders", "GET", &[])];
    let cases = IdorAnalyzer::analyze_endpoints(&endpoints);
    let numeric = cases.iter().find(|c| c.parameter == "123").unwrap();
    assert_eq!(numeric.likelihood, 0.9);
    assert_eq!(numeric.id_format, IdFormat::SequentialInteger);
}

#[test]
fn rule2_uuid_path_segment_medium_likelihood() {
    let endpoints = vec![ep(
        "/api/orders/550e8400-e29b-41d4-a716-446655440000",
        "GET",
        &[],
    )];
    let cases = IdorAnalyzer::analyze_endpoints(&endpoints);
    let uuid_case = cases
        .iter()
        .find(|c| c.parameter == "550e8400-e29b-41d4-a716-446655440000")
        .unwrap();
    assert_eq!(uuid_case.likelihood, 0.6);
    assert_eq!(uuid_case.id_format, IdFormat::Uuid);
}

#[test]
fn rule3_high_likelihood_id_parameters() {
    let params = ["id", "user_id", "account_id", "order_id"];
    for param in &params {
        let endpoints = vec![ep("/api/resource", "GET", &[param])];
        let cases = IdorAnalyzer::analyze_endpoints(&endpoints);
        let matched = cases.iter().find(|c| c.parameter == *param).unwrap();
        assert_eq!(
            matched.likelihood, 0.85,
            "expected 0.85 for param '{param}'"
        );
    }
}

#[test]
fn rule3_camelcase_id_parameters() {
    let endpoints = vec![ep("/api/resource", "GET", &["userId"])];
    let cases = IdorAnalyzer::analyze_endpoints(&endpoints);
    let matched = cases.iter().find(|c| c.parameter == "userId").unwrap();
    assert_eq!(matched.likelihood, 0.85);
}

#[test]
fn rule4_medium_likelihood_ref_params() {
    let params = ["ref", "code", "token"];
    for param in &params {
        let endpoints = vec![ep("/api/resource", "GET", &[param])];
        let cases = IdorAnalyzer::analyze_endpoints(&endpoints);
        let matched = cases.iter().find(|c| c.parameter == *param).unwrap();
        assert_eq!(matched.likelihood, 0.5, "expected 0.5 for param '{param}'");
    }
}

#[test]
fn rule5_get_user_specific_endpoint() {
    let user_paths = [
        "/api/users/me",
        "/api/account/settings",
        "/api/profile",
        "/api/orders",
        "/api/invoices/latest",
        "/api/documents/search",
        "/api/files",
        "/api/reports/summary",
    ];
    for path in &user_paths {
        let endpoints = vec![ep(path, "GET", &[])];
        let cases = IdorAnalyzer::analyze_endpoints(&endpoints);
        let user_case = cases.iter().find(|c| c.likelihood == 0.8);
        assert!(
            user_case.is_some(),
            "expected user-specific match for GET {path}"
        );
    }
}

#[test]
fn rule5_not_triggered_for_post() {
    let endpoints = vec![ep("/api/users", "POST", &[])];
    let cases = IdorAnalyzer::analyze_endpoints(&endpoints);
    let user_case = cases.iter().find(|c| c.likelihood == 0.8);
    assert!(
        user_case.is_none(),
        "POST should not trigger user-specific GET rule"
    );
}

#[test]
fn rule6_put_on_resource_endpoint() {
    let endpoints = vec![ep("/api/users/123", "PUT", &[])];
    let cases = IdorAnalyzer::analyze_endpoints(&endpoints);
    let state_change = cases
        .iter()
        .find(|c| c.reasoning.contains("state-changing"));
    assert!(state_change.is_some());
    assert_eq!(state_change.unwrap().likelihood, 0.85);
}

#[test]
fn rule6_patch_on_resource_endpoint() {
    let endpoints = vec![ep("/api/orders/{id}", "PATCH", &[])];
    let cases = IdorAnalyzer::analyze_endpoints(&endpoints);
    let state_change = cases
        .iter()
        .find(|c| c.reasoning.contains("state-changing"));
    assert!(state_change.is_some());
}

#[test]
fn rule6_delete_on_resource_endpoint() {
    let endpoints = vec![ep("/api/invoices/:invoice_id", "DELETE", &[])];
    let cases = IdorAnalyzer::analyze_endpoints(&endpoints);
    let state_change = cases
        .iter()
        .find(|c| c.reasoning.contains("state-changing"));
    assert!(state_change.is_some());
}

#[test]
fn rule6_not_triggered_for_get() {
    let endpoints = vec![ep("/api/items/42", "GET", &[])];
    let cases = IdorAnalyzer::analyze_endpoints(&endpoints);
    let state_change = cases
        .iter()
        .find(|c| c.reasoning.contains("state-changing"));
    assert!(
        state_change.is_none(),
        "GET should not trigger state-changing rule"
    );
}

#[test]
fn rule6_not_triggered_without_resource_id() {
    let endpoints = vec![ep("/api/settings", "PUT", &[])];
    let cases = IdorAnalyzer::analyze_endpoints(&endpoints);
    let state_change = cases
        .iter()
        .find(|c| c.reasoning.contains("state-changing"));
    assert!(
        state_change.is_none(),
        "PUT without resource ID pattern should not trigger rule 6"
    );
}

#[test]
fn results_sorted_by_likelihood_descending() {
    let endpoints = vec![
        ep(
            "/api/orders/550e8400-e29b-41d4-a716-446655440000",
            "GET",
            &["ref"],
        ),
        ep("/api/users/123", "PUT", &["id"]),
    ];
    let cases = IdorAnalyzer::analyze_endpoints(&endpoints);
    for window in cases.windows(2) {
        assert!(
            window[0].likelihood >= window[1].likelihood,
            "results not sorted: {} >= {} failed",
            window[0].likelihood,
            window[1].likelihood
        );
    }
}

#[test]
fn empty_endpoints_returns_empty() {
    let cases = IdorAnalyzer::analyze_endpoints(&[]);
    assert!(cases.is_empty());
}

#[test]
fn no_match_for_unrelated_endpoint() {
    let endpoints = vec![ep("/api/health", "GET", &["format"])];
    let cases = IdorAnalyzer::analyze_endpoints(&endpoints);
    assert!(
        cases.is_empty(),
        "health endpoint should not trigger IDOR rules"
    );
}

#[test]
fn deduplication_keeps_highest_likelihood() {
    let endpoints = vec![ep("/api/users/123", "GET", &["id"])];
    let cases = IdorAnalyzer::analyze_endpoints(&endpoints);
    let id_cases: Vec<_> = cases.iter().filter(|c| c.parameter == "id").collect();
    assert_eq!(id_cases.len(), 1, "should deduplicate by (endpoint, param)");
}

#[test]
fn id_format_display() {
    assert_eq!(
        IdFormat::SequentialInteger.to_string(),
        "sequential integer"
    );
    assert_eq!(IdFormat::Uuid.to_string(), "UUID");
    assert_eq!(IdFormat::Slug.to_string(), "slug");
    assert_eq!(IdFormat::Encoded.to_string(), "encoded");
}

#[test]
fn infer_format_token_param() {
    let endpoints = vec![ep("/api/reset", "GET", &["token"])];
    let cases = IdorAnalyzer::analyze_endpoints(&endpoints);
    let token_case = cases.iter().find(|c| c.parameter == "token").unwrap();
    assert_eq!(token_case.id_format, IdFormat::Encoded);
}

#[test]
fn infer_format_slug_param() {
    let endpoints = vec![ep("/api/posts", "GET", &["slug"])];
    let cases = IdorAnalyzer::analyze_endpoints(&endpoints);
    let slug_case = cases.iter().find(|c| c.parameter == "slug").unwrap();
    assert_eq!(slug_case.id_format, IdFormat::Slug);
}

#[test]
fn build_context_xml_structure() {
    let endpoints = vec![ep("/api/users/123", "GET", &[])];
    let findings = vec![(
        VulnerabilityClass::InsecureDirectObjectReference,
        "/api/users/1".to_string(),
    )];
    let context = IdorAnalyzer::build_idor_context(&endpoints, &findings);
    assert!(context.starts_with("<idor_analysis>"));
    assert!(context.ends_with("</idor_analysis>"));
    assert!(context.contains("<endpoints>"));
    assert!(context.contains("</endpoints>"));
    assert!(context.contains("<existing_findings>"));
    assert!(context.contains("</existing_findings>"));
}

#[test]
fn build_context_endpoint_attributes() {
    let endpoints = vec![ep("/api/users/123", "GET", &[])];
    let context = IdorAnalyzer::build_idor_context(&endpoints, &[]);
    assert!(context.contains("path=\"/api/users/123\""));
    assert!(context.contains("method=\"GET\""));
    assert!(context.contains("<idor_likelihood>"));
    assert!(context.contains("<reasoning>"));
}

#[test]
fn build_context_finding_attributes() {
    let findings = vec![(
        VulnerabilityClass::InsecureDirectObjectReference,
        "/api/users/1".to_string(),
    )];
    let context = IdorAnalyzer::build_idor_context(&[], &findings);
    assert!(context.contains("class=\"Insecure Direct Object Reference\""));
    assert!(context.contains("endpoint=\"/api/users/1\""));
}

#[test]
fn build_context_empty_inputs() {
    let context = IdorAnalyzer::build_idor_context(&[], &[]);
    assert!(context.contains("<endpoints>\n    </endpoints>"));
    assert!(context.contains("<existing_findings>\n    </existing_findings>"));
}

#[test]
fn build_context_xml_escaping() {
    let findings = vec![(
        VulnerabilityClass::InsecureDirectObjectReference,
        "/api/users?id=1&admin=true".to_string(),
    )];
    let context = IdorAnalyzer::build_idor_context(&[], &findings);
    assert!(context.contains("&amp;"));
    assert!(!context.contains("&admin"));
}

#[test]
fn suggest_tests_sequential_integer() {
    let cases = vec![IdorTestCase {
        endpoint: "/api/users/123".to_string(),
        method: "GET".to_string(),
        parameter: "123".to_string(),
        id_format: IdFormat::SequentialInteger,
        likelihood: 0.9,
        reasoning: String::new(),
    }];
    let suggestions = IdorAnalyzer::suggest_idor_tests(&cases);
    assert_eq!(suggestions.len(), 1);
    assert!(suggestions[0].contains("incrementing the numeric ID"));
    assert!(suggestions[0].contains("GET /api/users/123"));
}

#[test]
fn suggest_tests_uuid() {
    let cases = vec![IdorTestCase {
        endpoint: "/api/orders/abc-def".to_string(),
        method: "GET".to_string(),
        parameter: "abc-def".to_string(),
        id_format: IdFormat::Uuid,
        likelihood: 0.6,
        reasoning: String::new(),
    }];
    let suggestions = IdorAnalyzer::suggest_idor_tests(&cases);
    assert!(suggestions[0].contains("UUID"));
    assert!(suggestions[0].contains("GET /api/orders/abc-def"));
}

#[test]
fn suggest_tests_slug() {
    let cases = vec![IdorTestCase {
        endpoint: "/api/posts".to_string(),
        method: "GET".to_string(),
        parameter: "slug".to_string(),
        id_format: IdFormat::Slug,
        likelihood: 0.5,
        reasoning: String::new(),
    }];
    let suggestions = IdorAnalyzer::suggest_idor_tests(&cases);
    assert!(suggestions[0].contains("slugs"));
    assert!(suggestions[0].contains("'slug'"));
}

#[test]
fn suggest_tests_encoded() {
    let cases = vec![IdorTestCase {
        endpoint: "/api/reset".to_string(),
        method: "GET".to_string(),
        parameter: "token".to_string(),
        id_format: IdFormat::Encoded,
        likelihood: 0.5,
        reasoning: String::new(),
    }];
    let suggestions = IdorAnalyzer::suggest_idor_tests(&cases);
    assert!(suggestions[0].contains("decode or manipulate"));
    assert!(suggestions[0].contains("'token'"));
}

#[test]
fn suggest_tests_empty_input() {
    let suggestions = IdorAnalyzer::suggest_idor_tests(&[]);
    assert!(suggestions.is_empty());
}

#[test]
fn multiple_rules_on_same_endpoint() {
    let endpoints = vec![ep("/api/users/123", "GET", &["user_id"])];
    let cases = IdorAnalyzer::analyze_endpoints(&endpoints);
    assert!(
        cases.len() >= 2,
        "expected multiple rules to fire on /api/users/123 with user_id param, got {}",
        cases.len()
    );
}

#[test]
fn method_preserved_in_test_case() {
    let endpoints = vec![ep("/api/users/123", "DELETE", &[])];
    let cases = IdorAnalyzer::analyze_endpoints(&endpoints);
    for case in &cases {
        assert_eq!(case.method, "DELETE");
    }
}

#[test]
fn params_attribute_in_xml_when_present() {
    let endpoints = vec![ep("/api/resource", "GET", &["user_id"])];
    let context = IdorAnalyzer::build_idor_context(&endpoints, &[]);
    assert!(
        context.contains("params=\"user_id\""),
        "expected params attribute in XML"
    );
}

#[test]
fn no_params_attribute_when_empty_parameter() {
    let endpoints = vec![ep("/api/users/profile", "GET", &[])];
    let context = IdorAnalyzer::build_idor_context(&endpoints, &[]);
    assert!(
        !context.contains("params=\"\""),
        "should not emit empty params attribute"
    );
}
