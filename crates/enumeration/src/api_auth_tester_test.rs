#[cfg(test)]
mod tests {
    use crate::api_auth_tester::{
        ApiAuthTester, ApiKeyLocation, OAuthScopeTestType, SessionTestType, TokenTestType,
    };

    #[test]
    fn token_tests_cover_all_types() {
        let tester = ApiAuthTester::new();
        let tests = tester.generate_token_tests();

        assert_eq!(tests.len(), 10);

        let types: Vec<_> = tests.iter().map(|t| &t.test_type).collect();
        assert!(types.contains(&&TokenTestType::Expired));
        assert!(types.contains(&&TokenTestType::Malformed));
        assert!(types.contains(&&TokenTestType::Empty));
        assert!(types.contains(&&TokenTestType::Null));
        assert!(types.contains(&&TokenTestType::MissingSignature));
        assert!(types.contains(&&TokenTestType::WrongAlgorithm));
        assert!(types.contains(&&TokenTestType::TamperedPayload));
        assert!(types.contains(&&TokenTestType::InvalidAudience));
        assert!(types.contains(&&TokenTestType::InvalidIssuer));
        assert!(types.contains(&&TokenTestType::FutureNotBefore));
    }

    #[test]
    fn expired_token_has_jwt_structure() {
        let tester = ApiAuthTester::new();
        let tests = tester.generate_token_tests();

        let expired = tests
            .iter()
            .find(|t| t.test_type == TokenTestType::Expired)
            .unwrap();
        let parts: Vec<&str> = expired.token_value.split('.').collect();
        assert_eq!(parts.len(), 3, "Expired JWT should have 3 parts");
        assert_eq!(expired.header_name, "Authorization");
        assert_eq!(expired.header_prefix, "Bearer ");
    }

    #[test]
    fn empty_token_is_empty_string() {
        let tester = ApiAuthTester::new();
        let tests = tester.generate_token_tests();

        let empty = tests
            .iter()
            .find(|t| t.test_type == TokenTestType::Empty)
            .unwrap();
        assert!(empty.token_value.is_empty());
    }

    #[test]
    fn api_key_tests_cover_all_locations() {
        let tester = ApiAuthTester::new();
        let tests = tester.generate_api_key_tests();

        let locations: Vec<_> = tests.iter().map(|t| &t.location).collect();
        assert!(locations.contains(&&ApiKeyLocation::Header));
        assert!(locations.contains(&&ApiKeyLocation::Query));
        assert!(locations.contains(&&ApiKeyLocation::Cookie));

        let per_key_count = 4;
        assert_eq!(tests.len(), 6 * per_key_count);
    }

    #[test]
    fn api_key_oversized_test() {
        let tester = ApiAuthTester::new();
        let tests = tester.generate_api_key_tests();

        let oversized: Vec<_> = tests
            .iter()
            .filter(|t| t.key_value.len() >= 10000)
            .collect();
        assert_eq!(oversized.len(), 6);
    }

    #[test]
    fn custom_api_key_names() {
        let tester = ApiAuthTester::new()
            .with_api_key_names(vec![("X-Custom-Key".to_string(), ApiKeyLocation::Header)]);
        let tests = tester.generate_api_key_tests();

        assert_eq!(tests.len(), 4);
        assert!(tests.iter().all(|t| t.key_name == "X-Custom-Key"));
    }

    #[test]
    fn oauth_scope_tests_cover_all_types() {
        let tester = ApiAuthTester::new();
        let tests = tester.generate_oauth_scope_tests();

        assert_eq!(tests.len(), 5);

        let types: Vec<_> = tests.iter().map(|t| &t.test_type).collect();
        assert!(types.contains(&&OAuthScopeTestType::EscalateToAdmin));
        assert!(types.contains(&&OAuthScopeTestType::AddExtraScopes));
        assert!(types.contains(&&OAuthScopeTestType::RemoveAllScopes));
        assert!(types.contains(&&OAuthScopeTestType::WildcardScope));
        assert!(types.contains(&&OAuthScopeTestType::DuplicateScopes));
    }

    #[test]
    fn empty_scopes_for_remove_all() {
        let tester = ApiAuthTester::new();
        let tests = tester.generate_oauth_scope_tests();

        let remove_all = tests
            .iter()
            .find(|t| t.test_type == OAuthScopeTestType::RemoveAllScopes)
            .unwrap();
        assert!(remove_all.scopes_requested.is_empty());
    }

    #[test]
    fn wildcard_scope_includes_star() {
        let tester = ApiAuthTester::new();
        let tests = tester.generate_oauth_scope_tests();

        let wildcard = tests
            .iter()
            .find(|t| t.test_type == OAuthScopeTestType::WildcardScope)
            .unwrap();
        assert!(wildcard.scopes_requested.contains(&"*".to_string()));
    }

    #[test]
    fn session_tests_cover_all_combinations() {
        let tester = ApiAuthTester::new();
        let tests = tester.generate_session_tests();

        assert_eq!(tests.len(), 5);

        let types: Vec<_> = tests.iter().map(|t| &t.test_type).collect();
        assert!(types.contains(&&SessionTestType::CookieOnly));
        assert!(types.contains(&&SessionTestType::TokenOnly));
        assert!(types.contains(&&SessionTestType::BothCookieAndToken));
        assert!(types.contains(&&SessionTestType::NeitherCookieNorToken));
        assert!(types.contains(&&SessionTestType::MismatchedCookieAndToken));
    }

    #[test]
    fn cookie_only_has_no_token() {
        let tester = ApiAuthTester::new();
        let tests = tester.generate_session_tests();

        let cookie_only = tests
            .iter()
            .find(|t| t.test_type == SessionTestType::CookieOnly)
            .unwrap();
        assert!(cookie_only.cookie_value.is_some());
        assert!(cookie_only.token_value.is_none());
    }

    #[test]
    fn neither_has_nothing() {
        let tester = ApiAuthTester::new();
        let tests = tester.generate_session_tests();

        let neither = tests
            .iter()
            .find(|t| t.test_type == SessionTestType::NeitherCookieNorToken)
            .unwrap();
        assert!(neither.cookie_value.is_none());
        assert!(neither.token_value.is_none());
    }

    #[test]
    fn multi_tenant_tests_default_endpoints() {
        let tester = ApiAuthTester::new();
        let tests = tester.generate_multi_tenant_tests();

        let target_tenant_count = 5;
        let default_endpoint_count = 3;
        assert_eq!(tests.len(), target_tenant_count * default_endpoint_count);

        assert!(tests.iter().all(|t| t.tenant_header == "X-Tenant-ID"));
        assert!(tests.iter().all(|t| t.own_tenant_id == "tenant-001"));
    }

    #[test]
    fn multi_tenant_custom_endpoints() {
        let mut tester = ApiAuthTester::new()
            .with_tenant_header("X-Org-ID")
            .with_own_tenant_id("org-alpha");
        tester.add_target_endpoint("GET", "/api/data");
        tester.add_target_endpoint("POST", "/api/data");

        let tests = tester.generate_multi_tenant_tests();
        let target_tenant_count = 5;
        assert_eq!(tests.len(), target_tenant_count * 2);

        assert!(tests.iter().all(|t| t.tenant_header == "X-Org-ID"));
        assert!(tests.iter().all(|t| t.own_tenant_id == "org-alpha"));
    }

    #[test]
    fn multi_tenant_includes_path_traversal_tenant() {
        let tester = ApiAuthTester::new();
        let tests = tester.generate_multi_tenant_tests();

        let traversal = tests
            .iter()
            .find(|t| t.target_tenant_id.contains(".."))
            .unwrap();
        assert!(traversal.target_tenant_id.contains("../"));
    }

    #[test]
    fn full_test_suite_structure() {
        let tester = ApiAuthTester::new();
        let suite = tester.generate_test_suite();

        assert_eq!(suite.token_tests.len(), 10);
        assert!(!suite.api_key_tests.is_empty());
        assert_eq!(suite.oauth_scope_tests.len(), 5);
        assert_eq!(suite.session_tests.len(), 5);
        assert!(!suite.multi_tenant_tests.is_empty());
    }

    #[test]
    fn default_tester() {
        let tester = ApiAuthTester::default();
        let suite = tester.generate_test_suite();
        assert_eq!(suite.token_tests.len(), 10);
    }
}
