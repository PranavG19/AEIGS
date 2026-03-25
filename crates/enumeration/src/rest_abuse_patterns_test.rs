#[cfg(test)]
mod tests {
    use crate::rest_abuse_patterns::{AbusePatternCategory, AbusePatternLibrary, Severity};

    #[test]
    fn library_has_all_seven_categories() {
        let lib = AbusePatternLibrary::new();
        let patterns = lib.patterns();

        assert!(patterns.len() >= 7);

        let categories: Vec<_> = patterns.iter().map(|p| &p.category).collect();
        assert!(categories.contains(&&AbusePatternCategory::MassAssignment));
        assert!(categories.contains(&&AbusePatternCategory::BrokenObjectLevelAuth));
        assert!(categories.contains(&&AbusePatternCategory::ExcessiveDataExposure));
        assert!(categories.contains(&&AbusePatternCategory::RateLimitAbuse));
        assert!(categories.contains(&&AbusePatternCategory::BatchEndpointAbuse));
        assert!(categories.contains(&&AbusePatternCategory::HttpMethodOverride));
        assert!(categories.contains(&&AbusePatternCategory::ContentTypeConfusion));
    }

    #[test]
    fn mass_assignment_has_test_cases() {
        let lib = AbusePatternLibrary::new();
        let mass = lib.patterns_by_category(&AbusePatternCategory::MassAssignment);

        assert_eq!(mass.len(), 1);
        assert!(mass[0].test_cases.len() >= 4);
        assert_eq!(mass[0].severity, Severity::High);

        let admin_inject = mass[0]
            .test_cases
            .iter()
            .find(|tc| tc.name == "inject_admin_flag")
            .unwrap();
        assert!(admin_inject.body.as_ref().unwrap().contains("isAdmin"));
        assert_eq!(admin_inject.method, "POST");
    }

    #[test]
    fn bola_has_sequential_and_edge_cases() {
        let lib = AbusePatternLibrary::new();
        let bola = lib.patterns_by_category(&AbusePatternCategory::BrokenObjectLevelAuth);

        assert_eq!(bola.len(), 1);
        assert_eq!(bola[0].severity, Severity::Critical);

        let test_names: Vec<&str> = bola[0]
            .test_cases
            .iter()
            .map(|tc| tc.name.as_str())
            .collect();
        assert!(test_names.contains(&"idor_sequential_id"));
        assert!(test_names.contains(&"idor_zero_id"));
        assert!(test_names.contains(&"idor_negative_id"));
        assert!(test_names.contains(&"idor_delete_other_resource"));
    }

    #[test]
    fn http_method_override_has_multiple_headers() {
        let lib = AbusePatternLibrary::new();
        let overrides = lib.patterns_by_category(&AbusePatternCategory::HttpMethodOverride);

        assert_eq!(overrides.len(), 1);
        assert!(overrides[0].test_cases.len() >= 4);

        let header_override = overrides[0]
            .test_cases
            .iter()
            .find(|tc| tc.name.contains("x_http_method_override"))
            .unwrap();
        assert!(header_override
            .headers
            .contains_key("X-HTTP-Method-Override"));
        assert_eq!(header_override.headers["X-HTTP-Method-Override"], "DELETE");
    }

    #[test]
    fn content_type_confusion_includes_xml() {
        let lib = AbusePatternLibrary::new();
        let confusion = lib.patterns_by_category(&AbusePatternCategory::ContentTypeConfusion);

        assert_eq!(confusion.len(), 1);

        let xml_test = confusion[0]
            .test_cases
            .iter()
            .find(|tc| tc.name == "json_to_xml")
            .unwrap();
        assert!(xml_test.headers["Content-Type"].contains("xml"));
        assert!(xml_test.body.as_ref().unwrap().contains("<?xml"));
    }

    #[test]
    fn batch_abuse_large_batch_has_1000_operations() {
        let lib = AbusePatternLibrary::new();
        let batch = lib.patterns_by_category(&AbusePatternCategory::BatchEndpointAbuse);

        let large_batch = batch[0]
            .test_cases
            .iter()
            .find(|tc| tc.name == "batch_size_abuse")
            .unwrap();
        let body = large_batch.body.as_ref().unwrap();
        let count = body.matches("\"method\"").count();
        assert_eq!(count, 1000);
    }

    #[test]
    fn all_test_cases_aggregation() {
        let lib = AbusePatternLibrary::new();
        let all = lib.all_test_cases();

        let per_category_sum: usize = lib.patterns().iter().map(|p| p.test_cases.len()).sum();
        assert_eq!(all.len(), per_category_sum);
        assert!(all.len() >= 20);
    }

    #[test]
    fn generate_for_post_endpoint() {
        let lib = AbusePatternLibrary::new();
        let cases = lib.generate_for_endpoint("POST", "/api/users");

        assert!(!cases.is_empty());

        let has_mass_assign = cases.iter().any(|c| c.name == "inject_admin_flag");
        assert!(has_mass_assign);

        let has_content_type = cases.iter().any(|c| c.name == "json_to_xml");
        assert!(has_content_type);
    }

    #[test]
    fn generate_for_get_endpoint() {
        let lib = AbusePatternLibrary::new();
        let cases = lib.generate_for_endpoint("GET", "/api/users/123");

        let has_idor = cases.iter().any(|c| c.name == "idor_sequential_id");
        assert!(has_idor);

        let has_mass_assign = cases.iter().any(|c| c.name == "inject_admin_flag");
        assert!(
            !has_mass_assign,
            "GET endpoints should not get POST-only mass assignment tests"
        );
    }

    #[test]
    fn generate_for_delete_endpoint() {
        let lib = AbusePatternLibrary::new();
        let cases = lib.generate_for_endpoint("DELETE", "/api/users/123");

        let has_idor_delete = cases.iter().any(|c| c.name == "idor_delete_other_resource");
        assert!(has_idor_delete);
    }

    #[test]
    fn default_creates_populated_library() {
        let lib = AbusePatternLibrary::default();
        assert!(lib.patterns().len() >= 7);
    }

    #[test]
    fn rate_limit_abuse_includes_ip_rotation() {
        let lib = AbusePatternLibrary::new();
        let rate = lib.patterns_by_category(&AbusePatternCategory::RateLimitAbuse);

        let ip_rotation = rate[0]
            .test_cases
            .iter()
            .find(|tc| tc.name == "ip_rotation_bypass")
            .unwrap();
        assert!(ip_rotation.headers.contains_key("X-Forwarded-For"));
    }

    #[test]
    fn content_type_confusion_charset_override() {
        let lib = AbusePatternLibrary::new();
        let confusion = lib.patterns_by_category(&AbusePatternCategory::ContentTypeConfusion);

        let charset = confusion[0]
            .test_cases
            .iter()
            .find(|tc| tc.name == "charset_override")
            .unwrap();
        assert!(charset.headers["Content-Type"].contains("utf-7"));
    }
}
