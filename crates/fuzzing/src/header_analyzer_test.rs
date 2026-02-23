#[cfg(test)]
mod tests {
    use crate::header_analyzer::{HeaderIssue, SecurityHeaderAnalyzer};

    fn h(name: &str, value: &str) -> (String, String) {
        (name.to_string(), value.to_string())
    }

    fn full_compliant_headers() -> Vec<(String, String)> {
        vec![
            h(
                "Strict-Transport-Security",
                "max-age=63072000; includeSubDomains",
            ),
            h("Content-Security-Policy", "default-src 'self'"),
            h("X-Frame-Options", "DENY"),
            h("X-Content-Type-Options", "nosniff"),
            h("Referrer-Policy", "strict-origin-when-cross-origin"),
            h("Permissions-Policy", "geolocation=(), camera=()"),
        ]
    }

    #[test]
    fn no_findings_for_fully_compliant_headers() {
        let findings = SecurityHeaderAnalyzer::analyze_response_headers(&full_compliant_headers());
        assert!(
            findings.is_empty(),
            "expected no findings, got: {findings:?}"
        );
    }

    #[test]
    fn missing_hsts_detected() {
        let findings = SecurityHeaderAnalyzer::analyze_response_headers(&[]);
        let hsts = findings
            .iter()
            .find(|f| f.header_name == "Strict-Transport-Security")
            .unwrap();
        assert_eq!(hsts.issue, HeaderIssue::Missing);
        assert!((hsts.severity - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn weak_hsts_short_max_age() {
        let headers = vec![h("Strict-Transport-Security", "max-age=86400")];
        let findings = SecurityHeaderAnalyzer::analyze_response_headers(&headers);
        let hsts = findings
            .iter()
            .find(|f| f.header_name == "Strict-Transport-Security")
            .unwrap();
        assert!(matches!(&hsts.issue, HeaderIssue::Weak(reason) if reason.contains("86400")));
        assert!((hsts.severity - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn hsts_exactly_one_year_is_acceptable() {
        let headers = vec![h("Strict-Transport-Security", "max-age=31536000")];
        let findings = SecurityHeaderAnalyzer::analyze_response_headers(&headers);
        assert!(
            !findings
                .iter()
                .any(|f| f.header_name == "Strict-Transport-Security"),
            "max-age=31536000 should be accepted"
        );
    }

    #[test]
    fn hsts_case_insensitive_lookup() {
        let headers = vec![h("strict-transport-security", "max-age=63072000")];
        let findings = SecurityHeaderAnalyzer::analyze_response_headers(&headers);
        assert!(
            !findings
                .iter()
                .any(|f| f.header_name == "Strict-Transport-Security")
        );
    }

    #[test]
    fn missing_csp_detected() {
        let findings = SecurityHeaderAnalyzer::analyze_response_headers(&[]);
        let csp = findings
            .iter()
            .find(|f| f.header_name == "Content-Security-Policy")
            .unwrap();
        assert_eq!(csp.issue, HeaderIssue::Missing);
        assert!((csp.severity - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn weak_csp_unsafe_inline() {
        let headers = vec![h(
            "Content-Security-Policy",
            "default-src 'self' 'unsafe-inline'",
        )];
        let findings = SecurityHeaderAnalyzer::analyze_response_headers(&headers);
        let csp = findings
            .iter()
            .find(|f| f.header_name == "Content-Security-Policy")
            .unwrap();
        assert!(matches!(&csp.issue, HeaderIssue::Weak(r) if r.contains("unsafe-inline")));
    }

    #[test]
    fn weak_csp_unsafe_eval() {
        let headers = vec![h("Content-Security-Policy", "script-src 'unsafe-eval'")];
        let findings = SecurityHeaderAnalyzer::analyze_response_headers(&headers);
        let csp = findings
            .iter()
            .find(|f| f.header_name == "Content-Security-Policy")
            .unwrap();
        assert!(matches!(&csp.issue, HeaderIssue::Weak(r) if r.contains("unsafe-eval")));
    }

    #[test]
    fn csp_with_both_unsafe_directives_produces_two_findings() {
        let headers = vec![h(
            "Content-Security-Policy",
            "default-src 'unsafe-inline' 'unsafe-eval'",
        )];
        let findings = SecurityHeaderAnalyzer::analyze_response_headers(&headers);
        let csp_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.header_name == "Content-Security-Policy")
            .collect();
        assert_eq!(csp_findings.len(), 2);
    }

    #[test]
    fn missing_x_frame_options_detected() {
        let findings = SecurityHeaderAnalyzer::analyze_response_headers(&[]);
        let xfo = findings
            .iter()
            .find(|f| f.header_name == "X-Frame-Options")
            .unwrap();
        assert_eq!(xfo.issue, HeaderIssue::Missing);
        assert!((xfo.severity - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn x_frame_options_deny_is_valid() {
        let headers = vec![h("X-Frame-Options", "DENY")];
        let findings = SecurityHeaderAnalyzer::analyze_response_headers(&headers);
        assert!(!findings.iter().any(|f| f.header_name == "X-Frame-Options"));
    }

    #[test]
    fn x_frame_options_sameorigin_is_valid() {
        let headers = vec![h("X-Frame-Options", "SAMEORIGIN")];
        let findings = SecurityHeaderAnalyzer::analyze_response_headers(&headers);
        assert!(!findings.iter().any(|f| f.header_name == "X-Frame-Options"));
    }

    #[test]
    fn x_frame_options_case_insensitive_value() {
        let headers = vec![h("X-Frame-Options", "deny")];
        let findings = SecurityHeaderAnalyzer::analyze_response_headers(&headers);
        assert!(!findings.iter().any(|f| f.header_name == "X-Frame-Options"));
    }

    #[test]
    fn x_frame_options_invalid_value_flagged() {
        let headers = vec![h("X-Frame-Options", "ALLOW-FROM https://example.com")];
        let findings = SecurityHeaderAnalyzer::analyze_response_headers(&headers);
        let xfo = findings
            .iter()
            .find(|f| f.header_name == "X-Frame-Options")
            .unwrap();
        assert!(matches!(&xfo.issue, HeaderIssue::Weak(_)));
    }

    #[test]
    fn missing_x_content_type_options_detected() {
        let findings = SecurityHeaderAnalyzer::analyze_response_headers(&[]);
        let xcto = findings
            .iter()
            .find(|f| f.header_name == "X-Content-Type-Options")
            .unwrap();
        assert_eq!(xcto.issue, HeaderIssue::Missing);
        assert!((xcto.severity - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn x_content_type_options_nosniff_is_valid() {
        let headers = vec![h("X-Content-Type-Options", "nosniff")];
        let findings = SecurityHeaderAnalyzer::analyze_response_headers(&headers);
        assert!(
            !findings
                .iter()
                .any(|f| f.header_name == "X-Content-Type-Options")
        );
    }

    #[test]
    fn x_content_type_options_wrong_value_flagged() {
        let headers = vec![h("X-Content-Type-Options", "nope")];
        let findings = SecurityHeaderAnalyzer::analyze_response_headers(&headers);
        let xcto = findings
            .iter()
            .find(|f| f.header_name == "X-Content-Type-Options")
            .unwrap();
        assert!(matches!(&xcto.issue, HeaderIssue::Weak(r) if r.contains("nope")));
    }

    #[test]
    fn missing_referrer_policy_detected() {
        let findings = SecurityHeaderAnalyzer::analyze_response_headers(&[]);
        let rp = findings
            .iter()
            .find(|f| f.header_name == "Referrer-Policy")
            .unwrap();
        assert_eq!(rp.issue, HeaderIssue::Missing);
        assert!((rp.severity - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn referrer_policy_valid_values_accepted() {
        for policy in &[
            "no-referrer",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
        ] {
            let headers = vec![h("Referrer-Policy", policy)];
            let findings = SecurityHeaderAnalyzer::analyze_response_headers(&headers);
            assert!(
                !findings.iter().any(|f| f.header_name == "Referrer-Policy"),
                "'{policy}' should be accepted"
            );
        }
    }

    #[test]
    fn referrer_policy_permissive_value_flagged() {
        let headers = vec![h("Referrer-Policy", "unsafe-url")];
        let findings = SecurityHeaderAnalyzer::analyze_response_headers(&headers);
        let rp = findings
            .iter()
            .find(|f| f.header_name == "Referrer-Policy")
            .unwrap();
        assert!(matches!(&rp.issue, HeaderIssue::Weak(r) if r.contains("unsafe-url")));
    }

    #[test]
    fn missing_permissions_policy_detected() {
        let findings = SecurityHeaderAnalyzer::analyze_response_headers(&[]);
        let pp = findings
            .iter()
            .find(|f| f.header_name == "Permissions-Policy")
            .unwrap();
        assert_eq!(pp.issue, HeaderIssue::Missing);
        assert!((pp.severity - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn permissions_policy_any_value_clears_finding() {
        let headers = vec![h("Permissions-Policy", "camera=()")];
        let findings = SecurityHeaderAnalyzer::analyze_response_headers(&headers);
        assert!(
            !findings
                .iter()
                .any(|f| f.header_name == "Permissions-Policy")
        );
    }

    #[test]
    fn all_six_missing_headers_detected_from_empty_response() {
        let findings = SecurityHeaderAnalyzer::analyze_response_headers(&[]);
        assert_eq!(findings.len(), 6);
        let names: Vec<&str> = findings.iter().map(|f| f.header_name.as_str()).collect();
        assert!(names.contains(&"Strict-Transport-Security"));
        assert!(names.contains(&"Content-Security-Policy"));
        assert!(names.contains(&"X-Frame-Options"));
        assert!(names.contains(&"X-Content-Type-Options"));
        assert!(names.contains(&"Referrer-Policy"));
        assert!(names.contains(&"Permissions-Policy"));
    }

    #[test]
    fn cookie_missing_secure_flag() {
        let cookies = vec!["session=abc123; Path=/; HttpOnly; SameSite=Strict".to_string()];
        let findings = SecurityHeaderAnalyzer::analyze_cookies(&cookies);
        assert_eq!(findings.len(), 1);
        assert!(matches!(&findings[0].issue, HeaderIssue::Weak(r) if r.contains("Secure")));
        assert!((findings[0].severity - 4.0).abs() < f64::EPSILON);
    }

    #[test]
    fn cookie_missing_httponly_flag() {
        let cookies = vec!["session=abc123; Secure; SameSite=Strict".to_string()];
        let findings = SecurityHeaderAnalyzer::analyze_cookies(&cookies);
        assert_eq!(findings.len(), 1);
        assert!(matches!(&findings[0].issue, HeaderIssue::Weak(r) if r.contains("HttpOnly")));
        assert!((findings[0].severity - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn cookie_missing_samesite_attribute() {
        let cookies = vec!["session=abc123; Secure; HttpOnly".to_string()];
        let findings = SecurityHeaderAnalyzer::analyze_cookies(&cookies);
        assert_eq!(findings.len(), 1);
        assert!(matches!(&findings[0].issue, HeaderIssue::Weak(r) if r.contains("SameSite")));
        assert!((findings[0].severity - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn cookie_all_flags_present_no_findings() {
        let cookies = vec!["session=abc123; Secure; HttpOnly; SameSite=Strict".to_string()];
        let findings = SecurityHeaderAnalyzer::analyze_cookies(&cookies);
        assert!(findings.is_empty());
    }

    #[test]
    fn cookie_missing_all_flags_produces_three_findings() {
        let cookies = vec!["token=xyz".to_string()];
        let findings = SecurityHeaderAnalyzer::analyze_cookies(&cookies);
        assert_eq!(findings.len(), 3);
    }

    #[test]
    fn multiple_cookies_analyzed_independently() {
        let cookies = vec![
            "good=val; Secure; HttpOnly; SameSite=Lax".to_string(),
            "bad=val".to_string(),
        ];
        let findings = SecurityHeaderAnalyzer::analyze_cookies(&cookies);
        assert_eq!(findings.len(), 3);
        assert!(findings.iter().all(|f| f.description.contains("bad")));
    }

    #[test]
    fn empty_cookies_no_findings() {
        let findings = SecurityHeaderAnalyzer::analyze_cookies(&[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn server_header_with_version_detected() {
        let headers = vec![h("Server", "Apache/2.4.41")];
        let findings = SecurityHeaderAnalyzer::analyze_info_disclosure(&headers);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].header_name, "Server");
        assert!((findings[0].severity - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn server_header_without_version_not_flagged() {
        let headers = vec![h("Server", "Apache")];
        let findings = SecurityHeaderAnalyzer::analyze_info_disclosure(&headers);
        assert!(findings.is_empty());
    }

    #[test]
    fn nginx_version_detected() {
        let headers = vec![h("Server", "nginx/1.18.0")];
        let findings = SecurityHeaderAnalyzer::analyze_info_disclosure(&headers);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("nginx/1.18.0"));
    }

    #[test]
    fn x_powered_by_always_flagged() {
        let headers = vec![h("X-Powered-By", "Express")];
        let findings = SecurityHeaderAnalyzer::analyze_info_disclosure(&headers);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].header_name, "X-Powered-By");
        assert!((findings[0].severity - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn x_aspnet_version_flagged() {
        let headers = vec![h("X-AspNet-Version", "4.0.30319")];
        let findings = SecurityHeaderAnalyzer::analyze_info_disclosure(&headers);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].header_name, "X-AspNet-Version");
        assert!((findings[0].severity - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn x_debug_token_flagged_as_medium() {
        let headers = vec![h("X-Debug-Token", "abc123")];
        let findings = SecurityHeaderAnalyzer::analyze_info_disclosure(&headers);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].header_name, "X-Debug-Token");
        assert!((findings[0].severity - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn info_disclosure_no_findings_for_clean_headers() {
        let headers = vec![
            h("Content-Type", "text/html"),
            h("Cache-Control", "no-store"),
        ];
        let findings = SecurityHeaderAnalyzer::analyze_info_disclosure(&headers);
        assert!(findings.is_empty());
    }

    #[test]
    fn info_disclosure_multiple_leaky_headers() {
        let headers = vec![
            h("Server", "nginx/1.18.0"),
            h("X-Powered-By", "PHP/8.0"),
            h("X-Debug-Token", "debug-abc"),
        ];
        let findings = SecurityHeaderAnalyzer::analyze_info_disclosure(&headers);
        assert_eq!(findings.len(), 3);
    }

    #[test]
    fn analyze_all_combines_all_analyzers() {
        let headers = vec![h("X-Powered-By", "Express")];
        let cookies = vec!["session=abc".to_string()];
        let findings = SecurityHeaderAnalyzer::analyze_all(&headers, &cookies);

        let has_missing_headers = findings.iter().any(|f| f.issue == HeaderIssue::Missing);
        let has_cookie_findings = findings.iter().any(|f| f.header_name == "Set-Cookie");
        let has_info_disclosure = findings.iter().any(|f| f.header_name == "X-Powered-By");

        assert!(has_missing_headers);
        assert!(has_cookie_findings);
        assert!(has_info_disclosure);
    }

    #[test]
    fn analyze_all_no_findings_for_fully_secure_response() {
        let headers = full_compliant_headers();
        let cookies = vec!["session=abc; Secure; HttpOnly; SameSite=Strict".to_string()];
        let findings = SecurityHeaderAnalyzer::analyze_all(&headers, &cookies);
        assert!(
            findings.is_empty(),
            "expected no findings, got: {findings:?}"
        );
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let headers = vec![
            h("CONTENT-SECURITY-POLICY", "default-src 'self'"),
            h("x-frame-options", "DENY"),
            h("X-CONTENT-TYPE-OPTIONS", "nosniff"),
        ];
        let findings = SecurityHeaderAnalyzer::analyze_response_headers(&headers);
        assert!(
            !findings
                .iter()
                .any(|f| f.header_name == "Content-Security-Policy"),
            "CSP should be found case-insensitively"
        );
        assert!(
            !findings.iter().any(|f| f.header_name == "X-Frame-Options"),
            "XFO should be found case-insensitively"
        );
        assert!(
            !findings
                .iter()
                .any(|f| f.header_name == "X-Content-Type-Options"),
            "XCTO should be found case-insensitively"
        );
    }

    #[test]
    fn hsts_with_extra_directives_parsed_correctly() {
        let headers = vec![h(
            "Strict-Transport-Security",
            "max-age=63072000; includeSubDomains; preload",
        )];
        let findings = SecurityHeaderAnalyzer::analyze_response_headers(&headers);
        assert!(
            !findings
                .iter()
                .any(|f| f.header_name == "Strict-Transport-Security")
        );
    }

    #[test]
    fn cookie_flags_case_insensitive() {
        let cookies = vec!["id=val; SECURE; HTTPONLY; SAMESITE=Lax".to_string()];
        let findings = SecurityHeaderAnalyzer::analyze_cookies(&cookies);
        assert!(findings.is_empty());
    }

    #[test]
    fn server_header_slash_but_no_version_number() {
        let headers = vec![h("Server", "custom/build-info")];
        let findings = SecurityHeaderAnalyzer::analyze_info_disclosure(&headers);
        assert!(findings.is_empty());
    }

    #[test]
    fn info_disclosure_header_names_are_case_insensitive() {
        let headers = vec![h("x-powered-by", "Express")];
        let findings = SecurityHeaderAnalyzer::analyze_info_disclosure(&headers);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].header_name, "X-Powered-By");
    }
}
