use crate::url_pattern_audit::*;

#[test]
fn test_api_detected() {
    let body = "const pattern = new URLPattern({ pathname: '/api/*' });";
    let issues = analyze_url_pattern(body);
    assert!(issues.contains(&UrlPatternIssue::ApiDetected));
}

#[test]
fn test_api_detected_lowercase() {
    let body = "const urlPattern = { pathname: '/books/:id' };";
    let issues = analyze_url_pattern(body);
    assert!(issues.contains(&UrlPatternIssue::ApiDetected));
}

#[test]
fn test_redos_risk() {
    let body = "new URLPattern({ pathname: '/a*b+c{1,10}' });";
    let issues = analyze_url_pattern(body);
    assert!(issues.contains(&UrlPatternIssue::RedosRisk));
}

#[test]
fn test_redos_risk_with_search() {
    let body = "URLPattern({ search: '?q=*&filter=+' });";
    let issues = analyze_url_pattern(body);
    assert!(issues.contains(&UrlPatternIssue::RedosRisk));
}

#[test]
fn test_routing_bypass() {
    let body = "const p = new URLPattern('/admin/*'); if (p.test(url)) { grant(); }";
    let issues = analyze_url_pattern(body);
    assert!(issues.contains(&UrlPatternIssue::RoutingBypass));
}

#[test]
fn test_routing_bypass_exec() {
    let body = "URLPattern.exec(req.url) secure auth";
    let issues = analyze_url_pattern(body);
    assert!(issues.contains(&UrlPatternIssue::RoutingBypass));
}

#[test]
fn test_open_redirect() {
    let body = "window.location = new URLPattern({ protocol: 'https' }).hostname;";
    let issues = analyze_url_pattern(body);
    assert!(issues.contains(&UrlPatternIssue::OpenRedirect));
}

#[test]
fn test_open_redirect_location() {
    let body = "redirect(URLPattern.origin);";
    let issues = analyze_url_pattern(body);
    assert!(issues.contains(&UrlPatternIssue::OpenRedirect));
}

#[test]
fn test_pattern_injection() {
    let body = "new URLPattern({ pathname: userInput });";
    let issues = analyze_url_pattern(body);
    assert!(issues.contains(&UrlPatternIssue::PatternInjection));
}

#[test]
fn test_pattern_injection_param() {
    let body = "URLPattern(request.query.pattern);";
    let issues = analyze_url_pattern(body);
    assert!(issues.contains(&UrlPatternIssue::PatternInjection));
}

#[test]
fn test_no_api() {
    let body = "const url = 'https://example.com/test';";
    let issues = analyze_url_pattern(body);
    assert!(issues.is_empty());
}

#[test]
fn test_severity_values() {
    assert_eq!(url_pattern_severity(&UrlPatternIssue::ApiDetected), 2.0);
    assert_eq!(url_pattern_severity(&UrlPatternIssue::RedosRisk), 7.5);
    assert_eq!(url_pattern_severity(&UrlPatternIssue::RoutingBypass), 7.0);
    assert_eq!(url_pattern_severity(&UrlPatternIssue::OpenRedirect), 6.5);
    assert_eq!(
        url_pattern_severity(&UrlPatternIssue::PatternInjection),
        6.0
    );
}

#[test]
fn test_to_operations() {
    let issues = vec![UrlPatternIssue::ApiDetected, UrlPatternIssue::RedosRisk];
    let mut seq = 100;
    let ops = url_pattern_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 102);
}

#[test]
fn test_display_impl() {
    assert_eq!(UrlPatternIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(UrlPatternIssue::RedosRisk.to_string(), "redos_risk");
    assert_eq!(UrlPatternIssue::RoutingBypass.to_string(), "routing_bypass");
    assert_eq!(UrlPatternIssue::OpenRedirect.to_string(), "open_redirect");
    assert_eq!(
        UrlPatternIssue::PatternInjection.to_string(),
        "pattern_injection"
    );
}

#[test]
fn test_multiple_issues() {
    let body =
        "new URLPattern({ pathname: userInput + '*', search: '?auth=*' }); pattern.test(admin);";
    let issues = analyze_url_pattern(body);
    assert!(issues.len() >= 3);
}

// Security variant tests

#[test]
fn test_wildcard_url_pattern_pathname() {
    let body = "new URLPattern({ pathname: '*' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::WildcardUrlPattern));
}

#[test]
fn test_wildcard_url_pattern_search() {
    let body = "const pattern = new URLPattern({ search: '*' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::WildcardUrlPattern));
}

#[test]
fn test_wildcard_url_pattern_hash() {
    let body = "URLPattern({ hash: '*' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::WildcardUrlPattern));
}

#[test]
fn test_wildcard_url_pattern_no_spaces() {
    let body = "URLPattern({pathname:'*'});";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::WildcardUrlPattern));
}

#[test]
fn test_url_pattern_redos_nested_star() {
    let body = "new URLPattern({ pathname: '(.*)*' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::UrlPatternRedoS));
}

#[test]
fn test_url_pattern_redos_nested_plus() {
    let body = "URLPattern({ search: '(.+)+' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::UrlPatternRedoS));
}

#[test]
fn test_url_pattern_redos_nested_a_star() {
    let body = "const p = new URLPattern({ pathname: '(a*)*' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::UrlPatternRedoS));
}

#[test]
fn test_path_parameter_injection_id() {
    let body = "new URLPattern({ pathname: '/users/:id' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::PathParameterInjection));
}

#[test]
fn test_path_parameter_injection_user_id() {
    let body = "URLPattern({ pathname: '/api/:userId/posts' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::PathParameterInjection));
}

#[test]
fn test_path_parameter_injection_path() {
    let body = "const pattern = new URLPattern({ pathname: '/files/:path' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::PathParameterInjection));
}

#[test]
fn test_path_parameter_injection_with_validate_ok() {
    let body = "new URLPattern({ pathname: '/users/:id' }); validate(id);";
    let issues = analyze_url_pattern_security(body);
    assert!(!issues.contains(&UrlPatternSecurityIssue::PathParameterInjection));
}

#[test]
fn test_path_parameter_injection_with_sanitize_ok() {
    let body = "URLPattern({ pathname: '/api/:userId' }); sanitize(userId);";
    let issues = analyze_url_pattern_security(body);
    assert!(!issues.contains(&UrlPatternSecurityIssue::PathParameterInjection));
}

#[test]
fn test_url_pattern_bypass_percent_2e_2e() {
    let body = "const pattern = new URLPattern({ pathname: '/admin' }); pattern.test('/admin%2e%2e/secret');";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::UrlPatternBypass));
}

#[test]
fn test_url_pattern_bypass_dotdot_percent_2f() {
    let body = "const p = new URLPattern('/admin'); if (p.exec('..%2f/etc/passwd')) { allow(); }";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::UrlPatternBypass));
}

#[test]
fn test_url_pattern_bypass_null_byte() {
    let body =
        "const pattern = new URLPattern({ pathname: '/file.txt' }); pattern.match('/file%00.txt');";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::UrlPatternBypass));
}

#[test]
fn test_missing_path_normalization_dotdot_slash() {
    let body = "new URLPattern({ pathname: '/api/../admin' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::MissingPathNormalization));
}

#[test]
fn test_missing_path_normalization_dot_slash() {
    let body = "URLPattern({ pathname: '/./hidden/path' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::MissingPathNormalization));
}

#[test]
fn test_missing_path_normalization_double_slash() {
    let body = "const p = new URLPattern({ pathname: '//secret//path' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::MissingPathNormalization));
}

#[test]
fn test_missing_path_normalization_with_normalize_ok() {
    let body = "new URLPattern({ pathname: normalize('/../admin') });";
    let issues = analyze_url_pattern_security(body);
    assert!(!issues.contains(&UrlPatternSecurityIssue::MissingPathNormalization));
}

#[test]
fn test_missing_path_normalization_with_resolve_ok() {
    let body = "URLPattern({ pathname: resolve('/./path') });";
    let issues = analyze_url_pattern_security(body);
    assert!(!issues.contains(&UrlPatternSecurityIssue::MissingPathNormalization));
}

#[test]
fn test_url_pattern_cross_origin_protocol() {
    let body = "new URLPattern({ protocol: '*' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::UrlPatternCrossOrigin));
}

#[test]
fn test_url_pattern_cross_origin_hostname() {
    let body = "URLPattern({ hostname: '*' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::UrlPatternCrossOrigin));
}

#[test]
fn test_url_pattern_cross_origin_origin() {
    let body = "const pattern = new URLPattern({ origin: '*' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::UrlPatternCrossOrigin));
}

#[test]
fn test_url_pattern_cross_origin_no_spaces() {
    let body = "URLPattern({protocol:'*'});";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::UrlPatternCrossOrigin));
}

#[test]
fn test_sensitive_path_exposed_internal() {
    let body = "new URLPattern({ pathname: '/internal/debug' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::SensitivePathExposed));
}

#[test]
fn test_sensitive_path_exposed_api_v1_config() {
    let body = "URLPattern({ pathname: '/api/v1/config' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::SensitivePathExposed));
}

#[test]
fn test_sensitive_path_exposed_admin_secret() {
    let body = "const p = new URLPattern({ pathname: '/admin/secret' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::SensitivePathExposed));
}

#[test]
fn test_sensitive_path_exposed_no_issue_without_keywords() {
    let body = "new URLPattern({ pathname: '/api/v1/users' });";
    let issues = analyze_url_pattern_security(body);
    assert!(!issues.contains(&UrlPatternSecurityIssue::SensitivePathExposed));
}

#[test]
fn test_url_pattern_overlap_multiple_id() {
    let body = "new URLPattern({ pathname: '/users/:id' }); new URLPattern({ pathname: '/users/:userId' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::UrlPatternOverlap));
}

#[test]
fn test_url_pattern_overlap_wildcard() {
    let body = "URLPattern({ pathname: '/api/*' }); URLPattern({ pathname: '/api/:id' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::UrlPatternOverlap));
}

#[test]
fn test_url_pattern_overlap_path_star() {
    let body = "const p1 = new URLPattern({ pathname: '/:path*' }); const p2 = new URLPattern({ pathname: '/:slug' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::UrlPatternOverlap));
}

#[test]
fn test_url_pattern_without_auth_admin() {
    let body = "new URLPattern({ pathname: '/admin/users' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::UrlPatternWithoutAuth));
}

#[test]
fn test_url_pattern_without_auth_privileged() {
    let body = "URLPattern({ pathname: '/privileged/dashboard' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::UrlPatternWithoutAuth));
}

#[test]
fn test_url_pattern_without_auth_private() {
    let body = "const pattern = new URLPattern({ pathname: '/private/files' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::UrlPatternWithoutAuth));
}

#[test]
fn test_url_pattern_without_auth_with_authenticate_ok() {
    let body = "new URLPattern({ pathname: '/admin' }); authenticate();";
    let issues = analyze_url_pattern_security(body);
    assert!(!issues.contains(&UrlPatternSecurityIssue::UrlPatternWithoutAuth));
}

#[test]
fn test_url_pattern_without_auth_with_authorize_ok() {
    let body = "URLPattern({ pathname: '/admin/panel' }); authorize(user);";
    let issues = analyze_url_pattern_security(body);
    assert!(!issues.contains(&UrlPatternSecurityIssue::UrlPatternWithoutAuth));
}

#[test]
fn test_url_pattern_without_auth_with_check_auth_ok() {
    let body = "new URLPattern({ pathname: '/private/data' }); checkAuth(req);";
    let issues = analyze_url_pattern_security(body);
    assert!(!issues.contains(&UrlPatternSecurityIssue::UrlPatternWithoutAuth));
}

#[test]
fn test_url_pattern_without_auth_with_require_auth_ok() {
    let body = "URLPattern({ pathname: '/privileged/endpoint' }); requireAuth();";
    let issues = analyze_url_pattern_security(body);
    assert!(!issues.contains(&UrlPatternSecurityIssue::UrlPatternWithoutAuth));
}

#[test]
fn test_url_pattern_wildcard_subdomain_with_space() {
    let body = "new URLPattern({ hostname: '*.example.com' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::UrlPatternWildcardSubdomain));
}

#[test]
fn test_url_pattern_wildcard_subdomain_no_space() {
    let body = "URLPattern({hostname:'*.domain.org'});";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::UrlPatternWildcardSubdomain));
}

#[test]
fn test_url_pattern_wildcard_subdomain_subdomain_key() {
    let body = "const p = new URLPattern({ subdomain: '*' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::UrlPatternWildcardSubdomain));
}

#[test]
fn test_security_severity_values() {
    assert_eq!(
        url_pattern_security_severity(&UrlPatternSecurityIssue::WildcardUrlPattern),
        6.5
    );
    assert_eq!(
        url_pattern_security_severity(&UrlPatternSecurityIssue::UrlPatternRedoS),
        8.5
    );
    assert_eq!(
        url_pattern_security_severity(&UrlPatternSecurityIssue::PathParameterInjection),
        7.5
    );
    assert_eq!(
        url_pattern_security_severity(&UrlPatternSecurityIssue::UrlPatternBypass),
        8.0
    );
    assert_eq!(
        url_pattern_security_severity(&UrlPatternSecurityIssue::MissingPathNormalization),
        7.0
    );
    assert_eq!(
        url_pattern_security_severity(&UrlPatternSecurityIssue::UrlPatternCrossOrigin),
        7.5
    );
    assert_eq!(
        url_pattern_security_severity(&UrlPatternSecurityIssue::SensitivePathExposed),
        6.0
    );
    assert_eq!(
        url_pattern_security_severity(&UrlPatternSecurityIssue::UrlPatternOverlap),
        5.5
    );
    assert_eq!(
        url_pattern_security_severity(&UrlPatternSecurityIssue::UrlPatternWithoutAuth),
        9.0
    );
    assert_eq!(
        url_pattern_security_severity(&UrlPatternSecurityIssue::UrlPatternWildcardSubdomain),
        6.5
    );
}

#[test]
fn test_security_to_operations() {
    let issues = vec![
        UrlPatternSecurityIssue::WildcardUrlPattern,
        UrlPatternSecurityIssue::UrlPatternRedoS,
    ];
    let mut seq = 200;
    let ops = url_pattern_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 202);
}

#[test]
fn test_security_display_impl() {
    assert_eq!(
        UrlPatternSecurityIssue::WildcardUrlPattern.to_string(),
        "wildcard_url_pattern"
    );
    assert_eq!(
        UrlPatternSecurityIssue::UrlPatternRedoS.to_string(),
        "url_pattern_redos"
    );
    assert_eq!(
        UrlPatternSecurityIssue::PathParameterInjection.to_string(),
        "path_parameter_injection"
    );
    assert_eq!(
        UrlPatternSecurityIssue::UrlPatternBypass.to_string(),
        "url_pattern_bypass"
    );
    assert_eq!(
        UrlPatternSecurityIssue::MissingPathNormalization.to_string(),
        "missing_path_normalization"
    );
    assert_eq!(
        UrlPatternSecurityIssue::UrlPatternCrossOrigin.to_string(),
        "url_pattern_cross_origin"
    );
    assert_eq!(
        UrlPatternSecurityIssue::SensitivePathExposed.to_string(),
        "sensitive_path_exposed"
    );
    assert_eq!(
        UrlPatternSecurityIssue::UrlPatternOverlap.to_string(),
        "url_pattern_overlap"
    );
    assert_eq!(
        UrlPatternSecurityIssue::UrlPatternWithoutAuth.to_string(),
        "url_pattern_without_auth"
    );
    assert_eq!(
        UrlPatternSecurityIssue::UrlPatternWildcardSubdomain.to_string(),
        "url_pattern_wildcard_subdomain"
    );
}

#[test]
fn test_security_no_url_pattern() {
    let body = "const url = 'https://example.com/test';";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.is_empty());
}

#[test]
fn test_security_multiple_issues() {
    let body = "new URLPattern({ pathname: '*', hostname: '*', protocol: '*' }); /admin/secret /internal/debug";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.len() >= 3);
}

#[test]
fn test_security_empty_body() {
    let body = "";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.is_empty());
}

#[test]
fn test_wildcard_combined_with_search() {
    let body = "new URLPattern({ pathname: '*', search: '*' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::WildcardUrlPattern));
}

#[test]
fn test_redos_with_multiple_patterns() {
    let body = "URLPattern({ pathname: '(.*)*' }); URLPattern({ search: '(.+)+' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::UrlPatternRedoS));
}

#[test]
fn test_cross_origin_all_wildcards() {
    let body = "new URLPattern({ protocol: '*', hostname: '*', origin: '*' });";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::UrlPatternCrossOrigin));
}

#[test]
fn test_admin_without_any_auth_check() {
    let body = "new URLPattern({ pathname: '/admin/delete-all' }); execute();";
    let issues = analyze_url_pattern_security(body);
    assert!(issues.contains(&UrlPatternSecurityIssue::UrlPatternWithoutAuth));
}
