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
