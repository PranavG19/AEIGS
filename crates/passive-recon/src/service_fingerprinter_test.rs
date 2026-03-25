use super::service_fingerprinter::*;
use std::collections::HashMap;

fn make_response(headers: &[(&str, &str)], body: &str) -> HttpResponseData {
    HttpResponseData {
        status_code: 200,
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        body: body.to_string(),
        url: "https://target.local".to_string(),
    }
}

fn make_error_response(status: u16, body: &str) -> HttpResponseData {
    HttpResponseData {
        status_code: status,
        headers: HashMap::new(),
        body: body.to_string(),
        url: "https://target.local".to_string(),
    }
}

#[test]
fn test_nginx_detection_from_server_header() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(&[("server", "nginx/1.24.0")], "");
    let result = fp.fingerprint(&resp);
    let nginx = result.services.iter().find(|s| s.name == "Nginx");
    assert!(nginx.is_some());
    assert_eq!(nginx.unwrap().confidence, FingerprintConfidence::Definite);
    assert_eq!(nginx.unwrap().version.as_deref(), Some("1.24.0"));
}

#[test]
fn test_apache_detection() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(&[("server", "Apache/2.4.54 (Ubuntu)")], "");
    let result = fp.fingerprint(&resp);
    let apache = result.services.iter().find(|s| s.name == "Apache");
    assert!(apache.is_some());
    assert_eq!(apache.unwrap().version.as_deref(), Some("2.4.54"));
}

#[test]
fn test_iis_detection() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(&[("server", "Microsoft-IIS/10.0")], "");
    let result = fp.fingerprint(&resp);
    assert!(result.services.iter().any(|s| s.name == "IIS"));
}

#[test]
fn test_caddy_detection() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(&[("server", "Caddy")], "");
    let result = fp.fingerprint(&resp);
    assert!(result.services.iter().any(|s| s.name == "Caddy"));
}

#[test]
fn test_cloudflare_cdn_detection() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(&[("cf-ray", "abc123-LAX"), ("server", "cloudflare")], "");
    let result = fp.fingerprint(&resp);
    let cf = result.services.iter().find(|s| s.name == "Cloudflare");
    assert!(cf.is_some());
    assert_eq!(cf.unwrap().category, ServiceCategory::Cdn);
}

#[test]
fn test_cloudfront_cdn_detection() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(&[("x-amz-cf-id", "abc123"), ("server", "CloudFront")], "");
    let result = fp.fingerprint(&resp);
    assert!(result.services.iter().any(|s| s.name == "CloudFront"));
}

#[test]
fn test_akamai_cdn_detection() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(&[("x-akamai-request-id", "12345")], "");
    let result = fp.fingerprint(&resp);
    assert!(result.services.iter().any(|s| s.name == "Akamai"));
}

#[test]
fn test_fastly_cdn_detection() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(&[("x-fastly-request-id", "abc123")], "");
    let result = fp.fingerprint(&resp);
    assert!(result.services.iter().any(|s| s.name == "Fastly"));
}

#[test]
fn test_express_framework_detection() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(&[("x-powered-by", "Express")], "");
    let result = fp.fingerprint(&resp);
    let express = result.services.iter().find(|s| s.name == "Express.js");
    assert!(express.is_some());
    assert_eq!(express.unwrap().category, ServiceCategory::Framework);
}

#[test]
fn test_php_detection_from_header() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(&[("x-powered-by", "PHP/8.2.0")], "");
    let result = fp.fingerprint(&resp);
    assert!(result.services.iter().any(|s| s.name == "PHP"));
}

#[test]
fn test_wordpress_detection_from_body() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(
        &[],
        "<html><link rel='stylesheet' href='/wp-content/themes/theme/style.css'></html>",
    );
    let result = fp.fingerprint(&resp);
    assert!(result.services.iter().any(|s| s.name == "WordPress"));
}

#[test]
fn test_drupal_detection_from_body() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(&[], "<script>Drupal.settings = {};</script>");
    let result = fp.fingerprint(&resp);
    assert!(result.services.iter().any(|s| s.name == "Drupal"));
}

#[test]
fn test_joomla_detection_from_body() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(&[], r#"<meta name="generator" content="Joomla! 4.0" />"#);
    let result = fp.fingerprint(&resp);
    assert!(result.services.iter().any(|s| s.name == "Joomla"));
}

#[test]
fn test_django_detection_from_body() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(
        &[],
        r#"<input type="hidden" name="csrfmiddlewaretoken" value="abc123">"#,
    );
    let result = fp.fingerprint(&resp);
    assert!(result.services.iter().any(|s| s.name == "Django"));
}

#[test]
fn test_nextjs_detection_from_body() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(&[], r#"<div id="__next"><div>App</div></div>"#);
    let result = fp.fingerprint(&resp);
    assert!(result.services.iter().any(|s| s.name == "Next.js"));
}

#[test]
fn test_react_detection_from_body() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(&[], r#"<div data-reactroot="">Content</div>"#);
    let result = fp.fingerprint(&resp);
    assert!(result.services.iter().any(|s| s.name == "React"));
}

#[test]
fn test_cookie_based_php_detection() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(&[("set-cookie", "PHPSESSID=abc123; path=/")], "");
    let result = fp.fingerprint(&resp);
    assert!(result.services.iter().any(|s| s.name == "PHP"));
}

#[test]
fn test_cookie_based_java_detection() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(&[("set-cookie", "JSESSIONID=abc123; path=/")], "");
    let result = fp.fingerprint(&resp);
    assert!(result.services.iter().any(|s| s.name == "Java"));
}

#[test]
fn test_cookie_based_rails_detection() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(
        &[("set-cookie", "_rails_session=encrypted_data; path=/")],
        "",
    );
    let result = fp.fingerprint(&resp);
    assert!(result.services.iter().any(|s| s.name == "Ruby on Rails"));
}

#[test]
fn test_error_page_spring_boot() {
    let fp = ServiceFingerprinter::new();
    let resp = make_error_response(
        500,
        "Whitelabel Error Page\nThis application has no explicit mapping for /error",
    );
    let result = fp.fingerprint(&resp);
    assert!(result.services.iter().any(|s| s.name == "Spring Boot"));
}

#[test]
fn test_error_page_python_traceback() {
    let fp = ServiceFingerprinter::new();
    let resp = make_error_response(
        500,
        "Traceback (most recent call last):\n  File \"app.py\", line 42",
    );
    let result = fp.fingerprint(&resp);
    assert!(result.services.iter().any(|s| s.name == "Python"));
}

#[test]
fn test_error_page_rails() {
    let fp = ServiceFingerprinter::new();
    let resp = make_error_response(404, "ActionController::RoutingError (No route matches)");
    let result = fp.fingerprint(&resp);
    assert!(result.services.iter().any(|s| s.name == "Ruby on Rails"));
}

#[test]
fn test_security_headers_detection() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(
        &[
            ("strict-transport-security", "max-age=31536000"),
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
        ],
        "",
    );
    let result = fp.fingerprint(&resp);
    assert!(
        result
            .security_headers_present
            .contains(&"strict-transport-security".to_string())
    );
    assert!(
        result
            .security_headers_present
            .contains(&"x-content-type-options".to_string())
    );
    assert!(
        result
            .security_headers_missing
            .contains(&"content-security-policy".to_string())
    );
}

#[test]
fn test_os_detection_from_server() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(&[("server", "Apache/2.4.54 (Ubuntu)")], "");
    let result = fp.fingerprint(&resp);
    assert!(result.services.iter().any(|s| s.name == "Ubuntu Linux"));
}

#[test]
fn test_kong_api_gateway() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(&[("x-kong-proxy-latency", "12")], "");
    let result = fp.fingerprint(&resp);
    let kong = result.services.iter().find(|s| s.name == "Kong");
    assert!(kong.is_some());
    assert_eq!(kong.unwrap().category, ServiceCategory::ApiGateway);
}

#[test]
fn test_varnish_cache_detection() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(&[("x-varnish", "123456")], "");
    let result = fp.fingerprint(&resp);
    assert!(result.services.iter().any(|s| s.name == "Varnish"));
}

#[test]
fn test_multi_response_fingerprinting() {
    let fp = ServiceFingerprinter::new();
    let responses = vec![
        make_response(&[("server", "nginx/1.24.0")], ""),
        make_response(
            &[("x-powered-by", "Express")],
            "<div data-reactroot>App</div>",
        ),
        make_response(&[("set-cookie", "connect.sid=abc")], ""),
    ];
    let result = fp.fingerprint_multi(&responses);
    assert!(result.services.iter().any(|s| s.name == "Nginx"));
    assert!(result.services.iter().any(|s| s.name == "Express.js"));
    assert!(result.services.iter().any(|s| s.name == "React"));
}

#[test]
fn test_raw_server_header_captured() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(&[("server", "Apache/2.4.54")], "");
    let result = fp.fingerprint(&resp);
    assert_eq!(result.raw_server_header.as_deref(), Some("Apache/2.4.54"));
}

#[test]
fn test_empty_response() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(&[], "");
    let result = fp.fingerprint(&resp);
    assert!(result.services.is_empty());
    assert!(result.raw_server_header.is_none());
}

#[test]
fn test_confidence_display() {
    assert_eq!(FingerprintConfidence::Definite.to_string(), "definite");
    assert_eq!(FingerprintConfidence::High.to_string(), "high");
    assert_eq!(FingerprintConfidence::Medium.to_string(), "medium");
    assert_eq!(FingerprintConfidence::Low.to_string(), "low");
}

#[test]
fn test_category_display() {
    assert_eq!(ServiceCategory::WebServer.to_string(), "Web Server");
    assert_eq!(ServiceCategory::Framework.to_string(), "Framework");
    assert_eq!(ServiceCategory::Cms.to_string(), "CMS");
    assert_eq!(ServiceCategory::Cdn.to_string(), "CDN");
    assert_eq!(ServiceCategory::Waf.to_string(), "WAF");
}

#[test]
fn test_default_impl() {
    let fp = ServiceFingerprinter::default();
    let resp = make_response(&[], "");
    let result = fp.fingerprint(&resp);
    assert!(result.services.is_empty());
}

#[test]
fn test_haproxy_detection() {
    let fp = ServiceFingerprinter::new();
    let resp = make_response(&[("x-haproxy-server-state", "UP")], "");
    let result = fp.fingerprint(&resp);
    let lb = result.services.iter().find(|s| s.name == "HAProxy");
    assert!(lb.is_some());
    assert_eq!(lb.unwrap().category, ServiceCategory::LoadBalancer);
}
