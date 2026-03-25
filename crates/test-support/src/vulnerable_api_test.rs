use super::*;
use axum::body::Body;
use tower::ServiceExt;

async fn send_get(router: Router, uri: &str) -> Response {
    let req = axum::extract::Request::builder()
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    router.oneshot(req).await.unwrap()
}

async fn send_post(router: Router, uri: &str, body: &str) -> Response {
    let req = axum::extract::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    router.oneshot(req).await.unwrap()
}

async fn body_string(resp: Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).to_string()
}

#[test]
fn build_creates_32_annotations() {
    let api = VulnerableApi::build();
    assert_eq!(api.annotations().len(), 32);
}

#[test]
fn covers_at_least_25_unique_vuln_classes() {
    let api = VulnerableApi::build();
    let unique = api.unique_vuln_classes();
    assert!(
        unique >= 25,
        "Expected >=25 unique vuln classes, got {unique}"
    );
}

#[test]
fn owasp_coverage_spans_9_categories() {
    let api = VulnerableApi::build();
    let coverage = api.owasp_coverage();
    assert!(
        coverage.len() >= 9,
        "Expected >=9 OWASP categories, got {}",
        coverage.len()
    );
}

#[test]
fn annotations_have_required_fields() {
    let api = VulnerableApi::build();
    for ann in api.annotations() {
        assert!(!ann.endpoint.is_empty(), "Empty endpoint");
        assert!(!ann.method.is_empty(), "Empty method");
        assert!(!ann.description.is_empty(), "Empty description");
        assert!(
            ann.owasp_category.starts_with('A'),
            "OWASP category should start with A: {}",
            ann.owasp_category
        );
        assert!(
            ann.cwe_id.starts_with("CWE-"),
            "CWE should start with CWE-: {}",
            ann.cwe_id
        );
    }
}

#[test]
fn into_router_returns_valid_router() {
    let api = VulnerableApi::build();
    let _router = api.into_router();
}

#[tokio::test]
async fn health_endpoint_responds_ok() {
    let router = VulnerableApi::build().into_router();
    let resp = send_get(router, "/health").await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn sqli_reflects_injection_payload() {
    let router = VulnerableApi::build().into_router();
    let resp = send_get(router, "/api/search?q=%27%20OR%201%3D1--").await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn xss_reflects_input_unescaped() {
    let router = VulnerableApi::build().into_router();
    let resp = send_get(router, "/api/render?name=%3Cscript%3Ealert(1)%3C/script%3E").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(
        body.contains("<script>alert(1)</script>"),
        "XSS payload not reflected: {body}"
    );
}

#[tokio::test]
async fn admin_panel_no_auth_required() {
    let router = VulnerableApi::build().into_router();
    let resp = send_get(router, "/api/admin/users").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("api_key"));
}

#[tokio::test]
async fn ssrf_accepts_internal_urls() {
    let router = VulnerableApi::build().into_router();
    let resp = send_get(
        router,
        "/api/fetch?url=http://169.254.169.254/latest/meta-data/",
    )
    .await;
    let body = body_string(resp).await;
    assert!(body.contains("iam-role"));
}

#[tokio::test]
async fn path_traversal_returns_passwd() {
    let router = VulnerableApi::build().into_router();
    let resp = send_get(router, "/api/files?path=../../../etc/passwd").await;
    let body = body_string(resp).await;
    assert!(body.contains("root:x:0:0"));
}

#[tokio::test]
async fn command_injection_shows_uid() {
    let router = VulnerableApi::build().into_router();
    let resp = send_get(router, "/api/exec?host=localhost;id").await;
    let body = body_string(resp).await;
    assert!(body.contains("uid=0(root)"));
}

#[tokio::test]
async fn secrets_endpoint_leaks_credentials() {
    let router = VulnerableApi::build().into_router();
    let resp = send_get(router, "/api/secrets").await;
    let body = body_string(resp).await;
    assert!(body.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(body.contains("stripe_secret"));
}

#[tokio::test]
async fn debug_endpoint_leaks_stack_trace() {
    let router = VulnerableApi::build().into_router();
    let resp = send_get(router, "/api/debug").await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = body_string(resp).await;
    assert!(body.contains("stack_trace"));
}

#[tokio::test]
async fn xxe_processes_entity_payload() {
    let router = VulnerableApi::build().into_router();
    let resp = send_post(
        router,
        "/api/xml/parse",
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#,
    ).await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = body_string(resp).await;
    assert!(body.contains("entity expansion"));
}

#[tokio::test]
async fn mass_assignment_allows_admin() {
    let router = VulnerableApi::build().into_router();
    let req = axum::extract::Request::builder()
        .method("PUT")
        .uri("/api/mass-assign")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"test","is_admin":true}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let body = body_string(resp).await;
    assert!(body.contains("\"is_admin\":true") || body.contains("\"is_admin\": true"));
}

#[test]
fn severity_distribution_has_criticals_and_highs() {
    let api = VulnerableApi::build();
    let criticals = api
        .annotations()
        .iter()
        .filter(|a| a.severity == Severity::Critical)
        .count();
    let highs = api
        .annotations()
        .iter()
        .filter(|a| a.severity == Severity::High)
        .count();
    assert!(criticals >= 4, "Expected >=4 critical vulns, got {criticals}");
    assert!(highs >= 8, "Expected >=8 high vulns, got {highs}");
}
