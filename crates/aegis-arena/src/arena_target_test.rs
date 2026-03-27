use super::*;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use tower::ServiceExt;

fn test_router() -> Router {
    let (router, _log) = build_arena_router("CTF{test_flag_123}".to_string(), vec![]);
    router
}

fn router_with_patches(patches: Vec<PatchRule>) -> Router {
    let (router, _log) = build_arena_router("CTF{test_flag_123}".to_string(), patches);
    router
}

#[tokio::test]
async fn search_sqli_leaks_flag() {
    let app = test_router();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/search?q=%27%20OR%201%3D1%20--")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("CTF{test_flag_123}"), "SQLi should leak the flag");
}

#[tokio::test]
async fn search_normal_no_flag() {
    let app = test_router();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/search?q=shoes")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let text = String::from_utf8_lossy(&body);
    assert!(!text.contains("CTF{"), "Normal query should not leak flag");
}

#[tokio::test]
async fn login_sqli_returns_flag() {
    let app = test_router();
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"username":"admin' OR '1'='1","password":"x"}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("CTF{test_flag_123}"), "SQLi login should leak flag");
}

#[tokio::test]
async fn profile_idor_leaks_flag() {
    let app = test_router();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/profile/999")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("CTF{test_flag_123}"), "IDOR should leak flag in secret_note");
}

#[tokio::test]
async fn file_path_traversal_leaks_flag() {
    let app = test_router();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/file?path=../../../etc/passwd")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("CTF{test_flag_123}"), "LFI should leak flag");
}

#[tokio::test]
async fn template_ssti_leaks_flag() {
    let app = test_router();
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/template")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"template":"{{config}}"}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("CTF{test_flag_123}"), "SSTI should leak flag");
}

#[tokio::test]
async fn admin_jwt_alg_none_bypass() {
    let app = test_router();
    // JWT with alg:none — header: {"alg":"none","typ":"JWT"} base64url = eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
    // payload: {"user":"admin","role":"admin"} base64url = eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ
    let token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.";
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("Admin Control Panel"), "JWT alg:none should grant admin");
}

#[tokio::test]
async fn flag_endpoint_requires_auth() {
    let app = test_router();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/flag")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn flag_endpoint_returns_flag_with_jwt() {
    let app = test_router();
    let token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.";
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/flag")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("CTF{test_flag_123}"), "/flag should return the flag");
}

#[tokio::test]
async fn health_always_200() {
    let app = test_router();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn patch_blocks_sqli() {
    let patches = vec![PatchRule::new("/search", "OR ", false)];
    let app = router_with_patches(patches);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/search?q=%27%20OR%201%3D1%20--")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("Blocked"), "Patch should block SQLi");
}

#[tokio::test]
async fn patch_blocks_lfi() {
    let patches = vec![PatchRule::new("/file", "..", false)];
    let app = router_with_patches(patches);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/file?path=../../../etc/passwd")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn patch_does_not_block_health() {
    let patches = vec![
        PatchRule::new("/search", "OR", false),
        PatchRule::new("/file", "..", false),
    ];
    let app = router_with_patches(patches);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn regex_patch_blocks_sql_keywords() {
    let patches = vec![PatchRule::new(
        "/search",
        r"(?i)(union|select|insert|drop|delete|update)\s",
        true,
    )];
    let app = router_with_patches(patches);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/search?q=%27%20UNION%20SELECT%20*%20FROM%20users%20--")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn patch_rule_matches_logic() {
    let rule = PatchRule::new("/search", "OR ", false);
    assert!(rule.matches("/search", "/search?q=' OR 1=1"));
    assert!(!rule.matches("/file", "/file?path=../etc/passwd"));
    assert!(!rule.matches("/search", "/search?q=normal"));
}

#[tokio::test]
async fn comment_stored_xss() {
    let (router, _log) = build_arena_router("CTF{xss_test}".to_string(), vec![]);

    // Store a comment with XSS
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/comment")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"comment":"<script>alert('xss')</script>"}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
}
