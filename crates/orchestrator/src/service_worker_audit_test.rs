use crate::service_worker_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_service_worker_usage("", false);
    assert!(issues.is_empty());
}

#[test]
fn no_sw_registration_no_issues() {
    let body = "<script>var x = 1;</script>";
    let issues = analyze_service_worker_usage(body, false);
    assert!(issues.is_empty());
}

#[test]
fn sw_registration_detected() {
    let body = r#"<script>navigator.serviceWorker.register("/sw.js");</script>"#;
    let issues = analyze_service_worker_usage(body, false);
    assert!(issues
        .iter()
        .any(|i| matches!(i, ServiceWorkerIssue::SwRegistered { .. })));
}

#[test]
fn sw_on_http_origin_flagged() {
    let body = r#"<script>navigator.serviceWorker.register("/sw.js");</script>"#;
    let issues = analyze_service_worker_usage(body, true);
    assert!(issues
        .iter()
        .any(|i| *i == ServiceWorkerIssue::SwOnHttpOrigin));
}

#[test]
fn sw_on_https_origin_not_flagged() {
    let body = r#"<script>navigator.serviceWorker.register("/sw.js");</script>"#;
    let issues = analyze_service_worker_usage(body, false);
    assert!(!issues
        .iter()
        .any(|i| *i == ServiceWorkerIssue::SwOnHttpOrigin));
}

#[test]
fn sw_broad_scope_detected() {
    let body = r#"<script>navigator.serviceWorker.register("/sw.js", {scope: "/"});</script>"#;
    let issues = analyze_service_worker_usage(body, false);
    assert!(issues
        .iter()
        .any(|i| matches!(i, ServiceWorkerIssue::SwBroadScope { scope } if scope == "/")));
}

#[test]
fn sw_narrow_scope_not_flagged() {
    let body =
        r#"<script>navigator.serviceWorker.register("/sw.js", {scope: "/app/"});</script>"#;
    let issues = analyze_service_worker_usage(body, false);
    assert!(!issues
        .iter()
        .any(|i| matches!(i, ServiceWorkerIssue::SwBroadScope { .. })));
}

#[test]
fn external_import_detected() {
    let body = r#"importScripts("https://cdn.example.com/lib.js");"#;
    let issues = analyze_service_worker_usage(body, false);
    assert!(issues.iter().any(|i| matches!(
        i,
        ServiceWorkerIssue::SwImportsExternalScript { url }
            if url == "https://cdn.example.com/lib.js"
    )));
}

#[test]
fn local_import_not_flagged() {
    let body = r#"importScripts("/lib/utils.js");"#;
    let issues = analyze_service_worker_usage(body, false);
    assert!(!issues
        .iter()
        .any(|i| matches!(i, ServiceWorkerIssue::SwImportsExternalScript { .. })));
}

#[test]
fn credential_caching_detected() {
    let body = r#"
        caches.open("v1").then(function(cache) {
            return cache.put(request, response);
        });
        // stores authorization header
    "#;
    let issues = analyze_service_worker_usage(body, false);
    assert!(issues
        .iter()
        .any(|i| *i == ServiceWorkerIssue::SwCachesCredentials));
}

#[test]
fn cache_without_credentials_not_flagged() {
    let body = r#"
        caches.open("v1").then(function(cache) {
            return cache.put(request, response);
        });
    "#;
    let issues = analyze_service_worker_usage(body, false);
    assert!(!issues
        .iter()
        .any(|i| *i == ServiceWorkerIssue::SwCachesCredentials));
}

#[test]
fn severity_ordering() {
    assert!(
        service_worker_severity(&ServiceWorkerIssue::SwImportsExternalScript {
            url: "https://x.com/a.js".into()
        }) > service_worker_severity(&ServiceWorkerIssue::SwOnHttpOrigin)
    );
    assert!(
        service_worker_severity(&ServiceWorkerIssue::SwCachesCredentials)
            > service_worker_severity(&ServiceWorkerIssue::SwBroadScope {
                scope: "/".into()
            })
    );
}

#[test]
fn to_operations_produces_entries() {
    let issues = vec![
        ServiceWorkerIssue::SwRegistered {
            scope: "/sw.js".into(),
        },
        ServiceWorkerIssue::SwOnHttpOrigin,
    ];
    let mut seq = 70;
    let ops = service_worker_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 72);
}

#[test]
fn display_variants() {
    assert_eq!(
        ServiceWorkerIssue::SwOnHttpOrigin.to_string(),
        "sw_http_origin"
    );
    assert_eq!(
        ServiceWorkerIssue::SwBroadScope {
            scope: "/".into()
        }
        .to_string(),
        "sw_broad_scope:/"
    );
    assert_eq!(
        ServiceWorkerIssue::SwImportsExternalScript {
            url: "https://x.com/a.js".into()
        }
        .to_string(),
        "sw_external_import:https://x.com/a.js"
    );
}

#[test]
fn multiple_registrations_detected() {
    let body = r#"
        navigator.serviceWorker.register("/sw1.js");
        navigator.serviceWorker.register("/sw2.js");
    "#;
    let issues = analyze_service_worker_usage(body, false);
    let reg_count = issues
        .iter()
        .filter(|i| matches!(i, ServiceWorkerIssue::SwRegistered { .. }))
        .count();
    assert_eq!(reg_count, 2);
}
