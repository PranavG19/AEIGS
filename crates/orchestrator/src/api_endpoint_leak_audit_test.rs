use crate::api_endpoint_leak_audit::*;

#[test]
fn empty_body_no_issues() {
    assert!(analyze_api_endpoint_leaks("").is_empty());
}

#[test]
fn no_api_paths_no_issues() {
    let body = r#"<div>Hello World</div>"#;
    assert!(analyze_api_endpoint_leaks(body).is_empty());
}

#[test]
fn internal_api_path_detected() {
    let body = r#"fetch("/api/internal/users")"#;
    let issues = analyze_api_endpoint_leaks(body);
    assert!(issues
        .iter()
        .any(|i| matches!(i, ApiEndpointLeak::InternalApiPath { .. })));
}

#[test]
fn private_api_path_detected() {
    let body = r#"url: "/api/private/config""#;
    let issues = analyze_api_endpoint_leaks(body);
    assert!(issues
        .iter()
        .any(|i| matches!(i, ApiEndpointLeak::InternalApiPath { .. })));
}

#[test]
fn admin_endpoint_detected() {
    let body = r#"href="/admin/settings""#;
    let issues = analyze_api_endpoint_leaks(body);
    assert!(issues
        .iter()
        .any(|i| matches!(i, ApiEndpointLeak::AdminEndpoint { .. })));
}

#[test]
fn debug_endpoint_detected() {
    let body = r#"fetch("/actuator/health")"#;
    let issues = analyze_api_endpoint_leaks(body);
    assert!(issues
        .iter()
        .any(|i| matches!(i, ApiEndpointLeak::DebugEndpoint { .. })));
}

#[test]
fn healthcheck_detected() {
    let body = r#"url = "/healthcheck""#;
    let issues = analyze_api_endpoint_leaks(body);
    assert!(issues
        .iter()
        .any(|i| matches!(i, ApiEndpointLeak::DebugEndpoint { .. })));
}

#[test]
fn metrics_detected() {
    let body = r#""/metrics""#;
    let issues = analyze_api_endpoint_leaks(body);
    assert!(issues
        .iter()
        .any(|i| matches!(i, ApiEndpointLeak::DebugEndpoint { .. })));
}

#[test]
fn graphql_endpoint_detected() {
    let body = r#"fetch("/graphql", { method: "POST" })"#;
    let issues = analyze_api_endpoint_leaks(body);
    assert!(issues
        .iter()
        .any(|i| matches!(i, ApiEndpointLeak::GraphqlEndpoint { .. })));
}

#[test]
fn graphiql_detected() {
    let body = r#"window.location = "/graphiql""#;
    let issues = analyze_api_endpoint_leaks(body);
    assert!(issues
        .iter()
        .any(|i| matches!(i, ApiEndpointLeak::GraphqlEndpoint { .. })));
}

#[test]
fn versioned_api_detected() {
    let body = r#""/api/v2/users""#;
    let issues = analyze_api_endpoint_leaks(body);
    assert!(issues
        .iter()
        .any(|i| matches!(i, ApiEndpointLeak::VersionedEndpoint { .. })));
}

#[test]
fn static_assets_ignored() {
    let body = r#"src="/static/app.js" href="/styles/main.css" src="/img/logo.png""#;
    assert!(analyze_api_endpoint_leaks(body).is_empty());
}

#[test]
fn normal_paths_not_flagged() {
    let body = r#"href="/about" href="/contact" href="/products/123""#;
    assert!(analyze_api_endpoint_leaks(body).is_empty());
}

#[test]
fn single_quote_paths() {
    let body = "fetch('/api/internal/data')";
    let issues = analyze_api_endpoint_leaks(body);
    assert!(issues
        .iter()
        .any(|i| matches!(i, ApiEndpointLeak::InternalApiPath { .. })));
}

#[test]
fn backtick_paths() {
    let body = "url = `/admin/users`";
    let issues = analyze_api_endpoint_leaks(body);
    assert!(issues
        .iter()
        .any(|i| matches!(i, ApiEndpointLeak::AdminEndpoint { .. })));
}

#[test]
fn multiple_issues_same_body() {
    let body = r#"fetch("/api/internal/x"); url="/admin/y"; href="/graphql""#;
    let issues = analyze_api_endpoint_leaks(body);
    assert!(issues.len() >= 3);
}

#[test]
fn dedup_same_path() {
    let body = r#"fetch("/admin/users"); url="/admin/users""#;
    let issues = analyze_api_endpoint_leaks(body);
    let admin_count = issues
        .iter()
        .filter(|i| matches!(i, ApiEndpointLeak::AdminEndpoint { path } if path == "/admin/users"))
        .count();
    assert_eq!(admin_count, 1);
}

#[test]
fn severity_ordering() {
    assert!(
        api_endpoint_leak_severity(&ApiEndpointLeak::AdminEndpoint {
            path: "x".into()
        }) > api_endpoint_leak_severity(&ApiEndpointLeak::DebugEndpoint {
            path: "x".into()
        })
    );
    assert!(
        api_endpoint_leak_severity(&ApiEndpointLeak::DebugEndpoint {
            path: "x".into()
        }) > api_endpoint_leak_severity(&ApiEndpointLeak::VersionedEndpoint {
            path: "x".into()
        })
    );
}

#[test]
fn display_format() {
    let issue = ApiEndpointLeak::InternalApiPath {
        path: "/api/internal/x".into(),
    };
    assert_eq!(issue.to_string(), "internal_api:/api/internal/x");

    let issue = ApiEndpointLeak::GraphqlEndpoint {
        path: "/graphql".into(),
    };
    assert_eq!(issue.to_string(), "graphql_endpoint:/graphql");
}

#[test]
fn to_operations_count() {
    let issues = vec![
        ApiEndpointLeak::AdminEndpoint {
            path: "/admin/x".into(),
        },
        ApiEndpointLeak::DebugEndpoint {
            path: "/debug/y".into(),
        },
    ];
    let mut seq = 0;
    let ops = api_endpoint_leak_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn phpinfo_detected() {
    let body = r#"href="/phpinfo""#;
    let issues = analyze_api_endpoint_leaks(body);
    assert!(issues
        .iter()
        .any(|i| matches!(i, ApiEndpointLeak::DebugEndpoint { .. })));
}
