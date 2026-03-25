use super::js_bundle_analyzer::*;

fn sample_bundle() -> String {
    r#"
// webpack bundle
(window.webpackJsonp = window.webpackJsonp || []).push([[0], {
    "vendors": "abc123def456",
    "main": "789abc012345"
}]);

function loadData() {
    fetch("/api/v2/users/profile")
    axios.get("/api/v2/orders")
    axios.post("/api/v2/payments")
}

var config = {
    apiKey: "AKIAIOSFODNN7REALKEY1",
    dbUrl: "postgres://admin:s3cret@db.corp:5432/prod",
    stripeKey: "sk_live_abcdef1234567890abcdef12",
    internalApi: "https://api.corp.internal/v1/service",
};

const routes = [
    { path: "/admin/settings", component: AdminSettings },
    { path: "/debug/logs", component: DebugLogs },
    { path: "/users/:id", component: UserProfile },
    { path: "/dashboard", component: Dashboard },
];

process.env.REACT_APP_API_URL
process.env.SECRET_KEY
process.env.NODE_ENV
process.env.DATABASE_URL

var isAdmin = true;
var devMode = true;

//# sourceMappingURL=app.js.map
"#
    .to_string()
}

#[test]
fn test_api_endpoint_extraction_fetch() {
    let analyzer = JsBundleAnalyzer::new();
    let content = r#"fetch("/api/v2/users")"#;
    let result = analyzer.analyze("bundle.js", content);
    assert!(result.endpoints.iter().any(|e| e.url == "/api/v2/users"));
}

#[test]
fn test_api_endpoint_extraction_axios() {
    let analyzer = JsBundleAnalyzer::new();
    let content = r#"axios.post("/api/v2/orders")"#;
    let result = analyzer.analyze("bundle.js", content);
    let ep = result.endpoints.iter().find(|e| e.url == "/api/v2/orders");
    assert!(ep.is_some());
    assert_eq!(ep.unwrap().method.as_deref(), Some("POST"));
}

#[test]
fn test_api_endpoint_extraction_xhr() {
    let analyzer = JsBundleAnalyzer::new();
    let content = r#"xhr.open("PUT", "/api/v2/item/42")"#;
    let result = analyzer.analyze("bundle.js", content);
    let ep = result.endpoints.iter().find(|e| e.url == "/api/v2/item/42");
    assert!(ep.is_some());
    assert_eq!(ep.unwrap().method.as_deref(), Some("PUT"));
}

#[test]
fn test_api_string_literal_extraction() {
    let analyzer = JsBundleAnalyzer::new();
    let content = r#"const url = "/api/v1/internal/health""#;
    let result = analyzer.analyze("bundle.js", content);
    assert!(result
        .endpoints
        .iter()
        .any(|e| e.url.contains("/api/v1/internal/health")));
}

#[test]
fn test_aws_key_detection() {
    let analyzer = JsBundleAnalyzer::new();
    let content = r#"const key = "AKIAIOSFODNN7REALKEY1""#;
    let result = analyzer.analyze("bundle.js", content);
    let secret = result.findings.iter().find(|f| {
        matches!(f.category, JsBundleFindingCategory::HardcodedSecret)
            && f.description.contains("AWS")
    });
    assert!(secret.is_some());
    assert_eq!(secret.unwrap().severity, JsBundleSeverity::Critical);
}

#[test]
fn test_stripe_key_detection() {
    let analyzer = JsBundleAnalyzer::new();
    let content = r#"const sk = "sk_live_abcdef1234567890abcdef12""#;
    let result = analyzer.analyze("bundle.js", content);
    assert!(result
        .findings
        .iter()
        .any(|f| f.description.contains("Stripe")));
}

#[test]
fn test_github_token_detection() {
    let analyzer = JsBundleAnalyzer::new();
    let content = r#"token: "ghp_abcdef1234567890abcdef1234567890abcd""#;
    let result = analyzer.analyze("bundle.js", content);
    assert!(result
        .findings
        .iter()
        .any(|f| f.description.contains("GitHub")));
}

#[test]
fn test_db_connection_string_detection() {
    let analyzer = JsBundleAnalyzer::new();
    let content = r#"const db = "postgres://admin:pass@host:5432/mydb""#;
    let result = analyzer.analyze("bundle.js", content);
    assert!(result
        .findings
        .iter()
        .any(|f| f.description.contains("Database connection")));
}

#[test]
fn test_jwt_detection() {
    let analyzer = JsBundleAnalyzer::new();
    let content = r#"const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c""#;
    let result = analyzer.analyze("bundle.js", content);
    assert!(result
        .findings
        .iter()
        .any(|f| f.description.contains("JWT")));
}

#[test]
fn test_source_map_detection() {
    let analyzer = JsBundleAnalyzer::new();
    let content = "var x = 1;\n//# sourceMappingURL=app.js.map";
    let result = analyzer.analyze("app.js", content);
    assert!(!result.source_maps.is_empty());
    assert_eq!(result.source_maps[0].map_url, "app.js.map");
    assert!(result
        .findings
        .iter()
        .any(|f| matches!(f.category, JsBundleFindingCategory::SourceMapExposed)));
}

#[test]
fn test_webpack_chunk_detection() {
    let analyzer = JsBundleAnalyzer::new();
    let content = r#"
        window.webpackJsonp = [];
        __webpack_require__(42);
        {"vendors": "abc123def456", "main": "789012345678"}
    "#;
    let result = analyzer.analyze("bundle.js", content);
    assert!(!result.webpack_chunks.is_empty());
    assert!(result
        .findings
        .iter()
        .any(|f| matches!(f.category, JsBundleFindingCategory::WebpackChunk)));
}

#[test]
fn test_no_webpack_chunks_without_jsonp() {
    let analyzer = JsBundleAnalyzer::new();
    let content = r#"{"vendors": "abc123def456"}"#;
    let result = analyzer.analyze("bundle.js", content);
    assert!(result.webpack_chunks.is_empty());
}

#[test]
fn test_env_variable_detection() {
    let analyzer = JsBundleAnalyzer::new();
    let content = "var url = process.env.REACT_APP_API_URL;\nvar s = process.env.SECRET_KEY;";
    let result = analyzer.analyze("bundle.js", content);
    assert!(result
        .env_variables
        .contains(&"REACT_APP_API_URL".to_string()));
    assert!(result.env_variables.contains(&"SECRET_KEY".to_string()));

    let secret_env = result
        .findings
        .iter()
        .find(|f| f.description.contains("SECRET_KEY"));
    assert!(secret_env.is_some());
    assert_eq!(secret_env.unwrap().severity, JsBundleSeverity::Critical);
}

#[test]
fn test_env_variable_node_env_low_severity() {
    let analyzer = JsBundleAnalyzer::new();
    let content = "if (process.env.NODE_ENV === 'production') {}";
    let result = analyzer.analyze("bundle.js", content);
    let env_finding = result
        .findings
        .iter()
        .find(|f| f.description.contains("NODE_ENV"));
    assert!(env_finding.is_some());
    assert_eq!(env_finding.unwrap().severity, JsBundleSeverity::Low);
}

#[test]
fn test_admin_route_detection() {
    let analyzer = JsBundleAnalyzer::new();
    let content = r#"{ path: "/admin/users", component: AdminUsers }"#;
    let result = analyzer.analyze("bundle.js", content);
    assert!(result.routes.iter().any(|r| r.contains("/admin")));
    assert!(result
        .findings
        .iter()
        .any(|f| matches!(f.category, JsBundleFindingCategory::AdminRoute)));
}

#[test]
fn test_debug_route_detection() {
    let analyzer = JsBundleAnalyzer::new();
    let content = r#"{ path: "/debug/state", component: DebugState }"#;
    let result = analyzer.analyze("bundle.js", content);
    assert!(result
        .findings
        .iter()
        .any(|f| matches!(f.category, JsBundleFindingCategory::DebugRoute)));
}

#[test]
fn test_internal_url_detection() {
    let analyzer = JsBundleAnalyzer::new();
    let content = r#"const api = "https://api.corp.internal/v1/service";"#;
    let result = analyzer.analyze("bundle.js", content);
    assert!(result
        .findings
        .iter()
        .any(|f| matches!(f.category, JsBundleFindingCategory::InternalUrl)));
}

#[test]
fn test_firebase_detection() {
    let analyzer = JsBundleAnalyzer::new();
    let content = r#"const config = { databaseURL: "https://myapp.firebaseio.com" };"#;
    let result = analyzer.analyze("bundle.js", content);
    assert!(result
        .findings
        .iter()
        .any(|f| matches!(f.category, JsBundleFindingCategory::CloudConfig)));
}

#[test]
fn test_auth_bypass_detection() {
    let analyzer = JsBundleAnalyzer::new();
    let content = "if (isAdmin = true) { showPanel(); }";
    let result = analyzer.analyze("bundle.js", content);
    assert!(result
        .findings
        .iter()
        .any(|f| matches!(f.category, JsBundleFindingCategory::AuthBypass)));
}

#[test]
fn test_placeholder_secrets_ignored() {
    let analyzer = JsBundleAnalyzer::new();
    let content = r#"apiKey = "your_api_key_here""#;
    let result = analyzer.analyze("bundle.js", content);
    let secret_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| matches!(f.category, JsBundleFindingCategory::HardcodedSecret))
        .collect();
    assert!(secret_findings.is_empty());
}

#[test]
fn test_comprehensive_bundle_analysis() {
    let analyzer = JsBundleAnalyzer::new();
    let content = sample_bundle();
    let result = analyzer.analyze("app.bundle.js", &content);

    assert!(!result.endpoints.is_empty());
    assert!(!result.source_maps.is_empty());
    assert!(!result.webpack_chunks.is_empty());
    assert!(!result.env_variables.is_empty());
    assert!(!result.routes.is_empty());
    assert!(result.findings.len() >= 10);
}

#[test]
fn test_severity_display() {
    assert_eq!(JsBundleSeverity::Critical.to_string(), "critical");
    assert_eq!(JsBundleSeverity::Info.to_string(), "info");
}

#[test]
fn test_category_display() {
    assert_eq!(
        JsBundleFindingCategory::ApiEndpoint.to_string(),
        "API Endpoint"
    );
    assert_eq!(
        JsBundleFindingCategory::HardcodedSecret.to_string(),
        "Hardcoded Secret"
    );
    assert_eq!(
        JsBundleFindingCategory::SourceMapExposed.to_string(),
        "Source Map Exposed"
    );
}

#[test]
fn test_empty_content() {
    let analyzer = JsBundleAnalyzer::new();
    let result = analyzer.analyze("empty.js", "");
    assert!(result.findings.is_empty());
    assert!(result.endpoints.is_empty());
}

#[test]
fn test_gcp_api_key_detection() {
    let analyzer = JsBundleAnalyzer::new();
    let content = r#"const key = "AIzaSyA1234567890abcdefghijklmnopqrstuvw";"#;
    let result = analyzer.analyze("bundle.js", content);
    assert!(result
        .findings
        .iter()
        .any(|f| f.description.contains("GCP")));
}

#[test]
fn test_private_key_detection() {
    let analyzer = JsBundleAnalyzer::new();
    let content = r#"const key = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...";"#;
    let result = analyzer.analyze("bundle.js", content);
    assert!(result
        .findings
        .iter()
        .any(|f| f.description.contains("Private key")));
}

#[test]
fn test_default_impl() {
    let analyzer = JsBundleAnalyzer::default();
    let result = analyzer.analyze("test.js", "var x = 1;");
    assert!(result.findings.is_empty());
}
