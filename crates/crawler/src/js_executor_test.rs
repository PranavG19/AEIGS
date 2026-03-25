use crate::js_executor::*;

#[test]
fn extract_inline_script() {
    let html = r#"<script>console.log("hello");</script>"#;
    let sources = extract_js_sources(html);
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].source_type, JsSourceType::Inline);
    assert!(sources[0].content.contains("console.log"));
}

#[test]
fn extract_external_script() {
    let html = r#"<script src="/js/app.js"></script>"#;
    let sources = extract_js_sources(html);
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].source_type, JsSourceType::External);
    assert_eq!(sources[0].url.as_deref(), Some("/js/app.js"));
}

#[test]
fn extract_both_inline_and_external() {
    let html = r#"
        <script src="/js/vendor.js"></script>
        <script>var x = 1;</script>
        <script src="/js/app.js"></script>
    "#;
    let sources = extract_js_sources(html);
    assert_eq!(sources.len(), 3);
    let externals: Vec<_> = sources
        .iter()
        .filter(|s| s.source_type == JsSourceType::External)
        .collect();
    assert_eq!(externals.len(), 2);
}

#[test]
fn extract_event_handler_scripts() {
    let html = r#"<button onclick="alert('xss')">Click</button>"#;
    let sources = extract_js_sources(html);
    assert!(
        sources
            .iter()
            .any(|s| s.source_type == JsSourceType::EventHandler)
    );
}

#[test]
fn extract_dynamic_imports() {
    let html = r#"<script>import("/modules/lazy.js")</script>"#;
    let sources = extract_js_sources(html);
    assert!(
        sources
            .iter()
            .any(|s| s.source_type == JsSourceType::DynamicImport)
    );
}

#[test]
fn find_aws_access_key() {
    let js = r#"const key = "AKIAIOSFODNN7EXAMPLE";"#;
    let findings = find_sensitive_data(js, Some("config.js"));
    assert!(!findings.is_empty());
    assert!(
        findings
            .iter()
            .any(|f| f.data_type == SensitiveDataType::AwsAccessKey)
    );
}

#[test]
fn find_jwt_token() {
    let js = r#"const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";"#;
    let findings = find_sensitive_data(js, None);
    assert!(
        findings
            .iter()
            .any(|f| f.data_type == SensitiveDataType::JwtToken)
    );
}

#[test]
fn find_api_key() {
    let js = r#"const config = { apiKey: "sk_live_abcdef1234567890abcdef" };"#;
    let findings = find_sensitive_data(js, None);
    assert!(!findings.is_empty());
}

#[test]
fn find_password_in_js() {
    let js = r#"const password = "SuperSecret123!";"#;
    let findings = find_sensitive_data(js, None);
    assert!(
        findings
            .iter()
            .any(|f| f.data_type == SensitiveDataType::Password)
    );
}

#[test]
fn find_connection_string() {
    let js = r#"const db = "postgres://admin:pass123@db.internal:5432/mydb";"#;
    let findings = find_sensitive_data(js, None);
    assert!(
        findings
            .iter()
            .any(|f| f.data_type == SensitiveDataType::ConnectionString)
    );
}

#[test]
fn find_google_api_key() {
    let js = r#"const gkey = "AIzaSyA1234567890abcdefghijklmnopqrstuv";"#;
    let findings = find_sensitive_data(js, None);
    assert!(
        findings
            .iter()
            .any(|f| f.data_type == SensitiveDataType::GoogleApiKey)
    );
}

#[test]
fn find_stripe_key() {
    let js = r#"Stripe("pk_test_abcdefghijklmnopqrstuvwx");"#;
    let findings = find_sensitive_data(js, None);
    assert!(
        findings
            .iter()
            .any(|f| f.data_type == SensitiveDataType::StripeKey)
    );
}

#[test]
fn find_private_key() {
    let js = r#"const key = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...";"#;
    let findings = find_sensitive_data(js, None);
    assert!(
        findings
            .iter()
            .any(|f| f.data_type == SensitiveDataType::PrivateKey)
    );
}

#[test]
fn no_sensitive_data_in_clean_code() {
    let js = r#"function add(a, b) { return a + b; }"#;
    let findings = find_sensitive_data(js, None);
    assert!(findings.is_empty());
}

#[test]
fn find_innerhtml_sink() {
    let js = r#"element.innerHTML = userInput;"#;
    let sinks = find_xss_sinks(js, None);
    assert!(sinks.iter().any(|s| s.sink_type == XssSinkType::InnerHtml));
}

#[test]
fn find_document_write_sink() {
    let js = r#"document.write(data);"#;
    let sinks = find_xss_sinks(js, None);
    assert!(
        sinks
            .iter()
            .any(|s| s.sink_type == XssSinkType::DocumentWrite)
    );
}

#[test]
fn find_eval_sink() {
    let js = r#"eval(userCode);"#;
    let sinks = find_xss_sinks(js, None);
    assert!(sinks.iter().any(|s| s.sink_type == XssSinkType::Eval));
}

#[test]
fn find_window_open_sink() {
    let js = r#"window.open(url);"#;
    let sinks = find_xss_sinks(js, None);
    assert!(sinks.iter().any(|s| s.sink_type == XssSinkType::WindowOpen));
}

#[test]
fn find_location_href_sink() {
    let js = r#"location.href = redirectUrl;"#;
    let sinks = find_xss_sinks(js, None);
    assert!(
        sinks
            .iter()
            .any(|s| s.sink_type == XssSinkType::LocationHref)
    );
}

#[test]
fn find_jquery_html_sink() {
    let js = r#"$('#target').html(data);"#;
    let sinks = find_xss_sinks(js, None);
    assert!(sinks.iter().any(|s| s.sink_type == XssSinkType::JQueryHtml));
}

#[test]
fn find_insert_adjacent_html_sink() {
    let js = r#"el.insertAdjacentHTML('beforeend', markup);"#;
    let sinks = find_xss_sinks(js, None);
    assert!(
        sinks
            .iter()
            .any(|s| s.sink_type == XssSinkType::InsertAdjacentHtml)
    );
}

#[test]
fn no_sinks_in_clean_code() {
    let js = r#"const sum = a + b; console.log(sum);"#;
    let sinks = find_xss_sinks(js, None);
    assert!(sinks.is_empty());
}

#[test]
fn extract_api_endpoints_from_js() {
    let js = r#"
        fetch("/api/users");
        const url = "/api/products/list";
        axios.get("/v2/orders");
        req("/rest/data/export");
    "#;
    let endpoints = extract_api_endpoints(js);
    assert!(endpoints.contains(&"/api/users".to_string()));
    assert!(endpoints.contains(&"/api/products/list".to_string()));
    assert!(endpoints.contains(&"/v2/orders".to_string()));
    assert!(endpoints.contains(&"/rest/data/export".to_string()));
}

#[test]
fn detect_source_map_url() {
    let js = "var x = 1;\n//# sourceMappingURL=app.js.map";
    let maps = detect_source_maps(js);
    assert_eq!(maps.len(), 1);
    assert_eq!(maps[0].source_map_url, "app.js.map");
}

#[test]
fn detect_source_map_at_syntax() {
    let js = "var x = 1;\n//@ sourceMappingURL=legacy.js.map";
    let maps = detect_source_maps(js);
    assert_eq!(maps.len(), 1);
    assert_eq!(maps[0].source_map_url, "legacy.js.map");
}

#[test]
fn detect_webpack_chunk_name() {
    let js = r#"import(/* webpackChunkName: "dashboard" */ './Dashboard')"#;
    let chunks = detect_webpack_chunks(js);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].chunk_id, "dashboard");
}

#[test]
fn detect_service_worker_registration() {
    let js = r#"navigator.serviceWorker.register('/sw.js')"#;
    let workers = detect_service_workers(js);
    assert_eq!(workers.len(), 1);
    assert_eq!(workers[0].script_url, "/sw.js");
}

#[test]
fn detect_service_worker_with_scope() {
    let js = r#"navigator.serviceWorker.register('/sw.js', { scope: '/app/' })"#;
    let workers = detect_service_workers(js);
    assert_eq!(workers.len(), 1);
    assert_eq!(workers[0].scope, "/app/");
}

#[test]
fn detect_cache_strategies_in_sw() {
    let js = r#"
        navigator.serviceWorker.register('/sw.js')
        // Service worker uses cache-first for static assets
        // and network-first for API calls
        // with stale-while-revalidate fallback
    "#;
    let workers = detect_service_workers(js);
    assert!(
        workers[0]
            .cache_strategies
            .contains(&"CacheFirst".to_string())
    );
    assert!(
        workers[0]
            .cache_strategies
            .contains(&"NetworkFirst".to_string())
    );
    assert!(
        workers[0]
            .cache_strategies
            .contains(&"StaleWhileRevalidate".to_string())
    );
}

#[test]
fn full_analysis_integration() {
    let sources = vec![
        JsSource {
            url: Some("/js/app.js".to_string()),
            content: r#"
                const api_key = "sk_test_abc123def456ghi789jklmnop";
                element.innerHTML = userInput;
                fetch("/api/users");
                //# sourceMappingURL=app.js.map
            "#
            .to_string(),
            source_type: JsSourceType::External,
            size_bytes: 200,
        },
        JsSource {
            url: None,
            content: r#"
                navigator.serviceWorker.register('/sw.js');
                import(/* webpackChunkName: "admin" */ './admin');
            "#
            .to_string(),
            source_type: JsSourceType::Inline,
            size_bytes: 100,
        },
    ];

    let result = analyze_javascript(&sources);

    assert_eq!(result.sources.len(), 2);
    assert_eq!(result.total_js_bytes, 300);
    assert!(!result.sensitive_data.is_empty());
    assert!(!result.xss_sinks.is_empty());
    assert!(result.api_endpoints.contains(&"/api/users".to_string()));
    assert!(!result.source_maps.is_empty());
    assert!(!result.webpack_chunks.is_empty());
    assert!(!result.service_workers.is_empty());
}

#[test]
fn sensitive_data_includes_line_numbers() {
    let js = "line1\nline2\nconst password = \"secret123\";\nline4";
    let findings = find_sensitive_data(js, Some("test.js"));
    assert!(!findings.is_empty());
    let pw_finding = findings
        .iter()
        .find(|f| f.data_type == SensitiveDataType::Password)
        .unwrap();
    assert_eq!(pw_finding.line_number, Some(3));
    assert_eq!(pw_finding.source_file.as_deref(), Some("test.js"));
}

#[test]
fn graphql_endpoint_detected() {
    let js = r#"fetch("/graphql", { method: "POST" });"#;
    let endpoints = extract_api_endpoints(js);
    assert!(endpoints.contains(&"/graphql".to_string()));
}
