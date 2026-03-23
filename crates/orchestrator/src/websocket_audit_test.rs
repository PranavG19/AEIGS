use crate::websocket_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_websocket("");
    assert!(issues.is_empty());
}

#[test]
fn regular_javascript_no_websocket() {
    let body = r#"
        <script>
            var x = 42;
            function foo() { return x; }
        </script>
    "#;
    let issues = analyze_websocket(body);
    assert!(issues.is_empty());
}

#[test]
fn new_websocket_detected() {
    let body = r#"<script>var sock = new WebSocket("wss://example.com/ws");</script>"#;
    let issues = analyze_websocket(body);
    assert!(issues.contains(&WebSocketIssue::ApiDetected));
}

#[test]
fn websocket_constructor_detected() {
    let body = r#"<script>var sock = WebSocket("wss://example.com/ws");</script>"#;
    let issues = analyze_websocket(body);
    assert!(issues.contains(&WebSocketIssue::ApiDetected));
}

#[test]
fn ws_url_detected() {
    let body = r#"<script>connect("ws://example.com/socket");</script>"#;
    let issues = analyze_websocket(body);
    assert!(issues.contains(&WebSocketIssue::ApiDetected));
}

#[test]
fn wss_url_detected() {
    let body = r#"<script>var url = "wss://example.com/live";</script>"#;
    let issues = analyze_websocket(body);
    assert!(issues.contains(&WebSocketIssue::ApiDetected));
}

#[test]
fn insecure_ws_protocol() {
    let body = r#"<script>new WebSocket("ws://example.com/ws");</script>"#;
    let issues = analyze_websocket(body);
    assert!(issues.contains(&WebSocketIssue::InsecureProtocol));
}

#[test]
fn secure_wss_no_insecure_flag() {
    let body = r#"<script>new WebSocket("wss://example.com/ws");</script>"#;
    let issues = analyze_websocket(body);
    assert!(!issues.contains(&WebSocketIssue::InsecureProtocol));
    assert!(issues.contains(&WebSocketIssue::ApiDetected));
}

#[test]
fn missing_origin_validation() {
    let body = r#"
        <script>
            var ws = new WebSocket("wss://example.com/ws");
            ws.onmessage = function(e) { console.log(e.data); };
        </script>
    "#;
    let issues = analyze_websocket(body);
    assert!(issues.contains(&WebSocketIssue::MissingOriginValidation));
}

#[test]
fn origin_check_present() {
    let body = r#"
        <script>
            var ws = new WebSocket("wss://example.com/ws");
            ws.onopen = function() {
                if (event.origin !== "https://example.com") {
                    ws.close();
                }
            };
        </script>
    "#;
    let issues = analyze_websocket(body);
    assert!(!issues.contains(&WebSocketIssue::MissingOriginValidation));
}

#[test]
fn check_origin_function_present() {
    let body = r#"
        <script>
            function checkOrigin(origin) { return origin === "https://example.com"; }
            var ws = new WebSocket("wss://example.com/ws");
        </script>
    "#;
    let issues = analyze_websocket(body);
    assert!(!issues.contains(&WebSocketIssue::MissingOriginValidation));
}

#[test]
fn verify_origin_present() {
    let body = r#"
        <script>
            function verifyOrigin(e) { return true; }
            var ws = new WebSocket("wss://example.com/ws");
        </script>
    "#;
    let issues = analyze_websocket(body);
    assert!(!issues.contains(&WebSocketIssue::MissingOriginValidation));
}

#[test]
fn allowed_origins_present() {
    let body = r#"
        <script>
            const allowedOrigins = ["https://example.com"];
            var ws = new WebSocket("wss://example.com/ws");
        </script>
    "#;
    let issues = analyze_websocket(body);
    assert!(!issues.contains(&WebSocketIssue::MissingOriginValidation));
}

#[test]
fn inner_html_injection_risk() {
    let body = r#"
        <script>
            ws.onmessage = function(e) {
                document.getElementById("msg").innerHTML = e.data;
            };
        </script>
    "#;
    let issues = analyze_websocket(body);
    assert!(issues.contains(&WebSocketIssue::MessageInjectionRisk));
}

#[test]
fn eval_injection_risk() {
    let body = r#"
        <script>
            ws.onmessage = function(e) {
                eval(e.data);
            };
        </script>
    "#;
    let issues = analyze_websocket(body);
    assert!(issues.contains(&WebSocketIssue::MessageInjectionRisk));
}

#[test]
fn document_write_injection_risk() {
    let body = r#"
        <script>
            ws.onmessage = function(e) {
                document.write(e.data);
            };
        </script>
    "#;
    let issues = analyze_websocket(body);
    assert!(issues.contains(&WebSocketIssue::MessageInjectionRisk));
}

#[test]
fn function_constructor_injection_risk() {
    let body = r#"
        <script>
            ws.onmessage = function(e) {
                var fn = new Function(e.data);
                fn();
            };
        </script>
    "#;
    let issues = analyze_websocket(body);
    assert!(issues.contains(&WebSocketIssue::MessageInjectionRisk));
}

#[test]
fn sensitive_data_password() {
    let body = r#"
        <script>
            var ws = new WebSocket("wss://example.com/ws");
            ws.send(JSON.stringify({password: "secret123"}));
        </script>
    "#;
    let issues = analyze_websocket(body);
    assert!(issues.contains(&WebSocketIssue::SensitiveDataExposure));
}

#[test]
fn sensitive_data_token() {
    let body = r#"
        <script>
            var ws = new WebSocket("wss://example.com/ws");
            ws.send({token: "abc123"});
        </script>
    "#;
    let issues = analyze_websocket(body);
    assert!(issues.contains(&WebSocketIssue::SensitiveDataExposure));
}

#[test]
fn sensitive_data_secret() {
    let body = r#"
        <script>
            var ws = new WebSocket("wss://example.com/ws");
            var secret = "mySecret";
        </script>
    "#;
    let issues = analyze_websocket(body);
    assert!(issues.contains(&WebSocketIssue::SensitiveDataExposure));
}

#[test]
fn sensitive_data_credential() {
    let body = r#"
        <script>
            var ws = new WebSocket("wss://example.com/ws");
            ws.send({credential: user.credential});
        </script>
    "#;
    let issues = analyze_websocket(body);
    assert!(issues.contains(&WebSocketIssue::SensitiveDataExposure));
}

#[test]
fn sensitive_data_api_key() {
    let body = r#"
        <script>
            var ws = new WebSocket("wss://example.com/ws");
            var apiKey = "key123";
        </script>
    "#;
    let issues = analyze_websocket(body);
    assert!(issues.contains(&WebSocketIssue::SensitiveDataExposure));
}

#[test]
fn unlimited_reconnect() {
    let body = r#"
        <script>
            var ws = new WebSocket("wss://example.com/ws");
            ws.onclose = function() { reconnect(); };
        </script>
    "#;
    let issues = analyze_websocket(body);
    assert!(issues.contains(&WebSocketIssue::UnlimitedReconnect));
}

#[test]
fn reconnect_with_backoff() {
    let body = r#"
        <script>
            var ws = new WebSocket("wss://example.com/ws");
            var backoff = 1000;
            ws.onclose = function() {
                setTimeout(reconnect, backoff);
                backoff *= 2;
            };
        </script>
    "#;
    let issues = analyze_websocket(body);
    assert!(!issues.contains(&WebSocketIssue::UnlimitedReconnect));
}

#[test]
fn reconnect_with_max_retries() {
    let body = r#"
        <script>
            var ws = new WebSocket("wss://example.com/ws");
            var maxRetries = 5;
            ws.onclose = function() {
                if (retries < maxRetries) reconnect();
            };
        </script>
    "#;
    let issues = analyze_websocket(body);
    assert!(!issues.contains(&WebSocketIssue::UnlimitedReconnect));
}

#[test]
fn severity_ordering() {
    assert!(websocket_severity(&WebSocketIssue::MessageInjectionRisk) > 7.0);
    assert!(
        websocket_severity(&WebSocketIssue::MissingOriginValidation)
            > websocket_severity(&WebSocketIssue::InsecureProtocol)
    );
    assert!(
        websocket_severity(&WebSocketIssue::InsecureProtocol)
            > websocket_severity(&WebSocketIssue::UnlimitedReconnect)
    );
    assert!(
        websocket_severity(&WebSocketIssue::UnlimitedReconnect)
            > websocket_severity(&WebSocketIssue::ApiDetected)
    );
}

#[test]
fn to_operations_increments_sequence() {
    let issues = vec![
        WebSocketIssue::ApiDetected,
        WebSocketIssue::InsecureProtocol,
    ];
    let mut seq = 0u64;
    let ops = websocket_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn to_operations_empty_issues() {
    let issues = vec![];
    let mut seq = 5u64;
    let ops = websocket_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn display_all_variants() {
    assert_eq!(WebSocketIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        WebSocketIssue::InsecureProtocol.to_string(),
        "insecure_protocol"
    );
    assert_eq!(
        WebSocketIssue::MissingOriginValidation.to_string(),
        "missing_origin_validation"
    );
    assert_eq!(
        WebSocketIssue::MessageInjectionRisk.to_string(),
        "message_injection_risk"
    );
    assert_eq!(
        WebSocketIssue::SensitiveDataExposure.to_string(),
        "sensitive_data_exposure"
    );
    assert_eq!(
        WebSocketIssue::UnlimitedReconnect.to_string(),
        "unlimited_reconnect"
    );
}

#[test]
fn multiple_issues_detected() {
    let body = r#"
        <script>
            var ws = new WebSocket("ws://example.com/ws");
            ws.onmessage = function(e) {
                document.getElementById("x").innerHTML = e.data;
            };
            ws.onclose = function() { reconnect(); };
        </script>
    "#;
    let issues = analyze_websocket(body);
    assert!(issues.contains(&WebSocketIssue::ApiDetected));
    assert!(issues.contains(&WebSocketIssue::InsecureProtocol));
    assert!(issues.contains(&WebSocketIssue::MissingOriginValidation));
    assert!(issues.contains(&WebSocketIssue::MessageInjectionRisk));
    assert!(issues.contains(&WebSocketIssue::UnlimitedReconnect));
}
