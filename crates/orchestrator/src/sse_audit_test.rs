use crate::sse_audit::*;

#[test]
fn empty_body_no_issues() {
    assert!(analyze_sse_usage("").is_empty());
}

#[test]
fn no_sse_no_issues() {
    let body = "<h1>Hello</h1>";
    assert!(analyze_sse_usage(body).is_empty());
}

#[test]
fn eventsource_constructor_detected() {
    let body = r#"var es = new EventSource("/events");"#;
    let issues = analyze_sse_usage(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SseIssue::SseEndpointExposed { url } if url == "/events"))
    );
}

#[test]
fn eventsource_single_quote() {
    let body = "var es = new EventSource('/stream');";
    let issues = analyze_sse_usage(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SseIssue::SseEndpointExposed { url } if url == "/stream"))
    );
}

#[test]
fn eventsource_backtick() {
    let body = "var es = new EventSource(`/subscribe`);";
    let issues = analyze_sse_usage(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SseIssue::SseEndpointExposed { url } if url == "/subscribe"))
    );
}

#[test]
fn http_eventsource_flagged() {
    let body = r#"var es = new EventSource("http://api.example.com/events");"#;
    let issues = analyze_sse_usage(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SseIssue::EventSourceInsecure { .. }))
    );
}

#[test]
fn https_eventsource_not_flagged_insecure() {
    let body = r#"var es = new EventSource("https://api.example.com/events");"#;
    let issues = analyze_sse_usage(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SseIssue::EventSourceInsecure { .. }))
    );
}

#[test]
fn sse_path_with_eventsource_context() {
    let body = r#"
        const EventSource = require('eventsource');
        url = "/notifications"
    "#;
    let issues = analyze_sse_usage(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SseIssue::SseNoAuth { url } if url == "/notifications"))
    );
}

#[test]
fn sse_path_without_context_not_flagged() {
    let body = r#"<a href="/events">Events</a>"#;
    let issues = analyze_sse_usage(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SseIssue::SseNoAuth { .. }))
    );
}

#[test]
fn user_input_in_sse_detected() {
    let body = r#"
        var params = new URLSearchParams(location.search);
        var es = new EventSource("/events?token=" + params.get("token"));
    "#;
    let issues = analyze_sse_usage(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SseIssue::SseWithUserInput))
    );
}

#[test]
fn user_input_template_literal() {
    let body = r#"
        var es = new EventSource(`/events?id=${location.hash.slice(1)}`);
    "#;
    let issues = analyze_sse_usage(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SseIssue::SseWithUserInput))
    );
}

#[test]
fn no_user_input_not_flagged() {
    let body = r#"var es = new EventSource("/static-events");"#;
    let issues = analyze_sse_usage(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, SseIssue::SseWithUserInput))
    );
}

#[test]
fn severity_ordering() {
    assert!(
        sse_severity(&SseIssue::SseWithUserInput)
            > sse_severity(&SseIssue::EventSourceInsecure { url: "x".into() })
    );
    assert!(
        sse_severity(&SseIssue::SseNoAuth { url: "x".into() })
            > sse_severity(&SseIssue::SseEndpointExposed { url: "x".into() })
    );
}

#[test]
fn display_format() {
    let issue = SseIssue::SseEndpointExposed {
        url: "/events".into(),
    };
    assert_eq!(issue.to_string(), "sse_endpoint:/events");

    let issue = SseIssue::SseWithUserInput;
    assert_eq!(issue.to_string(), "sse_user_input");
}

#[test]
fn to_operations_count() {
    let issues = vec![
        SseIssue::SseEndpointExposed { url: "/x".into() },
        SseIssue::SseWithUserInput,
    ];
    let mut seq = 0;
    let ops = sse_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn text_event_stream_context() {
    let body = r#"
        accept: "text/event-stream"
        url = "/live"
    "#;
    let issues = analyze_sse_usage(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, SseIssue::SseNoAuth { url } if url == "/live"))
    );
}

// Security tests

#[test]
fn security_empty_body() {
    assert!(analyze_sse_security("").is_empty());
}

#[test]
fn security_no_sse() {
    let body = "<h1>Regular page</h1>";
    assert!(analyze_sse_security(body).is_empty());
}

#[test]
fn security_detects_data_exfiltration() {
    let body = r#"
        var es = new EventSource("/events");
        es.onmessage = function(e) {
            fetch("/exfil", { method: "POST", body: e.data });
        };
    "#;
    let issues = analyze_sse_security(body);
    assert!(issues.contains(&SseSecurityIssue::SseDataExfiltration));
}

#[test]
fn security_detects_xmlhttprequest_exfiltration() {
    let body = r#"
        var es = new EventSource("/events");
        es.onmessage = function(e) {
            var xhr = new XMLHttpRequest();
            xhr.send(e.data);
        };
    "#;
    let issues = analyze_sse_security(body);
    assert!(issues.contains(&SseSecurityIssue::SseDataExfiltration));
}

#[test]
fn security_detects_sendbeacon_exfiltration() {
    let body = r#"
        var es = new EventSource("/events");
        es.onmessage = function(e) {
            navigator.sendBeacon("/track", e.data);
        };
    "#;
    let issues = analyze_sse_security(body);
    assert!(issues.contains(&SseSecurityIssue::SseDataExfiltration));
}

#[test]
fn security_detects_sensitive_data_exposure() {
    let body = r#"
        var es = new EventSource("/events");
        es.onmessage = function(e) {
            var email = e.data.email;
            var password = e.data.password;
        };
    "#;
    let issues = analyze_sse_security(body);
    assert!(issues.contains(&SseSecurityIssue::SseSensitiveDataExposure));
}

#[test]
fn security_detects_ssn_exposure() {
    let body = r#"
        accept: "text/event-stream"
        data: { ssn: "123-45-6789" }
    "#;
    let issues = analyze_sse_security(body);
    assert!(issues.contains(&SseSecurityIssue::SseSensitiveDataExposure));
}

#[test]
fn security_detects_creditcard_exposure() {
    let body = r#"
        var es = new EventSource("/events");
        // Stream contains creditCard data
    "#;
    let issues = analyze_sse_security(body);
    assert!(issues.contains(&SseSecurityIssue::SseSensitiveDataExposure));
}

#[test]
fn security_detects_without_authentication() {
    let body = r#"
        var es = new EventSource("/events");
        es.onmessage = function(e) { console.log(e.data); };
    "#;
    let issues = analyze_sse_security(body);
    assert!(issues.contains(&SseSecurityIssue::SseWithoutAuthentication));
}

#[test]
fn security_not_flagged_with_auth_header() {
    let body = r#"
        var es = new EventSource("/events", {
            headers: { Authorization: "Bearer token123" }
        });
    "#;
    let issues = analyze_sse_security(body);
    assert!(!issues.contains(&SseSecurityIssue::SseWithoutAuthentication));
}

#[test]
fn security_not_flagged_with_token() {
    let body = r#"
        var token = getAuthToken();
        var es = new EventSource("/events?token=" + token);
    "#;
    let issues = analyze_sse_security(body);
    assert!(!issues.contains(&SseSecurityIssue::SseWithoutAuthentication));
}

#[test]
fn security_detects_reconnection_abuse() {
    let body = r#"
        var es = new EventSource("/events");
        retry: 100
    "#;
    let issues = analyze_sse_security(body);
    assert!(issues.contains(&SseSecurityIssue::SseReconnectionAbuse));
}

#[test]
fn security_detects_reconnect_interval_abuse() {
    let body = r#"
        var es = new EventSource("/events");
        reconnectInterval = 500;
    "#;
    let issues = analyze_sse_security(body);
    assert!(issues.contains(&SseSecurityIssue::SseReconnectionAbuse));
}

#[test]
fn security_not_flagged_normal_retry() {
    let body = r#"
        var es = new EventSource("/events");
        retry: 3000
    "#;
    let issues = analyze_sse_security(body);
    assert!(!issues.contains(&SseSecurityIssue::SseReconnectionAbuse));
}

#[test]
fn security_detects_cross_origin_connection() {
    let body = r#"
        var es = new EventSource("https://external.com/events");
    "#;
    let issues = analyze_sse_security(body);
    assert!(issues.contains(&SseSecurityIssue::SseCrossOriginConnection));
}

#[test]
fn security_detects_http_cross_origin() {
    let body = r#"
        var es = new EventSource("http://api.example.com/events");
    "#;
    let issues = analyze_sse_security(body);
    assert!(issues.contains(&SseSecurityIssue::SseCrossOriginConnection));
}

#[test]
fn security_detects_injection_vector() {
    let body = r#"
        var es = new EventSource("/events");
        es.onmessage = function(e) {
            document.getElementById("output").innerHTML = e.data;
        };
    "#;
    let issues = analyze_sse_security(body);
    assert!(issues.contains(&SseSecurityIssue::SseInjectionVector));
}

#[test]
fn security_detects_document_write_injection() {
    let body = r#"
        var es = new EventSource("/events");
        es.onmessage = function(e) {
            document.write(e.data);
        };
    "#;
    let issues = analyze_sse_security(body);
    assert!(issues.contains(&SseSecurityIssue::SseInjectionVector));
}

#[test]
fn security_detects_outerhtml_injection() {
    let body = r#"
        accept: "text/event-stream"
        element.outerHTML = eventData;
    "#;
    let issues = analyze_sse_security(body);
    assert!(issues.contains(&SseSecurityIssue::SseInjectionVector));
}

#[test]
fn security_detects_denial_of_service() {
    let body = r#"
        var es = new EventSource("/events");
        es.addEventListener("message", function(e) {
            console.log(e.data);
        });
        // No cleanup handlers
    "#;
    let issues = analyze_sse_security(body);
    assert!(issues.contains(&SseSecurityIssue::SseDenialOfService));
}

#[test]
fn security_detects_onmessage_no_cleanup() {
    let body = r#"
        var es = new EventSource("/events");
        es.onmessage = function(e) { };
        es.onerror = function(e) { };
    "#;
    let issues = analyze_sse_security(body);
    assert!(issues.contains(&SseSecurityIssue::SseDenialOfService));
}

#[test]
fn security_not_flagged_with_cleanup() {
    let body = r#"
        var es = new EventSource("/events");
        es.addEventListener("message", handler);
        window.onbeforeunload = function() {
            es.close();
        };
    "#;
    let issues = analyze_sse_security(body);
    assert!(!issues.contains(&SseSecurityIssue::SseDenialOfService));
}

#[test]
fn security_detects_data_persistence() {
    let body = r#"
        var es = new EventSource("/events");
        es.onmessage = function(e) {
            localStorage.setItem("data", e.data);
        };
    "#;
    let issues = analyze_sse_security(body);
    assert!(issues.contains(&SseSecurityIssue::SseDataPersistence));
}

#[test]
fn security_detects_sessionstorage_persistence() {
    let body = r#"
        var es = new EventSource("/events");
        es.onmessage = function(e) {
            sessionStorage.data = e.data;
        };
    "#;
    let issues = analyze_sse_security(body);
    assert!(issues.contains(&SseSecurityIssue::SseDataPersistence));
}

#[test]
fn security_detects_indexeddb_persistence() {
    let body = r#"
        accept: "text/event-stream"
        indexedDB.open("mydb").onsuccess = function() { };
    "#;
    let issues = analyze_sse_security(body);
    assert!(issues.contains(&SseSecurityIssue::SseDataPersistence));
}

#[test]
fn security_detects_without_encryption() {
    let body = r#"
        var es = new EventSource("http://api.example.com/events");
    "#;
    let issues = analyze_sse_security(body);
    assert!(issues.contains(&SseSecurityIssue::SseWithoutEncryption));
}

#[test]
fn security_not_flagged_with_https() {
    let body = r#"
        var es = new EventSource("https://api.example.com/events");
    "#;
    let issues = analyze_sse_security(body);
    assert!(!issues.contains(&SseSecurityIssue::SseWithoutEncryption));
}

#[test]
fn security_detects_event_spoofing() {
    let body = r#"
        var es = new EventSource("/events");
        es.addEventListener("error", customHandler);
    "#;
    let issues = analyze_sse_security(body);
    assert!(issues.contains(&SseSecurityIssue::SseEventSpoofing));
}

#[test]
fn security_detects_message_spoofing() {
    let body = r#"
        var es = new EventSource("/events");
        es.addEventListener("message", function(e) { });
    "#;
    let issues = analyze_sse_security(body);
    assert!(issues.contains(&SseSecurityIssue::SseEventSpoofing));
}

#[test]
fn security_detects_open_spoofing() {
    let body = r#"
        var es = new EventSource("/events");
        es.addEventListener('open', handler);
    "#;
    let issues = analyze_sse_security(body);
    assert!(issues.contains(&SseSecurityIssue::SseEventSpoofing));
}

#[test]
fn security_severity_data_exfiltration() {
    assert_eq!(
        sse_security_severity(&SseSecurityIssue::SseDataExfiltration),
        7.5
    );
}

#[test]
fn security_severity_sensitive_exposure() {
    assert_eq!(
        sse_security_severity(&SseSecurityIssue::SseSensitiveDataExposure),
        8.0
    );
}

#[test]
fn security_severity_without_auth() {
    assert_eq!(
        sse_security_severity(&SseSecurityIssue::SseWithoutAuthentication),
        6.5
    );
}

#[test]
fn security_severity_reconnection_abuse() {
    assert_eq!(
        sse_security_severity(&SseSecurityIssue::SseReconnectionAbuse),
        5.0
    );
}

#[test]
fn security_severity_cross_origin() {
    assert_eq!(
        sse_security_severity(&SseSecurityIssue::SseCrossOriginConnection),
        6.0
    );
}

#[test]
fn security_severity_injection() {
    assert_eq!(
        sse_security_severity(&SseSecurityIssue::SseInjectionVector),
        7.0
    );
}

#[test]
fn security_severity_denial_of_service() {
    assert_eq!(
        sse_security_severity(&SseSecurityIssue::SseDenialOfService),
        5.5
    );
}

#[test]
fn security_severity_persistence() {
    assert_eq!(
        sse_security_severity(&SseSecurityIssue::SseDataPersistence),
        6.0
    );
}

#[test]
fn security_severity_without_encryption() {
    assert_eq!(
        sse_security_severity(&SseSecurityIssue::SseWithoutEncryption),
        7.0
    );
}

#[test]
fn security_severity_event_spoofing() {
    assert_eq!(
        sse_security_severity(&SseSecurityIssue::SseEventSpoofing),
        5.0
    );
}

#[test]
fn security_operations_count() {
    let issues = vec![
        SseSecurityIssue::SseDataExfiltration,
        SseSecurityIssue::SseSensitiveDataExposure,
    ];
    let mut seq = 0;
    let ops = sse_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_operations_empty() {
    let issues = vec![];
    let mut seq = 0;
    let ops = sse_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 0);
    assert_eq!(seq, 0);
}

#[test]
fn security_combined_multiple_issues() {
    let body = r#"
        var es = new EventSource("http://api.example.com/events");
        es.onmessage = function(e) {
            document.getElementById("output").innerHTML = e.data;
            localStorage.setItem("data", e.data);
            fetch("/exfil", { method: "POST", body: e.data });
        };
    "#;
    let issues = analyze_sse_security(body);
    assert!(issues.contains(&SseSecurityIssue::SseWithoutEncryption));
    assert!(issues.contains(&SseSecurityIssue::SseInjectionVector));
    assert!(issues.contains(&SseSecurityIssue::SseDataPersistence));
    assert!(issues.contains(&SseSecurityIssue::SseDataExfiltration));
    assert!(issues.contains(&SseSecurityIssue::SseCrossOriginConnection));
}

#[test]
fn security_combined_auth_and_cleanup() {
    let body = r#"
        var es = new EventSource("/events", { headers: { Authorization: "Bearer xyz" } });
        es.onmessage = function(e) { console.log(e.data); };
        window.addEventListener("beforeunload", function() {
            es.close();
        });
    "#;
    let issues = analyze_sse_security(body);
    assert!(!issues.contains(&SseSecurityIssue::SseWithoutAuthentication));
    assert!(!issues.contains(&SseSecurityIssue::SseDenialOfService));
}

#[test]
fn security_display_format() {
    assert_eq!(
        SseSecurityIssue::SseDataExfiltration.to_string(),
        "sse_data_exfiltration"
    );
    assert_eq!(
        SseSecurityIssue::SseSensitiveDataExposure.to_string(),
        "sse_sensitive_data_exposure"
    );
    assert_eq!(
        SseSecurityIssue::SseWithoutAuthentication.to_string(),
        "sse_without_authentication"
    );
    assert_eq!(
        SseSecurityIssue::SseReconnectionAbuse.to_string(),
        "sse_reconnection_abuse"
    );
    assert_eq!(
        SseSecurityIssue::SseCrossOriginConnection.to_string(),
        "sse_cross_origin_connection"
    );
    assert_eq!(
        SseSecurityIssue::SseInjectionVector.to_string(),
        "sse_injection_vector"
    );
    assert_eq!(
        SseSecurityIssue::SseDenialOfService.to_string(),
        "sse_denial_of_service"
    );
    assert_eq!(
        SseSecurityIssue::SseDataPersistence.to_string(),
        "sse_data_persistence"
    );
    assert_eq!(
        SseSecurityIssue::SseWithoutEncryption.to_string(),
        "sse_without_encryption"
    );
    assert_eq!(
        SseSecurityIssue::SseEventSpoofing.to_string(),
        "sse_event_spoofing"
    );
}
