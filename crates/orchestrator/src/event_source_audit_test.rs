use crate::event_source_audit::*;

#[test]
fn test_no_event_source() {
    let body = "<html><body>Regular content</body></html>";
    let issues = analyze_event_source(body);
    assert_eq!(issues.len(), 0);
}

#[test]
fn test_api_detected_event_source() {
    let body = "const source = new EventSource('/api/stream');";
    let issues = analyze_event_source(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], EventSourceIssue::ApiDetected);
}

#[test]
fn test_api_detected_eventsource_lowercase() {
    let body = "import eventsource from 'eventsource';";
    let issues = analyze_event_source(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], EventSourceIssue::ApiDetected);
}

#[test]
fn test_api_detected_class_reference() {
    let body = "if (typeof EventSource !== 'undefined') { }";
    let issues = analyze_event_source(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], EventSourceIssue::ApiDetected);
}

#[test]
fn test_sensitive_data_stream_password() {
    let body = "const es = new EventSource('/stream'); es.onmessage = (e) => { const password = e.data; };";
    let issues = analyze_event_source(body);
    assert!(issues.contains(&EventSourceIssue::ApiDetected));
    assert!(issues.contains(&EventSourceIssue::SensitiveDataStream));
}

#[test]
fn test_sensitive_data_stream_token() {
    let body = "new EventSource('/auth'); const token = data.token;";
    let issues = analyze_event_source(body);
    assert!(issues.contains(&EventSourceIssue::SensitiveDataStream));
}

#[test]
fn test_sensitive_data_stream_api_key() {
    let body = "EventSource('/api'); apiKey: config.key";
    let issues = analyze_event_source(body);
    assert!(issues.contains(&EventSourceIssue::SensitiveDataStream));
}

#[test]
fn test_cross_origin_stream_http() {
    let body = "new EventSource('http://external.com/stream');";
    let issues = analyze_event_source(body);
    assert!(issues.contains(&EventSourceIssue::ApiDetected));
    assert!(issues.contains(&EventSourceIssue::CrossOriginStream));
}

#[test]
fn test_cross_origin_stream_https() {
    let body = "const es = new EventSource('https://api.example.com/events');";
    let issues = analyze_event_source(body);
    assert!(issues.contains(&EventSourceIssue::CrossOriginStream));
}

#[test]
fn test_cross_origin_stream_with_location_origin_excluded() {
    let body = "new EventSource(location.origin + '/stream');";
    let issues = analyze_event_source(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], EventSourceIssue::ApiDetected);
}

#[test]
fn test_cross_origin_stream_with_same_origin_excluded() {
    let body = "new EventSource('https://api.com', { mode: 'same-origin' });";
    let issues = analyze_event_source(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], EventSourceIssue::ApiDetected);
}

#[test]
fn test_no_reconnect_limit_onopen() {
    let body = "const es = new EventSource('/stream'); es.onopen = () => { console.log('open'); }; es.onerror = () => { };";
    let issues = analyze_event_source(body);
    assert!(issues.contains(&EventSourceIssue::ApiDetected));
    assert!(issues.contains(&EventSourceIssue::NoReconnectLimit));
}

#[test]
fn test_no_reconnect_limit_onerror() {
    let body = "EventSource('/api'); es.onerror = (err) => { console.error(err); };";
    let issues = analyze_event_source(body);
    assert!(issues.contains(&EventSourceIssue::NoReconnectLimit));
}

#[test]
fn test_no_reconnect_limit_with_close_excluded() {
    let body = "new EventSource('/stream'); es.onerror = () => { if (retries > 3) es.close(); };";
    let issues = analyze_event_source(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], EventSourceIssue::ApiDetected);
}

#[test]
fn test_no_reconnect_limit_with_max_retries_excluded() {
    let body = "EventSource('/api'); const maxRetries = 5; es.onopen = () => { };";
    let issues = analyze_event_source(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], EventSourceIssue::ApiDetected);
}

#[test]
fn test_injection_via_message_inner_html() {
    let body = "const es = new EventSource('/stream'); es.onmessage = (e) => { document.body.innerHTML = e.data; };";
    let issues = analyze_event_source(body);
    assert!(issues.contains(&EventSourceIssue::ApiDetected));
    assert!(issues.contains(&EventSourceIssue::InjectionViaMessage));
}

#[test]
fn test_injection_via_message_document_write() {
    let body = "EventSource('/api'); es.onmessage = (e) => { document.write(e.data); };";
    let issues = analyze_event_source(body);
    assert!(issues.contains(&EventSourceIssue::InjectionViaMessage));
}

#[test]
fn test_injection_via_message_eval() {
    let body =
        "new EventSource('/events'); es.addEventListener('message', (e) => { eval(e.data); });";
    let issues = analyze_event_source(body);
    assert!(issues.contains(&EventSourceIssue::InjectionViaMessage));
}

#[test]
fn test_multiple_issues() {
    let body = r#"
        const es = new EventSource('https://external.com/stream');
        es.onmessage = (e) => {
            const token = e.data.token;
            document.getElementById('output').innerHTML = e.data.html;
        };
        es.onerror = (err) => {
            console.error('Connection error:', err);
        };
    "#;
    let issues = analyze_event_source(body);
    assert_eq!(issues.len(), 5);
    assert!(issues.contains(&EventSourceIssue::ApiDetected));
    assert!(issues.contains(&EventSourceIssue::SensitiveDataStream));
    assert!(issues.contains(&EventSourceIssue::CrossOriginStream));
    assert!(issues.contains(&EventSourceIssue::NoReconnectLimit));
    assert!(issues.contains(&EventSourceIssue::InjectionViaMessage));
}

#[test]
fn test_operations_generation() {
    let issues = vec![
        EventSourceIssue::ApiDetected,
        EventSourceIssue::SensitiveDataStream,
    ];
    let mut seq = 0u64;
    let ops = event_source_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
}

#[test]
fn test_severity_values() {
    assert_eq!(event_source_severity(&EventSourceIssue::ApiDetected), 2.0);
    assert_eq!(
        event_source_severity(&EventSourceIssue::SensitiveDataStream),
        7.5
    );
    assert_eq!(
        event_source_severity(&EventSourceIssue::CrossOriginStream),
        6.5
    );
    assert_eq!(
        event_source_severity(&EventSourceIssue::NoReconnectLimit),
        5.5
    );
    assert_eq!(
        event_source_severity(&EventSourceIssue::InjectionViaMessage),
        7.0
    );
}
