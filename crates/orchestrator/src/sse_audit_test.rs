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
    assert!(issues.iter().any(
        |i| matches!(i, SseIssue::SseEndpointExposed { url } if url == "/events")
    ));
}

#[test]
fn eventsource_single_quote() {
    let body = "var es = new EventSource('/stream');";
    let issues = analyze_sse_usage(body);
    assert!(issues.iter().any(
        |i| matches!(i, SseIssue::SseEndpointExposed { url } if url == "/stream")
    ));
}

#[test]
fn eventsource_backtick() {
    let body = "var es = new EventSource(`/subscribe`);";
    let issues = analyze_sse_usage(body);
    assert!(issues.iter().any(
        |i| matches!(i, SseIssue::SseEndpointExposed { url } if url == "/subscribe")
    ));
}

#[test]
fn http_eventsource_flagged() {
    let body = r#"var es = new EventSource("http://api.example.com/events");"#;
    let issues = analyze_sse_usage(body);
    assert!(issues
        .iter()
        .any(|i| matches!(i, SseIssue::EventSourceInsecure { .. })));
}

#[test]
fn https_eventsource_not_flagged_insecure() {
    let body = r#"var es = new EventSource("https://api.example.com/events");"#;
    let issues = analyze_sse_usage(body);
    assert!(!issues
        .iter()
        .any(|i| matches!(i, SseIssue::EventSourceInsecure { .. })));
}

#[test]
fn sse_path_with_eventsource_context() {
    let body = r#"
        const EventSource = require('eventsource');
        url = "/notifications"
    "#;
    let issues = analyze_sse_usage(body);
    assert!(issues.iter().any(
        |i| matches!(i, SseIssue::SseNoAuth { url } if url == "/notifications")
    ));
}

#[test]
fn sse_path_without_context_not_flagged() {
    let body = r#"<a href="/events">Events</a>"#;
    let issues = analyze_sse_usage(body);
    assert!(!issues
        .iter()
        .any(|i| matches!(i, SseIssue::SseNoAuth { .. })));
}

#[test]
fn user_input_in_sse_detected() {
    let body = r#"
        var params = new URLSearchParams(location.search);
        var es = new EventSource("/events?token=" + params.get("token"));
    "#;
    let issues = analyze_sse_usage(body);
    assert!(issues
        .iter()
        .any(|i| matches!(i, SseIssue::SseWithUserInput)));
}

#[test]
fn user_input_template_literal() {
    let body = r#"
        var es = new EventSource(`/events?id=${location.hash.slice(1)}`);
    "#;
    let issues = analyze_sse_usage(body);
    assert!(issues
        .iter()
        .any(|i| matches!(i, SseIssue::SseWithUserInput)));
}

#[test]
fn no_user_input_not_flagged() {
    let body = r#"var es = new EventSource("/static-events");"#;
    let issues = analyze_sse_usage(body);
    assert!(!issues
        .iter()
        .any(|i| matches!(i, SseIssue::SseWithUserInput)));
}

#[test]
fn severity_ordering() {
    assert!(
        sse_severity(&SseIssue::SseWithUserInput)
            > sse_severity(&SseIssue::EventSourceInsecure {
                url: "x".into()
            })
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
        SseIssue::SseEndpointExposed {
            url: "/x".into(),
        },
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
    assert!(issues
        .iter()
        .any(|i| matches!(i, SseIssue::SseNoAuth { url } if url == "/live")));
}
