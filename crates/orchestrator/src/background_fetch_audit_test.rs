use crate::background_fetch_audit::*;

#[test]
fn no_issues_without_api() {
    let body = r#"<script>fetch('/data').then(r => r.json())</script>"#;
    let issues = analyze_background_fetch(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_api_via_background_fetch() {
    let body = "navigator.serviceWorker.ready.then(sw => sw.backgroundFetch.fetch('id', urls))";
    let issues = analyze_background_fetch(body);
    assert!(issues.iter().any(|i| *i == BackgroundFetchIssue::ApiDetected));
}

#[test]
fn detects_api_via_manager() {
    let body = "const mgr = new BackgroundFetchManager();";
    let issues = analyze_background_fetch(body);
    assert!(issues.iter().any(|i| *i == BackgroundFetchIssue::ApiDetected));
}

#[test]
fn detects_api_via_registration() {
    let body = "const reg = new BackgroundFetchRegistration();";
    let issues = analyze_background_fetch(body);
    assert!(issues.iter().any(|i| *i == BackgroundFetchIssue::ApiDetected));
}

#[test]
fn detects_data_exfiltration() {
    let body_ls = "sw.backgroundFetch.fetch('exfil', [fetch(localStorage.getItem('secret'))])";
    let issues_ls = analyze_background_fetch(body_ls);
    assert!(issues_ls.iter().any(|i| *i == BackgroundFetchIssue::DataExfiltration));

    let body_cookie = "sw.backgroundFetch.fetch('c', [fetch(document.cookie)])";
    let issues_cookie = analyze_background_fetch(body_cookie);
    assert!(issues_cookie.iter().any(|i| *i == BackgroundFetchIssue::DataExfiltration));
}

#[test]
fn no_exfiltration_without_fetch_call() {
    let body = "sw.backgroundFetch; localStorage.getItem('x');";
    let issues = analyze_background_fetch(body);
    assert!(!issues.iter().any(|i| *i == BackgroundFetchIssue::DataExfiltration));
}

#[test]
fn detects_large_download() {
    let body = "sw.backgroundFetch.fetch('big', urls, { downloadTotal: 1073741824 })";
    let issues = analyze_background_fetch(body);
    assert!(issues.iter().any(|i| *i == BackgroundFetchIssue::LargeDownload));
}

#[test]
fn no_large_download_with_confirm() {
    let body = "sw.backgroundFetch.fetch('big', urls, { downloadTotal: 5000000000 }); confirm('proceed?')";
    let issues = analyze_background_fetch(body);
    assert!(!issues.iter().any(|i| *i == BackgroundFetchIssue::LargeDownload));
}

#[test]
fn no_large_download_with_prompt() {
    let body = "sw.backgroundFetch.fetch('big', urls, { downloadTotal: 5000000000 }); prompt('size?')";
    let issues = analyze_background_fetch(body);
    assert!(!issues.iter().any(|i| *i == BackgroundFetchIssue::LargeDownload));
}

#[test]
fn detects_tracking_via_bg_fetch() {
    let body = "sw.backgroundFetch.fetch('t', urls); self.addEventListener('backgroundfetchsuccess', e => analytics.send(e))";
    let issues = analyze_background_fetch(body);
    assert!(issues.iter().any(|i| *i == BackgroundFetchIssue::TrackingViaBgFetch));
}

#[test]
fn no_tracking_without_analytics() {
    let body = "sw.backgroundFetch.fetch('t', urls); self.addEventListener('backgroundfetchsuccess', e => console.log(e))";
    let issues = analyze_background_fetch(body);
    assert!(!issues.iter().any(|i| *i == BackgroundFetchIssue::TrackingViaBgFetch));
}

#[test]
fn detects_resource_abuse() {
    let body = "sw.backgroundFetch.fetch('loop', urls); while(true) { fetch('/spam') }";
    let issues = analyze_background_fetch(body);
    assert!(issues.iter().any(|i| *i == BackgroundFetchIssue::ResourceAbuse));
}

#[test]
fn no_resource_abuse_with_limit() {
    let body = "sw.backgroundFetch.fetch('loop', urls); while(count < limit) { fetch('/data') }";
    let issues = analyze_background_fetch(body);
    assert!(!issues.iter().any(|i| *i == BackgroundFetchIssue::ResourceAbuse));
}

#[test]
fn all_issues_detected() {
    let body = concat!(
        "sw.backgroundFetch.fetch('all', [fetch(localStorage.getItem('x'))]);",
        " downloadTotal: 999GB;",
        " self.addEventListener('backgroundfetchsuccess', () => analytics.push());",
        " while(true) { fetch('/x') }",
    );
    let issues = analyze_background_fetch(body);
    assert_eq!(issues.len(), 5);
    assert_eq!(issues[0], BackgroundFetchIssue::ApiDetected);
    assert_eq!(issues[1], BackgroundFetchIssue::DataExfiltration);
    assert_eq!(issues[2], BackgroundFetchIssue::LargeDownload);
    assert_eq!(issues[3], BackgroundFetchIssue::TrackingViaBgFetch);
    assert_eq!(issues[4], BackgroundFetchIssue::ResourceAbuse);
}

#[test]
fn severity_values() {
    assert!((background_fetch_severity(&BackgroundFetchIssue::ApiDetected) - 2.0).abs() < f64::EPSILON);
    assert!((background_fetch_severity(&BackgroundFetchIssue::DataExfiltration) - 7.5).abs() < f64::EPSILON);
    assert!((background_fetch_severity(&BackgroundFetchIssue::LargeDownload) - 6.0).abs() < f64::EPSILON);
    assert!((background_fetch_severity(&BackgroundFetchIssue::TrackingViaBgFetch) - 6.5).abs() < f64::EPSILON);
    assert!((background_fetch_severity(&BackgroundFetchIssue::ResourceAbuse) - 5.5).abs() < f64::EPSILON);
}

#[test]
fn display_variants() {
    assert_eq!(BackgroundFetchIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(BackgroundFetchIssue::DataExfiltration.to_string(), "data_exfiltration");
    assert_eq!(BackgroundFetchIssue::LargeDownload.to_string(), "large_download");
    assert_eq!(BackgroundFetchIssue::TrackingViaBgFetch.to_string(), "tracking_via_bg_fetch");
    assert_eq!(BackgroundFetchIssue::ResourceAbuse.to_string(), "resource_abuse");
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = background_fetch_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_created_for_issues() {
    let issues = vec![
        BackgroundFetchIssue::ApiDetected,
        BackgroundFetchIssue::DataExfiltration,
        BackgroundFetchIssue::ResourceAbuse,
    ];
    let mut seq = 0;
    let ops = background_fetch_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}
