use crate::permissions_api_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_permissions_api("");
    assert!(issues.is_empty());
}

#[test]
fn no_permissions_api_no_issues() {
    let body = "<html><body>Hello</body></html>";
    let issues = analyze_permissions_api(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_bulk_permission_query() {
    let body = r#"
        navigator.permissions.query({name: 'camera'});
        navigator.permissions.query({name: 'microphone'});
        navigator.permissions.query({name: 'geolocation'});
    "#;
    let issues = analyze_permissions_api(body);
    assert!(issues.contains(&PermissionsApiIssue::BulkPermissionQuery));
}

#[test]
fn two_permissions_not_bulk() {
    let body = r#"
        navigator.permissions.query({name: 'camera'});
        navigator.permissions.query({name: 'microphone'});
    "#;
    let issues = analyze_permissions_api(body);
    assert!(!issues.contains(&PermissionsApiIssue::BulkPermissionQuery));
}

#[test]
fn detects_permission_status_monitoring() {
    let body = r#"
        navigator.permissions.query({name: 'camera'}).then(s => {
            console.log(s.state);
        });
    "#;
    let issues = analyze_permissions_api(body);
    assert!(issues.contains(&PermissionsApiIssue::PermissionStatusMonitoring));
}

#[test]
fn detects_sensitive_permission_request() {
    let body = "navigator.permissions.query({name: 'camera'})";
    let issues = analyze_permissions_api(body);
    assert!(issues.contains(&PermissionsApiIssue::SensitivePermissionRequest));
}

#[test]
fn detects_permission_fingerprinting() {
    let body = r#"
        navigator.permissions.query({name: 'notifications'}).then(s => {
            fetch('/track?perm=' + s.state);
        });
    "#;
    let issues = analyze_permissions_api(body);
    assert!(issues.contains(&PermissionsApiIssue::PermissionFingerprinting));
}

#[test]
fn detects_onchange_tracking() {
    let body = r#"
        navigator.permissions.query({name: 'camera'}).then(s => {
            s.onchange = function() { report(s.state); };
        });
    "#;
    let issues = analyze_permissions_api(body);
    assert!(issues.contains(&PermissionsApiIssue::PermissionOnchangeTracking));
}

#[test]
fn detects_autoplay_permission_probe() {
    let body = "navigator.permissions.query({name: 'autoplay'})";
    let issues = analyze_permissions_api(body);
    assert!(issues.contains(&PermissionsApiIssue::AutoplayPermissionProbe));
}

#[test]
fn detects_midi_permission_request() {
    let body = "navigator.requestMIDIAccess({sysex: true})";
    let issues = analyze_permissions_api(body);
    assert!(issues.contains(&PermissionsApiIssue::MidiPermissionRequest));
}

#[test]
fn detects_midi_via_string() {
    let body = r#"navigator.permissions.query({name: "midi"})"#;
    let issues = analyze_permissions_api(body);
    assert!(issues.contains(&PermissionsApiIssue::MidiPermissionRequest));
}

#[test]
fn severity_fingerprinting_highest() {
    assert_eq!(
        permissions_api_severity(&PermissionsApiIssue::PermissionFingerprinting),
        7.0
    );
}

#[test]
fn severity_autoplay_lowest() {
    assert_eq!(
        permissions_api_severity(&PermissionsApiIssue::AutoplayPermissionProbe),
        4.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        PermissionsApiIssue::BulkPermissionQuery,
        PermissionsApiIssue::MidiPermissionRequest,
    ];
    let mut seq = 0;
    let ops = permissions_api_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        PermissionsApiIssue::BulkPermissionQuery.to_string(),
        "bulk_permission_query"
    );
    assert_eq!(
        PermissionsApiIssue::PermissionFingerprinting.to_string(),
        "permission_fingerprinting"
    );
    assert_eq!(
        PermissionsApiIssue::MidiPermissionRequest.to_string(),
        "midi_permission_request"
    );
    assert_eq!(
        PermissionsApiIssue::AutoplayPermissionProbe.to_string(),
        "autoplay_permission_probe"
    );
    assert_eq!(
        PermissionsApiIssue::PermissionOnchangeTracking.to_string(),
        "permission_onchange_tracking"
    );
}
