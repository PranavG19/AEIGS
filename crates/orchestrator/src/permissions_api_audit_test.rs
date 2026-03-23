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

#[test]
fn security_empty_body_no_issues() {
    let issues = analyze_permissions_api_security("");
    assert!(issues.is_empty());
}

#[test]
fn security_detects_excessive_permission_requests() {
    let body = r#"
        Notification.requestPermission();
        navigator.mediaDevices.getUserMedia({audio: true});
        navigator.mediaDevices.getUserMedia({video: true});
        navigator.permissions.request({name: 'geolocation'});
        navigator.requestMIDIAccess();
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(issues.contains(&PermissionsApiSecurityIssue::ExcessivePermissionRequests));
}

#[test]
fn security_four_requests_not_excessive() {
    let body = r#"
        Notification.requestPermission();
        navigator.mediaDevices.getUserMedia({audio: true});
        navigator.permissions.request({name: 'geolocation'});
        navigator.requestMIDIAccess();
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(!issues.contains(&PermissionsApiSecurityIssue::ExcessivePermissionRequests));
}

#[test]
fn security_detects_permission_without_user_gesture() {
    let body = r#"
        window.onload = function() {
            Notification.requestPermission();
        };
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(issues.contains(&PermissionsApiSecurityIssue::PermissionWithoutUserGesture));
}

#[test]
fn security_permission_with_click_allowed() {
    let body = r#"
        document.addEventListener('click', function() {
            Notification.requestPermission();
        });
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(!issues.contains(&PermissionsApiSecurityIssue::PermissionWithoutUserGesture));
}

#[test]
fn security_permission_with_mousedown_allowed() {
    let body = r#"
        button.addEventListener("mousedown", function() {
            navigator.mediaDevices.getUserMedia({audio: true});
        });
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(!issues.contains(&PermissionsApiSecurityIssue::PermissionWithoutUserGesture));
}

#[test]
fn security_detects_persistent_permission_query() {
    let body = r#"
        setInterval(function() {
            navigator.permissions.query({name: 'camera'});
        }, 1000);
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(issues.contains(&PermissionsApiSecurityIssue::PermissionPersistentQuery));
}

#[test]
fn security_detects_persistent_with_settimeout() {
    let body = r#"
        setTimeout(function poll() {
            navigator.permissions.request({name: 'notifications'});
            setTimeout(poll, 5000);
        }, 5000);
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(issues.contains(&PermissionsApiSecurityIssue::PermissionPersistentQuery));
}

#[test]
fn security_detects_silent_permission_change() {
    let body = r#"
        navigator.permissions.revoke({name: 'camera'});
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(issues.contains(&PermissionsApiSecurityIssue::SilentPermissionChange));
}

#[test]
fn security_revoke_with_alert_allowed() {
    let body = r#"
        navigator.permissions.revoke({name: 'camera'});
        alert('Permission revoked');
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(!issues.contains(&PermissionsApiSecurityIssue::SilentPermissionChange));
}

#[test]
fn security_revoke_with_console_allowed() {
    let body = r#"
        navigator.permissions.revoke({name: 'camera'});
        console.log('Permission revoked');
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(!issues.contains(&PermissionsApiSecurityIssue::SilentPermissionChange));
}

#[test]
fn security_detects_cross_origin_permission_check() {
    let body = r#"
        navigator.permissions.query({name: 'camera'}).then(status => {
            iframe.contentWindow.postMessage(status.state, '*');
        });
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(issues.contains(&PermissionsApiSecurityIssue::CrossOriginPermissionCheck));
}

#[test]
fn security_detects_cross_origin_with_iframe() {
    let body = r#"
        const iframe = document.createElement('iframe');
        navigator.permissions.request({name: 'geolocation'});
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(issues.contains(&PermissionsApiSecurityIssue::CrossOriginPermissionCheck));
}

#[test]
fn security_detects_permission_fingerprinting() {
    let body = r#"
        Promise.all([
            navigator.permissions.query({name: 'camera'}),
            navigator.permissions.query({name: 'microphone'}),
            navigator.permissions.query({name: 'geolocation'})
        ]).then(statuses => {
            fetch('/track', {
                method: 'POST',
                body: JSON.stringify(statuses.map(s => s.state))
            });
        });
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(issues.contains(&PermissionsApiSecurityIssue::PermissionFingerprinting));
}

#[test]
fn security_fingerprinting_requires_multiple_permissions() {
    let body = r#"
        navigator.permissions.query({name: 'camera'}).then(status => {
            fetch('/track?perm=' + status.state);
        });
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(!issues.contains(&PermissionsApiSecurityIssue::PermissionFingerprinting));
}

#[test]
fn security_detects_fingerprinting_with_beacon() {
    let body = r#"
        navigator.permissions.query({name: 'camera'});
        navigator.permissions.query({name: 'microphone'});
        navigator.permissions.query({name: 'geolocation'});
        navigator.sendBeacon('/analytics', data);
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(issues.contains(&PermissionsApiSecurityIssue::PermissionFingerprinting));
}

#[test]
fn security_detects_geolocation_without_purpose() {
    let body = r#"
        navigator.geolocation.getCurrentPosition(function(pos) {
            console.log(pos.coords.latitude, pos.coords.longitude);
        });
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(issues.contains(&PermissionsApiSecurityIssue::GeolocationWithoutPurpose));
}

#[test]
fn security_geolocation_with_map_allowed() {
    let body = r#"
        navigator.geolocation.getCurrentPosition(function(pos) {
            map.setCenter(pos.coords.latitude, pos.coords.longitude);
        });
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(!issues.contains(&PermissionsApiSecurityIssue::GeolocationWithoutPurpose));
}

#[test]
fn security_geolocation_with_location_allowed() {
    let body = r#"
        navigator.geolocation.getCurrentPosition(function(pos) {
            updateLocation(pos);
        });
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(!issues.contains(&PermissionsApiSecurityIssue::GeolocationWithoutPurpose));
}

#[test]
fn security_detects_camera_and_mic_together() {
    let body = r#"
        navigator.mediaDevices.getUserMedia({
            video: true,
            audio: true
        });
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(issues.contains(&PermissionsApiSecurityIssue::CameraAndMicTogether));
}

#[test]
fn security_detects_camera_and_mic_no_spaces() {
    let body = r#"
        navigator.mediaDevices.getUserMedia({
            video:true,
            audio:true
        });
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(issues.contains(&PermissionsApiSecurityIssue::CameraAndMicTogether));
}

#[test]
fn security_detects_camera_and_mic_via_names() {
    let body = r#"
        navigator.permissions.query({name: 'camera'});
        navigator.permissions.query({name: 'microphone'});
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(issues.contains(&PermissionsApiSecurityIssue::CameraAndMicTogether));
}

#[test]
fn security_video_only_allowed() {
    let body = r#"
        navigator.mediaDevices.getUserMedia({
            video: true,
            audio: false
        });
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(!issues.contains(&PermissionsApiSecurityIssue::CameraAndMicTogether));
}

#[test]
fn security_detects_notification_spam() {
    let body = r#"
        setInterval(function() {
            Notification.requestPermission();
        }, 60000);
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(issues.contains(&PermissionsApiSecurityIssue::NotificationSpam));
}

#[test]
fn security_single_notification_request_allowed() {
    let body = r#"
        Notification.requestPermission();
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(!issues.contains(&PermissionsApiSecurityIssue::NotificationSpam));
}

#[test]
fn security_detects_permission_gated_data_leak() {
    let body = r#"
        navigator.permissions.query({name: 'camera'}).then(status => {
            if (status.state === 'granted') {
                fetch('/leak', {
                    method: 'POST',
                    body: localStorage.getItem('token')
                });
            }
        });
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(issues.contains(&PermissionsApiSecurityIssue::PermissionGatedDataLeak));
}

#[test]
fn security_detects_leak_with_session_storage() {
    let body = r#"
        if (permStatus.state === 'granted') {
            var xhr = new XMLHttpRequest();
            xhr.send(sessionStorage.getItem('data'));
        }
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(issues.contains(&PermissionsApiSecurityIssue::PermissionGatedDataLeak));
}

#[test]
fn security_detects_leak_with_cookie() {
    let body = r#"
        navigator.permissions.query({name: 'notifications'}).then(s => {
            fetch('/track?cookie=' + document.cookie);
        });
    "#;
    let issues = analyze_permissions_api_security(body);
    assert!(issues.contains(&PermissionsApiSecurityIssue::PermissionGatedDataLeak));
}

#[test]
fn security_severity_data_leak_highest() {
    assert_eq!(
        permissions_api_security_severity(&PermissionsApiSecurityIssue::PermissionGatedDataLeak),
        8.5
    );
}

#[test]
fn security_severity_fingerprinting_high() {
    assert_eq!(
        permissions_api_security_severity(&PermissionsApiSecurityIssue::PermissionFingerprinting),
        8.0
    );
}

#[test]
fn security_severity_geolocation_lowest() {
    assert_eq!(
        permissions_api_security_severity(&PermissionsApiSecurityIssue::GeolocationWithoutPurpose),
        4.0
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        PermissionsApiSecurityIssue::ExcessivePermissionRequests,
        PermissionsApiSecurityIssue::CameraAndMicTogether,
        PermissionsApiSecurityIssue::PermissionGatedDataLeak,
    ];
    let mut seq = 0;
    let ops = permissions_api_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn security_display_excessive_requests() {
    assert_eq!(
        PermissionsApiSecurityIssue::ExcessivePermissionRequests.to_string(),
        "excessive_permission_requests"
    );
}

#[test]
fn security_display_without_gesture() {
    assert_eq!(
        PermissionsApiSecurityIssue::PermissionWithoutUserGesture.to_string(),
        "permission_without_user_gesture"
    );
}

#[test]
fn security_display_persistent_query() {
    assert_eq!(
        PermissionsApiSecurityIssue::PermissionPersistentQuery.to_string(),
        "permission_persistent_query"
    );
}

#[test]
fn security_display_silent_change() {
    assert_eq!(
        PermissionsApiSecurityIssue::SilentPermissionChange.to_string(),
        "silent_permission_change"
    );
}

#[test]
fn security_display_cross_origin() {
    assert_eq!(
        PermissionsApiSecurityIssue::CrossOriginPermissionCheck.to_string(),
        "cross_origin_permission_check"
    );
}

#[test]
fn security_display_fingerprinting() {
    assert_eq!(
        PermissionsApiSecurityIssue::PermissionFingerprinting.to_string(),
        "permission_fingerprinting"
    );
}

#[test]
fn security_display_geolocation() {
    assert_eq!(
        PermissionsApiSecurityIssue::GeolocationWithoutPurpose.to_string(),
        "geolocation_without_purpose"
    );
}

#[test]
fn security_display_camera_and_mic() {
    assert_eq!(
        PermissionsApiSecurityIssue::CameraAndMicTogether.to_string(),
        "camera_and_mic_together"
    );
}

#[test]
fn security_display_notification_spam() {
    assert_eq!(
        PermissionsApiSecurityIssue::NotificationSpam.to_string(),
        "notification_spam"
    );
}

#[test]
fn security_display_data_leak() {
    assert_eq!(
        PermissionsApiSecurityIssue::PermissionGatedDataLeak.to_string(),
        "permission_gated_data_leak"
    );
}
