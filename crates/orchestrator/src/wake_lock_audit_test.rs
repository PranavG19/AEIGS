use crate::wake_lock_audit::*;

#[test]
fn no_wake_lock_no_issues() {
    assert!(analyze_wake_lock("<html></html>").is_empty());
}

#[test]
fn detects_wake_lock_request() {
    let body = r#"<script>navigator.wakeLock.request("screen")</script>"#;
    let issues = analyze_wake_lock(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockRequested));
}

#[test]
fn detects_screen_wake_lock() {
    let body = r#"<script>navigator.wakeLock.request("screen")</script>"#;
    let issues = analyze_wake_lock(body);
    assert!(issues.contains(&WakeLockIssue::ScreenWakeLock));
}

#[test]
fn detects_screen_single_quotes() {
    let body = r#"<script>navigator.wakeLock.request('screen')</script>"#;
    let issues = analyze_wake_lock(body);
    assert!(issues.contains(&WakeLockIssue::ScreenWakeLock));
}

#[test]
fn detects_no_release() {
    let body = r#"<script>
        const lock = await navigator.wakeLock.request("screen");
        doWork();
    </script>"#;
    let issues = analyze_wake_lock(body);
    assert!(issues.contains(&WakeLockIssue::NoRelease));
}

#[test]
fn no_release_issue_when_released() {
    let body = r#"<script>
        const lock = await navigator.wakeLock.request("screen");
        doWork();
        lock.release();
    </script>"#;
    let issues = analyze_wake_lock(body);
    assert!(!issues.contains(&WakeLockIssue::NoRelease));
}

#[test]
fn detects_no_visibility_check() {
    let body = r#"<script>navigator.wakeLock.request("screen")</script>"#;
    let issues = analyze_wake_lock(body);
    assert!(issues.contains(&WakeLockIssue::NoVisibilityCheck));
}

#[test]
fn no_visibility_issue_when_checked() {
    let body = r#"<script>
        const lock = await navigator.wakeLock.request("screen");
        document.addEventListener("visibilitychange", () => {
            if (document.hidden) lock.release();
        });
    </script>"#;
    let issues = analyze_wake_lock(body);
    assert!(!issues.contains(&WakeLockIssue::NoVisibilityCheck));
}

#[test]
fn detects_persistent_lock() {
    let body = r#"<script>
        setInterval(async () => {
            await navigator.wakeLock.request("screen");
        }, 10000);
    </script>"#;
    let issues = analyze_wake_lock(body);
    assert!(issues.contains(&WakeLockIssue::PersistentLock));
}

#[test]
fn severity_persistent_highest() {
    assert_eq!(wake_lock_severity(&WakeLockIssue::PersistentLock), 5.5);
}

#[test]
fn severity_requested_lowest() {
    assert_eq!(wake_lock_severity(&WakeLockIssue::WakeLockRequested), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![WakeLockIssue::WakeLockRequested, WakeLockIssue::NoRelease];
    let mut seq = 0;
    let ops = wake_lock_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        WakeLockIssue::WakeLockRequested.to_string(),
        "wake_lock_requested"
    );
    assert_eq!(
        WakeLockIssue::ScreenWakeLock.to_string(),
        "screen_wake_lock"
    );
    assert_eq!(WakeLockIssue::NoRelease.to_string(), "no_release");
    assert_eq!(
        WakeLockIssue::NoVisibilityCheck.to_string(),
        "no_visibility_check"
    );
    assert_eq!(WakeLockIssue::PersistentLock.to_string(), "persistent_lock");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_wake_lock("").is_empty());
}

#[test]
fn security_no_wake_lock_no_issues() {
    assert!(analyze_wake_lock_security("<html></html>").is_empty());
}

#[test]
fn security_empty_body_no_issues() {
    assert!(analyze_wake_lock_security("").is_empty());
}

#[test]
fn security_detects_background_with_background_keyword() {
    let body = r#"
        wakeLock.request();
        document.addEventListener("background", () => {});
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockInBackground));
}

#[test]
fn security_detects_background_with_hidden_keyword() {
    let body = r#"
        navigator.wakeLock.request("screen");
        if (document.hidden) { doSomething(); }
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockInBackground));
}

#[test]
fn security_detects_background_with_pagehide() {
    let body = r#"
        wakeLock.request();
        addEventListener("pagehide", () => {});
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockInBackground));
}

#[test]
fn security_no_background_without_request() {
    let body = r#"
        WakeLock.something();
        document.hidden;
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(!issues.contains(&WakeLockIssue::WakeLockInBackground));
}

#[test]
fn security_detects_tracking_with_fetch() {
    let body = r#"
        wakeLock.request();
        fetch("https://example.com/track", { method: "POST" });
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockWithTracking));
}

#[test]
fn security_detects_tracking_with_send_beacon() {
    let body = r#"
        navigator.wakeLock.request();
        navigator.sendBeacon("/analytics", data);
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockWithTracking));
}

#[test]
fn security_detects_tracking_with_xml_http_request() {
    let body = r#"
        WakeLock.request();
        const xhr = new XMLHttpRequest();
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockWithTracking));
}

#[test]
fn security_detects_battery_drain_with_get_battery() {
    let body = r#"
        wakeLock.request();
        navigator.getBattery().then(battery => {});
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockBatteryDrain));
}

#[test]
fn security_detects_battery_drain_with_battery_manager() {
    let body = r#"
        navigator.wakeLock.request("screen");
        const manager = BatteryManager.getInstance();
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockBatteryDrain));
}

#[test]
fn security_detects_battery_drain_with_battery_keyword() {
    let body = r#"
        WakeLock.request();
        checkBatteryLevel(battery.level);
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockBatteryDrain));
}

#[test]
fn security_detects_geolocation_with_get_current_position() {
    let body = r#"
        wakeLock.request();
        navigator.geolocation.getCurrentPosition(success);
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockWithGeolocation));
}

#[test]
fn security_detects_geolocation_with_watch_position() {
    let body = r#"
        navigator.wakeLock.request();
        navigator.geolocation.watchPosition(callback);
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockWithGeolocation));
}

#[test]
fn security_detects_geolocation_with_geolocation_keyword() {
    let body = r#"
        WakeLock.request();
        const geo = navigator.geolocation;
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockWithGeolocation));
}

#[test]
fn security_detects_cross_origin_with_post_message() {
    let body = r#"
        wakeLock.request();
        window.postMessage(data, "*");
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockCrossOrigin));
}

#[test]
fn security_detects_cross_origin_with_cross_origin_keyword() {
    let body = r#"
        navigator.wakeLock.request();
        fetch(url, { mode: "cross-origin" });
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockCrossOrigin));
}

#[test]
fn security_detects_cross_origin_with_iframe() {
    let body = r#"
        WakeLock.request();
        const frame = document.createElement("iframe");
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockCrossOrigin));
}

#[test]
fn security_detects_service_worker_with_service_worker_lowercase() {
    let body = r#"
        wakeLock.request();
        navigator.serviceWorker.register("/sw.js");
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockInServiceWorker));
}

#[test]
fn security_detects_service_worker_with_service_worker_capitalized() {
    let body = r#"
        navigator.wakeLock.request();
        const sw = new ServiceWorker();
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockInServiceWorker));
}

#[test]
fn security_detects_audio_with_audio_context() {
    let body = r#"
        wakeLock.request();
        const ctx = new AudioContext();
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockWithAudio));
}

#[test]
fn security_detects_audio_with_new_audio() {
    let body = r#"
        navigator.wakeLock.request();
        const audio = new Audio("sound.mp3");
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockWithAudio));
}

#[test]
fn security_detects_audio_with_media_stream() {
    let body = r#"
        WakeLock.request();
        navigator.mediaDevices.getUserMedia().then(MediaStream);
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockWithAudio));
}

#[test]
fn security_detects_dos_with_while_true_no_space() {
    let body = r#"
        wakeLock.request();
        while(true) { keepAlive(); }
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockDenialOfService));
}

#[test]
fn security_detects_dos_with_while_true_with_space() {
    let body = r#"
        navigator.wakeLock.request();
        while (true) { loop(); }
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockDenialOfService));
}

#[test]
fn security_detects_dos_with_for_infinite() {
    let body = r#"
        WakeLock.request();
        for(;;) { process(); }
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockDenialOfService));
}

#[test]
fn security_detects_dos_with_infinite_keyword() {
    let body = r#"
        wakeLock.request();
        createinfiniteLoop();
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockDenialOfService));
}

#[test]
fn security_detects_websocket_with_websocket_class() {
    let body = r#"
        wakeLock.request();
        const ws = new WebSocket("wss://example.com");
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockWithWebSocket));
}

#[test]
fn security_detects_websocket_with_ws_protocol() {
    let body = r#"
        navigator.wakeLock.request();
        connect("ws://localhost:8080");
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockWithWebSocket));
}

#[test]
fn security_detects_no_permission_check_without_permissions() {
    let body = r#"
        wakeLock.request();
        doSomething();
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockWithoutPermissionCheck));
}

#[test]
fn security_no_permission_issue_with_permissions_api() {
    let body = r#"
        wakeLock.request();
        navigator.permissions.query({ name: "wake-lock" });
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(!issues.contains(&WakeLockIssue::WakeLockWithoutPermissionCheck));
}

#[test]
fn security_no_permission_issue_with_query_call() {
    let body = r#"
        navigator.wakeLock.request();
        const status = await query({ name: "wake-lock" });
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(!issues.contains(&WakeLockIssue::WakeLockWithoutPermissionCheck));
}

#[test]
fn security_multiple_issues_detected() {
    let body = r#"
        wakeLock.request();
        fetch("/track");
        navigator.geolocation.getCurrentPosition();
        while(true) { loop(); }
    "#;
    let issues = analyze_wake_lock_security(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockWithTracking));
    assert!(issues.contains(&WakeLockIssue::WakeLockWithGeolocation));
    assert!(issues.contains(&WakeLockIssue::WakeLockDenialOfService));
    assert_eq!(issues.len(), 4);
}

#[test]
fn security_severity_dos_highest() {
    assert_eq!(
        wake_lock_severity(&WakeLockIssue::WakeLockDenialOfService),
        8.0
    );
}

#[test]
fn security_severity_geolocation_high() {
    assert_eq!(
        wake_lock_severity(&WakeLockIssue::WakeLockWithGeolocation),
        7.5
    );
}

#[test]
fn security_severity_tracking_high() {
    assert_eq!(
        wake_lock_severity(&WakeLockIssue::WakeLockWithTracking),
        7.0
    );
}

#[test]
fn security_severity_cross_origin_medium_high() {
    assert_eq!(wake_lock_severity(&WakeLockIssue::WakeLockCrossOrigin), 6.5);
}

#[test]
fn security_severity_background_medium() {
    assert_eq!(
        wake_lock_severity(&WakeLockIssue::WakeLockInBackground),
        6.0
    );
}

#[test]
fn security_severity_service_worker_medium() {
    assert_eq!(
        wake_lock_severity(&WakeLockIssue::WakeLockInServiceWorker),
        6.0
    );
}

#[test]
fn security_severity_battery_medium_low() {
    assert_eq!(
        wake_lock_severity(&WakeLockIssue::WakeLockBatteryDrain),
        5.5
    );
}

#[test]
fn security_severity_websocket_medium_low() {
    assert_eq!(
        wake_lock_severity(&WakeLockIssue::WakeLockWithWebSocket),
        5.5
    );
}

#[test]
fn security_severity_audio_low() {
    assert_eq!(wake_lock_severity(&WakeLockIssue::WakeLockWithAudio), 5.0);
}

#[test]
fn security_severity_no_permission_low() {
    assert_eq!(
        wake_lock_severity(&WakeLockIssue::WakeLockWithoutPermissionCheck),
        4.0
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        WakeLockIssue::WakeLockWithTracking,
        WakeLockIssue::WakeLockDenialOfService,
    ];
    let mut seq = 0;
    let ops = wake_lock_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_new_variants() {
    assert_eq!(
        WakeLockIssue::WakeLockInBackground.to_string(),
        "wake_lock_in_background"
    );
    assert_eq!(
        WakeLockIssue::WakeLockWithTracking.to_string(),
        "wake_lock_with_tracking"
    );
    assert_eq!(
        WakeLockIssue::WakeLockBatteryDrain.to_string(),
        "wake_lock_battery_drain"
    );
    assert_eq!(
        WakeLockIssue::WakeLockWithGeolocation.to_string(),
        "wake_lock_with_geolocation"
    );
    assert_eq!(
        WakeLockIssue::WakeLockCrossOrigin.to_string(),
        "wake_lock_cross_origin"
    );
    assert_eq!(
        WakeLockIssue::WakeLockInServiceWorker.to_string(),
        "wake_lock_in_service_worker"
    );
    assert_eq!(
        WakeLockIssue::WakeLockWithAudio.to_string(),
        "wake_lock_with_audio"
    );
    assert_eq!(
        WakeLockIssue::WakeLockDenialOfService.to_string(),
        "wake_lock_denial_of_service"
    );
    assert_eq!(
        WakeLockIssue::WakeLockWithWebSocket.to_string(),
        "wake_lock_with_web_socket"
    );
    assert_eq!(
        WakeLockIssue::WakeLockWithoutPermissionCheck.to_string(),
        "wake_lock_without_permission_check"
    );
}
