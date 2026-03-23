use crate::gamepad_audit::*;

#[test]
fn no_gamepad_no_issues() {
    assert!(analyze_gamepad("<html></html>").is_empty());
}

#[test]
fn detects_api_via_event() {
    let body = r#"<script>window.addEventListener("gamepadconnected", handler)</script>"#;
    let issues = analyze_gamepad(body);
    assert!(issues.contains(&GamepadIssue::ApiDetected));
}

#[test]
fn detects_get_gamepads() {
    let body = r#"<script>const pads = navigator.getGamepads()</script>"#;
    let issues = analyze_gamepad(body);
    assert!(issues.contains(&GamepadIssue::GetGamepadsPolling));
}

#[test]
fn detects_continuous_polling_raf() {
    let body = r#"<script>
        function poll() {
            const pads = navigator.getGamepads();
            requestAnimationFrame(poll);
        }
    </script>"#;
    let issues = analyze_gamepad(body);
    assert!(issues.contains(&GamepadIssue::ContinuousPolling));
}

#[test]
fn detects_continuous_polling_interval() {
    let body = r#"<script>setInterval(() => navigator.getGamepads(), 16)</script>"#;
    let issues = analyze_gamepad(body);
    assert!(issues.contains(&GamepadIssue::ContinuousPolling));
}

#[test]
fn detects_gamepad_id_access() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        console.log(gamepad.id);
    </script>"#;
    let issues = analyze_gamepad(body);
    assert!(issues.contains(&GamepadIssue::GamepadIdAccess));
}

#[test]
fn detects_vibration_actuator() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        pad.vibrationActuator.playEffect("dual-rumble", {});
    </script>"#;
    let issues = analyze_gamepad(body);
    assert!(issues.contains(&GamepadIssue::VibrationActuator));
}

#[test]
fn detects_haptic_actuators() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        pad.hapticActuators[0].pulse(1.0, 200);
    </script>"#;
    let issues = analyze_gamepad(body);
    assert!(issues.contains(&GamepadIssue::VibrationActuator));
}

#[test]
fn detects_multiple_gamepads() {
    let body = r#"<script>
        const pads = navigator.getGamepads();
        for (let i = 0; i < pads.length; i++) {}
    </script>"#;
    let issues = analyze_gamepad(body);
    assert!(issues.contains(&GamepadIssue::MultipleGamepads));
}

#[test]
fn severity_id_highest() {
    assert_eq!(gamepad_severity(&GamepadIssue::GamepadIdAccess), 5.5);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(gamepad_severity(&GamepadIssue::ApiDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![GamepadIssue::ApiDetected, GamepadIssue::GamepadIdAccess];
    let mut seq = 0;
    let ops = gamepad_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(GamepadIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        GamepadIssue::GetGamepadsPolling.to_string(),
        "get_gamepads_polling"
    );
    assert_eq!(
        GamepadIssue::GamepadIdAccess.to_string(),
        "gamepad_id_access"
    );
    assert_eq!(
        GamepadIssue::VibrationActuator.to_string(),
        "vibration_actuator"
    );
    assert_eq!(
        GamepadIssue::MultipleGamepads.to_string(),
        "multiple_gamepads"
    );
    assert_eq!(
        GamepadIssue::ContinuousPolling.to_string(),
        "continuous_polling"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_gamepad("").is_empty());
}

// Tests for analyze_gamepad_security function

#[test]
fn security_no_gamepad_api_returns_empty() {
    let body = r#"<script>console.log("hello")</script>"#;
    assert!(analyze_gamepad_security(body).is_empty());
}

#[test]
fn security_detects_fingerprinting_mapping_hash() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        const fingerprint = hash(pad.mapping + pad.vendor);
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadFingerprinting));
}

#[test]
fn security_detects_fingerprinting_id_fingerprint() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        const fp = fingerprint(pad.id);
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadFingerprinting));
}

#[test]
fn security_no_fingerprinting_without_hash() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        console.log(pad.mapping);
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(!issues.contains(&GamepadIssue::GamepadFingerprinting));
}

#[test]
fn security_detects_data_exfiltration_fetch() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        fetch('/api/log', { body: JSON.stringify(pad) });
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadDataExfiltration));
}

#[test]
fn security_detects_data_exfiltration_sendbeacon() {
    let body = r#"<script>
        window.addEventListener('gamepadconnected', (e) => {
            navigator.sendBeacon('/track', JSON.stringify(e.gamepad));
        });
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadDataExfiltration));
}

#[test]
fn security_detects_data_exfiltration_xhr() {
    let body = r#"<script>
        const xhr = new XMLHttpRequest();
        const pad = navigator.getGamepads()[0];
        xhr.send(JSON.stringify(pad));
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadDataExfiltration));
}

#[test]
fn security_no_exfiltration_without_network_call() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        console.log(pad);
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(!issues.contains(&GamepadIssue::GamepadDataExfiltration));
}

#[test]
fn security_detects_input_recording_record() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        record(pad.buttons);
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadInputRecording));
}

#[test]
fn security_detects_input_recording_keylog() {
    let body = r#"<script>
        window.addEventListener('gamepadconnected', () => {
            const pad = navigator.getGamepads()[0];
            keylog.push(pad.buttons);
        });
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadInputRecording));
}

#[test]
fn security_detects_input_recording_history() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        inputHistory.push(pad.buttons[0]);
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadInputRecording));
}

#[test]
fn security_detects_input_recording_buttonlog() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        buttonLog.append(pad.buttons);
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadInputRecording));
}

#[test]
fn security_detects_input_recording_push_button() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        history.push(pad.buttons[0].pressed);
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadInputRecording));
}

#[test]
fn security_no_recording_without_keywords() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        if (pad.buttons[0].pressed) console.log('pressed');
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(!issues.contains(&GamepadIssue::GamepadInputRecording));
}

#[test]
fn security_detects_button_mapping_buttons_standard() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        if (pad.mapping === 'standard') {
            console.log(pad.buttons[0]);
        }
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadButtonMapping));
}

#[test]
fn security_detects_button_mapping_axes_standard() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        const x = pad.axes[0];
        const isStandard = pad.mapping === 'standard';
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadButtonMapping));
}

#[test]
fn security_no_button_mapping_without_standard() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        console.log(pad.buttons[0]);
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(!issues.contains(&GamepadIssue::GamepadButtonMapping));
}

#[test]
fn security_detects_timing_attack_performance_now() {
    let body = r#"<script>
        const start = performance.now();
        const pad = navigator.getGamepads()[0];
        const elapsed = performance.now() - start;
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadTimingAttack));
}

#[test]
fn security_detects_timing_attack_date_now() {
    let body = r#"<script>
        window.addEventListener('gamepadconnected', () => {
            const t = Date.now();
        });
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadTimingAttack));
}

#[test]
fn security_detects_timing_attack_timestamp() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        const data = { timestamp: Date.now(), buttons: pad.buttons };
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadTimingAttack));
}

#[test]
fn security_no_timing_attack_without_timing_apis() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        console.log(pad.buttons);
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(!issues.contains(&GamepadIssue::GamepadTimingAttack));
}

#[test]
fn security_detects_in_worker_worker_keyword() {
    let body = r#"<script>
        const worker = new Worker('gamepad-worker.js');
        worker.postMessage(navigator.getGamepads());
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadInWorker));
}

#[test]
fn security_detects_in_worker_postmessage() {
    let body = r#"<script>
        window.addEventListener('gamepadconnected', (e) => {
            postMessage(e.gamepad);
        });
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadInWorker));
}

#[test]
fn security_detects_in_worker_sharedworker() {
    let body = r#"<script>
        const shared = new SharedWorker('shared.js');
        const pad = navigator.getGamepads()[0];
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadInWorker));
}

#[test]
fn security_no_worker_without_keywords() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        console.log(pad);
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(!issues.contains(&GamepadIssue::GamepadInWorker));
}

#[test]
fn security_detects_pose_tracking_pose() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        if (pad.pose) console.log(pad.pose);
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadPoseTracking));
}

#[test]
fn security_detects_pose_tracking_orientation() {
    let body = r#"<script>
        window.addEventListener('gamepadconnected', (e) => {
            const orientation = e.gamepad.pose.orientation;
        });
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadPoseTracking));
}

#[test]
fn security_detects_pose_tracking_position() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        const pos = pad.pose.position;
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadPoseTracking));
}

#[test]
fn security_detects_pose_tracking_velocity() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        const vel = pad.pose.linearVelocity;
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadPoseTracking));
}

#[test]
fn security_no_pose_tracking_without_keywords() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        console.log(pad.buttons);
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(!issues.contains(&GamepadIssue::GamepadPoseTracking));
}

#[test]
fn security_detects_touchpad_access_touchevents() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        const touchEvents = pad.touchEvents;
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadTouchpadAccess));
}

#[test]
fn security_detects_touchpad_access_touchpad() {
    let body = r#"<script>
        window.addEventListener('gamepadconnected', (e) => {
            if (e.gamepad.touchpad) console.log('has touchpad');
        });
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadTouchpadAccess));
}

#[test]
fn security_detects_touchpad_access_touch_gamepad() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        const touch = pad.touch;
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadTouchpadAccess));
}

#[test]
fn security_no_touchpad_access_without_keywords() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        console.log(pad.buttons);
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(!issues.contains(&GamepadIssue::GamepadTouchpadAccess));
}

#[test]
fn security_detects_cross_origin_postmessage() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        parent.postMessage(pad, '*');
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadCrossOriginSharing));
}

#[test]
fn security_detects_cross_origin_cross_origin_keyword() {
    let body = r#"<script>
        // cross-origin gamepad sharing
        window.addEventListener('gamepadconnected', (e) => {
            shareGamepad(e.gamepad);
        });
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadCrossOriginSharing));
}

#[test]
fn security_detects_cross_origin_iframe() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        document.querySelector('iframe').contentWindow.postMessage(pad);
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadCrossOriginSharing));
}

#[test]
fn security_no_cross_origin_without_keywords() {
    let body = r#"<script>
        const pad = navigator.getGamepads()[0];
        localStorage.setItem('pad', JSON.stringify(pad));
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(!issues.contains(&GamepadIssue::GamepadCrossOriginSharing));
}

#[test]
fn security_detects_without_user_gesture() {
    let body = r#"<script>
        setInterval(() => {
            const pads = navigator.getGamepads();
        }, 100);
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadWithoutUserGesture));
}

#[test]
fn security_no_without_user_gesture_with_listener() {
    let body = r#"<script>
        window.addEventListener('gamepadconnected', (e) => {
            console.log(e.gamepad);
        });
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(!issues.contains(&GamepadIssue::GamepadWithoutUserGesture));
}

#[test]
fn security_no_without_user_gesture_with_click() {
    let body = r#"<script>
        button.onclick = () => {
            const pad = navigator.getGamepads()[0];
        };
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(!issues.contains(&GamepadIssue::GamepadWithoutUserGesture));
}

#[test]
fn security_multiple_issues_realistic_code() {
    let body = r#"<script>
        const worker = new Worker('gamepad.js');
        setInterval(() => {
            const pad = navigator.getGamepads()[0];
            if (pad) {
                const data = {
                    timestamp: performance.now(),
                    buttons: pad.buttons,
                    mapping: pad.mapping
                };
                fetch('/track', {
                    method: 'POST',
                    body: JSON.stringify(data)
                });
            }
        }, 50);
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadDataExfiltration));
    assert!(issues.contains(&GamepadIssue::GamepadTimingAttack));
    assert!(issues.contains(&GamepadIssue::GamepadInWorker));
    assert!(issues.contains(&GamepadIssue::GamepadWithoutUserGesture));
}

#[test]
fn security_combined_fingerprinting_and_recording() {
    let body = r#"<script>
        window.addEventListener('gamepadconnected', (e) => {
            const fp = hash(e.gamepad.id + e.gamepad.mapping);
            inputHistory.push({ fingerprint: fp, buttons: e.gamepad.buttons });
        });
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadFingerprinting));
    assert!(issues.contains(&GamepadIssue::GamepadInputRecording));
}

#[test]
fn security_display_new_variants() {
    assert_eq!(
        GamepadIssue::GamepadFingerprinting.to_string(),
        "gamepad_fingerprinting"
    );
    assert_eq!(
        GamepadIssue::GamepadDataExfiltration.to_string(),
        "gamepad_data_exfiltration"
    );
    assert_eq!(
        GamepadIssue::GamepadInputRecording.to_string(),
        "gamepad_input_recording"
    );
    assert_eq!(
        GamepadIssue::GamepadButtonMapping.to_string(),
        "gamepad_button_mapping"
    );
    assert_eq!(
        GamepadIssue::GamepadTimingAttack.to_string(),
        "gamepad_timing_attack"
    );
    assert_eq!(
        GamepadIssue::GamepadInWorker.to_string(),
        "gamepad_in_worker"
    );
    assert_eq!(
        GamepadIssue::GamepadPoseTracking.to_string(),
        "gamepad_pose_tracking"
    );
    assert_eq!(
        GamepadIssue::GamepadTouchpadAccess.to_string(),
        "gamepad_touchpad_access"
    );
    assert_eq!(
        GamepadIssue::GamepadCrossOriginSharing.to_string(),
        "gamepad_cross_origin_sharing"
    );
    assert_eq!(
        GamepadIssue::GamepadWithoutUserGesture.to_string(),
        "gamepad_without_user_gesture"
    );
}

#[test]
fn security_severity_data_exfiltration_highest() {
    assert_eq!(
        gamepad_severity(&GamepadIssue::GamepadDataExfiltration),
        8.0
    );
}

#[test]
fn security_severity_cross_origin_high() {
    assert_eq!(
        gamepad_severity(&GamepadIssue::GamepadCrossOriginSharing),
        7.5
    );
}

#[test]
fn security_severity_without_gesture_lowest() {
    assert_eq!(
        gamepad_severity(&GamepadIssue::GamepadWithoutUserGesture),
        4.5
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        GamepadIssue::GamepadFingerprinting,
        GamepadIssue::GamepadDataExfiltration,
    ];
    let mut seq = 0;
    let ops = gamepad_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_empty_without_gamepad_event() {
    let body = r#"<script>
        fetch('/api/data');
        const worker = new Worker('test.js');
    </script>"#;
    assert!(analyze_gamepad_security(body).is_empty());
}

#[test]
fn security_gamepadevent_triggers_analysis() {
    let body = r#"<script>
        if (event instanceof GamepadEvent) {
            fetch('/api/track');
        }
    </script>"#;
    let issues = analyze_gamepad_security(body);
    assert!(issues.contains(&GamepadIssue::GamepadDataExfiltration));
}
