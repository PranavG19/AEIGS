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
    assert_eq!(GamepadIssue::GetGamepadsPolling.to_string(), "get_gamepads_polling");
    assert_eq!(GamepadIssue::GamepadIdAccess.to_string(), "gamepad_id_access");
    assert_eq!(GamepadIssue::VibrationActuator.to_string(), "vibration_actuator");
    assert_eq!(GamepadIssue::MultipleGamepads.to_string(), "multiple_gamepads");
    assert_eq!(GamepadIssue::ContinuousPolling.to_string(), "continuous_polling");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_gamepad("").is_empty());
}
