use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum GamepadIssue {
    ApiDetected,
    GetGamepadsPolling,
    GamepadIdAccess,
    VibrationActuator,
    MultipleGamepads,
    ContinuousPolling,
    GamepadFingerprinting,
    GamepadDataExfiltration,
    GamepadInputRecording,
    GamepadButtonMapping,
    GamepadTimingAttack,
    GamepadInWorker,
    GamepadPoseTracking,
    GamepadTouchpadAccess,
    GamepadCrossOriginSharing,
    GamepadWithoutUserGesture,
}

impl std::fmt::Display for GamepadIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::GetGamepadsPolling => write!(f, "get_gamepads_polling"),
            Self::GamepadIdAccess => write!(f, "gamepad_id_access"),
            Self::VibrationActuator => write!(f, "vibration_actuator"),
            Self::MultipleGamepads => write!(f, "multiple_gamepads"),
            Self::ContinuousPolling => write!(f, "continuous_polling"),
            Self::GamepadFingerprinting => write!(f, "gamepad_fingerprinting"),
            Self::GamepadDataExfiltration => write!(f, "gamepad_data_exfiltration"),
            Self::GamepadInputRecording => write!(f, "gamepad_input_recording"),
            Self::GamepadButtonMapping => write!(f, "gamepad_button_mapping"),
            Self::GamepadTimingAttack => write!(f, "gamepad_timing_attack"),
            Self::GamepadInWorker => write!(f, "gamepad_in_worker"),
            Self::GamepadPoseTracking => write!(f, "gamepad_pose_tracking"),
            Self::GamepadTouchpadAccess => write!(f, "gamepad_touchpad_access"),
            Self::GamepadCrossOriginSharing => write!(f, "gamepad_cross_origin_sharing"),
            Self::GamepadWithoutUserGesture => write!(f, "gamepad_without_user_gesture"),
        }
    }
}

pub fn audit_gamepad(target: &str) -> Vec<GamepadIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send() {
        Ok(r) => r.text().unwrap_or_default(),
        Err(_) => return Vec::new(),
    };
    analyze_gamepad(&body)
}

pub fn analyze_gamepad(body: &str) -> Vec<GamepadIssue> {
    let has_event = body.contains("gamepadconnected") || body.contains("gamepaddisconnected");
    let has_api = body.contains("getGamepads") || has_event;
    if !has_api {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(GamepadIssue::ApiDetected);

    if body.contains("getGamepads") {
        issues.push(GamepadIssue::GetGamepadsPolling);

        if body.contains("requestAnimationFrame") || body.contains("setInterval") {
            issues.push(GamepadIssue::ContinuousPolling);
        }
    }

    if body.contains(".id") && (body.contains("gamepad") || body.contains("Gamepad")) {
        issues.push(GamepadIssue::GamepadIdAccess);
    }

    if body.contains("vibrationActuator") || body.contains("hapticActuators") {
        issues.push(GamepadIssue::VibrationActuator);
    }

    if body.contains(".length") && body.contains("getGamepads") {
        issues.push(GamepadIssue::MultipleGamepads);
    }

    issues
}

pub fn gamepad_severity(issue: &GamepadIssue) -> f64 {
    match issue {
        GamepadIssue::GamepadIdAccess => 5.5,
        GamepadIssue::ContinuousPolling => 5.0,
        GamepadIssue::MultipleGamepads => 4.5,
        GamepadIssue::VibrationActuator => 4.0,
        GamepadIssue::GetGamepadsPolling => 3.5,
        GamepadIssue::ApiDetected => 3.0,
        GamepadIssue::GamepadDataExfiltration => 8.0,
        GamepadIssue::GamepadCrossOriginSharing => 7.5,
        GamepadIssue::GamepadInputRecording => 7.5,
        GamepadIssue::GamepadFingerprinting => 7.0,
        GamepadIssue::GamepadPoseTracking => 7.0,
        GamepadIssue::GamepadTimingAttack => 6.5,
        GamepadIssue::GamepadInWorker => 6.0,
        GamepadIssue::GamepadTouchpadAccess => 5.5,
        GamepadIssue::GamepadButtonMapping => 5.0,
        GamepadIssue::GamepadWithoutUserGesture => 4.5,
    }
}

pub fn gamepad_to_operations(issues: &[GamepadIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                gamepad_severity(issue),
                0.6,
            )
        })
        .collect()
}

pub fn analyze_gamepad_security(body: &str) -> Vec<GamepadIssue> {
    let has_api = body.contains("getGamepads")
        || body.contains("gamepadconnected")
        || body.contains("gamepaddisconnected")
        || body.contains("GamepadEvent");
    if !has_api {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if (body.contains("mapping") || body.contains("vendor") || body.contains(".id"))
        && (body.contains("hash") || body.contains("fingerprint"))
    {
        issues.push(GamepadIssue::GamepadFingerprinting);
    }

    if body.contains("fetch(")
        || body.contains("sendBeacon")
        || body.contains("XMLHttpRequest")
        || body.contains(".send(")
    {
        issues.push(GamepadIssue::GamepadDataExfiltration);
    }

    if body.contains("record")
        || body.contains("keylog")
        || body.contains("inputHistory")
        || body.contains("buttonLog")
        || (body.contains("push(") && body.contains("button"))
    {
        issues.push(GamepadIssue::GamepadInputRecording);
    }

    if (body.contains("buttons[") || body.contains("axes[") || body.contains("mapping"))
        && body.contains("standard")
    {
        issues.push(GamepadIssue::GamepadButtonMapping);
    }

    if body.contains("performance.now") || body.contains("Date.now") || body.contains("timestamp") {
        issues.push(GamepadIssue::GamepadTimingAttack);
    }

    if body.contains("Worker") || body.contains("postMessage") || body.contains("SharedWorker") {
        issues.push(GamepadIssue::GamepadInWorker);
    }

    if body.contains("pose")
        || body.contains("orientation")
        || body.contains("position")
        || body.contains("linearVelocity")
    {
        issues.push(GamepadIssue::GamepadPoseTracking);
    }

    if body.contains("touchEvents")
        || body.contains("touchpad")
        || (body.contains("touch") && (body.contains("gamepad") || body.contains("Gamepad")))
    {
        issues.push(GamepadIssue::GamepadTouchpadAccess);
    }

    if body.contains("postMessage") || body.contains("cross-origin") || body.contains("iframe") {
        issues.push(GamepadIssue::GamepadCrossOriginSharing);
    }

    if !body.contains("addEventListener")
        && !body.contains("onclick")
        && !body.contains("click")
        && !body.contains("user-gesture")
    {
        issues.push(GamepadIssue::GamepadWithoutUserGesture);
    }

    issues
}

pub fn gamepad_security_to_operations(
    issues: &[GamepadIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                gamepad_severity(issue),
                0.6,
            )
        })
        .collect()
}
