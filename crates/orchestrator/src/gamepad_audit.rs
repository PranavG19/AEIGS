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
