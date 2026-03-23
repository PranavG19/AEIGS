use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum DeviceMotionIssue {
    OrientationEventListener,
    MotionEventListener,
    AccelerometerApi,
    GyroscopeApi,
    SensorDataExfiltration,
    HighFrequencySampling,
    AbsoluteOrientationSensor,
}

impl std::fmt::Display for DeviceMotionIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OrientationEventListener => write!(f, "orientation_event_listener"),
            Self::MotionEventListener => write!(f, "motion_event_listener"),
            Self::AccelerometerApi => write!(f, "accelerometer_api"),
            Self::GyroscopeApi => write!(f, "gyroscope_api"),
            Self::SensorDataExfiltration => write!(f, "sensor_data_exfiltration"),
            Self::HighFrequencySampling => write!(f, "high_frequency_sampling"),
            Self::AbsoluteOrientationSensor => write!(f, "absolute_orientation_sensor"),
        }
    }
}

pub fn audit_device_motion(target: &str) -> Vec<DeviceMotionIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send().and_then(|r| r.text()) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    analyze_device_motion(&body)
}

pub fn analyze_device_motion(body: &str) -> Vec<DeviceMotionIssue> {
    if !has_motion_indicators(body) {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("deviceorientation") {
        issues.push(DeviceMotionIssue::OrientationEventListener);
    }

    if body.contains("devicemotion") {
        issues.push(DeviceMotionIssue::MotionEventListener);
    }

    if body.contains("Accelerometer") && body.contains("new ") {
        issues.push(DeviceMotionIssue::AccelerometerApi);
    }

    if body.contains("Gyroscope") && body.contains("new ") {
        issues.push(DeviceMotionIssue::GyroscopeApi);
    }

    let has_sensor = body.contains("deviceorientation")
        || body.contains("devicemotion")
        || body.contains("Accelerometer")
        || body.contains("Gyroscope");
    let sends = body.contains("fetch(")
        || body.contains("XMLHttpRequest")
        || body.contains(".send(")
        || body.contains("sendBeacon");
    if has_sensor && sends {
        issues.push(DeviceMotionIssue::SensorDataExfiltration);
    }

    if (body.contains("frequency") || body.contains("setInterval"))
        && (body.contains("devicemotion")
            || body.contains("Accelerometer")
            || body.contains("Gyroscope"))
    {
        issues.push(DeviceMotionIssue::HighFrequencySampling);
    }

    if body.contains("AbsoluteOrientationSensor")
        || body.contains("RelativeOrientationSensor")
    {
        issues.push(DeviceMotionIssue::AbsoluteOrientationSensor);
    }

    issues
}

fn has_motion_indicators(body: &str) -> bool {
    body.contains("deviceorientation")
        || body.contains("devicemotion")
        || body.contains("Accelerometer")
        || body.contains("Gyroscope")
        || body.contains("OrientationSensor")
}

pub fn device_motion_severity(issue: &DeviceMotionIssue) -> f64 {
    match issue {
        DeviceMotionIssue::SensorDataExfiltration => 7.0,
        DeviceMotionIssue::HighFrequencySampling => 6.5,
        DeviceMotionIssue::AbsoluteOrientationSensor => 6.0,
        DeviceMotionIssue::AccelerometerApi => 5.5,
        DeviceMotionIssue::GyroscopeApi => 5.5,
        DeviceMotionIssue::MotionEventListener => 4.5,
        DeviceMotionIssue::OrientationEventListener => 4.0,
    }
}

pub fn device_motion_to_operations(
    issues: &[DeviceMotionIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                device_motion_severity(issue),
                0.7,
            )
        })
        .collect()
}
