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

    if body.contains("AbsoluteOrientationSensor") || body.contains("RelativeOrientationSensor") {
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

#[derive(Debug, Clone, PartialEq)]
pub enum DeviceMotionSecurityIssue {
    MotionFingerprinting,
    MotionKeylogging,
    MotionWithoutPermission,
    MotionCrossOrigin,
    MotionInBackground,
    MotionHighFrequency,
    MotionWithGeolocation,
    MotionDataExfiltration,
    MotionInIframe,
    MotionPersistentCollection,
}

impl std::fmt::Display for DeviceMotionSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MotionFingerprinting => write!(f, "motion_fingerprinting"),
            Self::MotionKeylogging => write!(f, "motion_keylogging"),
            Self::MotionWithoutPermission => write!(f, "motion_without_permission"),
            Self::MotionCrossOrigin => write!(f, "motion_cross_origin"),
            Self::MotionInBackground => write!(f, "motion_in_background"),
            Self::MotionHighFrequency => write!(f, "motion_high_frequency"),
            Self::MotionWithGeolocation => write!(f, "motion_with_geolocation"),
            Self::MotionDataExfiltration => write!(f, "motion_data_exfiltration"),
            Self::MotionInIframe => write!(f, "motion_in_iframe"),
            Self::MotionPersistentCollection => write!(f, "motion_persistent_collection"),
        }
    }
}

pub fn analyze_device_motion_security(body: &str) -> Vec<DeviceMotionSecurityIssue> {
    if !has_motion_indicators(body) {
        return Vec::new();
    }

    let mut issues = Vec::new();

    // MotionFingerprinting: using motion data for device identification
    let has_motion_sensor = body.contains("devicemotion")
        || body.contains("deviceorientation")
        || body.contains("Accelerometer")
        || body.contains("Gyroscope");
    let has_fingerprint_indicators = body.contains("fingerprint")
        || body.contains("deviceId")
        || body.contains("uniqueId")
        || (body.contains("canvas") && has_motion_sensor)
        || (body.contains("hash") && has_motion_sensor);
    if has_motion_sensor && has_fingerprint_indicators {
        issues.push(DeviceMotionSecurityIssue::MotionFingerprinting);
    }

    // MotionKeylogging: inferring keystrokes from motion patterns
    let body_lower = body.to_ascii_lowercase();
    let has_keystroke_inference = (body_lower.contains("keypress")
        || body_lower.contains("keyboard")
        || body_lower.contains("input")
        || body_lower.contains("typing"))
        && has_motion_sensor;
    if has_keystroke_inference {
        issues.push(DeviceMotionSecurityIssue::MotionKeylogging);
    }

    // MotionWithoutPermission: accessing motion without permission checks
    let has_permission_check = body.contains("requestPermission")
        || body.contains("permissions.query")
        || body.contains("DeviceMotionEvent.requestPermission")
        || body.contains("DeviceOrientationEvent.requestPermission");
    if has_motion_sensor && !has_permission_check {
        issues.push(DeviceMotionSecurityIssue::MotionWithoutPermission);
    }

    // MotionCrossOrigin: sharing motion data cross-origin
    let has_cross_origin = body.contains("postMessage")
        || body.contains("crossOrigin")
        || body.contains("cors")
        || body.contains("origin");
    if has_motion_sensor && has_cross_origin {
        issues.push(DeviceMotionSecurityIssue::MotionCrossOrigin);
    }

    // MotionInBackground: collecting motion when page not visible
    let checks_visibility = body.contains("visibilityState")
        || body.contains("document.hidden")
        || body.contains("pageVisibilityAPI");
    let has_background_collection = has_motion_sensor
        && (body.contains("setInterval") || body.contains("requestAnimationFrame"))
        && !checks_visibility;
    if has_background_collection {
        issues.push(DeviceMotionSecurityIssue::MotionInBackground);
    }

    // MotionHighFrequency: sampling at unusually high frequency (>60Hz)
    let has_high_freq = (body.contains("frequency") && body.contains("120"))
        || (body.contains("frequency") && body.contains("100"))
        || (body.contains("frequency") && body.contains("200"))
        || (body.contains("setInterval") && body.contains("5"))
        || (body.contains("setInterval") && body.contains("10"));
    if has_motion_sensor && has_high_freq {
        issues.push(DeviceMotionSecurityIssue::MotionHighFrequency);
    }

    // MotionWithGeolocation: combining motion with geolocation
    let has_geolocation = body.contains("geolocation")
        || body.contains("getCurrentPosition")
        || body.contains("watchPosition")
        || body.contains("coords")
        || body.contains("latitude");
    if has_motion_sensor && has_geolocation {
        issues.push(DeviceMotionSecurityIssue::MotionWithGeolocation);
    }

    // MotionDataExfiltration: sending motion data to external endpoints
    let has_network = body.contains("fetch(")
        || body.contains("XMLHttpRequest")
        || body.contains(".send(")
        || body.contains("sendBeacon")
        || body.contains("WebSocket");
    let has_external_domain = body.contains("https://")
        || body.contains("http://")
        || body.contains("//analytics")
        || body.contains("//tracking");
    if has_motion_sensor && has_network && has_external_domain {
        issues.push(DeviceMotionSecurityIssue::MotionDataExfiltration);
    }

    // MotionInIframe: accessing motion sensors from iframe context
    let has_iframe = body.contains("iframe")
        || body.contains("contentWindow")
        || body.contains("parent.postMessage")
        || body.contains("window.parent");
    if has_motion_sensor && has_iframe {
        issues.push(DeviceMotionSecurityIssue::MotionInIframe);
    }

    // MotionPersistentCollection: storing motion data persistently
    let has_storage = body.contains("localStorage")
        || body.contains("sessionStorage")
        || body.contains("IndexedDB")
        || body.contains("indexedDB")
        || body.contains("openDatabase");
    if has_motion_sensor && has_storage {
        issues.push(DeviceMotionSecurityIssue::MotionPersistentCollection);
    }

    issues
}

pub fn device_motion_security_severity(issue: &DeviceMotionSecurityIssue) -> f64 {
    match issue {
        DeviceMotionSecurityIssue::MotionKeylogging => 9.0,
        DeviceMotionSecurityIssue::MotionDataExfiltration => 8.5,
        DeviceMotionSecurityIssue::MotionFingerprinting => 8.0,
        DeviceMotionSecurityIssue::MotionWithGeolocation => 7.5,
        DeviceMotionSecurityIssue::MotionPersistentCollection => 7.0,
        DeviceMotionSecurityIssue::MotionCrossOrigin => 6.5,
        DeviceMotionSecurityIssue::MotionHighFrequency => 6.0,
        DeviceMotionSecurityIssue::MotionInBackground => 5.5,
        DeviceMotionSecurityIssue::MotionInIframe => 5.0,
        DeviceMotionSecurityIssue::MotionWithoutPermission => 4.5,
    }
}

pub fn device_motion_security_to_operations(
    issues: &[DeviceMotionSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                device_motion_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
