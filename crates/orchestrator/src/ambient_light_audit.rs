use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum AmbientLightIssue {
    ApiDetected,
    LightExfiltration,
    HighFrequencyReading,
    CrossOriginLeak,
    ScreenContentInference,
}

impl std::fmt::Display for AmbientLightIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::LightExfiltration => write!(f, "light_exfiltration"),
            Self::HighFrequencyReading => write!(f, "high_frequency_reading"),
            Self::CrossOriginLeak => write!(f, "cross_origin_leak"),
            Self::ScreenContentInference => write!(f, "screen_content_inference"),
        }
    }
}

pub fn audit_ambient_light(target: &str) -> Vec<AmbientLightIssue> {
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
    analyze_ambient_light(&body)
}

pub fn analyze_ambient_light(body: &str) -> Vec<AmbientLightIssue> {
    if !body.contains("AmbientLightSensor") && !body.contains("devicelight") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(AmbientLightIssue::ApiDetected);

    let has_exfil =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_exfil {
        issues.push(AmbientLightIssue::LightExfiltration);
    }

    if body.contains("frequency") || body.contains("requestAnimationFrame") {
        issues.push(AmbientLightIssue::HighFrequencyReading);
    }

    if body.contains("iframe") || body.contains("postMessage") {
        issues.push(AmbientLightIssue::CrossOriginLeak);
    }

    if body.contains("illuminance")
        && (body.contains("threshold") || body.contains("Array") || body.contains("history"))
    {
        issues.push(AmbientLightIssue::ScreenContentInference);
    }

    issues
}

pub fn ambient_light_severity(issue: &AmbientLightIssue) -> f64 {
    match issue {
        AmbientLightIssue::ScreenContentInference => 7.0,
        AmbientLightIssue::LightExfiltration => 6.5,
        AmbientLightIssue::CrossOriginLeak => 6.0,
        AmbientLightIssue::HighFrequencyReading => 5.0,
        AmbientLightIssue::ApiDetected => 3.0,
    }
}

pub fn ambient_light_to_operations(
    issues: &[AmbientLightIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                ambient_light_severity(issue),
                0.6,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum AmbientLightSecurityIssue {
    SensorCreatedWithoutFeaturePolicy,
    DataCollectionWithoutConsent,
    TimingAttackVector,
    AmbientLightFingerprint,
    UnencryptedTransmission,
    WorkerBasedCollection,
    CanvasCorrelation,
    BatteryCorrelation,
    HighSampleRateExfiltration,
    PersistentStorage,
}

impl std::fmt::Display for AmbientLightSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SensorCreatedWithoutFeaturePolicy => {
                write!(f, "sensor_created_without_feature_policy")
            }
            Self::DataCollectionWithoutConsent => write!(f, "data_collection_without_consent"),
            Self::TimingAttackVector => write!(f, "timing_attack_vector"),
            Self::AmbientLightFingerprint => write!(f, "ambient_light_fingerprint"),
            Self::UnencryptedTransmission => write!(f, "unencrypted_transmission"),
            Self::WorkerBasedCollection => write!(f, "worker_based_collection"),
            Self::CanvasCorrelation => write!(f, "canvas_correlation"),
            Self::BatteryCorrelation => write!(f, "battery_correlation"),
            Self::HighSampleRateExfiltration => write!(f, "high_sample_rate_exfiltration"),
            Self::PersistentStorage => write!(f, "persistent_storage"),
        }
    }
}

pub fn analyze_ambient_light_security(body: &str) -> Vec<AmbientLightSecurityIssue> {
    // Check for actual sensor usage, not just mentions in comments
    let has_sensor_usage = body.contains("new AmbientLightSensor")
        || body.contains("addEventListener(\"devicelight\"");

    if !has_sensor_usage {
        return Vec::new();
    }

    let mut issues = Vec::new();

    // 1. SensorCreatedWithoutFeaturePolicy
    let has_feature_policy = body.contains("Permissions-Policy")
        || body.contains("Feature-Policy")
        || body.contains("ambient-light-sensor");
    if !has_feature_policy {
        issues.push(AmbientLightSecurityIssue::SensorCreatedWithoutFeaturePolicy);
    }

    // 2. DataCollectionWithoutConsent
    let has_storage = body.contains("localStorage")
        || body.contains("sessionStorage")
        || body.contains("IndexedDB")
        || body.contains("indexedDB");
    let has_consent = body.contains("userConsent")
        || body.contains("hasConsent")
        || body.contains("consentGranted")
        || body.contains("permissionGranted");
    if has_storage && !has_consent {
        issues.push(AmbientLightSecurityIssue::DataCollectionWithoutConsent);
    }

    // 3. TimingAttackVector
    let has_timing = (body.contains("performance.now")
        || body.contains("Date.now")
        || body.contains("timestamp"))
        && (body.contains("illuminance") || body.contains("reading"));
    if has_timing {
        issues.push(AmbientLightSecurityIssue::TimingAttackVector);
    }

    // 4. AmbientLightFingerprint
    let has_other_sensors = body.contains("Accelerometer")
        || body.contains("Gyroscope")
        || body.contains("Magnetometer")
        || body.contains("navigator.userAgent")
        || body.contains("screen.width")
        || body.contains("screen.height");
    if has_other_sensors {
        issues.push(AmbientLightSecurityIssue::AmbientLightFingerprint);
    }

    // 5. UnencryptedTransmission
    let has_http_exfil = body.contains("http://")
        && (body.contains("fetch")
            || body.contains("sendBeacon")
            || body.contains("XMLHttpRequest"));
    if has_http_exfil {
        issues.push(AmbientLightSecurityIssue::UnencryptedTransmission);
    }

    // 6. WorkerBasedCollection
    let has_worker = (body.contains("new Worker") || body.contains("ServiceWorker"))
        && (body.contains("AmbientLightSensor") || body.contains("devicelight"));
    if has_worker {
        issues.push(AmbientLightSecurityIssue::WorkerBasedCollection);
    }

    // 7. CanvasCorrelation
    let has_canvas = (body.contains("canvas") || body.contains("getContext"))
        && (body.contains("illuminance") || body.contains("AmbientLightSensor"));
    if has_canvas {
        issues.push(AmbientLightSecurityIssue::CanvasCorrelation);
    }

    // 8. BatteryCorrelation
    let has_battery = (body.contains("navigator.getBattery")
        || body.contains("BatteryManager")
        || body.contains("battery"))
        && (body.contains("illuminance") || body.contains("AmbientLightSensor"));
    if has_battery {
        issues.push(AmbientLightSecurityIssue::BatteryCorrelation);
    }

    // 9. HighSampleRateExfiltration
    let has_high_freq = body.contains("frequency")
        && (body.contains("60") || body.contains("100") || body.contains("Hz"));
    let has_network = body.contains("fetch")
        || body.contains("sendBeacon")
        || body.contains("XMLHttpRequest")
        || body.contains("WebSocket");
    if has_high_freq && has_network {
        issues.push(AmbientLightSecurityIssue::HighSampleRateExfiltration);
    }

    // 10. PersistentStorage
    let has_persistent =
        (body.contains("localStorage") || body.contains("IndexedDB") || body.contains("indexedDB"))
            && (body.contains("illuminance") || body.contains("sensor."));
    if has_persistent {
        issues.push(AmbientLightSecurityIssue::PersistentStorage);
    }

    issues
}

pub fn ambient_light_security_severity(issue: &AmbientLightSecurityIssue) -> f64 {
    match issue {
        AmbientLightSecurityIssue::AmbientLightFingerprint => 8.0,
        AmbientLightSecurityIssue::HighSampleRateExfiltration => 7.5,
        AmbientLightSecurityIssue::UnencryptedTransmission => 7.0,
        AmbientLightSecurityIssue::DataCollectionWithoutConsent => 6.5,
        AmbientLightSecurityIssue::TimingAttackVector => 6.0,
        AmbientLightSecurityIssue::CanvasCorrelation => 5.5,
        AmbientLightSecurityIssue::BatteryCorrelation => 5.5,
        AmbientLightSecurityIssue::WorkerBasedCollection => 5.0,
        AmbientLightSecurityIssue::PersistentStorage => 4.5,
        AmbientLightSecurityIssue::SensorCreatedWithoutFeaturePolicy => 4.0,
    }
}

pub fn ambient_light_security_to_operations(
    issues: &[AmbientLightSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                ambient_light_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
