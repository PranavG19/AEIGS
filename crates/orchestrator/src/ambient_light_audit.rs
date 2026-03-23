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
