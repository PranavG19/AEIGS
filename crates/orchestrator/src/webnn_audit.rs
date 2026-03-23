use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WebnnIssue {
    ApiDetected,
    ModelExfiltration,
    ResourceExhaustion,
    GpuFingerprinting,
    SideChannelTiming,
}

impl std::fmt::Display for WebnnIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::ModelExfiltration => write!(f, "model_exfiltration"),
            Self::ResourceExhaustion => write!(f, "resource_exhaustion"),
            Self::GpuFingerprinting => write!(f, "gpu_fingerprinting"),
            Self::SideChannelTiming => write!(f, "side_channel_timing"),
        }
    }
}

pub fn audit_webnn(target: &str) -> Vec<WebnnIssue> {
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
    analyze_webnn(&body)
}

pub fn analyze_webnn(body: &str) -> Vec<WebnnIssue> {
    let has_api = body.contains("navigator.ml")
        || body.contains("MLContext")
        || body.contains("MLGraphBuilder")
        || body.contains("MLGraph");

    if !has_api {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(WebnnIssue::ApiDetected);

    let has_network =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    let has_tensor =
        body.contains("arrayBuffer") || body.contains("Float32Array") || body.contains("tensor");
    if has_network && has_tensor {
        issues.push(WebnnIssue::ModelExfiltration);
    }

    let has_loop = body.contains("while") || body.contains("for(") || body.contains("for (");
    if has_loop && !body.contains("break") && !body.contains("limit") {
        issues.push(WebnnIssue::ResourceExhaustion);
    }

    let has_fingerprint_api = body.contains("MLContext") || body.contains("navigator.ml");
    let has_fingerprint_signal = body.contains("getDevices")
        || body.contains("deviceType")
        || body.contains("powerPreference")
        || body.contains("numThreads");
    if has_fingerprint_api && has_fingerprint_signal {
        issues.push(WebnnIssue::GpuFingerprinting);
    }

    let has_timing = body.contains("performance.now") || body.contains("Date.now");
    let has_compute = body.contains("compute") || body.contains("dispatch");
    if has_timing && has_compute {
        issues.push(WebnnIssue::SideChannelTiming);
    }

    issues
}

pub fn webnn_severity(issue: &WebnnIssue) -> f64 {
    match issue {
        WebnnIssue::ModelExfiltration => 7.5,
        WebnnIssue::ResourceExhaustion => 7.0,
        WebnnIssue::GpuFingerprinting => 6.5,
        WebnnIssue::SideChannelTiming => 6.0,
        WebnnIssue::ApiDetected => 2.0,
    }
}

pub fn webnn_to_operations(issues: &[WebnnIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                webnn_severity(issue),
                0.5,
            )
        })
        .collect()
}
