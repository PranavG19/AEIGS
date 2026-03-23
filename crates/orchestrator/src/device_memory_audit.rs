use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum DeviceMemoryIssue {
    ApiDetected,
    FingerprintingVector,
    DataExfiltration,
    CombinedFingerprint,
    ClientHintHeader,
    MemoryBasedContentAdaptation,
    CrossOriginMemorySharing,
    WorkerMemoryAccess,
    MemoryThresholdBranching,
    MemoryInLocalStorage,
    MemoryInCookies,
    MemoryBasedResourceLoading,
    MemoryWithBatteryStatus,
    MemoryWithNetworkInfo,
    MemoryTimingAttack,
}

impl std::fmt::Display for DeviceMemoryIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::FingerprintingVector => write!(f, "fingerprinting_vector"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::CombinedFingerprint => write!(f, "combined_fingerprint"),
            Self::ClientHintHeader => write!(f, "client_hint_header"),
            Self::MemoryBasedContentAdaptation => write!(f, "memory_based_content_adaptation"),
            Self::CrossOriginMemorySharing => write!(f, "cross_origin_memory_sharing"),
            Self::WorkerMemoryAccess => write!(f, "worker_memory_access"),
            Self::MemoryThresholdBranching => write!(f, "memory_threshold_branching"),
            Self::MemoryInLocalStorage => write!(f, "memory_in_local_storage"),
            Self::MemoryInCookies => write!(f, "memory_in_cookies"),
            Self::MemoryBasedResourceLoading => write!(f, "memory_based_resource_loading"),
            Self::MemoryWithBatteryStatus => write!(f, "memory_with_battery_status"),
            Self::MemoryWithNetworkInfo => write!(f, "memory_with_network_info"),
            Self::MemoryTimingAttack => write!(f, "memory_timing_attack"),
        }
    }
}

pub fn audit_device_memory(target: &str) -> Vec<DeviceMemoryIssue> {
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
    analyze_device_memory(&body)
}

pub fn analyze_device_memory(body: &str) -> Vec<DeviceMemoryIssue> {
    let has_api = body.contains("navigator.deviceMemory") || body.contains("deviceMemory");
    let has_header = body.contains("Device-Memory") || body.contains("device-memory");

    if !has_api && !has_header {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(DeviceMemoryIssue::ApiDetected);

    if has_header {
        issues.push(DeviceMemoryIssue::ClientHintHeader);
    }

    if has_api {
        issues.push(DeviceMemoryIssue::FingerprintingVector);
    }

    if has_api
        && (body.contains("fetch(")
            || body.contains("sendBeacon")
            || body.contains("XMLHttpRequest"))
    {
        issues.push(DeviceMemoryIssue::DataExfiltration);
    }

    if has_api
        && (body.contains("hardwareConcurrency")
            || body.contains("platform")
            || body.contains("userAgent")
            || body.contains("maxTouchPoints"))
    {
        issues.push(DeviceMemoryIssue::CombinedFingerprint);
    }

    issues
}

pub fn device_memory_severity(issue: &DeviceMemoryIssue) -> f64 {
    match issue {
        DeviceMemoryIssue::CombinedFingerprint => 7.0,
        DeviceMemoryIssue::DataExfiltration => 6.5,
        DeviceMemoryIssue::FingerprintingVector => 5.5,
        DeviceMemoryIssue::ClientHintHeader => 4.5,
        DeviceMemoryIssue::ApiDetected => 2.5,
        DeviceMemoryIssue::MemoryTimingAttack => 8.0,
        DeviceMemoryIssue::CrossOriginMemorySharing => 7.5,
        DeviceMemoryIssue::MemoryInCookies => 7.0,
        DeviceMemoryIssue::MemoryInLocalStorage => 6.5,
        DeviceMemoryIssue::WorkerMemoryAccess => 6.0,
        DeviceMemoryIssue::MemoryWithBatteryStatus => 6.0,
        DeviceMemoryIssue::MemoryWithNetworkInfo => 5.5,
        DeviceMemoryIssue::MemoryThresholdBranching => 4.0,
        DeviceMemoryIssue::MemoryBasedResourceLoading => 3.5,
        DeviceMemoryIssue::MemoryBasedContentAdaptation => 3.0,
    }
}

pub fn device_memory_to_operations(
    issues: &[DeviceMemoryIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                device_memory_severity(issue),
                0.6,
            )
        })
        .collect()
}

pub fn analyze_device_memory_security(body: &str) -> Vec<DeviceMemoryIssue> {
    let has_api = body.contains("deviceMemory") || body.contains("device-memory");

    if !has_api {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("quality")
        || body.contains("resolution")
        || body.contains("adaptive")
        || body.contains("lowEnd")
    {
        issues.push(DeviceMemoryIssue::MemoryBasedContentAdaptation);
    }

    if body.contains("postMessage")
        || body.contains("SharedArrayBuffer")
        || body.contains("cross-origin")
    {
        issues.push(DeviceMemoryIssue::CrossOriginMemorySharing);
    }

    if body.contains("Worker") || body.contains("SharedWorker") || body.contains("ServiceWorker") {
        issues.push(DeviceMemoryIssue::WorkerMemoryAccess);
    }

    if body.contains("< 4")
        || body.contains("<= 2")
        || body.contains("> 8")
        || body.contains("threshold")
        || body.contains("if.*deviceMemory")
    {
        issues.push(DeviceMemoryIssue::MemoryThresholdBranching);
    }

    if body.contains("localStorage") || body.contains("sessionStorage") {
        issues.push(DeviceMemoryIssue::MemoryInLocalStorage);
    }

    if body.contains("document.cookie") || body.contains("setCookie") || body.contains("Cookie") {
        issues.push(DeviceMemoryIssue::MemoryInCookies);
    }

    if body.contains("src=")
        || body.contains("href=")
        || body.contains("import(")
        || body.contains("loadScript")
    {
        issues.push(DeviceMemoryIssue::MemoryBasedResourceLoading);
    }

    if body.contains("getBattery") || body.contains("battery") || body.contains("BatteryManager") {
        issues.push(DeviceMemoryIssue::MemoryWithBatteryStatus);
    }

    if body.contains("connection.effectiveType")
        || body.contains("navigator.connection")
        || body.contains("NetworkInformation")
    {
        issues.push(DeviceMemoryIssue::MemoryWithNetworkInfo);
    }

    if body.contains("performance.now")
        || body.contains("Date.now")
        || body.contains("performance.mark")
    {
        issues.push(DeviceMemoryIssue::MemoryTimingAttack);
    }

    issues
}

pub fn device_memory_security_to_operations(
    issues: &[DeviceMemoryIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                device_memory_severity(issue),
                0.7,
            )
        })
        .collect()
}
