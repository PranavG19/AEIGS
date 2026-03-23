use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum BatteryIssue {
    BatteryApiUsed,
    BatteryLevelRead,
    ChargingStateRead,
    BatteryEventListener,
    BatteryDataSent,
    BatteryFingerprinting,
    BatteryCrossOriginSharing,
    BatteryInWorker,
    BatteryWithStorage,
    BatteryBasedCryptomining,
    BatteryDrainAttack,
    BatteryThresholdTracking,
    BatteryWithDeviceMemory,
    BatteryWithNetworkInfo,
    BatteryPersistentMonitoring,
}

impl std::fmt::Display for BatteryIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BatteryApiUsed => write!(f, "battery_api"),
            Self::BatteryLevelRead => write!(f, "battery_level_read"),
            Self::ChargingStateRead => write!(f, "charging_state_read"),
            Self::BatteryEventListener => write!(f, "battery_event_listener"),
            Self::BatteryDataSent => write!(f, "battery_data_sent"),
            Self::BatteryFingerprinting => write!(f, "battery_fingerprinting"),
            Self::BatteryCrossOriginSharing => write!(f, "battery_cross_origin_sharing"),
            Self::BatteryInWorker => write!(f, "battery_in_worker"),
            Self::BatteryWithStorage => write!(f, "battery_with_storage"),
            Self::BatteryBasedCryptomining => write!(f, "battery_based_cryptomining"),
            Self::BatteryDrainAttack => write!(f, "battery_drain_attack"),
            Self::BatteryThresholdTracking => write!(f, "battery_threshold_tracking"),
            Self::BatteryWithDeviceMemory => write!(f, "battery_with_device_memory"),
            Self::BatteryWithNetworkInfo => write!(f, "battery_with_network_info"),
            Self::BatteryPersistentMonitoring => write!(f, "battery_persistent_monitoring"),
        }
    }
}

pub fn audit_battery(target: &str) -> Vec<BatteryIssue> {
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
    analyze_battery(&body)
}

pub fn analyze_battery(body: &str) -> Vec<BatteryIssue> {
    if !body.contains("getBattery") && !body.contains("BatteryManager") {
        return Vec::new();
    }

    let mut issues = Vec::new();

    issues.push(BatteryIssue::BatteryApiUsed);

    if body.contains(".level") && body.contains("getBattery") {
        issues.push(BatteryIssue::BatteryLevelRead);
    }

    if body.contains(".charging")
        || body.contains(".chargingTime")
        || body.contains(".dischargingTime")
    {
        issues.push(BatteryIssue::ChargingStateRead);
    }

    let event_patterns = [
        "levelchange",
        "chargingchange",
        "chargingtimechange",
        "dischargingtimechange",
    ];
    if event_patterns.iter().any(|p| body.contains(p)) {
        issues.push(BatteryIssue::BatteryEventListener);
    }

    let sends_data = body.contains("fetch(")
        || body.contains("XMLHttpRequest")
        || body.contains("sendBeacon")
        || body.contains(".send(")
        || body.contains("$.ajax");
    if sends_data && (body.contains(".level") || body.contains(".charging")) {
        issues.push(BatteryIssue::BatteryDataSent);
    }

    issues
}

pub fn analyze_battery_security(body: &str) -> Vec<BatteryIssue> {
    if !body.contains("getBattery") && !body.contains("BatteryManager") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    let body_lower = body.to_lowercase();

    if body_lower.contains("fingerprint")
        || body_lower.contains("hash")
        || body_lower.contains("canvas")
        || body_lower.contains("screen")
    {
        issues.push(BatteryIssue::BatteryFingerprinting);
    }

    if body.contains("postMessage") || body.contains("cross-origin") || body.contains("iframe") {
        issues.push(BatteryIssue::BatteryCrossOriginSharing);
    }

    if body.contains("Worker") || body.contains("SharedWorker") {
        issues.push(BatteryIssue::BatteryInWorker);
    }

    if body.contains("localStorage")
        || body.contains("sessionStorage")
        || body.contains("indexedDB")
    {
        issues.push(BatteryIssue::BatteryWithStorage);
    }

    if body_lower.contains("mine")
        || body_lower.contains("miner")
        || body_lower.contains("crypto")
        || body_lower.contains("hash")
        || body_lower.contains("wasm")
    {
        issues.push(BatteryIssue::BatteryBasedCryptomining);
    }

    if body.contains("while(true)")
        || body.contains("while (true)")
        || body.contains("for(;;)")
        || body_lower.contains("infinite")
    {
        issues.push(BatteryIssue::BatteryDrainAttack);
    }

    if body.contains("< 0.")
        || body.contains("<= 0.")
        || body.contains("> 0.")
        || body_lower.contains("threshold")
        || body_lower.contains("low")
    {
        issues.push(BatteryIssue::BatteryThresholdTracking);
    }

    if body.contains("deviceMemory") || body.contains("hardwareConcurrency") {
        issues.push(BatteryIssue::BatteryWithDeviceMemory);
    }

    if body.contains("connection.effectiveType")
        || body.contains("navigator.connection")
        || body.contains("NetworkInformation")
    {
        issues.push(BatteryIssue::BatteryWithNetworkInfo);
    }

    let event_patterns = [
        "levelchange",
        "chargingchange",
        "chargingtimechange",
        "dischargingtimechange",
        "addEventListener",
    ];
    let has_event_listener = event_patterns.iter().any(|p| body.contains(p));
    if has_event_listener
        && (body.contains("setInterval") || body.contains("requestAnimationFrame"))
    {
        issues.push(BatteryIssue::BatteryPersistentMonitoring);
    }

    issues
}

pub fn battery_severity(issue: &BatteryIssue) -> f64 {
    match issue {
        BatteryIssue::BatteryDataSent => 6.0,
        BatteryIssue::BatteryEventListener => 5.0,
        BatteryIssue::BatteryLevelRead => 4.5,
        BatteryIssue::ChargingStateRead => 4.0,
        BatteryIssue::BatteryApiUsed => 3.0,
        BatteryIssue::BatteryBasedCryptomining => 8.5,
        BatteryIssue::BatteryDrainAttack => 8.0,
        BatteryIssue::BatteryCrossOriginSharing => 7.0,
        BatteryIssue::BatteryFingerprinting => 6.5,
        BatteryIssue::BatteryPersistentMonitoring => 6.5,
        BatteryIssue::BatteryWithStorage => 6.0,
        BatteryIssue::BatteryWithDeviceMemory => 6.0,
        BatteryIssue::BatteryInWorker => 5.5,
        BatteryIssue::BatteryWithNetworkInfo => 5.5,
        BatteryIssue::BatteryThresholdTracking => 5.0,
    }
}

pub fn battery_to_operations(issues: &[BatteryIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                battery_severity(issue),
                0.65,
            )
        })
        .collect()
}

pub fn battery_security_to_operations(
    issues: &[BatteryIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                battery_severity(issue),
                0.70,
            )
        })
        .collect()
}
