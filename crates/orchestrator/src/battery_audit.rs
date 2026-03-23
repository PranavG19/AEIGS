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
}

impl std::fmt::Display for BatteryIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BatteryApiUsed => write!(f, "battery_api"),
            Self::BatteryLevelRead => write!(f, "battery_level_read"),
            Self::ChargingStateRead => write!(f, "charging_state_read"),
            Self::BatteryEventListener => write!(f, "battery_event_listener"),
            Self::BatteryDataSent => write!(f, "battery_data_sent"),
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

pub fn battery_severity(issue: &BatteryIssue) -> f64 {
    match issue {
        BatteryIssue::BatteryDataSent => 6.0,
        BatteryIssue::BatteryEventListener => 5.0,
        BatteryIssue::BatteryLevelRead => 4.5,
        BatteryIssue::ChargingStateRead => 4.0,
        BatteryIssue::BatteryApiUsed => 3.0,
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
