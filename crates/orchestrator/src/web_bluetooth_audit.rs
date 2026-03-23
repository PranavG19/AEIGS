use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WebBluetoothIssue {
    ApiDetected,
    DataExfiltration,
    NoUserActivation,
    CharacteristicAccess,
    DeviceScan,
    PersistentConnection,
}

impl std::fmt::Display for WebBluetoothIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::NoUserActivation => write!(f, "no_user_activation"),
            Self::CharacteristicAccess => write!(f, "characteristic_access"),
            Self::DeviceScan => write!(f, "device_scan"),
            Self::PersistentConnection => write!(f, "persistent_connection"),
        }
    }
}

pub fn audit_web_bluetooth(target: &str) -> Vec<WebBluetoothIssue> {
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
    analyze_web_bluetooth(&body)
}

pub fn analyze_web_bluetooth(body: &str) -> Vec<WebBluetoothIssue> {
    if !body.contains("navigator.bluetooth") && !body.contains("BluetoothDevice") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(WebBluetoothIssue::ApiDetected);

    let has_exfil =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_exfil {
        issues.push(WebBluetoothIssue::DataExfiltration);
    }

    if !body.contains("click") && !body.contains("keydown") && !body.contains("pointerdown") {
        issues.push(WebBluetoothIssue::NoUserActivation);
    }

    if body.contains("getCharacteristic")
        || body.contains("readValue")
        || body.contains("writeValue")
        || body.contains("startNotifications")
    {
        issues.push(WebBluetoothIssue::CharacteristicAccess);
    }

    if body.contains("requestDevice") || body.contains("acceptAllDevices") {
        issues.push(WebBluetoothIssue::DeviceScan);
    }

    if body.contains("gattserverdisconnected")
        || body.contains("addEventListener(\"characteristicvaluechanged\"")
        || body.contains("addEventListener('characteristicvaluechanged'")
    {
        issues.push(WebBluetoothIssue::PersistentConnection);
    }

    issues
}

pub fn web_bluetooth_severity(issue: &WebBluetoothIssue) -> f64 {
    match issue {
        WebBluetoothIssue::DataExfiltration => 7.5,
        WebBluetoothIssue::CharacteristicAccess => 7.0,
        WebBluetoothIssue::PersistentConnection => 6.0,
        WebBluetoothIssue::DeviceScan => 5.5,
        WebBluetoothIssue::NoUserActivation => 5.0,
        WebBluetoothIssue::ApiDetected => 3.0,
    }
}

pub fn web_bluetooth_to_operations(
    issues: &[WebBluetoothIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                web_bluetooth_severity(issue),
                0.6,
            )
        })
        .collect()
}
