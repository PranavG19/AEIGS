use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WirelessApiIssue {
    WebBluetoothAccess,
    BluetoothDeviceScan,
    BluetoothGattConnection,
    WebNfcAccess,
    NfcWriteOperation,
    WirelessDataExfiltration,
    BluetoothCharacteristicRead,
    BluetoothCharacteristicWrite,
    BluetoothWithoutPermission,
    NfcRelayAttack,
    BluetoothInWorker,
    WirelessFingerprinting,
    BluetoothCrossOrigin,
    NfcDataInjection,
    BluetoothPersistentConnection,
    WirelessTimingAttack,
}

impl std::fmt::Display for WirelessApiIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WebBluetoothAccess => write!(f, "web_bluetooth_access"),
            Self::BluetoothDeviceScan => write!(f, "bluetooth_device_scan"),
            Self::BluetoothGattConnection => write!(f, "bluetooth_gatt_connection"),
            Self::WebNfcAccess => write!(f, "web_nfc_access"),
            Self::NfcWriteOperation => write!(f, "nfc_write_operation"),
            Self::WirelessDataExfiltration => write!(f, "wireless_data_exfiltration"),
            Self::BluetoothCharacteristicRead => write!(f, "bluetooth_characteristic_read"),
            Self::BluetoothCharacteristicWrite => write!(f, "bluetooth_characteristic_write"),
            Self::BluetoothWithoutPermission => write!(f, "bluetooth_without_permission"),
            Self::NfcRelayAttack => write!(f, "nfc_relay_attack"),
            Self::BluetoothInWorker => write!(f, "bluetooth_in_worker"),
            Self::WirelessFingerprinting => write!(f, "wireless_fingerprinting"),
            Self::BluetoothCrossOrigin => write!(f, "bluetooth_cross_origin"),
            Self::NfcDataInjection => write!(f, "nfc_data_injection"),
            Self::BluetoothPersistentConnection => write!(f, "bluetooth_persistent_connection"),
            Self::WirelessTimingAttack => write!(f, "wireless_timing_attack"),
        }
    }
}

pub fn audit_wireless_api(target: &str) -> Vec<WirelessApiIssue> {
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
    analyze_wireless_api(&body)
}

pub fn analyze_wireless_api(body: &str) -> Vec<WirelessApiIssue> {
    if !has_wireless_indicators(body) {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("navigator.bluetooth") || body.contains("requestDevice") {
        issues.push(WirelessApiIssue::WebBluetoothAccess);
    }

    if body.contains("acceptAllDevices") || body.contains("optionalServices") {
        issues.push(WirelessApiIssue::BluetoothDeviceScan);
    }

    if body.contains(".gatt.connect") || body.contains("getPrimaryService") {
        issues.push(WirelessApiIssue::BluetoothGattConnection);
    }

    if body.contains("NDEFReader") || body.contains("NDEFWriter") {
        issues.push(WirelessApiIssue::WebNfcAccess);
    }

    if body.contains("NDEFWriter") || body.contains(".write(") && body.contains("NDEF") {
        issues.push(WirelessApiIssue::NfcWriteOperation);
    }

    let has_wireless = body.contains("navigator.bluetooth") || body.contains("NDEFReader");
    let sends = body.contains("fetch(")
        || body.contains("XMLHttpRequest")
        || body.contains(".send(")
        || body.contains("sendBeacon");
    if has_wireless && sends {
        issues.push(WirelessApiIssue::WirelessDataExfiltration);
    }

    issues
}

pub fn analyze_wireless_security(body: &str) -> Vec<WirelessApiIssue> {
    if !has_wireless_indicators(body) {
        return Vec::new();
    }

    let mut issues = Vec::new();
    let has_wireless_api = body.contains("navigator.bluetooth")
        || body.contains("NDEFReader")
        || body.contains("NDEFWriter");

    if has_wireless_api
        && (body.contains("readValue")
            || body.contains("getCharacteristic")
            || body.contains("startNotifications"))
    {
        issues.push(WirelessApiIssue::BluetoothCharacteristicRead);
    }

    if has_wireless_api
        && (body.contains("writeValue")
            || body.contains("writeValueWithResponse")
            || body.contains("writeValueWithoutResponse"))
    {
        issues.push(WirelessApiIssue::BluetoothCharacteristicWrite);
    }

    if has_wireless_api
        && !body.contains("permissions")
        && !body.contains("navigator.permissions")
        && !body.contains("requestPermission")
    {
        issues.push(WirelessApiIssue::BluetoothWithoutPermission);
    }

    if body.contains("NDEF")
        && (body.contains("postMessage") || body.contains("WebSocket") || body.contains("fetch("))
    {
        issues.push(WirelessApiIssue::NfcRelayAttack);
    }

    if has_wireless_api && (body.contains("Worker") || body.contains("SharedWorker")) {
        issues.push(WirelessApiIssue::BluetoothInWorker);
    }

    if has_wireless_api
        && (body.contains("fingerprint")
            || body.contains("hash")
            || body.contains("identifier")
            || body.contains("deviceId"))
    {
        issues.push(WirelessApiIssue::WirelessFingerprinting);
    }

    if has_wireless_api
        && (body.contains("postMessage")
            || body.contains("cross-origin")
            || body.contains("iframe"))
    {
        issues.push(WirelessApiIssue::BluetoothCrossOrigin);
    }

    if body.contains("NDEF")
        && (body.contains("write") || body.contains("push") || body.contains("makeRecord"))
    {
        issues.push(WirelessApiIssue::NfcDataInjection);
    }

    if has_wireless_api
        && (body.contains("keepAlive")
            || body.contains("setInterval")
            || body.contains("reconnect"))
    {
        issues.push(WirelessApiIssue::BluetoothPersistentConnection);
    }

    if has_wireless_api
        && (body.contains("performance.now")
            || body.contains("Date.now")
            || body.contains("performance.mark"))
    {
        issues.push(WirelessApiIssue::WirelessTimingAttack);
    }

    issues
}

fn has_wireless_indicators(body: &str) -> bool {
    body.contains("navigator.bluetooth")
        || body.contains("NDEFReader")
        || body.contains("NDEFWriter")
        || body.contains("acceptAllDevices")
        || body.contains(".gatt.connect")
}

pub fn wireless_api_severity(issue: &WirelessApiIssue) -> f64 {
    match issue {
        WirelessApiIssue::NfcRelayAttack => 9.0,
        WirelessApiIssue::NfcDataInjection => 8.5,
        WirelessApiIssue::WirelessDataExfiltration => 8.0,
        WirelessApiIssue::BluetoothCharacteristicWrite => 8.0,
        WirelessApiIssue::NfcWriteOperation => 7.5,
        WirelessApiIssue::BluetoothCrossOrigin => 7.5,
        WirelessApiIssue::BluetoothGattConnection => 7.0,
        WirelessApiIssue::WirelessFingerprinting => 7.0,
        WirelessApiIssue::BluetoothDeviceScan => 6.5,
        WirelessApiIssue::BluetoothCharacteristicRead => 6.5,
        WirelessApiIssue::WirelessTimingAttack => 6.5,
        WirelessApiIssue::WebBluetoothAccess => 6.0,
        WirelessApiIssue::WebNfcAccess => 6.0,
        WirelessApiIssue::BluetoothInWorker => 6.0,
        WirelessApiIssue::BluetoothPersistentConnection => 5.5,
        WirelessApiIssue::BluetoothWithoutPermission => 5.0,
    }
}

pub fn wireless_api_to_operations(
    issues: &[WirelessApiIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                wireless_api_severity(issue),
                0.7,
            )
        })
        .collect()
}

pub fn wireless_security_to_operations(
    issues: &[WirelessApiIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                wireless_api_severity(issue),
                0.8,
            )
        })
        .collect()
}
