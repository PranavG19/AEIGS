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

    let has_wireless = body.contains("navigator.bluetooth")
        || body.contains("NDEFReader");
    let sends = body.contains("fetch(")
        || body.contains("XMLHttpRequest")
        || body.contains(".send(")
        || body.contains("sendBeacon");
    if has_wireless && sends {
        issues.push(WirelessApiIssue::WirelessDataExfiltration);
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
        WirelessApiIssue::WirelessDataExfiltration => 8.0,
        WirelessApiIssue::NfcWriteOperation => 7.5,
        WirelessApiIssue::BluetoothGattConnection => 7.0,
        WirelessApiIssue::BluetoothDeviceScan => 6.5,
        WirelessApiIssue::WebBluetoothAccess => 6.0,
        WirelessApiIssue::WebNfcAccess => 6.0,
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
