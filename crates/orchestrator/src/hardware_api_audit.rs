use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum HardwareApiIssue {
    WebUsbAccess,
    WebHidAccess,
    WebSerialAccess,
    UsbDeviceEnumeration,
    HidDeviceEnumeration,
    HardwareDataExfiltration,
    UsbTransferOut,
}

impl std::fmt::Display for HardwareApiIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WebUsbAccess => write!(f, "web_usb_access"),
            Self::WebHidAccess => write!(f, "web_hid_access"),
            Self::WebSerialAccess => write!(f, "web_serial_access"),
            Self::UsbDeviceEnumeration => write!(f, "usb_device_enumeration"),
            Self::HidDeviceEnumeration => write!(f, "hid_device_enumeration"),
            Self::HardwareDataExfiltration => write!(f, "hardware_data_exfiltration"),
            Self::UsbTransferOut => write!(f, "usb_transfer_out"),
        }
    }
}

pub fn audit_hardware_api(target: &str) -> Vec<HardwareApiIssue> {
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
    analyze_hardware_api(&body)
}

pub fn analyze_hardware_api(body: &str) -> Vec<HardwareApiIssue> {
    if !has_hardware_indicators(body) {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("navigator.usb") || body.contains("requestDevice") {
        issues.push(HardwareApiIssue::WebUsbAccess);
    }

    if body.contains("navigator.hid") {
        issues.push(HardwareApiIssue::WebHidAccess);
    }

    if body.contains("navigator.serial") {
        issues.push(HardwareApiIssue::WebSerialAccess);
    }

    if body.contains("getDevices") && body.contains("navigator.usb") {
        issues.push(HardwareApiIssue::UsbDeviceEnumeration);
    }

    if body.contains("getDevices") && body.contains("navigator.hid") {
        issues.push(HardwareApiIssue::HidDeviceEnumeration);
    }

    let has_hw = body.contains("navigator.usb")
        || body.contains("navigator.hid")
        || body.contains("navigator.serial");
    let sends = body.contains("fetch(")
        || body.contains("XMLHttpRequest")
        || body.contains(".send(")
        || body.contains("sendBeacon");
    if has_hw && sends {
        issues.push(HardwareApiIssue::HardwareDataExfiltration);
    }

    if body.contains("transferOut") || body.contains("controlTransferOut") {
        issues.push(HardwareApiIssue::UsbTransferOut);
    }

    issues
}

fn has_hardware_indicators(body: &str) -> bool {
    body.contains("navigator.usb")
        || body.contains("navigator.hid")
        || body.contains("navigator.serial")
        || body.contains("requestDevice")
}

pub fn hardware_api_severity(issue: &HardwareApiIssue) -> f64 {
    match issue {
        HardwareApiIssue::HardwareDataExfiltration => 8.0,
        HardwareApiIssue::UsbTransferOut => 7.5,
        HardwareApiIssue::UsbDeviceEnumeration => 7.0,
        HardwareApiIssue::HidDeviceEnumeration => 7.0,
        HardwareApiIssue::WebUsbAccess => 6.5,
        HardwareApiIssue::WebHidAccess => 6.0,
        HardwareApiIssue::WebSerialAccess => 6.0,
    }
}

pub fn hardware_api_to_operations(
    issues: &[HardwareApiIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                hardware_api_severity(issue),
                0.7,
            )
        })
        .collect()
}
