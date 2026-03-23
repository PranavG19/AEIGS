use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WebUsbIssue {
    ApiDetected,
    DataExfiltration,
    NoUserActivation,
    BulkTransfer,
    DeviceEnumeration,
    ClaimInterface,
}

impl std::fmt::Display for WebUsbIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::NoUserActivation => write!(f, "no_user_activation"),
            Self::BulkTransfer => write!(f, "bulk_transfer"),
            Self::DeviceEnumeration => write!(f, "device_enumeration"),
            Self::ClaimInterface => write!(f, "claim_interface"),
        }
    }
}

pub fn audit_webusb(target: &str) -> Vec<WebUsbIssue> {
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
    analyze_webusb(&body)
}

pub fn analyze_webusb(body: &str) -> Vec<WebUsbIssue> {
    if !body.contains("navigator.usb") && !body.contains("USBDevice") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(WebUsbIssue::ApiDetected);

    let has_exfil =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_exfil {
        issues.push(WebUsbIssue::DataExfiltration);
    }

    if !body.contains("click") && !body.contains("keydown") && !body.contains("pointerdown") {
        issues.push(WebUsbIssue::NoUserActivation);
    }

    if body.contains("transferIn") || body.contains("transferOut") {
        issues.push(WebUsbIssue::BulkTransfer);
    }

    if body.contains("getDevices") || body.contains("requestDevice") {
        issues.push(WebUsbIssue::DeviceEnumeration);
    }

    if body.contains("claimInterface") {
        issues.push(WebUsbIssue::ClaimInterface);
    }

    issues
}

pub fn webusb_severity(issue: &WebUsbIssue) -> f64 {
    match issue {
        WebUsbIssue::DataExfiltration => 7.5,
        WebUsbIssue::BulkTransfer => 7.0,
        WebUsbIssue::ClaimInterface => 6.5,
        WebUsbIssue::DeviceEnumeration => 5.5,
        WebUsbIssue::NoUserActivation => 5.0,
        WebUsbIssue::ApiDetected => 3.0,
    }
}

pub fn webusb_to_operations(issues: &[WebUsbIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                webusb_severity(issue),
                0.6,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum WebUsbSecurityIssue {
    UsbDeviceEnumeration,
    UsbDataExfiltration,
    UsbWithoutPermission,
    UsbFirmwareFlash,
    UsbCrossOrigin,
    UsbBulkTransfer,
    UsbControlTransfer,
    UsbInBackground,
    UsbDeviceFingerprinting,
    UsbPersistentConnection,
}

impl std::fmt::Display for WebUsbSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UsbDeviceEnumeration => write!(f, "usb_device_enumeration"),
            Self::UsbDataExfiltration => write!(f, "usb_data_exfiltration"),
            Self::UsbWithoutPermission => write!(f, "usb_without_permission"),
            Self::UsbFirmwareFlash => write!(f, "usb_firmware_flash"),
            Self::UsbCrossOrigin => write!(f, "usb_cross_origin"),
            Self::UsbBulkTransfer => write!(f, "usb_bulk_transfer"),
            Self::UsbControlTransfer => write!(f, "usb_control_transfer"),
            Self::UsbInBackground => write!(f, "usb_in_background"),
            Self::UsbDeviceFingerprinting => write!(f, "usb_device_fingerprinting"),
            Self::UsbPersistentConnection => write!(f, "usb_persistent_connection"),
        }
    }
}

pub fn analyze_webusb_security(body: &str) -> Vec<WebUsbSecurityIssue> {
    let has_usb_api = body.contains("navigator.usb")
        || body.contains("USBDevice")
        || body.contains("transferIn")
        || body.contains("transferOut")
        || body.contains("controlTransferIn")
        || body.contains("controlTransferOut")
        || body.contains("getDevices")
        || body.contains("requestDevice")
        || body.contains(".open()");

    if !has_usb_api {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("getDevices") {
        issues.push(WebUsbSecurityIssue::UsbDeviceEnumeration);
    }

    let has_network = body.contains("fetch(")
        || body.contains("XMLHttpRequest")
        || body.contains("sendBeacon")
        || body.contains("WebSocket")
        || body.contains("postMessage");
    if has_network && (body.contains("transferIn") || body.contains("transferOut")) {
        issues.push(WebUsbSecurityIssue::UsbDataExfiltration);
    }

    let has_explicit_request = body.contains("requestDevice");
    let has_event_listener = body.contains("addEventListener");
    let has_open = body.contains(".open()");

    if has_open && !has_explicit_request && !has_event_listener {
        issues.push(WebUsbSecurityIssue::UsbWithoutPermission);
    }

    if body.contains("controlTransferOut") && body.contains("0x") {
        issues.push(WebUsbSecurityIssue::UsbFirmwareFlash);
    }

    if body.contains("postMessage") && body.contains("transferIn") {
        issues.push(WebUsbSecurityIssue::UsbCrossOrigin);
    }

    if body.contains("transferIn") || body.contains("transferOut") {
        issues.push(WebUsbSecurityIssue::UsbBulkTransfer);
    }

    if body.contains("controlTransferIn") || body.contains("controlTransferOut") {
        issues.push(WebUsbSecurityIssue::UsbControlTransfer);
    }

    let has_visibility_check = body.contains("visibilitychange")
        || body.contains("document.hidden")
        || body.contains("focus")
        || body.contains("blur");
    if !has_visibility_check && body.contains("setInterval") && body.contains("transferIn") {
        issues.push(WebUsbSecurityIssue::UsbInBackground);
    }

    if body.contains("productId") || body.contains("vendorId") || body.contains("serialNumber") {
        issues.push(WebUsbSecurityIssue::UsbDeviceFingerprinting);
    }

    if body.contains("localStorage") && body.contains("serialNumber") {
        issues.push(WebUsbSecurityIssue::UsbPersistentConnection);
    }

    issues
}

pub fn webusb_security_severity(issue: &WebUsbSecurityIssue) -> f64 {
    match issue {
        WebUsbSecurityIssue::UsbFirmwareFlash => 9.5,
        WebUsbSecurityIssue::UsbDataExfiltration => 8.5,
        WebUsbSecurityIssue::UsbWithoutPermission => 8.0,
        WebUsbSecurityIssue::UsbControlTransfer => 7.5,
        WebUsbSecurityIssue::UsbCrossOrigin => 7.0,
        WebUsbSecurityIssue::UsbBulkTransfer => 6.5,
        WebUsbSecurityIssue::UsbInBackground => 6.0,
        WebUsbSecurityIssue::UsbDeviceEnumeration => 5.5,
        WebUsbSecurityIssue::UsbPersistentConnection => 5.0,
        WebUsbSecurityIssue::UsbDeviceFingerprinting => 4.5,
    }
}

pub fn webusb_security_to_operations(
    issues: &[WebUsbSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                webusb_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
