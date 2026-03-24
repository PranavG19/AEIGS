use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WebSerialIssue {
    ApiDetected,
    DataExfiltration,
    NoUserActivation,
    RawReadWrite,
    DeviceEnumeration,
    PersistentStream,
}

impl std::fmt::Display for WebSerialIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::DataExfiltration => write!(f, "data_exfiltration"),
            Self::NoUserActivation => write!(f, "no_user_activation"),
            Self::RawReadWrite => write!(f, "raw_read_write"),
            Self::DeviceEnumeration => write!(f, "device_enumeration"),
            Self::PersistentStream => write!(f, "persistent_stream"),
        }
    }
}

pub fn audit_web_serial(target: &str) -> Vec<WebSerialIssue> {
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
    analyze_web_serial(&body)
}

pub fn analyze_web_serial(body: &str) -> Vec<WebSerialIssue> {
    if !body.contains("navigator.serial") && !body.contains("SerialPort") {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(WebSerialIssue::ApiDetected);

    let has_exfil =
        body.contains("fetch(") || body.contains("sendBeacon") || body.contains("XMLHttpRequest");
    if has_exfil {
        issues.push(WebSerialIssue::DataExfiltration);
    }

    if !body.contains("click") && !body.contains("keydown") && !body.contains("pointerdown") {
        issues.push(WebSerialIssue::NoUserActivation);
    }

    if body.contains(".readable")
        || body.contains(".writable")
        || body.contains("getReader")
        || body.contains("getWriter")
    {
        issues.push(WebSerialIssue::RawReadWrite);
    }

    if body.contains("getPorts") || body.contains("requestPort") {
        issues.push(WebSerialIssue::DeviceEnumeration);
    }

    if body.contains("pipeTo") || body.contains("pipeThrough") || body.contains("ReadableStream") {
        issues.push(WebSerialIssue::PersistentStream);
    }

    issues
}

pub fn web_serial_severity(issue: &WebSerialIssue) -> f64 {
    match issue {
        WebSerialIssue::DataExfiltration => 7.5,
        WebSerialIssue::RawReadWrite => 7.0,
        WebSerialIssue::PersistentStream => 6.0,
        WebSerialIssue::DeviceEnumeration => 5.5,
        WebSerialIssue::NoUserActivation => 5.0,
        WebSerialIssue::ApiDetected => 3.0,
    }
}

pub fn web_serial_to_operations(
    issues: &[WebSerialIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                web_serial_severity(issue),
                0.6,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum WebSerialSecurityIssue {
    SerialPortEnumeration,
    SerialDataExfiltration,
    SerialWithoutPermission,
    SerialFirmwareAccess,
    SerialCrossOrigin,
    SerialPersistentConnection,
    SerialHighBaudRate,
    SerialInBackground,
    SerialDeviceFingerprinting,
    SerialBinaryDataTransfer,
}

impl std::fmt::Display for WebSerialSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SerialPortEnumeration => write!(f, "serial_port_enumeration"),
            Self::SerialDataExfiltration => write!(f, "serial_data_exfiltration"),
            Self::SerialWithoutPermission => write!(f, "serial_without_permission"),
            Self::SerialFirmwareAccess => write!(f, "serial_firmware_access"),
            Self::SerialCrossOrigin => write!(f, "serial_cross_origin"),
            Self::SerialPersistentConnection => write!(f, "serial_persistent_connection"),
            Self::SerialHighBaudRate => write!(f, "serial_high_baud_rate"),
            Self::SerialInBackground => write!(f, "serial_in_background"),
            Self::SerialDeviceFingerprinting => write!(f, "serial_device_fingerprinting"),
            Self::SerialBinaryDataTransfer => write!(f, "serial_binary_data_transfer"),
        }
    }
}

pub fn analyze_web_serial_security(body: &str) -> Vec<WebSerialSecurityIssue> {
    if !body.contains("navigator.serial")
        && !body.contains("SerialPort")
        && !body.contains(".readable")
        && !body.contains(".writable")
        && !body.contains("serial")
        && !body.contains("baudRate")
        && !body.contains("getReader")
        && !body.contains("getWriter")
        && !body.contains("getPorts")
        && !body.contains("getInfo")
        && !body.contains("usbVendorId")
        && !body.contains("usbProductId")
    {
        return Vec::new();
    }

    let mut issues = Vec::new();
    let body_lower = body.to_lowercase();

    // SerialPortEnumeration: listing all available serial ports
    if body.contains("getPorts()") || (body.contains("getPorts") && body.contains("forEach")) {
        issues.push(WebSerialSecurityIssue::SerialPortEnumeration);
    }

    // SerialDataExfiltration: reading serial data and sending externally
    if (body.contains("getReader()") || body.contains(".readable"))
        && (body.contains("fetch(")
            || body.contains("sendBeacon")
            || body.contains("XMLHttpRequest"))
    {
        issues.push(WebSerialSecurityIssue::SerialDataExfiltration);
    }

    // SerialWithoutPermission: accessing serial without user gesture
    if body.contains("requestPort()")
        && !body.contains("click")
        && !body.contains("keydown")
        && !body.contains("pointerdown")
        && !body.contains("touchstart")
        && !body.contains("mousedown")
    {
        issues.push(WebSerialSecurityIssue::SerialWithoutPermission);
    }

    // SerialFirmwareAccess: attempting firmware updates via serial
    if body_lower.contains("firmware")
        || body_lower.contains("flash")
        || body_lower.contains("bootloader")
        || (body_lower.contains("upload") && body.contains(".writable"))
    {
        issues.push(WebSerialSecurityIssue::SerialFirmwareAccess);
    }

    // SerialCrossOrigin: serial data shared cross-origin
    if (body.contains("postMessage")
        && (body.contains("navigator.serial") || body.contains(".readable")))
        || body.contains("parent.postMessage")
        || body.contains("opener.postMessage")
    {
        issues.push(WebSerialSecurityIssue::SerialCrossOrigin);
    }

    // SerialPersistentConnection: maintaining long-lived serial connections
    if (body.contains("setInterval") && body.contains(".readable"))
        || body.contains("while(true)")
        || body.contains("while (true)")
        || (body.contains("for(;;)") && body.contains("serial"))
    {
        issues.push(WebSerialSecurityIssue::SerialPersistentConnection);
    }

    // SerialHighBaudRate: using very high baud rates (unusual)
    let high_baud_rates = ["115200", "230400", "460800", "921600", "1000000", "2000000"];
    if high_baud_rates.iter().any(|rate| {
        body.contains(&format!("baudRate: {}", rate))
            || body.contains(&format!("baudRate:{}", rate))
    }) {
        issues.push(WebSerialSecurityIssue::SerialHighBaudRate);
    }

    // SerialInBackground: serial operations when page hidden
    if (body.contains("visibilitychange") && body.contains("serial"))
        || (body.contains("document.hidden") && body.contains(".readable"))
    {
        issues.push(WebSerialSecurityIssue::SerialInBackground);
    }

    // SerialDeviceFingerprinting: fingerprinting via serial device info
    if body.contains("getInfo()") || body.contains("usbVendorId") || body.contains("usbProductId") {
        issues.push(WebSerialSecurityIssue::SerialDeviceFingerprinting);
    }

    // SerialBinaryDataTransfer: transferring binary data via serial
    if (body.contains("ArrayBuffer") && body.contains("serial"))
        || (body.contains("Uint8Array") && body.contains(".writable"))
        || (body.contains("DataView") && body.contains("serial"))
    {
        issues.push(WebSerialSecurityIssue::SerialBinaryDataTransfer);
    }

    issues
}

pub fn web_serial_security_severity(issue: &WebSerialSecurityIssue) -> f64 {
    match issue {
        WebSerialSecurityIssue::SerialDataExfiltration => 8.5,
        WebSerialSecurityIssue::SerialFirmwareAccess => 8.0,
        WebSerialSecurityIssue::SerialCrossOrigin => 7.5,
        WebSerialSecurityIssue::SerialWithoutPermission => 7.0,
        WebSerialSecurityIssue::SerialBinaryDataTransfer => 6.5,
        WebSerialSecurityIssue::SerialPersistentConnection => 6.0,
        WebSerialSecurityIssue::SerialInBackground => 5.5,
        WebSerialSecurityIssue::SerialDeviceFingerprinting => 5.0,
        WebSerialSecurityIssue::SerialHighBaudRate => 4.5,
        WebSerialSecurityIssue::SerialPortEnumeration => 4.0,
    }
}

pub fn web_serial_security_to_operations(
    issues: &[WebSerialSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                web_serial_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
