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

#[derive(Debug, Clone, PartialEq)]
pub enum HardwareApiSecurityIssue {
    UsbDeviceEnumeration,
    SerialPortAccess,
    HidDeviceFingerprinting,
    BluetoothSilentScan,
    SensorFusion,
    GpuFingerprinting,
    MidiSysex,
    UsbDataExfiltration,
    HardwareWithoutPermission,
    PersistentHardwareAccess,
}

impl std::fmt::Display for HardwareApiSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UsbDeviceEnumeration => write!(f, "usb_device_enumeration_security"),
            Self::SerialPortAccess => write!(f, "serial_port_access_security"),
            Self::HidDeviceFingerprinting => write!(f, "hid_device_fingerprinting"),
            Self::BluetoothSilentScan => write!(f, "bluetooth_silent_scan"),
            Self::SensorFusion => write!(f, "sensor_fusion_tracking"),
            Self::GpuFingerprinting => write!(f, "gpu_fingerprinting"),
            Self::MidiSysex => write!(f, "midi_sysex_exploit"),
            Self::UsbDataExfiltration => write!(f, "usb_data_exfiltration_security"),
            Self::HardwareWithoutPermission => write!(f, "hardware_without_permission"),
            Self::PersistentHardwareAccess => write!(f, "persistent_hardware_access"),
        }
    }
}

pub fn analyze_hardware_api_security(body: &str) -> Vec<HardwareApiSecurityIssue> {
    let mut issues = Vec::new();

    // USB device enumeration for fingerprinting
    if (body.contains("navigator.usb") && body.contains("getDevices"))
        || (body.contains("requestDevice") && body.contains("productId"))
    {
        issues.push(HardwareApiSecurityIssue::UsbDeviceEnumeration);
    }

    // Serial port access without user gesture
    if (body.contains("navigator.serial") && body.contains("requestPort"))
        || (body.contains("SerialPort") && body.contains("open"))
    {
        issues.push(HardwareApiSecurityIssue::SerialPortAccess);
    }

    // HID device fingerprinting
    if (body.contains("navigator.hid") && body.contains("getDevices"))
        || (body.contains("navigator.hid") && body.contains("productId"))
        || (body.contains("navigator.hid") && body.contains("vendorId"))
    {
        issues.push(HardwareApiSecurityIssue::HidDeviceFingerprinting);
    }

    // Bluetooth silent scanning
    if (body.contains("navigator.bluetooth") && body.contains("requestDevice"))
        || (body.contains("navigator.bluetooth") && body.contains("getDevices"))
        || (body.contains("navigator.bluetooth") && body.contains("acceptAllDevices"))
    {
        issues.push(HardwareApiSecurityIssue::BluetoothSilentScan);
    }

    // Sensor fusion for tracking
    let has_multiple_sensors = [
        body.contains("Accelerometer"),
        body.contains("Gyroscope"),
        body.contains("Magnetometer"),
        body.contains("OrientationSensor"),
        body.contains("AbsoluteOrientationSensor"),
    ]
    .iter()
    .filter(|&&x| x)
    .count()
        >= 2;

    if has_multiple_sensors {
        issues.push(HardwareApiSecurityIssue::SensorFusion);
    }

    // GPU fingerprinting via WebGPU
    if (body.contains("navigator.gpu") && body.contains("requestAdapter"))
        || (body.contains("GPUAdapter") && body.contains("requestDevice"))
        || (body.contains("getPreferredCanvasFormat"))
    {
        issues.push(HardwareApiSecurityIssue::GpuFingerprinting);
    }

    // MIDI system exclusive messages
    if (body.contains("navigator.requestMIDIAccess") && body.contains("sysex"))
        || (body.contains("MIDIAccess") && body.contains("sysex: true"))
    {
        issues.push(HardwareApiSecurityIssue::MidiSysex);
    }

    // USB data exfiltration
    let has_usb_read = body.contains("transferIn") || body.contains("controlTransferIn");
    let has_network = body.contains("fetch(")
        || body.contains("XMLHttpRequest")
        || body.contains("sendBeacon")
        || body.contains("WebSocket");

    if has_usb_read && has_network {
        issues.push(HardwareApiSecurityIssue::UsbDataExfiltration);
    }

    // Hardware access without permission
    if (body.contains("navigator.usb") || body.contains("navigator.hid"))
        && !body.contains("requestDevice")
        && body.contains("getDevices")
    {
        issues.push(HardwareApiSecurityIssue::HardwareWithoutPermission);
    }

    // Persistent hardware access tokens
    if (body.contains("localStorage")
        || body.contains("sessionStorage")
        || body.contains("indexedDB"))
        && (body.contains("navigator.usb")
            || body.contains("navigator.hid")
            || body.contains("navigator.serial")
            || body.contains("navigator.bluetooth"))
    {
        issues.push(HardwareApiSecurityIssue::PersistentHardwareAccess);
    }

    issues
}

pub fn hardware_api_security_severity(issue: &HardwareApiSecurityIssue) -> f64 {
    match issue {
        HardwareApiSecurityIssue::UsbDataExfiltration => 9.0,
        HardwareApiSecurityIssue::MidiSysex => 8.5,
        HardwareApiSecurityIssue::SerialPortAccess => 8.0,
        HardwareApiSecurityIssue::HardwareWithoutPermission => 7.5,
        HardwareApiSecurityIssue::UsbDeviceEnumeration => 7.0,
        HardwareApiSecurityIssue::HidDeviceFingerprinting => 7.0,
        HardwareApiSecurityIssue::BluetoothSilentScan => 6.5,
        HardwareApiSecurityIssue::PersistentHardwareAccess => 6.5,
        HardwareApiSecurityIssue::GpuFingerprinting => 6.0,
        HardwareApiSecurityIssue::SensorFusion => 5.5,
    }
}

pub fn hardware_api_security_to_operations(
    issues: &[HardwareApiSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                hardware_api_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
