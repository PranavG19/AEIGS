use crate::hardware_api_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_hardware_api("");
    assert!(issues.is_empty());
}

#[test]
fn no_hardware_api_no_issues() {
    let body = "<html><body>Hello</body></html>";
    let issues = analyze_hardware_api(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_web_usb_access() {
    let body = "navigator.usb.requestDevice({filters: []})";
    let issues = analyze_hardware_api(body);
    assert!(issues.contains(&HardwareApiIssue::WebUsbAccess));
}

#[test]
fn detects_web_usb_via_request_device() {
    let body = "const device = await requestDevice({filters: []})";
    let issues = analyze_hardware_api(body);
    assert!(issues.contains(&HardwareApiIssue::WebUsbAccess));
}

#[test]
fn detects_web_hid_access() {
    let body = "navigator.hid.requestDevice({filters: []})";
    let issues = analyze_hardware_api(body);
    assert!(issues.contains(&HardwareApiIssue::WebHidAccess));
}

#[test]
fn detects_web_serial_access() {
    let body = "navigator.serial.requestPort()";
    let issues = analyze_hardware_api(body);
    assert!(issues.contains(&HardwareApiIssue::WebSerialAccess));
}

#[test]
fn detects_usb_device_enumeration() {
    let body = "const devices = await navigator.usb.getDevices()";
    let issues = analyze_hardware_api(body);
    assert!(issues.contains(&HardwareApiIssue::UsbDeviceEnumeration));
}

#[test]
fn detects_hid_device_enumeration() {
    let body = "const devices = await navigator.hid.getDevices()";
    let issues = analyze_hardware_api(body);
    assert!(issues.contains(&HardwareApiIssue::HidDeviceEnumeration));
}

#[test]
fn detects_hardware_data_exfiltration() {
    let body = r#"
        const dev = await navigator.usb.requestDevice({filters: []});
        fetch('/collect', {method:'POST', body: data});
    "#;
    let issues = analyze_hardware_api(body);
    assert!(issues.contains(&HardwareApiIssue::HardwareDataExfiltration));
}

#[test]
fn detects_usb_transfer_out() {
    let body = "navigator.usb.requestDevice({}); device.transferOut(1, data)";
    let issues = analyze_hardware_api(body);
    assert!(issues.contains(&HardwareApiIssue::UsbTransferOut));
}

#[test]
fn detects_control_transfer_out() {
    let body = "navigator.usb.requestDevice({}); device.controlTransferOut(setup, data)";
    let issues = analyze_hardware_api(body);
    assert!(issues.contains(&HardwareApiIssue::UsbTransferOut));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        hardware_api_severity(&HardwareApiIssue::HardwareDataExfiltration),
        8.0
    );
}

#[test]
fn severity_serial_lowest() {
    assert_eq!(
        hardware_api_severity(&HardwareApiIssue::WebSerialAccess),
        6.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        HardwareApiIssue::WebUsbAccess,
        HardwareApiIssue::WebHidAccess,
    ];
    let mut seq = 0;
    let ops = hardware_api_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(HardwareApiIssue::WebUsbAccess.to_string(), "web_usb_access");
    assert_eq!(HardwareApiIssue::WebHidAccess.to_string(), "web_hid_access");
    assert_eq!(
        HardwareApiIssue::WebSerialAccess.to_string(),
        "web_serial_access"
    );
    assert_eq!(
        HardwareApiIssue::UsbTransferOut.to_string(),
        "usb_transfer_out"
    );
}
