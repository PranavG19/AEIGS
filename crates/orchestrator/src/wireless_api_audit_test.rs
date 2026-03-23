use crate::wireless_api_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_wireless_api("");
    assert!(issues.is_empty());
}

#[test]
fn no_wireless_api_no_issues() {
    let body = "<html><body>Hello</body></html>";
    let issues = analyze_wireless_api(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_web_bluetooth_access() {
    let body = "navigator.bluetooth.requestDevice({filters: []})";
    let issues = analyze_wireless_api(body);
    assert!(issues.contains(&WirelessApiIssue::WebBluetoothAccess));
}

#[test]
fn detects_bluetooth_device_scan() {
    let body = "navigator.bluetooth.requestDevice({acceptAllDevices: true})";
    let issues = analyze_wireless_api(body);
    assert!(issues.contains(&WirelessApiIssue::BluetoothDeviceScan));
}

#[test]
fn detects_optional_services_scan() {
    let body = r#"navigator.bluetooth.requestDevice({optionalServices: ['battery_service']})"#;
    let issues = analyze_wireless_api(body);
    assert!(issues.contains(&WirelessApiIssue::BluetoothDeviceScan));
}

#[test]
fn detects_gatt_connection() {
    let body = "device.gatt.connect().then(server => server.getPrimaryService('heart_rate'))";
    let issues = analyze_wireless_api(body);
    assert!(issues.contains(&WirelessApiIssue::BluetoothGattConnection));
}

#[test]
fn detects_gatt_via_get_primary_service() {
    let body = "navigator.bluetooth.requestDevice({}); server.getPrimaryService('battery')";
    let issues = analyze_wireless_api(body);
    assert!(issues.contains(&WirelessApiIssue::BluetoothGattConnection));
}

#[test]
fn detects_web_nfc_access() {
    let body = "const reader = new NDEFReader();";
    let issues = analyze_wireless_api(body);
    assert!(issues.contains(&WirelessApiIssue::WebNfcAccess));
}

#[test]
fn detects_nfc_write_operation() {
    let body = "const writer = new NDEFWriter();";
    let issues = analyze_wireless_api(body);
    assert!(issues.contains(&WirelessApiIssue::NfcWriteOperation));
}

#[test]
fn detects_wireless_data_exfiltration() {
    let body = r#"
        navigator.bluetooth.requestDevice({}).then(device => {
            fetch('/collect', {method:'POST', body: JSON.stringify(device)});
        });
    "#;
    let issues = analyze_wireless_api(body);
    assert!(issues.contains(&WirelessApiIssue::WirelessDataExfiltration));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        wireless_api_severity(&WirelessApiIssue::WirelessDataExfiltration),
        8.0
    );
}

#[test]
fn severity_bluetooth_access_lowest() {
    assert_eq!(
        wireless_api_severity(&WirelessApiIssue::WebBluetoothAccess),
        6.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        WirelessApiIssue::WebBluetoothAccess,
        WirelessApiIssue::WebNfcAccess,
    ];
    let mut seq = 0;
    let ops = wireless_api_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        WirelessApiIssue::WebBluetoothAccess.to_string(),
        "web_bluetooth_access"
    );
    assert_eq!(
        WirelessApiIssue::BluetoothGattConnection.to_string(),
        "bluetooth_gatt_connection"
    );
    assert_eq!(WirelessApiIssue::WebNfcAccess.to_string(), "web_nfc_access");
    assert_eq!(
        WirelessApiIssue::NfcWriteOperation.to_string(),
        "nfc_write_operation"
    );
}
