use crate::web_bluetooth_audit::*;

#[test]
fn no_bluetooth_no_issues() {
    assert!(analyze_web_bluetooth("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_navigator() {
    let body = r#"<script>const dev = await navigator.bluetooth.requestDevice({});</script>"#;
    let issues = analyze_web_bluetooth(body);
    assert!(issues.contains(&WebBluetoothIssue::ApiDetected));
}

#[test]
fn detects_api_bluetooth_device() {
    let body = r#"<script>const dev = new BluetoothDevice();</script>"#;
    let issues = analyze_web_bluetooth(body);
    assert!(issues.contains(&WebBluetoothIssue::ApiDetected));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        const dev = await navigator.bluetooth.requestDevice({});
        fetch("/api/bt-data", {body: "data"});
    </script>"#;
    let issues = analyze_web_bluetooth(body);
    assert!(issues.contains(&WebBluetoothIssue::DataExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const dev = await navigator.bluetooth.requestDevice({});
        console.log(dev);
    </script>"#;
    let issues = analyze_web_bluetooth(body);
    assert!(!issues.contains(&WebBluetoothIssue::DataExfiltration));
}

#[test]
fn detects_no_user_activation() {
    let body = r#"<script>await navigator.bluetooth.requestDevice({});</script>"#;
    let issues = analyze_web_bluetooth(body);
    assert!(issues.contains(&WebBluetoothIssue::NoUserActivation));
}

#[test]
fn no_activation_issue_with_click() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            await navigator.bluetooth.requestDevice({});
        });
    </script>"#;
    let issues = analyze_web_bluetooth(body);
    assert!(!issues.contains(&WebBluetoothIssue::NoUserActivation));
}

#[test]
fn detects_characteristic_access() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const dev = await navigator.bluetooth.requestDevice({});
            const server = await dev.gatt.connect();
            const svc = await server.getPrimaryService("heart_rate");
            const chr = await svc.getCharacteristic("heart_rate_measurement");
            const val = await chr.readValue();
        });
    </script>"#;
    let issues = analyze_web_bluetooth(body);
    assert!(issues.contains(&WebBluetoothIssue::CharacteristicAccess));
}

#[test]
fn detects_device_scan() {
    let body = r#"<script>
        navigator.bluetooth.requestDevice({acceptAllDevices: true});
    </script>"#;
    let issues = analyze_web_bluetooth(body);
    assert!(issues.contains(&WebBluetoothIssue::DeviceScan));
}

#[test]
fn detects_persistent_connection() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const dev = await navigator.bluetooth.requestDevice({});
            dev.addEventListener("gattserverdisconnected", reconnect);
        });
    </script>"#;
    let issues = analyze_web_bluetooth(body);
    assert!(issues.contains(&WebBluetoothIssue::PersistentConnection));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        web_bluetooth_severity(&WebBluetoothIssue::DataExfiltration),
        7.5
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(web_bluetooth_severity(&WebBluetoothIssue::ApiDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        WebBluetoothIssue::ApiDetected,
        WebBluetoothIssue::DeviceScan,
    ];
    let mut seq = 0;
    let ops = web_bluetooth_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(WebBluetoothIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        WebBluetoothIssue::DataExfiltration.to_string(),
        "data_exfiltration"
    );
    assert_eq!(
        WebBluetoothIssue::NoUserActivation.to_string(),
        "no_user_activation"
    );
    assert_eq!(
        WebBluetoothIssue::CharacteristicAccess.to_string(),
        "characteristic_access"
    );
    assert_eq!(WebBluetoothIssue::DeviceScan.to_string(), "device_scan");
    assert_eq!(
        WebBluetoothIssue::PersistentConnection.to_string(),
        "persistent_connection"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_web_bluetooth("").is_empty());
}

// ===== New Security Variant Tests =====

#[test]
fn no_bluetooth_no_security_issues() {
    assert!(analyze_web_bluetooth_security("<html><body>hello</body></html>").is_empty());
}

#[test]
fn empty_body_no_security_issues() {
    assert!(analyze_web_bluetooth_security("").is_empty());
}

#[test]
fn detects_device_enumeration_accept_all() {
    let body = r#"<script>
        navigator.bluetooth.requestDevice({acceptAllDevices: true});
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothDeviceEnumeration));
}

#[test]
fn detects_device_enumeration_optional_services() {
    let body = r#"<script>
        navigator.bluetooth.requestDevice({
            optionalServices: ['battery_service', 'heart_rate']
        });
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothDeviceEnumeration));
}

#[test]
fn detects_device_enumeration_get_devices() {
    let body = r#"<script>
        const devices = await navigator.bluetooth.getDevices();
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothDeviceEnumeration));
}

#[test]
fn no_device_enumeration_simple_request() {
    let body = r#"<script>
        navigator.bluetooth.requestDevice({filters: [{services: ['battery_service']}]});
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(!issues.contains(&WebBluetoothSecurityIssue::BluetoothDeviceEnumeration));
}

#[test]
fn detects_data_interception_read_value() {
    let body = r#"<script>
        const value = await characteristic.readValue();
        const view = new DataView(value.buffer);
        const data = view.getUint8(0);
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothDataInterception));
}

#[test]
fn detects_data_interception_start_notifications() {
    let body = r#"<script>
        await characteristic.startNotifications();
        characteristic.addEventListener('characteristicvaluechanged', e => {
            const value = e.target.value;
            const buffer = value.buffer;
        });
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothDataInterception));
}

#[test]
fn no_data_interception_without_buffer_access() {
    let body = r#"<script>
        const value = await characteristic.readValue();
        console.log(value);
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(!issues.contains(&WebBluetoothSecurityIssue::BluetoothDataInterception));
}

#[test]
fn detects_bluetooth_without_permission() {
    let body = r#"<script>
        window.onload = async () => {
            const device = await navigator.bluetooth.requestDevice({});
        };
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothWithoutPermission));
}

#[test]
fn no_permission_issue_with_click() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            await navigator.bluetooth.requestDevice({});
        });
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(!issues.contains(&WebBluetoothSecurityIssue::BluetoothWithoutPermission));
}

#[test]
fn no_permission_issue_with_touchstart() {
    let body = r#"<script>
        btn.addEventListener("touchstart", async () => {
            await navigator.bluetooth.requestDevice({});
        });
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(!issues.contains(&WebBluetoothSecurityIssue::BluetoothWithoutPermission));
}

#[test]
fn no_permission_issue_with_keypress() {
    let body = r#"<script>
        document.addEventListener("keypress", async () => {
            await navigator.bluetooth.requestDevice({});
        });
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(!issues.contains(&WebBluetoothSecurityIssue::BluetoothWithoutPermission));
}

#[test]
fn detects_persistent_connection_reconnect() {
    let body = r#"<script>
        device.addEventListener("gattserverdisconnected", reconnect);
        function reconnect() {
            device.gatt.connect();
        }
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothPersistentConnection));
}

#[test]
fn detects_persistent_connection_interval() {
    let body = r#"<script>
        setInterval(() => {
            device.gatt.connect();
        }, 5000);
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothPersistentConnection));
}

#[test]
fn detects_persistent_connection_keepalive() {
    let body = r#"<script>
        navigator.bluetooth.requestDevice({keepalive: true});
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothPersistentConnection));
}

#[test]
fn no_persistent_connection_simple_disconnect() {
    let body = r#"<script>
        device.addEventListener("gattserverdisconnected", () => {
            console.log("disconnected");
        });
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(!issues.contains(&WebBluetoothSecurityIssue::BluetoothPersistentConnection));
}

#[test]
fn detects_cross_origin_post_message() {
    let body = r#"<script>
        const value = await characteristic.readValue();
        window.parent.postMessage({bluetooth: value}, "*");
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothCrossOrigin));
}

#[test]
fn detects_cross_origin_opener() {
    let body = r#"<script>
        const gatt = await device.gatt.connect();
        window.opener.shareGattConnection(gatt);
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothCrossOrigin));
}

#[test]
fn detects_cross_origin_parent_characteristic() {
    let body = r#"<script>
        const characteristic = await service.getCharacteristic("uuid");
        window.parent.storeCharacteristic(characteristic);
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothCrossOrigin));
}

#[test]
fn no_cross_origin_without_postmessage() {
    let body = r#"<script>
        const value = await characteristic.readValue();
        console.log(value);
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(!issues.contains(&WebBluetoothSecurityIssue::BluetoothCrossOrigin));
}

#[test]
fn detects_gatt_exploration_get_primary_services() {
    let body = r#"<script>
        const services = await server.getPrimaryServices();
        for (const service of services) {
            console.log(service.uuid);
        }
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothGattExploration));
}

#[test]
fn detects_gatt_exploration_get_characteristics() {
    let body = r#"<script>
        const characteristics = await service.getCharacteristics();
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothGattExploration));
}

#[test]
fn detects_gatt_exploration_loop_characteristics() {
    let body = r#"<script>
        for (const uuid of characteristicUuids) {
            const char = await service.getCharacteristic(uuid);
        }
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothGattExploration));
}

#[test]
fn detects_gatt_exploration_descriptors() {
    let body = r#"<script>
        const descriptors = await characteristic.descriptors;
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothGattExploration));
}

#[test]
fn no_gatt_exploration_single_service() {
    let body = r#"<script>
        const service = await server.getPrimaryService("battery_service");
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(!issues.contains(&WebBluetoothSecurityIssue::BluetoothGattExploration));
}

#[test]
fn detects_write_characteristic() {
    let body = r#"<script>
        const data = new Uint8Array([0x01, 0x02]);
        await characteristic.writeValue(data);
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothWriteCharacteristic));
}

#[test]
fn detects_write_characteristic_with_response() {
    let body = r#"<script>
        await characteristic.writeValueWithResponse(data);
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothWriteCharacteristic));
}

#[test]
fn detects_write_characteristic_without_response() {
    let body = r#"<script>
        await characteristic.writeValueWithoutResponse(data);
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothWriteCharacteristic));
}

#[test]
fn no_write_characteristic_read_only() {
    let body = r#"<script>
        const value = await characteristic.readValue();
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(!issues.contains(&WebBluetoothSecurityIssue::BluetoothWriteCharacteristic));
}

#[test]
fn detects_location_tracking_rssi() {
    let body = r#"<script>
        const rssi = device.rssi;
        const position = calculatePosition(rssi);
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothLocationTracking));
}

#[test]
fn detects_location_tracking_txpower() {
    let body = r#"<script>
        const txPower = device.txPower;
        const location = estimateLocation(txPower);
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothLocationTracking));
}

#[test]
fn detects_location_tracking_proximity() {
    let body = r#"<script>
        const proximity = calculateProximity(device);
        updateCoordinates(proximity);
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothLocationTracking));
}

#[test]
fn no_location_tracking_without_position() {
    let body = r#"<script>
        const rssi = device.rssi;
        console.log(rssi);
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(!issues.contains(&WebBluetoothSecurityIssue::BluetoothLocationTracking));
}

#[test]
fn detects_bluetooth_in_background_visibility() {
    let body = r#"<script>
        document.addEventListener("visibilitychange", () => {
            if (document.hidden) {
                characteristic.readValue();
            }
        });
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothInBackground));
}

#[test]
fn detects_bluetooth_in_background_hidden_gatt() {
    let body = r#"<script>
        if (document.hidden) {
            device.gatt.connect();
        }
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothInBackground));
}

#[test]
fn no_bluetooth_in_background_without_visibility() {
    let body = r#"<script>
        await device.gatt.connect();
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(!issues.contains(&WebBluetoothSecurityIssue::BluetoothInBackground));
}

#[test]
fn detects_device_fingerprinting_tracking() {
    let body = r#"<script>
        const devices = await navigator.bluetooth.getDevices();
        sendToAnalytics({fingerprint: devices.map(d => d.id)});
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothDeviceFingerprinting));
}

#[test]
fn detects_device_fingerprinting_request() {
    let body = r#"<script>
        const device = await navigator.bluetooth.requestDevice({});
        tracking.addFingerprint(device.id);
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothDeviceFingerprinting));
}

#[test]
fn detects_device_fingerprinting_analytics() {
    let body = r#"<script>
        navigator.bluetooth.getDevices().then(devices => {
            analytics.track(devices);
        });
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothDeviceFingerprinting));
}

#[test]
fn no_device_fingerprinting_without_tracking() {
    let body = r#"<script>
        const devices = await navigator.bluetooth.getDevices();
        console.log(devices);
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(!issues.contains(&WebBluetoothSecurityIssue::BluetoothDeviceFingerprinting));
}

#[test]
fn security_severity_data_interception_highest() {
    assert_eq!(
        web_bluetooth_security_severity(&WebBluetoothSecurityIssue::BluetoothDataInterception),
        8.5
    );
}

#[test]
fn security_severity_write_characteristic_high() {
    assert_eq!(
        web_bluetooth_security_severity(&WebBluetoothSecurityIssue::BluetoothWriteCharacteristic),
        8.0
    );
}

#[test]
fn security_severity_cross_origin() {
    assert_eq!(
        web_bluetooth_security_severity(&WebBluetoothSecurityIssue::BluetoothCrossOrigin),
        7.5
    );
}

#[test]
fn security_severity_without_permission_lowest() {
    assert_eq!(
        web_bluetooth_security_severity(&WebBluetoothSecurityIssue::BluetoothWithoutPermission),
        4.0
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        WebBluetoothSecurityIssue::BluetoothDeviceEnumeration,
        WebBluetoothSecurityIssue::BluetoothDataInterception,
        WebBluetoothSecurityIssue::BluetoothWriteCharacteristic,
    ];
    let mut seq = 0;
    let ops = web_bluetooth_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn security_to_operations_empty_list() {
    let issues = vec![];
    let mut seq = 0;
    let ops = web_bluetooth_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 0);
    assert_eq!(seq, 0);
}

#[test]
fn security_display_device_enumeration() {
    assert_eq!(
        WebBluetoothSecurityIssue::BluetoothDeviceEnumeration.to_string(),
        "bluetooth_device_enumeration"
    );
}

#[test]
fn security_display_data_interception() {
    assert_eq!(
        WebBluetoothSecurityIssue::BluetoothDataInterception.to_string(),
        "bluetooth_data_interception"
    );
}

#[test]
fn security_display_without_permission() {
    assert_eq!(
        WebBluetoothSecurityIssue::BluetoothWithoutPermission.to_string(),
        "bluetooth_without_permission"
    );
}

#[test]
fn security_display_persistent_connection() {
    assert_eq!(
        WebBluetoothSecurityIssue::BluetoothPersistentConnection.to_string(),
        "bluetooth_persistent_connection"
    );
}

#[test]
fn security_display_cross_origin() {
    assert_eq!(
        WebBluetoothSecurityIssue::BluetoothCrossOrigin.to_string(),
        "bluetooth_cross_origin"
    );
}

#[test]
fn security_display_gatt_exploration() {
    assert_eq!(
        WebBluetoothSecurityIssue::BluetoothGattExploration.to_string(),
        "bluetooth_gatt_exploration"
    );
}

#[test]
fn security_display_write_characteristic() {
    assert_eq!(
        WebBluetoothSecurityIssue::BluetoothWriteCharacteristic.to_string(),
        "bluetooth_write_characteristic"
    );
}

#[test]
fn security_display_location_tracking() {
    assert_eq!(
        WebBluetoothSecurityIssue::BluetoothLocationTracking.to_string(),
        "bluetooth_location_tracking"
    );
}

#[test]
fn security_display_in_background() {
    assert_eq!(
        WebBluetoothSecurityIssue::BluetoothInBackground.to_string(),
        "bluetooth_in_background"
    );
}

#[test]
fn security_display_device_fingerprinting() {
    assert_eq!(
        WebBluetoothSecurityIssue::BluetoothDeviceFingerprinting.to_string(),
        "bluetooth_device_fingerprinting"
    );
}

#[test]
fn multiple_security_issues_detected() {
    let body = r#"<script>
        window.onload = async () => {
            const device = await navigator.bluetooth.requestDevice({acceptAllDevices: true});
            const server = await device.gatt.connect();
            const services = await server.getPrimaryServices();
            for (const service of services) {
                const characteristics = await service.getCharacteristics();
                for (const char of characteristics) {
                    const value = await char.readValue();
                    const buffer = value.buffer;
                    await char.writeValue(new Uint8Array([0x01]));
                }
            }
            window.parent.postMessage({bluetooth: "data"}, "*");
        };
    </script>"#;
    let issues = analyze_web_bluetooth_security(body);
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothDeviceEnumeration));
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothWithoutPermission));
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothGattExploration));
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothDataInterception));
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothWriteCharacteristic));
    assert!(issues.contains(&WebBluetoothSecurityIssue::BluetoothCrossOrigin));
}
