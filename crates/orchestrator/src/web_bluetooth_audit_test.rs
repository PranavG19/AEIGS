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
