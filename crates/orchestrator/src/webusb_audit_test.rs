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
