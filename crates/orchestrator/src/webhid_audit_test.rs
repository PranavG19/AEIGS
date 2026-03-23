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
    assert_eq!(WebHidIssue::DataExfiltration.to_string(), "data_exfiltration");
    assert_eq!(WebHidIssue::NoUserActivation.to_string(), "no_user_activation");
    assert_eq!(WebHidIssue::RawDataAccess.to_string(), "raw_data_access");
    assert_eq!(WebHidIssue::DeviceEnumeration.to_string(), "device_enumeration");
    assert_eq!(WebHidIssue::PersistentConnection.to_string(), "persistent_connection");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_webhid("").is_empty());
}
