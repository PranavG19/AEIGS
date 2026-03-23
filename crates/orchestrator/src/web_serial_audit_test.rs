use crate::web_serial_audit::*;

#[test]
fn no_serial_no_issues() {
    assert!(analyze_web_serial("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_navigator() {
    let body = r#"<script>const port = await navigator.serial.requestPort();</script>"#;
    let issues = analyze_web_serial(body);
    assert!(issues.contains(&WebSerialIssue::ApiDetected));
}

#[test]
fn detects_api_serial_port() {
    let body = r#"<script>const port = new SerialPort();</script>"#;
    let issues = analyze_web_serial(body);
    assert!(issues.contains(&WebSerialIssue::ApiDetected));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        const port = await navigator.serial.requestPort();
        fetch("/api/serial-data", {body: "data"});
    </script>"#;
    let issues = analyze_web_serial(body);
    assert!(issues.contains(&WebSerialIssue::DataExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const port = await navigator.serial.requestPort();
        console.log(port);
    </script>"#;
    let issues = analyze_web_serial(body);
    assert!(!issues.contains(&WebSerialIssue::DataExfiltration));
}

#[test]
fn detects_no_user_activation() {
    let body = r#"<script>await navigator.serial.requestPort();</script>"#;
    let issues = analyze_web_serial(body);
    assert!(issues.contains(&WebSerialIssue::NoUserActivation));
}

#[test]
fn no_activation_issue_with_click() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            await navigator.serial.requestPort();
        });
    </script>"#;
    let issues = analyze_web_serial(body);
    assert!(!issues.contains(&WebSerialIssue::NoUserActivation));
}

#[test]
fn detects_raw_read_write() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const port = await navigator.serial.requestPort();
            await port.open({baudRate: 9600});
            const reader = port.readable.getReader();
        });
    </script>"#;
    let issues = analyze_web_serial(body);
    assert!(issues.contains(&WebSerialIssue::RawReadWrite));
}

#[test]
fn detects_device_enumeration() {
    let body = r#"<script>
        const ports = await navigator.serial.getPorts();
    </script>"#;
    let issues = analyze_web_serial(body);
    assert!(issues.contains(&WebSerialIssue::DeviceEnumeration));
}

#[test]
fn detects_persistent_stream() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const port = await navigator.serial.requestPort();
            await port.open({baudRate: 115200});
            port.readable.pipeTo(writableStream);
        });
    </script>"#;
    let issues = analyze_web_serial(body);
    assert!(issues.contains(&WebSerialIssue::PersistentStream));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(web_serial_severity(&WebSerialIssue::DataExfiltration), 7.5);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(web_serial_severity(&WebSerialIssue::ApiDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![WebSerialIssue::ApiDetected, WebSerialIssue::RawReadWrite];
    let mut seq = 0;
    let ops = web_serial_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(WebSerialIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(WebSerialIssue::DataExfiltration.to_string(), "data_exfiltration");
    assert_eq!(WebSerialIssue::NoUserActivation.to_string(), "no_user_activation");
    assert_eq!(WebSerialIssue::RawReadWrite.to_string(), "raw_read_write");
    assert_eq!(WebSerialIssue::DeviceEnumeration.to_string(), "device_enumeration");
    assert_eq!(WebSerialIssue::PersistentStream.to_string(), "persistent_stream");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_web_serial("").is_empty());
}
