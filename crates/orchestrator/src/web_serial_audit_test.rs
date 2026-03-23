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
    assert_eq!(
        WebSerialIssue::DataExfiltration.to_string(),
        "data_exfiltration"
    );
    assert_eq!(
        WebSerialIssue::NoUserActivation.to_string(),
        "no_user_activation"
    );
    assert_eq!(WebSerialIssue::RawReadWrite.to_string(), "raw_read_write");
    assert_eq!(
        WebSerialIssue::DeviceEnumeration.to_string(),
        "device_enumeration"
    );
    assert_eq!(
        WebSerialIssue::PersistentStream.to_string(),
        "persistent_stream"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_web_serial("").is_empty());
}

// WebSerialSecurityIssue Tests

#[test]
fn security_no_serial_no_issues() {
    assert!(analyze_web_serial_security("<html><body>hello</body></html>").is_empty());
}

#[test]
fn security_empty_body_no_issues() {
    assert!(analyze_web_serial_security("").is_empty());
}

#[test]
fn detects_serial_port_enumeration() {
    let body = r#"<script>
        const ports = await navigator.serial.getPorts();
        ports.forEach(port => console.log(port));
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(issues.contains(&WebSerialSecurityIssue::SerialPortEnumeration));
}

#[test]
fn detects_serial_port_enumeration_with_call() {
    let body = r#"<script>
        const ports = await navigator.serial.getPorts();
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(issues.contains(&WebSerialSecurityIssue::SerialPortEnumeration));
}

#[test]
fn detects_serial_data_exfiltration() {
    let body = r#"<script>
        const port = await navigator.serial.requestPort();
        await port.open({baudRate: 9600});
        const reader = port.readable.getReader();
        const {value} = await reader.read();
        fetch("/exfil", {method: "POST", body: JSON.stringify(value)});
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(issues.contains(&WebSerialSecurityIssue::SerialDataExfiltration));
}

#[test]
fn detects_serial_data_exfiltration_with_send_beacon() {
    let body = r#"<script>
        const reader = port.readable.getReader();
        const {value} = await reader.read();
        navigator.sendBeacon("/data", value);
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(issues.contains(&WebSerialSecurityIssue::SerialDataExfiltration));
}

#[test]
fn no_exfiltration_without_network() {
    let body = r#"<script>
        const port = await navigator.serial.requestPort();
        const reader = port.readable.getReader();
        console.log(await reader.read());
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(!issues.contains(&WebSerialSecurityIssue::SerialDataExfiltration));
}

#[test]
fn detects_serial_without_permission() {
    let body = r#"<script>
        await navigator.serial.requestPort();
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(issues.contains(&WebSerialSecurityIssue::SerialWithoutPermission));
}

#[test]
fn no_permission_issue_with_click() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            await navigator.serial.requestPort();
        });
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(!issues.contains(&WebSerialSecurityIssue::SerialWithoutPermission));
}

#[test]
fn no_permission_issue_with_keydown() {
    let body = r#"<script>
        document.addEventListener("keydown", async () => {
            await navigator.serial.requestPort();
        });
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(!issues.contains(&WebSerialSecurityIssue::SerialWithoutPermission));
}

#[test]
fn no_permission_issue_with_touchstart() {
    let body = r#"<script>
        element.addEventListener("touchstart", async () => {
            await navigator.serial.requestPort();
        });
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(!issues.contains(&WebSerialSecurityIssue::SerialWithoutPermission));
}

#[test]
fn detects_serial_firmware_access_firmware_keyword() {
    let body = r#"<script>
        const port = await navigator.serial.requestPort();
        const writer = port.writable.getWriter();
        await writer.write(firmwareData);
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(issues.contains(&WebSerialSecurityIssue::SerialFirmwareAccess));
}

#[test]
fn detects_serial_firmware_access_flash_keyword() {
    let body = r#"<script>
        const writer = port.writable.getWriter();
        await flashDevice(writer);
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(issues.contains(&WebSerialSecurityIssue::SerialFirmwareAccess));
}

#[test]
fn detects_serial_firmware_access_bootloader() {
    let body = r#"<script>
        await enterBootloader();
        const writer = port.writable.getWriter();
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(issues.contains(&WebSerialSecurityIssue::SerialFirmwareAccess));
}

#[test]
fn detects_serial_cross_origin_post_message() {
    let body = r#"<script>
        const port = await navigator.serial.requestPort();
        const reader = port.readable.getReader();
        const data = await reader.read();
        parent.postMessage(data, "*");
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(issues.contains(&WebSerialSecurityIssue::SerialCrossOrigin));
}

#[test]
fn detects_serial_cross_origin_opener() {
    let body = r#"<script>
        const reader = port.readable.getReader();
        opener.postMessage(await reader.read(), "*");
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(issues.contains(&WebSerialSecurityIssue::SerialCrossOrigin));
}

#[test]
fn detects_serial_persistent_connection_set_interval() {
    let body = r#"<script>
        const reader = port.readable.getReader();
        setInterval(async () => {
            const {value} = await reader.read();
            processData(value);
        }, 100);
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(issues.contains(&WebSerialSecurityIssue::SerialPersistentConnection));
}

#[test]
fn detects_serial_persistent_connection_while_loop() {
    let body = r#"<script>
        while(true) {
            const {value} = await port.readable.getReader().read();
        }
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(issues.contains(&WebSerialSecurityIssue::SerialPersistentConnection));
}

#[test]
fn detects_serial_persistent_connection_while_loop_spaces() {
    let body = r#"<script>
        while (true) {
            const reader = port.readable.getReader();
        }
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(issues.contains(&WebSerialSecurityIssue::SerialPersistentConnection));
}

#[test]
fn detects_serial_high_baud_rate_115200() {
    let body = r#"<script>
        await port.open({baudRate: 115200});
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(issues.contains(&WebSerialSecurityIssue::SerialHighBaudRate));
}

#[test]
fn detects_serial_high_baud_rate_921600() {
    let body = r#"<script>
        await port.open({baudRate: 921600});
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(issues.contains(&WebSerialSecurityIssue::SerialHighBaudRate));
}

#[test]
fn detects_serial_high_baud_rate_no_space() {
    let body = r#"<script>
        await port.open({baudRate:230400});
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(issues.contains(&WebSerialSecurityIssue::SerialHighBaudRate));
}

#[test]
fn no_high_baud_rate_for_9600() {
    let body = r#"<script>
        await port.open({baudRate: 9600});
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(!issues.contains(&WebSerialSecurityIssue::SerialHighBaudRate));
}

#[test]
fn detects_serial_in_background_visibility_change() {
    let body = r#"<script>
        document.addEventListener("visibilitychange", () => {
            const port = navigator.serial.requestPort();
        });
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(issues.contains(&WebSerialSecurityIssue::SerialInBackground));
}

#[test]
fn detects_serial_in_background_hidden_check() {
    let body = r#"<script>
        if (document.hidden) {
            const reader = port.readable.getReader();
        }
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(issues.contains(&WebSerialSecurityIssue::SerialInBackground));
}

#[test]
fn detects_serial_device_fingerprinting_get_info() {
    let body = r#"<script>
        const port = await navigator.serial.requestPort();
        const info = port.getInfo();
        console.log(info);
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(issues.contains(&WebSerialSecurityIssue::SerialDeviceFingerprinting));
}

#[test]
fn detects_serial_device_fingerprinting_usb_vendor() {
    let body = r#"<script>
        const ports = await navigator.serial.getPorts();
        ports.forEach(port => {
            console.log(port.usbVendorId);
        });
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(issues.contains(&WebSerialSecurityIssue::SerialDeviceFingerprinting));
}

#[test]
fn detects_serial_device_fingerprinting_usb_product() {
    let body = r#"<script>
        const info = await port.getInfo();
        const id = info.usbProductId;
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(issues.contains(&WebSerialSecurityIssue::SerialDeviceFingerprinting));
}

#[test]
fn detects_serial_binary_data_transfer_array_buffer() {
    let body = r#"<script>
        const port = await navigator.serial.requestPort();
        const buffer = new ArrayBuffer(1024);
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(issues.contains(&WebSerialSecurityIssue::SerialBinaryDataTransfer));
}

#[test]
fn detects_serial_binary_data_transfer_uint8_array() {
    let body = r#"<script>
        const writer = port.writable.getWriter();
        const data = new Uint8Array([0x01, 0x02, 0x03]);
        await writer.write(data);
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(issues.contains(&WebSerialSecurityIssue::SerialBinaryDataTransfer));
}

#[test]
fn detects_serial_binary_data_transfer_data_view() {
    let body = r#"<script>
        const buffer = new ArrayBuffer(8);
        const view = new DataView(buffer);
        await navigator.serial.requestPort();
    </script>"#;
    let issues = analyze_web_serial_security(body);
    assert!(issues.contains(&WebSerialSecurityIssue::SerialBinaryDataTransfer));
}

#[test]
fn security_severity_data_exfiltration_highest() {
    assert_eq!(
        web_serial_security_severity(&WebSerialSecurityIssue::SerialDataExfiltration),
        8.5
    );
}

#[test]
fn security_severity_firmware_access_high() {
    assert_eq!(
        web_serial_security_severity(&WebSerialSecurityIssue::SerialFirmwareAccess),
        8.0
    );
}

#[test]
fn security_severity_cross_origin() {
    assert_eq!(
        web_serial_security_severity(&WebSerialSecurityIssue::SerialCrossOrigin),
        7.5
    );
}

#[test]
fn security_severity_port_enumeration_lowest() {
    assert_eq!(
        web_serial_security_severity(&WebSerialSecurityIssue::SerialPortEnumeration),
        4.0
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        WebSerialSecurityIssue::SerialPortEnumeration,
        WebSerialSecurityIssue::SerialDataExfiltration,
    ];
    let mut seq = 0;
    let ops = web_serial_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_to_operations_empty_issues() {
    let issues = vec![];
    let mut seq = 0;
    let ops = web_serial_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 0);
    assert_eq!(seq, 0);
}

#[test]
fn security_display_serial_port_enumeration() {
    assert_eq!(
        WebSerialSecurityIssue::SerialPortEnumeration.to_string(),
        "serial_port_enumeration"
    );
}

#[test]
fn security_display_serial_data_exfiltration() {
    assert_eq!(
        WebSerialSecurityIssue::SerialDataExfiltration.to_string(),
        "serial_data_exfiltration"
    );
}

#[test]
fn security_display_serial_without_permission() {
    assert_eq!(
        WebSerialSecurityIssue::SerialWithoutPermission.to_string(),
        "serial_without_permission"
    );
}

#[test]
fn security_display_serial_firmware_access() {
    assert_eq!(
        WebSerialSecurityIssue::SerialFirmwareAccess.to_string(),
        "serial_firmware_access"
    );
}

#[test]
fn security_display_serial_cross_origin() {
    assert_eq!(
        WebSerialSecurityIssue::SerialCrossOrigin.to_string(),
        "serial_cross_origin"
    );
}

#[test]
fn security_display_serial_persistent_connection() {
    assert_eq!(
        WebSerialSecurityIssue::SerialPersistentConnection.to_string(),
        "serial_persistent_connection"
    );
}

#[test]
fn security_display_serial_high_baud_rate() {
    assert_eq!(
        WebSerialSecurityIssue::SerialHighBaudRate.to_string(),
        "serial_high_baud_rate"
    );
}

#[test]
fn security_display_serial_in_background() {
    assert_eq!(
        WebSerialSecurityIssue::SerialInBackground.to_string(),
        "serial_in_background"
    );
}

#[test]
fn security_display_serial_device_fingerprinting() {
    assert_eq!(
        WebSerialSecurityIssue::SerialDeviceFingerprinting.to_string(),
        "serial_device_fingerprinting"
    );
}

#[test]
fn security_display_serial_binary_data_transfer() {
    assert_eq!(
        WebSerialSecurityIssue::SerialBinaryDataTransfer.to_string(),
        "serial_binary_data_transfer"
    );
}
