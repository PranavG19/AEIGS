use crate::presentation_audit::*;

#[test]
fn no_presentation_no_issues() {
    assert!(analyze_presentation("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_request() {
    let body = r#"<script>const req = new PresentationRequest(["cast.html"]);</script>"#;
    let issues = analyze_presentation(body);
    assert!(issues.contains(&PresentationIssue::ApiDetected));
}

#[test]
fn detects_api_connection() {
    let body = r#"<script>const conn = new PresentationConnection();</script>"#;
    let issues = analyze_presentation(body);
    assert!(issues.contains(&PresentationIssue::ApiDetected));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        fetch("/track?data=leaked");
    </script>"#;
    let issues = analyze_presentation(body);
    assert!(issues.contains(&PresentationIssue::DataExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        console.log(req);
    </script>"#;
    let issues = analyze_presentation(body);
    assert!(!issues.contains(&PresentationIssue::DataExfiltration));
}

#[test]
fn detects_cross_origin_url() {
    let body = r#"<script>
        const req = new PresentationRequest("http://evil.com/cast.html");
    </script>"#;
    let issues = analyze_presentation(body);
    assert!(issues.contains(&PresentationIssue::CrossOriginUrl));
}

#[test]
fn no_cross_origin_with_https() {
    let body = r#"<script>
        const req = new PresentationRequest("https://example.com/cast.html");
    </script>"#;
    let issues = analyze_presentation(body);
    assert!(!issues.contains(&PresentationIssue::CrossOriginUrl));
}

#[test]
fn detects_no_availability_check() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        req.start();
    </script>"#;
    let issues = analyze_presentation(body);
    assert!(issues.contains(&PresentationIssue::NoAvailabilityCheck));
}

#[test]
fn no_availability_issue_with_check() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        const avail = await req.getAvailability();
    </script>"#;
    let issues = analyze_presentation(body);
    assert!(!issues.contains(&PresentationIssue::NoAvailabilityCheck));
}

#[test]
fn detects_message_channel() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        conn.send("secret data");
        conn.onmessage = (e) => console.log(e);
    </script>"#;
    let issues = analyze_presentation(body);
    assert!(issues.contains(&PresentationIssue::MessageChannel));
}

#[test]
fn detects_auto_reconnect() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        navigator.presentation.defaultRequest = req;
        navigator.presentation.receiver.connectionavailable = handler;
    </script>"#;
    let issues = analyze_presentation(body);
    assert!(issues.contains(&PresentationIssue::AutoReconnect));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        presentation_severity(&PresentationIssue::DataExfiltration),
        6.5
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(presentation_severity(&PresentationIssue::ApiDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        PresentationIssue::ApiDetected,
        PresentationIssue::MessageChannel,
    ];
    let mut seq = 0;
    let ops = presentation_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(PresentationIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        PresentationIssue::DataExfiltration.to_string(),
        "data_exfiltration"
    );
    assert_eq!(
        PresentationIssue::CrossOriginUrl.to_string(),
        "cross_origin_url"
    );
    assert_eq!(
        PresentationIssue::NoAvailabilityCheck.to_string(),
        "no_availability_check"
    );
    assert_eq!(
        PresentationIssue::MessageChannel.to_string(),
        "message_channel"
    );
    assert_eq!(
        PresentationIssue::AutoReconnect.to_string(),
        "auto_reconnect"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_presentation("").is_empty());
}

#[test]
pub fn security_empty_body_no_issues() {
    assert!(analyze_presentation_security("").is_empty());
}

#[test]
pub fn security_no_presentation_no_issues() {
    assert!(analyze_presentation_security("<html><body>hello</body></html>").is_empty());
}

#[test]
pub fn security_no_keywords_no_issues() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        console.log(req);
    </script>"#;
    assert!(analyze_presentation_security(body).is_empty());
}

#[test]
pub fn detects_presentation_data_exfiltration() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        connection.send("sensitive data");
        fetch("/exfil", { method: "POST", body: data });
    </script>"#;
    let issues = analyze_presentation_security(body);
    assert!(issues.contains(&PresentationSecurityIssue::PresentationDataExfiltration));
}

#[test]
pub fn no_data_exfiltration_without_send() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        fetch("/api");
    </script>"#;
    let issues = analyze_presentation_security(body);
    assert!(!issues.contains(&PresentationSecurityIssue::PresentationDataExfiltration));
}

#[test]
pub fn data_exfiltration_with_sendbeacon() {
    let body = r#"<script>
        const conn = new PresentationConnection();
        conn.send(data);
        navigator.sendBeacon("/track", blob);
    </script>"#;
    let issues = analyze_presentation_security(body);
    assert!(issues.contains(&PresentationSecurityIssue::PresentationDataExfiltration));
}

#[test]
pub fn detects_presentation_cross_origin() {
    let body = r#"<script>
        const conn = new PresentationConnection();
        window.postMessage(conn.id, "*");
    </script>"#;
    let issues = analyze_presentation_security(body);
    assert!(issues.contains(&PresentationSecurityIssue::PresentationCrossOrigin));
}

#[test]
pub fn no_cross_origin_without_postmessage() {
    let body = r#"<script>
        const conn = new PresentationConnection();
        console.log(conn);
    </script>"#;
    let issues = analyze_presentation_security(body);
    assert!(!issues.contains(&PresentationSecurityIssue::PresentationCrossOrigin));
}

#[test]
pub fn detects_presentation_session_hijack() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        localStorage.setItem("conn_id", connection.id);
    </script>"#;
    let issues = analyze_presentation_security(body);
    assert!(issues.contains(&PresentationSecurityIssue::PresentationSessionHijack));
}

#[test]
pub fn no_session_hijack_without_storage() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        console.log(connection.id);
    </script>"#;
    let issues = analyze_presentation_security(body);
    assert!(!issues.contains(&PresentationSecurityIssue::PresentationSessionHijack));
}

#[test]
pub fn detects_presentation_without_consent() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        req.start();
    </script>"#;
    let issues = analyze_presentation_security(body);
    assert!(issues.contains(&PresentationSecurityIssue::PresentationWithoutConsent));
}

#[test]
pub fn no_consent_issue_with_click() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        button.addEventListener("click", () => req.start());
    </script>"#;
    let issues = analyze_presentation_security(body);
    assert!(!issues.contains(&PresentationSecurityIssue::PresentationWithoutConsent));
}

#[test]
pub fn no_consent_issue_with_user_activation() {
    let body = r#"<script>
        // Requires user activation
        const req = new PresentationRequest(["cast.html"]);
        req.start();
    </script>"#;
    let body_with_activation = body.replace("//", "// user activation");
    let issues = analyze_presentation_security(&body_with_activation);
    assert!(!issues.contains(&PresentationSecurityIssue::PresentationWithoutConsent));
}

#[test]
pub fn detects_presentation_screen_capture() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        const stream = await navigator.mediaDevices.getDisplayMedia();
    </script>"#;
    let issues = analyze_presentation_security(body);
    assert!(issues.contains(&PresentationSecurityIssue::PresentationScreenCapture));
}

#[test]
pub fn no_screen_capture_without_getdisplaymedia() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        const stream = await navigator.mediaDevices.getUserMedia();
    </script>"#;
    let issues = analyze_presentation_security(body);
    assert!(!issues.contains(&PresentationSecurityIssue::PresentationScreenCapture));
}

#[test]
pub fn detects_presentation_persistence() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        sessionStorage.setItem("pres_id", connection.id);
    </script>"#;
    let issues = analyze_presentation_security(body);
    assert!(issues.contains(&PresentationSecurityIssue::PresentationPersistence));
}

#[test]
pub fn persistence_with_indexeddb() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        indexedDB.open("pres").onsuccess = () => {
            store.put({ id: presentation.id });
        };
    </script>"#;
    let issues = analyze_presentation_security(body);
    assert!(issues.contains(&PresentationSecurityIssue::PresentationPersistence));
}

#[test]
pub fn no_persistence_without_storage() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        console.log(connection.id);
    </script>"#;
    let issues = analyze_presentation_security(body);
    assert!(!issues.contains(&PresentationSecurityIssue::PresentationPersistence));
}

#[test]
pub fn detects_presentation_in_background() {
    let body = r#"<script>
        const conn = new PresentationConnection();
        if (document.visibilityState === "hidden") {
            conn.send(data);
        }
    </script>"#;
    let issues = analyze_presentation_security(body);
    assert!(issues.contains(&PresentationSecurityIssue::PresentationInBackground));
}

#[test]
pub fn no_background_without_visibility_check() {
    let body = r#"<script>
        const conn = new PresentationConnection();
        conn.send(data);
    </script>"#;
    let issues = analyze_presentation_security(body);
    assert!(!issues.contains(&PresentationSecurityIssue::PresentationInBackground));
}

#[test]
pub fn detects_presentation_channel_abuse() {
    let body = r#"<script>
        const conn = new PresentationConnection();
        const channel = new MessageChannel();
        conn.postMessage("data", [channel.port2]);
    </script>"#;
    let issues = analyze_presentation_security(body);
    assert!(issues.contains(&PresentationSecurityIssue::PresentationChannelAbuse));
}

#[test]
pub fn no_channel_abuse_without_messagechannel() {
    let body = r#"<script>
        const conn = new PresentationConnection();
        conn.send("data");
    </script>"#;
    let issues = analyze_presentation_security(body);
    assert!(!issues.contains(&PresentationSecurityIssue::PresentationChannelAbuse));
}

#[test]
pub fn detects_presentation_device_enumeration() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        const avail = await req.getAvailability();
        avail.addEventListener("change", () => monitor(avail.value));
    </script>"#;
    let issues = analyze_presentation_security(body);
    assert!(issues.contains(&PresentationSecurityIssue::PresentationDeviceEnumeration));
}

#[test]
pub fn no_device_enumeration_without_monitor() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        const avail = await req.getAvailability();
    </script>"#;
    let issues = analyze_presentation_security(body);
    assert!(!issues.contains(&PresentationSecurityIssue::PresentationDeviceEnumeration));
}

#[test]
pub fn detects_presentation_content_injection() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        const payload = "<script>alert(1)</script>";
        connection.send(payload);
    </script>"#;
    let issues = analyze_presentation_security(body);
    assert!(issues.contains(&PresentationSecurityIssue::PresentationContentInjection));
}

#[test]
pub fn no_content_injection_without_script_tag() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        connection.send("safe data");
    </script>"#;
    let issues = analyze_presentation_security(body);
    assert!(!issues.contains(&PresentationSecurityIssue::PresentationContentInjection));
}

#[test]
pub fn multiple_security_issues_detected() {
    let body = r#"<script>
        const req = new PresentationRequest(["cast.html"]);
        const conn = new PresentationConnection();

        // Data exfiltration
        conn.send("data");
        fetch("/exfil");

        // Cross origin
        window.postMessage(conn.id, "*");

        // Session hijack
        localStorage.setItem("id", connection.id);

        // Content injection
        connection.send("<script>alert(1)</script>");
    </script>"#;
    let issues = analyze_presentation_security(body);
    assert!(issues.contains(&PresentationSecurityIssue::PresentationDataExfiltration));
    assert!(issues.contains(&PresentationSecurityIssue::PresentationCrossOrigin));
    assert!(issues.contains(&PresentationSecurityIssue::PresentationSessionHijack));
    assert!(issues.contains(&PresentationSecurityIssue::PresentationContentInjection));
}

#[test]
pub fn security_display_variants() {
    assert_eq!(
        PresentationSecurityIssue::PresentationDataExfiltration.to_string(),
        "presentation_data_exfiltration"
    );
    assert_eq!(
        PresentationSecurityIssue::PresentationCrossOrigin.to_string(),
        "presentation_cross_origin"
    );
    assert_eq!(
        PresentationSecurityIssue::PresentationSessionHijack.to_string(),
        "presentation_session_hijack"
    );
    assert_eq!(
        PresentationSecurityIssue::PresentationWithoutConsent.to_string(),
        "presentation_without_consent"
    );
    assert_eq!(
        PresentationSecurityIssue::PresentationScreenCapture.to_string(),
        "presentation_screen_capture"
    );
    assert_eq!(
        PresentationSecurityIssue::PresentationPersistence.to_string(),
        "presentation_persistence"
    );
    assert_eq!(
        PresentationSecurityIssue::PresentationInBackground.to_string(),
        "presentation_in_background"
    );
    assert_eq!(
        PresentationSecurityIssue::PresentationChannelAbuse.to_string(),
        "presentation_channel_abuse"
    );
    assert_eq!(
        PresentationSecurityIssue::PresentationDeviceEnumeration.to_string(),
        "presentation_device_enumeration"
    );
    assert_eq!(
        PresentationSecurityIssue::PresentationContentInjection.to_string(),
        "presentation_content_injection"
    );
}

#[test]
pub fn security_severity_content_injection_highest() {
    assert_eq!(
        presentation_security_severity(&PresentationSecurityIssue::PresentationContentInjection),
        9.0
    );
}

#[test]
pub fn security_severity_device_enumeration_lowest() {
    assert_eq!(
        presentation_security_severity(&PresentationSecurityIssue::PresentationDeviceEnumeration),
        3.0
    );
}

#[test]
pub fn security_severity_all_variants() {
    assert_eq!(
        presentation_security_severity(&PresentationSecurityIssue::PresentationContentInjection),
        9.0
    );
    assert_eq!(
        presentation_security_severity(&PresentationSecurityIssue::PresentationSessionHijack),
        8.5
    );
    assert_eq!(
        presentation_security_severity(&PresentationSecurityIssue::PresentationDataExfiltration),
        8.0
    );
    assert_eq!(
        presentation_security_severity(&PresentationSecurityIssue::PresentationScreenCapture),
        7.5
    );
    assert_eq!(
        presentation_security_severity(&PresentationSecurityIssue::PresentationCrossOrigin),
        7.0
    );
    assert_eq!(
        presentation_security_severity(&PresentationSecurityIssue::PresentationChannelAbuse),
        6.5
    );
    assert_eq!(
        presentation_security_severity(&PresentationSecurityIssue::PresentationPersistence),
        6.0
    );
    assert_eq!(
        presentation_security_severity(&PresentationSecurityIssue::PresentationInBackground),
        5.5
    );
    assert_eq!(
        presentation_security_severity(&PresentationSecurityIssue::PresentationWithoutConsent),
        5.0
    );
    assert_eq!(
        presentation_security_severity(&PresentationSecurityIssue::PresentationDeviceEnumeration),
        3.0
    );
}

#[test]
pub fn security_to_operations_creates_entries() {
    let issues = vec![
        PresentationSecurityIssue::PresentationDataExfiltration,
        PresentationSecurityIssue::PresentationCrossOrigin,
        PresentationSecurityIssue::PresentationSessionHijack,
    ];
    let mut seq = 0;
    let ops = presentation_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
pub fn security_to_operations_empty_input() {
    let issues = vec![];
    let mut seq = 0;
    let ops = presentation_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 0);
    assert_eq!(seq, 0);
}
