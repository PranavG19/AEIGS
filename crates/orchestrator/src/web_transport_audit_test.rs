use crate::web_transport_audit::*;

#[test]
fn no_transport_no_issues() {
    assert!(analyze_web_transport("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api() {
    let body = r#"<script>const wt = new WebTransport("https://example.com");</script>"#;
    let issues = analyze_web_transport(body);
    assert!(issues.contains(&WebTransportIssue::ApiDetected));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        fetch("/track?data=leaked");
    </script>"#;
    let issues = analyze_web_transport(body);
    assert!(issues.contains(&WebTransportIssue::DataExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        console.log(wt);
    </script>"#;
    let issues = analyze_web_transport(body);
    assert!(!issues.contains(&WebTransportIssue::DataExfiltration));
}

#[test]
fn detects_unencrypted_endpoint() {
    let body = r#"<script>
        const wt = new WebTransport("http://example.com:4433/wt");
    </script>"#;
    let issues = analyze_web_transport(body);
    assert!(issues.contains(&WebTransportIssue::UnencryptedEndpoint));
}

#[test]
fn no_unencrypted_with_https() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com:4433/wt");
    </script>"#;
    let issues = analyze_web_transport(body);
    assert!(!issues.contains(&WebTransportIssue::UnencryptedEndpoint));
}

#[test]
fn detects_bidirectional_stream() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        const stream = await wt.createBidirectionalStream();
    </script>"#;
    let issues = analyze_web_transport(body);
    assert!(issues.contains(&WebTransportIssue::BidirectionalStream));
}

#[test]
fn detects_datagram_abuse() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        const writer = wt.datagrams.writable.getWriter();
    </script>"#;
    let issues = analyze_web_transport(body);
    assert!(issues.contains(&WebTransportIssue::DatagramAbuse));
}

#[test]
fn detects_no_close_handling() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        const stream = await wt.createBidirectionalStream();
    </script>"#;
    let issues = analyze_web_transport(body);
    assert!(issues.contains(&WebTransportIssue::NoCloseHandling));
}

#[test]
fn no_close_issue_with_close() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        wt.closed.then(() => console.log("done"));
    </script>"#;
    let issues = analyze_web_transport(body);
    assert!(!issues.contains(&WebTransportIssue::NoCloseHandling));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        web_transport_severity(&WebTransportIssue::DataExfiltration),
        7.0
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(web_transport_severity(&WebTransportIssue::ApiDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        WebTransportIssue::ApiDetected,
        WebTransportIssue::DatagramAbuse,
    ];
    let mut seq = 0;
    let ops = web_transport_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(WebTransportIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        WebTransportIssue::DataExfiltration.to_string(),
        "data_exfiltration"
    );
    assert_eq!(
        WebTransportIssue::UnencryptedEndpoint.to_string(),
        "unencrypted_endpoint"
    );
    assert_eq!(
        WebTransportIssue::BidirectionalStream.to_string(),
        "bidirectional_stream"
    );
    assert_eq!(
        WebTransportIssue::DatagramAbuse.to_string(),
        "datagram_abuse"
    );
    assert_eq!(
        WebTransportIssue::NoCloseHandling.to_string(),
        "no_close_handling"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_web_transport("").is_empty());
}

// WebTransportSecurityIssue tests

#[test]
fn security_no_transport_no_issues() {
    assert!(analyze_web_transport_security("<html><body>hello</body></html>").is_empty());
}

#[test]
fn security_empty_body_no_issues() {
    assert!(analyze_web_transport_security("").is_empty());
}

#[test]
fn detects_unencrypted_transport() {
    let body = r#"<script>const wt = new WebTransport("http://example.com:4433/wt");</script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::UnencryptedTransport));
}

#[test]
fn no_unencrypted_transport_with_https() {
    let body = r#"<script>const wt = new WebTransport("https://example.com:4433/wt");</script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(!issues.contains(&WebTransportSecurityIssue::UnencryptedTransport));
}

#[test]
fn detects_transport_data_exfiltration_fetch() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        fetch("/track?data=leaked");
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportDataExfiltration));
}

#[test]
fn detects_transport_data_exfiltration_sendbeacon() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        navigator.sendBeacon("/track", data);
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportDataExfiltration));
}

#[test]
fn detects_transport_data_exfiltration_xhr() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        const xhr = new XMLHttpRequest();
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportDataExfiltration));
}

#[test]
fn no_exfiltration_without_transport() {
    let body = r#"<script>fetch("/track?data=leaked");</script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(!issues.contains(&WebTransportSecurityIssue::TransportDataExfiltration));
}

#[test]
fn detects_transport_cross_origin() {
    let body = r#"<script>const wt = new WebTransport("https://external.com/wt");</script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportCrossOrigin));
}

#[test]
fn detects_transport_cross_origin_net() {
    let body = r#"<script>const wt = new WebTransport("https://external.net/wt");</script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportCrossOrigin));
}

#[test]
fn detects_transport_cross_origin_org() {
    let body = r#"<script>const wt = new WebTransport("https://external.org/wt");</script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportCrossOrigin));
}

#[test]
fn no_cross_origin_with_same_origin() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com/wt");
        // same-origin policy enforced
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(!issues.contains(&WebTransportSecurityIssue::TransportCrossOrigin));
}

#[test]
fn detects_transport_in_background_visibilitychange() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        document.addEventListener("visibilitychange", () => {
            wt.createBidirectionalStream();
        });
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportInBackground));
}

#[test]
fn detects_transport_in_background_hidden() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        if (document.hidden) {
            wt.createBidirectionalStream();
        }
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportInBackground));
}

#[test]
fn no_background_issue_without_visibility_check() {
    let body = r#"<script>const wt = new WebTransport("https://example.com");</script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(!issues.contains(&WebTransportSecurityIssue::TransportInBackground));
}

#[test]
fn detects_transport_high_frequency_setinterval() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        setInterval(() => wt.createBidirectionalStream(), 100);
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportHighFrequency));
}

#[test]
fn detects_transport_high_frequency_while() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        while(true) { wt.createBidirectionalStream(); }
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportHighFrequency));
}

#[test]
fn detects_transport_high_frequency_for() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        for(let i=0; i<1000; i++) { wt.createBidirectionalStream(); }
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportHighFrequency));
}

#[test]
fn no_high_frequency_without_loop() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        wt.createBidirectionalStream();
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(!issues.contains(&WebTransportSecurityIssue::TransportHighFrequency));
}

#[test]
fn detects_transport_without_cert_check_pooling() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com", { allowPooling: false });
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportWithoutCertCheck));
}

#[test]
fn detects_transport_without_cert_check_hashes() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com", {
            serverCertificateHashes: [{ algorithm: "sha-256", value: hash }]
        });
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportWithoutCertCheck));
}

#[test]
fn detects_transport_without_cert_check_unreliable() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com", { requireUnreliable: true });
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportWithoutCertCheck));
}

#[test]
fn no_cert_check_issue_without_options() {
    let body = r#"<script>const wt = new WebTransport("https://example.com");</script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(!issues.contains(&WebTransportSecurityIssue::TransportWithoutCertCheck));
}

#[test]
fn detects_transport_bidirectional_abuse_localstorage() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        const stream = await wt.createBidirectionalStream();
        const data = localStorage.getItem("token");
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportBidirectionalAbuse));
}

#[test]
fn detects_transport_bidirectional_abuse_sessionstorage() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        const stream = await wt.createBidirectionalStream();
        const data = sessionStorage.getItem("session");
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportBidirectionalAbuse));
}

#[test]
fn detects_transport_bidirectional_abuse_cookie() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        const stream = await wt.createBidirectionalStream();
        const data = document.cookie;
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportBidirectionalAbuse));
}

#[test]
fn no_bidirectional_abuse_without_storage_access() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        const stream = await wt.createBidirectionalStream();
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(!issues.contains(&WebTransportSecurityIssue::TransportBidirectionalAbuse));
}

#[test]
fn detects_transport_datagram_flood_setinterval() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        const writer = wt.datagrams.writable.getWriter();
        setInterval(() => writer.write(data), 1);
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportDatagramFlood));
}

#[test]
fn detects_transport_datagram_flood_while() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        const writer = wt.datagrams.writable.getWriter();
        while(true) { writer.write(data); }
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportDatagramFlood));
}

#[test]
fn detects_transport_datagram_flood_for() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        const writer = wt.datagrams.writable.getWriter();
        for(let i=0; i<10000; i++) { writer.write(data); }
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportDatagramFlood));
}

#[test]
fn no_datagram_flood_without_loop() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        const writer = wt.datagrams.writable.getWriter();
        writer.write(data);
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(!issues.contains(&WebTransportSecurityIssue::TransportDatagramFlood));
}

#[test]
fn detects_transport_persistence_reconnect() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        wt.closed.then(() => reconnect());
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportPersistence));
}

#[test]
fn detects_transport_persistence_retry() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com");
        wt.closed.then(() => retry());
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportPersistence));
}

#[test]
fn detects_transport_persistence_keepalive() {
    let body = r#"<script>
        const wt = new WebTransport("https://example.com", { keepalive: true });
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportPersistence));
}

#[test]
fn no_persistence_without_reconnect_logic() {
    let body = r#"<script>const wt = new WebTransport("https://example.com");</script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(!issues.contains(&WebTransportSecurityIssue::TransportPersistence));
}

#[test]
fn detects_transport_to_internal_network_127() {
    let body = r#"<script>const wt = new WebTransport("https://127.0.0.1:4433/wt");</script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportToInternalNetwork));
}

#[test]
fn detects_transport_to_internal_network_localhost() {
    let body = r#"<script>const wt = new WebTransport("https://localhost:4433/wt");</script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportToInternalNetwork));
}

#[test]
fn detects_transport_to_internal_network_192() {
    let body = r#"<script>const wt = new WebTransport("https://192.168.1.100:4433/wt");</script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportToInternalNetwork));
}

#[test]
fn detects_transport_to_internal_network_10() {
    let body = r#"<script>const wt = new WebTransport("https://10.0.0.1:4433/wt");</script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportToInternalNetwork));
}

#[test]
fn detects_transport_to_internal_network_172() {
    let body = r#"<script>const wt = new WebTransport("https://172.16.0.1:4433/wt");</script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::TransportToInternalNetwork));
}

#[test]
fn no_internal_network_with_public_ip() {
    let body = r#"<script>const wt = new WebTransport("https://example.com:4433/wt");</script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(!issues.contains(&WebTransportSecurityIssue::TransportToInternalNetwork));
}

#[test]
fn security_severity_exfiltration_highest() {
    assert_eq!(
        web_transport_security_severity(&WebTransportSecurityIssue::TransportDataExfiltration),
        8.5
    );
}

#[test]
fn security_severity_unencrypted_high() {
    assert_eq!(
        web_transport_security_severity(&WebTransportSecurityIssue::UnencryptedTransport),
        8.0
    );
}

#[test]
fn security_severity_persistence_lowest() {
    assert_eq!(
        web_transport_security_severity(&WebTransportSecurityIssue::TransportPersistence),
        4.0
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        WebTransportSecurityIssue::UnencryptedTransport,
        WebTransportSecurityIssue::TransportDataExfiltration,
    ];
    let mut seq = 0;
    let ops = web_transport_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_to_operations_empty_list() {
    let issues = vec![];
    let mut seq = 0;
    let ops = web_transport_security_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn security_display_unencrypted_transport() {
    assert_eq!(
        WebTransportSecurityIssue::UnencryptedTransport.to_string(),
        "unencrypted_transport"
    );
}

#[test]
fn security_display_transport_data_exfiltration() {
    assert_eq!(
        WebTransportSecurityIssue::TransportDataExfiltration.to_string(),
        "transport_data_exfiltration"
    );
}

#[test]
fn security_display_transport_cross_origin() {
    assert_eq!(
        WebTransportSecurityIssue::TransportCrossOrigin.to_string(),
        "transport_cross_origin"
    );
}

#[test]
fn security_display_transport_in_background() {
    assert_eq!(
        WebTransportSecurityIssue::TransportInBackground.to_string(),
        "transport_in_background"
    );
}

#[test]
fn security_display_transport_high_frequency() {
    assert_eq!(
        WebTransportSecurityIssue::TransportHighFrequency.to_string(),
        "transport_high_frequency"
    );
}

#[test]
fn security_display_transport_without_cert_check() {
    assert_eq!(
        WebTransportSecurityIssue::TransportWithoutCertCheck.to_string(),
        "transport_without_cert_check"
    );
}

#[test]
fn security_display_transport_bidirectional_abuse() {
    assert_eq!(
        WebTransportSecurityIssue::TransportBidirectionalAbuse.to_string(),
        "transport_bidirectional_abuse"
    );
}

#[test]
fn security_display_transport_datagram_flood() {
    assert_eq!(
        WebTransportSecurityIssue::TransportDatagramFlood.to_string(),
        "transport_datagram_flood"
    );
}

#[test]
fn security_display_transport_persistence() {
    assert_eq!(
        WebTransportSecurityIssue::TransportPersistence.to_string(),
        "transport_persistence"
    );
}

#[test]
fn security_display_transport_to_internal_network() {
    assert_eq!(
        WebTransportSecurityIssue::TransportToInternalNetwork.to_string(),
        "transport_to_internal_network"
    );
}

#[test]
fn multiple_security_issues_detected() {
    let body = r#"<script>
        const wt = new WebTransport("http://192.168.1.1:4433/wt");
        setInterval(() => wt.createBidirectionalStream(), 100);
        fetch("/track?data=leaked");
        const data = localStorage.getItem("token");
    </script>"#;
    let issues = analyze_web_transport_security(body);
    assert!(issues.contains(&WebTransportSecurityIssue::UnencryptedTransport));
    assert!(issues.contains(&WebTransportSecurityIssue::TransportToInternalNetwork));
    assert!(issues.contains(&WebTransportSecurityIssue::TransportHighFrequency));
    assert!(issues.contains(&WebTransportSecurityIssue::TransportDataExfiltration));
}

#[test]
fn security_issues_clone_equality() {
    let issue1 = WebTransportSecurityIssue::UnencryptedTransport;
    let issue2 = issue1.clone();
    assert_eq!(issue1, issue2);
}

#[test]
fn security_issues_debug_format() {
    let issue = WebTransportSecurityIssue::TransportDataExfiltration;
    let debug_str = format!("{:?}", issue);
    assert!(debug_str.contains("TransportDataExfiltration"));
}
