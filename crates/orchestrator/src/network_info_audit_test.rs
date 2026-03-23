use crate::network_info_audit::*;

#[test]
fn no_network_info_no_issues() {
    assert!(analyze_network_info("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_navigator_connection() {
    let body = r#"<script>const conn = navigator.connection;</script>"#;
    let issues = analyze_network_info(body);
    assert!(issues.contains(&NetworkInfoIssue::ApiDetected));
}

#[test]
fn detects_api_class_name() {
    let body = r#"<script>if (window.NetworkInformation) {}</script>"#;
    let issues = analyze_network_info(body);
    assert!(issues.contains(&NetworkInfoIssue::ApiDetected));
}

#[test]
fn detects_fingerprinting_effective_type() {
    let body = r#"<script>const type = navigator.connection.effectiveType;</script>"#;
    let issues = analyze_network_info(body);
    assert!(issues.contains(&NetworkInfoIssue::FingerprintingVector));
}

#[test]
fn detects_fingerprinting_downlink() {
    let body = r#"<script>const dl = navigator.connection.downlink;</script>"#;
    let issues = analyze_network_info(body);
    assert!(issues.contains(&NetworkInfoIssue::FingerprintingVector));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        const conn = navigator.connection;
        fetch("/track", {body: JSON.stringify({type: conn.effectiveType})});
    </script>"#;
    let issues = analyze_network_info(body);
    assert!(issues.contains(&NetworkInfoIssue::DataExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>const conn = navigator.connection; console.log(conn);</script>"#;
    let issues = analyze_network_info(body);
    assert!(!issues.contains(&NetworkInfoIssue::DataExfiltration));
}

#[test]
fn detects_connection_monitoring() {
    let body = r#"<script>
        navigator.connection.addEventListener("change", () => { update(); });
    </script>"#;
    let issues = analyze_network_info(body);
    assert!(issues.contains(&NetworkInfoIssue::ConnectionMonitoring));
}

#[test]
fn detects_onchange_monitoring() {
    let body = r#"<script>navigator.connection.onchange = handler;</script>"#;
    let issues = analyze_network_info(body);
    assert!(issues.contains(&NetworkInfoIssue::ConnectionMonitoring));
}

#[test]
fn detects_combined_fingerprint() {
    let body = r#"<script>
        const fp = {
            connection: navigator.connection.effectiveType,
            cores: navigator.hardwareConcurrency
        };
    </script>"#;
    let issues = analyze_network_info(body);
    assert!(issues.contains(&NetworkInfoIssue::CombinedFingerprint));
}

#[test]
fn no_combined_without_other_apis() {
    let body = r#"<script>const conn = navigator.connection;</script>"#;
    let issues = analyze_network_info(body);
    assert!(!issues.contains(&NetworkInfoIssue::CombinedFingerprint));
}

#[test]
fn severity_combined_highest() {
    assert_eq!(network_info_severity(&NetworkInfoIssue::CombinedFingerprint), 7.0);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(network_info_severity(&NetworkInfoIssue::ApiDetected), 2.5);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![NetworkInfoIssue::ApiDetected, NetworkInfoIssue::FingerprintingVector];
    let mut seq = 0;
    let ops = network_info_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(NetworkInfoIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(NetworkInfoIssue::FingerprintingVector.to_string(), "fingerprinting_vector");
    assert_eq!(NetworkInfoIssue::DataExfiltration.to_string(), "data_exfiltration");
    assert_eq!(NetworkInfoIssue::ConnectionMonitoring.to_string(), "connection_monitoring");
    assert_eq!(NetworkInfoIssue::CombinedFingerprint.to_string(), "combined_fingerprint");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_network_info("").is_empty());
}
