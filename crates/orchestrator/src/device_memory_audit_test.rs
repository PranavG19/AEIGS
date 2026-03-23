use crate::device_memory_audit::*;

#[test]
fn no_device_memory_no_issues() {
    assert!(analyze_device_memory("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_navigator() {
    let body = r#"<script>const mem = navigator.deviceMemory;</script>"#;
    let issues = analyze_device_memory(body);
    assert!(issues.contains(&DeviceMemoryIssue::ApiDetected));
}

#[test]
fn detects_client_hint_header() {
    let body = r#"<meta http-equiv="Accept-CH" content="Device-Memory">"#;
    let issues = analyze_device_memory(body);
    assert!(issues.contains(&DeviceMemoryIssue::ClientHintHeader));
}

#[test]
fn detects_fingerprinting_vector() {
    let body = r#"<script>const mem = navigator.deviceMemory;</script>"#;
    let issues = analyze_device_memory(body);
    assert!(issues.contains(&DeviceMemoryIssue::FingerprintingVector));
}

#[test]
fn detects_data_exfiltration() {
    let body = r#"<script>
        const mem = navigator.deviceMemory;
        fetch("/track", {body: JSON.stringify({memory: mem})});
    </script>"#;
    let issues = analyze_device_memory(body);
    assert!(issues.contains(&DeviceMemoryIssue::DataExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>const mem = navigator.deviceMemory; console.log(mem);</script>"#;
    let issues = analyze_device_memory(body);
    assert!(!issues.contains(&DeviceMemoryIssue::DataExfiltration));
}

#[test]
fn detects_combined_fingerprint() {
    let body = r#"<script>
        const fp = {
            memory: navigator.deviceMemory,
            cores: navigator.hardwareConcurrency
        };
    </script>"#;
    let issues = analyze_device_memory(body);
    assert!(issues.contains(&DeviceMemoryIssue::CombinedFingerprint));
}

#[test]
fn no_combined_without_other_apis() {
    let body = r#"<script>const mem = navigator.deviceMemory;</script>"#;
    let issues = analyze_device_memory(body);
    assert!(!issues.contains(&DeviceMemoryIssue::CombinedFingerprint));
}

#[test]
fn detects_lowercase_header() {
    let body = r#"<meta http-equiv="Accept-CH" content="device-memory">"#;
    let issues = analyze_device_memory(body);
    assert!(issues.contains(&DeviceMemoryIssue::ClientHintHeader));
}

#[test]
fn severity_combined_highest() {
    assert_eq!(
        device_memory_severity(&DeviceMemoryIssue::CombinedFingerprint),
        7.0
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(device_memory_severity(&DeviceMemoryIssue::ApiDetected), 2.5);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        DeviceMemoryIssue::ApiDetected,
        DeviceMemoryIssue::FingerprintingVector,
    ];
    let mut seq = 0;
    let ops = device_memory_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(DeviceMemoryIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        DeviceMemoryIssue::FingerprintingVector.to_string(),
        "fingerprinting_vector"
    );
    assert_eq!(
        DeviceMemoryIssue::DataExfiltration.to_string(),
        "data_exfiltration"
    );
    assert_eq!(
        DeviceMemoryIssue::CombinedFingerprint.to_string(),
        "combined_fingerprint"
    );
    assert_eq!(
        DeviceMemoryIssue::ClientHintHeader.to_string(),
        "client_hint_header"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_device_memory("").is_empty());
}
