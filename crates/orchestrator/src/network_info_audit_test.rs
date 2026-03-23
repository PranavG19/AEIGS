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
    assert_eq!(
        network_info_severity(&NetworkInfoIssue::CombinedFingerprint),
        7.0
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(network_info_severity(&NetworkInfoIssue::ApiDetected), 2.5);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        NetworkInfoIssue::ApiDetected,
        NetworkInfoIssue::FingerprintingVector,
    ];
    let mut seq = 0;
    let ops = network_info_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(NetworkInfoIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        NetworkInfoIssue::FingerprintingVector.to_string(),
        "fingerprinting_vector"
    );
    assert_eq!(
        NetworkInfoIssue::DataExfiltration.to_string(),
        "data_exfiltration"
    );
    assert_eq!(
        NetworkInfoIssue::ConnectionMonitoring.to_string(),
        "connection_monitoring"
    );
    assert_eq!(
        NetworkInfoIssue::CombinedFingerprint.to_string(),
        "combined_fingerprint"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_network_info("").is_empty());
}

#[test]
pub fn security_no_network_keywords_no_issues() {
    let body = "<html><body>hello world</body></html>";
    assert!(analyze_network_security_issues(body).is_empty());
}

#[test]
pub fn security_empty_body_no_issues() {
    assert!(analyze_network_security_issues("").is_empty());
}

#[test]
pub fn detects_network_exfiltration() {
    let body = r#"<script>
        const conn = navigator.connection;
        fetch("/api/track", {
            method: "POST",
            body: JSON.stringify({type: conn.effectiveType})
        });
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(issues.contains(&NetworkInfoSecurityIssue::NetworkExfiltration));
}

#[test]
pub fn no_exfiltration_without_fetch() {
    let body = r#"<script>
        const conn = navigator.connection;
        console.log(conn.effectiveType);
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(!issues.contains(&NetworkInfoSecurityIssue::NetworkExfiltration));
}

#[test]
pub fn detects_network_fingerprinting() {
    let body = r#"<script>
        const fp = {
            type: navigator.connection.effectiveType,
            bandwidth: navigator.connection.downlink,
            latency: navigator.connection.rtt
        };
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(issues.contains(&NetworkInfoSecurityIssue::NetworkFingerprinting));
}

#[test]
pub fn no_fingerprinting_without_all_three() {
    let body = r#"<script>
        const type = navigator.connection.effectiveType;
        const dl = navigator.connection.downlink;
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(!issues.contains(&NetworkInfoSecurityIssue::NetworkFingerprinting));
}

#[test]
pub fn detects_network_change_tracking() {
    let body = r#"<script>
        navigator.connection.addEventListener("change", () => {
            logNetworkChange();
        });
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(issues.contains(&NetworkInfoSecurityIssue::NetworkChangeTracking));
}

#[test]
pub fn detects_network_change_tracking_onchange() {
    let body = r#"<script>
        navigator.connection.onchange = function() {
            trackUser();
        };
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(issues.contains(&NetworkInfoSecurityIssue::NetworkChangeTracking));
}

#[test]
pub fn no_change_tracking_without_listener() {
    let body = r#"<script>
        const conn = navigator.connection;
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(!issues.contains(&NetworkInfoSecurityIssue::NetworkChangeTracking));
}

#[test]
pub fn detects_network_cross_origin() {
    let body = r#"<script>
        const conn = navigator.connection;
        window.parent.postMessage({
            networkType: conn.effectiveType
        }, "*");
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(issues.contains(&NetworkInfoSecurityIssue::NetworkCrossOrigin));
}

#[test]
pub fn no_cross_origin_without_postmessage() {
    let body = r#"<script>
        const conn = navigator.connection;
        const type = conn.effectiveType;
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(!issues.contains(&NetworkInfoSecurityIssue::NetworkCrossOrigin));
}

#[test]
pub fn detects_network_persistence() {
    let body = r#"<script>
        const conn = navigator.connection;
        localStorage.setItem("networkType", conn.effectiveType);
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(issues.contains(&NetworkInfoSecurityIssue::NetworkPersistence));
}

#[test]
pub fn no_persistence_without_localstorage() {
    let body = r#"<script>
        const conn = navigator.connection;
        const type = conn.effectiveType;
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(!issues.contains(&NetworkInfoSecurityIssue::NetworkPersistence));
}

#[test]
pub fn detects_network_in_background() {
    let body = r#"<script>
        document.addEventListener("visibilitychange", () => {
            if (document.hidden) {
                const conn = navigator.connection;
                trackInBackground(conn);
            }
        });
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(issues.contains(&NetworkInfoSecurityIssue::NetworkInBackground));
}

#[test]
pub fn no_background_without_visibility() {
    let body = r#"<script>
        const conn = navigator.connection;
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(!issues.contains(&NetworkInfoSecurityIssue::NetworkInBackground));
}

#[test]
pub fn detects_network_bandwidth_probing() {
    let body = r#"<script>
        const start = performance.now();
        const dl = navigator.connection.downlink;
        const elapsed = performance.now() - start;
        fingerprint(dl, elapsed);
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(issues.contains(&NetworkInfoSecurityIssue::NetworkBandwidthProbing));
}

#[test]
pub fn detects_bandwidth_probing_with_date() {
    let body = r#"<script>
        const t = Date.now();
        const bw = navigator.connection.downlink;
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(issues.contains(&NetworkInfoSecurityIssue::NetworkBandwidthProbing));
}

#[test]
pub fn no_bandwidth_probing_without_timing() {
    let body = r#"<script>
        const dl = navigator.connection.downlink;
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(!issues.contains(&NetworkInfoSecurityIssue::NetworkBandwidthProbing));
}

#[test]
pub fn detects_network_save_data_bypass() {
    let body = r#"<script>
        if (navigator.connection.saveData === false) {
            loadHighResImages();
        }
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(issues.contains(&NetworkInfoSecurityIssue::NetworkSaveDataBypass));
}

#[test]
pub fn no_save_data_bypass_without_false() {
    let body = r#"<script>
        if (navigator.connection.saveData) {
            loadLowResImages();
        }
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(!issues.contains(&NetworkInfoSecurityIssue::NetworkSaveDataBypass));
}

#[test]
pub fn detects_network_type_disclosure() {
    let body = r#"<script>
        const type = navigator.connection.effectiveType;
        fetch("/analytics", {
            method: "POST",
            body: JSON.stringify({type})
        });
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(issues.contains(&NetworkInfoSecurityIssue::NetworkTypeDisclosure));
}

#[test]
pub fn detects_type_disclosure_with_sendbeacon() {
    let body = r#"<script>
        const type = navigator.connection.effectiveType;
        navigator.sendBeacon("/track", JSON.stringify({type}));
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(issues.contains(&NetworkInfoSecurityIssue::NetworkTypeDisclosure));
}

#[test]
pub fn no_type_disclosure_without_send() {
    let body = r#"<script>
        const type = navigator.connection.effectiveType;
        console.log(type);
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(!issues.contains(&NetworkInfoSecurityIssue::NetworkTypeDisclosure));
}

#[test]
pub fn detects_network_latency_mapping() {
    let body = r#"<script>
        const rtt = navigator.connection.rtt;
        navigator.geolocation.getCurrentPosition((pos) => {
            correlate(rtt, pos.coords.latitude, pos.coords.longitude);
        });
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(issues.contains(&NetworkInfoSecurityIssue::NetworkLatencyMapping));
}

#[test]
pub fn detects_latency_mapping_with_coords() {
    let body = r#"<script>
        const latency = navigator.connection.rtt;
        const lat = position.coords.latitude;
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(issues.contains(&NetworkInfoSecurityIssue::NetworkLatencyMapping));
}

#[test]
pub fn no_latency_mapping_without_geolocation() {
    let body = r#"<script>
        const rtt = navigator.connection.rtt;
        console.log(rtt);
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(!issues.contains(&NetworkInfoSecurityIssue::NetworkLatencyMapping));
}

#[test]
pub fn security_display_variants() {
    assert_eq!(
        NetworkInfoSecurityIssue::NetworkExfiltration.to_string(),
        "network_exfiltration"
    );
    assert_eq!(
        NetworkInfoSecurityIssue::NetworkFingerprinting.to_string(),
        "network_fingerprinting"
    );
    assert_eq!(
        NetworkInfoSecurityIssue::NetworkChangeTracking.to_string(),
        "network_change_tracking"
    );
    assert_eq!(
        NetworkInfoSecurityIssue::NetworkCrossOrigin.to_string(),
        "network_cross_origin"
    );
    assert_eq!(
        NetworkInfoSecurityIssue::NetworkPersistence.to_string(),
        "network_persistence"
    );
    assert_eq!(
        NetworkInfoSecurityIssue::NetworkInBackground.to_string(),
        "network_in_background"
    );
    assert_eq!(
        NetworkInfoSecurityIssue::NetworkBandwidthProbing.to_string(),
        "network_bandwidth_probing"
    );
    assert_eq!(
        NetworkInfoSecurityIssue::NetworkSaveDataBypass.to_string(),
        "network_save_data_bypass"
    );
    assert_eq!(
        NetworkInfoSecurityIssue::NetworkTypeDisclosure.to_string(),
        "network_type_disclosure"
    );
    assert_eq!(
        NetworkInfoSecurityIssue::NetworkLatencyMapping.to_string(),
        "network_latency_mapping"
    );
}

#[test]
pub fn security_severity_latency_mapping_highest() {
    assert_eq!(
        network_security_severity(&NetworkInfoSecurityIssue::NetworkLatencyMapping),
        9.0
    );
}

#[test]
pub fn security_severity_save_data_bypass_lowest() {
    assert_eq!(
        network_security_severity(&NetworkInfoSecurityIssue::NetworkSaveDataBypass),
        3.0
    );
}

#[test]
pub fn security_severity_exfiltration_high() {
    assert_eq!(
        network_security_severity(&NetworkInfoSecurityIssue::NetworkExfiltration),
        8.5
    );
}

#[test]
pub fn security_to_operations_creates_entries() {
    let issues = vec![
        NetworkInfoSecurityIssue::NetworkExfiltration,
        NetworkInfoSecurityIssue::NetworkFingerprinting,
        NetworkInfoSecurityIssue::NetworkLatencyMapping,
    ];
    let mut seq = 0;
    let ops = network_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
pub fn security_to_operations_empty_vector() {
    let issues = vec![];
    let mut seq = 0;
    let ops = network_security_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
pub fn security_multiple_issues_detected() {
    let body = r#"<script>
        const conn = navigator.connection;
        const fp = {
            type: conn.effectiveType,
            dl: conn.downlink,
            rtt: conn.rtt
        };
        fetch("/track", {body: JSON.stringify(fp)});
        localStorage.setItem("network", JSON.stringify(fp));
        conn.addEventListener("change", () => {
            trackChange();
        });
    </script>"#;
    let issues = analyze_network_security_issues(body);
    assert!(issues.contains(&NetworkInfoSecurityIssue::NetworkExfiltration));
    assert!(issues.contains(&NetworkInfoSecurityIssue::NetworkFingerprinting));
    assert!(issues.contains(&NetworkInfoSecurityIssue::NetworkChangeTracking));
    assert!(issues.contains(&NetworkInfoSecurityIssue::NetworkPersistence));
    assert!(issues.contains(&NetworkInfoSecurityIssue::NetworkTypeDisclosure));
}

#[test]
pub fn security_all_severity_values_valid() {
    let all_issues = vec![
        NetworkInfoSecurityIssue::NetworkExfiltration,
        NetworkInfoSecurityIssue::NetworkFingerprinting,
        NetworkInfoSecurityIssue::NetworkChangeTracking,
        NetworkInfoSecurityIssue::NetworkCrossOrigin,
        NetworkInfoSecurityIssue::NetworkPersistence,
        NetworkInfoSecurityIssue::NetworkInBackground,
        NetworkInfoSecurityIssue::NetworkBandwidthProbing,
        NetworkInfoSecurityIssue::NetworkSaveDataBypass,
        NetworkInfoSecurityIssue::NetworkTypeDisclosure,
        NetworkInfoSecurityIssue::NetworkLatencyMapping,
    ];
    for issue in &all_issues {
        let severity = network_security_severity(issue);
        assert!(severity >= 3.0 && severity <= 9.0);
    }
}
