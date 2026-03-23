use crate::webrtc_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_webrtc("");
    assert!(issues.is_empty());
}

#[test]
fn no_webrtc_indicators_no_issues() {
    let body = "var x = document.title; console.log('hello');";
    let issues = analyze_webrtc(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_api_via_rtc_peer_connection() {
    let body = "var pc = new RTCPeerConnection(config);";
    let issues = analyze_webrtc(body);
    assert!(issues.contains(&WebRtcIssue::ApiDetected));
}

#[test]
fn detects_api_via_webkit_rtc_peer_connection() {
    let body = "var pc = new webkitRTCPeerConnection(config);";
    let issues = analyze_webrtc(body);
    assert!(issues.contains(&WebRtcIssue::ApiDetected));
}

#[test]
fn detects_api_via_moz_rtc_peer_connection() {
    let body = "var pc = new mozRTCPeerConnection(config);";
    let issues = analyze_webrtc(body);
    assert!(issues.contains(&WebRtcIssue::ApiDetected));
}

#[test]
fn detects_api_via_get_user_media() {
    let body = "navigator.mediaDevices.getUserMedia({video: true});";
    let issues = analyze_webrtc(body);
    assert!(issues.contains(&WebRtcIssue::ApiDetected));
}

#[test]
fn detects_api_via_create_offer() {
    let body = "pc.createOffer().then(offer => {});";
    let issues = analyze_webrtc(body);
    assert!(issues.contains(&WebRtcIssue::ApiDetected));
}

#[test]
fn detects_api_via_create_answer() {
    let body = "pc.createAnswer().then(answer => {});";
    let issues = analyze_webrtc(body);
    assert!(issues.contains(&WebRtcIssue::ApiDetected));
}

#[test]
fn detects_ip_leak_via_stun() {
    let body = r#"
        var pc = new RTCPeerConnection(config);
        pc.onicecandidate = function(event) {
            if (event.candidate) {
                var ip = event.candidate.candidate;
                sendToServer(ip);
            }
        };
    "#;
    let issues = analyze_webrtc(body);
    assert!(issues.contains(&WebRtcIssue::IpLeakViaStun));
}

#[test]
fn no_ip_leak_with_relay_policy() {
    let body = r#"
        var pc = new RTCPeerConnection({
            iceTransportPolicy: "relay"
        });
        pc.onicecandidate = function(event) {
            var ip = event.candidate.candidate;
        };
    "#;
    let issues = analyze_webrtc(body);
    assert!(!issues.contains(&WebRtcIssue::IpLeakViaStun));
}

#[test]
fn detects_missing_dtls_srtp() {
    let body = "var pc = new RTCPeerConnection({});";
    let issues = analyze_webrtc(body);
    assert!(issues.contains(&WebRtcIssue::MissingDtlsSrtp));
}

#[test]
fn missing_dtls_when_absent() {
    let body = r#"
        var pc = new RTCPeerConnection({});
    "#;
    let issues = analyze_webrtc(body);
    assert!(issues.contains(&WebRtcIssue::MissingDtlsSrtp));
}

#[test]
fn no_missing_dtls_with_indicator() {
    let body = r#"
        var pc = new RTCPeerConnection({});
        console.log("DTLS enabled");
    "#;
    let issues = analyze_webrtc(body);
    assert!(!issues.contains(&WebRtcIssue::MissingDtlsSrtp));
}

#[test]
fn detects_unrestricted_data_channel() {
    let body = r#"
        var pc = new RTCPeerConnection(config);
        var dc = pc.createDataChannel("myChannel");
    "#;
    let issues = analyze_webrtc(body);
    assert!(issues.contains(&WebRtcIssue::UnrestrictedDataChannel));
}

#[test]
fn no_unrestricted_with_max_packet_life_time() {
    let body = r#"
        var pc = new RTCPeerConnection(config);
        var dc = pc.createDataChannel("myChannel", {maxPacketLifeTime: 1000});
    "#;
    let issues = analyze_webrtc(body);
    assert!(!issues.contains(&WebRtcIssue::UnrestrictedDataChannel));
}

#[test]
fn no_unrestricted_with_max_retransmits() {
    let body = r#"
        var pc = new RTCPeerConnection(config);
        var dc = pc.createDataChannel("myChannel", {maxRetransmits: 5});
    "#;
    let issues = analyze_webrtc(body);
    assert!(!issues.contains(&WebRtcIssue::UnrestrictedDataChannel));
}

#[test]
fn detects_third_party_stun_server() {
    let body = r#"
        var pc = new RTCPeerConnection({
            iceServers: [{urls: "stun:stun.example.com:3478"}]
        });
    "#;
    let issues = analyze_webrtc(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, WebRtcIssue::ThirdPartyIceServer { .. }))
    );
}

#[test]
fn detects_third_party_turn_server() {
    let body = r#"
        var pc = new RTCPeerConnection({
            iceServers: [{
                urls: "turn:turn.example.com:3478",
                username: "user",
                credential: "pass"
            }]
        });
    "#;
    let issues = analyze_webrtc(body);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, WebRtcIssue::ThirdPartyIceServer { .. }))
    );
}

#[test]
fn ignores_localhost_ice_servers() {
    let body = r#"
        var pc = new RTCPeerConnection({
            iceServers: [{urls: "stun:localhost:3478"}]
        });
    "#;
    let issues = analyze_webrtc(body);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, WebRtcIssue::ThirdPartyIceServer { .. }))
    );
}

#[test]
fn detects_screen_share_without_consent() {
    let body = "navigator.mediaDevices.getDisplayMedia({video: true});";
    let issues = analyze_webrtc(body);
    assert!(issues.contains(&WebRtcIssue::ScreenShareWithoutConsent));
}

#[test]
fn no_screen_share_issue_with_consent_indicator() {
    let body = r#"
        navigator.mediaDevices.getDisplayMedia({video: true});
        showRecordingIndicator();
        function showRecordingIndicator() {
            document.querySelector('.recording-indicator').style.display = 'block';
        }
    "#;
    let issues = analyze_webrtc(body);
    assert!(!issues.contains(&WebRtcIssue::ScreenShareWithoutConsent));
}

#[test]
fn detects_missing_ice_candidate_filtering() {
    let body = "var pc = new RTCPeerConnection({});";
    let issues = analyze_webrtc(body);
    assert!(issues.contains(&WebRtcIssue::MissingIceCandidateFiltering));
}

#[test]
fn no_missing_filtering_with_relay_policy() {
    let body = r#"
        var pc = new RTCPeerConnection({
            iceTransportPolicy: "relay"
        });
    "#;
    let issues = analyze_webrtc(body);
    assert!(!issues.contains(&WebRtcIssue::MissingIceCandidateFiltering));
}

#[test]
fn no_missing_filtering_with_pool_size() {
    let body = r#"
        var pc = new RTCPeerConnection({
            iceCandidatePoolSize: 10
        });
    "#;
    let issues = analyze_webrtc(body);
    assert!(!issues.contains(&WebRtcIssue::MissingIceCandidateFiltering));
}

#[test]
fn severity_ip_leak_highest() {
    assert_eq!(webrtc_severity(&WebRtcIssue::IpLeakViaStun), 7.5);
}

#[test]
fn severity_missing_dtls() {
    assert_eq!(webrtc_severity(&WebRtcIssue::MissingDtlsSrtp), 7.0);
}

#[test]
fn severity_api_detected_lowest() {
    assert_eq!(webrtc_severity(&WebRtcIssue::ApiDetected), 2.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![WebRtcIssue::IpLeakViaStun, WebRtcIssue::ApiDetected];
    let mut seq = 0u64;
    let ops = webrtc_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn to_operations_increments_sequence() {
    let issues = vec![
        WebRtcIssue::MissingDtlsSrtp,
        WebRtcIssue::UnrestrictedDataChannel,
        WebRtcIssue::MissingIceCandidateFiltering,
    ];
    let mut seq = 10u64;
    let ops = webrtc_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 13);
}

#[test]
fn display_api_detected() {
    assert_eq!(WebRtcIssue::ApiDetected.to_string(), "api_detected");
}

#[test]
fn display_ip_leak() {
    assert_eq!(WebRtcIssue::IpLeakViaStun.to_string(), "ip_leak_via_stun");
}

#[test]
fn display_missing_dtls() {
    assert_eq!(
        WebRtcIssue::MissingDtlsSrtp.to_string(),
        "missing_dtls_srtp"
    );
}

#[test]
fn display_unrestricted_data_channel() {
    assert_eq!(
        WebRtcIssue::UnrestrictedDataChannel.to_string(),
        "unrestricted_data_channel"
    );
}

#[test]
fn display_third_party_ice_server() {
    let issue = WebRtcIssue::ThirdPartyIceServer {
        server: "stun:stun.example.com".to_string(),
    };
    assert_eq!(
        issue.to_string(),
        "third_party_ice_server:stun:stun.example.com"
    );
}

#[test]
fn display_screen_share_without_consent() {
    assert_eq!(
        WebRtcIssue::ScreenShareWithoutConsent.to_string(),
        "screen_share_without_consent"
    );
}

#[test]
fn display_missing_ice_filtering() {
    assert_eq!(
        WebRtcIssue::MissingIceCandidateFiltering.to_string(),
        "missing_ice_candidate_filtering"
    );
}
