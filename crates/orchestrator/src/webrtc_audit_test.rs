use crate::webrtc_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_webrtc("");
    assert!(issues.is_empty());
}

#[test]
fn no_webrtc_no_issues() {
    let body = "var x = document.title;";
    let issues = analyze_webrtc(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_rtc_peer_connection() {
    let body = "var pc = new RTCPeerConnection(config);";
    let issues = analyze_webrtc(body);
    assert!(issues.contains(&WebRtcIssue::RtcPeerConnectionUsed));
}

#[test]
fn detects_webkit_rtc() {
    let body = "var pc = new webkitRTCPeerConnection(config);";
    let issues = analyze_webrtc(body);
    assert!(issues.contains(&WebRtcIssue::RtcPeerConnectionUsed));
}

#[test]
fn detects_ice_candidate_leak() {
    let body = r#"
        var pc = new RTCPeerConnection(config);
        pc.onicecandidate = function(event) {
            var candidate = event.candidate.candidate;
            send(candidate);
        };
    "#;
    let issues = analyze_webrtc(body);
    assert!(issues.contains(&WebRtcIssue::IceCandidateLeak));
}

#[test]
fn no_ice_leak_without_extraction() {
    let body = r#"
        var pc = new RTCPeerConnection(config);
        pc.onicecandidate = function(event) {
            console.log("got candidate");
        };
    "#;
    let issues = analyze_webrtc(body);
    assert!(!issues.contains(&WebRtcIssue::IceCandidateLeak));
}

#[test]
fn detects_stun_server() {
    let body = r#"
        var pc = new RTCPeerConnection({
            iceServers: [{urls: "stun:stun.example.com:3478"}]
        });
    "#;
    let issues = analyze_webrtc(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        WebRtcIssue::StunServerExposed { .. }
    )));
}

#[test]
fn detects_turn_server() {
    let body = r#"
        var pc = new RTCPeerConnection({
            iceServers: [{urls: "turn:turn.example.com:3478", username: "user", credential: "pass"}]
        });
    "#;
    let issues = analyze_webrtc(body);
    assert!(issues.iter().any(|i| matches!(
        i,
        WebRtcIssue::TurnServerExposed { .. }
    )));
}

#[test]
fn detects_data_channel() {
    let body = r#"
        var pc = new RTCPeerConnection(config);
        var dc = pc.createDataChannel("myChannel");
    "#;
    let issues = analyze_webrtc(body);
    assert!(issues.contains(&WebRtcIssue::DataChannelUsed));
}

#[test]
fn detects_no_ice_filtering() {
    let body = "var pc = new RTCPeerConnection({});";
    let issues = analyze_webrtc(body);
    assert!(issues.contains(&WebRtcIssue::NoIceCandidateFiltering));
}

#[test]
fn ice_transport_policy_no_filtering_issue() {
    let body = r#"
        var pc = new RTCPeerConnection({iceTransportPolicy: "relay"});
    "#;
    let issues = analyze_webrtc(body);
    assert!(!issues.contains(&WebRtcIssue::NoIceCandidateFiltering));
}

#[test]
fn detects_get_user_media() {
    let body = "navigator.mediaDevices.getUserMedia({video: true});";
    let issues = analyze_webrtc(body);
    assert!(issues.contains(&WebRtcIssue::MediaDevicesAccess));
}

#[test]
fn detects_get_display_media() {
    let body = "navigator.mediaDevices.getDisplayMedia({video: true});";
    let issues = analyze_webrtc(body);
    assert!(issues.contains(&WebRtcIssue::MediaDevicesAccess));
}

#[test]
fn detects_enumerate_devices() {
    let body = "navigator.mediaDevices.enumerateDevices().then(devices => {});";
    let issues = analyze_webrtc(body);
    assert!(issues.contains(&WebRtcIssue::MediaDevicesAccess));
}

#[test]
fn severity_ice_leak_highest() {
    assert_eq!(webrtc_severity(&WebRtcIssue::IceCandidateLeak), 7.0);
}

#[test]
fn severity_rtc_connection_lowest() {
    assert_eq!(webrtc_severity(&WebRtcIssue::RtcPeerConnectionUsed), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        WebRtcIssue::IceCandidateLeak,
        WebRtcIssue::RtcPeerConnectionUsed,
    ];
    let mut seq = 0;
    let ops = webrtc_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        WebRtcIssue::RtcPeerConnectionUsed.to_string(),
        "rtc_peer_connection"
    );
    assert_eq!(WebRtcIssue::IceCandidateLeak.to_string(), "ice_candidate_leak");
    assert_eq!(WebRtcIssue::DataChannelUsed.to_string(), "data_channel");
    assert_eq!(
        WebRtcIssue::NoIceCandidateFiltering.to_string(),
        "no_ice_filtering"
    );
    assert_eq!(WebRtcIssue::MediaDevicesAccess.to_string(), "media_devices_access");
}

#[test]
fn display_stun_server() {
    let issue = WebRtcIssue::StunServerExposed {
        server: "stun:stun.example.com".to_string(),
    };
    assert_eq!(issue.to_string(), "stun_exposed:stun:stun.example.com");
}

#[test]
fn display_turn_server() {
    let issue = WebRtcIssue::TurnServerExposed {
        server: "turn:turn.example.com".to_string(),
    };
    assert_eq!(issue.to_string(), "turn_exposed:turn:turn.example.com");
}
