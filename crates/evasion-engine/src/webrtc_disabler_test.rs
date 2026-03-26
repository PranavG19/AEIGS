use super::webrtc_disabler::*;

#[test]
fn stub_replacement_generates_js() {
    let disabler = WebRtcDisabler::with_defaults();
    let override_js = disabler.generate_js_override();
    assert!(!override_js.script.is_empty());
    assert!(override_js.script.contains("RTCPeerConnection"));
    assert_eq!(override_js.strategy, BlockingStrategy::StubReplacement);
}

#[test]
fn stub_replacement_blocks_expected_apis() {
    let disabler = WebRtcDisabler::with_defaults();
    let override_js = disabler.generate_js_override();
    assert!(override_js
        .apis_blocked
        .contains(&"RTCPeerConnection".to_string()));
    assert!(override_js
        .apis_blocked
        .contains(&"webkitRTCPeerConnection".to_string()));
}

#[test]
fn stub_replacement_blocks_media_devices_by_default() {
    let disabler = WebRtcDisabler::with_defaults();
    let override_js = disabler.generate_js_override();
    assert!(override_js.script.contains("getUserMedia"));
    assert!(override_js.script.contains("enumerateDevices"));
}

#[test]
fn ice_candidate_filter_strategy() {
    let config = WebRtcDisablerConfig {
        strategy: BlockingStrategy::IceCandidateFilter,
        ..Default::default()
    };
    let disabler = WebRtcDisabler::new(config);
    let override_js = disabler.generate_js_override();
    assert!(override_js.script.contains("onicecandidate"));
    assert_eq!(override_js.strategy, BlockingStrategy::IceCandidateFilter);
}

#[test]
fn api_removal_deletes_rtc_objects() {
    let config = WebRtcDisablerConfig {
        strategy: BlockingStrategy::ApiRemoval,
        ..Default::default()
    };
    let disabler = WebRtcDisabler::new(config);
    let override_js = disabler.generate_js_override();
    assert!(override_js
        .script
        .contains("delete window.RTCPeerConnection"));
    assert!(override_js
        .script
        .contains("delete window.RTCSessionDescription"));
}

#[test]
fn csp_block_generates_no_js() {
    let config = WebRtcDisablerConfig {
        strategy: BlockingStrategy::CspBlock,
        ..Default::default()
    };
    let disabler = WebRtcDisabler::new(config);
    let override_js = disabler.generate_js_override();
    assert!(override_js.script.is_empty());
}

#[test]
fn csp_directives_block_media_by_default() {
    let disabler = WebRtcDisabler::with_defaults();
    let csp = disabler.generate_csp_directives();
    assert_eq!(csp.media_src, "'none'");
}

#[test]
fn csp_allows_specified_stun_servers() {
    let config = WebRtcDisablerConfig {
        allowed_stun_servers: vec!["stun:stun.example.com".to_string()],
        ..Default::default()
    };
    let disabler = WebRtcDisabler::new(config);
    let csp = disabler.generate_csp_directives();
    assert!(csp.connect_src.contains("stun:stun.example.com"));
}

#[test]
fn scan_detects_private_ip_leak() {
    let disabler = WebRtcDisabler::with_defaults();
    let candidates = vec!["candidate:1 1 udp 2122260223 192.168.1.100 54321 typ host".to_string()];
    let result = disabler.scan_for_leaks(&candidates);
    assert!(!result.is_safe);
    assert_eq!(result.leaks_detected.len(), 1);
    assert_eq!(result.leaks_detected[0].ip_type, IpType::PrivateIpv4);
}

#[test]
fn scan_detects_public_ip_leak() {
    let disabler = WebRtcDisabler::with_defaults();
    let candidates = vec!["candidate:2 1 udp 1686052607 203.0.113.5 12345 typ srflx".to_string()];
    let result = disabler.scan_for_leaks(&candidates);
    assert!(!result.is_safe);
    assert_eq!(result.leaks_detected[0].ip_type, IpType::PublicIpv4);
}

#[test]
fn scan_detects_ipv6_leak() {
    let disabler = WebRtcDisabler::with_defaults();
    let candidates = vec!["candidate:3 1 udp 2122194687 2001:db8::1 54321 typ host".to_string()];
    let result = disabler.scan_for_leaks(&candidates);
    assert!(!result.is_safe);
    assert_eq!(result.leaks_detected[0].ip_type, IpType::PublicIpv6);
}

#[test]
fn scan_empty_candidates_is_safe() {
    let disabler = WebRtcDisabler::with_defaults();
    let result = disabler.scan_for_leaks(&[]);
    assert!(result.is_safe);
    assert_eq!(result.total_candidates_checked, 0);
}

#[test]
fn verify_zero_leak_passes_on_empty() {
    let disabler = WebRtcDisabler::with_defaults();
    assert!(disabler.verify_zero_leak(&[]));
}

#[test]
fn verify_zero_leak_fails_on_private_ip() {
    let disabler = WebRtcDisabler::with_defaults();
    let candidates = vec!["candidate:1 1 udp 2122260223 10.0.0.1 54321 typ host".to_string()];
    assert!(!disabler.verify_zero_leak(&candidates));
}

#[test]
fn blocked_vectors_includes_stun_and_turn() {
    let disabler = WebRtcDisabler::with_defaults();
    let vectors = disabler.blocked_vectors();
    assert!(vectors.contains(&LeakVector::StunBinding));
    assert!(vectors.contains(&LeakVector::TurnAllocation));
    assert!(vectors.contains(&LeakVector::IceCandidateGathering));
}

#[test]
fn blocked_vectors_includes_media_when_enabled() {
    let disabler = WebRtcDisabler::with_defaults();
    let vectors = disabler.blocked_vectors();
    assert!(vectors.contains(&LeakVector::GetUserMedia));
    assert!(vectors.contains(&LeakVector::MediaDevicesEnumerate));
}

#[test]
fn blocked_vectors_excludes_media_when_disabled() {
    let config = WebRtcDisablerConfig {
        block_media_devices: false,
        ..Default::default()
    };
    let disabler = WebRtcDisabler::new(config);
    let vectors = disabler.blocked_vectors();
    assert!(!vectors.contains(&LeakVector::GetUserMedia));
}

#[test]
fn blocking_strategy_display() {
    assert_eq!(
        format!("{}", BlockingStrategy::StubReplacement),
        "stub-replacement"
    );
    assert_eq!(format!("{}", BlockingStrategy::CspBlock), "csp-block");
    assert_eq!(
        format!("{}", BlockingStrategy::IceCandidateFilter),
        "ice-candidate-filter"
    );
    assert_eq!(format!("{}", BlockingStrategy::ApiRemoval), "api-removal");
}
