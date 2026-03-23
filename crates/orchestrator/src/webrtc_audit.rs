use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum WebRtcIssue {
    ApiDetected,
    IpLeakViaStun,
    MissingDtlsSrtp,
    UnrestrictedDataChannel,
    ThirdPartyIceServer { server: String },
    ScreenShareWithoutConsent,
    MissingIceCandidateFiltering,
}

impl std::fmt::Display for WebRtcIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::IpLeakViaStun => write!(f, "ip_leak_via_stun"),
            Self::MissingDtlsSrtp => write!(f, "missing_dtls_srtp"),
            Self::UnrestrictedDataChannel => write!(f, "unrestricted_data_channel"),
            Self::ThirdPartyIceServer { server } => write!(f, "third_party_ice_server:{server}"),
            Self::ScreenShareWithoutConsent => write!(f, "screen_share_without_consent"),
            Self::MissingIceCandidateFiltering => write!(f, "missing_ice_candidate_filtering"),
        }
    }
}

pub fn webrtc_severity(issue: &WebRtcIssue) -> f64 {
    match issue {
        WebRtcIssue::IpLeakViaStun => 7.5,
        WebRtcIssue::MissingDtlsSrtp => 7.0,
        WebRtcIssue::ThirdPartyIceServer { .. } => 6.5,
        WebRtcIssue::ScreenShareWithoutConsent => 6.0,
        WebRtcIssue::UnrestrictedDataChannel => 5.5,
        WebRtcIssue::MissingIceCandidateFiltering => 5.0,
        WebRtcIssue::ApiDetected => 2.0,
    }
}

pub fn audit_webrtc(target: &str) -> Vec<WebRtcIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send() {
        Ok(r) => r.text().unwrap_or_default(),
        Err(_) => return Vec::new(),
    };
    analyze_webrtc(&body)
}

pub fn analyze_webrtc(body: &str) -> Vec<WebRtcIssue> {
    let mut issues = Vec::new();

    let has_rtc_peer_connection = body.contains("RTCPeerConnection")
        || body.contains("webkitRTCPeerConnection")
        || body.contains("mozRTCPeerConnection");

    let has_get_user_media = body.contains("getUserMedia") || body.contains("webkitGetUserMedia");

    let has_rtc_data_channel =
        body.contains("RTCDataChannel") || body.contains("createDataChannel");

    let has_create_offer = body.contains("createOffer");
    let has_create_answer = body.contains("createAnswer");

    let has_get_display_media = body.contains("getDisplayMedia");

    if !has_rtc_peer_connection
        && !has_get_user_media
        && !has_rtc_data_channel
        && !has_get_display_media
        && !has_create_offer
        && !has_create_answer
    {
        return Vec::new();
    }

    if has_rtc_peer_connection || has_get_user_media || has_create_offer || has_create_answer {
        issues.push(WebRtcIssue::ApiDetected);
    }

    if has_rtc_peer_connection && has_ip_leak_pattern(body) {
        issues.push(WebRtcIssue::IpLeakViaStun);
    }

    if has_rtc_peer_connection && !has_dtls_srtp_indicators(body) {
        issues.push(WebRtcIssue::MissingDtlsSrtp);
    }

    if has_rtc_data_channel && !has_message_size_limit(body) {
        issues.push(WebRtcIssue::UnrestrictedDataChannel);
    }

    extract_third_party_ice_servers(body, &mut issues);

    if has_get_display_media && !has_consent_indicator(body) {
        issues.push(WebRtcIssue::ScreenShareWithoutConsent);
    }

    if has_rtc_peer_connection && !has_ice_candidate_filtering(body) {
        issues.push(WebRtcIssue::MissingIceCandidateFiltering);
    }

    issues
}

pub fn webrtc_to_operations(issues: &[WebRtcIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                webrtc_severity(issue),
                0.5,
            )
        })
        .collect()
}

fn has_ip_leak_pattern(body: &str) -> bool {
    let has_ice_candidate_handler =
        body.contains("onicecandidate") || body.contains("addEventListener(\"icecandidate\"");

    let has_candidate_extraction = body.contains("candidate.candidate")
        || body.contains("candidate.address")
        || body.contains(".sdpMid")
        || body.contains(".sdpMLineIndex");

    let no_turn_relay = !body.contains("iceTransportPolicy")
        || body.contains("iceTransportPolicy: \"all\"")
        || body.contains("iceTransportPolicy:\"all\"");

    has_ice_candidate_handler && has_candidate_extraction && no_turn_relay
}

fn has_dtls_srtp_indicators(body: &str) -> bool {
    body.contains("DTLS") || body.contains("SRTP") || body.contains("srtpCryptoSuite")
}

fn has_message_size_limit(body: &str) -> bool {
    body.contains("maxPacketLifeTime")
        || body.contains("maxRetransmits")
        || body.contains("bufferedAmountLowThreshold")
}

fn extract_third_party_ice_servers(body: &str, issues: &mut Vec<WebRtcIssue>) {
    let prefixes = ["stun:", "stuns:", "turn:", "turns:"];

    for prefix in prefixes {
        let mut pos = 0;
        while let Some(idx) = body[pos..].find(prefix) {
            let abs = pos + idx;
            let end = body[abs..]
                .find(['"', '\'', '`', ' ', ',', '}', ']'])
                .unwrap_or(body.len() - abs)
                .min(100);
            let server = &body[abs..abs + end];
            if server.len() > prefix.len() && is_third_party_server(server) {
                issues.push(WebRtcIssue::ThirdPartyIceServer {
                    server: server.to_string(),
                });
                pos = abs + end;
                continue;
            }
            pos = abs + 1;
        }
    }
}

fn is_third_party_server(server: &str) -> bool {
    !server.contains("localhost")
        && !server.contains("127.0.0.1")
        && !server.contains("::1")
        && !server.contains("0.0.0.0")
}

fn has_consent_indicator(body: &str) -> bool {
    body.contains("recording-indicator")
        || body.contains("screen-share-indicator")
        || body.contains("consent-dialog")
        || body.contains("user-feedback")
}

fn has_ice_candidate_filtering(body: &str) -> bool {
    body.contains("iceTransportPolicy: \"relay\"")
        || body.contains("iceTransportPolicy:\"relay\"")
        || body.contains("iceCandidatePoolSize")
}
