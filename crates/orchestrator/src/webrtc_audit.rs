use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WebRtcIssue {
    RtcPeerConnectionUsed,
    IceCandidateLeak,
    StunServerExposed { server: String },
    TurnServerExposed { server: String },
    DataChannelUsed,
    NoIceCandidateFiltering,
    MediaDevicesAccess,
}

impl std::fmt::Display for WebRtcIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RtcPeerConnectionUsed => write!(f, "rtc_peer_connection"),
            Self::IceCandidateLeak => write!(f, "ice_candidate_leak"),
            Self::StunServerExposed { server } => write!(f, "stun_exposed:{server}"),
            Self::TurnServerExposed { server } => write!(f, "turn_exposed:{server}"),
            Self::DataChannelUsed => write!(f, "data_channel"),
            Self::NoIceCandidateFiltering => write!(f, "no_ice_filtering"),
            Self::MediaDevicesAccess => write!(f, "media_devices_access"),
        }
    }
}

pub fn audit_webrtc(target: &str) -> Vec<WebRtcIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send().and_then(|r| r.text()) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    analyze_webrtc(&body)
}

pub fn analyze_webrtc(body: &str) -> Vec<WebRtcIssue> {
    if !has_webrtc_indicators(body) {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if body.contains("RTCPeerConnection") || body.contains("webkitRTCPeerConnection") {
        issues.push(WebRtcIssue::RtcPeerConnectionUsed);
    }

    if has_ice_candidate_leak(body) {
        issues.push(WebRtcIssue::IceCandidateLeak);
    }

    extract_stun_turn_servers(body, &mut issues);

    if body.contains("createDataChannel") {
        issues.push(WebRtcIssue::DataChannelUsed);
    }

    if (body.contains("RTCPeerConnection") || body.contains("webkitRTCPeerConnection"))
        && !body.contains("iceCandidatePoolSize")
        && !body.contains("iceTransportPolicy")
    {
        issues.push(WebRtcIssue::NoIceCandidateFiltering);
    }

    if body.contains("getUserMedia")
        || body.contains("getDisplayMedia")
        || body.contains("enumerateDevices")
    {
        issues.push(WebRtcIssue::MediaDevicesAccess);
    }

    issues
}

fn has_webrtc_indicators(body: &str) -> bool {
    body.contains("RTCPeerConnection")
        || body.contains("webkitRTCPeerConnection")
        || body.contains("getUserMedia")
        || body.contains("getDisplayMedia")
        || body.contains("enumerateDevices")
}

fn has_ice_candidate_leak(body: &str) -> bool {
    let has_ice_event = body.contains("onicecandidate")
        || body.contains("icecandidate")
        || body.contains("candidate.candidate");

    let has_ip_extraction = body.contains(".address")
        || body.contains("candidate.candidate")
        || body.contains("sdpMid");

    has_ice_event && has_ip_extraction
}

fn extract_stun_turn_servers(body: &str, issues: &mut Vec<WebRtcIssue>) {
    for prefix in ["stun:", "stuns:"] {
        let mut pos = 0;
        while let Some(idx) = body[pos..].find(prefix) {
            let abs = pos + idx;
            let end = body[abs..]
                .find(['"', '\'', '`', ' ', ',', '}'])
                .unwrap_or(body.len() - abs)
                .min(100);
            let server = &body[abs..abs + end];
            if server.len() > prefix.len() {
                issues.push(WebRtcIssue::StunServerExposed {
                    server: server.to_string(),
                });
                pos = abs + end;
                continue;
            }
            pos = abs + 1;
        }
    }

    for prefix in ["turn:", "turns:"] {
        let mut pos = 0;
        while let Some(idx) = body[pos..].find(prefix) {
            let abs = pos + idx;
            let end = body[abs..]
                .find(['"', '\'', '`', ' ', ',', '}'])
                .unwrap_or(body.len() - abs)
                .min(100);
            let server = &body[abs..abs + end];
            if server.len() > prefix.len() {
                issues.push(WebRtcIssue::TurnServerExposed {
                    server: server.to_string(),
                });
                pos = abs + end;
                continue;
            }
            pos = abs + 1;
        }
    }
}

pub fn webrtc_severity(issue: &WebRtcIssue) -> f64 {
    match issue {
        WebRtcIssue::IceCandidateLeak => 7.0,
        WebRtcIssue::TurnServerExposed { .. } => 6.5,
        WebRtcIssue::MediaDevicesAccess => 5.5,
        WebRtcIssue::StunServerExposed { .. } => 5.0,
        WebRtcIssue::NoIceCandidateFiltering => 4.5,
        WebRtcIssue::DataChannelUsed => 3.5,
        WebRtcIssue::RtcPeerConnectionUsed => 3.0,
    }
}

pub fn webrtc_to_operations(
    issues: &[WebRtcIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                webrtc_severity(issue),
                0.7,
            )
        })
        .collect()
}
