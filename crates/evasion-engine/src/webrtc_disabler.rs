use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// WebRTC leak prevention module.
///
/// WebRTC's ICE candidate gathering can expose real IP addresses even when
/// traffic is tunneled through proxies or VPNs. This module generates
/// JavaScript overrides and CSP rules that suppress WebRTC entirely.

/// WebRTC blocking strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BlockingStrategy {
    /// Replace RTCPeerConnection with a no-op stub.
    StubReplacement,
    /// Block via Content-Security-Policy headers.
    CspBlock,
    /// Override ICE candidate event to filter out real IPs.
    IceCandidateFilter,
    /// Complete removal of all WebRTC APIs from the page context.
    ApiRemoval,
}

impl std::fmt::Display for BlockingStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StubReplacement => write!(f, "stub-replacement"),
            Self::CspBlock => write!(f, "csp-block"),
            Self::IceCandidateFilter => write!(f, "ice-candidate-filter"),
            Self::ApiRemoval => write!(f, "api-removal"),
        }
    }
}

/// WebRTC API surface that can leak IP information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LeakVector {
    StunBinding,
    TurnAllocation,
    IceCandidateGathering,
    GetUserMedia,
    DataChannel,
    MediaDevicesEnumerate,
}

/// Configuration for WebRTC disabling.
#[derive(Debug, Clone)]
pub struct WebRtcDisablerConfig {
    pub strategy: BlockingStrategy,
    pub block_media_devices: bool,
    pub block_data_channels: bool,
    pub allowed_stun_servers: Vec<String>,
}

impl Default for WebRtcDisablerConfig {
    fn default() -> Self {
        Self {
            strategy: BlockingStrategy::StubReplacement,
            block_media_devices: true,
            block_data_channels: true,
            allowed_stun_servers: Vec::new(),
        }
    }
}

/// Result of a WebRTC leak scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakScanResult {
    pub leaks_detected: Vec<DetectedLeak>,
    pub total_candidates_checked: u32,
    pub is_safe: bool,
}

/// A specific leak detected during scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedLeak {
    pub vector: LeakVector,
    pub ip_address: String,
    pub ip_type: IpType,
    pub description: String,
}

/// Type of leaked IP address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpType {
    PublicIpv4,
    PublicIpv6,
    PrivateIpv4,
    LinkLocal,
    Loopback,
}

/// Generated JavaScript override to block WebRTC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsOverride {
    pub script: String,
    pub strategy: BlockingStrategy,
    pub apis_blocked: Vec<String>,
}

/// Generated CSP directives to block WebRTC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CspDirectives {
    pub connect_src: String,
    pub media_src: String,
    pub additional_directives: Vec<String>,
}

/// WebRTC disabler implementation.
pub struct WebRtcDisabler {
    config: WebRtcDisablerConfig,
}

impl WebRtcDisabler {
    pub fn new(config: WebRtcDisablerConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(WebRtcDisablerConfig::default())
    }

    /// Generate the JavaScript override code that neutralizes WebRTC APIs.
    pub fn generate_js_override(&self) -> JsOverride {
        let mut apis_blocked = Vec::new();
        let script = match self.config.strategy {
            BlockingStrategy::StubReplacement => {
                apis_blocked.push("RTCPeerConnection".to_string());
                apis_blocked.push("webkitRTCPeerConnection".to_string());
                apis_blocked.push("mozRTCPeerConnection".to_string());
                if self.config.block_media_devices {
                    apis_blocked.push("navigator.mediaDevices.getUserMedia".to_string());
                    apis_blocked.push("navigator.mediaDevices.enumerateDevices".to_string());
                }
                self.stub_replacement_script()
            }
            BlockingStrategy::IceCandidateFilter => {
                apis_blocked.push("RTCPeerConnection.onicecandidate".to_string());
                self.ice_candidate_filter_script()
            }
            BlockingStrategy::ApiRemoval => {
                apis_blocked.push("RTCPeerConnection".to_string());
                apis_blocked.push("RTCSessionDescription".to_string());
                apis_blocked.push("RTCIceCandidate".to_string());
                if self.config.block_data_channels {
                    apis_blocked.push("RTCDataChannel".to_string());
                }
                self.api_removal_script()
            }
            BlockingStrategy::CspBlock => {
                apis_blocked.push("connect-src (CSP)".to_string());
                String::new()
            }
        };

        JsOverride {
            script,
            strategy: self.config.strategy,
            apis_blocked,
        }
    }

    /// Generate CSP directives that block WebRTC at the network level.
    pub fn generate_csp_directives(&self) -> CspDirectives {
        let connect_src = if self.config.allowed_stun_servers.is_empty() {
            "'self'".to_string()
        } else {
            let allowed: Vec<_> = std::iter::once("'self'".to_string())
                .chain(self.config.allowed_stun_servers.iter().cloned())
                .collect();
            allowed.join(" ")
        };

        let media_src = if self.config.block_media_devices {
            "'none'".to_string()
        } else {
            "'self'".to_string()
        };

        CspDirectives {
            connect_src,
            media_src,
            additional_directives: vec![
                "default-src 'self'".to_string(),
                "script-src 'self' 'unsafe-inline'".to_string(),
            ],
        }
    }

    /// Scan a list of ICE candidate strings for IP leaks.
    pub fn scan_for_leaks(&self, candidates: &[String]) -> LeakScanResult {
        let mut leaks = Vec::new();
        let total = candidates.len() as u32;

        for candidate in candidates {
            if let Some(leak) = self.check_candidate(candidate) {
                leaks.push(leak);
            }
        }

        let is_safe = leaks.is_empty();
        LeakScanResult {
            leaks_detected: leaks,
            total_candidates_checked: total,
            is_safe,
        }
    }

    /// Verify that zero IP addresses leak through WebRTC after applying overrides.
    pub fn verify_zero_leak(&self, candidates: &[String]) -> bool {
        let result = self.scan_for_leaks(candidates);
        result.is_safe
    }

    /// List all leak vectors blocked by the current configuration.
    pub fn blocked_vectors(&self) -> HashSet<LeakVector> {
        let mut vectors = HashSet::new();
        vectors.insert(LeakVector::StunBinding);
        vectors.insert(LeakVector::TurnAllocation);
        vectors.insert(LeakVector::IceCandidateGathering);

        if self.config.block_media_devices {
            vectors.insert(LeakVector::GetUserMedia);
            vectors.insert(LeakVector::MediaDevicesEnumerate);
        }

        if self.config.block_data_channels {
            vectors.insert(LeakVector::DataChannel);
        }

        vectors
    }

    fn check_candidate(&self, candidate: &str) -> Option<DetectedLeak> {
        let parts: Vec<&str> = candidate.split_whitespace().collect();
        if parts.len() < 5 {
            return None;
        }

        let ip_str = parts.get(4)?;

        if ip_str.starts_with("127.") || *ip_str == "::1" {
            return Some(DetectedLeak {
                vector: LeakVector::IceCandidateGathering,
                ip_address: ip_str.to_string(),
                ip_type: IpType::Loopback,
                description: format!("Loopback address leaked: {ip_str}"),
            });
        }

        if ip_str.starts_with("192.168.") || ip_str.starts_with("10.") || ip_str.starts_with("172.")
        {
            return Some(DetectedLeak {
                vector: LeakVector::IceCandidateGathering,
                ip_address: ip_str.to_string(),
                ip_type: IpType::PrivateIpv4,
                description: format!("Private IP leaked via ICE candidate: {ip_str}"),
            });
        }

        if ip_str.starts_with("169.254.") {
            return Some(DetectedLeak {
                vector: LeakVector::IceCandidateGathering,
                ip_address: ip_str.to_string(),
                ip_type: IpType::LinkLocal,
                description: format!("Link-local address leaked: {ip_str}"),
            });
        }

        if ip_str.contains('.') && !ip_str.starts_with("0.") {
            return Some(DetectedLeak {
                vector: LeakVector::StunBinding,
                ip_address: ip_str.to_string(),
                ip_type: IpType::PublicIpv4,
                description: format!("Public IPv4 leaked via STUN: {ip_str}"),
            });
        }

        if ip_str.contains(':') && *ip_str != "::1" {
            return Some(DetectedLeak {
                vector: LeakVector::StunBinding,
                ip_address: ip_str.to_string(),
                ip_type: IpType::PublicIpv6,
                description: format!("Public IPv6 leaked via STUN: {ip_str}"),
            });
        }

        None
    }

    fn stub_replacement_script(&self) -> String {
        let mut script = String::new();
        script.push_str("(function() {\n");
        script.push_str("  'use strict';\n");
        script.push_str("  const noop = function() {};\n");
        script.push_str("  const NoOpRTC = function() {\n");
        script.push_str("    return {\n");
        script.push_str("      createDataChannel: noop,\n");
        script.push_str("      createOffer: function() { return Promise.reject('blocked'); },\n");
        script.push_str("      createAnswer: function() { return Promise.reject('blocked'); },\n");
        script.push_str(
            "      setLocalDescription: function() { return Promise.reject('blocked'); },\n",
        );
        script.push_str(
            "      setRemoteDescription: function() { return Promise.reject('blocked'); },\n",
        );
        script.push_str("      addIceCandidate: noop,\n");
        script.push_str("      close: noop,\n");
        script.push_str("      onicecandidate: null,\n");
        script.push_str("      ontrack: null,\n");
        script.push_str("    };\n");
        script.push_str("  };\n");
        script.push_str("  window.RTCPeerConnection = NoOpRTC;\n");
        script.push_str("  window.webkitRTCPeerConnection = NoOpRTC;\n");
        script.push_str("  window.mozRTCPeerConnection = NoOpRTC;\n");
        if self.config.block_media_devices {
            script.push_str("  if (navigator.mediaDevices) {\n");
            script.push_str("    navigator.mediaDevices.getUserMedia = function() { return Promise.reject(new DOMException('NotAllowedError')); };\n");
            script.push_str("    navigator.mediaDevices.enumerateDevices = function() { return Promise.resolve([]); };\n");
            script.push_str("  }\n");
        }
        script.push_str("})();\n");
        script
    }

    fn ice_candidate_filter_script(&self) -> String {
        let mut script = String::new();
        script.push_str("(function() {\n");
        script.push_str("  'use strict';\n");
        script.push_str("  const OrigRTC = window.RTCPeerConnection;\n");
        script.push_str("  window.RTCPeerConnection = function() {\n");
        script.push_str("    const pc = new OrigRTC(...arguments);\n");
        script.push_str("    const origSet = Object.getOwnPropertyDescriptor(pc.__proto__, 'onicecandidate');\n");
        script.push_str("    Object.defineProperty(pc, 'onicecandidate', {\n");
        script.push_str("      set: function(fn) {\n");
        script.push_str("        origSet.set.call(this, function(e) {\n");
        script.push_str("          if (e.candidate && e.candidate.candidate) {\n");
        script.push_str("            return; // suppress all candidates\n");
        script.push_str("          }\n");
        script.push_str("          fn(e);\n");
        script.push_str("        });\n");
        script.push_str("      }\n");
        script.push_str("    });\n");
        script.push_str("    return pc;\n");
        script.push_str("  };\n");
        script.push_str("})();\n");
        script
    }

    fn api_removal_script(&self) -> String {
        let mut script = String::new();
        script.push_str("(function() {\n");
        script.push_str("  'use strict';\n");
        script.push_str("  delete window.RTCPeerConnection;\n");
        script.push_str("  delete window.webkitRTCPeerConnection;\n");
        script.push_str("  delete window.mozRTCPeerConnection;\n");
        script.push_str("  delete window.RTCSessionDescription;\n");
        script.push_str("  delete window.RTCIceCandidate;\n");
        if self.config.block_data_channels {
            script.push_str("  delete window.RTCDataChannel;\n");
        }
        if self.config.block_media_devices {
            script.push_str("  if (navigator.mediaDevices) {\n");
            script.push_str("    delete navigator.mediaDevices.getUserMedia;\n");
            script.push_str("    delete navigator.mediaDevices.enumerateDevices;\n");
            script.push_str("  }\n");
        }
        script.push_str("})();\n");
        script
    }
}
