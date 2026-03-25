use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Types of proxy layers in a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProxyLayer {
    ResidentialProxy,
    Vpn,
    Tor,
    Socks5,
    HttpProxy,
    CloudFunction,
    SshTunnel,
}

impl fmt::Display for ProxyLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ResidentialProxy => "Residential Proxy",
            Self::Vpn => "VPN",
            Self::Tor => "Tor",
            Self::Socks5 => "SOCKS5",
            Self::HttpProxy => "HTTP Proxy",
            Self::CloudFunction => "Cloud Function",
            Self::SshTunnel => "SSH Tunnel",
        };
        write!(f, "{label}")
    }
}

/// A single link in a proxy chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyChainLink {
    pub layer: ProxyLayer,
    pub address: String,
    pub port: u16,
    pub country_code: Option<String>,
    pub estimated_latency_ms: u64,
    pub anonymity_score: f64,
}

/// A complete proxy chain configuration from client to target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyChain {
    pub links: Vec<ProxyChainLink>,
    pub total_latency_ms: u64,
    pub overall_anonymity_score: f64,
    pub countries_traversed: Vec<String>,
}

impl ProxyChain {
    pub fn new() -> Self {
        Self {
            links: Vec::new(),
            total_latency_ms: 0,
            overall_anonymity_score: 1.0,
            countries_traversed: Vec::new(),
        }
    }

    pub fn add_link(&mut self, link: ProxyChainLink) {
        self.total_latency_ms += link.estimated_latency_ms;
        self.overall_anonymity_score *= link.anonymity_score;
        if let Some(ref cc) = link.country_code {
            if !self.countries_traversed.contains(cc) {
                self.countries_traversed.push(cc.clone());
            }
        }
        self.links.push(link);
    }

    pub fn hop_count(&self) -> usize {
        self.links.len()
    }
}

/// Build a recommended proxy chain for maximum attribution resistance.
pub fn build_recommended_chain() -> ProxyChain {
    let mut chain = ProxyChain::new();
    chain.add_link(ProxyChainLink {
        layer: ProxyLayer::ResidentialProxy,
        address: "proxy-pool.example.com".to_string(),
        port: 8080,
        country_code: Some("US".to_string()),
        estimated_latency_ms: 80,
        anonymity_score: 0.85,
    });
    chain.add_link(ProxyChainLink {
        layer: ProxyLayer::Vpn,
        address: "vpn-exit.example.com".to_string(),
        port: 1194,
        country_code: Some("CH".to_string()),
        estimated_latency_ms: 40,
        anonymity_score: 0.90,
    });
    chain.add_link(ProxyChainLink {
        layer: ProxyLayer::Tor,
        address: "127.0.0.1".to_string(),
        port: 9050,
        country_code: None,
        estimated_latency_ms: 300,
        anonymity_score: 0.95,
    });
    chain
}

/// Traffic mixing profile to interleave scan traffic with legitimate browsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficMixProfile {
    pub cover_sites: Vec<String>,
    pub scan_to_cover_ratio: f64,
    pub cover_request_pattern: RequestPattern,
    pub user_agent: String,
}

/// Request pattern types for cover traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestPattern {
    Sequential,
    Random,
    BurstThenPause,
    HumanLike,
}

impl Default for TrafficMixProfile {
    fn default() -> Self {
        Self {
            cover_sites: vec![
                "https://news.ycombinator.com".to_string(),
                "https://www.reddit.com".to_string(),
                "https://stackoverflow.com".to_string(),
                "https://github.com".to_string(),
                "https://en.wikipedia.org".to_string(),
            ],
            scan_to_cover_ratio: 0.3,
            cover_request_pattern: RequestPattern::HumanLike,
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                         (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                .to_string(),
        }
    }
}

/// Generate a request schedule that mixes scan and cover requests.
pub fn generate_mixed_schedule(
    scan_urls: &[String],
    profile: &TrafficMixProfile,
) -> Vec<ScheduledRequest> {
    let mut schedule = Vec::new();
    let mut scan_idx = 0;
    let mut cover_idx = 0;
    let mut time_offset_ms: u64 = 0;

    for i in 0..(scan_urls.len() * 3) {
        let is_scan = (i as f64 * profile.scan_to_cover_ratio) as usize > cover_idx
            && scan_idx < scan_urls.len();

        if is_scan {
            schedule.push(ScheduledRequest {
                url: scan_urls[scan_idx].clone(),
                is_cover_traffic: false,
                delay_ms: time_offset_ms,
                user_agent: profile.user_agent.clone(),
            });
            scan_idx += 1;
        } else if !profile.cover_sites.is_empty() {
            let site = &profile.cover_sites[cover_idx % profile.cover_sites.len()];
            schedule.push(ScheduledRequest {
                url: site.clone(),
                is_cover_traffic: true,
                delay_ms: time_offset_ms,
                user_agent: profile.user_agent.clone(),
            });
            cover_idx += 1;
        }

        time_offset_ms += generate_human_delay(&profile.cover_request_pattern);

        if scan_idx >= scan_urls.len() && cover_idx > scan_urls.len() {
            break;
        }
    }
    schedule
}

/// A request in the mixed traffic schedule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledRequest {
    pub url: String,
    pub is_cover_traffic: bool,
    pub delay_ms: u64,
    pub user_agent: String,
}

fn generate_human_delay(pattern: &RequestPattern) -> u64 {
    match pattern {
        RequestPattern::Sequential => 1000,
        RequestPattern::Random => 500,
        RequestPattern::BurstThenPause => 200,
        RequestPattern::HumanLike => 2000,
    }
}

/// Cloud provider options for scan infrastructure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CloudProvider {
    Aws,
    Gcp,
    Azure,
    DigitalOcean,
    Linode,
    Vultr,
    Hetzner,
}

impl fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Aws => "AWS",
            Self::Gcp => "GCP",
            Self::Azure => "Azure",
            Self::DigitalOcean => "DigitalOcean",
            Self::Linode => "Linode",
            Self::Vultr => "Vultr",
            Self::Hetzner => "Hetzner",
        };
        write!(f, "{label}")
    }
}

/// Infrastructure diversity plan assigning scan phases to different providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructurePlan {
    pub phase_assignments: HashMap<String, CloudProvider>,
    pub ephemeral: bool,
    pub max_instance_lifetime_secs: u64,
    pub auto_destroy: bool,
}

impl Default for InfrastructurePlan {
    fn default() -> Self {
        let mut assignments = HashMap::new();
        assignments.insert("recon".to_string(), CloudProvider::DigitalOcean);
        assignments.insert("crawl".to_string(), CloudProvider::Vultr);
        assignments.insert("fuzz".to_string(), CloudProvider::Aws);
        assignments.insert("report".to_string(), CloudProvider::Hetzner);
        Self {
            phase_assignments: assignments,
            ephemeral: true,
            max_instance_lifetime_secs: 3600,
            auto_destroy: true,
        }
    }
}

/// Operational security checklist item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsecCheck {
    pub name: String,
    pub description: String,
    pub category: OpsecCategory,
    pub passed: Option<bool>,
    pub severity: OpsecSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OpsecCategory {
    Network,
    Identity,
    Infrastructure,
    Timing,
    DataHandling,
    Forensics,
}

impl fmt::Display for OpsecCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Network => "Network",
            Self::Identity => "Identity",
            Self::Infrastructure => "Infrastructure",
            Self::Timing => "Timing",
            Self::DataHandling => "Data Handling",
            Self::Forensics => "Forensics",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OpsecSeverity {
    Advisory,
    Warning,
    Critical,
}

impl fmt::Display for OpsecSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Advisory => "Advisory",
            Self::Warning => "Warning",
            Self::Critical => "Critical",
        };
        write!(f, "{label}")
    }
}

/// Generate the pre-scan OPSEC verification checklist.
pub fn generate_opsec_checklist() -> Vec<OpsecCheck> {
    vec![
        OpsecCheck {
            name: "VPN/Proxy Active".to_string(),
            description: "Verify VPN or proxy chain is active before any scan traffic".to_string(),
            category: OpsecCategory::Network,
            passed: None,
            severity: OpsecSeverity::Critical,
        },
        OpsecCheck {
            name: "DNS Leak Test".to_string(),
            description: "Verify DNS queries are routed through the tunnel, not leaked to ISP"
                .to_string(),
            category: OpsecCategory::Network,
            passed: None,
            severity: OpsecSeverity::Critical,
        },
        OpsecCheck {
            name: "WebRTC Leak Test".to_string(),
            description: "Ensure WebRTC does not leak real IP address".to_string(),
            category: OpsecCategory::Network,
            passed: None,
            severity: OpsecSeverity::Warning,
        },
        OpsecCheck {
            name: "Clean Browser Profile".to_string(),
            description: "Use a fresh browser profile with no identifying cookies or history"
                .to_string(),
            category: OpsecCategory::Identity,
            passed: None,
            severity: OpsecSeverity::Warning,
        },
        OpsecCheck {
            name: "Burner Accounts".to_string(),
            description:
                "All service accounts used are burner accounts, not linked to real identity"
                    .to_string(),
            category: OpsecCategory::Identity,
            passed: None,
            severity: OpsecSeverity::Critical,
        },
        OpsecCheck {
            name: "Ephemeral Infrastructure".to_string(),
            description: "Scan infrastructure is ephemeral and will be destroyed post-scan"
                .to_string(),
            category: OpsecCategory::Infrastructure,
            passed: None,
            severity: OpsecSeverity::Warning,
        },
        OpsecCheck {
            name: "Time Zone Consistency".to_string(),
            description: "System timezone matches the proxy exit location".to_string(),
            category: OpsecCategory::Timing,
            passed: None,
            severity: OpsecSeverity::Advisory,
        },
        OpsecCheck {
            name: "No Persistent State".to_string(),
            description: "No scan results or logs stored on non-encrypted volumes".to_string(),
            category: OpsecCategory::DataHandling,
            passed: None,
            severity: OpsecSeverity::Critical,
        },
        OpsecCheck {
            name: "RAM Disk for Temp".to_string(),
            description: "Temporary files written to RAM disk, not persistent storage".to_string(),
            category: OpsecCategory::Forensics,
            passed: None,
            severity: OpsecSeverity::Warning,
        },
        OpsecCheck {
            name: "MAC Address Randomized".to_string(),
            description: "Network interface MAC address is randomized".to_string(),
            category: OpsecCategory::Network,
            passed: None,
            severity: OpsecSeverity::Advisory,
        },
    ]
}

/// Evaluate the OPSEC checklist and return a pass/fail summary.
pub fn evaluate_opsec(checks: &[OpsecCheck]) -> OpsecEvaluation {
    let total = checks.len();
    let passed = checks.iter().filter(|c| c.passed == Some(true)).count();
    let failed = checks.iter().filter(|c| c.passed == Some(false)).count();
    let unchecked = checks.iter().filter(|c| c.passed.is_none()).count();
    let critical_failures = checks
        .iter()
        .filter(|c| c.passed == Some(false) && c.severity == OpsecSeverity::Critical)
        .count();
    let safe_to_proceed = critical_failures == 0 && failed <= 2;

    OpsecEvaluation {
        total,
        passed,
        failed,
        unchecked,
        critical_failures,
        safe_to_proceed,
    }
}

/// Result of evaluating the OPSEC checklist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsecEvaluation {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub unchecked: usize,
    pub critical_failures: usize,
    pub safe_to_proceed: bool,
}

/// Decoy traffic configuration to mask real scan activity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyConfig {
    pub decoy_targets: Vec<String>,
    pub decoy_ratio: f64,
    pub mimic_real_scan: bool,
    pub randomize_order: bool,
}

impl Default for DecoyConfig {
    fn default() -> Self {
        Self {
            decoy_targets: vec![
                "scanme.nmap.org".to_string(),
                "testphp.vulnweb.com".to_string(),
                "demo.testfire.net".to_string(),
            ],
            decoy_ratio: 0.5,
            mimic_real_scan: true,
            randomize_order: true,
        }
    }
}

/// Generate a blended target list mixing real and decoy targets.
pub fn generate_blended_targets(
    real_targets: &[String],
    config: &DecoyConfig,
) -> Vec<BlendedTarget> {
    let mut blended = Vec::new();
    for target in real_targets {
        blended.push(BlendedTarget {
            url: target.clone(),
            is_decoy: false,
        });
    }
    let decoy_count = (real_targets.len() as f64 * config.decoy_ratio) as usize;
    for i in 0..decoy_count {
        if !config.decoy_targets.is_empty() {
            let decoy = &config.decoy_targets[i % config.decoy_targets.len()];
            blended.push(BlendedTarget {
                url: decoy.clone(),
                is_decoy: true,
            });
        }
    }
    blended
}

/// A target in the blended list (real or decoy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlendedTarget {
    pub url: String,
    pub is_decoy: bool,
}

#[cfg(test)]
#[path = "attribution_resistance_test.rs"]
mod tests;
