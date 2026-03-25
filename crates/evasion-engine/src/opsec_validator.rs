use std::fmt;

use serde::{Deserialize, Serialize};

/// OPSEC check category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OpsecCheckCategory {
    DnsLeak,
    WebRtcLeak,
    Ipv6Leak,
    KillSwitch,
    ClockSkew,
    MacAddress,
    Hostname,
    ProcessList,
}

impl fmt::Display for OpsecCheckCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DnsLeak => write!(f, "DNS Leak"),
            Self::WebRtcLeak => write!(f, "WebRTC Leak"),
            Self::Ipv6Leak => write!(f, "IPv6 Leak"),
            Self::KillSwitch => write!(f, "Kill Switch"),
            Self::ClockSkew => write!(f, "Clock Skew"),
            Self::MacAddress => write!(f, "MAC Address"),
            Self::Hostname => write!(f, "Hostname"),
            Self::ProcessList => write!(f, "Process List"),
        }
    }
}

/// Severity level for an OPSEC finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OpsecSeverity {
    Info,
    Warning,
    Critical,
    Blocking,
}

impl fmt::Display for OpsecSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARN"),
            Self::Critical => write!(f, "CRIT"),
            Self::Blocking => write!(f, "BLOCK"),
        }
    }
}

/// Result of a single OPSEC check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsecCheckResult {
    pub category: OpsecCheckCategory,
    pub passed: bool,
    pub severity: OpsecSeverity,
    pub detail: String,
    pub remediation: String,
    pub score_impact: i32,
}

/// DNS leak check input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsLeakInput {
    pub resolved_dns_servers: Vec<String>,
    pub expected_proxy_dns: Vec<String>,
}

/// WebRTC leak check input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebRtcLeakInput {
    pub local_candidates: Vec<String>,
    pub public_ip: String,
    pub proxy_ip: String,
}

/// IPv6 leak check input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6LeakInput {
    pub ipv6_addresses: Vec<String>,
    pub ipv6_disabled: bool,
}

/// Kill switch verification input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchInput {
    pub vpn_connected: bool,
    pub firewall_rules_set: bool,
    pub default_route_via_vpn: bool,
}

/// Clock skew check input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockSkewInput {
    pub local_timezone: String,
    pub expected_timezone: String,
    pub ntp_offset_ms: i64,
}

/// MAC address check input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacAddressInput {
    pub current_mac: String,
    pub is_randomized: bool,
    pub vendor_oui: Option<String>,
}

/// Hostname check input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostnameInput {
    pub hostname: String,
    pub contains_real_name: bool,
    pub contains_org_name: bool,
}

/// Process list check input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessListInput {
    pub running_processes: Vec<String>,
}

/// Known identifying process names.
const IDENTIFYING_PROCESSES: &[&str] = &[
    "outlook",
    "teams",
    "slack",
    "zoom",
    "discord",
    "1password",
    "lastpass",
    "bitwarden",
    "dropbox",
    "onedrive",
    "google-drive",
    "vmware",
    "virtualbox",
    "parallels",
    "wireshark",
    "burpsuite",
    "ida64",
    "ghidra",
    "corporate-vpn",
    "crowdstrike",
    "sentinel-one",
    "carbon-black",
];

/// Overall OPSEC validation result with aggregate score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsecValidationResult {
    pub checks: Vec<OpsecCheckResult>,
    pub score: u32,
    pub max_score: u32,
    pub passed: bool,
    pub blocking_issues: Vec<String>,
}

impl OpsecValidationResult {
    /// Returns the score as a percentage (0..=100).
    pub fn score_pct(&self) -> f64 {
        if self.max_score == 0 {
            return 100.0;
        }
        (self.score as f64 / self.max_score as f64) * 100.0
    }

    /// Returns all checks that failed.
    pub fn failed_checks(&self) -> Vec<&OpsecCheckResult> {
        self.checks.iter().filter(|c| !c.passed).collect()
    }

    /// Returns all critical or blocking findings.
    pub fn critical_findings(&self) -> Vec<&OpsecCheckResult> {
        self.checks
            .iter()
            .filter(|c| !c.passed && c.severity >= OpsecSeverity::Critical)
            .collect()
    }
}

/// Configuration for the OPSEC validator.
#[derive(Debug, Clone)]
pub struct OpsecValidatorConfig {
    pub min_score_threshold: u32,
    pub block_on_critical: bool,
    pub custom_identifying_processes: Vec<String>,
    pub expected_timezone: String,
    pub max_clock_offset_ms: i64,
}

impl Default for OpsecValidatorConfig {
    fn default() -> Self {
        Self {
            min_score_threshold: 70,
            block_on_critical: true,
            custom_identifying_processes: Vec::new(),
            expected_timezone: "UTC".to_string(),
            max_clock_offset_ms: 2000,
        }
    }
}

impl OpsecValidatorConfig {
    pub fn with_threshold(mut self, threshold: u32) -> Self {
        self.min_score_threshold = threshold.min(100);
        self
    }

    pub fn with_block_on_critical(mut self, block: bool) -> Self {
        self.block_on_critical = block;
        self
    }

    pub fn with_expected_timezone(mut self, tz: &str) -> Self {
        self.expected_timezone = tz.to_string();
        self
    }

    pub fn with_max_clock_offset(mut self, ms: i64) -> Self {
        self.max_clock_offset_ms = ms;
        self
    }

    pub fn add_identifying_process(mut self, process: &str) -> Self {
        self.custom_identifying_processes.push(process.to_string());
        self
    }
}

/// Pre-scan OPSEC validator that checks for DNS leaks, WebRTC leaks,
/// IPv6 leaks, kill switch status, clock skew, MAC randomization,
/// hostname exposure, and identifying processes. Returns a confidence
/// score 0-100 and blocks the scan if below threshold.
pub struct OpsecValidator {
    config: OpsecValidatorConfig,
    last_result: Option<OpsecValidationResult>,
}

impl OpsecValidator {
    pub fn new(config: OpsecValidatorConfig) -> Self {
        Self {
            config,
            last_result: None,
        }
    }

    /// Checks for DNS leaks by comparing resolved DNS servers against expected proxy DNS.
    pub fn check_dns_leak(&self, input: &DnsLeakInput) -> OpsecCheckResult {
        let leaking_servers: Vec<&String> = input
            .resolved_dns_servers
            .iter()
            .filter(|s| !input.expected_proxy_dns.contains(s))
            .collect();

        if leaking_servers.is_empty() {
            OpsecCheckResult {
                category: OpsecCheckCategory::DnsLeak,
                passed: true,
                severity: OpsecSeverity::Info,
                detail: "All DNS queries route through proxy/VPN".to_string(),
                remediation: String::new(),
                score_impact: 0,
            }
        } else {
            OpsecCheckResult {
                category: OpsecCheckCategory::DnsLeak,
                passed: false,
                severity: OpsecSeverity::Critical,
                detail: format!(
                    "DNS queries leaking to non-proxy servers: {}",
                    leaking_servers.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                ),
                remediation: "Configure DNS to resolve exclusively through proxy/VPN. Set /etc/resolv.conf or use systemd-resolved with DNS=<proxy-dns>".to_string(),
                score_impact: -20,
            }
        }
    }

    /// Checks for WebRTC IP leaks.
    pub fn check_webrtc_leak(&self, input: &WebRtcLeakInput) -> OpsecCheckResult {
        let real_ip_exposed = input
            .local_candidates
            .iter()
            .any(|c| c.contains(&input.public_ip) && input.public_ip != input.proxy_ip);

        if !real_ip_exposed {
            OpsecCheckResult {
                category: OpsecCheckCategory::WebRtcLeak,
                passed: true,
                severity: OpsecSeverity::Info,
                detail: "WebRTC candidates do not expose real IP".to_string(),
                remediation: String::new(),
                score_impact: 0,
            }
        } else {
            OpsecCheckResult {
                category: OpsecCheckCategory::WebRtcLeak,
                passed: false,
                severity: OpsecSeverity::Critical,
                detail: format!("WebRTC leaking real IP {} via ICE candidates", input.public_ip),
                remediation: "Disable WebRTC in browser (media.peerconnection.enabled=false) or use browser extension to block STUN".to_string(),
                score_impact: -25,
            }
        }
    }

    /// Checks for IPv6 traffic bypassing proxy.
    pub fn check_ipv6_leak(&self, input: &Ipv6LeakInput) -> OpsecCheckResult {
        if input.ipv6_disabled {
            return OpsecCheckResult {
                category: OpsecCheckCategory::Ipv6Leak,
                passed: true,
                severity: OpsecSeverity::Info,
                detail: "IPv6 is disabled system-wide".to_string(),
                remediation: String::new(),
                score_impact: 0,
            };
        }

        if input.ipv6_addresses.is_empty() {
            OpsecCheckResult {
                category: OpsecCheckCategory::Ipv6Leak,
                passed: true,
                severity: OpsecSeverity::Info,
                detail: "No IPv6 addresses detected".to_string(),
                remediation: String::new(),
                score_impact: 0,
            }
        } else {
            OpsecCheckResult {
                category: OpsecCheckCategory::Ipv6Leak,
                passed: false,
                severity: OpsecSeverity::Critical,
                detail: format!(
                    "IPv6 addresses detected that may bypass proxy: {}",
                    input.ipv6_addresses.join(", ")
                ),
                remediation: "Disable IPv6: sysctl -w net.ipv6.conf.all.disable_ipv6=1 or add ip6tables DROP rules".to_string(),
                score_impact: -20,
            }
        }
    }

    /// Verifies the VPN kill switch is active.
    pub fn check_kill_switch(&self, input: &KillSwitchInput) -> OpsecCheckResult {
        let all_good =
            input.vpn_connected && input.firewall_rules_set && input.default_route_via_vpn;

        if all_good {
            OpsecCheckResult {
                category: OpsecCheckCategory::KillSwitch,
                passed: true,
                severity: OpsecSeverity::Info,
                detail: "VPN connected, firewall rules active, default route via VPN".to_string(),
                remediation: String::new(),
                score_impact: 0,
            }
        } else {
            let mut issues = Vec::new();
            if !input.vpn_connected {
                issues.push("VPN disconnected");
            }
            if !input.firewall_rules_set {
                issues.push("firewall rules missing");
            }
            if !input.default_route_via_vpn {
                issues.push("default route not through VPN");
            }

            OpsecCheckResult {
                category: OpsecCheckCategory::KillSwitch,
                passed: false,
                severity: OpsecSeverity::Blocking,
                detail: format!("Kill switch issues: {}", issues.join(", ")),
                remediation: "Ensure VPN is connected, iptables/nftables rules block non-VPN traffic, and default route points to tun0/wg0".to_string(),
                score_impact: -30,
            }
        }
    }

    /// Checks for clock skew that could reveal timezone/location.
    pub fn check_clock_skew(&self, input: &ClockSkewInput) -> OpsecCheckResult {
        let tz_matches = input.local_timezone == self.config.expected_timezone;
        let offset_ok =
            input.ntp_offset_ms.unsigned_abs() <= self.config.max_clock_offset_ms as u64;

        if tz_matches && offset_ok {
            OpsecCheckResult {
                category: OpsecCheckCategory::ClockSkew,
                passed: true,
                severity: OpsecSeverity::Info,
                detail: format!(
                    "Timezone {} matches expected, NTP offset {}ms within threshold",
                    input.local_timezone, input.ntp_offset_ms
                ),
                remediation: String::new(),
                score_impact: 0,
            }
        } else {
            let mut detail = String::new();
            if !tz_matches {
                detail.push_str(&format!(
                    "Timezone {} differs from expected {}. ",
                    input.local_timezone, self.config.expected_timezone
                ));
            }
            if !offset_ok {
                detail.push_str(&format!(
                    "NTP offset {}ms exceeds {}ms threshold.",
                    input.ntp_offset_ms, self.config.max_clock_offset_ms
                ));
            }

            OpsecCheckResult {
                category: OpsecCheckCategory::ClockSkew,
                passed: false,
                severity: if tz_matches {
                    OpsecSeverity::Warning
                } else {
                    OpsecSeverity::Critical
                },
                detail,
                remediation: format!(
                    "Set timezone to {}: timedatectl set-timezone {}. Sync NTP: ntpdate pool.ntp.org",
                    self.config.expected_timezone, self.config.expected_timezone
                ),
                score_impact: if tz_matches { -5 } else { -15 },
            }
        }
    }

    /// Checks MAC address randomization.
    pub fn check_mac_address(&self, input: &MacAddressInput) -> OpsecCheckResult {
        if input.is_randomized {
            OpsecCheckResult {
                category: OpsecCheckCategory::MacAddress,
                passed: true,
                severity: OpsecSeverity::Info,
                detail: format!("MAC {} is randomized", input.current_mac),
                remediation: String::new(),
                score_impact: 0,
            }
        } else {
            OpsecCheckResult {
                category: OpsecCheckCategory::MacAddress,
                passed: false,
                severity: OpsecSeverity::Warning,
                detail: format!(
                    "MAC {} is not randomized (vendor: {})",
                    input.current_mac,
                    input.vendor_oui.as_deref().unwrap_or("unknown")
                ),
                remediation: "Randomize MAC: macchanger -r eth0 or ip link set dev eth0 address XX:XX:XX:XX:XX:XX".to_string(),
                score_impact: -10,
            }
        }
    }

    /// Checks hostname for identifying information.
    pub fn check_hostname(&self, input: &HostnameInput) -> OpsecCheckResult {
        if !input.contains_real_name && !input.contains_org_name {
            OpsecCheckResult {
                category: OpsecCheckCategory::Hostname,
                passed: true,
                severity: OpsecSeverity::Info,
                detail: format!(
                    "Hostname '{}' does not contain identifying info",
                    input.hostname
                ),
                remediation: String::new(),
                score_impact: 0,
            }
        } else {
            let mut issues = Vec::new();
            if input.contains_real_name {
                issues.push("contains real name");
            }
            if input.contains_org_name {
                issues.push("contains organization name");
            }

            OpsecCheckResult {
                category: OpsecCheckCategory::Hostname,
                passed: false,
                severity: OpsecSeverity::Warning,
                detail: format!("Hostname '{}' {}", input.hostname, issues.join(" and ")),
                remediation: "Set hostname to generic value: hostnamectl set-hostname scan-node"
                    .to_string(),
                score_impact: -10,
            }
        }
    }

    /// Checks running processes for identifying applications.
    pub fn check_process_list(&self, input: &ProcessListInput) -> OpsecCheckResult {
        let mut found: Vec<String> = Vec::new();

        for proc in &input.running_processes {
            let lower = proc.to_lowercase();
            if IDENTIFYING_PROCESSES.iter().any(|p| lower.contains(p)) {
                found.push(proc.clone());
            }
            for custom in &self.config.custom_identifying_processes {
                if lower.contains(&custom.to_lowercase()) {
                    found.push(proc.clone());
                }
            }
        }

        found.sort();
        found.dedup();

        if found.is_empty() {
            OpsecCheckResult {
                category: OpsecCheckCategory::ProcessList,
                passed: true,
                severity: OpsecSeverity::Info,
                detail: "No identifying processes detected".to_string(),
                remediation: String::new(),
                score_impact: 0,
            }
        } else {
            OpsecCheckResult {
                category: OpsecCheckCategory::ProcessList,
                passed: false,
                severity: OpsecSeverity::Warning,
                detail: format!("Identifying processes running: {}", found.join(", ")),
                remediation: "Kill identifying processes before scanning: kill $(pgrep -f 'outlook|teams|slack')".to_string(),
                score_impact: -5 * found.len() as i32,
            }
        }
    }

    /// Runs all OPSEC checks and returns aggregate result with score.
    pub fn validate_all(
        &mut self,
        dns: &DnsLeakInput,
        webrtc: &WebRtcLeakInput,
        ipv6: &Ipv6LeakInput,
        kill_switch: &KillSwitchInput,
        clock: &ClockSkewInput,
        mac: &MacAddressInput,
        hostname: &HostnameInput,
        processes: &ProcessListInput,
    ) -> OpsecValidationResult {
        let checks = vec![
            self.check_dns_leak(dns),
            self.check_webrtc_leak(webrtc),
            self.check_ipv6_leak(ipv6),
            self.check_kill_switch(kill_switch),
            self.check_clock_skew(clock),
            self.check_mac_address(mac),
            self.check_hostname(hostname),
            self.check_process_list(processes),
        ];

        let max_score = 100_u32;
        let total_penalty: i32 = checks.iter().map(|c| c.score_impact).sum();
        let score = (max_score as i32 + total_penalty).max(0) as u32;

        let blocking_issues: Vec<String> = checks
            .iter()
            .filter(|c| !c.passed && c.severity == OpsecSeverity::Blocking)
            .map(|c| c.detail.clone())
            .collect();

        let has_blocking = !blocking_issues.is_empty() && self.config.block_on_critical;
        let below_threshold = score < self.config.min_score_threshold;
        let passed = !has_blocking && !below_threshold;

        let result = OpsecValidationResult {
            checks,
            score,
            max_score,
            passed,
            blocking_issues,
        };

        self.last_result = Some(result.clone());
        result
    }

    /// Returns the last validation result.
    pub fn last_result(&self) -> Option<&OpsecValidationResult> {
        self.last_result.as_ref()
    }

    /// Returns the configured minimum score threshold.
    pub fn threshold(&self) -> u32 {
        self.config.min_score_threshold
    }
}
