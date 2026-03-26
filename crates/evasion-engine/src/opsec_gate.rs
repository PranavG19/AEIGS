use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Individual OPSEC check types performed by the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OpsecCheck {
    DnsLeak,
    WebRtcLeak,
    Ipv6Suppression,
    ProcessListScan,
    HostnameCheck,
    ClockCheck,
    MacCheck,
}

impl fmt::Display for OpsecCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DnsLeak => write!(f, "dns-leak"),
            Self::WebRtcLeak => write!(f, "webrtc-leak"),
            Self::Ipv6Suppression => write!(f, "ipv6-suppression"),
            Self::ProcessListScan => write!(f, "process-list-scan"),
            Self::HostnameCheck => write!(f, "hostname-check"),
            Self::ClockCheck => write!(f, "clock-check"),
            Self::MacCheck => write!(f, "mac-check"),
        }
    }
}

/// Severity level for an OPSEC violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OpsecGateSeverity {
    Critical,
    Warning,
}

impl fmt::Display for OpsecGateSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "CRITICAL"),
            Self::Warning => write!(f, "WARNING"),
        }
    }
}

/// A single OPSEC violation detected by the gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsecViolation {
    pub check: OpsecCheck,
    pub description: String,
    pub severity: OpsecGateSeverity,
}

impl fmt::Display for OpsecViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {}: {}",
            self.severity, self.check, self.description
        )
    }
}

/// Aggregated OPSEC gate report after running all checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsecReport {
    pub checks_run: Vec<OpsecCheck>,
    pub violations: Vec<OpsecViolation>,
    pub passed: bool,
    pub timestamp_ms: u64,
}

/// Environment snapshot provided to the OPSEC gate for validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsecEnvironment {
    pub hostname: String,
    pub timezone: String,
    pub processes: Vec<String>,
    pub mac_address: String,
    pub has_ipv6: bool,
    pub dns_proxy_configured: bool,
}

impl Default for OpsecEnvironment {
    fn default() -> Self {
        Self {
            hostname: "localhost".to_string(),
            timezone: "UTC".to_string(),
            processes: Vec::new(),
            mac_address: "00:00:00:00:00:00".to_string(),
            has_ipv6: false,
            dns_proxy_configured: true,
        }
    }
}

const ANALYSIS_TOOL_SIGNATURES: &[&str] = &[
    "wireshark",
    "fiddler",
    "burpsuite",
    "tcpdump",
    "strace",
    "ida64",
    "x64dbg",
    "ghidra",
    "procmon",
];

const SUSPICIOUS_HOSTNAME_PATTERNS: &[&str] = &[
    "-pc",
    "-laptop",
    "-desktop",
    "-workstation",
    "macbook",
    "imac",
    "thinkpad",
    "dell-",
    "hp-",
    "lenovo-",
];

const VM_MAC_PREFIXES: &[&str] = &[
    "00:0c:29", "00:50:56", "00:1c:42", "08:00:27", "00:05:69", "00:03:ff", "00:15:5d", "52:54:00",
];

/// Mandatory pre-scan OPSEC hard gate that validates the operational
/// security posture of the scanning environment. All checks must pass
/// (no critical violations) before a scan proceeds.
pub struct OpsecGate;

impl OpsecGate {
    pub fn new() -> Self {
        Self
    }

    /// Runs all OPSEC checks against the provided environment.
    /// Returns `Ok(OpsecReport)` if no critical violations are found,
    /// or `Err(OpsecViolation)` with the first critical violation.
    pub fn check(&self, env: &OpsecEnvironment) -> Result<OpsecReport, OpsecViolation> {
        let mut violations = Vec::new();
        let checks_run = vec![
            OpsecCheck::DnsLeak,
            OpsecCheck::Ipv6Suppression,
            OpsecCheck::ProcessListScan,
            OpsecCheck::HostnameCheck,
            OpsecCheck::ClockCheck,
            OpsecCheck::MacCheck,
        ];

        if !env.dns_proxy_configured {
            violations.push(OpsecViolation {
                check: OpsecCheck::DnsLeak,
                description: "DNS proxy not configured; queries may leak to ISP resolver"
                    .to_string(),
                severity: OpsecGateSeverity::Critical,
            });
        }

        if let Some(v) = self.check_ipv6(env.has_ipv6) {
            violations.push(v);
        }

        let proc_violations = self.check_processes(&env.processes);
        violations.extend(proc_violations);

        if let Some(v) = self.check_hostname(&env.hostname) {
            violations.push(v);
        }

        if let Some(v) = self.check_timezone(&env.timezone) {
            violations.push(v);
        }

        if let Some(v) = self.check_mac_address(&env.mac_address) {
            violations.push(v);
        }

        let first_critical = violations
            .iter()
            .find(|v| v.severity == OpsecGateSeverity::Critical)
            .cloned();

        let passed = first_critical.is_none();
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let report = OpsecReport {
            checks_run,
            violations,
            passed,
            timestamp_ms,
        };

        match first_critical {
            Some(v) => Err(v),
            None => Ok(report),
        }
    }

    /// Checks the hostname for patterns that reveal identity or hardware.
    pub fn check_hostname(&self, hostname: &str) -> Option<OpsecViolation> {
        let lower = hostname.to_lowercase();

        for pattern in SUSPICIOUS_HOSTNAME_PATTERNS {
            if lower.contains(pattern) {
                return Some(OpsecViolation {
                    check: OpsecCheck::HostnameCheck,
                    description: format!(
                        "Hostname '{}' contains identifying pattern '{}'",
                        hostname, pattern
                    ),
                    severity: OpsecGateSeverity::Warning,
                });
            }
        }

        if lower.len() > 3
            && !lower.starts_with("localhost")
            && !lower.starts_with("scan-")
            && !lower.starts_with("node-")
            && lower.chars().any(|c| c.is_ascii_uppercase() || c == '-')
            && lower.chars().filter(|c| c.is_ascii_alphabetic()).count() > 5
        {
            let has_name_pattern =
                lower
                    .split(|c: char| c == '-' || c == '.' || c == '_')
                    .any(|segment| {
                        segment.len() >= 4 && segment.chars().all(|c| c.is_ascii_alphabetic())
                    });

            if has_name_pattern {
                return Some(OpsecViolation {
                    check: OpsecCheck::HostnameCheck,
                    description: format!(
                        "Hostname '{}' may contain personally identifying information",
                        hostname,
                    ),
                    severity: OpsecGateSeverity::Warning,
                });
            }
        }

        None
    }

    /// Checks the timezone string for non-UTC values that reveal geography.
    pub fn check_timezone(&self, tz: &str) -> Option<OpsecViolation> {
        let normalized = tz.trim().to_uppercase();
        if normalized == "UTC"
            || normalized == "GMT"
            || normalized == "UTC+0"
            || normalized == "UTC-0"
            || normalized == "GMT+0"
            || normalized == "GMT-0"
        {
            return None;
        }

        Some(OpsecViolation {
            check: OpsecCheck::ClockCheck,
            description: format!(
                "System timezone '{}' is not UTC; geographic location may be inferred",
                tz
            ),
            severity: OpsecGateSeverity::Critical,
        })
    }

    /// Checks the running process list for known analysis and forensic tools.
    pub fn check_processes(&self, processes: &[String]) -> Vec<OpsecViolation> {
        let mut violations = Vec::new();

        for proc in processes {
            if Self::is_analysis_tool(proc) {
                violations.push(OpsecViolation {
                    check: OpsecCheck::ProcessListScan,
                    description: format!("Analysis tool '{}' detected in process list", proc),
                    severity: OpsecGateSeverity::Warning,
                });
            }
        }

        violations
    }

    /// Checks the MAC address for known VM/hypervisor OUI prefixes.
    pub fn check_mac_address(&self, mac: &str) -> Option<OpsecViolation> {
        let normalized = mac.to_lowercase();

        for prefix in VM_MAC_PREFIXES {
            if normalized.starts_with(prefix) {
                return Some(OpsecViolation {
                    check: OpsecCheck::MacCheck,
                    description: format!(
                        "MAC address '{}' has VM/hypervisor OUI prefix '{}'",
                        mac, prefix
                    ),
                    severity: OpsecGateSeverity::Warning,
                });
            }
        }

        None
    }

    /// Checks whether IPv6 is enabled (potential leak vector).
    pub fn check_ipv6(&self, has_ipv6: bool) -> Option<OpsecViolation> {
        if has_ipv6 {
            Some(OpsecViolation {
                check: OpsecCheck::Ipv6Suppression,
                description: "IPv6 is enabled; traffic may bypass proxy and leak real address"
                    .to_string(),
                severity: OpsecGateSeverity::Critical,
            })
        } else {
            None
        }
    }

    /// Returns true if the process name matches a known analysis/forensic tool.
    pub fn is_analysis_tool(process: &str) -> bool {
        let lower = process.to_lowercase();
        ANALYSIS_TOOL_SIGNATURES
            .iter()
            .any(|sig| lower.contains(sig))
    }
}

impl Default for OpsecGate {
    fn default() -> Self {
        Self::new()
    }
}
