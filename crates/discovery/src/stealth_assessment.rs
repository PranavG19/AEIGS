use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

const SCANNER_USER_AGENTS: &[&str] = &[
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "gobuster",
    "dirbuster",
    "wfuzz",
    "ffuf",
    "burp",
    "zap",
    "nuclei",
    "feroxbuster",
    "httpx",
    "dalfox",
    "whatweb",
    "wpscan",
    "arachni",
    "skipfish",
    "w3af",
];

const SCANNER_PAYLOAD_SIGNATURES: &[&str] = &[
    "' OR '1'='1",
    "<script>alert(",
    "../../etc/passwd",
    "${jndi:ldap://",
    "{{7*7}}",
    "| whoami",
    "UNION SELECT",
    "%27%20OR%20",
    "1; DROP TABLE",
];

#[derive(Debug, Clone, PartialEq)]
pub struct StealthAssessmentResult {
    pub overall_score: f64,
    pub grade: StealthGrade,
    pub categories: StealthCategories,
    pub findings: Vec<StealthFinding>,
    pub recommendations: Vec<StealthRecommendation>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StealthCategories {
    pub request_pattern_score: f64,
    pub payload_detection_score: f64,
    pub timing_score: f64,
    pub ip_diversity_score: f64,
    pub header_stealth_score: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StealthGrade {
    Excellent,
    Good,
    Fair,
    Poor,
    Compromised,
}

impl std::fmt::Display for StealthGrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Excellent => write!(f, "Excellent"),
            Self::Good => write!(f, "Good"),
            Self::Fair => write!(f, "Fair"),
            Self::Poor => write!(f, "Poor"),
            Self::Compromised => write!(f, "Compromised"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StealthFinding {
    pub category: StealthCategory,
    pub severity: StealthSeverity,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StealthCategory {
    RequestPattern,
    PayloadDetection,
    TimingAnalysis,
    IpDiversity,
    HeaderStealth,
}

impl std::fmt::Display for StealthCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::RequestPattern => "Request Pattern",
            Self::PayloadDetection => "Payload Detection",
            Self::TimingAnalysis => "Timing Analysis",
            Self::IpDiversity => "IP Diversity",
            Self::HeaderStealth => "Header Stealth",
        };
        write!(f, "{name}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StealthSeverity {
    Info,
    Warning,
    Critical,
}

impl std::fmt::Display for StealthSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Info => "Info",
            Self::Warning => "Warning",
            Self::Critical => "Critical",
        };
        write!(f, "{name}")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StealthRecommendation {
    pub priority: RecommendationPriority,
    pub category: StealthCategory,
    pub action: String,
    pub impact: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RecommendationPriority {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RecommendationPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        };
        write!(f, "{name}")
    }
}

#[derive(Debug, Clone)]
pub struct ScanProfile {
    pub request_timestamps: Vec<Duration>,
    pub user_agents_used: Vec<String>,
    pub payloads_sent: Vec<String>,
    pub source_ips: Vec<IpAddr>,
    pub headers_sent: HashMap<String, String>,
    pub total_requests: usize,
    pub requests_per_second: f64,
    pub unique_paths_hit: usize,
}

impl Default for ScanProfile {
    fn default() -> Self {
        Self {
            request_timestamps: Vec::new(),
            user_agents_used: Vec::new(),
            payloads_sent: Vec::new(),
            source_ips: Vec::new(),
            headers_sent: HashMap::new(),
            total_requests: 0,
            requests_per_second: 0.0,
            unique_paths_hit: 0,
        }
    }
}

pub struct StealthAssessor;

impl std::fmt::Debug for StealthAssessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StealthAssessor").finish()
    }
}

impl Default for StealthAssessor {
    fn default() -> Self {
        Self::new()
    }
}

impl StealthAssessor {
    pub fn new() -> Self {
        Self
    }

    pub fn assess(&self, profile: &ScanProfile) -> StealthAssessmentResult {
        let mut findings = Vec::new();
        let mut recommendations = Vec::new();

        let rp = self.assess_request_patterns(profile, &mut findings, &mut recommendations);
        let pd = self.assess_payload_detection(profile, &mut findings, &mut recommendations);
        let tm = self.assess_timing(profile, &mut findings, &mut recommendations);
        let ip = self.assess_ip_diversity(profile, &mut findings, &mut recommendations);
        let hs = self.assess_header_stealth(profile, &mut findings, &mut recommendations);

        let overall_score =
            (rp * 0.20 + pd * 0.25 + tm * 0.25 + ip * 0.15 + hs * 0.15).clamp(0.0, 1.0);

        let grade = score_to_grade(overall_score);

        recommendations.sort_by(|a, b| b.priority.cmp(&a.priority));

        StealthAssessmentResult {
            overall_score,
            grade,
            categories: StealthCategories {
                request_pattern_score: rp,
                payload_detection_score: pd,
                timing_score: tm,
                ip_diversity_score: ip,
                header_stealth_score: hs,
            },
            findings,
            recommendations,
        }
    }

    fn assess_request_patterns(
        &self,
        profile: &ScanProfile,
        findings: &mut Vec<StealthFinding>,
        recommendations: &mut Vec<StealthRecommendation>,
    ) -> f64 {
        let mut score: f64 = 1.0;

        if profile.request_timestamps.len() >= 3 {
            let intervals = compute_intervals(&profile.request_timestamps);
            if let Some(regularity) = compute_regularity(&intervals) {
                if regularity > 0.9 {
                    score -= 0.4;
                    findings.push(StealthFinding {
                        category: StealthCategory::RequestPattern,
                        severity: StealthSeverity::Critical,
                        description: format!(
                            "Request timing is {:.0}% regular - easily flagged as automated",
                            regularity * 100.0
                        ),
                    });
                    recommendations.push(StealthRecommendation {
                        priority: RecommendationPriority::High,
                        category: StealthCategory::RequestPattern,
                        action: "Add random jitter (50-500ms) between requests".into(),
                        impact: "Reduces timing-based detection by IDS".into(),
                    });
                } else if regularity > 0.7 {
                    score -= 0.2;
                    findings.push(StealthFinding {
                        category: StealthCategory::RequestPattern,
                        severity: StealthSeverity::Warning,
                        description: format!(
                            "Request timing is {:.0}% regular - somewhat detectable",
                            regularity * 100.0
                        ),
                    });
                }
            }
        }

        if profile.total_requests > 50 && profile.unique_paths_hit > 0 {
            let ratio = profile.unique_paths_hit as f64 / profile.total_requests as f64;
            if ratio > 0.95 {
                score -= 0.2;
                findings.push(StealthFinding {
                    category: StealthCategory::RequestPattern,
                    severity: StealthSeverity::Warning,
                    description:
                        "Nearly every request hits a unique path - directory brute-force pattern"
                            .into(),
                });
                recommendations.push(StealthRecommendation {
                    priority: RecommendationPriority::Medium,
                    category: StealthCategory::RequestPattern,
                    action: "Interleave legitimate-looking navigation requests between probes"
                        .into(),
                    impact: "Makes request pattern resemble normal browsing".into(),
                });
            }
        }

        score.clamp(0.0, 1.0)
    }

    fn assess_payload_detection(
        &self,
        profile: &ScanProfile,
        findings: &mut Vec<StealthFinding>,
        recommendations: &mut Vec<StealthRecommendation>,
    ) -> f64 {
        let mut score: f64 = 1.0;

        if profile.payloads_sent.is_empty() {
            return score;
        }

        let mut flagged_count = 0;
        for payload in &profile.payloads_sent {
            let lower = payload.to_lowercase();
            for sig in SCANNER_PAYLOAD_SIGNATURES {
                if lower.contains(&sig.to_lowercase()) {
                    flagged_count += 1;
                    break;
                }
            }
        }

        if flagged_count > 0 {
            let ratio = flagged_count as f64 / profile.payloads_sent.len() as f64;
            score -= ratio * 0.6;

            let severity = if ratio > 0.5 {
                StealthSeverity::Critical
            } else {
                StealthSeverity::Warning
            };

            findings.push(StealthFinding {
                category: StealthCategory::PayloadDetection,
                severity,
                description: format!(
                    "{flagged_count}/{} payloads contain known scanner signatures",
                    profile.payloads_sent.len()
                ),
            });

            recommendations.push(StealthRecommendation {
                priority: RecommendationPriority::High,
                category: StealthCategory::PayloadDetection,
                action: "Use encoded/obfuscated payloads instead of raw attack strings".into(),
                impact: "Bypasses signature-based IDS detection".into(),
            });
        }

        score.clamp(0.0, 1.0)
    }

    fn assess_timing(
        &self,
        profile: &ScanProfile,
        findings: &mut Vec<StealthFinding>,
        recommendations: &mut Vec<StealthRecommendation>,
    ) -> f64 {
        let mut score: f64 = 1.0;

        if profile.requests_per_second > 100.0 {
            score -= 0.5;
            findings.push(StealthFinding {
                category: StealthCategory::TimingAnalysis,
                severity: StealthSeverity::Critical,
                description: format!(
                    "{:.0} req/sec is extremely aggressive - will trigger rate limiting",
                    profile.requests_per_second
                ),
            });
            recommendations.push(StealthRecommendation {
                priority: RecommendationPriority::Critical,
                category: StealthCategory::TimingAnalysis,
                action: "Reduce request rate to <10 req/sec with random delays".into(),
                impact: "Avoids rate limiting and automated blocking".into(),
            });
        } else if profile.requests_per_second > 50.0 {
            score -= 0.3;
            findings.push(StealthFinding {
                category: StealthCategory::TimingAnalysis,
                severity: StealthSeverity::Warning,
                description: format!(
                    "{:.0} req/sec is above normal browsing patterns",
                    profile.requests_per_second
                ),
            });
            recommendations.push(StealthRecommendation {
                priority: RecommendationPriority::Medium,
                category: StealthCategory::TimingAnalysis,
                action: "Throttle to 5-15 req/sec to blend with normal traffic".into(),
                impact: "Reduces likelihood of rate-based detection".into(),
            });
        } else if profile.requests_per_second > 20.0 {
            score -= 0.1;
            findings.push(StealthFinding {
                category: StealthCategory::TimingAnalysis,
                severity: StealthSeverity::Info,
                description: format!(
                    "{:.0} req/sec is slightly elevated but may pass",
                    profile.requests_per_second
                ),
            });
        }

        score.clamp(0.0, 1.0)
    }

    fn assess_ip_diversity(
        &self,
        profile: &ScanProfile,
        findings: &mut Vec<StealthFinding>,
        recommendations: &mut Vec<StealthRecommendation>,
    ) -> f64 {
        let mut score: f64 = 1.0;

        if profile.source_ips.is_empty() || profile.source_ips.len() == 1 {
            score -= 0.3;
            findings.push(StealthFinding {
                category: StealthCategory::IpDiversity,
                severity: StealthSeverity::Warning,
                description: "All traffic from a single IP - easy to block".into(),
            });
            recommendations.push(StealthRecommendation {
                priority: RecommendationPriority::Medium,
                category: StealthCategory::IpDiversity,
                action: "Rotate through multiple source IPs or use proxy rotation".into(),
                impact: "Makes IP-based blocking ineffective".into(),
            });
        } else {
            let diversity = compute_subnet_diversity(&profile.source_ips);
            if diversity < 0.3 {
                score -= 0.2;
                findings.push(StealthFinding {
                    category: StealthCategory::IpDiversity,
                    severity: StealthSeverity::Warning,
                    description: format!(
                        "All IPs from same /24 subnet (diversity={:.0}%) - correlated traffic",
                        diversity * 100.0
                    ),
                });
                recommendations.push(StealthRecommendation {
                    priority: RecommendationPriority::Medium,
                    category: StealthCategory::IpDiversity,
                    action: "Use IPs from different /16 subnets".into(),
                    impact: "Prevents subnet-based correlation".into(),
                });
            }
        }

        score.clamp(0.0, 1.0)
    }

    fn assess_header_stealth(
        &self,
        profile: &ScanProfile,
        findings: &mut Vec<StealthFinding>,
        recommendations: &mut Vec<StealthRecommendation>,
    ) -> f64 {
        let mut score: f64 = 1.0;

        for ua in &profile.user_agents_used {
            let lower = ua.to_lowercase();
            for scanner_sig in SCANNER_USER_AGENTS {
                if lower.contains(scanner_sig) {
                    score -= 0.4;
                    let truncated = if ua.len() > 60 {
                        &ua[..60]
                    } else {
                        ua.as_str()
                    };
                    findings.push(StealthFinding {
                        category: StealthCategory::HeaderStealth,
                        severity: StealthSeverity::Critical,
                        description: format!(
                            "User-Agent [{}] contains known scanner signature [{}]",
                            truncated, scanner_sig
                        ),
                    });
                    recommendations.push(StealthRecommendation {
                        priority: RecommendationPriority::Critical,
                        category: StealthCategory::HeaderStealth,
                        action: "Use a realistic browser User-Agent (Chrome/Firefox/Safari)".into(),
                        impact: "Prevents trivial UA-based scanner detection".into(),
                    });
                    break;
                }
            }
        }

        if profile.user_agents_used.len() == 1 && profile.total_requests > 100 {
            score -= 0.1;
            findings.push(StealthFinding {
                category: StealthCategory::HeaderStealth,
                severity: StealthSeverity::Info,
                description: "Single User-Agent for all requests - consider rotating".into(),
            });
        }

        let has_accept = profile.headers_sent.contains_key("accept")
            || profile.headers_sent.contains_key("Accept");
        if !has_accept {
            score -= 0.05;
            findings.push(StealthFinding {
                category: StealthCategory::HeaderStealth,
                severity: StealthSeverity::Info,
                description: "Missing Accept header - real browsers always send this".into(),
            });
        }

        let has_accept_lang = profile.headers_sent.contains_key("accept-language")
            || profile.headers_sent.contains_key("Accept-Language");
        if !has_accept_lang {
            score -= 0.05;
            findings.push(StealthFinding {
                category: StealthCategory::HeaderStealth,
                severity: StealthSeverity::Info,
                description: "Missing Accept-Language header - browser fingerprinting gap".into(),
            });
        }

        score.clamp(0.0, 1.0)
    }
}

pub(crate) fn score_to_grade(score: f64) -> StealthGrade {
    if score >= 0.85 {
        StealthGrade::Excellent
    } else if score >= 0.70 {
        StealthGrade::Good
    } else if score >= 0.50 {
        StealthGrade::Fair
    } else if score >= 0.30 {
        StealthGrade::Poor
    } else {
        StealthGrade::Compromised
    }
}

fn compute_intervals(timestamps: &[Duration]) -> Vec<f64> {
    timestamps
        .windows(2)
        .map(|w| (w[1].as_millis() as f64 - w[0].as_millis() as f64).abs())
        .collect()
}

pub(crate) fn compute_regularity(intervals: &[f64]) -> Option<f64> {
    if intervals.len() < 2 {
        return None;
    }

    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    if mean == 0.0 {
        return Some(1.0);
    }

    let variance =
        intervals.iter().map(|i| (i - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
    let cv = variance.sqrt() / mean;

    Some((1.0 - cv).clamp(0.0, 1.0))
}

pub(crate) fn compute_subnet_diversity(ips: &[IpAddr]) -> f64 {
    if ips.len() <= 1 {
        return 0.0;
    }

    let mut subnets: Vec<String> = Vec::new();
    for ip in ips {
        if let IpAddr::V4(v4) = ip {
            let o = v4.octets();
            subnets.push(format!("{}.{}.{}", o[0], o[1], o[2]));
        }
    }

    if subnets.is_empty() {
        return 0.0;
    }

    let total = subnets.len();
    subnets.sort();
    subnets.dedup();
    subnets.len() as f64 / total as f64
}
