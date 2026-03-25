use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// IP burn status indicating detection/blocking history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BurnStatus {
    /// Clean — no known blocks or detections.
    Clean,
    /// Warm — minor detections, still usable with caution.
    Warm,
    /// Hot — actively flagged by multiple services.
    Hot,
    /// Burned — blocked everywhere, unusable.
    Burned,
}

impl fmt::Display for BurnStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clean => write!(f, "Clean"),
            Self::Warm => write!(f, "Warm"),
            Self::Hot => write!(f, "Hot"),
            Self::Burned => write!(f, "Burned"),
        }
    }
}

/// ISP/hosting classification for scanning infrastructure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IspClassification {
    /// Major residential ISP — least suspicious.
    Residential,
    /// Mobile carrier — moderate trust.
    Mobile,
    /// Commercial/business ISP.
    Business,
    /// Cloud hosting provider (AWS, GCP, Azure) — commonly flagged.
    CloudHosting,
    /// Budget VPS/hosting — frequently abused.
    BudgetVps,
    /// Known proxy/VPN provider — usually blocked.
    ProxyVpn,
    /// Tor exit node — blocked by most services.
    TorExit,
    /// Data center with unknown reputation.
    DataCenter,
    /// Educational/research network.
    Education,
    /// Government network.
    Government,
}

impl IspClassification {
    /// Base reputation score modifier for this ISP type (0.0 = worst, 1.0 = best).
    pub fn base_reputation(&self) -> f64 {
        match self {
            Self::Residential => 0.95,
            Self::Mobile => 0.85,
            Self::Business => 0.80,
            Self::Education => 0.75,
            Self::Government => 0.70,
            Self::DataCenter => 0.50,
            Self::CloudHosting => 0.40,
            Self::BudgetVps => 0.25,
            Self::ProxyVpn => 0.15,
            Self::TorExit => 0.05,
        }
    }

    pub fn all() -> &'static [IspClassification] {
        &[
            Self::Residential,
            Self::Mobile,
            Self::Business,
            Self::CloudHosting,
            Self::BudgetVps,
            Self::ProxyVpn,
            Self::TorExit,
            Self::DataCenter,
            Self::Education,
            Self::Government,
        ]
    }
}

impl fmt::Display for IspClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Residential => write!(f, "Residential"),
            Self::Mobile => write!(f, "Mobile"),
            Self::Business => write!(f, "Business"),
            Self::CloudHosting => write!(f, "Cloud Hosting"),
            Self::BudgetVps => write!(f, "Budget VPS"),
            Self::ProxyVpn => write!(f, "Proxy/VPN"),
            Self::TorExit => write!(f, "Tor Exit"),
            Self::DataCenter => write!(f, "Data Center"),
            Self::Education => write!(f, "Education"),
            Self::Government => write!(f, "Government"),
        }
    }
}

/// Geographic region for IP diversity scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpGeoRegion {
    NorthAmerica,
    Europe,
    AsiaPacific,
    SouthAmerica,
    MiddleEast,
    Africa,
    Oceania,
}

impl IpGeoRegion {
    pub fn all() -> &'static [IpGeoRegion] {
        &[
            Self::NorthAmerica,
            Self::Europe,
            Self::AsiaPacific,
            Self::SouthAmerica,
            Self::MiddleEast,
            Self::Africa,
            Self::Oceania,
        ]
    }
}

impl fmt::Display for IpGeoRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NorthAmerica => write!(f, "North America"),
            Self::Europe => write!(f, "Europe"),
            Self::AsiaPacific => write!(f, "Asia-Pacific"),
            Self::SouthAmerica => write!(f, "South America"),
            Self::MiddleEast => write!(f, "Middle East"),
            Self::Africa => write!(f, "Africa"),
            Self::Oceania => write!(f, "Oceania"),
        }
    }
}

/// Blocklist hit record for an IP address.
#[derive(Debug, Clone)]
pub struct BlocklistHit {
    pub list_name: String,
    pub category: BlocklistCategory,
    pub first_seen_epoch: u64,
    pub last_seen_epoch: u64,
    pub severity: u8,
}

/// Blocklist category classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlocklistCategory {
    SpamSource,
    Malware,
    BotnetC2,
    BruteForce,
    WebAttack,
    PortScanning,
    Phishing,
    DdosSource,
    OpenProxy,
    TorNode,
}

impl fmt::Display for BlocklistCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SpamSource => write!(f, "Spam Source"),
            Self::Malware => write!(f, "Malware"),
            Self::BotnetC2 => write!(f, "Botnet C2"),
            Self::BruteForce => write!(f, "Brute Force"),
            Self::WebAttack => write!(f, "Web Attack"),
            Self::PortScanning => write!(f, "Port Scanning"),
            Self::Phishing => write!(f, "Phishing"),
            Self::DdosSource => write!(f, "DDoS Source"),
            Self::OpenProxy => write!(f, "Open Proxy"),
            Self::TorNode => write!(f, "Tor Node"),
        }
    }
}

/// A tracked IP address with full reputation metadata.
#[derive(Debug, Clone)]
pub struct TrackedIp {
    pub address: Ipv4Addr,
    pub isp: IspClassification,
    pub region: IpGeoRegion,
    pub burn_status: BurnStatus,
    pub reputation_score: f64,
    pub blocklist_hits: Vec<BlocklistHit>,
    pub total_requests_sent: u64,
    pub total_blocks_received: u64,
    pub last_used_epoch: u64,
    pub cooldown_until_epoch: Option<u64>,
}

impl TrackedIp {
    /// Calculate block rate as fraction of total requests.
    pub fn block_rate(&self) -> f64 {
        if self.total_requests_sent == 0 {
            return 0.0;
        }
        self.total_blocks_received as f64 / self.total_requests_sent as f64
    }

    /// Check if the IP is currently in cooldown.
    pub fn is_in_cooldown(&self) -> bool {
        if let Some(until) = self.cooldown_until_epoch {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now < until
        } else {
            false
        }
    }

    /// Check if the IP is usable (not burned and not in cooldown).
    pub fn is_usable(&self) -> bool {
        self.burn_status != BurnStatus::Burned && !self.is_in_cooldown()
    }
}

/// IP rotation recommendation.
#[derive(Debug, Clone)]
pub struct RotationRecommendation {
    pub current_ip: Ipv4Addr,
    pub action: RotationAction,
    pub reason: String,
    pub suggested_cooldown: Option<Duration>,
    pub replacement_criteria: Vec<String>,
}

/// Recommended action for an IP in rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationAction {
    /// Continue using — reputation is good.
    Continue,
    /// Reduce request rate to avoid detection.
    ThrottleDown,
    /// Place in cooldown for specified duration.
    Cooldown,
    /// Rotate to a different IP immediately.
    RotateNow,
    /// Permanently retire this IP.
    Retire,
}

impl fmt::Display for RotationAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Continue => write!(f, "Continue"),
            Self::ThrottleDown => write!(f, "Throttle Down"),
            Self::Cooldown => write!(f, "Cooldown"),
            Self::RotateNow => write!(f, "Rotate Now"),
            Self::Retire => write!(f, "Retire"),
        }
    }
}

/// Geo-diversity scoring result for an IP pool.
#[derive(Debug, Clone)]
pub struct GeoDiversityScore {
    pub total_ips: usize,
    pub regions_covered: usize,
    pub region_distribution: HashMap<IpGeoRegion, usize>,
    pub diversity_score: f64,
    pub recommendations: Vec<String>,
}

/// IP reputation tracking and rotation management system.
#[derive(Debug)]
pub struct IpReputationChecker {
    tracked_ips: Vec<TrackedIp>,
    burn_threshold_block_rate: f64,
    hot_threshold_block_rate: f64,
    warm_threshold_block_rate: f64,
    max_blocklist_hits_before_burn: usize,
    cooldown_base_duration_secs: u64,
}

impl Default for IpReputationChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl IpReputationChecker {
    pub fn new() -> Self {
        Self {
            tracked_ips: Vec::new(),
            burn_threshold_block_rate: 0.50,
            hot_threshold_block_rate: 0.25,
            warm_threshold_block_rate: 0.10,
            max_blocklist_hits_before_burn: 5,
            cooldown_base_duration_secs: 3600,
        }
    }

    pub fn with_burn_threshold(mut self, rate: f64) -> Self {
        self.burn_threshold_block_rate = rate.clamp(0.0, 1.0);
        self
    }

    pub fn with_cooldown_duration(mut self, secs: u64) -> Self {
        self.cooldown_base_duration_secs = secs;
        self
    }

    /// Register a new IP for tracking.
    pub fn track_ip(&mut self, address: Ipv4Addr, isp: IspClassification, region: IpGeoRegion) {
        if self.tracked_ips.iter().any(|t| t.address == address) {
            return;
        }
        self.tracked_ips.push(TrackedIp {
            address,
            isp,
            region,
            burn_status: BurnStatus::Clean,
            reputation_score: isp.base_reputation(),
            blocklist_hits: Vec::new(),
            total_requests_sent: 0,
            total_blocks_received: 0,
            last_used_epoch: 0,
            cooldown_until_epoch: None,
        });
    }

    /// Record that requests were sent from an IP.
    pub fn record_requests(&mut self, address: Ipv4Addr, sent: u64, blocked: u64) {
        if let Some(ip) = self.tracked_ips.iter_mut().find(|t| t.address == address) {
            ip.total_requests_sent += sent;
            ip.total_blocks_received += blocked;
            ip.last_used_epoch = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.recalculate_status(address);
        }
    }

    /// Record a blocklist hit for an IP.
    pub fn record_blocklist_hit(&mut self, address: Ipv4Addr, hit: BlocklistHit) {
        if let Some(ip) = self.tracked_ips.iter_mut().find(|t| t.address == address) {
            ip.blocklist_hits.push(hit);
            self.recalculate_status(address);
        }
    }

    fn recalculate_status(&mut self, address: Ipv4Addr) {
        if let Some(ip) = self.tracked_ips.iter_mut().find(|t| t.address == address) {
            let block_rate = ip.block_rate();
            let blocklist_count = ip.blocklist_hits.len();

            ip.burn_status = if block_rate >= self.burn_threshold_block_rate
                || blocklist_count >= self.max_blocklist_hits_before_burn
            {
                BurnStatus::Burned
            } else if block_rate >= self.hot_threshold_block_rate || blocklist_count >= 3 {
                BurnStatus::Hot
            } else if block_rate >= self.warm_threshold_block_rate || blocklist_count >= 1 {
                BurnStatus::Warm
            } else {
                BurnStatus::Clean
            };

            let isp_base = ip.isp.base_reputation();
            let block_penalty = block_rate * 0.5;
            let blocklist_penalty = (blocklist_count as f64 * 0.1).min(0.5);
            ip.reputation_score = (isp_base - block_penalty - blocklist_penalty).clamp(0.0, 1.0);
        }
    }

    /// Get rotation recommendation for a specific IP.
    pub fn rotation_recommendation(&self, address: Ipv4Addr) -> Option<RotationRecommendation> {
        let ip = self.tracked_ips.iter().find(|t| t.address == address)?;

        let (action, reason, cooldown) = match ip.burn_status {
            BurnStatus::Burned => (
                RotationAction::Retire,
                format!(
                    "IP {address} is burned: block rate {:.1}%, {} blocklist hits",
                    ip.block_rate() * 100.0,
                    ip.blocklist_hits.len()
                ),
                None,
            ),
            BurnStatus::Hot => (
                RotationAction::RotateNow,
                format!(
                    "IP {address} is hot: block rate {:.1}%, rotate immediately",
                    ip.block_rate() * 100.0
                ),
                Some(Duration::from_secs(self.cooldown_base_duration_secs * 4)),
            ),
            BurnStatus::Warm => {
                if ip.block_rate() > self.warm_threshold_block_rate * 1.5 {
                    (
                        RotationAction::Cooldown,
                        format!(
                            "IP {address} warming up: {:.1}% blocks, needs rest",
                            ip.block_rate() * 100.0
                        ),
                        Some(Duration::from_secs(self.cooldown_base_duration_secs)),
                    )
                } else {
                    (
                        RotationAction::ThrottleDown,
                        format!("IP {address} is warm: reduce request rate"),
                        None,
                    )
                }
            }
            BurnStatus::Clean => (
                RotationAction::Continue,
                format!(
                    "IP {address} is clean: reputation {:.2}",
                    ip.reputation_score
                ),
                None,
            ),
        };

        let mut criteria = Vec::new();
        if action == RotationAction::RotateNow || action == RotationAction::Retire {
            criteria.push("Different ISP type than current".into());
            criteria.push("Different geographic region".into());
            criteria.push(format!("Reputation score > {:.2}", 0.7));
            criteria.push("No existing blocklist hits".into());
        }

        Some(RotationRecommendation {
            current_ip: address,
            action,
            reason,
            suggested_cooldown: cooldown,
            replacement_criteria: criteria,
        })
    }

    /// Calculate geo-diversity score for the current IP pool.
    pub fn geo_diversity_score(&self) -> GeoDiversityScore {
        let mut region_counts: HashMap<IpGeoRegion, usize> = HashMap::new();
        for ip in &self.tracked_ips {
            *region_counts.entry(ip.region).or_insert(0) += 1;
        }

        let total = self.tracked_ips.len();
        let regions_covered = region_counts.len();
        let total_regions = IpGeoRegion::all().len();

        let diversity = if total == 0 {
            0.0
        } else {
            let coverage = regions_covered as f64 / total_regions as f64;
            let evenness = if regions_covered > 0 {
                let expected = total as f64 / regions_covered as f64;
                let variance: f64 = region_counts
                    .values()
                    .map(|&c| {
                        let diff = c as f64 - expected;
                        diff * diff
                    })
                    .sum::<f64>()
                    / regions_covered as f64;
                let max_variance = expected * expected;
                if max_variance > 0.0 {
                    1.0 - (variance / max_variance).min(1.0)
                } else {
                    1.0
                }
            } else {
                0.0
            };
            coverage * 0.6 + evenness * 0.4
        };

        let mut recommendations = Vec::new();
        for region in IpGeoRegion::all() {
            if !region_counts.contains_key(region) {
                recommendations.push(format!("Add IPs in {region} for better diversity"));
            }
        }
        if let Some((&max_region, &max_count)) = region_counts.iter().max_by_key(|(_, c)| *c)
            && total > 0
            && max_count as f64 / total as f64 > 0.5
        {
            recommendations.push(format!(
                "Rebalance: {max_region} has {:.0}% of IPs",
                max_count as f64 / total as f64 * 100.0
            ));
        }

        GeoDiversityScore {
            total_ips: total,
            regions_covered,
            region_distribution: region_counts,
            diversity_score: diversity,
            recommendations,
        }
    }

    /// Get ISP classification distribution for the pool.
    pub fn isp_distribution(&self) -> HashMap<IspClassification, usize> {
        let mut dist = HashMap::new();
        for ip in &self.tracked_ips {
            *dist.entry(ip.isp).or_insert(0) += 1;
        }
        dist
    }

    /// Get all tracked IPs sorted by reputation score (best first).
    pub fn ranked_ips(&self) -> Vec<&TrackedIp> {
        let mut sorted: Vec<_> = self.tracked_ips.iter().collect();
        sorted.sort_by(|a, b| b.reputation_score.partial_cmp(&a.reputation_score).unwrap());
        sorted
    }

    /// Get usable IPs (not burned, not in cooldown) sorted by reputation.
    pub fn usable_ips(&self) -> Vec<&TrackedIp> {
        let mut usable: Vec<_> = self
            .tracked_ips
            .iter()
            .filter(|ip| ip.is_usable())
            .collect();
        usable.sort_by(|a, b| b.reputation_score.partial_cmp(&a.reputation_score).unwrap());
        usable
    }

    /// Get burned IPs that should be retired.
    pub fn burned_ips(&self) -> Vec<&TrackedIp> {
        self.tracked_ips
            .iter()
            .filter(|ip| ip.burn_status == BurnStatus::Burned)
            .collect()
    }

    /// Get all tracked IPs.
    pub fn all_tracked(&self) -> &[TrackedIp] {
        &self.tracked_ips
    }

    /// Summarize pool health.
    pub fn pool_health_summary(&self) -> PoolHealthSummary {
        let total = self.tracked_ips.len();
        let clean = self
            .tracked_ips
            .iter()
            .filter(|ip| ip.burn_status == BurnStatus::Clean)
            .count();
        let warm = self
            .tracked_ips
            .iter()
            .filter(|ip| ip.burn_status == BurnStatus::Warm)
            .count();
        let hot = self
            .tracked_ips
            .iter()
            .filter(|ip| ip.burn_status == BurnStatus::Hot)
            .count();
        let burned = self
            .tracked_ips
            .iter()
            .filter(|ip| ip.burn_status == BurnStatus::Burned)
            .count();
        let avg_reputation = if total > 0 {
            self.tracked_ips
                .iter()
                .map(|ip| ip.reputation_score)
                .sum::<f64>()
                / total as f64
        } else {
            0.0
        };

        PoolHealthSummary {
            total_ips: total,
            clean_count: clean,
            warm_count: warm,
            hot_count: hot,
            burned_count: burned,
            average_reputation: avg_reputation,
            usable_percentage: if total > 0 {
                (total - burned) as f64 / total as f64 * 100.0
            } else {
                0.0
            },
        }
    }
}

/// Summary of IP pool health metrics.
#[derive(Debug, Clone)]
pub struct PoolHealthSummary {
    pub total_ips: usize,
    pub clean_count: usize,
    pub warm_count: usize,
    pub hot_count: usize,
    pub burned_count: usize,
    pub average_reputation: f64,
    pub usable_percentage: f64,
}
