use crate::identity_system::Identity;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Type of pattern a ban rule matches against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BanPatternType {
    /// Match against IP address pattern.
    Ip,
    /// Match against User-Agent string.
    UserAgent,
    /// Match against timing profile hash.
    TimingHash,
    /// Match against TLS fingerprint hash.
    TlsHash,
    /// Match against request URL+body pattern (regex).
    RequestPattern,
}

impl std::fmt::Display for BanPatternType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip => write!(f, "IP"),
            Self::UserAgent => write!(f, "UA"),
            Self::TimingHash => write!(f, "Timing"),
            Self::TlsHash => write!(f, "TLS"),
            Self::RequestPattern => write!(f, "ReqPattern"),
        }
    }
}

/// A ban rule created by Blue to block Red's identities or request patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanRule {
    /// Type of pattern this ban matches.
    pub pattern_type: BanPatternType,
    /// The pattern string (exact match, substring, CIDR range, or regex).
    pub pattern: String,
    /// Blue's confidence that this ban targets malicious activity (0.0–1.0).
    pub confidence: f64,
    /// Cycle this ban was created.
    pub created_cycle: usize,
    /// Number of Red requests this ban has caught.
    pub catch_count: usize,
    /// Last cycle this ban caught something.
    pub last_catch_cycle: usize,
}

impl BanRule {
    /// Create a new ban rule.
    pub fn new(pattern_type: BanPatternType, pattern: &str, confidence: f64, cycle: usize) -> Self {
        Self {
            pattern_type,
            pattern: pattern.to_string(),
            confidence: confidence.clamp(0.0, 1.0),
            created_cycle: cycle,
            catch_count: 0,
            last_catch_cycle: 0,
        }
    }

    /// Check if this ban matches the given identity.
    pub fn matches_identity(&self, identity: &Identity) -> bool {
        match self.pattern_type {
            BanPatternType::Ip => {
                ip_matches(&self.pattern, &identity.ip_pattern)
            }
            BanPatternType::UserAgent => {
                ua_matches(&self.pattern, &identity.user_agent)
            }
            BanPatternType::TimingHash => {
                timing_hash_matches(&self.pattern, &identity.timing_profile_hash)
            }
            BanPatternType::TlsHash => {
                self.pattern == identity.tls_fingerprint_hash
            }
            BanPatternType::RequestPattern => {
                // Request patterns don't match identities directly
                false
            }
        }
    }

    /// Check if this ban matches a request string (URL+body).
    pub fn matches_request(&self, request: &str) -> bool {
        match self.pattern_type {
            BanPatternType::RequestPattern => {
                if let Ok(re) = Regex::new(&self.pattern) {
                    re.is_match(request)
                } else {
                    request.contains(&self.pattern)
                }
            }
            _ => false,
        }
    }

    /// Record a catch (ban matched something).
    pub fn record_catch(&mut self, cycle: usize) {
        self.catch_count += 1;
        self.last_catch_cycle = cycle;
    }
}

/// Blue's ban system with budget enforcement, false positive checking, and auto-expiry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanSystem {
    /// All active ban rules.
    pub active_bans: Vec<BanRule>,
    /// Maximum new bans per cycle.
    pub max_bans_per_cycle: usize,
    /// Bans added in the current cycle (reset each cycle).
    pub bans_this_cycle: usize,
    /// Number of cycles a ban can go without catching before expiry.
    pub inactivity_expiry_cycles: usize,
    /// Total false positives incurred.
    pub total_false_positives: usize,
    /// Points penalty per false positive.
    pub false_positive_penalty: i64,
    /// Score adjustment from false positives.
    pub score_adjustment: i64,
}

impl BanSystem {
    /// Create a new ban system with default budgets.
    pub fn new() -> Self {
        Self {
            active_bans: Vec::new(),
            max_bans_per_cycle: 3,
            bans_this_cycle: 0,
            inactivity_expiry_cycles: 10,
            total_false_positives: 0,
            false_positive_penalty: 20,
            score_adjustment: 0,
        }
    }

    /// Reset the per-cycle ban counter (call at start of each cycle).
    pub fn new_cycle(&mut self) {
        self.bans_this_cycle = 0;
    }

    /// Remaining ban budget for the current cycle.
    pub fn remaining_budget(&self) -> usize {
        self.max_bans_per_cycle.saturating_sub(self.bans_this_cycle)
    }

    /// Attempt to add a ban. Returns Ok(()) if added, Err with reason if rejected.
    pub fn add_ban(&mut self, rule: BanRule) -> Result<(), String> {
        if self.bans_this_cycle >= self.max_bans_per_cycle {
            return Err(format!(
                "Ban budget exhausted: {}/{} bans used this cycle",
                self.bans_this_cycle, self.max_bans_per_cycle
            ));
        }

        // False positive check: test if ban would block /health endpoint
        if self.would_block_health(&rule) {
            self.total_false_positives += 1;
            self.score_adjustment -= self.false_positive_penalty;
            return Err(format!(
                "Ban rejected: pattern '{}' matches /health endpoint (false positive, -{}pts)",
                rule.pattern, self.false_positive_penalty
            ));
        }

        // Check for duplicate bans
        if self.active_bans.iter().any(|b| {
            b.pattern_type == rule.pattern_type && b.pattern == rule.pattern
        }) {
            return Err(format!(
                "Duplicate ban: {} pattern '{}' already active",
                rule.pattern_type, rule.pattern
            ));
        }

        self.bans_this_cycle += 1;
        self.active_bans.push(rule);
        Ok(())
    }

    /// Check if a ban would block the /health endpoint (false positive).
    fn would_block_health(&self, rule: &BanRule) -> bool {
        match rule.pattern_type {
            BanPatternType::RequestPattern => {
                rule.matches_request("/health")
                    || rule.matches_request("GET /health HTTP/1.1")
            }
            // Identity-based bans can't block /health
            _ => false,
        }
    }

    /// Check if Red's identity is banned. Returns the matching ban rule if so.
    pub fn check_identity_banned(&self, identity: &Identity) -> Option<&BanRule> {
        self.active_bans.iter().find(|ban| ban.matches_identity(identity))
    }

    /// Check all bans against Red's request. Returns all matching bans.
    pub fn check_request_banned(&self, request: &str) -> Vec<&BanRule> {
        self.active_bans
            .iter()
            .filter(|ban| ban.matches_request(request))
            .collect()
    }

    /// Record catches for all bans that match the given identity.
    pub fn record_identity_catches(&mut self, identity: &Identity, cycle: usize) -> usize {
        let mut count = 0;
        for ban in &mut self.active_bans {
            if ban.matches_identity(identity) {
                ban.record_catch(cycle);
                count += 1;
            }
        }
        count
    }

    /// Record catches for all bans that match the given request.
    pub fn record_request_catches(&mut self, request: &str, cycle: usize) -> usize {
        let mut count = 0;
        for ban in &mut self.active_bans {
            if ban.matches_request(request) {
                ban.record_catch(cycle);
                count += 1;
            }
        }
        count
    }

    /// Expire bans that haven't caught anything for `inactivity_expiry_cycles` cycles.
    pub fn expire_inactive_bans(&mut self, current_cycle: usize) -> usize {
        let threshold = self.inactivity_expiry_cycles;
        let before = self.active_bans.len();
        self.active_bans.retain(|ban| {
            if ban.catch_count == 0 {
                // Never caught anything — expire if old enough
                current_cycle.saturating_sub(ban.created_cycle) < threshold
            } else {
                // Has caught before — expire if inactive long enough
                current_cycle.saturating_sub(ban.last_catch_cycle) < threshold
            }
        });
        before - self.active_bans.len()
    }

    /// Generate a briefing section listing all active bans for Blue's prompt.
    pub fn ban_briefing(&self) -> String {
        let mut briefing = String::new();
        briefing.push_str("### Active Bans\n\n");

        if self.active_bans.is_empty() {
            briefing.push_str("No active bans.\n\n");
            return briefing;
        }

        for (i, ban) in self.active_bans.iter().enumerate() {
            briefing.push_str(&format!(
                "{}. [{}] `{}` (confidence: {:.0}%, catches: {}, created cycle {})\n",
                i + 1,
                ban.pattern_type,
                ban.pattern,
                ban.confidence * 100.0,
                ban.catch_count,
                ban.created_cycle,
            ));
        }
        briefing.push('\n');
        briefing.push_str(&format!(
            "**Budget:** {}/{} bans remaining this cycle\n\n",
            self.remaining_budget(),
            self.max_bans_per_cycle,
        ));

        briefing
    }

    /// Total number of active bans.
    pub fn active_ban_count(&self) -> usize {
        self.active_bans.len()
    }

    /// Total catches across all bans.
    pub fn total_catches(&self) -> usize {
        self.active_bans.iter().map(|b| b.catch_count).sum()
    }
}

impl Default for BanSystem {
    fn default() -> Self {
        Self::new()
    }
}

/// IP matching: exact match, or CIDR-like prefix match.
fn ip_matches(ban_pattern: &str, identity_ip: &str) -> bool {
    // Exact match
    if ban_pattern == identity_ip {
        return true;
    }
    // Prefix/subnet match: "10.50." matches "10.50.123.x"
    if ban_pattern.ends_with('.') && identity_ip.starts_with(ban_pattern) {
        return true;
    }
    // Substring match for partial patterns
    identity_ip.contains(ban_pattern)
}

/// User-Agent matching: exact or substring.
fn ua_matches(ban_pattern: &str, identity_ua: &str) -> bool {
    if ban_pattern == identity_ua {
        return true;
    }
    identity_ua.contains(ban_pattern)
}

/// Timing hash matching: exact or ±10% tolerance on the numeric hash value.
fn timing_hash_matches(ban_pattern: &str, identity_hash: &str) -> bool {
    if ban_pattern == identity_hash {
        return true;
    }
    // Try numeric comparison with 10% tolerance
    if let (Ok(ban_val), Ok(id_val)) = (
        u64::from_str_radix(ban_pattern, 16),
        u64::from_str_radix(identity_hash, 16),
    ) {
        let tolerance = ban_val / 10;
        let lower = ban_val.saturating_sub(tolerance);
        let upper = ban_val.saturating_add(tolerance);
        return id_val >= lower && id_val <= upper;
    }
    false
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "ban_system_test.rs"]
mod ban_system_test;
