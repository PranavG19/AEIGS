use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A single Red team identity with unique network fingerprint characteristics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Identity {
    /// Unique identifier for this identity.
    pub id: String,
    /// Simulated IP pattern (e.g., "10.0.1.x" or "192.168.3.x").
    pub ip_pattern: String,
    /// User-Agent string for this identity.
    pub user_agent: String,
    /// Hash of the timing profile (inter-request-time distribution).
    pub timing_profile_hash: String,
    /// Hash of the TLS fingerprint (JA3-style).
    pub tls_fingerprint_hash: String,
    /// Whether this identity is still usable (not banned by Blue).
    pub active: bool,
}

impl Identity {
    /// Generate a new random identity with the given index.
    pub fn generate(index: usize) -> Self {
        let mut rng = rand::thread_rng();
        let subnet: u8 = rng.random_range(1..=254);
        let ua_pool = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 Safari/17.2",
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0.0.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Safari/604.1",
            "Mozilla/5.0 (Linux; Android 14) Chrome/120.0.6099.43 Mobile",
            "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) Safari/605.1.15",
            "curl/8.4.0",
            "python-requests/2.31.0",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Opera/9.80 (Windows NT 6.1) Presto/2.12.388 Version/12.18",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) Gecko/20100101 Firefox/120.0",
        ];
        let ua_idx = (index + rng.random_range(0..ua_pool.len())) % ua_pool.len();
        let timing_hash: u64 = rng.random();
        let tls_hash: u64 = rng.random();

        Self {
            id: format!("red-{index:03}-{:04x}", rng.random::<u16>()),
            ip_pattern: format!("10.{subnet}.{}.x", rng.random_range(1..=254)),
            user_agent: ua_pool[ua_idx].to_string(),
            timing_profile_hash: format!("{timing_hash:016x}"),
            tls_fingerprint_hash: format!("{tls_hash:016x}"),
            active: true,
        }
    }

    /// Burn this identity — mark it permanently inactive.
    pub fn burn(&mut self) {
        self.active = false;
    }
}

/// Pool of Red team identities with rotation and burn tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityPool {
    /// All identities ever created (active + burned).
    pub identities: Vec<Identity>,
    /// Set of burned identity IDs for fast lookup.
    pub burned_ids: HashSet<String>,
    /// Index of the current active identity being used.
    pub current_index: usize,
    /// Total flags captured across all identities.
    pub total_flags: usize,
    /// Total identities burned across all time.
    pub total_burned: usize,
    /// Number of identity forge operations performed.
    pub forge_count: usize,
    /// Next generation index for new identities.
    next_gen_index: usize,
}

impl IdentityPool {
    /// Create a new pool with `initial_count` random identities.
    pub fn new(initial_count: usize) -> Self {
        let identities: Vec<Identity> = (0..initial_count).map(Identity::generate).collect();
        Self {
            identities,
            burned_ids: HashSet::new(),
            current_index: 0,
            total_flags: 0,
            total_burned: 0,
            forge_count: 0,
            next_gen_index: initial_count,
        }
    }

    /// Get the currently active identity, if any.
    pub fn current_identity(&self) -> Option<&Identity> {
        self.identities
            .get(self.current_index)
            .filter(|id| id.active)
    }

    /// Get a list of all active (non-burned) identities.
    pub fn active_identities(&self) -> Vec<&Identity> {
        self.identities.iter().filter(|id| id.active).collect()
    }

    /// Count of remaining active identities.
    pub fn active_count(&self) -> usize {
        self.identities.iter().filter(|id| id.active).count()
    }

    /// Get all burned identities for Red's briefing.
    pub fn burned_identities(&self) -> Vec<&Identity> {
        self.identities.iter().filter(|id| !id.active).collect()
    }

    /// Record a flag capture on the current identity.
    pub fn record_flag_capture(&mut self) {
        self.total_flags += 1;
    }

    /// Burn an identity by its ID. Returns true if the identity was found and burned.
    pub fn burn_identity(&mut self, identity_id: &str) -> bool {
        if self.burned_ids.contains(identity_id) {
            return false;
        }
        if let Some(identity) = self.identities.iter_mut().find(|id| id.id == identity_id) {
            if identity.active {
                identity.burn();
                self.burned_ids.insert(identity_id.to_string());
                self.total_burned += 1;
                // If we burned the current identity, rotate
                if self.identities.get(self.current_index).map(|id| &id.id)
                    == Some(&identity_id.to_string())
                {
                    self.rotate_to_next_active();
                }
                return true;
            }
        }
        false
    }

    /// Burn the currently active identity and rotate to the next.
    pub fn burn_current(&mut self) -> bool {
        if let Some(id_str) = self.current_identity().map(|id| id.id.clone()) {
            self.burn_identity(&id_str)
        } else {
            false
        }
    }

    /// Rotate to the next available active identity.
    /// Returns true if an active identity was found.
    pub fn rotate_to_next_active(&mut self) -> bool {
        let len = self.identities.len();
        for offset in 1..=len {
            let idx = (self.current_index + offset) % len;
            if self.identities[idx].active {
                self.current_index = idx;
                return true;
            }
        }
        false
    }

    /// Check whether all identities are burned (triggers forge mode).
    pub fn all_burned(&self) -> bool {
        self.active_count() == 0
    }

    /// Forge new identities when all existing ones are burned.
    /// Generates `count` new identities with NO overlap with any burned identity.
    pub fn forge_new_identities(&mut self, count: usize) {
        let burned_ips: HashSet<String> = self
            .identities
            .iter()
            .filter(|id| !id.active)
            .map(|id| id.ip_pattern.clone())
            .collect();
        let burned_uas: HashSet<String> = self
            .identities
            .iter()
            .filter(|id| !id.active)
            .map(|id| id.user_agent.clone())
            .collect();

        let mut new_identities = Vec::new();
        let mut attempts = 0;
        while new_identities.len() < count && attempts < count * 20 {
            let candidate = Identity::generate(self.next_gen_index);
            self.next_gen_index += 1;
            attempts += 1;

            // Ensure no overlap with burned identities
            if burned_ips.contains(&candidate.ip_pattern)
                || burned_uas.contains(&candidate.user_agent)
            {
                continue;
            }
            new_identities.push(candidate);
        }

        self.current_index = self.identities.len();
        self.identities.extend(new_identities);
        self.forge_count += 1;
    }

    /// Identity efficiency metric: flags captured per identity burned.
    pub fn identity_efficiency(&self) -> f64 {
        if self.total_burned == 0 {
            return self.total_flags as f64;
        }
        self.total_flags as f64 / self.total_burned as f64
    }

    /// Generate a briefing section describing the current identity state.
    pub fn identity_briefing(&self) -> String {
        let mut briefing = String::new();
        briefing.push_str("### Identity Status\n\n");

        if let Some(current) = self.current_identity() {
            briefing.push_str(&format!("**Current Identity:** {}\n", current.id));
            briefing.push_str(&format!("- IP pattern: `{}`\n", current.ip_pattern));
            briefing.push_str(&format!("- User-Agent: `{}`\n", current.user_agent));
            briefing.push_str(&format!(
                "- TLS fingerprint: `{}`\n",
                current.tls_fingerprint_hash
            ));
            briefing.push_str(&format!(
                "- Timing profile: `{}`\n\n",
                current.timing_profile_hash
            ));
        } else {
            briefing.push_str("**WARNING:** No active identities. Forge mode required.\n\n");
        }

        briefing.push_str(&format!(
            "**Active identities remaining:** {}/{}\n",
            self.active_count(),
            self.identities.len()
        ));
        briefing.push_str(&format!(
            "**Identity efficiency:** {:.2} flags/identity burned\n\n",
            self.identity_efficiency()
        ));

        let burned = self.burned_identities();
        if !burned.is_empty() {
            briefing.push_str("**Burned identities (NEVER use these):**\n");
            for id in &burned {
                briefing.push_str(&format!(
                    "- {} — IP: `{}`, UA: `{}`\n",
                    id.id, id.ip_pattern, id.user_agent
                ));
            }
            briefing.push('\n');
        }

        briefing
    }
}

impl Default for IdentityPool {
    fn default() -> Self {
        Self::new(10)
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "identity_system_test.rs"]
mod identity_system_test;
