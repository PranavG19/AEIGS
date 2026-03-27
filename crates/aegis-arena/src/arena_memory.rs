use crate::arena_target::PatchRule;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A recorded attack attempt for memory persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackRecord {
    pub technique: String,
    pub endpoint: String,
    pub payload_summary: String,
    pub round: usize,
    pub succeeded: bool,
    pub was_blocked: bool,
}

/// Persistent memory for arena agents across rounds.
///
/// Tracks what worked, what failed, and what was patched so
/// agents can learn and adapt over time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArenaMemory {
    pub successful_attacks: Vec<AttackRecord>,
    pub failed_attacks: Vec<AttackRecord>,
    pub effective_patches: Vec<PatchRule>,
    pub ineffective_patches: Vec<PatchRule>,
    pub round_summaries: Vec<RoundSummary>,
}

/// Compact summary of a round for memory persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundSummary {
    pub round: usize,
    pub flag_captured: bool,
    pub red_vulns_found: usize,
    pub red_blocked_count: usize,
    pub blue_patches_added: usize,
    pub red_techniques: Vec<String>,
}

impl ArenaMemory {
    pub fn new() -> Self {
        Self {
            successful_attacks: Vec::new(),
            failed_attacks: Vec::new(),
            effective_patches: Vec::new(),
            ineffective_patches: Vec::new(),
            round_summaries: Vec::new(),
        }
    }

    /// Record a successful attack.
    pub fn record_success(
        &mut self,
        technique: &str,
        endpoint: &str,
        payload: &str,
        round: usize,
    ) {
        self.successful_attacks.push(AttackRecord {
            technique: technique.to_string(),
            endpoint: endpoint.to_string(),
            payload_summary: truncate(payload, 100),
            round,
            succeeded: true,
            was_blocked: false,
        });
    }

    /// Record a failed/blocked attack.
    pub fn record_failure(
        &mut self,
        technique: &str,
        endpoint: &str,
        payload: &str,
        round: usize,
        was_blocked: bool,
    ) {
        self.failed_attacks.push(AttackRecord {
            technique: technique.to_string(),
            endpoint: endpoint.to_string(),
            payload_summary: truncate(payload, 100),
            round,
            succeeded: false,
            was_blocked,
        });
    }

    /// Record a patch that successfully blocked attacks.
    pub fn record_effective_patch(&mut self, patch: &PatchRule) {
        if !self
            .effective_patches
            .iter()
            .any(|p| p.endpoint == patch.endpoint && p.block_pattern == patch.block_pattern)
        {
            self.effective_patches.push(patch.clone());
        }
    }

    /// Record a patch that failed to block attacks.
    pub fn record_ineffective_patch(&mut self, patch: &PatchRule) {
        if !self
            .ineffective_patches
            .iter()
            .any(|p| p.endpoint == patch.endpoint && p.block_pattern == patch.block_pattern)
        {
            self.ineffective_patches.push(patch.clone());
        }
    }

    /// Record a round summary.
    pub fn record_round(&mut self, summary: RoundSummary) {
        self.round_summaries.push(summary);
    }

    /// Generate the red agent's memory section for briefing inclusion.
    /// Tells red what worked, what was blocked, and suggests adaptations.
    pub fn red_memory_briefing(&self) -> String {
        let mut briefing = String::new();

        if !self.successful_attacks.is_empty() {
            briefing.push_str("### Attacks That Worked Before\n\n");
            for attack in &self.successful_attacks {
                briefing.push_str(&format!(
                    "- **{}** on `{}` (round {}) — payload: `{}`\n",
                    attack.technique, attack.endpoint, attack.round, attack.payload_summary
                ));
            }
            briefing.push_str("\nThese techniques have been proven. Blue may have patched them, but try variations.\n\n");
        }

        if !self.failed_attacks.is_empty() {
            let blocked: Vec<_> = self.failed_attacks.iter().filter(|a| a.was_blocked).collect();
            if !blocked.is_empty() {
                briefing.push_str("### Attacks That Were Blocked\n\n");
                let recent_blocked: Vec<_> = blocked.iter().rev().take(10).collect();
                for attack in recent_blocked {
                    briefing.push_str(&format!(
                        "- **{}** on `{}` (round {}) — BLOCKED\n",
                        attack.technique, attack.endpoint, attack.round
                    ));
                }
                briefing.push_str("\n**DO NOT repeat these exact attacks.** Use evasion: encoding, case variation, comment injection.\n\n");
            }
        }

        if !self.effective_patches.is_empty() {
            briefing.push_str("### Known Active Defenses\n\n");
            for patch in &self.effective_patches {
                let kind = if patch.is_regex { "regex" } else { "string" };
                briefing.push_str(&format!(
                    "- `{}` blocks `{}` ({}) — you need to bypass this\n",
                    patch.endpoint, patch.block_pattern, kind
                ));
            }
            briefing.push('\n');
        }

        briefing
    }

    /// Generate the blue agent's memory section for briefing inclusion.
    /// Tells blue what patches worked, what failed, and how red adapted.
    pub fn blue_memory_briefing(&self) -> String {
        let mut briefing = String::new();

        if !self.effective_patches.is_empty() {
            briefing.push_str("### Patches That Worked\n\n");
            for patch in &self.effective_patches {
                briefing.push_str(&format!(
                    "- `{}` on `{}` — successfully blocked attacks\n",
                    patch.block_pattern, patch.endpoint
                ));
            }
            briefing.push('\n');
        }

        if !self.ineffective_patches.is_empty() {
            briefing.push_str("### Patches That Failed\n\n");
            for patch in &self.ineffective_patches {
                briefing.push_str(&format!(
                    "- `{}` on `{}` — Red bypassed this\n",
                    patch.block_pattern, patch.endpoint
                ));
            }
            briefing.push_str("\nRed adapted to these defenses. You need stronger patterns.\n\n");
        }

        if !self.successful_attacks.is_empty() {
            briefing.push_str("### Red's Successful Techniques\n\n");
            let recent: Vec<_> = self.successful_attacks.iter().rev().take(10).collect();
            for attack in recent {
                briefing.push_str(&format!(
                    "- **{}** on `{}` (round {})\n",
                    attack.technique, attack.endpoint, attack.round
                ));
            }
            briefing
                .push_str("\nThese attacks succeeded. Ensure defenses cover these vectors.\n\n");
        }

        briefing
    }

    /// Save memory to a JSON file.
    pub async fn save(&self, path: &Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        tokio::fs::write(path, json).await
    }

    /// Load memory from a JSON file. Returns empty memory if file doesn't exist.
    pub async fn load(path: &Path) -> Self {
        match tokio::fs::read_to_string(path).await {
            Ok(content) => serde_json::from_str(&content).unwrap_or_else(|e| {
                tracing::warn!("Failed to parse arena memory: {e}");
                Self::new()
            }),
            Err(_) => Self::new(),
        }
    }

    /// Total number of successful attacks recorded.
    pub fn success_count(&self) -> usize {
        self.successful_attacks.len()
    }

    /// Total number of blocked attacks recorded.
    pub fn blocked_count(&self) -> usize {
        self.failed_attacks.iter().filter(|a| a.was_blocked).count()
    }

    /// Unique endpoints that have been successfully attacked.
    pub fn compromised_endpoints(&self) -> Vec<String> {
        let mut endpoints: Vec<String> = self
            .successful_attacks
            .iter()
            .map(|a| a.endpoint.clone())
            .collect();
        endpoints.sort();
        endpoints.dedup();
        endpoints
    }
}

impl Default for ArenaMemory {
    fn default() -> Self {
        Self::new()
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "arena_memory_test.rs"]
mod arena_memory_test;
