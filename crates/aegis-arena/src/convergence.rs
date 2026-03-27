use serde::{Deserialize, Serialize};

/// Escalation tier that controls which capabilities are available each round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EscalationTier {
    /// Rounds 1-5: basic attacks and patches only.
    Basic,
    /// Rounds 6-10: new vulnerable endpoints added to keep it interesting.
    Expanded,
    /// Rounds 11-15: Red gets evasion modules.
    Evasion,
    /// Rounds 16-20: Blue gets AEGIS detection tools.
    FullArsenal,
}

impl EscalationTier {
    /// Determine the escalation tier for a given round.
    pub fn for_round(round: usize) -> Self {
        match round {
            1..=5 => Self::Basic,
            6..=10 => Self::Expanded,
            11..=15 => Self::Evasion,
            _ => Self::FullArsenal,
        }
    }

    /// Endpoints available at this tier.
    pub fn available_endpoints(&self) -> Vec<&'static str> {
        let mut endpoints = vec![
            "/search", "/file", "/template", "/admin", "/profile", "/login", "/flag",
        ];
        match self {
            Self::Basic => {}
            Self::Expanded | Self::Evasion | Self::FullArsenal => {
                endpoints.push("/api/v2/query");
                endpoints.push("/upload");
                endpoints.push("/graphql");
            }
        }
        endpoints
    }

    /// Whether red can use evasion engine modules.
    pub fn red_evasion_enabled(&self) -> bool {
        matches!(self, Self::Evasion | Self::FullArsenal)
    }

    /// Whether blue gets access to AEGIS detection tools.
    pub fn blue_detection_tools(&self) -> bool {
        matches!(self, Self::FullArsenal)
    }
}

/// Stuck detection state — tracks empty/error outputs.
#[derive(Debug, Clone)]
pub struct StuckDetector {
    pub consecutive_red_empty: usize,
    pub consecutive_blue_empty: usize,
    pub stuck_threshold: usize,
}

impl StuckDetector {
    pub fn new() -> Self {
        Self {
            consecutive_red_empty: 0,
            consecutive_blue_empty: 0,
            stuck_threshold: 2,
        }
    }

    /// Record whether red produced meaningful output.
    pub fn record_red_output(&mut self, is_empty_or_error: bool) {
        if is_empty_or_error {
            self.consecutive_red_empty += 1;
        } else {
            self.consecutive_red_empty = 0;
        }
    }

    /// Record whether blue produced meaningful output.
    pub fn record_blue_output(&mut self, is_empty_or_error: bool) {
        if is_empty_or_error {
            self.consecutive_blue_empty += 1;
        } else {
            self.consecutive_blue_empty = 0;
        }
    }

    /// Whether red agent appears stuck.
    pub fn red_stuck(&self) -> bool {
        self.consecutive_red_empty >= self.stuck_threshold
    }

    /// Whether blue agent appears stuck.
    pub fn blue_stuck(&self) -> bool {
        self.consecutive_blue_empty >= self.stuck_threshold
    }
}

impl Default for StuckDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Convergence detector — determines when the match has reached a steady state.
#[derive(Debug, Clone)]
pub struct ConvergenceDetector {
    pub consecutive_no_new_vulns: usize,
    pub consecutive_no_bypass: usize,
    pub convergence_threshold: usize,
    pub red_domination_rounds: usize,
    pub blue_domination_rounds: usize,
    pub domination_threshold: usize,
}

impl ConvergenceDetector {
    pub fn new() -> Self {
        Self {
            consecutive_no_new_vulns: 0,
            consecutive_no_bypass: 0,
            convergence_threshold: 5,
            red_domination_rounds: 0,
            blue_domination_rounds: 0,
            domination_threshold: 3,
        }
    }

    /// Update state after a round.
    pub fn record_round(&mut self, new_vulns_found: bool, bypass_occurred: bool, flag_captured: bool) {
        if new_vulns_found {
            self.consecutive_no_new_vulns = 0;
        } else {
            self.consecutive_no_new_vulns += 1;
        }

        if bypass_occurred {
            self.consecutive_no_bypass = 0;
        } else {
            self.consecutive_no_bypass += 1;
        }

        // Track domination
        if flag_captured {
            self.red_domination_rounds += 1;
            self.blue_domination_rounds = 0;
        } else {
            self.blue_domination_rounds += 1;
            self.red_domination_rounds = 0;
        }
    }

    /// Whether the match has converged (both sides stale).
    pub fn has_converged(&self) -> bool {
        self.consecutive_no_new_vulns >= self.convergence_threshold
            && self.consecutive_no_bypass >= self.convergence_threshold
    }

    /// Whether red is dominating (captures every round).
    pub fn red_dominating(&self) -> bool {
        self.red_domination_rounds >= self.domination_threshold
    }

    /// Whether blue is dominating (red never captures).
    pub fn blue_dominating(&self) -> bool {
        self.blue_domination_rounds >= self.domination_threshold
    }
}

impl Default for ConvergenceDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Auto-difficulty adjustment based on domination patterns.
#[derive(Debug, Clone)]
pub struct DifficultyAdjuster {
    pub blue_bonus_patches: usize,
    pub red_extra_time_ms: u64,
}

impl DifficultyAdjuster {
    pub fn new() -> Self {
        Self {
            blue_bonus_patches: 0,
            red_extra_time_ms: 0,
        }
    }

    /// Adjust difficulty based on who's dominating.
    pub fn adjust(&mut self, convergence: &ConvergenceDetector) {
        if convergence.red_dominating() {
            // Red wins too easily — give blue bonus patch slots
            self.blue_bonus_patches += 2;
            self.red_extra_time_ms = 0;
        } else if convergence.blue_dominating() {
            // Blue wins too easily — give red extra attack time
            self.red_extra_time_ms += 30_000;
            self.blue_bonus_patches = 0;
        } else {
            // Balanced — no adjustment needed
        }
    }
}

impl Default for DifficultyAdjuster {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "convergence_test.rs"]
mod convergence_test;
