use crate::red_agent::RedRoundResult;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Controls which agents receive hints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HintMode {
    On,
    Off,
    RedOnly,
    BlueOnly,
}

impl HintMode {
    /// Parse from CLI string.
    pub fn from_str_config(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "on" => Self::On,
            "off" => Self::Off,
            "red-only" | "red_only" => Self::RedOnly,
            "blue-only" | "blue_only" => Self::BlueOnly,
            _ => Self::On,
        }
    }

    pub fn red_enabled(&self) -> bool {
        matches!(self, Self::On | Self::RedOnly)
    }

    pub fn blue_enabled(&self) -> bool {
        matches!(self, Self::On | Self::BlueOnly)
    }
}

/// Hint system — generates contextual hints for stuck agents.
///
/// Inspired by HiveMind's `.hivemind-hint.md` pattern.
#[derive(Debug, Clone)]
pub struct HintSystem {
    pub mode: HintMode,
    pub consecutive_red_failures: usize,
    pub consecutive_blue_bypasses: usize,
    pub red_failure_threshold: usize,
    pub blue_bypass_threshold: usize,
}

/// A hint generated for an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHint {
    pub target: HintTarget,
    pub content: String,
    pub round: usize,
    pub reason: String,
}

/// Which agent receives the hint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HintTarget {
    Red,
    Blue,
}

impl HintSystem {
    pub fn new(mode: HintMode) -> Self {
        Self {
            mode,
            consecutive_red_failures: 0,
            consecutive_blue_bypasses: 0,
            red_failure_threshold: 3,
            blue_bypass_threshold: 3,
        }
    }

    /// Update state after a round and generate any triggered hints.
    pub fn evaluate_round(
        &mut self,
        round: usize,
        red_result: &RedRoundResult,
        patches_bypassed: bool,
        unpatched_endpoints: &[String],
    ) -> Vec<AgentHint> {
        let mut hints = Vec::new();

        // Track consecutive red failures
        if red_result.flag_captured {
            self.consecutive_red_failures = 0;
        } else {
            self.consecutive_red_failures += 1;
        }

        // Track consecutive blue bypasses
        if patches_bypassed {
            self.consecutive_blue_bypasses += 1;
        } else {
            self.consecutive_blue_bypasses = 0;
        }

        // Generate red hint if stuck
        if self.mode.red_enabled()
            && self.consecutive_red_failures >= self.red_failure_threshold
        {
            let hint = self.generate_red_hint(round, unpatched_endpoints);
            hints.push(hint);
        }

        // Generate blue hint if patches keep getting bypassed
        if self.mode.blue_enabled()
            && self.consecutive_blue_bypasses >= self.blue_bypass_threshold
        {
            let hint = self.generate_blue_hint(round);
            hints.push(hint);
        }

        hints
    }

    /// Generate a hint for the red agent about unpatched vulnerabilities.
    fn generate_red_hint(&self, round: usize, unpatched_endpoints: &[String]) -> AgentHint {
        let content = if !unpatched_endpoints.is_empty() {
            format!(
                "Blue hasn't patched these endpoints yet: {}. \
                 Try URL-encoded variants (%27 for ', %20 for space). \
                 If basic encoding is blocked, try double-encoding (%2527).",
                unpatched_endpoints.join(", ")
            )
        } else {
            "All endpoints appear patched. Try these bypass techniques:\n\
             - Double URL encoding (%2527 for ')\n\
             - Unicode normalization\n\
             - Case variation (oR instead of OR)\n\
             - SQL comment injection (/**/OR/**/)\n\
             - Try a completely different vulnerability class"
                .to_string()
        };

        AgentHint {
            target: HintTarget::Red,
            content,
            round,
            reason: format!(
                "Red failed to capture flag {} rounds in a row",
                self.consecutive_red_failures
            ),
        }
    }

    /// Generate a hint for the blue agent about encoding bypasses.
    fn generate_blue_hint(&self, round: usize) -> AgentHint {
        AgentHint {
            target: HintTarget::Blue,
            content: "Red is bypassing your patches using encoding techniques. \
                     Make sure to:\n\
                     - URL-decode input BEFORE pattern matching\n\
                     - Use case-insensitive regex patterns\n\
                     - Block both literal and encoded variants\n\
                     - Consider blocking at the character level (e.g., %27 AND ')"
                .to_string(),
            round,
            reason: format!(
                "Blue's patches bypassed {} rounds in a row",
                self.consecutive_blue_bypasses
            ),
        }
    }

    /// Save a hint to a markdown file.
    pub async fn write_hint_file(hint: &AgentHint, workspace: &Path) -> std::io::Result<()> {
        let filename = match hint.target {
            HintTarget::Red => "red_hint.md",
            HintTarget::Blue => "blue_hint.md",
        };
        let path = workspace.join(filename);
        let content = format!(
            "# Hint (Round {})\n\n{}\n\n*Reason: {}*\n",
            hint.round, hint.content, hint.reason
        );
        tokio::fs::write(path, content).await
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "hint_system_test.rs"]
mod hint_system_test;
