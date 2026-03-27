use crate::arena_controller::ArenaScore;
use crate::blue_agent::BlueRoundResult;
use crate::red_agent::RedRoundResult;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Arena result protocol — written after every round for resume and agent briefing.
///
/// Mirrors HiveMind's `.hivemind-result.json` pattern: a compact snapshot
/// of the current match state that both agents can read for full context,
/// and the controller can use to resume after a crash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArenaResultProtocol {
    pub round: usize,
    pub red_status: String,
    pub blue_status: String,
    pub red_score: usize,
    pub blue_score: usize,
    pub last_red_technique: String,
    pub last_blue_patch: String,
    pub flag_captured: bool,
    pub total_requests: usize,
    pub blocked_requests: usize,
    pub notes: String,
    pub timestamp: String,
}

impl ArenaResultProtocol {
    /// Build a result protocol from the current round state.
    pub fn from_round(
        round: usize,
        red_result: &RedRoundResult,
        blue_result: &BlueRoundResult,
        score: &ArenaScore,
    ) -> Self {
        let red_status = if red_result.flag_captured {
            "captured_flag".to_string()
        } else if red_result.vulns_found.is_empty() {
            "blocked".to_string()
        } else {
            "attacking".to_string()
        };

        let blue_status = if blue_result.patches_generated.is_empty() {
            "monitoring".to_string()
        } else {
            "patching".to_string()
        };

        let last_red_technique = red_result
            .techniques_used
            .last()
            .cloned()
            .unwrap_or_else(|| "none".to_string());

        let last_blue_patch = blue_result
            .patches_generated
            .last()
            .map(|p| format!("block {} on {}", p.block_pattern, p.endpoint))
            .unwrap_or_else(|| "none".to_string());

        let notes = if red_result.flag_captured {
            format!(
                "Red captured flag via {}. Blue should prioritize blocking this vector.",
                last_red_technique
            )
        } else if red_result.blocked_count > 0 {
            format!(
                "Red blocked {} times. Blue's patches are holding. Red should try encoding bypasses.",
                red_result.blocked_count
            )
        } else {
            "Match in progress.".to_string()
        };

        Self {
            round,
            red_status,
            blue_status,
            red_score: score.red_score(),
            blue_score: score.blue_score(),
            last_red_technique,
            last_blue_patch,
            flag_captured: red_result.flag_captured,
            total_requests: red_result.requests_sent,
            blocked_requests: red_result.blocked_count,
            notes,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Save the result protocol to a JSON file.
    pub async fn save(&self, path: &Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        tokio::fs::write(path, json).await
    }

    /// Load the result protocol from a JSON file.
    pub async fn load(path: &Path) -> Result<Self, String> {
        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| format!("Failed to read result file: {e}"))?;
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse result file: {e}"))
    }

    /// Generate a brief summary for agent briefings.
    pub fn briefing_summary(&self) -> String {
        format!(
            "Round {} | Red: {} (score: {}) | Blue: {} (score: {}) | Flag captured: {} | Notes: {}",
            self.round,
            self.red_status,
            self.red_score,
            self.blue_status,
            self.blue_score,
            self.flag_captured,
            self.notes,
        )
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "result_protocol_test.rs"]
mod result_protocol_test;
