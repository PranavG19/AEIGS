use crate::arena_controller::ArenaMatchResult;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Arena replay — a complete record of a match for later review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArenaReplay {
    pub version: String,
    pub timestamp: String,
    pub match_result: ArenaMatchResult,
}

impl ArenaReplay {
    /// Create a replay from a completed match.
    pub fn from_match(result: ArenaMatchResult) -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            match_result: result,
        }
    }

    /// Save the replay to a JSON file.
    pub async fn save(&self, path: &Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        tokio::fs::write(path, json).await
    }

    /// Load a replay from a JSON file.
    pub async fn load(path: &Path) -> Result<Self, String> {
        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| format!("Failed to read replay: {e}"))?;
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse replay: {e}"))
    }

    /// Print a summary of the replay.
    pub fn print_summary(&self) {
        println!("=== Arena Replay ===");
        println!("Version: {}", self.version);
        println!("Timestamp: {}", self.timestamp);
        println!(
            "Rounds: {}",
            self.match_result.rounds.len()
        );
        println!(
            "Red score: {} | Blue score: {}",
            self.match_result.score.red_score(),
            self.match_result.score.blue_score()
        );
        let winner = if self.match_result.score.red_score() > self.match_result.score.blue_score() {
            "RED"
        } else if self.match_result.score.blue_score() > self.match_result.score.red_score() {
            "BLUE"
        } else {
            "DRAW"
        };
        println!("Winner: {winner}");
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "replay_test.rs"]
mod replay_test;
