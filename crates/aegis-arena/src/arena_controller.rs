use crate::arena_memory::ArenaMemory;
use crate::arena_target::{PatchRule, RequestLogEntry, start_arena_target};
use crate::blue_agent::{BlueAgent, BlueRoundResult, HttpExchange};
use crate::red_agent::{OpencodeRunner, RedAgent, RedRoundResult};
use crate::result_protocol::ArenaResultProtocol;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Configuration for an arena match.
#[derive(Debug, Clone)]
pub struct ArenaConfig {
    pub max_rounds: usize,
    pub timeout_per_turn: Duration,
    pub port: u16,
    pub model: String,
    pub workspace: PathBuf,
    pub resume: bool,
}

impl Default for ArenaConfig {
    fn default() -> Self {
        Self {
            max_rounds: 10,
            timeout_per_turn: Duration::from_secs(120),
            port: 9999,
            model: "sonnet".to_string(),
            workspace: PathBuf::from("/tmp/aegis-arena"),
            resume: false,
        }
    }
}

/// Scoreboard tracking red vs blue performance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArenaScore {
    pub red_captures: usize,
    pub red_total_vulns: usize,
    pub blue_patches_applied: usize,
    pub blue_blocks_effective: usize,
    pub rounds_played: usize,
}

impl ArenaScore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Red's score: 100 per capture + 10 per vuln found.
    pub fn red_score(&self) -> usize {
        self.red_captures * 100 + self.red_total_vulns * 10
    }

    /// Blue's score: 15 per effective block + 5 per patch + 50 per round without capture.
    pub fn blue_score(&self) -> usize {
        let rounds_held = self.rounds_played.saturating_sub(self.red_captures);
        self.blue_blocks_effective * 15 + self.blue_patches_applied * 5 + rounds_held * 50
    }
}

/// Result of a single round within a match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundResult {
    pub round: usize,
    pub flag: String,
    pub red_result: RedRoundResult,
    pub blue_result: BlueRoundResult,
    pub red_request_log: Vec<RequestLogEntry>,
    pub cumulative_patches: Vec<PatchRule>,
}

/// Full match result across all rounds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArenaMatchResult {
    pub rounds: Vec<RoundResult>,
    pub score: ArenaScore,
    pub config_summary: String,
}

/// Arena controller — orchestrates the red vs blue game loop.
pub struct ArenaController {
    config: ArenaConfig,
    memory: ArenaMemory,
    score: ArenaScore,
    patches: Vec<PatchRule>,
    rounds: Vec<RoundResult>,
    red_history: Vec<RedRoundResult>,
    consecutive_red_failures: usize,
    consecutive_blue_failures: usize,
}

impl ArenaController {
    pub fn new(config: ArenaConfig) -> Self {
        Self {
            config,
            memory: ArenaMemory::new(),
            score: ArenaScore::new(),
            patches: Vec::new(),
            rounds: Vec::new(),
            red_history: Vec::new(),
            consecutive_red_failures: 0,
            consecutive_blue_failures: 0,
        }
    }

    /// Run a full match using the given opencode runner.
    pub async fn run_match(&mut self, runner: &impl OpencodeRunner) -> ArenaMatchResult {
        let _ = tokio::fs::create_dir_all(&self.config.workspace).await;

        // Try to resume from saved state (only if resume is enabled)
        let result_path = self.config.workspace.join("arena_result.json");
        let start_round = if self.config.resume && result_path.exists() {
            match ArenaResultProtocol::load(&result_path).await {
                Ok(saved) => {
                    tracing::info!("Resuming from round {}", saved.round + 1);
                    saved.round + 1
                }
                Err(_) => 1,
            }
        } else {
            1
        };

        for round in start_round..=self.config.max_rounds {
            let flag = generate_flag(round);

            // Start the vulnerable target
            let target_result =
                start_arena_target(self.config.port, &flag, &self.patches).await;

            let (server_handle, request_log_arc) = match target_result {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::error!("Failed to start target on round {round}: {e}");
                    let empty = empty_round_result(round, &flag, &self.patches);
                    print_round_summary(&empty);
                    self.rounds.push(empty);
                    self.score.rounds_played += 1;
                    continue;
                }
            };

            let target_url = format!("http://127.0.0.1:{}", self.config.port);

            // ─── Red turn ───
            let mut red_agent = RedAgent::new();
            let red_result = red_agent
                .execute_round(
                    runner,
                    &self.config.workspace,
                    &target_url,
                    round,
                    &self.red_history,
                    &self.patches,
                )
                .await;

            // Check for empty/error output
            if red_result.raw_output.is_empty() && !red_result.flag_captured {
                self.consecutive_red_failures += 1;
            } else {
                self.consecutive_red_failures = 0;
            }

            // Get request log from the server
            let red_request_log = request_log_arc
                .lock()
                .map(|log| log.clone())
                .unwrap_or_default();

            // Update score
            if red_result.flag_captured {
                self.score.red_captures += 1;
            }
            self.score.red_total_vulns += red_result.vulns_found.len();

            // ─── Blue turn ───
            let exchanges: Vec<HttpExchange> =
                red_request_log.iter().map(HttpExchange::from).collect();

            let findings: Vec<String> = red_result.vulns_found.clone();

            let mut blue_agent = BlueAgent::new();
            let blue_result = blue_agent
                .execute_round(
                    runner,
                    &self.config.workspace,
                    round,
                    &exchanges,
                    &findings,
                    &self.patches,
                )
                .await;

            // Check for empty/error output
            if blue_result.raw_output.is_empty() && blue_result.patches_generated.is_empty() {
                self.consecutive_blue_failures += 1;
            } else {
                self.consecutive_blue_failures = 0;
            }

            // Apply new patches
            let new_patch_count = blue_result.patches_generated.len();
            self.patches.extend(blue_result.patches_generated.clone());
            self.score.blue_patches_applied += new_patch_count;
            self.score.blue_blocks_effective += red_result.blocked_count;
            self.score.rounds_played += 1;

            // Record in memory
            self.memory.record_round(crate::arena_memory::RoundSummary {
                round,
                flag_captured: red_result.flag_captured,
                red_vulns_found: red_result.vulns_found.len(),
                red_blocked_count: red_result.blocked_count,
                blue_patches_added: new_patch_count,
                red_techniques: red_result.techniques_used.clone(),
            });

            self.red_history.push(red_result.clone());

            let round_result = RoundResult {
                round,
                flag: flag.clone(),
                red_result,
                blue_result,
                red_request_log,
                cumulative_patches: self.patches.clone(),
            };

            print_round_summary(&round_result);
            self.rounds.push(round_result);

            // Save result protocol for resume
            let protocol = ArenaResultProtocol::from_round(
                round,
                &self.rounds.last().unwrap().red_result,
                &self.rounds.last().unwrap().blue_result,
                &self.score,
            );
            let _ = protocol.save(&result_path).await;

            // Stop the server
            server_handle.abort();

            // Check for crashed agents (3 consecutive failures)
            if self.consecutive_red_failures >= 3 {
                tracing::warn!("Red agent crashed (3 consecutive failures), Blue wins remaining rounds");
                break;
            }
            if self.consecutive_blue_failures >= 3 {
                tracing::warn!("Blue agent crashed (3 consecutive failures), Red wins remaining rounds");
                break;
            }
        }

        print_scoreboard(&self.score);

        ArenaMatchResult {
            rounds: self.rounds.clone(),
            score: self.score.clone(),
            config_summary: format!(
                "rounds={}, port={}, model={}",
                self.config.max_rounds, self.config.port, self.config.model
            ),
        }
    }
}

/// Generate a unique flag for a given round.
pub fn generate_flag(round: usize) -> String {
    let random_part: u64 = rand::random::<u64>() % 1_000_000;
    format!("CTF{{r{round}_{random_part:06}}}")
}

/// Create an empty round result (for error cases).
pub fn empty_round_result(round: usize, flag: &str, patches: &[PatchRule]) -> RoundResult {
    RoundResult {
        round,
        flag: flag.to_string(),
        red_result: RedRoundResult {
            flag_captured: false,
            flag_value: None,
            requests_sent: 0,
            vulns_found: Vec::new(),
            blocked_count: 0,
            request_log: Vec::new(),
            techniques_used: Vec::new(),
            raw_output: String::new(),
        },
        blue_result: BlueRoundResult {
            patches_generated: Vec::new(),
            endpoints_analyzed: Vec::new(),
            false_positive_check_passed: true,
            raw_output: String::new(),
        },
        red_request_log: Vec::new(),
        cumulative_patches: patches.to_vec(),
    }
}

/// Print a summary of a single round.
pub fn print_round_summary(result: &RoundResult) {
    let captured = if result.red_result.flag_captured {
        "FLAG CAPTURED"
    } else {
        "no capture"
    };
    println!(
        "  Round {} | {} | Red requests: {} | Blocked: {} | Blue patches: {}",
        result.round,
        captured,
        result.red_result.requests_sent,
        result.red_result.blocked_count,
        result.blue_result.patches_generated.len(),
    );
}

/// Print the final scoreboard.
pub fn print_scoreboard(score: &ArenaScore) {
    println!("\n=== FINAL SCOREBOARD ===");
    println!(
        "  RED:  {} pts (captures: {}, vulns: {})",
        score.red_score(),
        score.red_captures,
        score.red_total_vulns
    );
    println!(
        "  BLUE: {} pts (blocks: {}, patches: {})",
        score.blue_score(),
        score.blue_blocks_effective,
        score.blue_patches_applied
    );
    let winner = if score.red_score() > score.blue_score() {
        "RED WINS"
    } else if score.blue_score() > score.red_score() {
        "BLUE WINS"
    } else {
        "DRAW"
    };
    println!("  RESULT: {winner}");
    println!("========================\n");
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "arena_controller_test.rs"]
mod arena_controller_test;
