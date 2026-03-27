use crate::arena_memory::ArenaMemory;
use crate::arena_target::{PatchRule, RequestLogEntry, start_arena_target};
use crate::blue_agent::{BlueAgent, BlueRoundResult, HttpExchange};
use crate::red_agent::{OpencodeRunner, RedAgent, RedRoundResult};
use crate::result_protocol::ArenaResultProtocol;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

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

/// Configuration for infinite mode.
#[derive(Debug, Clone)]
pub struct InfiniteConfig {
    pub timeout_per_turn: Duration,
    pub port: u16,
    pub model: String,
    pub workspace: PathBuf,
    pub resume: bool,
    /// Minimum cycle duration to prevent runaway.
    pub min_cycle_duration: Duration,
    /// Maximum cycle duration before forceful timeout.
    pub max_cycle_duration: Duration,
    /// Cycles between adding new vulnerable endpoints.
    pub endpoint_escalation_interval: usize,
    /// Cycles between unlocking new capabilities.
    pub capability_escalation_interval: usize,
    /// Speed preset: affects timeouts.
    pub speed: SpeedPreset,
    /// Verbose output every cycle.
    pub watch: bool,
}

/// Speed presets for infinite mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpeedPreset {
    Normal,
    Fast,
}

impl Default for InfiniteConfig {
    fn default() -> Self {
        Self {
            timeout_per_turn: Duration::from_secs(120),
            port: 9999,
            model: "sonnet".to_string(),
            workspace: PathBuf::from("/tmp/aegis-arena"),
            resume: false,
            min_cycle_duration: Duration::from_secs(5),
            max_cycle_duration: Duration::from_secs(600),
            endpoint_escalation_interval: 10,
            capability_escalation_interval: 25,
            speed: SpeedPreset::Normal,
            watch: false,
        }
    }
}

/// Persistent state for the infinite loop, saved every cycle for crash recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfiniteState {
    pub cycle: usize,
    pub score: ArenaScore,
    pub patches: Vec<PatchRule>,
    pub red_flags: usize,
    pub red_blocked: usize,
    pub blue_blocks: usize,
    pub blue_bypassed: usize,
    pub red_identities_remaining: usize,
    pub red_identities_total: usize,
    pub escalation_level: usize,
    pub endpoints_active: usize,
    pub uptime_secs: u64,
    pub cycles_since_last_capture: usize,
    pub cycles_since_last_bypass: usize,
    pub red_consecutive_blocks: usize,
    pub false_positive_count: usize,
    pub timestamp: String,
}

impl InfiniteState {
    /// Create initial state for a fresh infinite run.
    pub fn new() -> Self {
        Self {
            cycle: 0,
            score: ArenaScore::new(),
            patches: Vec::new(),
            red_flags: 0,
            red_blocked: 0,
            blue_blocks: 0,
            blue_bypassed: 0,
            red_identities_remaining: 10,
            red_identities_total: 10,
            escalation_level: 0,
            endpoints_active: 8,
            uptime_secs: 0,
            cycles_since_last_capture: 0,
            cycles_since_last_bypass: 0,
            red_consecutive_blocks: 0,
            false_positive_count: 0,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Save state to disk for crash recovery.
    pub async fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        tokio::fs::write(path, json).await
    }

    /// Load state from disk. Returns None if file doesn't exist or is corrupt.
    pub async fn load(path: &std::path::Path) -> Option<Self> {
        let content = tokio::fs::read_to_string(path).await.ok()?;
        serde_json::from_str(&content).ok()
    }

    /// Security maturity score: Blue's block rate * Red's creativity score.
    pub fn security_maturity(&self) -> f64 {
        let total_interactions = self.blue_blocks + self.blue_bypassed;
        let block_rate = if total_interactions > 0 {
            self.blue_blocks as f64 / total_interactions as f64
        } else {
            0.0
        };
        let creativity = if self.red_flags > 0 {
            (self.red_flags as f64 / self.cycle.max(1) as f64) * 100.0
        } else {
            0.0
        };
        (block_rate * creativity * 100.0).min(100.0)
    }

    /// Determine escalation level from cycle count.
    pub fn compute_escalation_level(&self, endpoint_interval: usize, cap_interval: usize) -> usize {
        let endpoint_unlocks = if endpoint_interval > 0 {
            self.cycle / endpoint_interval
        } else {
            0
        };
        let cap_unlocks = if cap_interval > 0 {
            self.cycle / cap_interval
        } else {
            0
        };
        endpoint_unlocks + cap_unlocks
    }
}

impl Default for InfiniteState {
    fn default() -> Self {
        Self::new()
    }
}

/// Cycle outcome — what happened during one cycle of infinite mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CycleOutcome {
    /// Red captured the flag.
    RedCapture,
    /// Red was blocked by Blue's bans.
    RedBlocked,
    /// Red found nothing, neither scored.
    Stalemate,
}

/// Result of a single infinite-mode cycle.
#[derive(Debug, Clone)]
pub struct CycleResult {
    pub cycle: usize,
    pub outcome: CycleOutcome,
    pub red_result: RedRoundResult,
    pub blue_result: BlueRoundResult,
    pub cycle_duration: Duration,
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

/// Infinite loop controller — runs the arena forever with escalation and state persistence.
pub struct InfiniteController {
    config: InfiniteConfig,
    state: InfiniteState,
    memory: ArenaMemory,
    patches: Vec<PatchRule>,
    red_history: Vec<RedRoundResult>,
    start_time: Instant,
    shutdown: Arc<AtomicBool>,
}

impl InfiniteController {
    /// Create a new infinite controller.
    pub fn new(config: InfiniteConfig, shutdown: Arc<AtomicBool>) -> Self {
        Self {
            config,
            state: InfiniteState::new(),
            memory: ArenaMemory::new(),
            patches: Vec::new(),
            red_history: Vec::new(),
            start_time: Instant::now(),
            shutdown,
        }
    }

    /// Create with existing state (for resume).
    pub fn with_state(config: InfiniteConfig, state: InfiniteState, shutdown: Arc<AtomicBool>) -> Self {
        let patches = state.patches.clone();
        Self {
            config,
            state,
            memory: ArenaMemory::new(),
            patches,
            red_history: Vec::new(),
            start_time: Instant::now(),
            shutdown,
        }
    }

    /// Get current state snapshot.
    pub fn state(&self) -> &InfiniteState {
        &self.state
    }

    /// Check if a shutdown has been requested.
    pub fn should_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    /// Run one cycle of the infinite loop. Returns the cycle result.
    pub async fn run_cycle(&mut self, runner: &impl OpencodeRunner) -> Option<CycleResult> {
        if self.should_shutdown() {
            return None;
        }

        self.state.cycle += 1;
        let cycle = self.state.cycle;
        let cycle_start = Instant::now();
        let flag = generate_flag(cycle);

        let _ = tokio::fs::create_dir_all(&self.config.workspace).await;

        // Start target server
        let target_result =
            start_arena_target(self.config.port, &flag, &self.patches).await;

        let (server_handle, request_log_arc) = match target_result {
            Ok(pair) => {
                tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
                pair
            }
            Err(e) => {
                eprintln!("[arena] ERROR cycle {cycle}: target failed to start: {e}");
                return Some(CycleResult {
                    cycle,
                    outcome: CycleOutcome::Stalemate,
                    red_result: empty_red_result(),
                    blue_result: empty_blue_result(),
                    cycle_duration: cycle_start.elapsed(),
                });
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
                cycle,
                &self.red_history,
                &self.patches,
            )
            .await;

        let red_request_log = request_log_arc
            .lock()
            .map(|log| log.clone())
            .unwrap_or_default();

        // ─── Blue turn ───
        let exchanges: Vec<HttpExchange> =
            red_request_log.iter().map(HttpExchange::from).collect();
        let findings: Vec<String> = red_result.vulns_found.clone();

        let mut blue_agent = BlueAgent::new();
        let blue_result = blue_agent
            .execute_round(
                runner,
                &self.config.workspace,
                cycle,
                &exchanges,
                &findings,
                &self.patches,
            )
            .await;

        server_handle.abort();

        // Determine outcome
        let outcome = if red_result.flag_captured {
            CycleOutcome::RedCapture
        } else if red_result.blocked_count > 0 && red_result.vulns_found.is_empty() {
            CycleOutcome::RedBlocked
        } else {
            CycleOutcome::Stalemate
        };

        // Update state
        self.update_state(&outcome, &red_result, &blue_result);

        // Apply new patches
        self.patches.extend(blue_result.patches_generated.clone());
        self.state.patches = self.patches.clone();

        // Record in memory
        self.memory.record_round(crate::arena_memory::RoundSummary {
            round: cycle,
            flag_captured: red_result.flag_captured,
            red_vulns_found: red_result.vulns_found.len(),
            red_blocked_count: red_result.blocked_count,
            blue_patches_added: blue_result.patches_generated.len(),
            red_techniques: red_result.techniques_used.clone(),
        });

        self.red_history.push(red_result.clone());

        // Save state every cycle
        self.state.uptime_secs = self.start_time.elapsed().as_secs();
        self.state.timestamp = chrono::Utc::now().to_rfc3339();
        let state_path = self.config.workspace.join("arena_result.json");
        let _ = self.state.save(&state_path).await;

        // Check escalation triggers
        if self.config.endpoint_escalation_interval > 0
            && cycle % self.config.endpoint_escalation_interval == 0
        {
            self.state.endpoints_active += 1;
        }
        if self.config.capability_escalation_interval > 0
            && cycle % self.config.capability_escalation_interval == 0
        {
            self.state.escalation_level += 1;
        }

        // Enforce minimum cycle duration
        let elapsed = cycle_start.elapsed();
        if elapsed < self.config.min_cycle_duration {
            let remaining = self.config.min_cycle_duration - elapsed;
            tokio::time::sleep(remaining).await;
        }

        Some(CycleResult {
            cycle,
            outcome,
            red_result,
            blue_result,
            cycle_duration: cycle_start.elapsed(),
        })
    }

    /// Update internal state based on a cycle outcome.
    fn update_state(
        &mut self,
        outcome: &CycleOutcome,
        red_result: &RedRoundResult,
        blue_result: &BlueRoundResult,
    ) {
        self.state.score.rounds_played += 1;

        match outcome {
            CycleOutcome::RedCapture => {
                self.state.red_flags += 1;
                self.state.score.red_captures += 1;
                self.state.blue_bypassed += 1;
                self.state.cycles_since_last_capture = 0;
                self.state.cycles_since_last_bypass += 1;
                self.state.red_consecutive_blocks = 0;
            }
            CycleOutcome::RedBlocked => {
                self.state.red_blocked += 1;
                self.state.blue_blocks += 1;
                self.state.score.blue_blocks_effective += red_result.blocked_count;
                self.state.cycles_since_last_capture += 1;
                self.state.cycles_since_last_bypass = 0;
                self.state.red_consecutive_blocks += 1;
            }
            CycleOutcome::Stalemate => {
                self.state.cycles_since_last_capture += 1;
                self.state.cycles_since_last_bypass += 1;
                self.state.red_consecutive_blocks = 0;
            }
        }

        self.state.score.red_total_vulns += red_result.vulns_found.len();
        self.state.score.blue_patches_applied += blue_result.patches_generated.len();
    }

    /// Whether Red should enter deep research mode (3 consecutive blocks).
    pub fn red_needs_deep_research(&self) -> bool {
        self.state.red_consecutive_blocks >= 3
    }

    /// Format a live stats summary line.
    pub fn live_stats_line(&self) -> String {
        let uptime = format_duration(self.start_time.elapsed());
        format!(
            "RED: {} flags | BLUE: {} blocks | Cycle: {} | Uptime: {}",
            self.state.red_flags,
            self.state.blue_blocks,
            self.state.cycle,
            uptime,
        )
    }

    /// Generate a final summary for shutdown.
    pub fn final_summary(&self) -> String {
        let uptime = format_duration(self.start_time.elapsed());
        let maturity = self.state.security_maturity();
        format!(
            "\n=== INFINITE ARENA — FINAL SUMMARY ===\n\
             Uptime: {uptime} | Cycles: {cycles}\n\
             RED:  {red_flags} flags captured | {red_blocked} times blocked\n\
             BLUE: {blue_blocks} blocks | {blue_bypassed} bypasses | {fp} false positives\n\
             Security Maturity: {maturity:.0}/100\n\
             Escalation Level: {esc}\n\
             ========================================\n",
            cycles = self.state.cycle,
            red_flags = self.state.red_flags,
            red_blocked = self.state.red_blocked,
            blue_blocks = self.state.blue_blocks,
            blue_bypassed = self.state.blue_bypassed,
            fp = self.state.false_positive_count,
            esc = self.state.escalation_level,
        )
    }
}

/// Format a Duration as "Xh Ym" or "Xm Ys".
pub fn format_duration(d: Duration) -> String {
    let total_secs = d.as_secs();
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    if hours > 0 {
        format!("{hours}h {minutes:02}m")
    } else if minutes > 0 {
        format!("{minutes}m {secs:02}s")
    } else {
        format!("{secs}s")
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
        red_result: empty_red_result(),
        blue_result: empty_blue_result(),
        red_request_log: Vec::new(),
        cumulative_patches: patches.to_vec(),
    }
}

/// Create an empty RedRoundResult.
pub fn empty_red_result() -> RedRoundResult {
    RedRoundResult {
        flag_captured: false,
        flag_value: None,
        requests_sent: 0,
        vulns_found: Vec::new(),
        blocked_count: 0,
        request_log: Vec::new(),
        techniques_used: Vec::new(),
        raw_output: String::new(),
    }
}

/// Create an empty BlueRoundResult.
pub fn empty_blue_result() -> BlueRoundResult {
    BlueRoundResult {
        patches_generated: Vec::new(),
        endpoints_analyzed: Vec::new(),
        false_positive_check_passed: true,
        raw_output: String::new(),
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
