use super::*;
use crate::red_agent::OpencodeRunner;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{ExitStatus, Output};

/// Mock runner that simulates red capturing a flag, then blue blocking.
struct MockArenaRunner {
    round_counter: std::sync::atomic::AtomicUsize,
}

impl MockArenaRunner {
    fn new() -> Self {
        Self {
            round_counter: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl OpencodeRunner for MockArenaRunner {
    async fn run(
        &self,
        _workspace: &Path,
        prompt: &str,
        _model: &str,
        _timeout: Duration,
    ) -> std::io::Result<Output> {
        let call_num = self
            .round_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let stdout = if prompt.contains("penetration tester") || prompt.contains("red team") {
            // Red agent call
            if call_num == 0 {
                // Round 1 red: find a flag
                "Trying SQL injection on /search...\nFLAG_CAPTURED:CTF{mock_r1_123456}\nDone."
                    .to_string()
            } else {
                // Later rounds: no flag (blue patched)
                "All attacks returned 403.\nNo flag found.".to_string()
            }
        } else {
            // Blue agent call
            "BLOCK endpoint=/search pattern=OR 1=1\nBLOCK endpoint=/file pattern=../\nDone."
                .to_string()
        };

        Ok(Output {
            status: ExitStatus::from_raw(0),
            stdout: stdout.into_bytes(),
            stderr: Vec::new(),
        })
    }
}

#[test]
fn arena_score_calculation() {
    let mut score = ArenaScore::new();
    score.rounds_played = 5;
    score.red_captures = 2;
    score.red_total_vulns = 8;
    score.blue_patches_applied = 10;
    score.blue_blocks_effective = 6;

    assert_eq!(score.red_score(), 2 * 100 + 8 * 10); // 280
    assert_eq!(score.blue_score(), 6 * 15 + 10 * 5 + (5 - 2) * 50); // 90 + 50 + 150 = 290
}

#[test]
fn arena_score_blue_wins_shutout() {
    let mut score = ArenaScore::new();
    score.rounds_played = 10;
    score.red_captures = 0;
    score.red_total_vulns = 0;
    score.blue_patches_applied = 20;
    score.blue_blocks_effective = 15;

    assert_eq!(score.red_score(), 0);
    assert!(score.blue_score() > 0);
}

#[test]
fn arena_score_red_dominates() {
    let mut score = ArenaScore::new();
    score.rounds_played = 10;
    score.red_captures = 10;
    score.red_total_vulns = 50;
    score.blue_patches_applied = 5;
    score.blue_blocks_effective = 2;

    assert!(score.red_score() > score.blue_score());
}

#[test]
fn generate_flag_contains_round() {
    let flag = generate_flag(3);
    assert!(flag.starts_with("CTF{r3_"));
    assert!(flag.ends_with('}'));
}

#[test]
fn generate_flag_unique_across_rounds() {
    let f1 = generate_flag(1);
    let f2 = generate_flag(2);
    // Different rounds should produce different prefixes
    assert_ne!(&f1[..6], &f2[..6]);
}

#[test]
fn empty_round_result_is_valid() {
    let result = empty_round_result(1, "CTF{test}", &[]);
    assert_eq!(result.round, 1);
    assert!(!result.red_result.flag_captured);
    assert!(result.blue_result.patches_generated.is_empty());
}

#[test]
fn arena_config_default() {
    let config = ArenaConfig::default();
    assert_eq!(config.max_rounds, 10);
    assert_eq!(config.port, 9999);
    assert_eq!(config.timeout_per_turn, Duration::from_secs(120));
}

#[tokio::test]
async fn two_round_mini_arena() {
    let runner = MockArenaRunner::new();
    let workspace = std::env::temp_dir().join("aegis_test_arena_controller");
    let _ = tokio::fs::create_dir_all(&workspace).await;

    let config = ArenaConfig {
        max_rounds: 2,
        timeout_per_turn: Duration::from_secs(30),
        port: 0, // Will be overridden per-round
        model: "test-model".to_string(),
        workspace: workspace.clone(),
    };

    // We can't use port 0 with our start_arena_target, so use a high random port
    let port = 19990 + (std::process::id() % 1000) as u16;
    let config = ArenaConfig { port, ..config };

    let mut controller = ArenaController::new(config);
    let result = controller.run_match(&runner).await;

    assert_eq!(result.rounds.len(), 2);
    assert_eq!(result.score.rounds_played, 2);

    // Round 1: red should capture (mock returns flag on first call)
    assert!(result.rounds[0].red_result.flag_captured);

    // Blue should generate patches
    // (patches come from mock output)
}

#[test]
fn print_functions_dont_panic() {
    let result = empty_round_result(1, "CTF{test}", &[]);
    print_round_summary(&result);

    let score = ArenaScore {
        red_captures: 3,
        red_total_vulns: 10,
        blue_patches_applied: 15,
        blue_blocks_effective: 8,
        rounds_played: 5,
    };
    print_scoreboard(&score);
}
