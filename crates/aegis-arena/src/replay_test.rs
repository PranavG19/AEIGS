use super::*;
use crate::arena_controller::{ArenaMatchResult, ArenaScore, RoundResult};
use crate::blue_agent::BlueRoundResult;
use crate::red_agent::RedRoundResult;

fn mock_match_result() -> ArenaMatchResult {
    let red = RedRoundResult {
        flag_captured: true,
        flag_value: Some("CTF{test}".to_string()),
        requests_sent: 15,
        vulns_found: vec!["sqli".to_string()],
        blocked_count: 3,
        request_log: Vec::new(),
        techniques_used: vec!["sqli_search_0".to_string()],
        raw_output: String::new(),
    };

    let blue = BlueRoundResult {
        patches_generated: Vec::new(),
        endpoints_analyzed: Vec::new(),
        false_positive_check_passed: true,
        raw_output: String::new(),
    };

    ArenaMatchResult {
        rounds: vec![RoundResult {
            round: 1,
            flag: "CTF{test}".to_string(),
            red_result: red,
            blue_result: blue,
            red_request_log: Vec::new(),
            cumulative_patches: Vec::new(),
        }],
        score: ArenaScore {
            red_captures: 1,
            red_total_vulns: 1,
            blue_patches_applied: 0,
            blue_blocks_effective: 3,
            rounds_played: 1,
        },
        config_summary: "test config".to_string(),
    }
}

#[test]
fn replay_from_match() {
    let result = mock_match_result();
    let replay = ArenaReplay::from_match(result);

    assert!(!replay.version.is_empty());
    assert!(!replay.timestamp.is_empty());
    assert_eq!(replay.match_result.rounds.len(), 1);
}

#[tokio::test]
async fn save_and_load_replay() {
    let result = mock_match_result();
    let replay = ArenaReplay::from_match(result);

    let path = std::env::temp_dir().join("aegis_test_replay.json");
    replay.save(&path).await.expect("save replay");

    let loaded = ArenaReplay::load(&path).await.expect("load replay");
    assert_eq!(loaded.match_result.rounds.len(), 1);
    assert_eq!(loaded.match_result.score.red_captures, 1);

    let _ = tokio::fs::remove_file(&path).await;
}

#[test]
fn print_summary_doesnt_panic() {
    let result = mock_match_result();
    let replay = ArenaReplay::from_match(result);
    replay.print_summary();
}
