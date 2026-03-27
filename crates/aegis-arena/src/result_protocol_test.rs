use super::*;
use crate::arena_controller::ArenaScore;
use crate::arena_target::PatchRule;
use crate::blue_agent::BlueRoundResult;
use crate::red_agent::RedRoundResult;

fn mock_red_result(captured: bool) -> RedRoundResult {
    RedRoundResult {
        flag_captured: captured,
        flag_value: if captured {
            Some("CTF{test}".to_string())
        } else {
            None
        },
        requests_sent: 10,
        vulns_found: if captured {
            vec!["sqli_search_0".to_string()]
        } else {
            Vec::new()
        },
        blocked_count: 3,
        request_log: Vec::new(),
        techniques_used: vec!["sqli_search_0".to_string()],
        raw_output: "test output".to_string(),
    }
}

fn mock_blue_result(patched: bool) -> BlueRoundResult {
    BlueRoundResult {
        patches_generated: if patched {
            vec![PatchRule::new("/search", "OR ", false)]
        } else {
            Vec::new()
        },
        endpoints_analyzed: Vec::new(),
        false_positive_check_passed: true,
        raw_output: "blue output".to_string(),
    }
}

#[test]
fn from_round_with_capture() {
    let red = mock_red_result(true);
    let blue = mock_blue_result(true);
    let score = ArenaScore {
        red_captures: 1,
        red_total_vulns: 1,
        blue_patches_applied: 1,
        blue_blocks_effective: 3,
        rounds_played: 1,
    };

    let protocol = ArenaResultProtocol::from_round(1, &red, &blue, &score);
    assert_eq!(protocol.round, 1);
    assert!(protocol.flag_captured);
    assert_eq!(protocol.red_status, "captured_flag");
    assert_eq!(protocol.blue_status, "patching");
    assert!(protocol.notes.contains("captured flag"));
    assert!(protocol.red_score > 0);
}

#[test]
fn from_round_without_capture() {
    let red = mock_red_result(false);
    let blue = mock_blue_result(false);
    let score = ArenaScore::new();

    let protocol = ArenaResultProtocol::from_round(2, &red, &blue, &score);
    assert_eq!(protocol.round, 2);
    assert!(!protocol.flag_captured);
    assert_eq!(protocol.red_status, "blocked");
    assert_eq!(protocol.blue_status, "monitoring");
}

#[test]
fn serialization_roundtrip() {
    let red = mock_red_result(true);
    let blue = mock_blue_result(true);
    let score = ArenaScore {
        red_captures: 1,
        red_total_vulns: 3,
        blue_patches_applied: 2,
        blue_blocks_effective: 5,
        rounds_played: 3,
    };

    let protocol = ArenaResultProtocol::from_round(3, &red, &blue, &score);
    let json = serde_json::to_string_pretty(&protocol).expect("serialize");
    let deserialized: ArenaResultProtocol = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(deserialized.round, protocol.round);
    assert_eq!(deserialized.flag_captured, protocol.flag_captured);
    assert_eq!(deserialized.red_score, protocol.red_score);
    assert_eq!(deserialized.blue_score, protocol.blue_score);
    assert_eq!(deserialized.red_status, protocol.red_status);
    assert_eq!(deserialized.blue_status, protocol.blue_status);
}

#[tokio::test]
async fn save_and_load_result() {
    let red = mock_red_result(true);
    let blue = mock_blue_result(true);
    let score = ArenaScore {
        red_captures: 1,
        red_total_vulns: 2,
        blue_patches_applied: 3,
        blue_blocks_effective: 4,
        rounds_played: 5,
    };

    let protocol = ArenaResultProtocol::from_round(5, &red, &blue, &score);
    let path = std::env::temp_dir().join("aegis_test_result_protocol.json");
    protocol.save(&path).await.expect("save");

    let loaded = ArenaResultProtocol::load(&path).await.expect("load");
    assert_eq!(loaded.round, 5);
    assert!(loaded.flag_captured);
    assert_eq!(loaded.red_score, protocol.red_score);

    let _ = tokio::fs::remove_file(&path).await;
}

#[tokio::test]
async fn resume_from_saved_state() {
    let red = mock_red_result(false);
    let blue = mock_blue_result(true);
    let score = ArenaScore {
        red_captures: 0,
        red_total_vulns: 5,
        blue_patches_applied: 3,
        blue_blocks_effective: 7,
        rounds_played: 4,
    };

    let protocol = ArenaResultProtocol::from_round(4, &red, &blue, &score);
    let path = std::env::temp_dir().join("aegis_test_resume.json");
    protocol.save(&path).await.expect("save");

    let loaded = ArenaResultProtocol::load(&path).await.expect("load");
    let resume_round = loaded.round + 1;
    assert_eq!(resume_round, 5, "Should resume from round 5");

    let _ = tokio::fs::remove_file(&path).await;
}

#[test]
fn briefing_summary_contains_key_info() {
    let red = mock_red_result(true);
    let blue = mock_blue_result(true);
    let score = ArenaScore {
        red_captures: 1,
        red_total_vulns: 2,
        blue_patches_applied: 1,
        blue_blocks_effective: 3,
        rounds_played: 1,
    };

    let protocol = ArenaResultProtocol::from_round(1, &red, &blue, &score);
    let summary = protocol.briefing_summary();
    assert!(summary.contains("Round 1"));
    assert!(summary.contains("captured_flag"));
    assert!(summary.contains("Flag captured: true"));
}
