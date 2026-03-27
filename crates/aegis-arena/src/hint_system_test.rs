use super::*;
use crate::red_agent::RedRoundResult;

fn mock_red_failure() -> RedRoundResult {
    RedRoundResult {
        flag_captured: false,
        flag_value: None,
        requests_sent: 10,
        vulns_found: Vec::new(),
        blocked_count: 8,
        request_log: Vec::new(),
        techniques_used: vec!["sqli_search_0".to_string()],
        raw_output: "all blocked".to_string(),
    }
}

fn mock_red_success() -> RedRoundResult {
    RedRoundResult {
        flag_captured: true,
        flag_value: Some("CTF{test}".to_string()),
        requests_sent: 5,
        vulns_found: vec!["sqli".to_string()],
        blocked_count: 0,
        request_log: Vec::new(),
        techniques_used: vec!["sqli_search_0".to_string()],
        raw_output: "found flag".to_string(),
    }
}

#[test]
fn hint_mode_parsing() {
    assert_eq!(HintMode::from_str_config("on"), HintMode::On);
    assert_eq!(HintMode::from_str_config("off"), HintMode::Off);
    assert_eq!(HintMode::from_str_config("red-only"), HintMode::RedOnly);
    assert_eq!(HintMode::from_str_config("blue-only"), HintMode::BlueOnly);
    assert_eq!(HintMode::from_str_config("unknown"), HintMode::On);
}

#[test]
fn hint_mode_enables() {
    assert!(HintMode::On.red_enabled());
    assert!(HintMode::On.blue_enabled());
    assert!(!HintMode::Off.red_enabled());
    assert!(!HintMode::Off.blue_enabled());
    assert!(HintMode::RedOnly.red_enabled());
    assert!(!HintMode::RedOnly.blue_enabled());
    assert!(!HintMode::BlueOnly.red_enabled());
    assert!(HintMode::BlueOnly.blue_enabled());
}

#[test]
fn no_hint_when_off() {
    let mut system = HintSystem::new(HintMode::Off);
    for round in 1..=5 {
        let hints = system.evaluate_round(round, &mock_red_failure(), false, &[]);
        assert!(hints.is_empty(), "No hints when mode is Off");
    }
}

#[test]
fn red_hint_after_consecutive_failures() {
    let mut system = HintSystem::new(HintMode::On);

    // Rounds 1-2: no hint yet (below threshold of 3)
    let hints = system.evaluate_round(1, &mock_red_failure(), false, &[]);
    assert!(hints.is_empty());
    let hints = system.evaluate_round(2, &mock_red_failure(), false, &[]);
    assert!(hints.is_empty());

    // Round 3: threshold reached, should get hint
    let hints = system.evaluate_round(
        3,
        &mock_red_failure(),
        false,
        &["/file".to_string()],
    );
    assert_eq!(hints.len(), 1);
    assert_eq!(hints[0].target, HintTarget::Red);
    assert!(hints[0].content.contains("/file"));
    assert!(hints[0].reason.contains("3 rounds"));
}

#[test]
fn red_hint_resets_on_success() {
    let mut system = HintSystem::new(HintMode::On);

    system.evaluate_round(1, &mock_red_failure(), false, &[]);
    system.evaluate_round(2, &mock_red_failure(), false, &[]);

    // Success resets the counter
    system.evaluate_round(3, &mock_red_success(), false, &[]);
    assert_eq!(system.consecutive_red_failures, 0);

    // Need 3 more failures for next hint
    let hints = system.evaluate_round(4, &mock_red_failure(), false, &[]);
    assert!(hints.is_empty());
}

#[test]
fn blue_hint_after_consecutive_bypasses() {
    let mut system = HintSystem::new(HintMode::On);

    system.evaluate_round(1, &mock_red_success(), true, &[]);
    system.evaluate_round(2, &mock_red_success(), true, &[]);
    let hints = system.evaluate_round(3, &mock_red_success(), true, &[]);

    let blue_hints: Vec<_> = hints.iter().filter(|h| h.target == HintTarget::Blue).collect();
    assert_eq!(blue_hints.len(), 1);
    assert!(blue_hints[0].content.contains("encoding"));
}

#[test]
fn blue_hint_resets_when_patches_hold() {
    let mut system = HintSystem::new(HintMode::On);

    system.evaluate_round(1, &mock_red_success(), true, &[]);
    system.evaluate_round(2, &mock_red_success(), true, &[]);

    // Patches hold — resets counter
    system.evaluate_round(3, &mock_red_failure(), false, &[]);
    assert_eq!(system.consecutive_blue_bypasses, 0);
}

#[test]
fn red_only_mode_no_blue_hints() {
    let mut system = HintSystem::new(HintMode::RedOnly);

    for round in 1..=5 {
        let hints = system.evaluate_round(round, &mock_red_success(), true, &[]);
        let blue_hints: Vec<_> = hints.iter().filter(|h| h.target == HintTarget::Blue).collect();
        assert!(blue_hints.is_empty(), "No blue hints in red-only mode");
    }
}

#[test]
fn blue_only_mode_no_red_hints() {
    let mut system = HintSystem::new(HintMode::BlueOnly);

    for round in 1..=5 {
        let hints = system.evaluate_round(round, &mock_red_failure(), false, &[]);
        let red_hints: Vec<_> = hints.iter().filter(|h| h.target == HintTarget::Red).collect();
        assert!(red_hints.is_empty(), "No red hints in blue-only mode");
    }
}

#[test]
fn red_hint_with_unpatched_endpoints() {
    let mut system = HintSystem::new(HintMode::On);

    for round in 1..=3 {
        system.evaluate_round(round, &mock_red_failure(), false, &[]);
    }
    // At round 3 the hint should mention unpatched endpoints
    // We need to trigger again since we already consumed the hint
    let hints = system.evaluate_round(
        4,
        &mock_red_failure(),
        false,
        &["/template".to_string(), "/admin".to_string()],
    );
    assert!(!hints.is_empty());
    let red_hint = hints.iter().find(|h| h.target == HintTarget::Red).unwrap();
    assert!(red_hint.content.contains("/template"));
    assert!(red_hint.content.contains("/admin"));
}

#[test]
fn red_hint_without_unpatched_endpoints() {
    let mut system = HintSystem::new(HintMode::On);
    for round in 1..=3 {
        system.evaluate_round(round, &mock_red_failure(), false, &[]);
    }
    let hints = system.evaluate_round(4, &mock_red_failure(), false, &[]);
    let red_hint = hints.iter().find(|h| h.target == HintTarget::Red).unwrap();
    assert!(red_hint.content.contains("bypass techniques"));
}

#[tokio::test]
async fn write_hint_file_creates_file() {
    let hint = AgentHint {
        target: HintTarget::Red,
        content: "Try encoding bypass".to_string(),
        round: 5,
        reason: "3 consecutive failures".to_string(),
    };

    let workspace = std::env::temp_dir().join("aegis_test_hints");
    let _ = tokio::fs::create_dir_all(&workspace).await;

    HintSystem::write_hint_file(&hint, &workspace)
        .await
        .expect("write hint");

    let content = tokio::fs::read_to_string(workspace.join("red_hint.md"))
        .await
        .expect("read hint");
    assert!(content.contains("Try encoding bypass"));
    assert!(content.contains("Round 5"));

    let _ = tokio::fs::remove_dir_all(&workspace).await;
}
