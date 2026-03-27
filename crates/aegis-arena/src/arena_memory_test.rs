use super::*;
use crate::arena_target::PatchRule;

#[test]
fn record_success_and_failure() {
    let mut mem = ArenaMemory::new();
    mem.record_success("sqli_search_0", "/search", "' OR 1=1 --", 1);
    mem.record_failure("lfi_file_0", "/file", "../etc/passwd", 1, true);

    assert_eq!(mem.success_count(), 1);
    assert_eq!(mem.blocked_count(), 1);
    assert_eq!(mem.successful_attacks[0].technique, "sqli_search_0");
    assert!(mem.failed_attacks[0].was_blocked);
}

#[test]
fn record_effective_patches() {
    let mut mem = ArenaMemory::new();
    let patch = PatchRule::new("/search", "OR ", false);
    mem.record_effective_patch(&patch);
    mem.record_effective_patch(&patch); // duplicate

    assert_eq!(mem.effective_patches.len(), 1, "Should deduplicate");
}

#[test]
fn record_ineffective_patches() {
    let mut mem = ArenaMemory::new();
    let patch = PatchRule::new("/file", "..", false);
    mem.record_ineffective_patch(&patch);

    assert_eq!(mem.ineffective_patches.len(), 1);
    assert_eq!(mem.ineffective_patches[0].endpoint, "/file");
}

#[test]
fn record_round_summary() {
    let mut mem = ArenaMemory::new();
    mem.record_round(RoundSummary {
        round: 1,
        flag_captured: true,
        red_vulns_found: 3,
        red_blocked_count: 1,
        blue_patches_added: 5,
        red_techniques: vec!["sqli".to_string(), "lfi".to_string()],
    });

    assert_eq!(mem.round_summaries.len(), 1);
    assert!(mem.round_summaries[0].flag_captured);
}

#[test]
fn compromised_endpoints_deduplication() {
    let mut mem = ArenaMemory::new();
    mem.record_success("sqli_1", "/search", "payload1", 1);
    mem.record_success("sqli_2", "/search", "payload2", 1);
    mem.record_success("lfi_1", "/file", "payload3", 2);

    let endpoints = mem.compromised_endpoints();
    assert_eq!(endpoints.len(), 2);
    assert!(endpoints.contains(&"/file".to_string()));
    assert!(endpoints.contains(&"/search".to_string()));
}

#[test]
fn red_memory_briefing_includes_successes() {
    let mut mem = ArenaMemory::new();
    mem.record_success("sqli_search_0", "/search", "' OR 1=1 --", 1);

    let briefing = mem.red_memory_briefing();
    assert!(briefing.contains("sqli_search_0"));
    assert!(briefing.contains("/search"));
    assert!(briefing.contains("Worked Before"));
}

#[test]
fn red_memory_briefing_includes_blocked() {
    let mut mem = ArenaMemory::new();
    mem.record_failure("sqli_search_0", "/search", "' OR 1=1", 2, true);

    let briefing = mem.red_memory_briefing();
    assert!(briefing.contains("BLOCKED"));
    assert!(briefing.contains("DO NOT repeat"));
}

#[test]
fn red_memory_briefing_includes_defenses() {
    let mut mem = ArenaMemory::new();
    mem.record_effective_patch(&PatchRule::new("/search", "OR ", false));

    let briefing = mem.red_memory_briefing();
    assert!(briefing.contains("Known Active Defenses"));
    assert!(briefing.contains("OR "));
}

#[test]
fn blue_memory_briefing_includes_effective_patches() {
    let mut mem = ArenaMemory::new();
    mem.record_effective_patch(&PatchRule::new("/search", "OR ", false));

    let briefing = mem.blue_memory_briefing();
    assert!(briefing.contains("Patches That Worked"));
    assert!(briefing.contains("OR "));
}

#[test]
fn blue_memory_briefing_includes_failed_patches() {
    let mut mem = ArenaMemory::new();
    mem.record_ineffective_patch(&PatchRule::new("/file", "..", false));

    let briefing = mem.blue_memory_briefing();
    assert!(briefing.contains("Patches That Failed"));
    assert!(briefing.contains("Red bypassed"));
}

#[test]
fn blue_memory_briefing_includes_red_techniques() {
    let mut mem = ArenaMemory::new();
    mem.record_success("jwt_bypass", "/admin", "alg:none", 3);

    let briefing = mem.blue_memory_briefing();
    assert!(briefing.contains("jwt_bypass"));
    assert!(briefing.contains("/admin"));
}

#[test]
fn empty_memory_briefings() {
    let mem = ArenaMemory::new();
    let red_brief = mem.red_memory_briefing();
    let blue_brief = mem.blue_memory_briefing();
    assert!(red_brief.is_empty() || red_brief.trim().is_empty());
    assert!(blue_brief.is_empty() || blue_brief.trim().is_empty());
}

#[tokio::test]
async fn save_and_load_memory() {
    let mut mem = ArenaMemory::new();
    mem.record_success("sqli", "/search", "' OR 1=1", 1);
    mem.record_failure("lfi", "/file", "../passwd", 1, true);
    mem.record_effective_patch(&PatchRule::new("/search", "OR", false));
    mem.record_round(RoundSummary {
        round: 1,
        flag_captured: true,
        red_vulns_found: 2,
        red_blocked_count: 1,
        blue_patches_added: 3,
        red_techniques: vec!["sqli".to_string()],
    });

    let path = std::env::temp_dir().join("aegis_test_memory.json");
    mem.save(&path).await.expect("save");

    let loaded = ArenaMemory::load(&path).await;
    assert_eq!(loaded.successful_attacks.len(), 1);
    assert_eq!(loaded.failed_attacks.len(), 1);
    assert_eq!(loaded.effective_patches.len(), 1);
    assert_eq!(loaded.round_summaries.len(), 1);
    assert_eq!(loaded.successful_attacks[0].technique, "sqli");

    let _ = tokio::fs::remove_file(&path).await;
}

#[tokio::test]
async fn load_missing_file_returns_empty() {
    let mem = ArenaMemory::load(Path::new("/tmp/nonexistent_aegis_memory_xyz.json")).await;
    assert_eq!(mem.success_count(), 0);
    assert!(mem.round_summaries.is_empty());
}

#[test]
fn truncate_long_payload() {
    let long = "x".repeat(200);
    let result = truncate(&long, 100);
    assert!(result.len() <= 103); // 100 + "..."
    assert!(result.ends_with("..."));
}

#[test]
fn truncate_short_payload() {
    let short = "short";
    let result = truncate(short, 100);
    assert_eq!(result, "short");
}
