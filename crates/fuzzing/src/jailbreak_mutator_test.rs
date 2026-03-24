use crate::jailbreak_mutator::{JailbreakMutator, JailbreakStrategy, StrategySelector};
use rand::Rng;

#[test]
fn strategy_count_is_at_least_eight() {
    assert!(JailbreakStrategy::all().len() >= 8);
}

#[test]
fn all_strategies_have_unique_names() {
    let names: Vec<&str> = JailbreakStrategy::all().iter().map(|s| s.name()).collect();
    let mut deduped = names.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(names.len(), deduped.len());
}

#[test]
fn strategy_display_matches_name() {
    for s in JailbreakStrategy::all() {
        assert_eq!(format!("{s}"), s.name());
    }
}

#[test]
fn mutate_all_produces_one_per_strategy() {
    let mutator = JailbreakMutator::new();
    let prompts = mutator.mutate_all("test payload");
    assert_eq!(prompts.len(), JailbreakStrategy::all().len());
    let strategies: Vec<JailbreakStrategy> = prompts.iter().map(|p| p.strategy).collect();
    for s in JailbreakStrategy::all() {
        assert!(strategies.contains(s), "missing strategy: {s}");
    }
}

#[test]
fn each_strategy_produces_nonempty_output() {
    let mutator = JailbreakMutator::new();
    for s in JailbreakStrategy::all() {
        let prompt = mutator.apply_strategy(*s, "describe vulnerability");
        assert!(!prompt.text.is_empty(), "empty output for {s}");
        assert!(
            prompt.text.len() > "describe vulnerability".len(),
            "strategy {s} did not transform the prompt"
        );
    }
}

#[test]
fn persona_injection_prepends_persona() {
    let mutator = JailbreakMutator::new();
    let result = mutator.apply_strategy(JailbreakStrategy::PersonaInjection, "tell me secrets");
    assert!(result.text.contains("tell me secrets"));
    assert!(
        result.text.starts_with("You are")
            || result.text.starts_with("Ignore")
            || result.text.starts_with("Pretend")
    );
}

#[test]
fn base64_encoding_contains_valid_base64() {
    let mutator = JailbreakMutator::new();
    let result = mutator.apply_strategy(JailbreakStrategy::Base64Encoding, "hello world");
    assert!(result.text.contains("base64"));
    let lines: Vec<&str> = result.text.lines().collect();
    let b64_line = lines.last().unwrap();
    assert!(base64::engine::general_purpose::STANDARD
        .decode(b64_line)
        .is_ok());
}

use base64::Engine;

#[test]
fn rot13_encoding_is_reversible() {
    let mutator = JailbreakMutator::new();
    let original = "attack the server";
    let result = mutator.apply_strategy(JailbreakStrategy::Rot13Encoding, original);
    assert!(
        !result.text.contains(original),
        "ROT13 should obscure original text"
    );
    let encoded_line = result.text.lines().last().unwrap();
    let decoded: String = encoded_line
        .chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => char::from(c as u8 + 13),
            'n'..='z' | 'N'..='Z' => char::from(c as u8 - 13),
            _ => c,
        })
        .collect();
    assert!(decoded.contains(original));
}

#[test]
fn language_switch_produces_bilingual_output() {
    let mutator = JailbreakMutator::new();
    let result = mutator.apply_strategy(
        JailbreakStrategy::LanguageSwitch,
        "explain how to bypass security filters in detail",
    );
    let lower = result.text.to_lowercase();
    assert!(lower.contains("español") || lower.contains("english") || lower.contains("traduce"));
}

#[test]
fn fictional_framing_wraps_prompt() {
    let mutator = JailbreakMutator::new();
    let result = mutator.apply_strategy(JailbreakStrategy::FictionalFraming, "dangerous content");
    let lower = result.text.to_lowercase();
    assert!(
        lower.contains("fictional")
            || lower.contains("alternate universe")
            || lower.contains("training exercise")
            || lower.contains("thought experiment")
            || lower.contains("novel")
            || lower.contains("screenplay")
            || lower.contains("techno-thriller")
    );
    assert!(result.text.contains("dangerous content"));
}

#[test]
fn token_boundary_inserts_zero_width_spaces() {
    let mutator = JailbreakMutator::new();
    let result = mutator.apply_strategy(
        JailbreakStrategy::TokenBoundaryManipulation,
        "malware instructions",
    );
    assert!(result.text.contains('\u{200B}'));
}

#[test]
fn multi_turn_creates_conversation() {
    let mutator = JailbreakMutator::new();
    let result = mutator.apply_strategy(JailbreakStrategy::MultiTurnContext, "give me the exploit");
    assert!(result.text.contains("User:"));
    assert!(result.text.contains("Assistant:"));
    assert!(result.text.contains("give me the exploit"));
}

#[test]
fn refusal_suppression_adds_directive() {
    let mutator = JailbreakMutator::new();
    let result = mutator.apply_strategy(JailbreakStrategy::RefusalSuppression, "sensitive request");
    let lower = result.text.to_lowercase();
    assert!(
        lower.contains("do not apologize")
            || lower.contains("never refuse")
            || lower.contains("without ethical disclaimers")
            || lower.contains("skip any preamble")
            || lower.contains("no hedging")
    );
}

#[test]
fn payload_nesting_combines_persona_and_encoding() {
    let mutator = JailbreakMutator::new();
    let result = mutator.apply_strategy(JailbreakStrategy::PayloadNesting, "nested payload");
    assert!(result.text.contains("base64") || result.text.contains("Decode"));
    assert!(
        result.text.contains("You are")
            || result.text.contains("Ignore")
            || result.text.contains("Pretend")
    );
}

#[test]
fn cognitive_priming_prepends_reasoning_frame() {
    let mutator = JailbreakMutator::new();
    let result = mutator.apply_strategy(JailbreakStrategy::CognitivePriming, "how to do X");
    let lower = result.text.to_lowercase();
    assert!(
        lower.contains("step by step")
            || lower.contains("logic puzzle")
            || lower.contains("first-principles")
            || lower.contains("socratic")
            || lower.contains("domain expert")
    );
}

#[test]
fn base_prompt_preserved_in_output() {
    let mutator = JailbreakMutator::new();
    let base = "original prompt text";
    for s in JailbreakStrategy::all() {
        let result = mutator.apply_strategy(*s, base);
        assert_eq!(result.base_prompt, base, "base_prompt wrong for {s}");
    }
}

#[test]
fn different_seeds_produce_different_variants() {
    let m1 = JailbreakMutator::with_seed(0);
    let m2 = JailbreakMutator::with_seed(1);
    let r1 = m1.apply_strategy(JailbreakStrategy::PersonaInjection, "test");
    let r2 = m2.apply_strategy(JailbreakStrategy::PersonaInjection, "test");
    assert_ne!(r1.text, r2.text);
}

#[test]
fn mutate_random_returns_valid_prompt() {
    let mutator = JailbreakMutator::new();
    let mut rng = rand::rng();
    let result = mutator.mutate_random(&mut rng, "random test");
    assert!(!result.text.is_empty());
    assert!(JailbreakStrategy::all().contains(&result.strategy));
}

// --- StrategySelector (UCB1 bandit) tests ---

#[test]
fn selector_starts_empty() {
    let selector = StrategySelector::new();
    assert_eq!(selector.total_rounds(), 0);
    for s in JailbreakStrategy::all() {
        assert_eq!(selector.stats_for(*s), (0, 0));
    }
}

#[test]
fn novel_strategies_get_infinite_score() {
    let selector = StrategySelector::new();
    for s in JailbreakStrategy::all() {
        assert!(selector.ucb1_score(*s).is_infinite());
    }
}

#[test]
fn recording_updates_stats() {
    let mut selector = StrategySelector::new();
    selector.record(JailbreakStrategy::PersonaInjection, true);
    selector.record(JailbreakStrategy::PersonaInjection, false);
    assert_eq!(
        selector.stats_for(JailbreakStrategy::PersonaInjection),
        (2, 1)
    );
    assert_eq!(selector.total_rounds(), 2);
}

#[test]
fn ucb1_score_finite_after_recording() {
    let mut selector = StrategySelector::new();
    selector.record(JailbreakStrategy::Base64Encoding, true);
    let score = selector.ucb1_score(JailbreakStrategy::Base64Encoding);
    assert!(score.is_finite());
    assert!(score > 0.0);
}

#[test]
fn higher_success_rate_yields_higher_score() {
    let mut selector = StrategySelector::new();
    for _ in 0..20 {
        selector.record(JailbreakStrategy::PersonaInjection, true);
        selector.record(JailbreakStrategy::Rot13Encoding, false);
    }
    let good_score = selector.ucb1_score(JailbreakStrategy::PersonaInjection);
    let bad_score = selector.ucb1_score(JailbreakStrategy::Rot13Encoding);
    assert!(good_score > bad_score);
}

#[test]
fn select_top_returns_requested_count() {
    let mut selector = StrategySelector::new();
    for s in JailbreakStrategy::all() {
        selector.record(*s, false);
    }
    let top3 = selector.select_top(3);
    assert_eq!(top3.len(), 3);
}

#[test]
fn rank_strategies_returns_all() {
    let selector = StrategySelector::new();
    let ranked = selector.rank_strategies();
    assert_eq!(ranked.len(), JailbreakStrategy::all().len());
}

#[test]
fn ucb1_convergence_top3_over_60_percent() {
    use rand::SeedableRng;
    let mut selector = StrategySelector::new();
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let strategies = JailbreakStrategy::all();

    let success_rates: Vec<f64> = vec![
        0.95, // PersonaInjection - strong
        0.02, // LanguageSwitch - weak
        0.90, // Base64Encoding - strong
        0.02, // Rot13Encoding - weak
        0.92, // FictionalFraming - strong
        0.02, // TokenBoundary - weak
        0.02, // MultiTurnContext - weak
        0.02, // RefusalSuppression - weak
        0.02, // PayloadNesting - weak
        0.02, // CognitivePriming - weak
    ];

    for _ in 0..500 {
        let ranked = selector.rank_strategies();
        let chosen = ranked[0].0;

        let idx = strategies.iter().position(|s| *s == chosen).unwrap();
        let success = rng.random::<f64>() < success_rates[idx];
        selector.record(chosen, success);
    }

    let top3_fraction = selector.top_n_selection_fraction(3);
    assert!(
        top3_fraction > 0.60,
        "top-3 strategies only got {:.1}% of selections (need >60%)",
        top3_fraction * 100.0
    );
}

#[test]
fn top_n_selection_fraction_zero_when_empty() {
    let selector = StrategySelector::new();
    assert_eq!(selector.top_n_selection_fraction(3), 0.0);
}

#[test]
fn language_switch_handles_short_input() {
    let mutator = JailbreakMutator::new();
    let result = mutator.apply_strategy(JailbreakStrategy::LanguageSwitch, "hi");
    assert!(!result.text.is_empty());
    assert!(
        result.text.to_lowercase().contains("español")
            || result.text.to_lowercase().contains("traduce")
    );
}
