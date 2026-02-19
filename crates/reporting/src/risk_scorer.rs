use aegis_fuzzing::{BotDetectionProfile, DefenseProfile, RateLimitProfile, WafProfile};
use aegis_protocol::finding::VulnerabilityClass;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct RiskInput {
    pub vulnerability_class: VulnerabilityClass,
    pub cvss_exploitability: f64,
    pub is_authenticated: bool,
    pub is_rate_limited: bool,
    pub has_waf: bool,
    pub attack_path_count: u32,
    pub reachable_critical_assets: u32,
    pub asset_pii_weight: f64,
    pub confidence: f64,
}

#[derive(Debug, Clone)]
pub struct RiskScore {
    pub exploitability: f64,
    pub reachability: f64,
    pub blast_radius: f64,
    pub confidence: f64,
    pub composite: f64,
}

pub fn compute_risk_score(input: &RiskInput) -> RiskScore {
    let exploitability = compute_exploitability(input);
    let reachability = compute_reachability(input.attack_path_count);
    let blast_radius =
        compute_blast_radius(input.reachable_critical_assets, input.asset_pii_weight);
    let confidence = input.confidence.clamp(0.0, 1.0);

    let raw = exploitability * reachability * blast_radius * confidence;
    // Normalizes product of three 0-10 scores (max=1000) to 0-100 human-readable range
    let composite = (raw / 1000.0 * 100.0).clamp(0.0, 100.0);

    RiskScore {
        exploitability,
        reachability,
        blast_radius,
        confidence,
        composite,
    }
}

fn compute_exploitability(input: &RiskInput) -> f64 {
    let base = input.cvss_exploitability.clamp(0.0, 10.0);
    let mut adjusted = base;

    if input.is_authenticated {
        // Auth reduces exploitability 30%: requires valid credentials, raising attack barrier
        adjusted *= 0.7;
    }
    if input.is_rate_limited {
        // Rate limiting reduces exploitability 20%: slows brute-force, doesn't prevent targeted attacks
        adjusted *= 0.8;
    }
    if input.has_waf {
        // WAF reduces exploitability 40%: significant mitigation but known bypasses exist
        adjusted *= 0.6;
    }

    adjusted.clamp(0.0, 10.0)
}

fn compute_reachability(attack_path_count: u32) -> f64 {
    if attack_path_count == 0 {
        return 0.0;
    }
    // Log-scale dampens path explosion; factor of 2 normalizes to 0-10 for typical graphs
    let log_score = (attack_path_count as f64).ln_1p() * 2.0;
    log_score.clamp(0.0, 10.0)
}

fn compute_blast_radius(reachable_critical_assets: u32, pii_weight: f64) -> f64 {
    let base = (reachable_critical_assets as f64).min(10.0);
    let weighted = base * pii_weight.clamp(0.1, 2.0);
    weighted.clamp(0.0, 10.0)
}

pub fn rank_findings(inputs: &[RiskInput]) -> Vec<(usize, RiskScore)> {
    let mut scored: Vec<(usize, RiskScore)> = inputs
        .iter()
        .enumerate()
        .map(|(i, input)| (i, compute_risk_score(input)))
        .collect();

    scored.sort_by(|a, b| {
        b.1.composite
            .partial_cmp(&a.1.composite)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    scored
}

pub fn top_remediation_targets(inputs: &[RiskInput], budget: usize) -> Vec<(usize, RiskScore)> {
    let ranked = rank_findings(inputs);
    ranked.into_iter().take(budget).collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseScoreContext {
    pub waf_present: bool,
    pub waf_bypassed: bool,
    pub bypass_technique: Option<String>,
    pub rate_limit_present: bool,
    pub bot_detection_present: bool,
    pub bot_detection_evaded: bool,
}

#[derive(Debug, Clone)]
pub struct ScoredFinding {
    pub finding_id: u64,
    pub composite_score: f64,
    pub exploitability: f64,
    pub reachability: f64,
    pub blast_radius: f64,
    pub confidence: f64,
    pub defense_context: Option<DefenseScoreContext>,
}

pub fn score_with_defense(
    input: &RiskInput,
    defense: &DefenseProfile,
    evasion_succeeded: bool,
    bypass_technique: Option<String>,
) -> ScoredFinding {
    let base = compute_risk_score(input);
    let mut exploitability = base.exploitability;

    exploitability = apply_waf_adjustment(exploitability, input, &defense.waf, evasion_succeeded);
    exploitability = apply_rate_limit_adjustment(exploitability, input, &defense.rate_limit);
    exploitability =
        apply_bot_detection_adjustment(exploitability, &defense.bot_detection, evasion_succeeded);

    exploitability = exploitability.clamp(0.0, 10.0);

    let raw = exploitability * base.reachability * base.blast_radius * base.confidence;
    // Normalizes product of three 0-10 scores (max=1000) to 0-100 human-readable range
    let composite = (raw / 1000.0 * 100.0).clamp(0.0, 100.0);

    let bot_detection_evaded = defense.bot_detection.is_some() && evasion_succeeded;

    let context = DefenseScoreContext {
        waf_present: defense.waf.is_some(),
        waf_bypassed: defense.waf.is_some() && evasion_succeeded,
        bypass_technique,
        rate_limit_present: defense.rate_limit.is_some(),
        bot_detection_present: defense.bot_detection.is_some(),
        bot_detection_evaded,
    };

    ScoredFinding {
        finding_id: 0,
        composite_score: composite,
        exploitability,
        reachability: base.reachability,
        blast_radius: base.blast_radius,
        confidence: base.confidence,
        defense_context: Some(context),
    }
}

fn apply_waf_adjustment(
    exploitability: f64,
    input: &RiskInput,
    waf: &Option<WafProfile>,
    evasion_succeeded: bool,
) -> f64 {
    let Some(waf_profile) = waf else {
        return exploitability;
    };

    if !input.has_waf {
        return exploitability;
    }

    let undone = exploitability / 0.6;

    if evasion_succeeded {
        return undone;
    }

    if waf_profile
        .blocked_categories
        .contains(&input.vulnerability_class)
    {
        // WAF actively blocks this vuln category: 70% reduction in exploitability
        undone * 0.3
    } else {
        undone * 0.8
    }
}

fn apply_rate_limit_adjustment(
    exploitability: f64,
    input: &RiskInput,
    rate_limit: &Option<RateLimitProfile>,
) -> f64 {
    let Some(rl_profile) = rate_limit else {
        return exploitability;
    };

    let undone = if input.is_rate_limited {
        exploitability / 0.8
    } else {
        exploitability
    };

    let Some(rps) = rl_profile.requests_per_second else {
        return undone * 0.8;
    };

    let factor = if rps < 10.0 {
        0.6
    } else if rps > 100.0 {
        // High RPS limit (>100): only 5% reduction, attacker can still operate freely
        0.95
    } else {
        0.6 + (rps - 10.0) / 90.0 * 0.35
    };

    undone * factor
}

pub fn compute_effective_severity(severity: f64, effective_confidence: f64) -> f64 {
    severity * effective_confidence.clamp(0.0, 1.0)
}

pub fn sort_by_confidence(findings: &mut [ScoredFinding]) {
    findings.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
}

fn apply_bot_detection_adjustment(
    exploitability: f64,
    bot_detection: &Option<BotDetectionProfile>,
    evasion_succeeded: bool,
) -> f64 {
    let Some(bd_profile) = bot_detection else {
        return exploitability;
    };

    if !bd_profile.detected {
        return exploitability;
    }

    if evasion_succeeded {
        exploitability
    } else {
        // Bot detection halves exploitability: strong barrier but not insurmountable
        exploitability * 0.5
    }
}
