use aegis_protocol::finding::VulnerabilityClass;

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
    let blast_radius = compute_blast_radius(input.reachable_critical_assets, input.asset_pii_weight);
    let confidence = input.confidence.clamp(0.0, 1.0);

    let raw = exploitability * reachability * blast_radius * confidence;
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
        adjusted *= 0.7;
    }
    if input.is_rate_limited {
        adjusted *= 0.8;
    }
    if input.has_waf {
        adjusted *= 0.6;
    }

    adjusted.clamp(0.0, 10.0)
}

fn compute_reachability(attack_path_count: u32) -> f64 {
    if attack_path_count == 0 {
        return 0.0;
    }
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
