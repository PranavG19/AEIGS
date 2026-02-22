use aegis_protocol::defense_context::DefenseContext;

use crate::context_adjuster::{FindingContext, adjust_cvss_for_context};
use crate::cvss_scorer::{
    AttackComplexity, AttackVector, CvssMetrics, Impact, PrivilegesRequired, Scope,
    UserInteraction, compute_cvss,
};

fn base_sqli() -> CvssMetrics {
    CvssMetrics {
        attack_vector: AttackVector::Network,
        attack_complexity: AttackComplexity::Low,
        privileges_required: PrivilegesRequired::None,
        user_interaction: UserInteraction::None,
        scope: Scope::Unchanged,
        confidentiality: Impact::High,
        integrity: Impact::High,
        availability: Impact::None,
    }
}

#[test]
fn no_context_changes_nothing() {
    let base = base_sqli();
    let ctx = FindingContext::default();
    let adjusted = adjust_cvss_for_context(&base, &ctx);
    let base_result = compute_cvss(&base);
    let adj_result = compute_cvss(&adjusted);
    assert_eq!(base_result.score, adj_result.score);
    assert_eq!(base_result.vector_string, adj_result.vector_string);
}

#[test]
fn authentication_required_lowers_score() {
    let base = base_sqli();
    let ctx = FindingContext {
        requires_authentication: true,
        ..Default::default()
    };
    let adjusted = adjust_cvss_for_context(&base, &ctx);
    assert_eq!(adjusted.privileges_required, PrivilegesRequired::Low);

    let base_score = compute_cvss(&base).score;
    let adj_score = compute_cvss(&adjusted).score;
    assert!(adj_score < base_score);
}

#[test]
fn admin_only_sets_high_privilege() {
    let base = base_sqli();
    let ctx = FindingContext {
        requires_authentication: true,
        admin_only: true,
        ..Default::default()
    };
    let adjusted = adjust_cvss_for_context(&base, &ctx);
    assert_eq!(adjusted.privileges_required, PrivilegesRequired::High);

    let base_score = compute_cvss(&base).score;
    let adj_score = compute_cvss(&adjusted).score;
    assert!(adj_score < base_score);
}

#[test]
fn waf_present_not_bypassed_raises_complexity() {
    let base = base_sqli();
    let defense = DefenseContext {
        has_waf: true,
        waf_vendor: Some("ModSecurity".to_string()),
        ..Default::default()
    };
    let ctx = FindingContext {
        defense_context: Some(defense),
        waf_bypassed: false,
        ..Default::default()
    };
    let adjusted = adjust_cvss_for_context(&base, &ctx);
    assert_eq!(adjusted.attack_complexity, AttackComplexity::High);

    let base_score = compute_cvss(&base).score;
    let adj_score = compute_cvss(&adjusted).score;
    assert!(adj_score < base_score);
}

#[test]
fn waf_bypassed_keeps_low_complexity() {
    let base = base_sqli();
    let defense = DefenseContext {
        has_waf: true,
        ..Default::default()
    };
    let ctx = FindingContext {
        defense_context: Some(defense),
        waf_bypassed: true,
        ..Default::default()
    };
    let adjusted = adjust_cvss_for_context(&base, &ctx);
    assert_eq!(adjusted.attack_complexity, AttackComplexity::Low);
}

#[test]
fn no_waf_keeps_low_complexity() {
    let base = base_sqli();
    let defense = DefenseContext {
        has_waf: false,
        ..Default::default()
    };
    let ctx = FindingContext {
        defense_context: Some(defense),
        waf_bypassed: false,
        ..Default::default()
    };
    let adjusted = adjust_cvss_for_context(&base, &ctx);
    assert_eq!(adjusted.attack_complexity, AttackComplexity::Low);
}

#[test]
fn user_interaction_required_sets_flag() {
    let base = base_sqli();
    let ctx = FindingContext {
        requires_user_interaction: true,
        ..Default::default()
    };
    let adjusted = adjust_cvss_for_context(&base, &ctx);
    assert_eq!(adjusted.user_interaction, UserInteraction::Required);

    let base_score = compute_cvss(&base).score;
    let adj_score = compute_cvss(&adjusted).score;
    assert!(adj_score < base_score);
}

#[test]
fn multiple_adjustments_stack() {
    let base = base_sqli();
    let defense = DefenseContext {
        has_waf: true,
        ..Default::default()
    };
    let ctx = FindingContext {
        requires_authentication: true,
        defense_context: Some(defense),
        waf_bypassed: false,
        requires_user_interaction: true,
        ..Default::default()
    };
    let adjusted = adjust_cvss_for_context(&base, &ctx);
    assert_eq!(adjusted.privileges_required, PrivilegesRequired::Low);
    assert_eq!(adjusted.attack_complexity, AttackComplexity::High);
    assert_eq!(adjusted.user_interaction, UserInteraction::Required);

    let base_score = compute_cvss(&base).score;
    let adj_score = compute_cvss(&adjusted).score;
    assert!(adj_score < base_score);
}

#[test]
fn impact_metrics_unchanged_by_context() {
    let base = base_sqli();
    let defense = DefenseContext {
        has_waf: true,
        ..Default::default()
    };
    let ctx = FindingContext {
        requires_authentication: true,
        admin_only: true,
        defense_context: Some(defense),
        waf_bypassed: false,
        requires_user_interaction: true,
    };
    let adjusted = adjust_cvss_for_context(&base, &ctx);
    assert_eq!(adjusted.confidentiality, base.confidentiality);
    assert_eq!(adjusted.integrity, base.integrity);
    assert_eq!(adjusted.availability, base.availability);
    assert_eq!(adjusted.scope, base.scope);
    assert_eq!(adjusted.attack_vector, base.attack_vector);
}

#[test]
fn serde_roundtrip_finding_context() {
    let ctx = FindingContext {
        requires_authentication: true,
        admin_only: false,
        defense_context: Some(DefenseContext {
            has_waf: true,
            waf_vendor: Some("Cloudflare".to_string()),
            ..Default::default()
        }),
        waf_bypassed: true,
        requires_user_interaction: false,
    };
    let json = serde_json::to_string(&ctx).unwrap();
    let deserialized: FindingContext = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.requires_authentication, true);
    assert_eq!(deserialized.waf_bypassed, true);
    assert!(deserialized.defense_context.unwrap().has_waf);
}

#[test]
fn admin_only_without_auth_does_not_adjust() {
    let base = base_sqli();
    let ctx = FindingContext {
        requires_authentication: false,
        admin_only: true,
        ..Default::default()
    };
    let adjusted = adjust_cvss_for_context(&base, &ctx);
    assert_eq!(adjusted.privileges_required, PrivilegesRequired::None);
}
