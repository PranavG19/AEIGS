use aegis_protocol::defense_context::DefenseContext;
use serde::{Deserialize, Serialize};

use crate::cvss_scorer::{AttackComplexity, CvssMetrics, PrivilegesRequired, UserInteraction};

/// Runtime context surrounding a specific finding, used to adjust CVSS scores.
///
/// Captures authentication requirements, WAF presence and bypass status,
/// and whether user interaction is needed for exploitation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FindingContext {
    pub requires_authentication: bool,
    pub admin_only: bool,
    pub defense_context: Option<DefenseContext>,
    pub waf_bypassed: bool,
    pub requires_user_interaction: bool,
}

/// Adjusts CVSS base metrics based on observed finding context.
///
/// Modifies exploitability sub-metrics to reflect actual attack conditions:
/// - Authentication requirements raise `privileges_required`
/// - Un-bypassed WAF raises `attack_complexity`
/// - User interaction requirements set `user_interaction` to Required
pub fn adjust_cvss_for_context(base: &CvssMetrics, context: &FindingContext) -> CvssMetrics {
    let mut adjusted = base.clone();

    if context.requires_authentication {
        adjusted.privileges_required = if context.admin_only {
            PrivilegesRequired::High
        } else {
            PrivilegesRequired::Low
        };
    }

    if let Some(ref defense) = context.defense_context
        && defense.has_waf
        && !context.waf_bypassed
    {
        adjusted.attack_complexity = AttackComplexity::High;
    }

    if context.requires_user_interaction {
        adjusted.user_interaction = UserInteraction::Required;
    }

    adjusted
}
