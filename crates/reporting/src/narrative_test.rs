#[cfg(test)]
mod tests {
    use crate::narrative::{
        NarrativeContext, describe_defense_impact, generate_actionable_narrative,
        generate_executive_summary, generate_finding_narrative, remediation_advice,
        summarize_attack_paths, translate_centrality_to_narrative,
    };

    #[test]
    fn narrative_includes_vulnerability_class_name() {
        let narrative = generate_finding_narrative("AEGIS-0", Some("SQL Injection"), 73.5, None);
        assert!(narrative.contains("SQL Injection"));
    }

    #[test]
    fn narrative_includes_composite_score() {
        let narrative = generate_finding_narrative("AEGIS-1", Some("SQL Injection"), 73.5, None);
        assert!(narrative.contains("73.5"));
    }

    #[test]
    fn narrative_with_defense_context_mentions_defense() {
        let narrative = generate_finding_narrative(
            "AEGIS-2",
            Some("SQL Injection"),
            65.0,
            Some("Cloudflare WAF protection"),
        );
        assert!(narrative.contains("Cloudflare WAF protection"));
        assert!(narrative.contains("exploitable"));
    }

    #[test]
    fn centrality_high_mentions_critical_chokepoint() {
        let narrative = translate_centrality_to_narrative("/api/auth/validate", 0.83);
        assert!(narrative.contains("critical chokepoint"));
        assert!(narrative.contains("83%"));
    }

    #[test]
    fn centrality_low_does_not_use_alarming_language() {
        let narrative = translate_centrality_to_narrative("/api/health", 0.15);
        assert!(!narrative.contains("critical"));
        assert!(!narrative.contains("chokepoint"));
        assert!(!narrative.contains("significantly"));
    }

    #[test]
    fn centrality_medium_says_moderately_connected() {
        let narrative = translate_centrality_to_narrative("/api/users", 0.52);
        assert!(narrative.contains("moderately connected"));
        assert!(narrative.contains("52%"));
        assert!(!narrative.contains("critical chokepoint"));
    }

    #[test]
    fn summarize_attack_paths_formats_counts() {
        let summary = summarize_attack_paths(3, 2, 17);
        assert_eq!(
            summary,
            "Discovered 17 attack paths from 3 entry points to 2 critical assets."
        );
    }

    #[test]
    fn describe_defense_impact_formats_reduction() {
        let description = describe_defense_impact("Cloudflare WAF", 34.0);
        assert_eq!(description, "Cloudflare WAF reduces risk by 34%.");
    }

    #[test]
    fn describe_defense_impact_rounds_fractional_percentage() {
        let description = describe_defense_impact("Rate Limiter", 27.6);
        assert_eq!(description, "Rate Limiter reduces risk by 28%.");
    }

    #[test]
    fn executive_summary_includes_finding_counts() {
        let defenses = vec!["Cloudflare WAF".to_string(), "Rate Limiting".to_string()];
        let summary = generate_executive_summary(12, 3, 5, &defenses);
        assert!(summary.contains("12 findings"));
        assert!(summary.contains("3 critical"));
        assert!(summary.contains("5 high"));
        assert!(summary.contains("Cloudflare WAF"));
        assert!(summary.contains("Rate Limiting"));
    }

    fn base_context() -> NarrativeContext {
        NarrativeContext {
            endpoint: "/api/users".to_string(),
            method: "GET".to_string(),
            parameter: "search".to_string(),
            vulnerability_class: "SQL Injection".to_string(),
            severity: 8.5,
            confidence: 0.82,
            is_authenticated: true,
            accesses_pii: false,
            defense_context: None,
            calibration_note: None,
        }
    }

    #[test]
    fn test_actionable_narrative_with_parameter() {
        let ctx = base_context();
        let narrative = generate_actionable_narrative(&ctx);
        assert_eq!(
            narrative.what,
            "SQL Injection in the search parameter of GET /api/users"
        );
    }

    #[test]
    fn test_actionable_narrative_without_parameter() {
        let mut ctx = base_context();
        ctx.parameter = String::new();
        let narrative = generate_actionable_narrative(&ctx);
        assert_eq!(narrative.what, "SQL Injection detected in GET /api/users");
    }

    #[test]
    fn test_actionable_narrative_unauthenticated_pii() {
        let mut ctx = base_context();
        ctx.is_authenticated = false;
        ctx.accesses_pii = true;
        let narrative = generate_actionable_narrative(&ctx);
        assert!(
            narrative
                .why_it_matters
                .contains("accessible without authentication")
        );
        assert!(
            narrative
                .why_it_matters
                .contains("personally identifiable information")
        );
    }

    #[test]
    fn test_actionable_narrative_with_defense_context() {
        let mut ctx = base_context();
        ctx.defense_context = Some("WAF (AWS WAF)".to_string());
        let narrative = generate_actionable_narrative(&ctx);
        assert!(
            narrative
                .why_it_matters
                .contains("Active defense: WAF (AWS WAF)")
        );
        assert!(narrative.why_it_matters.contains("remains exploitable"));
    }

    #[test]
    fn test_actionable_narrative_with_calibration() {
        let mut ctx = base_context();
        ctx.calibration_note = Some("82% of similar findings are true positives".to_string());
        let narrative = generate_actionable_narrative(&ctx);
        assert!(narrative.confidence_note.contains("82%"));
        assert!(
            narrative
                .confidence_note
                .contains("82% of similar findings are true positives")
        );
    }

    #[test]
    fn test_actionable_narrative_low_confidence_warning() {
        let mut ctx = base_context();
        ctx.confidence = 0.35;
        let narrative = generate_actionable_narrative(&ctx);
        assert!(narrative.confidence_note.contains("35%"));
        assert!(narrative.confidence_note.contains("manually verified"));
    }

    #[test]
    fn test_remediation_advice_known_class() {
        let advice = remediation_advice("SQL Injection");
        assert!(advice.contains("parameterized queries"));
    }

    #[test]
    fn test_remediation_advice_unknown_class() {
        let advice = remediation_advice("Some Unknown Vuln");
        assert!(advice.contains("defense-in-depth"));
    }
}
