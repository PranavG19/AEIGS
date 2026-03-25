#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use aegis_protocol::finding::VulnerabilityClass;

    use crate::alert_rules::{
        AlertFinding, AlertRule, AlertRuleEngine, AlertRuleKind, AlertSeverity, RateOfChangeContext,
    };

    fn make_finding(id: &str, severity: AlertSeverity, class: VulnerabilityClass) -> AlertFinding {
        AlertFinding {
            finding_id: id.to_string(),
            vulnerability_class: class,
            severity,
            endpoint: "/api/users".to_string(),
            cwe_id: None,
            owasp_category: None,
            score: 7.5,
            is_new: true,
        }
    }

    fn severity_rule(min: AlertSeverity) -> AlertRule {
        AlertRule {
            rule_id: "sev-threshold".to_string(),
            name: "Severity Threshold".to_string(),
            enabled: true,
            kind: AlertRuleKind::SeverityThreshold { min_severity: min },
        }
    }

    #[test]
    fn severity_threshold_critical_only() {
        let mut engine = AlertRuleEngine::new();
        engine.add_rule(severity_rule(AlertSeverity::Critical));

        let critical = make_finding(
            "f1",
            AlertSeverity::Critical,
            VulnerabilityClass::SqlInjection,
        );
        let high = make_finding(
            "f2",
            AlertSeverity::High,
            VulnerabilityClass::CrossSiteScripting,
        );

        assert_eq!(engine.evaluate_finding(&critical).len(), 1);
        assert_eq!(engine.evaluate_finding(&high).len(), 0);
    }

    #[test]
    fn severity_threshold_medium_includes_higher() {
        let mut engine = AlertRuleEngine::new();
        engine.add_rule(severity_rule(AlertSeverity::Medium));

        let medium = make_finding(
            "f1",
            AlertSeverity::Medium,
            VulnerabilityClass::PathTraversal,
        );
        let high = make_finding(
            "f2",
            AlertSeverity::High,
            VulnerabilityClass::CommandInjection,
        );
        let low = make_finding("f3", AlertSeverity::Low, VulnerabilityClass::OpenRedirect);

        assert_eq!(engine.evaluate_finding(&medium).len(), 1);
        assert_eq!(engine.evaluate_finding(&high).len(), 1);
        assert_eq!(engine.evaluate_finding(&low).len(), 0);
    }

    #[test]
    fn finding_type_filter() {
        let mut engine = AlertRuleEngine::new();
        let mut allowed = HashSet::new();
        allowed.insert(VulnerabilityClass::SqlInjection);
        allowed.insert(VulnerabilityClass::CommandInjection);
        engine.add_rule(AlertRule {
            rule_id: "type-filter".to_string(),
            name: "SQL/Command only".to_string(),
            enabled: true,
            kind: AlertRuleKind::FindingTypeFilter {
                allowed_classes: allowed,
            },
        });

        let sqli = make_finding("f1", AlertSeverity::High, VulnerabilityClass::SqlInjection);
        let xss = make_finding(
            "f2",
            AlertSeverity::High,
            VulnerabilityClass::CrossSiteScripting,
        );

        assert_eq!(engine.evaluate_finding(&sqli).len(), 1);
        assert_eq!(engine.evaluate_finding(&xss).len(), 0);
    }

    #[test]
    fn rate_of_change_spike_detection() {
        let mut engine = AlertRuleEngine::new();
        engine.add_rule(AlertRule {
            rule_id: "spike".to_string(),
            name: "Finding Spike".to_string(),
            enabled: true,
            kind: AlertRuleKind::RateOfChange {
                min_delta: 5,
                min_percent_increase: 50.0,
            },
        });

        let spike = RateOfChangeContext {
            findings_current_scan: 20,
            findings_previous_scan: 10,
            time_delta_secs: 3600,
        };
        let alerts = engine.evaluate_rate_of_change(&spike);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].delta, 10);
        assert!((alerts[0].percent_increase - 100.0).abs() < 0.1);
    }

    #[test]
    fn rate_of_change_below_threshold() {
        let mut engine = AlertRuleEngine::new();
        engine.add_rule(AlertRule {
            rule_id: "spike".to_string(),
            name: "Finding Spike".to_string(),
            enabled: true,
            kind: AlertRuleKind::RateOfChange {
                min_delta: 10,
                min_percent_increase: 50.0,
            },
        });

        let no_spike = RateOfChangeContext {
            findings_current_scan: 12,
            findings_previous_scan: 10,
            time_delta_secs: 3600,
        };
        let alerts = engine.evaluate_rate_of_change(&no_spike);
        assert!(alerts.is_empty());
    }

    #[test]
    fn compliance_violation_alert() {
        let mut engine = AlertRuleEngine::new();
        let mut cats = HashSet::new();
        cats.insert("A01:2021-Broken Access Control".to_string());
        engine.add_rule(AlertRule {
            rule_id: "owasp".to_string(),
            name: "OWASP Top10".to_string(),
            enabled: true,
            kind: AlertRuleKind::ComplianceViolation {
                owasp_categories: cats,
            },
        });

        let mut finding = make_finding(
            "f1",
            AlertSeverity::High,
            VulnerabilityClass::BrokenAuthorization,
        );
        finding.owasp_category = Some("A01:2021-Broken Access Control".to_string());
        assert_eq!(engine.evaluate_finding(&finding).len(), 1);

        let mut other = make_finding("f2", AlertSeverity::High, VulnerabilityClass::SqlInjection);
        other.owasp_category = Some("A03:2021-Injection".to_string());
        assert_eq!(engine.evaluate_finding(&other).len(), 0);
    }

    #[test]
    fn specific_cwe_alert() {
        let mut engine = AlertRuleEngine::new();
        let mut cwes = HashSet::new();
        cwes.insert(89u32); // SQL Injection
        cwes.insert(79u32); // XSS
        engine.add_rule(AlertRule {
            rule_id: "cwe-watch".to_string(),
            name: "CWE Watchlist".to_string(),
            enabled: true,
            kind: AlertRuleKind::SpecificCwe { cwe_ids: cwes },
        });

        let mut sqli = make_finding("f1", AlertSeverity::High, VulnerabilityClass::SqlInjection);
        sqli.cwe_id = Some(89);
        assert_eq!(engine.evaluate_finding(&sqli).len(), 1);

        let mut other = make_finding("f2", AlertSeverity::High, VulnerabilityClass::PathTraversal);
        other.cwe_id = Some(22);
        assert_eq!(engine.evaluate_finding(&other).len(), 0);
    }

    #[test]
    fn endpoint_match_alert() {
        let mut engine = AlertRuleEngine::new();
        engine.add_rule(AlertRule {
            rule_id: "ep-match".to_string(),
            name: "Admin endpoint".to_string(),
            enabled: true,
            kind: AlertRuleKind::EndpointMatch {
                patterns: vec!["/admin".to_string(), "/internal".to_string()],
            },
        });

        let mut admin_finding = make_finding(
            "f1",
            AlertSeverity::High,
            VulnerabilityClass::BrokenAuthentication,
        );
        admin_finding.endpoint = "/admin/dashboard".to_string();
        assert_eq!(engine.evaluate_finding(&admin_finding).len(), 1);

        let public = make_finding(
            "f2",
            AlertSeverity::High,
            VulnerabilityClass::CrossSiteScripting,
        );
        assert_eq!(engine.evaluate_finding(&public).len(), 0);
    }

    #[test]
    fn new_findings_only_rule() {
        let mut engine = AlertRuleEngine::new();
        engine.add_rule(AlertRule {
            rule_id: "new-only".to_string(),
            name: "New Findings".to_string(),
            enabled: true,
            kind: AlertRuleKind::NewFindingsOnly,
        });

        let new_finding = make_finding("f1", AlertSeverity::High, VulnerabilityClass::SqlInjection);
        assert_eq!(engine.evaluate_finding(&new_finding).len(), 1);

        let mut old_finding =
            make_finding("f2", AlertSeverity::High, VulnerabilityClass::SqlInjection);
        old_finding.is_new = false;
        assert_eq!(engine.evaluate_finding(&old_finding).len(), 0);
    }

    #[test]
    fn disabled_rules_are_skipped() {
        let mut engine = AlertRuleEngine::new();
        let mut rule = severity_rule(AlertSeverity::Info);
        rule.enabled = false;
        engine.add_rule(rule);

        let finding = make_finding(
            "f1",
            AlertSeverity::Critical,
            VulnerabilityClass::SqlInjection,
        );
        assert!(engine.evaluate_finding(&finding).is_empty());
    }

    #[test]
    fn multiple_rules_can_match() {
        let mut engine = AlertRuleEngine::new();
        engine.add_rule(severity_rule(AlertSeverity::High));
        engine.add_rule(AlertRule {
            rule_id: "new-only".to_string(),
            name: "New Findings".to_string(),
            enabled: true,
            kind: AlertRuleKind::NewFindingsOnly,
        });

        let finding = make_finding(
            "f1",
            AlertSeverity::Critical,
            VulnerabilityClass::SqlInjection,
        );
        let matches = engine.evaluate_finding(&finding);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn evaluate_batch_aggregates_all() {
        let mut engine = AlertRuleEngine::new();
        engine.add_rule(severity_rule(AlertSeverity::High));

        let findings = vec![
            make_finding(
                "f1",
                AlertSeverity::Critical,
                VulnerabilityClass::SqlInjection,
            ),
            make_finding("f2", AlertSeverity::Low, VulnerabilityClass::OpenRedirect),
            make_finding(
                "f3",
                AlertSeverity::High,
                VulnerabilityClass::CommandInjection,
            ),
        ];

        let matches = engine.evaluate_batch(&findings);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn remove_rule_by_id() {
        let mut engine = AlertRuleEngine::new();
        engine.add_rule(severity_rule(AlertSeverity::High));
        assert_eq!(engine.rule_count(), 1);
        assert!(engine.remove_rule("sev-threshold"));
        assert_eq!(engine.rule_count(), 0);
        assert!(!engine.remove_rule("nonexistent"));
    }

    #[test]
    fn severity_from_score() {
        assert_eq!(AlertSeverity::from_score(9.5), AlertSeverity::Critical);
        assert_eq!(AlertSeverity::from_score(7.0), AlertSeverity::High);
        assert_eq!(AlertSeverity::from_score(4.0), AlertSeverity::Medium);
        assert_eq!(AlertSeverity::from_score(0.5), AlertSeverity::Low);
        assert_eq!(AlertSeverity::from_score(0.0), AlertSeverity::Info);
    }

    #[test]
    fn rate_of_change_context_zero_baseline() {
        let ctx = RateOfChangeContext {
            findings_current_scan: 10,
            findings_previous_scan: 0,
            time_delta_secs: 3600,
        };
        assert_eq!(ctx.delta(), 10);
        assert_eq!(ctx.percent_increase(), 0.0);
    }

    #[test]
    fn rate_of_change_decrease_is_zero_delta() {
        let ctx = RateOfChangeContext {
            findings_current_scan: 5,
            findings_previous_scan: 10,
            time_delta_secs: 3600,
        };
        assert_eq!(ctx.delta(), 0);
    }
}
