#[cfg(test)]
mod tests {
    use aegis_protocol::finding::VulnerabilityClass;

    use crate::scheduler::{FuzzScheduler, FuzzTarget, is_fuzzable};
    use crate::stealth_config::StealthConfig;

    fn target(endpoint: &str, priority: f64) -> FuzzTarget {
        FuzzTarget {
            endpoint: endpoint.to_string(),
            method: "GET".to_string(),
            parameter: "q".to_string(),
            vulnerability_class: VulnerabilityClass::SqlInjection,
            priority_score: priority,
            attempts: 0,
            max_attempts: 3,
        }
    }

    #[test]
    fn empty_scheduler() {
        let mut scheduler = FuzzScheduler::new();
        assert!(scheduler.is_empty());
        assert_eq!(scheduler.pending_count(), 0);
        assert!(scheduler.next_target().is_none());
    }

    #[test]
    fn enqueue_and_dequeue_by_priority() {
        let mut scheduler = FuzzScheduler::new();
        scheduler.enqueue(target("/low", 1.0));
        scheduler.enqueue(target("/high", 10.0));
        scheduler.enqueue(target("/mid", 5.0));

        let next = scheduler.next_target().unwrap();
        assert_eq!(next.endpoint, "/high");
        let next = scheduler.next_target().unwrap();
        assert_eq!(next.endpoint, "/mid");
        let next = scheduler.next_target().unwrap();
        assert_eq!(next.endpoint, "/low");
    }

    #[test]
    fn enqueue_batch() {
        let mut scheduler = FuzzScheduler::new();
        scheduler.enqueue_batch(vec![target("/a", 1.0), target("/b", 2.0)]);
        assert_eq!(scheduler.pending_count(), 2);
    }

    #[test]
    fn mark_completed_re_enqueues_with_lower_priority() {
        let mut scheduler = FuzzScheduler::new();
        scheduler.enqueue(target("/api", 10.0));

        let t = scheduler.next_target().unwrap();
        assert_eq!(t.priority_score, 10.0);

        scheduler.mark_completed(t);
        assert_eq!(scheduler.completed_count(), 1);
        assert_eq!(scheduler.pending_count(), 1);

        let t2 = scheduler.next_target().unwrap();
        assert_eq!(t2.priority_score, 8.0);
        assert_eq!(t2.attempts, 1);
    }

    #[test]
    fn max_attempts_exhaustion() {
        let mut scheduler = FuzzScheduler::new();
        let mut t = target("/api", 10.0);
        t.max_attempts = 1;
        scheduler.enqueue(t);

        let t = scheduler.next_target().unwrap();
        scheduler.mark_completed(t);

        assert!(scheduler.is_empty());
    }

    #[test]
    fn skips_exhausted_targets() {
        let mut scheduler = FuzzScheduler::new();
        let mut exhausted = target("/old", 100.0);
        exhausted.attempts = 3;
        exhausted.max_attempts = 3;

        scheduler.enqueue(exhausted);
        scheduler.enqueue(target("/fresh", 1.0));

        let next = scheduler.next_target().unwrap();
        assert_eq!(next.endpoint, "/fresh");
        assert_eq!(scheduler.skipped_count(), 1);
    }

    #[test]
    fn default_creates_empty_scheduler() {
        let scheduler = FuzzScheduler::default();
        assert!(scheduler.is_empty());
    }

    #[test]
    fn completed_count_increments() {
        let mut scheduler = FuzzScheduler::new();
        scheduler.enqueue(target("/a", 5.0));
        scheduler.enqueue(target("/b", 3.0));

        let t1 = scheduler.next_target().unwrap();
        scheduler.mark_completed(t1);
        assert_eq!(scheduler.completed_count(), 1);

        let t2 = scheduler.next_target().unwrap();
        scheduler.mark_completed(t2);
        assert_eq!(scheduler.completed_count(), 2);
    }

    #[test]
    fn is_fuzzable_returns_true_for_fuzzable_class() {
        assert!(is_fuzzable(VulnerabilityClass::SqlInjection));
    }

    #[test]
    fn is_fuzzable_returns_false_for_non_fuzzable_class() {
        assert!(!is_fuzzable(VulnerabilityClass::BrokenAuthentication));
    }

    fn target_with_class(endpoint: &str, priority: f64, class: VulnerabilityClass) -> FuzzTarget {
        FuzzTarget {
            endpoint: endpoint.to_string(),
            method: "GET".to_string(),
            parameter: "q".to_string(),
            vulnerability_class: class,
            priority_score: priority,
            attempts: 0,
            max_attempts: 3,
        }
    }

    #[test]
    fn reprioritize_boosts_blind_classes() {
        let mut scheduler = FuzzScheduler::new();
        scheduler.enqueue(target_with_class(
            "/sqli",
            10.0,
            VulnerabilityClass::SqlInjection,
        ));
        scheduler.enqueue(target_with_class(
            "/cmdi",
            10.0,
            VulnerabilityClass::CommandInjection,
        ));

        let config = StealthConfig::default().with_prefer_blind_payloads(true);
        scheduler.reprioritize_for_stealth(&config);

        let first = scheduler.next_target().unwrap();
        assert!((first.priority_score - 15.0).abs() < f64::EPSILON);
        let second = scheduler.next_target().unwrap();
        assert!((second.priority_score - 15.0).abs() < f64::EPSILON);
    }

    #[test]
    fn reprioritize_reduces_reflection_classes() {
        let mut scheduler = FuzzScheduler::new();
        scheduler.enqueue(target_with_class(
            "/xss",
            10.0,
            VulnerabilityClass::CrossSiteScripting,
        ));
        scheduler.enqueue(target_with_class(
            "/redir",
            10.0,
            VulnerabilityClass::OpenRedirect,
        ));

        let config = StealthConfig::default().with_prefer_blind_payloads(true);
        scheduler.reprioritize_for_stealth(&config);

        let first = scheduler.next_target().unwrap();
        assert!((first.priority_score - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    fn reprioritize_leaves_other_classes_unchanged() {
        let mut scheduler = FuzzScheduler::new();
        scheduler.enqueue(target_with_class(
            "/path",
            10.0,
            VulnerabilityClass::PathTraversal,
        ));

        let config = StealthConfig::default().with_prefer_blind_payloads(true);
        scheduler.reprioritize_for_stealth(&config);

        let t = scheduler.next_target().unwrap();
        assert!((t.priority_score - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn reprioritize_reorders_queue_correctly() {
        let mut scheduler = FuzzScheduler::new();
        scheduler.enqueue(target_with_class(
            "/xss",
            10.0,
            VulnerabilityClass::CrossSiteScripting,
        ));
        scheduler.enqueue(target_with_class(
            "/sqli",
            8.0,
            VulnerabilityClass::SqlInjection,
        ));

        let config = StealthConfig::default().with_prefer_blind_payloads(true);
        scheduler.reprioritize_for_stealth(&config);

        let first = scheduler.next_target().unwrap();
        assert_eq!(first.endpoint, "/sqli");
        assert!((first.priority_score - 12.0).abs() < f64::EPSILON);
        let second = scheduler.next_target().unwrap();
        assert_eq!(second.endpoint, "/xss");
        assert!((second.priority_score - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    fn reprioritize_no_op_when_prefer_blind_false() {
        let mut scheduler = FuzzScheduler::new();
        scheduler.enqueue(target_with_class(
            "/sqli",
            10.0,
            VulnerabilityClass::SqlInjection,
        ));

        let config = StealthConfig::default().with_prefer_blind_payloads(false);
        scheduler.reprioritize_for_stealth(&config);

        let t = scheduler.next_target().unwrap();
        assert!((t.priority_score - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn avoid_signatures_default_false() {
        let scheduler = FuzzScheduler::new();
        assert!(!scheduler.should_avoid_signatures());
    }

    #[test]
    fn avoid_signatures_set_by_stealth_config() {
        let mut scheduler = FuzzScheduler::new();
        let config = StealthConfig::default().with_avoid_signature_payloads(true);
        scheduler.reprioritize_for_stealth(&config);
        assert!(scheduler.should_avoid_signatures());
    }

    #[test]
    fn avoid_signatures_not_set_when_config_false() {
        let mut scheduler = FuzzScheduler::new();
        let config = StealthConfig::default().with_avoid_signature_payloads(false);
        scheduler.reprioritize_for_stealth(&config);
        assert!(!scheduler.should_avoid_signatures());
    }

    #[test]
    fn novelty_high_boosts_priority() {
        let mut scheduler = FuzzScheduler::new();
        scheduler.enqueue(target("/api", 10.0));

        let t = scheduler.next_target().unwrap();
        scheduler.mark_completed_with_novelty(t, 0.9);

        let t2 = scheduler.next_target().unwrap();
        assert!((t2.priority_score - 12.0).abs() < f64::EPSILON);
        assert_eq!(t2.attempts, 1);
    }

    #[test]
    fn novelty_medium_decays_priority() {
        let mut scheduler = FuzzScheduler::new();
        scheduler.enqueue(target("/api", 10.0));

        let t = scheduler.next_target().unwrap();
        scheduler.mark_completed_with_novelty(t, 0.5);

        let t2 = scheduler.next_target().unwrap();
        assert!((t2.priority_score - 9.0).abs() < f64::EPSILON);
        assert_eq!(t2.attempts, 1);
    }

    #[test]
    fn novelty_low_decays_priority_faster() {
        let mut scheduler = FuzzScheduler::new();
        scheduler.enqueue(target("/api", 10.0));

        let t = scheduler.next_target().unwrap();
        scheduler.mark_completed_with_novelty(t, 0.1);

        let t2 = scheduler.next_target().unwrap();
        assert!((t2.priority_score - 7.0).abs() < f64::EPSILON);
        assert_eq!(t2.attempts, 1);
    }

    #[test]
    fn novelty_respects_max_attempts() {
        let mut scheduler = FuzzScheduler::new();
        let mut t = target("/api", 10.0);
        t.max_attempts = 1;
        scheduler.enqueue(t);

        let t = scheduler.next_target().unwrap();
        scheduler.mark_completed_with_novelty(t, 0.9);

        assert!(scheduler.is_empty());
        assert_eq!(scheduler.completed_count(), 1);
    }

    #[test]
    fn novelty_boundary_0_3_is_medium() {
        let mut scheduler = FuzzScheduler::new();
        scheduler.enqueue(target("/api", 10.0));

        let t = scheduler.next_target().unwrap();
        scheduler.mark_completed_with_novelty(t, 0.3);

        let t2 = scheduler.next_target().unwrap();
        assert!((t2.priority_score - 9.0).abs() < f64::EPSILON);
    }

    #[test]
    fn novelty_boundary_0_7_is_medium() {
        let mut scheduler = FuzzScheduler::new();
        scheduler.enqueue(target("/api", 10.0));

        let t = scheduler.next_target().unwrap();
        scheduler.mark_completed_with_novelty(t, 0.7);

        let t2 = scheduler.next_target().unwrap();
        assert!((t2.priority_score - 9.0).abs() < f64::EPSILON);
    }

    #[test]
    fn reprioritize_by_endpoints_boosts_matching() {
        let mut scheduler = FuzzScheduler::new();
        scheduler.enqueue(target("/api/low", 5.0));
        scheduler.enqueue(target("/api/high", 5.0));

        scheduler.reprioritize_by_endpoints(&["/api/high".to_string()], 3.0);

        let first = scheduler.next_target().unwrap();
        assert_eq!(first.endpoint, "/api/high");
        assert!((first.priority_score - 15.0).abs() < f64::EPSILON);
    }

    #[test]
    fn reprioritize_by_endpoints_empty_list_is_noop() {
        let mut scheduler = FuzzScheduler::new();
        scheduler.enqueue(target("/api", 10.0));

        scheduler.reprioritize_by_endpoints(&[], 5.0);

        let t = scheduler.next_target().unwrap();
        assert!((t.priority_score - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn inject_targets_adds_to_queue() {
        let mut scheduler = FuzzScheduler::new();
        scheduler.enqueue(target("/existing", 5.0));

        scheduler.inject_targets(vec![
            target("/new1", 8.0),
            target("/new2", 3.0),
        ]);

        assert_eq!(scheduler.pending_count(), 3);
        let first = scheduler.next_target().unwrap();
        assert_eq!(first.endpoint, "/new1");
    }

    #[test]
    fn inject_targets_preserves_heap_ordering() {
        let mut scheduler = FuzzScheduler::new();
        scheduler.enqueue(target("/a", 10.0));
        scheduler.inject_targets(vec![target("/b", 20.0)]);

        let first = scheduler.next_target().unwrap();
        assert_eq!(first.endpoint, "/b");

        let second = scheduler.next_target().unwrap();
        assert_eq!(second.endpoint, "/a");
    }
}
