#[cfg(test)]
mod tests {
    use crate::scheduler::{FuzzScheduler, FuzzTarget, VulnerabilityClassTarget};

    fn target(endpoint: &str, priority: f64) -> FuzzTarget {
        FuzzTarget {
            endpoint: endpoint.to_string(),
            method: "GET".to_string(),
            parameter: "q".to_string(),
            vulnerability_class: VulnerabilityClassTarget::SqlInjection,
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
    fn vulnerability_class_display() {
        assert_eq!(VulnerabilityClassTarget::SqlInjection.to_string(), "sqli");
        assert_eq!(
            VulnerabilityClassTarget::CrossSiteScripting.to_string(),
            "xss"
        );
        assert_eq!(
            VulnerabilityClassTarget::CommandInjection.to_string(),
            "cmdi"
        );
        assert_eq!(
            VulnerabilityClassTarget::PathTraversal.to_string(),
            "path-traversal"
        );
        assert_eq!(
            VulnerabilityClassTarget::ServerSideRequestForgery.to_string(),
            "ssrf"
        );
        assert_eq!(
            VulnerabilityClassTarget::ServerSideTemplateInjection.to_string(),
            "ssti"
        );
        assert_eq!(
            VulnerabilityClassTarget::Deserialization.to_string(),
            "deserialization"
        );
        assert_eq!(
            VulnerabilityClassTarget::HeaderInjection.to_string(),
            "header-injection"
        );
        assert_eq!(
            VulnerabilityClassTarget::OpenRedirect.to_string(),
            "open-redirect"
        );
        assert_eq!(VulnerabilityClassTarget::CrlfInjection.to_string(), "crlf");
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
}
