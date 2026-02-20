use crate::convergence::RefutedTracker;

#[test]
fn record_refuted_marks_key_as_refuted() {
    let mut tracker = RefutedTracker::new();
    tracker.record_refuted("sqli:/api/login:' OR 1=1--".to_string());
    assert!(tracker.is_refuted("sqli:/api/login:' OR 1=1--"));
}

#[test]
fn is_refuted_returns_false_for_unknown_keys() {
    let tracker = RefutedTracker::new();
    assert!(!tracker.is_refuted("never-seen"));
}

#[test]
fn refuted_count_tracks_correctly() {
    let mut tracker = RefutedTracker::new();
    assert_eq!(tracker.refuted_count(), 0);
    tracker.record_refuted("a".to_string());
    assert_eq!(tracker.refuted_count(), 1);
    tracker.record_refuted("b".to_string());
    assert_eq!(tracker.refuted_count(), 2);
    tracker.record_refuted("c".to_string());
    assert_eq!(tracker.refuted_count(), 3);
}

#[test]
fn convergence_guaranteed_true_when_threshold_le_max_iterations() {
    assert!(RefutedTracker::convergence_guaranteed(5, 3));
    assert!(RefutedTracker::convergence_guaranteed(5, 5));
    assert!(RefutedTracker::convergence_guaranteed(1, 1));
}

#[test]
fn convergence_guaranteed_false_when_threshold_exceeds_max_iterations() {
    assert!(!RefutedTracker::convergence_guaranteed(3, 5));
    assert!(!RefutedTracker::convergence_guaranteed(1, 2));
    assert!(!RefutedTracker::convergence_guaranteed(0, 1));
}

#[test]
fn convergence_guaranteed_threshold_zero_always_true() {
    assert!(RefutedTracker::convergence_guaranteed(0, 0));
    assert!(RefutedTracker::convergence_guaranteed(1, 0));
    assert!(RefutedTracker::convergence_guaranteed(100, 0));
}

#[test]
fn monotonic_progress_refuted_count_equals_n() {
    let mut tracker = RefutedTracker::new();
    for i in 0..50 {
        tracker.record_refuted(format!("hypothesis-{i}"));
        assert_eq!(tracker.refuted_count(), i + 1);
    }
}

#[test]
fn duplicate_refutations_do_not_increase_count() {
    let mut tracker = RefutedTracker::new();
    tracker.record_refuted("same-key".to_string());
    tracker.record_refuted("same-key".to_string());
    tracker.record_refuted("same-key".to_string());
    assert_eq!(tracker.refuted_count(), 1);
    assert!(tracker.is_refuted("same-key"));
}

#[test]
fn default_tracker_is_empty() {
    let tracker = RefutedTracker::default();
    assert_eq!(tracker.refuted_count(), 0);
    assert!(!tracker.is_refuted("anything"));
}
