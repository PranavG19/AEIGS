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

#[test]
fn empty_string_key_is_valid() {
    let mut tracker = RefutedTracker::new();
    tracker.record_refuted(String::new());
    assert!(tracker.is_refuted(""));
    assert_eq!(tracker.refuted_count(), 1);
}

#[test]
fn unicode_keys_stored_correctly() {
    let mut tracker = RefutedTracker::new();
    tracker.record_refuted("xss:/api/日本語:🎯".to_string());
    assert!(tracker.is_refuted("xss:/api/日本語:🎯"));
    assert!(!tracker.is_refuted("xss:/api/日本語:🎯x"));
}

#[test]
fn very_long_key_stored_correctly() {
    let mut tracker = RefutedTracker::new();
    let long_key = "a".repeat(10_000);
    tracker.record_refuted(long_key.clone());
    assert!(tracker.is_refuted(&long_key));
    assert_eq!(tracker.refuted_count(), 1);
}

#[test]
fn large_number_of_refuted_keys() {
    let mut tracker = RefutedTracker::new();
    for i in 0..5000 {
        tracker.record_refuted(format!("hypothesis-{i}"));
    }
    assert_eq!(tracker.refuted_count(), 5000);
    assert!(tracker.is_refuted("hypothesis-0"));
    assert!(tracker.is_refuted("hypothesis-4999"));
    assert!(!tracker.is_refuted("hypothesis-5000"));
}

#[test]
fn convergence_guaranteed_both_zero_is_true() {
    assert!(RefutedTracker::convergence_guaranteed(0, 0));
}

#[test]
fn convergence_guaranteed_large_values() {
    assert!(RefutedTracker::convergence_guaranteed(u32::MAX, u32::MAX));
    assert!(RefutedTracker::convergence_guaranteed(u32::MAX, 0));
    assert!(!RefutedTracker::convergence_guaranteed(0, u32::MAX));
}

#[test]
fn is_refuted_case_sensitive() {
    let mut tracker = RefutedTracker::new();
    tracker.record_refuted("SqlInjection:/api".to_string());
    assert!(tracker.is_refuted("SqlInjection:/api"));
    assert!(!tracker.is_refuted("sqlinjection:/api"));
    assert!(!tracker.is_refuted("SQLINJECTION:/API"));
}

#[test]
fn record_refuted_with_whitespace_key() {
    let mut tracker = RefutedTracker::new();
    tracker.record_refuted("  spaces  ".to_string());
    assert!(tracker.is_refuted("  spaces  "));
    assert!(!tracker.is_refuted("spaces"));
}

#[test]
fn separate_trackers_are_independent() {
    let mut tracker_a = RefutedTracker::new();
    let mut tracker_b = RefutedTracker::new();
    tracker_a.record_refuted("shared-key".to_string());
    assert!(tracker_a.is_refuted("shared-key"));
    assert!(!tracker_b.is_refuted("shared-key"));
    tracker_b.record_refuted("other-key".to_string());
    assert!(!tracker_a.is_refuted("other-key"));
}

#[test]
fn monotonic_count_never_decreases() {
    let mut tracker = RefutedTracker::new();
    let mut prev_count = 0;
    for i in 0..100 {
        tracker.record_refuted(format!("key-{i}"));
        let count = tracker.refuted_count();
        assert!(
            count >= prev_count,
            "count decreased from {prev_count} to {count}"
        );
        prev_count = count;
    }
}

#[test]
fn duplicate_then_new_increments_correctly() {
    let mut tracker = RefutedTracker::new();
    tracker.record_refuted("dup".to_string());
    tracker.record_refuted("dup".to_string());
    tracker.record_refuted("dup".to_string());
    assert_eq!(tracker.refuted_count(), 1);
    tracker.record_refuted("new".to_string());
    assert_eq!(tracker.refuted_count(), 2);
}
