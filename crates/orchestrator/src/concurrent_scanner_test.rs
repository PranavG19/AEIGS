use super::*;
use std::time::Duration;

#[test]
fn default_concurrency_config() {
    let config = ConcurrencyConfig::default();
    assert_eq!(config.max_concurrency, 50);
    assert_eq!(config.per_host_rps, 10.0);
}

#[test]
fn endpoint_priority_ordering() {
    assert!(EndpointPriority::Critical > EndpointPriority::High);
    assert!(EndpointPriority::High > EndpointPriority::Medium);
    assert!(EndpointPriority::Medium > EndpointPriority::Low);
}

#[test]
fn prioritize_admin_as_critical() {
    let endpoints = vec![
        ("http://localhost:8080/admin/users".into(), "GET".into()),
        ("http://localhost:8080/about".into(), "GET".into()),
    ];
    let sorted = prioritize_endpoints(endpoints);
    assert_eq!(sorted[0].priority, EndpointPriority::Critical);
    assert_eq!(sorted[1].priority, EndpointPriority::Low);
}

#[test]
fn prioritize_api_as_high() {
    let endpoints = vec![("http://localhost:8080/api/users".into(), "GET".into())];
    let sorted = prioritize_endpoints(endpoints);
    assert_eq!(sorted[0].priority, EndpointPriority::High);
}

#[test]
fn prioritize_upload_as_medium() {
    let endpoints = vec![("http://localhost:8080/upload".into(), "POST".into())];
    let sorted = prioritize_endpoints(endpoints);
    assert_eq!(sorted[0].priority, EndpointPriority::Medium);
}

#[test]
fn progress_tracker_counts() {
    let tracker = ProgressTracker::new(10);
    assert_eq!(tracker.percent_complete(), 0.0);

    tracker.record_completion(2);
    tracker.record_completion(0);
    let snap = tracker.snapshot();
    assert_eq!(snap.completed, 2);
    assert_eq!(snap.findings_so_far, 2);
    assert_eq!(snap.total_endpoints, 10);
}

#[test]
fn progress_tracker_shutdown() {
    let tracker = ProgressTracker::new(5);
    assert!(!tracker.is_shutdown_requested());
    tracker.request_shutdown();
    assert!(tracker.is_shutdown_requested());
}

#[test]
fn progress_tracker_workers() {
    let tracker = ProgressTracker::new(5);
    tracker.worker_started();
    tracker.worker_started();
    assert_eq!(tracker.snapshot().active_workers, 2);
    tracker.worker_finished();
    assert_eq!(tracker.snapshot().active_workers, 1);
}

#[test]
fn rate_limiter_zero_rps() {
    let limiter = RateLimiter::new(0.0);
    assert_eq!(limiter.interval, Duration::ZERO);
}

#[test]
fn rate_limiter_interval() {
    let limiter = RateLimiter::new(10.0);
    assert_eq!(limiter.interval, Duration::from_millis(100));
}

#[test]
fn extract_host_basic() {
    assert_eq!(
        extract_host_from_url("http://localhost:8080/foo"),
        "localhost"
    );
    assert_eq!(
        extract_host_from_url("https://example.com/bar"),
        "example.com"
    );
}

#[test]
fn scan_state_new() {
    let state = ScanState::new();
    assert!(state.completed_urls.is_empty());
    assert_eq!(state.findings_count, 0);
}

#[test]
fn prioritize_sorts_highest_first() {
    let endpoints = vec![
        ("http://localhost/about".into(), "GET".into()),
        ("http://localhost/admin".into(), "GET".into()),
        ("http://localhost/api/data".into(), "GET".into()),
        ("http://localhost/upload".into(), "POST".into()),
    ];
    let sorted = prioritize_endpoints(endpoints);
    assert_eq!(sorted[0].priority, EndpointPriority::Critical);
    assert_eq!(sorted[1].priority, EndpointPriority::High);
}

#[test]
fn percent_complete_with_zero_total() {
    let tracker = ProgressTracker::new(0);
    assert_eq!(tracker.percent_complete(), 100.0);
}
