use super::error_recovery::*;
use std::time::Duration;

#[test]
fn classify_timeout() {
    let mgr = ErrorRecoveryManager::new();
    let cat = mgr.classify_error("request timed out after 30s");
    assert_eq!(cat, ErrorCategory::NetworkTimeout);
}

#[test]
fn classify_waf_blocked() {
    let mgr = ErrorRecoveryManager::new();
    let cat = mgr.classify_error("403 Forbidden - WAF blocked request");
    assert_eq!(cat, ErrorCategory::WafBlocked);
}

#[test]
fn classify_rate_limited() {
    let mgr = ErrorRecoveryManager::new();
    let cat = mgr.classify_error("HTTP 429 Too Many Requests");
    assert_eq!(cat, ErrorCategory::RateLimited);
}

#[test]
fn classify_disk_full() {
    let mgr = ErrorRecoveryManager::new();
    let cat = mgr.classify_error("write failed: no space left on device");
    assert_eq!(cat, ErrorCategory::DiskFull);
}

#[test]
fn classify_auth_expired() {
    let mgr = ErrorRecoveryManager::new();
    let cat = mgr.classify_error("authentication failed: token expired");
    assert_eq!(cat, ErrorCategory::AuthExpired);
}

#[test]
fn classify_unknown() {
    let mgr = ErrorRecoveryManager::new();
    let cat = mgr.classify_error("something weird happened");
    assert!(matches!(cat, ErrorCategory::Unknown(_)));
}

#[test]
fn strategy_for_timeout_is_retry_backoff() {
    let mgr = ErrorRecoveryManager::new();
    let strat = mgr.strategy_for(&ErrorCategory::NetworkTimeout);
    assert_eq!(strat, RecoveryStrategy::RetryWithBackoff);
}

#[test]
fn strategy_for_waf_is_switch_evasion() {
    let mgr = ErrorRecoveryManager::new();
    let strat = mgr.strategy_for(&ErrorCategory::WafBlocked);
    assert_eq!(strat, RecoveryStrategy::SwitchEvasion);
}

#[test]
fn strategy_for_disk_full_is_emergency_save() {
    let mgr = ErrorRecoveryManager::new();
    let strat = mgr.strategy_for(&ErrorCategory::DiskFull);
    assert_eq!(strat, RecoveryStrategy::EmergencySave);
}

#[test]
fn record_error_increments_counts() {
    let mut mgr = ErrorRecoveryManager::new();
    mgr.record_error("sql_injection", "request timed out");
    mgr.record_error("sql_injection", "another timeout");

    assert_eq!(mgr.module_error_count("sql_injection"), 2);
    assert_eq!(mgr.total_errors(), 2);
}

#[test]
fn consecutive_errors_disable_module() {
    let mut mgr = ErrorRecoveryManager::new().with_max_consecutive_errors(3);

    for _ in 0..3 {
        mgr.record_error("flaky_module", "crash: segfault");
    }

    assert!(mgr.is_module_disabled("flaky_module"));
    assert!(mgr.disabled_modules().contains(&"flaky_module".to_string()));
}

#[test]
fn success_resets_consecutive_errors() {
    let mut mgr = ErrorRecoveryManager::new().with_max_consecutive_errors(3);

    mgr.record_error("scanner", "timeout");
    mgr.record_error("scanner", "timeout");
    mgr.record_success("scanner");
    mgr.record_error("scanner", "timeout");

    assert!(
        !mgr.is_module_disabled("scanner"),
        "should not be disabled after success reset"
    );
}

#[test]
fn disabled_module_returns_skip() {
    let mut mgr = ErrorRecoveryManager::new().with_max_consecutive_errors(2);

    mgr.record_error("broken", "crash");
    let strat = mgr.record_error("broken", "crash");
    assert_eq!(strat, RecoveryStrategy::Skip);
}

#[test]
fn backoff_increases_exponentially() {
    let mgr = ErrorRecoveryManager::new();
    let d0 = mgr.backoff_duration(0);
    let d1 = mgr.backoff_duration(1);
    let d2 = mgr.backoff_duration(2);

    assert_eq!(d0, Duration::from_millis(500));
    assert_eq!(d1, Duration::from_millis(1000));
    assert_eq!(d2, Duration::from_millis(2000));
}

#[test]
fn backoff_capped_at_max() {
    let mgr = ErrorRecoveryManager::new();
    let d_large = mgr.backoff_duration(20);
    assert!(d_large <= Duration::from_secs(30));
}

#[test]
fn should_retry_within_limit() {
    let mgr = ErrorRecoveryManager::new().with_max_retries(3);
    assert!(mgr.should_retry(0));
    assert!(mgr.should_retry(2));
    assert!(!mgr.should_retry(3));
}

#[test]
fn error_log_records_all_events() {
    let mut mgr = ErrorRecoveryManager::new();
    mgr.record_error("mod_a", "timeout");
    mgr.record_error("mod_b", "WAF blocked");

    let log = mgr.error_log();
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].module, "mod_a");
    assert_eq!(log[1].module, "mod_b");
}

#[test]
fn reenable_module() {
    let mut mgr = ErrorRecoveryManager::new().with_max_consecutive_errors(1);
    mgr.record_error("disabled_mod", "crash");
    assert!(mgr.is_module_disabled("disabled_mod"));

    let result = mgr.reenable_module("disabled_mod");
    assert!(result);
    assert!(!mgr.is_module_disabled("disabled_mod"));
    assert!(!mgr.disabled_modules().contains(&"disabled_mod".to_string()));
}

#[test]
fn reenable_nonexistent_returns_false() {
    let mut mgr = ErrorRecoveryManager::new();
    assert!(!mgr.reenable_module("nope"));
}

#[test]
fn error_category_display() {
    assert_eq!(
        format!("{}", ErrorCategory::NetworkTimeout),
        "network timeout"
    );
    assert_eq!(format!("{}", ErrorCategory::WafBlocked), "WAF blocked");
    assert_eq!(
        format!("{}", ErrorCategory::ModuleCrash("xss".into())),
        "module crash: xss"
    );
}
