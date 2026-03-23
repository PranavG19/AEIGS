use crate::wake_lock_audit::*;

#[test]
fn no_wake_lock_no_issues() {
    assert!(analyze_wake_lock("<html></html>").is_empty());
}

#[test]
fn detects_wake_lock_request() {
    let body = r#"<script>navigator.wakeLock.request("screen")</script>"#;
    let issues = analyze_wake_lock(body);
    assert!(issues.contains(&WakeLockIssue::WakeLockRequested));
}

#[test]
fn detects_screen_wake_lock() {
    let body = r#"<script>navigator.wakeLock.request("screen")</script>"#;
    let issues = analyze_wake_lock(body);
    assert!(issues.contains(&WakeLockIssue::ScreenWakeLock));
}

#[test]
fn detects_screen_single_quotes() {
    let body = r#"<script>navigator.wakeLock.request('screen')</script>"#;
    let issues = analyze_wake_lock(body);
    assert!(issues.contains(&WakeLockIssue::ScreenWakeLock));
}

#[test]
fn detects_no_release() {
    let body = r#"<script>
        const lock = await navigator.wakeLock.request("screen");
        doWork();
    </script>"#;
    let issues = analyze_wake_lock(body);
    assert!(issues.contains(&WakeLockIssue::NoRelease));
}

#[test]
fn no_release_issue_when_released() {
    let body = r#"<script>
        const lock = await navigator.wakeLock.request("screen");
        doWork();
        lock.release();
    </script>"#;
    let issues = analyze_wake_lock(body);
    assert!(!issues.contains(&WakeLockIssue::NoRelease));
}

#[test]
fn detects_no_visibility_check() {
    let body = r#"<script>navigator.wakeLock.request("screen")</script>"#;
    let issues = analyze_wake_lock(body);
    assert!(issues.contains(&WakeLockIssue::NoVisibilityCheck));
}

#[test]
fn no_visibility_issue_when_checked() {
    let body = r#"<script>
        const lock = await navigator.wakeLock.request("screen");
        document.addEventListener("visibilitychange", () => {
            if (document.hidden) lock.release();
        });
    </script>"#;
    let issues = analyze_wake_lock(body);
    assert!(!issues.contains(&WakeLockIssue::NoVisibilityCheck));
}

#[test]
fn detects_persistent_lock() {
    let body = r#"<script>
        setInterval(async () => {
            await navigator.wakeLock.request("screen");
        }, 10000);
    </script>"#;
    let issues = analyze_wake_lock(body);
    assert!(issues.contains(&WakeLockIssue::PersistentLock));
}

#[test]
fn severity_persistent_highest() {
    assert_eq!(wake_lock_severity(&WakeLockIssue::PersistentLock), 5.5);
}

#[test]
fn severity_requested_lowest() {
    assert_eq!(wake_lock_severity(&WakeLockIssue::WakeLockRequested), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        WakeLockIssue::WakeLockRequested,
        WakeLockIssue::NoRelease,
    ];
    let mut seq = 0;
    let ops = wake_lock_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(WakeLockIssue::WakeLockRequested.to_string(), "wake_lock_requested");
    assert_eq!(WakeLockIssue::ScreenWakeLock.to_string(), "screen_wake_lock");
    assert_eq!(WakeLockIssue::NoRelease.to_string(), "no_release");
    assert_eq!(WakeLockIssue::NoVisibilityCheck.to_string(), "no_visibility_check");
    assert_eq!(WakeLockIssue::PersistentLock.to_string(), "persistent_lock");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_wake_lock("").is_empty());
}
