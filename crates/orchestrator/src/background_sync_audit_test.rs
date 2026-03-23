use crate::background_sync_audit::*;

#[test]
fn no_sync_no_issues() {
    assert!(analyze_background_sync("<html></html>").is_empty());
}

#[test]
fn detects_sync_register() {
    let body = r#"<script>reg.sync.register("sync-tag")</script>"#;
    let issues = analyze_background_sync(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncRegisterDetected));
}

#[test]
fn detects_periodic_sync() {
    let body = r#"<script>reg.periodicSync.register("update", {minInterval: 3600000})</script>"#;
    let issues = analyze_background_sync(body);
    assert!(issues.contains(&BackgroundSyncIssue::PeriodicSyncDetected));
}

#[test]
fn detects_short_min_interval() {
    let body = r#"<script>reg.periodicSync.register("check", {minInterval: 5000})</script>"#;
    let issues = analyze_background_sync(body);
    assert!(issues.contains(&BackgroundSyncIssue::ShortMinInterval));
}

#[test]
fn no_short_interval_when_large() {
    let body = r#"<script>reg.periodicSync.register("check", {minInterval: 86400000})</script>"#;
    let issues = analyze_background_sync(body);
    assert!(!issues.contains(&BackgroundSyncIssue::ShortMinInterval));
}

#[test]
fn detects_excessive_sync_tags() {
    let body = r#"<script>
        reg.sync.register("a");
        reg.sync.register("b");
        reg.sync.register("c");
        reg.sync.register("d");
        reg.sync.register("e");
        reg.sync.register("f");
    </script>"#;
    let issues = analyze_background_sync(body);
    assert!(issues.contains(&BackgroundSyncIssue::ExcessiveSyncTags));
}

#[test]
fn no_excessive_with_few_tags() {
    let body = r#"<script>
        reg.sync.register("a");
        reg.sync.register("b");
    </script>"#;
    let issues = analyze_background_sync(body);
    assert!(!issues.contains(&BackgroundSyncIssue::ExcessiveSyncTags));
}

#[test]
fn detects_sync_with_fetch() {
    let body = r#"<script>
        reg.sync.register("upload");
        fetch("/api/upload", {method: "POST"});
    </script>"#;
    let issues = analyze_background_sync(body);
    assert!(issues.contains(&BackgroundSyncIssue::SyncWithFetch));
}

#[test]
fn detects_no_permission_check() {
    let body = r#"<script>reg.periodicSync.register("update", {minInterval: 3600000})</script>"#;
    let issues = analyze_background_sync(body);
    assert!(issues.contains(&BackgroundSyncIssue::NoPermissionCheck));
}

#[test]
fn no_permission_issue_when_checked() {
    let body = r#"<script>
        const status = await navigator.permissions.query({name: 'periodic-background-sync'});
        reg.periodicSync.register("update", {minInterval: 3600000});
    </script>"#;
    let issues = analyze_background_sync(body);
    assert!(!issues.contains(&BackgroundSyncIssue::NoPermissionCheck));
}

#[test]
fn severity_periodic_highest() {
    assert_eq!(
        background_sync_severity(&BackgroundSyncIssue::PeriodicSyncDetected),
        6.0
    );
}

#[test]
fn severity_register_lowest() {
    assert_eq!(
        background_sync_severity(&BackgroundSyncIssue::SyncRegisterDetected),
        3.5
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        BackgroundSyncIssue::SyncRegisterDetected,
        BackgroundSyncIssue::SyncWithFetch,
    ];
    let mut seq = 0;
    let ops = background_sync_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        BackgroundSyncIssue::SyncRegisterDetected.to_string(),
        "sync_register_detected"
    );
    assert_eq!(
        BackgroundSyncIssue::PeriodicSyncDetected.to_string(),
        "periodic_sync_detected"
    );
    assert_eq!(
        BackgroundSyncIssue::ShortMinInterval.to_string(),
        "short_min_interval"
    );
    assert_eq!(
        BackgroundSyncIssue::ExcessiveSyncTags.to_string(),
        "excessive_sync_tags"
    );
    assert_eq!(
        BackgroundSyncIssue::SyncWithFetch.to_string(),
        "sync_with_fetch"
    );
    assert_eq!(
        BackgroundSyncIssue::NoPermissionCheck.to_string(),
        "no_permission_check"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_background_sync("").is_empty());
}
