use crate::page_lifecycle_audit::*;

#[test]
fn test_no_lifecycle_api() {
    let body = "<script>console.log('hello');</script>";
    let issues = analyze_page_lifecycle(body);
    assert!(issues.is_empty());
}

#[test]
fn test_api_detected_freeze() {
    let body = "<script>document.addEventListener('freeze', () => {});</script>";
    let issues = analyze_page_lifecycle(body);
    assert_eq!(issues, vec![PageLifecycleIssue::ApiDetected]);
}

#[test]
fn test_api_detected_resume() {
    let body = "<script>document.addEventListener('resume', handleResume);</script>";
    let issues = analyze_page_lifecycle(body);
    assert_eq!(issues, vec![PageLifecycleIssue::ApiDetected]);
}

#[test]
fn test_api_detected_visibilitychange() {
    let body = "<script>document.addEventListener('visibilitychange', track);</script>";
    let issues = analyze_page_lifecycle(body);
    assert_eq!(issues, vec![PageLifecycleIssue::ApiDetected]);
}

#[test]
fn test_api_detected_was_discarded() {
    let body = "<script>if (document.wasDiscarded) { init(); }</script>";
    let issues = analyze_page_lifecycle(body);
    assert_eq!(issues, vec![PageLifecycleIssue::ApiDetected]);
}

#[test]
fn test_api_detected_pagehide() {
    let body = "<script>window.addEventListener('pagehide', cleanup);</script>";
    let issues = analyze_page_lifecycle(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], PageLifecycleIssue::ApiDetected);
}

#[test]
fn test_api_detected_pageshow() {
    let body = "<script>window.addEventListener('pageshow', init);</script>";
    let issues = analyze_page_lifecycle(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], PageLifecycleIssue::ApiDetected);
}

#[test]
fn test_data_leak_on_freeze_with_fetch() {
    let body = r#"
        <script>
        document.addEventListener('freeze', () => {
            fetch('/track', {method: 'POST'});
        });
        </script>
    "#;
    let issues = analyze_page_lifecycle(body);
    assert!(issues.contains(&PageLifecycleIssue::ApiDetected));
    assert!(issues.contains(&PageLifecycleIssue::DataLeakOnFreeze));
}

#[test]
fn test_data_leak_on_pagehide_with_sendbeacon() {
    let body = r#"
        <script>
        window.addEventListener('pagehide', () => {
            navigator.sendBeacon('/analytics', data);
        });
        </script>
    "#;
    let issues = analyze_page_lifecycle(body);
    assert!(issues.contains(&PageLifecycleIssue::DataLeakOnFreeze));
}

#[test]
fn test_data_leak_on_visibilitychange_with_xmlhttprequest() {
    let body = r#"
        <script>
        document.addEventListener('visibilitychange', () => {
            const xhr = new XMLHttpRequest();
            xhr.open('POST', '/track');
        });
        </script>
    "#;
    let issues = analyze_page_lifecycle(body);
    assert!(issues.contains(&PageLifecycleIssue::DataLeakOnFreeze));
}

#[test]
fn test_state_restoration_risk_without_validation() {
    let body = r#"
        <script>
        window.addEventListener('pageshow', (e) => {
            if (e.persisted) {
                const state = sessionStorage.getItem('userState');
                applyState(state);
            }
        });
        </script>
    "#;
    let issues = analyze_page_lifecycle(body);
    assert!(issues.contains(&PageLifecycleIssue::StateRestorationRisk));
}

#[test]
fn test_state_restoration_with_validation_is_safe() {
    let body = r#"
        <script>
        window.addEventListener('pageshow', (e) => {
            const state = sessionStorage.getItem('userState');
            if (validate(state)) {
                applyState(state);
            }
        });
        </script>
    "#;
    let issues = analyze_page_lifecycle(body);
    assert!(!issues.contains(&PageLifecycleIssue::StateRestorationRisk));
}

#[test]
fn test_state_restoration_with_localstorage() {
    let body = r#"
        <script>
        document.addEventListener('resume', () => {
            const data = localStorage.getItem('appData');
            restoreApp(data);
        });
        </script>
    "#;
    let issues = analyze_page_lifecycle(body);
    assert!(issues.contains(&PageLifecycleIssue::StateRestorationRisk));
}

#[test]
fn test_bfcache_abuse() {
    let body = r#"
        <script>
        window.addEventListener('pageshow', (e) => {
            if (e.persisted) {
                cache.restore();
            }
        });
        </script>
    "#;
    let issues = analyze_page_lifecycle(body);
    assert!(issues.contains(&PageLifecycleIssue::BackForwardCacheAbuse));
}

#[test]
fn test_bfcache_with_performance_navigation() {
    let body = r#"
        <script>
        window.addEventListener('pageshow', () => {
            if (performance.navigation.type === 2) {
                restoreCache();
            }
        });
        </script>
    "#;
    let issues = analyze_page_lifecycle(body);
    assert!(issues.contains(&PageLifecycleIssue::BackForwardCacheAbuse));
}

#[test]
fn test_unload_data_loss() {
    let body = r#"
        <script>
        window.addEventListener('beforeunload', (e) => {
            if (dirty) {
                e.returnValue = 'You have pending changes';
            }
        });
        </script>
    "#;
    let issues = analyze_page_lifecycle(body);
    assert!(issues.contains(&PageLifecycleIssue::UnloadDataLoss));
}

#[test]
fn test_unload_data_loss_with_dirty_flag() {
    let body = r#"
        <script>
        window.addEventListener('unload', () => {
            if (dirty) {
                logError('Data may be lost');
            }
        });
        </script>
    "#;
    let issues = analyze_page_lifecycle(body);
    assert!(issues.contains(&PageLifecycleIssue::UnloadDataLoss));
}

#[test]
fn test_unload_with_save_is_safe() {
    let body = r#"
        <script>
        window.addEventListener('pagehide', () => {
            if (modified) {
                save();
            }
        });
        </script>
    "#;
    let issues = analyze_page_lifecycle(body);
    assert!(!issues.contains(&PageLifecycleIssue::UnloadDataLoss));
}

#[test]
fn test_severity_values() {
    assert_eq!(page_lifecycle_severity(&PageLifecycleIssue::ApiDetected), 2.0);
    assert_eq!(page_lifecycle_severity(&PageLifecycleIssue::DataLeakOnFreeze), 7.0);
    assert_eq!(page_lifecycle_severity(&PageLifecycleIssue::StateRestorationRisk), 6.5);
    assert_eq!(page_lifecycle_severity(&PageLifecycleIssue::BackForwardCacheAbuse), 6.0);
    assert_eq!(page_lifecycle_severity(&PageLifecycleIssue::UnloadDataLoss), 5.5);
}

#[test]
fn test_to_operations() {
    let issues = vec![
        PageLifecycleIssue::ApiDetected,
        PageLifecycleIssue::DataLeakOnFreeze,
    ];
    let mut seq = 0u64;
    let ops = page_lifecycle_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
}
