use crate::web_locks_audit::*;

#[test]
fn test_no_web_locks_api() {
    let body = r#"
        <script>
        function loadData() {
            fetch('/api/data').then(r => r.json());
        }
        </script>
    "#;
    let issues = analyze_web_locks(body);
    assert!(issues.is_empty());
}

#[test]
fn test_lock_request_detected() {
    let body = r#"
        <script>
        navigator.locks.request('resource', async lock => {
            await doWork();
        });
        </script>
    "#;
    let issues = analyze_web_locks(body);
    assert!(issues.contains(&WebLocksIssue::ApiDetected));
}

#[test]
fn test_lock_query_detected() {
    let body = r#"
        <script>
        navigator.locks.query().then(info => {
            console.log(info);
        });
        </script>
    "#;
    let issues = analyze_web_locks(body);
    assert!(issues.contains(&WebLocksIssue::ApiDetected));
    assert!(issues.contains(&WebLocksIssue::LockEnumeration));
}

#[test]
fn test_lock_manager_detected() {
    let body = r#"
        <script>
        if ('LockManager' in window) {
            console.log('Locks API supported');
        }
        </script>
    "#;
    let issues = analyze_web_locks(body);
    assert!(issues.contains(&WebLocksIssue::ApiDetected));
}

#[test]
fn test_deadlock_risk_nested_without_timeout() {
    let body = r#"
        <script>
        navigator.locks.request('a', async lock => {
            await navigator.locks.request('b', async lock2 => {
                await work();
            });
        });
        </script>
    "#;
    let issues = analyze_web_locks(body);
    assert!(issues.contains(&WebLocksIssue::DeadlockRisk));
}

#[test]
fn test_no_deadlock_risk_with_abort_controller() {
    let body = r#"
        <script>
        const controller = new AbortController();
        navigator.locks.request('a', { signal: controller.signal }, async lock => {
            await navigator.locks.request('b', async lock2 => {
                await work();
            });
        });
        </script>
    "#;
    let issues = analyze_web_locks(body);
    assert!(!issues.contains(&WebLocksIssue::DeadlockRisk));
}

#[test]
fn test_no_deadlock_risk_with_signal() {
    let body = r#"
        <script>
        navigator.locks.request('a', { signal: abortSignal }, async lock => {
            await navigator.locks.request('b', async lock2 => {
                await work();
            });
        });
        </script>
    "#;
    let issues = analyze_web_locks(body);
    assert!(!issues.contains(&WebLocksIssue::DeadlockRisk));
}

#[test]
fn test_resource_starvation_no_error_handling() {
    let body = r#"
        <script>
        navigator.locks.request('resource', async lock => {
            await riskyOperation();
        });
        </script>
    "#;
    let issues = analyze_web_locks(body);
    assert!(issues.contains(&WebLocksIssue::ResourceStarvation));
}

#[test]
fn test_no_resource_starvation_with_catch() {
    let body = r#"
        <script>
        navigator.locks.request('resource', async lock => {
            await riskyOperation();
        }).catch(err => console.error(err));
        </script>
    "#;
    let issues = analyze_web_locks(body);
    assert!(!issues.contains(&WebLocksIssue::ResourceStarvation));
}

#[test]
fn test_no_resource_starvation_with_try_catch() {
    let body = r#"
        <script>
        navigator.locks.request('resource', async lock => {
            try {
                await riskyOperation();
            } catch (err) {
                console.error(err);
            }
        });
        </script>
    "#;
    let issues = analyze_web_locks(body);
    assert!(!issues.contains(&WebLocksIssue::ResourceStarvation));
}

#[test]
fn test_no_resource_starvation_with_finally() {
    let body = r#"
        <script>
        navigator.locks.request('resource', async lock => {
            await riskyOperation();
        }).finally(() => cleanup());
        </script>
    "#;
    let issues = analyze_web_locks(body);
    assert!(!issues.contains(&WebLocksIssue::ResourceStarvation));
}

#[test]
fn test_shared_state_corruption() {
    let body = r#"
        <script>
        navigator.locks.request('resource', { mode: "shared" }, async lock => {
            state = await fetchInfo();
        });
        </script>
    "#;
    let issues = analyze_web_locks(body);
    assert!(issues.contains(&WebLocksIssue::SharedStateCorruption));
}

#[test]
fn test_shared_state_corruption_single_quotes() {
    let body = r#"
        <script>
        navigator.locks.request('resource', { mode:'shared' }, async lock => {
            data = processInput();
        });
        </script>
    "#;
    let issues = analyze_web_locks(body);
    assert!(issues.contains(&WebLocksIssue::SharedStateCorruption));
}

#[test]
fn test_no_shared_state_corruption_exclusive_mode() {
    let body = r#"
        <script>
        navigator.locks.request('resource', { mode: "exclusive" }, async lock => {
            state = await fetchInfo();
        });
        </script>
    "#;
    let issues = analyze_web_locks(body);
    assert!(!issues.contains(&WebLocksIssue::SharedStateCorruption));
}

#[test]
fn test_lock_enumeration() {
    let body = r#"
        <script>
        async function checkLocks() {
            const info = await navigator.locks.query();
            return info.held.length > 0;
        }
        </script>
    "#;
    let issues = analyze_web_locks(body);
    assert!(issues.contains(&WebLocksIssue::LockEnumeration));
}

#[test]
fn test_combined_issues() {
    let body = r#"
        <script>
        navigator.locks.request('a', async lock => {
            await navigator.locks.request('b', async lock2 => {
                await work();
            });
        });
        navigator.locks.query().then(info => console.log(info));
        </script>
    "#;
    let issues = analyze_web_locks(body);
    assert!(issues.contains(&WebLocksIssue::ApiDetected));
    assert!(issues.contains(&WebLocksIssue::DeadlockRisk));
    assert!(issues.contains(&WebLocksIssue::ResourceStarvation));
    assert!(issues.contains(&WebLocksIssue::LockEnumeration));
}

#[test]
fn test_to_operations() {
    let issues = vec![WebLocksIssue::ApiDetected, WebLocksIssue::DeadlockRisk];
    let mut seq = 0u64;
    let ops = web_locks_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn test_severity_values() {
    assert_eq!(web_locks_severity(&WebLocksIssue::ApiDetected), 2.0);
    assert_eq!(web_locks_severity(&WebLocksIssue::DeadlockRisk), 6.0);
    assert_eq!(web_locks_severity(&WebLocksIssue::ResourceStarvation), 6.5);
    assert_eq!(
        web_locks_severity(&WebLocksIssue::SharedStateCorruption),
        7.5
    );
    assert_eq!(web_locks_severity(&WebLocksIssue::LockEnumeration), 5.0);
}

#[test]
fn test_display_impl() {
    assert_eq!(WebLocksIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(WebLocksIssue::DeadlockRisk.to_string(), "deadlock_risk");
    assert_eq!(
        WebLocksIssue::ResourceStarvation.to_string(),
        "resource_starvation"
    );
    assert_eq!(
        WebLocksIssue::SharedStateCorruption.to_string(),
        "shared_state_corruption"
    );
    assert_eq!(
        WebLocksIssue::LockEnumeration.to_string(),
        "lock_enumeration"
    );
}

#[test]
fn test_empty_body() {
    let issues = analyze_web_locks("");
    assert!(issues.is_empty());
}

#[test]
fn test_single_request_no_deadlock() {
    let body = r#"
        <script>
        navigator.locks.request('single', async lock => {
            await work();
        });
        </script>
    "#;
    let issues = analyze_web_locks(body);
    assert!(!issues.contains(&WebLocksIssue::DeadlockRisk));
}

#[test]
fn test_no_shared_corruption_without_write() {
    let body = r#"
        <script>
        navigator.locks.request('resource', { mode: "shared" }, async lock => {
            const value = await fetchInfo();
            console.log(value);
        });
        </script>
    "#;
    let issues = analyze_web_locks(body);
    assert!(!issues.contains(&WebLocksIssue::SharedStateCorruption));
}
