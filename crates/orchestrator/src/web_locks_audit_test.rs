use crate::web_locks_audit::*;

#[test]
fn no_locks_api_no_issues() {
    let body = "<html><body>Hello</body></html>";
    assert!(analyze_web_locks(body).is_empty());
}

#[test]
fn detects_lock_request() {
    let body = r#"<script>navigator.locks.request("my_lock", async lock => {})</script>"#;
    let issues = analyze_web_locks(body);
    assert!(issues.contains(&WebLocksIssue::LockRequestDetected));
}

#[test]
fn detects_lock_query() {
    let body = r#"<script>navigator.locks.query().then(state => console.log(state))</script>"#;
    let issues = analyze_web_locks(body);
    assert!(issues.contains(&WebLocksIssue::LockQueryDetected));
}

#[test]
fn detects_steal_option() {
    let body = r#"<script>navigator.locks.request("res", {steal: true}, async lock => {})</script>"#;
    let issues = analyze_web_locks(body);
    assert!(issues.contains(&WebLocksIssue::StealLockOption));
}

#[test]
fn detects_no_abort_signal() {
    let body = r#"<script>navigator.locks.request("res", async lock => { await work(); })</script>"#;
    let issues = analyze_web_locks(body);
    assert!(issues.contains(&WebLocksIssue::NoAbortSignal));
}

#[test]
fn no_abort_issue_when_signal_present() {
    let body = r#"<script>
        const ac = new AbortController();
        navigator.locks.request("res", {signal: ac.signal}, async lock => {});
    </script>"#;
    let issues = analyze_web_locks(body);
    assert!(!issues.contains(&WebLocksIssue::NoAbortSignal));
}

#[test]
fn detects_shared_mode_double_quotes() {
    let body = r#"<script>navigator.locks.request("r", {mode: "shared"}, async l => {})</script>"#;
    let issues = analyze_web_locks(body);
    assert!(issues.contains(&WebLocksIssue::SharedLockMode));
}

#[test]
fn detects_shared_mode_single_quotes() {
    let body = r#"<script>navigator.locks.request("r", {mode: 'shared'}, async l => {})</script>"#;
    let issues = analyze_web_locks(body);
    assert!(issues.contains(&WebLocksIssue::SharedLockMode));
}

#[test]
fn detects_excessive_lock_names() {
    let body = r#"<script>
        navigator.locks.request("a", async l => {});
        navigator.locks.request("b", async l => {});
        navigator.locks.request("c", async l => {});
        navigator.locks.request("d", async l => {});
        navigator.locks.request("e", async l => {});
        navigator.locks.request("f", async l => {});
    </script>"#;
    let issues = analyze_web_locks(body);
    assert!(issues.contains(&WebLocksIssue::ExcessiveLockNames));
}

#[test]
fn no_excessive_with_few_names() {
    let body = r#"<script>
        navigator.locks.request("a", async l => {});
        navigator.locks.request("b", async l => {});
    </script>"#;
    let issues = analyze_web_locks(body);
    assert!(!issues.contains(&WebLocksIssue::ExcessiveLockNames));
}

#[test]
fn duplicate_names_not_counted_twice() {
    let body = r#"<script>
        navigator.locks.request("a", async l => {});
        navigator.locks.request("a", async l => {});
        navigator.locks.request("a", async l => {});
        navigator.locks.request("a", async l => {});
        navigator.locks.request("a", async l => {});
        navigator.locks.request("a", async l => {});
    </script>"#;
    let issues = analyze_web_locks(body);
    assert!(!issues.contains(&WebLocksIssue::ExcessiveLockNames));
}

#[test]
fn severity_steal_highest() {
    assert_eq!(web_locks_severity(&WebLocksIssue::StealLockOption), 6.0);
}

#[test]
fn severity_request_lowest() {
    assert_eq!(web_locks_severity(&WebLocksIssue::LockRequestDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        WebLocksIssue::LockRequestDetected,
        WebLocksIssue::StealLockOption,
    ];
    let mut seq = 0;
    let ops = web_locks_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(WebLocksIssue::LockRequestDetected.to_string(), "lock_request_detected");
    assert_eq!(WebLocksIssue::LockQueryDetected.to_string(), "lock_query_detected");
    assert_eq!(WebLocksIssue::ExcessiveLockNames.to_string(), "excessive_lock_names");
    assert_eq!(WebLocksIssue::SharedLockMode.to_string(), "shared_lock_mode");
    assert_eq!(WebLocksIssue::StealLockOption.to_string(), "steal_lock_option");
    assert_eq!(WebLocksIssue::NoAbortSignal.to_string(), "no_abort_signal");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_web_locks("").is_empty());
}
