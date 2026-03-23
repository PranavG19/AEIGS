use crate::shared_buffer_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_shared_buffer("", "", "");
    assert!(issues.is_empty());
}

#[test]
fn no_shared_buffer_no_issues() {
    let body = "<html><body>Hello</body></html>";
    let issues = analyze_shared_buffer(body, "", "");
    assert!(issues.is_empty());
}

#[test]
fn sab_without_coep() {
    let body = "var buf = new SharedArrayBuffer(1024);";
    let issues = analyze_shared_buffer(body, "", "same-origin");
    assert!(issues.contains(&SharedBufferIssue::SharedArrayBufferWithoutCoep));
}

#[test]
fn sab_with_coep_require_corp() {
    let body = "var buf = new SharedArrayBuffer(1024);";
    let issues = analyze_shared_buffer(body, "require-corp", "same-origin");
    assert!(!issues.contains(&SharedBufferIssue::SharedArrayBufferWithoutCoep));
}

#[test]
fn sab_with_coep_credentialless() {
    let body = "var buf = new SharedArrayBuffer(1024);";
    let issues = analyze_shared_buffer(body, "credentialless", "same-origin");
    assert!(!issues.contains(&SharedBufferIssue::SharedArrayBufferWithoutCoep));
}

#[test]
fn sab_without_coop() {
    let body = "var buf = new SharedArrayBuffer(1024);";
    let issues = analyze_shared_buffer(body, "require-corp", "");
    assert!(issues.contains(&SharedBufferIssue::SharedArrayBufferWithoutCoop));
}

#[test]
fn sab_with_coop_same_origin() {
    let body = "var buf = new SharedArrayBuffer(1024);";
    let issues = analyze_shared_buffer(body, "require-corp", "same-origin");
    assert!(!issues.contains(&SharedBufferIssue::SharedArrayBufferWithoutCoop));
}

#[test]
fn detects_atomics_usage() {
    let body = "Atomics.wait(view, 0, 0);";
    let issues = analyze_shared_buffer(body, "", "");
    assert!(issues.contains(&SharedBufferIssue::AtomicsUsage));
}

#[test]
fn detects_atomics_bracket() {
    let body = "Atomics[\"store\"](arr, 0, 1);";
    let issues = analyze_shared_buffer(body, "", "");
    assert!(issues.contains(&SharedBufferIssue::AtomicsUsage));
}

#[test]
fn detects_high_res_timer_with_sab() {
    let body = r#"
        var sab = new SharedArrayBuffer(4);
        var t = performance.now();
    "#;
    let issues = analyze_shared_buffer(body, "", "");
    assert!(issues.contains(&SharedBufferIssue::HighResTimerWithSharedBuffer));
}

#[test]
fn detects_wasm_shared_memory() {
    let body = r#"new WebAssembly.Memory({initial: 1, maximum: 10, shared: true})"#;
    let issues = analyze_shared_buffer(body, "", "");
    assert!(issues.contains(&SharedBufferIssue::WasmSharedMemory));
}

#[test]
fn detects_cross_origin_isolation_missing() {
    let body = "var buf = new SharedArrayBuffer(1024);";
    let issues = analyze_shared_buffer(body, "", "");
    assert!(issues.contains(&SharedBufferIssue::CrossOriginIsolationMissing));
}

#[test]
fn no_cross_origin_issue_when_isolated() {
    let body = "var buf = new SharedArrayBuffer(1024);";
    let issues = analyze_shared_buffer(body, "require-corp", "same-origin");
    assert!(!issues.contains(&SharedBufferIssue::CrossOriginIsolationMissing));
}

#[test]
fn detects_shared_worker_with_buffer() {
    let body = r#"
        var w = new SharedWorker('worker.js');
        var sab = new SharedArrayBuffer(256);
    "#;
    let issues = analyze_shared_buffer(body, "", "");
    assert!(issues.contains(&SharedBufferIssue::SharedWorkerWithBuffer));
}

#[test]
fn severity_isolation_missing_highest() {
    assert_eq!(
        shared_buffer_severity(&SharedBufferIssue::CrossOriginIsolationMissing),
        7.5
    );
}

#[test]
fn severity_atomics_lowest() {
    assert_eq!(
        shared_buffer_severity(&SharedBufferIssue::AtomicsUsage),
        5.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        SharedBufferIssue::AtomicsUsage,
        SharedBufferIssue::WasmSharedMemory,
    ];
    let mut seq = 0;
    let ops = shared_buffer_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        SharedBufferIssue::SharedArrayBufferWithoutCoep.to_string(),
        "sab_without_coep"
    );
    assert_eq!(
        SharedBufferIssue::CrossOriginIsolationMissing.to_string(),
        "cross_origin_isolation_missing"
    );
    assert_eq!(
        SharedBufferIssue::WasmSharedMemory.to_string(),
        "wasm_shared_memory"
    );
    assert_eq!(SharedBufferIssue::AtomicsUsage.to_string(), "atomics_usage");
}
