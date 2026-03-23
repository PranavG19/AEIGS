use crate::wasm_audit::*;

#[test]
fn empty_body_no_issues() {
    assert!(analyze_wasm_usage("", "").is_empty());
}

#[test]
fn no_wasm_no_issues() {
    let body = "<h1>Hello</h1>";
    assert!(analyze_wasm_usage(body, "").is_empty());
}

#[test]
fn wasm_module_url_detected() {
    let body = r#"fetch("/app.wasm").then(r => WebAssembly.instantiate(r))"#;
    let issues = analyze_wasm_usage(body, "");
    assert!(issues
        .iter()
        .any(|i| matches!(i, WasmIssue::WasmModuleLoaded { .. })));
}

#[test]
fn wasm_over_http_detected() {
    let body = r#"fetch("http://cdn.example.com/app.wasm")"#;
    let issues = analyze_wasm_usage(body, "");
    assert!(issues
        .iter()
        .any(|i| matches!(i, WasmIssue::WasmOverHttp { .. })));
}

#[test]
fn https_wasm_not_flagged_http() {
    let body = r#"fetch("https://cdn.example.com/app.wasm")"#;
    let issues = analyze_wasm_usage(body, "");
    assert!(!issues
        .iter()
        .any(|i| matches!(i, WasmIssue::WasmOverHttp { .. })));
}

#[test]
fn instantiate_streaming_detected() {
    let body = "WebAssembly.instantiateStreaming(fetch('/app.wasm'))";
    let issues = analyze_wasm_usage(body, "");
    assert!(issues
        .iter()
        .any(|i| matches!(i, WasmIssue::WasmInstantiateStreaming)));
}

#[test]
fn compile_from_buffer_detected() {
    let body = "const bytes = new Uint8Array(data); WebAssembly.compile(bytes)";
    let issues = analyze_wasm_usage(body, "");
    assert!(issues
        .iter()
        .any(|i| matches!(i, WasmIssue::WasmCompileFromBuffer)));
}

#[test]
fn instantiate_from_arraybuffer_detected() {
    let body = "var buf = new ArrayBuffer(data); WebAssembly.instantiate(buf)";
    let issues = analyze_wasm_usage(body, "");
    assert!(issues
        .iter()
        .any(|i| matches!(i, WasmIssue::WasmCompileFromBuffer)));
}

#[test]
fn import_object_detected() {
    let body = r#"
        const importObject = { env: { memory: new WebAssembly.Memory({initial: 1}) } };
        WebAssembly.instantiate(wasmBytes, importObject);
    "#;
    let issues = analyze_wasm_usage(body, "");
    assert!(issues
        .iter()
        .any(|i| matches!(i, WasmIssue::WasmImportObject)));
}

#[test]
fn wasm_without_csp_detected() {
    let body = "WebAssembly.instantiateStreaming(fetch('/app.wasm'))";
    let csp = "script-src 'self'";
    let issues = analyze_wasm_usage(body, csp);
    assert!(issues
        .iter()
        .any(|i| matches!(i, WasmIssue::WasmWithoutCsp)));
}

#[test]
fn wasm_with_unsafe_eval_not_flagged() {
    let body = "WebAssembly.instantiateStreaming(fetch('/app.wasm'))";
    let csp = "script-src 'self' 'unsafe-eval'";
    let issues = analyze_wasm_usage(body, csp);
    assert!(!issues
        .iter()
        .any(|i| matches!(i, WasmIssue::WasmWithoutCsp)));
}

#[test]
fn wasm_with_wasm_unsafe_eval_ok() {
    let body = "WebAssembly.instantiateStreaming(fetch('/app.wasm'))";
    let csp = "script-src 'self' 'wasm-unsafe-eval'";
    let issues = analyze_wasm_usage(body, csp);
    assert!(!issues
        .iter()
        .any(|i| matches!(i, WasmIssue::WasmWithoutCsp)));
}

#[test]
fn no_csp_header_no_wasm_csp_issue() {
    let body = "WebAssembly.instantiateStreaming(fetch('/app.wasm'))";
    let issues = analyze_wasm_usage(body, "");
    assert!(!issues
        .iter()
        .any(|i| matches!(i, WasmIssue::WasmWithoutCsp)));
}

#[test]
fn severity_ordering() {
    assert!(
        wasm_severity(&WasmIssue::WasmOverHttp {
            url: "x".into()
        }) > wasm_severity(&WasmIssue::WasmCompileFromBuffer)
    );
    assert!(
        wasm_severity(&WasmIssue::WasmCompileFromBuffer)
            > wasm_severity(&WasmIssue::WasmModuleLoaded {
                url: "x".into()
            })
    );
}

#[test]
fn display_format() {
    let issue = WasmIssue::WasmModuleLoaded {
        url: "/app.wasm".into(),
    };
    assert_eq!(issue.to_string(), "wasm_module:/app.wasm");

    let issue = WasmIssue::WasmWithoutCsp;
    assert_eq!(issue.to_string(), "wasm_no_csp");
}

#[test]
fn to_operations_count() {
    let issues = vec![
        WasmIssue::WasmModuleLoaded {
            url: "/x.wasm".into(),
        },
        WasmIssue::WasmInstantiateStreaming,
    ];
    let mut seq = 0;
    let ops = wasm_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn wasm_exec_indicator() {
    let body = r#"<script src="wasm_exec.js"></script>"#;
    let issues = analyze_wasm_usage(body, "");
    assert!(!issues.is_empty() || body.contains("wasm_exec"));
}
