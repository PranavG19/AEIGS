use crate::webgpu_audit::*;

#[test]
fn no_webgpu_no_issues() {
    assert!(analyze_webgpu("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_navigator_gpu() {
    let body = r#"<script>const adapter = await navigator.gpu.requestAdapter();</script>"#;
    let issues = analyze_webgpu(body);
    assert!(issues.contains(&WebGpuIssue::ApiDetected));
}

#[test]
fn detects_gpu_adapter() {
    let body = r#"<script>function init(adapter: GPUAdapter) { /* ... */ }</script>"#;
    let issues = analyze_webgpu(body);
    assert!(issues.contains(&WebGpuIssue::ApiDetected));
}

#[test]
fn detects_gpu_device() {
    let body = r#"<script>const device: GPUDevice = await adapter.requestDevice();</script>"#;
    let issues = analyze_webgpu(body);
    assert!(issues.contains(&WebGpuIssue::ApiDetected));
}

#[test]
fn detects_gpu_fingerprinting_info() {
    let body = r#"<script>
        const adapter = await navigator.gpu.requestAdapter();
        const info = await adapter.requestAdapterInfo();
        sendToServer(info.vendor, info.architecture);
    </script>"#;
    let issues = analyze_webgpu(body);
    assert!(issues.contains(&WebGpuIssue::GpuFingerprinting));
}

#[test]
fn detects_gpu_fingerprinting_features() {
    let body = r#"<script>
        const adapter = await navigator.gpu.requestAdapter();
        const featureList = [...adapter.features];
    </script>"#;
    let issues = analyze_webgpu(body);
    assert!(issues.contains(&WebGpuIssue::GpuFingerprinting));
}

#[test]
fn detects_gpu_fingerprinting_limits() {
    let body = r#"<script>
        const adapter = await navigator.gpu.requestAdapter();
        const maxTex = adapter.limits.maxTextureDimension2D;
    </script>"#;
    let issues = analyze_webgpu(body);
    assert!(issues.contains(&WebGpuIssue::GpuFingerprinting));
}

#[test]
fn no_fingerprint_without_info() {
    let body = r#"<script>const adapter = await navigator.gpu.requestAdapter();</script>"#;
    let issues = analyze_webgpu(body);
    assert!(!issues.contains(&WebGpuIssue::GpuFingerprinting));
}

#[test]
fn detects_timing_side_channel() {
    let body = r#"<script>
        const device = await navigator.gpu.requestAdapter().then(a => a.requestDevice());
        device.createShaderModule({code: wgsl});
        const t0 = performance.now();
    </script>"#;
    let issues = analyze_webgpu(body);
    assert!(issues.contains(&WebGpuIssue::TimingSideChannel));
}

#[test]
fn no_timing_without_perf() {
    let body = r#"<script>
        const device = await navigator.gpu.requestAdapter().then(a => a.requestDevice());
        device.createShaderModule({code: wgsl});
    </script>"#;
    let issues = analyze_webgpu(body);
    assert!(!issues.contains(&WebGpuIssue::TimingSideChannel));
}

#[test]
fn detects_crypto_mining() {
    let body = r#"<script>
        const device = await navigator.gpu.requestAdapter().then(a => a.requestDevice());
        const pipeline = device.createComputePipeline({compute: {module: shader}});
        // hash nonce loop
    </script>"#;
    let issues = analyze_webgpu(body);
    assert!(issues.contains(&WebGpuIssue::CryptoMining));
}

#[test]
fn no_mining_without_hash() {
    let body = r#"<script>
        const device = await navigator.gpu.requestAdapter().then(a => a.requestDevice());
        const pipeline = device.createComputePipeline({compute: {module: shader}});
    </script>"#;
    let issues = analyze_webgpu(body);
    assert!(!issues.contains(&WebGpuIssue::CryptoMining));
}

#[test]
fn detects_memory_exhaustion() {
    let body = r#"<script>
        const device = await navigator.gpu.requestAdapter().then(a => a.requestDevice());
        while (true) {
            device.createBuffer({size: 1024 * 1024, usage: GPUBufferUsage.STORAGE});
        }
    </script>"#;
    let issues = analyze_webgpu(body);
    assert!(issues.contains(&WebGpuIssue::MemoryExhaustion));
}

#[test]
fn no_exhaustion_with_destroy() {
    let body = r#"<script>
        const device = await navigator.gpu.requestAdapter().then(a => a.requestDevice());
        for (let i = 0; i < 10; i++) {
            const buf = device.createBuffer({size: 1024});
            buf.destroy();
        }
    </script>"#;
    let issues = analyze_webgpu(body);
    assert!(!issues.contains(&WebGpuIssue::MemoryExhaustion));
}

#[test]
fn severity_mining_highest() {
    assert_eq!(webgpu_severity(&WebGpuIssue::CryptoMining), 8.0);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(webgpu_severity(&WebGpuIssue::ApiDetected), 2.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![WebGpuIssue::ApiDetected, WebGpuIssue::GpuFingerprinting];
    let mut seq = 0;
    let ops = webgpu_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(WebGpuIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(WebGpuIssue::GpuFingerprinting.to_string(), "gpu_fingerprinting");
    assert_eq!(WebGpuIssue::TimingSideChannel.to_string(), "timing_side_channel");
    assert_eq!(WebGpuIssue::CryptoMining.to_string(), "crypto_mining");
    assert_eq!(WebGpuIssue::MemoryExhaustion.to_string(), "memory_exhaustion");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_webgpu("").is_empty());
}
