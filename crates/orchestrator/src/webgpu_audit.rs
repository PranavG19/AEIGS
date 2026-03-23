use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WebGpuIssue {
    ApiDetected,
    GpuFingerprinting,
    TimingSideChannel,
    CryptoMining,
    MemoryExhaustion,
}

impl std::fmt::Display for WebGpuIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::GpuFingerprinting => write!(f, "gpu_fingerprinting"),
            Self::TimingSideChannel => write!(f, "timing_side_channel"),
            Self::CryptoMining => write!(f, "crypto_mining"),
            Self::MemoryExhaustion => write!(f, "memory_exhaustion"),
        }
    }
}

pub fn audit_webgpu(target: &str) -> Vec<WebGpuIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send() {
        Ok(r) => r.text().unwrap_or_default(),
        Err(_) => return Vec::new(),
    };
    analyze_webgpu(&body)
}

pub fn analyze_webgpu(body: &str) -> Vec<WebGpuIssue> {
    let has_gpu = body.contains("navigator.gpu") || body.contains("GPUAdapter") || body.contains("GPUDevice");

    if !has_gpu {
        return Vec::new();
    }

    let mut issues = Vec::new();
    issues.push(WebGpuIssue::ApiDetected);

    if has_gpu
        && (body.contains("requestAdapterInfo") || body.contains("adapterInfo")
            || body.contains(".features") || body.contains(".limits"))
    {
        issues.push(WebGpuIssue::GpuFingerprinting);
    }

    if has_gpu
        && body.contains("createShaderModule")
        && (body.contains("performance.now") || body.contains("Date.now") || body.contains("timestamp"))
    {
        issues.push(WebGpuIssue::TimingSideChannel);
    }

    if has_gpu
        && (body.contains("createComputePipeline") || body.contains("computePass"))
        && (body.contains("hash") || body.contains("nonce") || body.contains("mining") || body.contains("coin"))
    {
        issues.push(WebGpuIssue::CryptoMining);
    }

    if has_gpu
        && body.contains("createBuffer")
        && (body.contains("while") || body.contains("for(") || body.contains("for ("))
        && !body.contains("destroy(")
    {
        issues.push(WebGpuIssue::MemoryExhaustion);
    }

    issues
}

pub fn webgpu_severity(issue: &WebGpuIssue) -> f64 {
    match issue {
        WebGpuIssue::CryptoMining => 8.0,
        WebGpuIssue::MemoryExhaustion => 7.0,
        WebGpuIssue::TimingSideChannel => 6.0,
        WebGpuIssue::GpuFingerprinting => 5.5,
        WebGpuIssue::ApiDetected => 2.0,
    }
}

pub fn webgpu_to_operations(
    issues: &[WebGpuIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                webgpu_severity(issue),
                0.5,
            )
        })
        .collect()
}
