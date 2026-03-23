use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum SharedBufferIssue {
    SharedArrayBufferWithoutCoep,
    SharedArrayBufferWithoutCoop,
    AtomicsUsage,
    HighResTimerWithSharedBuffer,
    WasmSharedMemory,
    CrossOriginIsolationMissing,
    SharedWorkerWithBuffer,
}

impl std::fmt::Display for SharedBufferIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SharedArrayBufferWithoutCoep => write!(f, "sab_without_coep"),
            Self::SharedArrayBufferWithoutCoop => write!(f, "sab_without_coop"),
            Self::AtomicsUsage => write!(f, "atomics_usage"),
            Self::HighResTimerWithSharedBuffer => write!(f, "highres_timer_shared_buffer"),
            Self::WasmSharedMemory => write!(f, "wasm_shared_memory"),
            Self::CrossOriginIsolationMissing => write!(f, "cross_origin_isolation_missing"),
            Self::SharedWorkerWithBuffer => write!(f, "shared_worker_with_buffer"),
        }
    }
}

pub fn audit_shared_buffer(target: &str) -> Vec<SharedBufferIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let resp = match client.get(target).send() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let coep = resp
        .headers()
        .get("cross-origin-embedder-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let coop = resp
        .headers()
        .get("cross-origin-opener-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = resp.text().unwrap_or_default();
    analyze_shared_buffer(&body, &coep, &coop)
}

pub fn analyze_shared_buffer(body: &str, coep: &str, coop: &str) -> Vec<SharedBufferIssue> {
    if !has_shared_buffer_indicators(body) {
        return Vec::new();
    }

    let mut issues = Vec::new();
    let has_sab = body.contains("SharedArrayBuffer");

    if has_sab && !coep.contains("require-corp") && !coep.contains("credentialless") {
        issues.push(SharedBufferIssue::SharedArrayBufferWithoutCoep);
    }

    if has_sab && !coop.contains("same-origin") {
        issues.push(SharedBufferIssue::SharedArrayBufferWithoutCoop);
    }

    if body.contains("Atomics.") || body.contains("Atomics[") {
        issues.push(SharedBufferIssue::AtomicsUsage);
    }

    if has_sab && (body.contains("performance.now") || body.contains("performance.timeOrigin")) {
        issues.push(SharedBufferIssue::HighResTimerWithSharedBuffer);
    }

    if body.contains("WebAssembly.Memory") && body.contains("shared") {
        issues.push(SharedBufferIssue::WasmSharedMemory);
    }

    if has_sab
        && !coep.contains("require-corp")
        && !coep.contains("credentialless")
        && !coop.contains("same-origin")
    {
        issues.push(SharedBufferIssue::CrossOriginIsolationMissing);
    }

    if body.contains("SharedWorker") && has_sab {
        issues.push(SharedBufferIssue::SharedWorkerWithBuffer);
    }

    issues
}

fn has_shared_buffer_indicators(body: &str) -> bool {
    body.contains("SharedArrayBuffer")
        || body.contains("Atomics.")
        || body.contains("Atomics[")
        || (body.contains("WebAssembly.Memory") && body.contains("shared"))
}

pub fn shared_buffer_severity(issue: &SharedBufferIssue) -> f64 {
    match issue {
        SharedBufferIssue::CrossOriginIsolationMissing => 7.5,
        SharedBufferIssue::HighResTimerWithSharedBuffer => 7.0,
        SharedBufferIssue::SharedArrayBufferWithoutCoep => 6.5,
        SharedBufferIssue::SharedArrayBufferWithoutCoop => 6.5,
        SharedBufferIssue::WasmSharedMemory => 6.0,
        SharedBufferIssue::SharedWorkerWithBuffer => 5.5,
        SharedBufferIssue::AtomicsUsage => 5.0,
    }
}

pub fn shared_buffer_to_operations(
    issues: &[SharedBufferIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                shared_buffer_severity(issue),
                0.7,
            )
        })
        .collect()
}
