use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum WasmIssue {
    WasmModuleLoaded { url: String },
    WasmOverHttp { url: String },
    WasmInstantiateStreaming,
    WasmCompileFromBuffer,
    WasmWithoutCsp,
    WasmImportObject,
}

impl std::fmt::Display for WasmIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WasmModuleLoaded { url } => write!(f, "wasm_module:{url}"),
            Self::WasmOverHttp { url } => write!(f, "wasm_http:{url}"),
            Self::WasmInstantiateStreaming => write!(f, "wasm_instantiate_streaming"),
            Self::WasmCompileFromBuffer => write!(f, "wasm_compile_buffer"),
            Self::WasmWithoutCsp => write!(f, "wasm_no_csp"),
            Self::WasmImportObject => write!(f, "wasm_import_object"),
        }
    }
}

pub fn audit_wasm(target: &str) -> Vec<WasmIssue> {
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

    let csp = resp
        .headers()
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let body = resp.text().unwrap_or_default();
    analyze_wasm_usage(&body, &csp)
}

pub fn analyze_wasm_usage(body: &str, csp: &str) -> Vec<WasmIssue> {
    if !has_wasm_indicators(body) {
        return Vec::new();
    }

    let mut issues = Vec::new();

    find_wasm_urls(body, &mut issues);

    if body.contains("WebAssembly.instantiateStreaming") {
        issues.push(WasmIssue::WasmInstantiateStreaming);
    }

    if (body.contains("WebAssembly.compile(") || body.contains("WebAssembly.instantiate("))
        && (body.contains("ArrayBuffer") || body.contains("Uint8Array") || body.contains("Buffer"))
    {
        issues.push(WasmIssue::WasmCompileFromBuffer);
    }

    if body.contains("importObject") || body.contains("import_object") {
        issues.push(WasmIssue::WasmImportObject);
    }

    if !issues.is_empty() && !csp_allows_wasm_eval(csp) && !csp.is_empty() {
        issues.push(WasmIssue::WasmWithoutCsp);
    }

    issues
}

fn has_wasm_indicators(body: &str) -> bool {
    body.contains("WebAssembly")
        || body.contains(".wasm")
        || body.contains("application/wasm")
        || body.contains("wasm_exec")
}

fn find_wasm_urls(body: &str, issues: &mut Vec<WasmIssue>) {
    for prefix in ["\"", "'", "`"] {
        let suffix = ".wasm";
        let pattern = prefix;
        let mut pos = 0;
        while let Some(idx) = body[pos..].find(pattern) {
            let abs = pos + idx + prefix.len();
            let remaining = &body[abs..];
            let end = remaining
                .find(['"', '\'', '`', ' ', '<', '>', '\n'])
                .unwrap_or(remaining.len().min(300));
            let value = &remaining[..end];
            if value.contains(suffix) && value.len() < 200 {
                if value.starts_with("http://") {
                    issues.push(WasmIssue::WasmOverHttp {
                        url: value.to_string(),
                    });
                }
                issues.push(WasmIssue::WasmModuleLoaded {
                    url: value.to_string(),
                });
                pos = abs + end;
                continue;
            }
            pos = abs + 1;
        }
    }
}

fn csp_allows_wasm_eval(csp: &str) -> bool {
    let lower = csp.to_ascii_lowercase();
    lower.contains("'wasm-unsafe-eval'") || lower.contains("'unsafe-eval'")
}

pub fn wasm_severity(issue: &WasmIssue) -> f64 {
    match issue {
        WasmIssue::WasmOverHttp { .. } => 7.0,
        WasmIssue::WasmCompileFromBuffer => 6.0,
        WasmIssue::WasmImportObject => 5.0,
        WasmIssue::WasmInstantiateStreaming => 4.0,
        WasmIssue::WasmWithoutCsp => 4.0,
        WasmIssue::WasmModuleLoaded { .. } => 3.0,
    }
}

pub fn wasm_to_operations(issues: &[WasmIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                wasm_severity(issue),
                0.7,
            )
        })
        .collect()
}
