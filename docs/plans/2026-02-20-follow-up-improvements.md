# AEGIS Follow-Up Improvements Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix functional gaps, enable parameter-aware fuzzing, wire hypothesis-engine IPC, enrich SARIF output, and add true end-to-end scanner-vs-fixture tests.

**Architecture:** Five groups in dependency order: (1) cleanup/docs, (2) parameter-aware fuzzing pipeline, (3) SARIF enrichment, (4) hypothesis-engine subprocess bridge, (5) end-to-end scanner tests. Groups 2-3 are prerequisites for Group 5. Group 4 is independent.

**Tech Stack:** Rust 2024, Python 3.12, Docker/Colima, serde_json, subprocess IPC (stdin/stdout JSON), reqwest (dev), SARIF 2.1.0

---

## Group 1: Cleanup & Documentation (Tasks 1-3)

### Task 1: Delete dead defense-fingerprinting directory

**Files:**
- Delete: `crates/defense-fingerprinting/` (entire directory)

**Step 1: Verify directory is excluded from workspace**

Run: `grep defense-fingerprinting Cargo.toml`
Expected: No match (already excluded from workspace members)

**Step 2: Delete the directory**

```bash
rm -rf crates/defense-fingerprinting/
```

**Step 3: Verify workspace still builds**

Run: `cargo test --workspace 2>&1 | tail -5`
Expected: All 2,309 tests pass

**Step 4: Commit**

```bash
git add -A crates/defense-fingerprinting/
git commit -m "[workspace] remove dead defense-fingerprinting directory"
```

---

### Task 2: Fix stale CLAUDE.md notes

**Files:**
- Modify: `CLAUDE.md`

**Step 1: Remove stale `--resume-from` / `--save-state` note**

The CLAUDE.md line says:
> `--resume-from` / `--save-state` CLI flags parse correctly but their logic is **not implemented**

This is stale. Checkpoint/resume IS implemented via `--resume` + `--graph-db` flags. The `--resume-from` and `--save-state` flag names never existed. Replace with:

> `--resume` requires `--graph-db` — checkpoint logic is fully wired: saves after each phase, skips completed phases on resume, deletes checkpoint on successful completion. Without `--graph-db`, `--resume` logs a warning and proceeds without checkpointing.

**Step 2: Fix stale OpenAPI requestBody note**

Current note says requestBody is not extracted. Exploration found extraction IS implemented in `introspection.rs:120-150`. The actual gap is different. Replace:

> OpenAPI `requestBody` is not extracted in `enumeration` crate

With:

> OpenAPI `requestBody` IS extracted in `enumeration` crate (`introspection.rs:120-150`) — body parameters are parsed with `ParameterLocation::Body`. However, parameter metadata is **not persisted to the knowledge graph** and **not used by the fuzzer**. `FuzzTarget.parameter` is always empty string. `enqueue_targets_for_endpoints()` in `phase_fuzz.rs` reads only `path` and `method` from graph node properties, ignoring all parameter info from `IntrospectedEndpoint`.

**Step 3: Verify formatting**

Run: `head -5 CLAUDE.md`
Expected: Test count still shows 2,309

**Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "[docs] fix stale checkpoint and requestBody notes in CLAUDE.md"
```

---

### Task 3: Remove run_recon_standalone duplication

**Files:**
- Modify: `crates/orchestrator/src/phase_recon.rs`
- Modify: `crates/orchestrator/src/pipeline.rs`
- Test: `crates/orchestrator/src/phase_recon_test.rs`

**Step 1: Read both functions to understand the duplication**

Read `phase_recon.rs` — find `run_recon_standalone()` and its signature.
Read `pipeline.rs` — find `collect_recon_ops()` and its signature.
Identify which callers use which function.

**Step 2: Consolidate to a single function**

Keep `run_recon_standalone(source_dir: &Path) -> Vec<OperationLogEntry>` in `phase_recon.rs` as the canonical implementation. Update `collect_recon_ops` in `pipeline.rs` to delegate to it (or remove it if unused).

**Step 3: Run tests**

Run: `cargo test -p aegis-orchestrator`
Expected: All orchestrator tests pass

**Step 4: Commit**

```bash
git add crates/orchestrator/src/phase_recon.rs crates/orchestrator/src/pipeline.rs
git commit -m "[orchestrator] consolidate recon op collection into single function"
```

---

## Group 2: Parameter-Aware Fuzzing (Tasks 4-9)

### Task 4: Store endpoint parameters in knowledge graph during recon

**Files:**
- Modify: `crates/orchestrator/src/phase_recon.rs` — where `IntrospectedEndpoint` → graph ops
- Modify: `crates/orchestrator/src/phase_fingerprint.rs` — where introspection results are processed
- Test: existing phase tests

**Context:** Currently, when endpoints are discovered via OpenAPI parsing, only `path` and `method` are stored as node properties. The `parameters` vec from `IntrospectedEndpoint` is discarded. We need to serialize parameter metadata into the node properties so the fuzz phase can read it.

**Step 1: Write failing test**

In the appropriate phase test file, write a test that:
- Creates an `IntrospectedEndpoint` with parameters (including a Body param)
- Converts it to graph operations
- Asserts the resulting node has a `parameters` property containing serialized JSON

**Step 2: Run test to verify it fails**

Run: `cargo test -p aegis-orchestrator -- test_name -v`
Expected: FAIL

**Step 3: Implement parameter serialization**

In the phase that converts `IntrospectedEndpoint` to `GraphOperation::AddNode`, add:
```rust
// Serialize parameters as JSON array in node properties
let params_json = serde_json::to_string(&endpoint.parameters
    .iter()
    .map(|p| serde_json::json!({
        "name": p.name,
        "location": format!("{:?}", p.location),
        "param_type": p.param_type,
        "required": p.required,
    }))
    .collect::<Vec<_>>())
    .unwrap_or_default();
properties.insert("parameters".to_string(), params_json);
```

Also store `request_content_types` as a property.

**Step 4: Run tests**

Run: `cargo test -p aegis-orchestrator`
Expected: All pass including new test

**Step 5: Commit**

```bash
git commit -m "[orchestrator] persist endpoint parameter metadata in graph node properties"
```

---

### Task 5: Add ParameterLocation to protocol crate

**Files:**
- Modify: `crates/protocol/src/request.rs` — add `parameter_location` field to `FuzzRequest`
- Test: `crates/protocol/src/request_test.rs`

**Context:** `ParameterLocation` is currently defined in the `enumeration` crate. For the `protocol` crate (which owns `FuzzRequest`) to use it, we need to either move the enum to `protocol` or add a simpler variant. Since `protocol` is the shared types crate, adding a `ParameterLocation` enum there is the correct approach.

**Step 1: Write test for new FuzzRequest field**

```rust
#[test]
fn fuzz_request_with_parameter_location() {
    let req = FuzzRequest {
        request_id: 1,
        endpoint: "http://localhost/api/users".into(),
        method: "POST".into(),
        parameter_name: "email".into(),
        parameter_location: ParameterLocation::Body,
        payload: "test@evil.com".into(),
        headers: vec![],
    };
    assert_eq!(req.parameter_location, ParameterLocation::Body);
}
```

**Step 2: Run test to verify it fails**

Expected: FAIL — `parameter_location` field doesn't exist

**Step 3: Add ParameterLocation enum to protocol crate**

In `crates/protocol/src/request.rs`:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum ParameterLocation {
    #[default]
    Query,
    Path,
    Header,
    Cookie,
    Body,
}
```

Add field to `FuzzRequest`:
```rust
pub parameter_location: ParameterLocation,
```

**Step 4: Fix all compilation errors**

Every place that constructs a `FuzzRequest` now needs `parameter_location`. Add `parameter_location: ParameterLocation::Query` (default) to all existing construction sites. Key files:
- `crates/fuzzing/src/executor.rs` — `build_request()`
- `crates/orchestrator/src/phase_fuzz.rs` — inline FuzzRequest construction
- `crates/evasion-engine/src/transport.rs` — if it constructs FuzzRequest
- All test files that create FuzzRequest instances

**Step 5: Run full workspace tests**

Run: `cargo test --workspace`
Expected: All 2,309 tests pass

**Step 6: Commit**

```bash
git commit -m "[protocol] add ParameterLocation enum and field to FuzzRequest"
```

---

### Task 6: Add ParameterLocation to FuzzTarget

**Files:**
- Modify: `crates/fuzzing/src/scheduler.rs` — add field to `FuzzTarget`
- Test: `crates/fuzzing/src/scheduler_test.rs`

**Step 1: Write test**

```rust
#[test]
fn fuzz_target_carries_parameter_location() {
    let target = FuzzTarget {
        endpoint: "/api/users".into(),
        method: "POST".into(),
        parameter: "email".into(),
        parameter_location: ParameterLocation::Body,
        vulnerability_class: VulnerabilityClass::SqlInjection,
        priority_score: 1.0,
        attempts: 0,
        max_attempts: 3,
    };
    assert_eq!(target.parameter_location, ParameterLocation::Body);
}
```

**Step 2: Add field to FuzzTarget**

In `scheduler.rs`:
```rust
pub struct FuzzTarget {
    // ... existing fields ...
    pub parameter_location: ParameterLocation,
}
```

**Step 3: Fix all compilation errors**

Add `parameter_location: ParameterLocation::Query` to all FuzzTarget construction sites.

**Step 4: Run tests**

Run: `cargo test --workspace`
Expected: All pass

**Step 5: Commit**

```bash
git commit -m "[fuzzing] add parameter_location field to FuzzTarget"
```

---

### Task 7: Create per-parameter FuzzTargets in phase_fuzz

**Files:**
- Modify: `crates/orchestrator/src/phase_fuzz.rs` — `enqueue_targets_for_endpoints()`
- Test: `crates/orchestrator/src/phase_fuzz_test.rs`

**Context:** Currently `enqueue_targets_for_endpoints()` creates one FuzzTarget per (endpoint, vulnerability_class) pair with empty parameter. After Task 4, parameter metadata is stored in node properties. We need to read it and create one FuzzTarget per (endpoint, parameter, vulnerability_class) triple.

**Step 1: Write failing test**

Test that `enqueue_targets_for_endpoints` creates separate targets for each parameter:
```rust
#[test]
fn enqueue_creates_per_parameter_targets() {
    // Create a graph node with parameters property containing:
    // [{"name":"id","location":"Query",...}, {"name":"email","location":"Body",...}]
    // Call enqueue_targets_for_endpoints
    // Assert scheduler has targets for both "id" (Query) and "email" (Body)
}
```

**Step 2: Implement parameter-aware enqueuing**

In `enqueue_targets_for_endpoints()`:
```rust
// Parse parameters from node properties
let params: Vec<serde_json::Value> = node.properties
    .get("parameters")
    .and_then(|p| serde_json::from_str(p).ok())
    .unwrap_or_default();

if params.is_empty() {
    // Fallback: create targets with empty parameter (current behavior)
    for class in fuzzable_classes() {
        scheduler.enqueue(FuzzTarget {
            parameter: String::new(),
            parameter_location: ParameterLocation::Query,
            // ...
        });
    }
} else {
    // Create targets per parameter per class
    for param in &params {
        let name = param["name"].as_str().unwrap_or_default().to_string();
        let location = match param["location"].as_str().unwrap_or("Query") {
            "Body" => ParameterLocation::Body,
            "Path" => ParameterLocation::Path,
            "Header" => ParameterLocation::Header,
            "Cookie" => ParameterLocation::Cookie,
            _ => ParameterLocation::Query,
        };
        for class in fuzzable_classes() {
            scheduler.enqueue(FuzzTarget {
                parameter: name.clone(),
                parameter_location: location,
                // ...
            });
        }
    }
}
```

**Step 3: Run tests**

Run: `cargo test -p aegis-orchestrator`
Expected: All pass

**Step 4: Commit**

```bash
git commit -m "[orchestrator] create per-parameter fuzz targets from graph metadata"
```

---

### Task 8: Add body injection logic to fuzz pipeline

**Files:**
- Modify: `crates/orchestrator/src/phase_fuzz.rs` — FuzzRequest construction in the fuzz loop
- Test: `crates/orchestrator/src/phase_fuzz_test.rs`

**Context:** Currently the fuzz loop constructs FuzzRequest with `parameter_name` but doesn't differentiate how the payload is injected. For Body parameters, the payload should go in the request body (JSON or form-encoded). For Query parameters, it should go in the URL query string.

**Step 1: Write test for body parameter injection**

```rust
#[test]
fn fuzz_request_body_parameter_has_content_type_header() {
    // Create a FuzzTarget with parameter_location = Body
    // Run through the request construction logic
    // Assert FuzzRequest has Content-Type header and parameter_location = Body
}
```

**Step 2: Update FuzzRequest construction in the fuzz loop**

In `phase_fuzz.rs`, where FuzzRequest is built inline (~line 93-100):
```rust
let request = FuzzRequest {
    request_id: next_request_id,
    endpoint: format!("{}{}", target_base, target.endpoint),
    method: target.method.clone(),
    parameter_name: target.parameter.clone(),
    parameter_location: target.parameter_location,
    payload: payload.raw.clone(),
    headers: match target.parameter_location {
        ParameterLocation::Body => vec![
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
        _ => vec![],
    },
};
```

**Step 3: Update evasion-engine transport to handle body params**

In the transport layer that sends `FuzzRequest`, check `parameter_location`:
- `Query` → append `?parameter_name=payload` to URL
- `Body` → set request body to `{"parameter_name": "payload"}`
- `Path` → replace `{parameter_name}` in URL path
- `Header` → add as request header

**Step 4: Run tests**

Run: `cargo test --workspace`
Expected: All pass

**Step 5: Commit**

```bash
git commit -m "[orchestrator] inject payloads based on parameter location (body/query/path/header)"
```

---

### Task 9: Integration test for parameter-aware fuzzing

**Files:**
- Add test to: `crates/orchestrator/src/phase_fuzz_test.rs`

**Step 1: Write integration test**

Create a test that:
1. Sets up a graph with an endpoint node having parameters (Query + Body)
2. Runs `enqueue_targets_for_endpoints` → verifies correct targets created
3. Verifies FuzzRequest objects have correct `parameter_location` and headers

**Step 2: Run test**

Run: `cargo test -p aegis-orchestrator -- parameter_aware -v`
Expected: PASS

**Step 3: Commit**

```bash
git commit -m "[orchestrator] add integration test for parameter-aware fuzzing pipeline"
```

---

## Group 3: SARIF Enrichment (Tasks 10-11)

### Task 10: Add endpoint/method/parameter to SARIF output

**Files:**
- Modify: `crates/reporting/src/sarif_emitter.rs` — add properties to SARIF results
- Modify: `crates/orchestrator/src/phase_report.rs` — pass endpoint/method data to SARIF emitter
- Test: `crates/reporting/src/sarif_emitter_test.rs`

**Context:** Currently SARIF results have `uri: None` for locations (see `phase_report.rs:126`). The `endpoint_for_finding()` helper exists but its result isn't placed into SARIF. For ground-truth comparison, we need endpoint path, method, and vulnerability class in the SARIF output.

**Step 1: Write failing test**

```rust
#[test]
fn sarif_result_includes_endpoint_and_method() {
    let finding = SarifFinding {
        endpoint: Some("/api/users".to_string()),
        http_method: Some("POST".to_string()),
        parameter_name: Some("id".to_string()),
        // ... other fields
    };
    let sarif = emit_sarif(&[finding]);
    let result = &sarif.runs[0].results[0];
    let props = result.properties.as_ref().unwrap();
    assert_eq!(props["endpoint"], "/api/users");
    assert_eq!(props["httpMethod"], "POST");
    assert_eq!(props["parameterName"], "id");
}
```

**Step 2: Add fields to SarifFinding struct**

```rust
pub struct SarifFinding {
    // ... existing fields ...
    pub endpoint: Option<String>,
    pub http_method: Option<String>,
    pub parameter_name: Option<String>,
}
```

**Step 3: Emit into SARIF properties**

In the SARIF emission logic, add to the `properties` map:
```rust
if let Some(ep) = &finding.endpoint {
    properties.insert("endpoint".to_string(), serde_json::Value::String(ep.clone()));
}
if let Some(method) = &finding.http_method {
    properties.insert("httpMethod".to_string(), serde_json::Value::String(method.clone()));
}
if let Some(param) = &finding.parameter_name {
    properties.insert("parameterName".to_string(), serde_json::Value::String(param.clone()));
}
```

Also set the SARIF `locations[0].physicalLocation.artifactLocation.uri` to the endpoint path.

**Step 4: Wire in phase_report.rs**

In `phase_report.rs`, use the existing `endpoint_for_finding()` helper to populate the new fields.

**Step 5: Run tests**

Run: `cargo test --workspace`
Expected: All pass

**Step 6: Commit**

```bash
git commit -m "[reporting] add endpoint/method/parameter to SARIF result properties"
```

---

### Task 11: Add VulnerabilityClass string to SARIF properties

**Files:**
- Modify: `crates/reporting/src/sarif_emitter.rs`
- Test: `crates/reporting/src/sarif_emitter_test.rs`

**Context:** Currently vuln class is only recoverable from CWE code in the `taxa` array. For ground-truth comparison, we need the exact `VulnerabilityClass` variant name as a string in properties.

**Step 1: Write failing test**

```rust
#[test]
fn sarif_result_includes_vulnerability_class_name() {
    let finding = SarifFinding {
        vulnerability_class: Some(VulnerabilityClass::SqlInjection),
        // ...
    };
    let sarif = emit_sarif(&[finding]);
    let props = &sarif.runs[0].results[0].properties;
    assert_eq!(props["vulnerabilityClass"], "SqlInjection");
}
```

**Step 2: Add vulnerability class name to properties**

```rust
if let Some(vc) = &finding.vulnerability_class {
    properties.insert("vulnerabilityClass".to_string(),
        serde_json::Value::String(format!("{:?}", vc)));
}
```

**Step 3: Run tests and commit**

```bash
cargo test --workspace
git commit -m "[reporting] add vulnerabilityClass name to SARIF properties"
```

---

## Group 4: Hypothesis-Engine IPC Bridge (Tasks 12-15)

### Task 12: Create Python CLI entrypoint for hypothesis-engine

**Files:**
- Create: `hypothesis-engine/src/hypothesis_engine/cli.py`
- Test: `hypothesis-engine/src/hypothesis_engine/test_cli.py`

**Context:** The Rust orchestrator will communicate with hypothesis-engine via subprocess + JSON over stdin/stdout. We need a Python CLI entrypoint that reads a JSON request from stdin and writes a JSON response to stdout.

**Step 1: Write test for CLI handler**

```python
def test_cli_generate_hypothesis(monkeypatch):
    """CLI reads JSON request from stdin, returns JSON response on stdout."""
    request = {
        "action": "generate",
        "backend": "ollama",
        "context": {
            "technology_stack": ["express", "node"],
            "findings_summary": [],
            "known_vulnerable_dependencies": [],
            "feedback_summary": "",
            # ... minimal ScanContext fields
        }
    }
    # Mock LlmBackend to avoid real API calls
    # Call handle_request(request) directly
    # Assert response has {"hypotheses": [...], "model_id": ..., "tokens": {...}}
```

**Step 2: Implement CLI handler**

```python
"""CLI entrypoint for hypothesis-engine subprocess IPC."""
import json
import sys
from hypothesis_engine import create_backend, HypothesisGenerator, ScanContext

def handle_request(request: dict) -> dict:
    action = request["action"]
    backend_type = request.get("backend", "bedrock")

    if action == "generate":
        backend = create_backend(backend_type, **request.get("backend_kwargs", {}))
        generator = HypothesisGenerator(client=backend)
        context = ScanContext(**request["context"])
        result = generator.generate(context)
        return {
            "hypotheses": [h.model_dump() for h in result.hypotheses],
            "model_id": result.model_id,
            "reasoning_trace": result.reasoning_trace,
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
        }
    elif action == "compile":
        # ... compile action
        pass
    else:
        return {"error": f"Unknown action: {action}"}

def main():
    request = json.loads(sys.stdin.read())
    response = handle_request(request)
    sys.stdout.write(json.dumps(response))
    sys.stdout.flush()

if __name__ == "__main__":
    main()
```

**Step 3: Run tests**

Run: `cd hypothesis-engine && uv run pytest src/hypothesis_engine/test_cli.py -v`
Expected: PASS

**Step 4: Commit**

```bash
git commit -m "[hypothesis-engine] add CLI entrypoint for subprocess IPC"
```

---

### Task 13: Create Rust subprocess bridge module

**Files:**
- Create: `crates/orchestrator/src/hypothesis_bridge.rs`
- Test: `crates/orchestrator/src/hypothesis_bridge_test.rs`
- Modify: `crates/orchestrator/src/lib.rs` — add module

**Context:** This module spawns the Python hypothesis-engine as a subprocess, sends JSON requests via stdin, and reads JSON responses from stdout.

**Step 1: Write test (mocked subprocess)**

```rust
#[test]
fn bridge_serializes_request_correctly() {
    let context = HypothesisRequest::Generate {
        backend: "ollama".to_string(),
        context: serde_json::json!({
            "technology_stack": ["express"],
            "findings_summary": [],
        }),
    };
    let json = serde_json::to_string(&context).unwrap();
    assert!(json.contains("\"action\":\"generate\""));
}

#[test]
fn bridge_deserializes_response() {
    let json = r#"{"hypotheses":[],"model_id":"test","reasoning_trace":"","input_tokens":0,"output_tokens":0}"#;
    let response: HypothesisResponse = serde_json::from_str(json).unwrap();
    assert_eq!(response.model_id, "test");
}
```

**Step 2: Implement bridge types and subprocess call**

```rust
use std::process::{Command, Stdio};

#[derive(Serialize)]
#[serde(tag = "action", rename_all = "lowercase")]
pub enum HypothesisRequest {
    Generate {
        backend: String,
        #[serde(flatten)]
        context: serde_json::Value,
    },
    Compile {
        hypotheses: Vec<serde_json::Value>,
    },
}

#[derive(Deserialize)]
pub struct HypothesisResponse {
    pub hypotheses: Vec<serde_json::Value>,
    pub model_id: String,
    pub reasoning_trace: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub error: Option<String>,
}

pub fn invoke_hypothesis_engine(
    request: &HypothesisRequest,
    python_path: &str,
) -> Result<HypothesisResponse, PipelineError> {
    let input = serde_json::to_string(request)?;
    let output = Command::new(python_path)
        .args(["-m", "hypothesis_engine.cli"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // Write input, read output, deserialize
    // ...
}
```

**Step 3: Run tests**

Run: `cargo test -p aegis-orchestrator -- hypothesis_bridge`
Expected: PASS

**Step 4: Commit**

```bash
git commit -m "[orchestrator] add hypothesis-engine subprocess bridge module"
```

---

### Task 14: Wire bridge into pipeline

**Files:**
- Modify: `crates/orchestrator/src/pipeline.rs` — call bridge in fuzz loop
- Modify: `crates/orchestrator/src/scan_config.rs` — ensure `--no-llm` flag gates calls

**Context:** The bridge should be called once per fuzz iteration to generate hypotheses based on current graph state. Gated by `--no-llm` flag. Findings from hypotheses tagged with `FindingOrigin::LlmHypothesis`.

**Step 1: Add hypothesis generation to fuzz-analyze loop**

In `run_fuzz_analyze_loop()`, after the fuzz phase and before analyze:
```rust
if !ctx.config.llm.no_llm {
    let request = build_hypothesis_request(ctx);
    match invoke_hypothesis_engine(&request, &ctx.config.llm.python_path) {
        Ok(response) => {
            // Convert hypotheses to FuzzTargets and enqueue
            // Track LLM metrics
        }
        Err(e) => {
            tracing::warn!(error = %e, "hypothesis engine unavailable, continuing with static fuzzing");
        }
    }
}
```

**Step 2: Run tests**

Run: `cargo test -p aegis-orchestrator`
Expected: All pass (hypothesis engine is optional, tests use `--no-llm`)

**Step 3: Commit**

```bash
git commit -m "[orchestrator] wire hypothesis-engine bridge into fuzz-analyze loop"
```

---

### Task 15: Integration test for hypothesis bridge

**Files:**
- Add test to: `crates/orchestrator/src/hypothesis_bridge_test.rs`

**Step 1: Write integration test using mock Python script**

Create a test that:
1. Writes a minimal Python script to a temp file that reads stdin JSON and writes a canned response
2. Calls `invoke_hypothesis_engine()` pointing to that script
3. Asserts the response is correctly deserialized

**Step 2: Run test and commit**

```bash
cargo test -p aegis-orchestrator -- hypothesis_bridge_integration
git commit -m "[orchestrator] add integration test for hypothesis engine subprocess bridge"
```

---

## Group 5: End-to-End Scanner Tests (Tasks 16-19)

### Task 16: Create ground truth comparison utility

**Files:**
- Create: `crates/orchestrator/tests/ground_truth.rs` (helper module)
- Modify: `crates/orchestrator/tests/docker_integration.rs` — use the utility

**Context:** Need a utility that loads ground-truth JSON, parses SARIF output, and computes precision/recall. After Task 10, SARIF results include `endpoint`, `httpMethod`, and `vulnerabilityClass` in properties.

**Step 1: Define GroundTruthEntry struct**

```rust
#[derive(Debug, Deserialize)]
struct GroundTruthEntry {
    endpoint: String,
    method: String,
    parameter: String,
    vulnerability_class: String,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GroundTruth {
    findings: Vec<GroundTruthEntry>,
}
```

**Step 2: Implement comparison function**

```rust
struct ComparisonResult {
    true_positives: usize,
    false_positives: usize,
    false_negatives: usize,
    precision: f64,
    recall: f64,
    f1: f64,
    matched: Vec<String>,
    missed: Vec<String>,
    extra: Vec<String>,
}

fn compare_sarif_to_ground_truth(
    sarif_path: &Path,
    ground_truth_path: &Path,
) -> ComparisonResult {
    // Load SARIF, extract (endpoint, vulnerabilityClass) tuples from properties
    // Load ground truth, extract (endpoint, vulnerability_class) tuples
    // Compute set intersection / difference
    // Return metrics
}
```

**Step 3: Write test for comparison utility itself**

Test with synthetic SARIF and ground truth to verify precision/recall calculation.

**Step 4: Commit**

```bash
git commit -m "[orchestrator] add ground truth comparison utility for e2e tests"
```

---

### Task 17: E2E test — Express plain scan

**Files:**
- Modify: `crates/orchestrator/tests/docker_integration.rs`

**Context:** This test starts the Express fixture, invokes `run_scan()` with `--no-llm --max-iterations 1`, then compares SARIF output to ground truth. Requires Docker/Colima.

**Step 1: Write the test**

```rust
#[test]
fn express_e2e_scanner_vs_ground_truth() {
    require_integration_tests();
    let compose = DockerCompose::new("express-e2e", "docker-compose.yml");
    compose.up().unwrap();
    wait_for_health("http://localhost:3000/health", Duration::from_secs(60)).unwrap();

    // Build ScanConfig targeting http://localhost:3000
    // with --no-llm, --no-audit, --max-iterations 1
    // Output to temp SARIF file
    let config = build_test_scan_config("http://localhost:3000", &sarif_path);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let summary = rt.block_on(run_scan(config)).unwrap();

    assert!(summary.total_findings > 0, "scanner should find at least one vulnerability");

    let comparison = compare_sarif_to_ground_truth(
        &sarif_path,
        Path::new("../defense-stacks/express-vuln-app/ground-truth.json"),
    );

    println!("Express E2E: TP={}, FP={}, FN={}, P={:.2}, R={:.2}, F1={:.2}",
        comparison.true_positives, comparison.false_positives, comparison.false_negatives,
        comparison.precision, comparison.recall, comparison.f1);

    // Static analysis should at minimum find KnownVulnerableDependency
    assert!(comparison.true_positives >= 1, "should find at least 1 true positive");
}
```

**Step 2: Run test**

Run: `AEGIS_INTEGRATION_TESTS=1 cargo test -p aegis-orchestrator --test docker_integration -- express_e2e -v --test-threads=1`
Expected: PASS with at least 1 true positive

**Step 3: Commit**

```bash
git commit -m "[orchestrator] add e2e scanner-vs-ground-truth test for express fixture"
```

---

### Task 18: E2E test — Flask scan

**Files:**
- Modify: `crates/orchestrator/tests/docker_integration.rs`

Same pattern as Task 17 but targeting the Flask fixture on port 5001. Flask ground truth has 7 findings.

**Step 1: Write test (same pattern, different port/ground-truth)**

**Step 2: Run and commit**

```bash
git commit -m "[orchestrator] add e2e scanner-vs-ground-truth test for flask fixture"
```

---

### Task 19: E2E test — GraphQL scan

**Files:**
- Modify: `crates/orchestrator/tests/docker_integration.rs`

Same pattern targeting the GraphQL fixture on port 4000. GraphQL ground truth has 8 findings.

**Step 1: Write test**

**Step 2: Run and commit**

```bash
git commit -m "[orchestrator] add e2e scanner-vs-ground-truth test for graphql fixture"
```

---

## Dependency Graph

```
Group 1 (Tasks 1-3): Independent, can run first
    │
Group 2 (Tasks 4-9): Parameter-aware fuzzing
    │   Task 4 → Task 7 (need params in graph before using them)
    │   Task 5 → Task 6 → Task 7 → Task 8 (protocol → scheduler → orchestrator → executor)
    │   Task 9 depends on Tasks 4-8
    │
Group 3 (Tasks 10-11): SARIF enrichment
    │   Depends on Group 2 (needs parameter_location in findings)
    │
Group 4 (Tasks 12-15): Hypothesis-engine IPC
    │   Independent of Groups 2-3
    │   Task 12 → Task 13 → Task 14 → Task 15
    │
Group 5 (Tasks 16-19): E2E scanner tests
        Depends on Groups 2 + 3 (needs enriched SARIF for comparison)
        Task 16 → Tasks 17-19 (comparison utility first, then tests)
```

## Validation Gates

After each group, run:
```bash
cargo test --workspace                    # All Rust tests pass
cargo clippy --workspace -- -D warnings   # Zero warnings
cargo fmt --all --check                   # Clean formatting
cd hypothesis-engine && uv run pytest src/hypothesis_engine/ -v  # Python tests pass
```

After Group 5, additionally run:
```bash
AEGIS_INTEGRATION_TESTS=1 cargo test -p aegis-orchestrator --test docker_integration -- --test-threads=1
```
