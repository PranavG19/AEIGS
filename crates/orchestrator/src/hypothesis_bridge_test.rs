#[cfg(test)]
mod tests {
    use crate::hypothesis_bridge::{
        BridgeRequest, BridgeResponse, DefenseContextJson, HypothesisBridge, HypothesisBridgeError,
        HypothesisJson, HypothesisRequest, HypothesisResult, ScanContextJson,
        invoke_hypothesis_engine, read_ipc_frame, write_ipc_frame,
    };
    use serde_json::json;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;

    #[test]
    fn generate_request_serializes_with_action_tag() {
        let req = HypothesisRequest::Generate {
            backend: "ollama".to_string(),
            backend_kwargs: None,
            context: json!({
                "technology_stack": ["express"],
                "high_centrality_nodes": [],
            }),
        };
        let serialized: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(serialized["action"], "generate");
        assert_eq!(serialized["backend"], "ollama");
        assert_eq!(serialized["context"]["technology_stack"][0], "express");
        assert!(serialized.get("backend_kwargs").is_none());
    }

    #[test]
    fn compile_request_serializes_with_action_tag() {
        let req = HypothesisRequest::Compile {
            backend: "bedrock".to_string(),
            backend_kwargs: Some(json!({"aws_profile": "ziya"})),
            hypotheses: vec![json!({"condition": "test", "vulnerability_class": "SqlInjection"})],
        };
        let serialized: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(serialized["action"], "compile");
        assert_eq!(serialized["backend"], "bedrock");
        assert_eq!(serialized["backend_kwargs"]["aws_profile"], "ziya");
        assert_eq!(serialized["hypotheses"][0]["condition"], "test");
    }

    #[test]
    fn generate_request_includes_backend_kwargs_when_present() {
        let req = HypothesisRequest::Generate {
            backend: "openai".to_string(),
            backend_kwargs: Some(json!({"base_url": "http://localhost:11434/v1"})),
            context: json!({}),
        };
        let serialized: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(
            serialized["backend_kwargs"]["base_url"],
            "http://localhost:11434/v1"
        );
    }

    #[test]
    fn result_deserializes_happy_path() {
        let json_str = r#"{
            "hypotheses": [{"condition": "sqli in /login", "vulnerability_class": "SqlInjection", "confidence": 0.85}],
            "model_id": "test-model",
            "reasoning_trace": "analyzed endpoints",
            "input_tokens": 150,
            "output_tokens": 75
        }"#;
        let result: HypothesisResult = serde_json::from_str(json_str).unwrap();
        assert_eq!(result.hypotheses.len(), 1);
        assert_eq!(result.model_id, "test-model");
        assert_eq!(result.reasoning_trace, "analyzed endpoints");
        assert_eq!(result.input_tokens, 150);
        assert_eq!(result.output_tokens, 75);
        assert!(result.error.is_none());
        assert!(result.specifications.is_empty());
    }

    #[test]
    fn result_deserializes_error_response() {
        let json_str = r#"{"error": "backend unavailable"}"#;
        let result: HypothesisResult = serde_json::from_str(json_str).unwrap();
        assert_eq!(result.error.as_deref(), Some("backend unavailable"));
        assert!(result.hypotheses.is_empty());
        assert_eq!(result.model_id, "");
        assert_eq!(result.input_tokens, 0);
        assert_eq!(result.output_tokens, 0);
    }

    #[test]
    fn result_deserializes_partial_fields_with_defaults() {
        let json_str = r#"{"model_id": "partial"}"#;
        let result: HypothesisResult = serde_json::from_str(json_str).unwrap();
        assert_eq!(result.model_id, "partial");
        assert!(result.hypotheses.is_empty());
        assert_eq!(result.reasoning_trace, "");
        assert_eq!(result.input_tokens, 0);
        assert_eq!(result.output_tokens, 0);
        assert!(result.specifications.is_empty());
        assert!(result.error.is_none());
    }

    #[test]
    fn result_deserializes_compile_response_with_specifications() {
        let json_str = r#"{
            "specifications": [{"endpoint": "/api/users", "method": "POST", "payloads": ["' OR 1=1--"]}],
            "model_id": "compile-model",
            "input_tokens": 200,
            "output_tokens": 100
        }"#;
        let result: HypothesisResult = serde_json::from_str(json_str).unwrap();
        assert_eq!(result.specifications.len(), 1);
        assert_eq!(result.model_id, "compile-model");
        assert_eq!(result.input_tokens, 200);
    }

    #[test]
    fn error_display_spawn_failed() {
        let err = HypothesisBridgeError::SpawnFailed(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "python3 not found",
        ));
        let msg = err.to_string();
        assert!(msg.contains("failed to spawn"));
        assert!(msg.contains("python3 not found"));
    }

    #[test]
    fn error_display_write_failed() {
        let err = HypothesisBridgeError::WriteFailed(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "broken pipe",
        ));
        let msg = err.to_string();
        assert!(msg.contains("failed to write"));
        assert!(msg.contains("broken pipe"));
    }

    #[test]
    fn error_display_read_failed() {
        let err = HypothesisBridgeError::ReadFailed(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "eof",
        ));
        let msg = err.to_string();
        assert!(msg.contains("failed to read"));
    }

    #[test]
    fn error_display_deserialize_failed() {
        let bad_json = serde_json::from_str::<HypothesisResult>("not json").unwrap_err();
        let err = HypothesisBridgeError::DeserializeFailed(bad_json);
        let msg = err.to_string();
        assert!(msg.contains("failed to deserialize"));
    }

    #[test]
    fn error_display_process_failed_with_exit_code() {
        let err = HypothesisBridgeError::ProcessFailed {
            stderr: "ModuleNotFoundError".to_string(),
            exit_code: Some(1),
        };
        let msg = err.to_string();
        assert!(msg.contains("exited with code 1"));
        assert!(msg.contains("ModuleNotFoundError"));
    }

    #[test]
    fn error_display_process_failed_without_exit_code() {
        let err = HypothesisBridgeError::ProcessFailed {
            stderr: "killed".to_string(),
            exit_code: None,
        };
        let msg = err.to_string();
        assert!(msg.contains("code unknown"));
    }

    #[test]
    fn error_display_python_error() {
        let err = HypothesisBridgeError::PythonError("backend timeout".to_string());
        let msg = err.to_string();
        assert!(msg.contains("returned error"));
        assert!(msg.contains("backend timeout"));
    }

    #[test]
    fn error_implements_std_error() {
        let err = HypothesisBridgeError::PythonError("test".to_string());
        let _: &dyn std::error::Error = &err;
    }

    /// Creates a temp directory containing a mock `hypothesis_engine` Python
    /// package and a wrapper shell script that sets PYTHONPATH before invoking
    /// python3. Returns `(TempDir, path_to_wrapper_script)`. The `TempDir` must
    /// be kept alive for the duration of the test.
    fn create_mock_hypothesis_env(cli_py_source: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let pkg_dir = tmp.path().join("hypothesis_engine");
        std::fs::create_dir(&pkg_dir).expect("failed to create package dir");
        std::fs::write(pkg_dir.join("__init__.py"), "").expect("failed to write __init__.py");
        std::fs::write(pkg_dir.join("cli.py"), cli_py_source).expect("failed to write cli.py");

        let wrapper = tmp.path().join("python_wrapper.sh");
        let wrapper_contents = format!(
            "#!/bin/bash\nexport PYTHONPATH=\"{}\"\nexec python3 \"$@\"\n",
            tmp.path().display()
        );
        std::fs::write(&wrapper, wrapper_contents).expect("failed to write wrapper script");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755))
                .expect("failed to chmod wrapper");
        }

        (tmp, wrapper)
    }

    #[test]
    fn invoke_hypothesis_engine_with_mock_python_generate() {
        let mock_cli = r#"
import json, sys

request = json.loads(sys.stdin.read())
assert request["action"] == "generate", f"unexpected action: {request['action']}"

response = {
    "hypotheses": [
        {"condition": "sqli in /login", "vulnerability_class": "SqlInjection", "confidence": 0.9}
    ],
    "model_id": "mock-model-v1",
    "reasoning_trace": "mock reasoning for generate",
    "input_tokens": 42,
    "output_tokens": 17,
}
json.dump(response, sys.stdout)
"#;

        let (_tmp, wrapper) = create_mock_hypothesis_env(mock_cli);
        let request = HypothesisRequest::Generate {
            backend: "ollama".to_string(),
            backend_kwargs: None,
            context: json!({
                "technology_stack": ["express"],
                "high_centrality_nodes": [],
            }),
        };

        let result = invoke_hypothesis_engine(&request, wrapper.to_str().unwrap())
            .expect("invoke should succeed");

        assert_eq!(result.model_id, "mock-model-v1");
        assert_eq!(result.reasoning_trace, "mock reasoning for generate");
        assert_eq!(result.input_tokens, 42);
        assert_eq!(result.output_tokens, 17);
        assert_eq!(result.hypotheses.len(), 1);
        assert_eq!(result.hypotheses[0]["vulnerability_class"], "SqlInjection");
        assert!(result.error.is_none());
        assert!(result.specifications.is_empty());
    }

    #[test]
    fn invoke_hypothesis_engine_with_mock_python_compile() {
        let mock_cli = r#"
import json, sys

request = json.loads(sys.stdin.read())
assert request["action"] == "compile", f"unexpected action: {request['action']}"
assert len(request["hypotheses"]) == 1

response = {
    "specifications": [
        {"endpoint": "/api/users", "method": "POST", "payloads": ["' OR 1=1--"]}
    ],
    "model_id": "mock-compiler-v1",
    "reasoning_trace": "mock reasoning for compile",
    "input_tokens": 100,
    "output_tokens": 50,
}
json.dump(response, sys.stdout)
"#;

        let (_tmp, wrapper) = create_mock_hypothesis_env(mock_cli);
        let request = HypothesisRequest::Compile {
            backend: "bedrock".to_string(),
            backend_kwargs: Some(json!({"aws_profile": "test"})),
            hypotheses: vec![
                json!({"condition": "sqli in /login", "vulnerability_class": "SqlInjection"}),
            ],
        };

        let result = invoke_hypothesis_engine(&request, wrapper.to_str().unwrap())
            .expect("invoke should succeed");

        assert_eq!(result.model_id, "mock-compiler-v1");
        assert_eq!(result.reasoning_trace, "mock reasoning for compile");
        assert_eq!(result.input_tokens, 100);
        assert_eq!(result.output_tokens, 50);
        assert_eq!(result.specifications.len(), 1);
        assert_eq!(result.specifications[0]["endpoint"], "/api/users");
        assert!(result.hypotheses.is_empty());
        assert!(result.error.is_none());
    }

    #[test]
    fn invoke_hypothesis_engine_returns_python_error_on_error_field() {
        let mock_cli = r#"
import json, sys
json.dump({"error": "mock backend failure"}, sys.stdout)
"#;

        let (_tmp, wrapper) = create_mock_hypothesis_env(mock_cli);
        let request = HypothesisRequest::Generate {
            backend: "ollama".to_string(),
            backend_kwargs: None,
            context: json!({}),
        };

        let err = invoke_hypothesis_engine(&request, wrapper.to_str().unwrap())
            .expect_err("should return PythonError");
        let msg = err.to_string();
        assert!(msg.contains("mock backend failure"), "got: {msg}");
    }

    #[test]
    fn invoke_hypothesis_engine_returns_process_failed_on_nonzero_exit() {
        let mock_cli = r#"
import sys
print("something went wrong", file=sys.stderr)
sys.exit(1)
"#;

        let (_tmp, wrapper) = create_mock_hypothesis_env(mock_cli);
        let request = HypothesisRequest::Generate {
            backend: "ollama".to_string(),
            backend_kwargs: None,
            context: json!({}),
        };

        let err = invoke_hypothesis_engine(&request, wrapper.to_str().unwrap())
            .expect_err("should return ProcessFailed");
        let msg = err.to_string();
        assert!(msg.contains("exited with code 1"), "got: {msg}");
        assert!(msg.contains("something went wrong"), "got: {msg}");
    }

    #[test]
    fn invoke_hypothesis_engine_returns_deserialize_failed_on_invalid_json() {
        let mock_cli = r#"
import sys
sys.stdout.write("this is not json")
"#;

        let (_tmp, wrapper) = create_mock_hypothesis_env(mock_cli);
        let request = HypothesisRequest::Generate {
            backend: "ollama".to_string(),
            backend_kwargs: None,
            context: json!({}),
        };

        let err = invoke_hypothesis_engine(&request, wrapper.to_str().unwrap())
            .expect_err("should return DeserializeFailed");
        let msg = err.to_string();
        assert!(msg.contains("failed to deserialize"), "got: {msg}");
    }

    #[test]
    fn invoke_hypothesis_engine_echoes_request_fields_through_subprocess() {
        let mock_cli = r#"
import json, sys

request = json.loads(sys.stdin.read())
response = {
    "model_id": request.get("backend", ""),
    "reasoning_trace": json.dumps(request.get("context", {})),
    "input_tokens": 0,
    "output_tokens": 0,
}
json.dump(response, sys.stdout)
"#;

        let (_tmp, wrapper) = create_mock_hypothesis_env(mock_cli);
        let request = HypothesisRequest::Generate {
            backend: "echo-backend".to_string(),
            backend_kwargs: None,
            context: json!({"marker": "round-trip-test"}),
        };

        let result = invoke_hypothesis_engine(&request, wrapper.to_str().unwrap())
            .expect("invoke should succeed");

        assert_eq!(result.model_id, "echo-backend");
        let echoed_context: serde_json::Value =
            serde_json::from_str(&result.reasoning_trace).unwrap();
        assert_eq!(echoed_context["marker"], "round-trip-test");
    }

    // -----------------------------------------------------------------------
    // IPC message type tests (Task 8.1)
    // -----------------------------------------------------------------------

    #[test]
    fn bridge_request_serializes_generate() {
        let req = BridgeRequest::GenerateHypotheses {
            request_id: 1,
            scan_context: ScanContextJson {
                technology_stack: vec!["express".to_string()],
                findings_summary: vec!["SQLi in /login".to_string()],
                high_centrality_nodes: vec![],
                defense_posture: json!({"has_waf": false}),
            },
            vulnerability_class: "SqlInjection".to_string(),
            feedback_summary: Some("prior run found 2 issues".to_string()),
        };
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(v["type"], "GenerateHypotheses");
        assert_eq!(v["request_id"], 1);
        assert_eq!(v["scan_context"]["technology_stack"][0], "express");
        assert_eq!(v["vulnerability_class"], "SqlInjection");
        assert_eq!(v["feedback_summary"], "prior run found 2 issues");
    }

    #[test]
    fn bridge_request_serializes_compile() {
        let req = BridgeRequest::CompilePayloads {
            request_id: 42,
            hypotheses: vec![HypothesisJson {
                vulnerability_class: "XSS".to_string(),
                description: "reflected XSS in search".to_string(),
                confidence: 0.85,
                test_specification: Some("inject <script>".to_string()),
            }],
        };
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(v["type"], "CompilePayloads");
        assert_eq!(v["request_id"], 42);
        assert_eq!(v["hypotheses"][0]["vulnerability_class"], "XSS");
        assert_eq!(v["hypotheses"][0]["confidence"], 0.85);
    }

    #[test]
    fn bridge_request_serializes_evasion() {
        let req = BridgeRequest::EvasionGenerate {
            request_id: 7,
            defense_context: DefenseContextJson {
                has_waf: true,
                waf_vendor: Some("ModSecurity".to_string()),
                rate_limit_rps: Some(10.0),
                bot_detection_present: false,
            },
        };
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(v["type"], "EvasionGenerate");
        assert_eq!(v["request_id"], 7);
        assert_eq!(v["defense_context"]["has_waf"], true);
        assert_eq!(v["defense_context"]["waf_vendor"], "ModSecurity");
        assert_eq!(v["defense_context"]["rate_limit_rps"], 10.0);
        assert_eq!(v["defense_context"]["bot_detection_present"], false);
    }

    #[test]
    fn bridge_request_serializes_shutdown() {
        let req = BridgeRequest::Shutdown;
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(v, json!({"type": "Shutdown"}));
    }

    #[test]
    fn bridge_response_deserializes_ready() {
        let json_str = r#"{"type": "Ready"}"#;
        let resp: BridgeResponse = serde_json::from_str(json_str).unwrap();
        assert!(matches!(resp, BridgeResponse::Ready));
    }

    #[test]
    fn bridge_response_deserializes_hypotheses() {
        let json_str = r#"{
            "type": "Hypotheses",
            "request_id": 1,
            "hypotheses": [
                {
                    "vulnerability_class": "SqlInjection",
                    "description": "blind sqli in /users",
                    "confidence": 0.9,
                    "test_specification": null
                }
            ],
            "reasoning_trace": "analyzed endpoints for injection points",
            "input_tokens": 500,
            "output_tokens": 120
        }"#;
        let resp: BridgeResponse = serde_json::from_str(json_str).unwrap();
        match resp {
            BridgeResponse::Hypotheses {
                request_id,
                hypotheses,
                reasoning_trace,
                input_tokens,
                output_tokens,
            } => {
                assert_eq!(request_id, 1);
                assert_eq!(hypotheses.len(), 1);
                assert_eq!(hypotheses[0].vulnerability_class, "SqlInjection");
                assert_eq!(hypotheses[0].confidence, 0.9);
                assert!(hypotheses[0].test_specification.is_none());
                assert_eq!(reasoning_trace, "analyzed endpoints for injection points");
                assert_eq!(input_tokens, 500);
                assert_eq!(output_tokens, 120);
            }
            other => panic!("expected Hypotheses, got {other:?}"),
        }
    }

    #[test]
    fn bridge_response_deserializes_error() {
        let json_str = r#"{
            "type": "Error",
            "request_id": 99,
            "message": "backend timeout after 120s"
        }"#;
        let resp: BridgeResponse = serde_json::from_str(json_str).unwrap();
        match resp {
            BridgeResponse::Error {
                request_id,
                message,
            } => {
                assert_eq!(request_id, 99);
                assert_eq!(message, "backend timeout after 120s");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn ipc_frame_roundtrip() {
        let req = BridgeRequest::GenerateHypotheses {
            request_id: 5,
            scan_context: ScanContextJson {
                technology_stack: vec!["flask".to_string()],
                findings_summary: vec![],
                high_centrality_nodes: vec![],
                defense_posture: json!({}),
            },
            vulnerability_class: "SSTI".to_string(),
            feedback_summary: None,
        };

        let mut buf = Vec::new();
        write_ipc_frame(&mut buf, &req).unwrap();

        assert!(buf.len() > 4);
        let payload_len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        assert_eq!(payload_len + 4, buf.len());

        let json_payload: serde_json::Value = serde_json::from_slice(&buf[4..]).unwrap();
        assert_eq!(json_payload["type"], "GenerateHypotheses");
        assert_eq!(json_payload["request_id"], 5);
    }

    #[test]
    fn ipc_frame_handles_empty_payload() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes());

        let mut cursor = std::io::Cursor::new(buf);
        let result: Result<BridgeResponse, _> = read_ipc_frame(&mut cursor);
        assert!(result.is_err());
        let err_msg = match result.unwrap_err() {
            HypothesisBridgeError::FrameReadFailed(msg) => msg,
            other => panic!("expected FrameReadFailed, got {other:?}"),
        };
        assert!(err_msg.contains("deserializing payload"), "got: {err_msg}");
    }

    #[test]
    fn ipc_frame_rejects_oversized_length_prefix() {
        let oversized_len: u32 = (65 * 1024 * 1024) as u32;
        let mut buf = Vec::new();
        buf.extend_from_slice(&oversized_len.to_le_bytes());
        buf.extend_from_slice(&[0u8; 16]);

        let mut cursor = std::io::Cursor::new(buf);
        let result: Result<BridgeResponse, _> = read_ipc_frame(&mut cursor);
        let err_msg = match result.unwrap_err() {
            HypothesisBridgeError::FrameReadFailed(msg) => msg,
            other => panic!("expected FrameReadFailed, got {other:?}"),
        };
        assert!(err_msg.contains("exceeds maximum"), "got: {err_msg}");
    }

    #[test]
    fn ipc_frame_read_write_roundtrip_bridge_response() {
        let resp_json = r#"{"type":"Ready"}"#;
        let mut buf = Vec::new();
        let payload = resp_json.as_bytes();
        let len = payload.len() as u32;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(payload);

        let mut cursor = std::io::Cursor::new(buf);
        let resp: BridgeResponse = read_ipc_frame(&mut cursor).unwrap();
        assert!(matches!(resp, BridgeResponse::Ready));
    }

    #[test]
    fn scan_context_json_serializes() {
        let ctx = ScanContextJson {
            technology_stack: vec!["express".to_string(), "postgresql".to_string()],
            findings_summary: vec!["SQLi found".to_string()],
            high_centrality_nodes: vec!["/api/users".to_string()],
            defense_posture: json!({"has_waf": true, "waf_vendor": "ModSecurity"}),
        };
        let json_str = serde_json::to_string(&ctx).unwrap();
        let roundtripped: ScanContextJson = serde_json::from_str(&json_str).unwrap();
        assert_eq!(roundtripped.technology_stack, ctx.technology_stack);
        assert_eq!(roundtripped.findings_summary, ctx.findings_summary);
        assert_eq!(
            roundtripped.high_centrality_nodes,
            ctx.high_centrality_nodes
        );
        assert_eq!(roundtripped.defense_posture, ctx.defense_posture);
    }

    #[test]
    fn hypothesis_json_serializes() {
        let h = HypothesisJson {
            vulnerability_class: "PathTraversal".to_string(),
            description: "directory traversal via filename param".to_string(),
            confidence: 0.75,
            test_specification: Some("../../etc/passwd".to_string()),
        };
        let json_str = serde_json::to_string(&h).unwrap();
        let roundtripped: HypothesisJson = serde_json::from_str(&json_str).unwrap();
        assert_eq!(roundtripped.vulnerability_class, h.vulnerability_class);
        assert_eq!(roundtripped.description, h.description);
        assert_eq!(roundtripped.confidence, h.confidence);
        assert_eq!(roundtripped.test_specification, h.test_specification);
    }

    // -----------------------------------------------------------------------
    // HypothesisBridge tests (Task 8.2)
    // -----------------------------------------------------------------------

    fn unique_socket_path(test_name: &str) -> PathBuf {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        PathBuf::from(format!(
            "/tmp/aegis-test-{}-{}-{}.sock",
            std::process::id(),
            test_name,
            ts
        ))
    }

    fn make_scan_context() -> ScanContextJson {
        ScanContextJson {
            technology_stack: vec!["express".to_string()],
            findings_summary: vec![],
            high_centrality_nodes: vec![],
            defense_posture: json!({"has_waf": false}),
        }
    }

    fn make_defense_context() -> DefenseContextJson {
        DefenseContextJson {
            has_waf: true,
            waf_vendor: Some("ModSecurity".to_string()),
            rate_limit_rps: Some(10.0),
            bot_detection_present: false,
        }
    }

    fn spawn_mock_bridge(
        socket_path: &PathBuf,
        handler: impl FnOnce(UnixStream) + Send + 'static,
    ) -> std::thread::JoinHandle<()> {
        let listener =
            std::os::unix::net::UnixListener::bind(socket_path).expect("bind mock listener");
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept mock connection");
            handler(stream);
        })
    }

    fn write_response_frame(stream: &mut UnixStream, response: &BridgeResponse) {
        let payload = serde_json::to_vec(response).unwrap();
        let len = payload.len() as u32;
        stream.write_all(&len.to_le_bytes()).unwrap();
        stream.write_all(&payload).unwrap();
    }

    fn read_request_frame(stream: &mut UnixStream) -> BridgeRequest {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).unwrap();
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).unwrap();
        serde_json::from_slice(&payload).unwrap()
    }

    fn connect_and_build_bridge(socket_path: PathBuf) -> HypothesisBridge {
        let stream = UnixStream::connect(&socket_path).expect("connect to mock bridge");
        HypothesisBridge {
            child: Command::new("sleep")
                .arg("300")
                .spawn()
                .expect("spawn sleep"),
            socket: stream,
            request_counter: 0,
            socket_path,
        }
    }

    use std::process::Command;

    #[test]
    fn bridge_handshake_receives_ready() {
        let sock = unique_socket_path("handshake");
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let mock = spawn_mock_bridge(&sock, move |mut stream| {
            write_response_frame(&mut stream, &BridgeResponse::Ready);
            let _ = done_rx.recv();
        });

        let mut bridge = connect_and_build_bridge(sock.clone());
        bridge
            .socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let result = bridge.read_handshake();
        assert!(result.is_ok(), "handshake should succeed: {result:?}");

        let _ = done_tx.send(());
        let _ = bridge.child.kill();
        let _ = std::fs::remove_file(&sock);
        mock.join().unwrap();
    }

    #[test]
    fn bridge_handshake_fails_on_non_ready_response() {
        let sock = unique_socket_path("handshake_fail");
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let mock = spawn_mock_bridge(&sock, move |mut stream| {
            write_response_frame(
                &mut stream,
                &BridgeResponse::Error {
                    request_id: 0,
                    message: "not ready".to_string(),
                },
            );
            let _ = done_rx.recv();
        });

        let mut bridge = connect_and_build_bridge(sock.clone());
        bridge
            .socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let result = bridge.read_handshake();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("handshake"),
            "error should mention handshake: {err_msg}"
        );

        let _ = done_tx.send(());
        let _ = bridge.child.kill();
        let _ = std::fs::remove_file(&sock);
        mock.join().unwrap();
    }

    #[test]
    fn bridge_generate_hypotheses_roundtrip() {
        let sock = unique_socket_path("gen_hyp");
        let mock = spawn_mock_bridge(&sock, |mut stream| {
            write_response_frame(&mut stream, &BridgeResponse::Ready);

            let _req: BridgeRequest = read_request_frame(&mut stream);

            write_response_frame(
                &mut stream,
                &BridgeResponse::Hypotheses {
                    request_id: 1,
                    hypotheses: vec![HypothesisJson {
                        vulnerability_class: "SqlInjection".to_string(),
                        description: "blind sqli in /users".to_string(),
                        confidence: 0.9,
                        test_specification: None,
                    }],
                    reasoning_trace: "analyzed endpoints".to_string(),
                    input_tokens: 500,
                    output_tokens: 120,
                },
            );
        });

        let mut bridge = connect_and_build_bridge(sock.clone());
        bridge
            .socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        bridge.read_handshake().unwrap();

        let result = bridge
            .generate_hypotheses(make_scan_context(), "SqlInjection".to_string(), None)
            .unwrap();

        assert_eq!(result.hypotheses.len(), 1);
        assert_eq!(result.hypotheses[0].vulnerability_class, "SqlInjection");
        assert_eq!(result.reasoning_trace, "analyzed endpoints");
        assert_eq!(result.input_tokens, 500);
        assert_eq!(result.output_tokens, 120);

        let _ = bridge.child.kill();
        let _ = std::fs::remove_file(&sock);
        mock.join().unwrap();
    }

    #[test]
    fn bridge_compile_payloads_roundtrip() {
        let sock = unique_socket_path("compile");
        let mock = spawn_mock_bridge(&sock, |mut stream| {
            write_response_frame(&mut stream, &BridgeResponse::Ready);

            let _req: BridgeRequest = read_request_frame(&mut stream);

            write_response_frame(
                &mut stream,
                &BridgeResponse::CompiledPayloads {
                    request_id: 1,
                    payloads: vec![
                        "' OR 1=1--".to_string(),
                        "<script>alert(1)</script>".to_string(),
                    ],
                    input_tokens: 200,
                    output_tokens: 80,
                },
            );
        });

        let mut bridge = connect_and_build_bridge(sock.clone());
        bridge
            .socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        bridge.read_handshake().unwrap();

        let hypotheses = vec![HypothesisJson {
            vulnerability_class: "SqlInjection".to_string(),
            description: "test".to_string(),
            confidence: 0.8,
            test_specification: None,
        }];
        let result = bridge.compile_payloads(hypotheses).unwrap();

        assert_eq!(result.payloads.len(), 2);
        assert_eq!(result.payloads[0], "' OR 1=1--");
        assert_eq!(result.input_tokens, 200);
        assert_eq!(result.output_tokens, 80);

        let _ = bridge.child.kill();
        let _ = std::fs::remove_file(&sock);
        mock.join().unwrap();
    }

    #[test]
    fn bridge_generate_evasion_roundtrip() {
        let sock = unique_socket_path("evasion");
        let mock = spawn_mock_bridge(&sock, |mut stream| {
            write_response_frame(&mut stream, &BridgeResponse::Ready);

            let _req: BridgeRequest = read_request_frame(&mut stream);

            write_response_frame(
                &mut stream,
                &BridgeResponse::EvasionPayloads {
                    request_id: 1,
                    payloads: vec!["evasion-payload-1".to_string()],
                    input_tokens: 300,
                    output_tokens: 60,
                },
            );
        });

        let mut bridge = connect_and_build_bridge(sock.clone());
        bridge
            .socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        bridge.read_handshake().unwrap();

        let result = bridge.generate_evasion(make_defense_context()).unwrap();

        assert_eq!(result.payloads, vec!["evasion-payload-1"]);
        assert_eq!(result.input_tokens, 300);
        assert_eq!(result.output_tokens, 60);

        let _ = bridge.child.kill();
        let _ = std::fs::remove_file(&sock);
        mock.join().unwrap();
    }

    #[test]
    fn bridge_shutdown_sends_shutdown_request() {
        let sock = unique_socket_path("shutdown");
        let (tx, rx) = std::sync::mpsc::channel();
        let mock = spawn_mock_bridge(&sock, move |mut stream| {
            write_response_frame(&mut stream, &BridgeResponse::Ready);

            let req: BridgeRequest = read_request_frame(&mut stream);
            let is_shutdown = matches!(req, BridgeRequest::Shutdown);
            tx.send(is_shutdown).unwrap();
        });

        let mut bridge = connect_and_build_bridge(sock.clone());
        bridge
            .socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        bridge.read_handshake().unwrap();

        let _ = bridge.shutdown();

        let received_shutdown = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert!(received_shutdown, "mock should have received Shutdown");

        let _ = std::fs::remove_file(&sock);
        mock.join().unwrap();
    }

    #[test]
    fn bridge_request_id_increments() {
        let sock = unique_socket_path("req_id");
        let (tx, rx) = std::sync::mpsc::channel();
        let mock = spawn_mock_bridge(&sock, move |mut stream| {
            write_response_frame(&mut stream, &BridgeResponse::Ready);

            for expected_id in 1..=3u64 {
                let req: BridgeRequest = read_request_frame(&mut stream);
                let actual_id = match &req {
                    BridgeRequest::GenerateHypotheses { request_id, .. } => *request_id,
                    BridgeRequest::CompilePayloads { request_id, .. } => *request_id,
                    BridgeRequest::EvasionGenerate { request_id, .. } => *request_id,
                    _ => 0,
                };
                tx.send(actual_id).unwrap();

                match expected_id {
                    1 => write_response_frame(
                        &mut stream,
                        &BridgeResponse::Hypotheses {
                            request_id: expected_id,
                            hypotheses: vec![],
                            reasoning_trace: String::new(),
                            input_tokens: 0,
                            output_tokens: 0,
                        },
                    ),
                    2 => write_response_frame(
                        &mut stream,
                        &BridgeResponse::CompiledPayloads {
                            request_id: expected_id,
                            payloads: vec![],
                            input_tokens: 0,
                            output_tokens: 0,
                        },
                    ),
                    3 => write_response_frame(
                        &mut stream,
                        &BridgeResponse::EvasionPayloads {
                            request_id: expected_id,
                            payloads: vec![],
                            input_tokens: 0,
                            output_tokens: 0,
                        },
                    ),
                    _ => {}
                }
            }
        });

        let mut bridge = connect_and_build_bridge(sock.clone());
        bridge
            .socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        bridge.read_handshake().unwrap();

        bridge
            .generate_hypotheses(make_scan_context(), "SqlInjection".to_string(), None)
            .unwrap();
        bridge.compile_payloads(vec![]).unwrap();
        bridge.generate_evasion(make_defense_context()).unwrap();

        assert_eq!(rx.recv().unwrap(), 1);
        assert_eq!(rx.recv().unwrap(), 2);
        assert_eq!(rx.recv().unwrap(), 3);
        assert_eq!(bridge.request_counter, 3);

        let _ = bridge.child.kill();
        let _ = std::fs::remove_file(&sock);
        mock.join().unwrap();
    }

    #[test]
    fn bridge_request_id_mismatch_returns_error() {
        let sock = unique_socket_path("mismatch");
        let mock = spawn_mock_bridge(&sock, |mut stream| {
            write_response_frame(&mut stream, &BridgeResponse::Ready);

            let _req: BridgeRequest = read_request_frame(&mut stream);

            write_response_frame(
                &mut stream,
                &BridgeResponse::Hypotheses {
                    request_id: 999,
                    hypotheses: vec![],
                    reasoning_trace: String::new(),
                    input_tokens: 0,
                    output_tokens: 0,
                },
            );
        });

        let mut bridge = connect_and_build_bridge(sock.clone());
        bridge
            .socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        bridge.read_handshake().unwrap();

        let result =
            bridge.generate_hypotheses(make_scan_context(), "SqlInjection".to_string(), None);
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("mismatch"), "should report ID mismatch: {msg}");
        assert!(msg.contains("expected 1"), "should show expected: {msg}");
        assert!(msg.contains("999"), "should show actual: {msg}");

        let _ = bridge.child.kill();
        let _ = std::fs::remove_file(&sock);
        mock.join().unwrap();
    }

    #[test]
    fn bridge_timeout_on_slow_response() {
        let sock = unique_socket_path("timeout");
        let mock = spawn_mock_bridge(&sock, |mut stream| {
            write_response_frame(&mut stream, &BridgeResponse::Ready);

            let _req: BridgeRequest = read_request_frame(&mut stream);

            std::thread::sleep(std::time::Duration::from_secs(5));
        });

        let mut bridge = connect_and_build_bridge(sock.clone());
        bridge
            .socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        bridge.read_handshake().unwrap();

        bridge
            .socket
            .set_read_timeout(Some(std::time::Duration::from_millis(100)))
            .unwrap();

        bridge.request_counter += 1;
        let request = BridgeRequest::GenerateHypotheses {
            request_id: bridge.request_counter,
            scan_context: make_scan_context(),
            vulnerability_class: "SqlInjection".to_string(),
            feedback_summary: None,
        };
        write_ipc_frame(&mut bridge.socket, &request).unwrap();

        let result: Result<BridgeResponse, _> = read_ipc_frame(&mut bridge.socket);
        assert!(result.is_err(), "should timeout: {result:?}");

        let _ = bridge.child.kill();
        let _ = std::fs::remove_file(&sock);
        mock.join().unwrap();
    }

    #[test]
    fn bridge_python_error_response_propagates() {
        let sock = unique_socket_path("py_err");
        let mock = spawn_mock_bridge(&sock, |mut stream| {
            write_response_frame(&mut stream, &BridgeResponse::Ready);

            let _req: BridgeRequest = read_request_frame(&mut stream);

            write_response_frame(
                &mut stream,
                &BridgeResponse::Error {
                    request_id: 1,
                    message: "backend unavailable".to_string(),
                },
            );
        });

        let mut bridge = connect_and_build_bridge(sock.clone());
        bridge
            .socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        bridge.read_handshake().unwrap();

        let result =
            bridge.generate_hypotheses(make_scan_context(), "SqlInjection".to_string(), None);
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("backend unavailable"),
            "should propagate error: {msg}"
        );

        let _ = bridge.child.kill();
        let _ = std::fs::remove_file(&sock);
        mock.join().unwrap();
    }

    #[test]
    fn bridge_generate_verifies_request_fields_sent() {
        let sock = unique_socket_path("verify_fields");
        let (tx, rx) = std::sync::mpsc::channel();
        let mock = spawn_mock_bridge(&sock, move |mut stream| {
            write_response_frame(&mut stream, &BridgeResponse::Ready);

            let req: BridgeRequest = read_request_frame(&mut stream);
            tx.send(serde_json::to_value(&req).unwrap()).unwrap();

            write_response_frame(
                &mut stream,
                &BridgeResponse::Hypotheses {
                    request_id: 1,
                    hypotheses: vec![],
                    reasoning_trace: String::new(),
                    input_tokens: 0,
                    output_tokens: 0,
                },
            );
        });

        let mut bridge = connect_and_build_bridge(sock.clone());
        bridge
            .socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        bridge.read_handshake().unwrap();

        let ctx = ScanContextJson {
            technology_stack: vec!["flask".to_string()],
            findings_summary: vec!["XSS found".to_string()],
            high_centrality_nodes: vec!["/api".to_string()],
            defense_posture: json!({"has_waf": true}),
        };
        bridge
            .generate_hypotheses(
                ctx,
                "CrossSiteScripting".to_string(),
                Some("prior feedback".to_string()),
            )
            .unwrap();

        let sent = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(sent["type"], "GenerateHypotheses");
        assert_eq!(sent["request_id"], 1);
        assert_eq!(sent["vulnerability_class"], "CrossSiteScripting");
        assert_eq!(sent["feedback_summary"], "prior feedback");
        assert_eq!(sent["scan_context"]["technology_stack"][0], "flask");

        let _ = bridge.child.kill();
        let _ = std::fs::remove_file(&sock);
        mock.join().unwrap();
    }

    #[test]
    fn bridge_socket_cleanup_on_shutdown() {
        let sock = unique_socket_path("cleanup");
        let mock = spawn_mock_bridge(&sock, |mut stream| {
            write_response_frame(&mut stream, &BridgeResponse::Ready);
            let _ = read_request_frame(&mut stream);
        });

        let mut bridge = connect_and_build_bridge(sock.clone());
        bridge
            .socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        bridge.read_handshake().unwrap();

        let socket_existed_before = sock.exists();
        let _ = bridge.shutdown();

        assert!(socket_existed_before, "socket should exist before shutdown");
        assert!(
            !sock.exists(),
            "socket file should be cleaned up after shutdown"
        );

        mock.join().unwrap();
    }

    #[test]
    fn bridge_error_display_handshake_failed() {
        let err = HypothesisBridgeError::HandshakeFailed("expected Ready".to_string());
        assert!(err.to_string().contains("handshake"));
        assert!(err.to_string().contains("expected Ready"));
    }

    #[test]
    fn bridge_error_display_request_id_mismatch() {
        let err = HypothesisBridgeError::RequestIdMismatch {
            expected: 1,
            actual: 5,
        };
        let msg = err.to_string();
        assert!(msg.contains("mismatch"));
        assert!(msg.contains("expected 1"));
        assert!(msg.contains("5"));
    }

    #[test]
    fn bridge_error_display_timeout() {
        let err = HypothesisBridgeError::Timeout("connection timed out".to_string());
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn bridge_error_display_socket_cleanup() {
        let err = HypothesisBridgeError::SocketCleanupFailed(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "permission denied",
        ));
        assert!(err.to_string().contains("clean up socket"));
    }

    #[test]
    fn bridge_compile_error_response_propagates() {
        let sock = unique_socket_path("compile_err");
        let mock = spawn_mock_bridge(&sock, |mut stream| {
            write_response_frame(&mut stream, &BridgeResponse::Ready);
            let _req: BridgeRequest = read_request_frame(&mut stream);
            write_response_frame(
                &mut stream,
                &BridgeResponse::Error {
                    request_id: 1,
                    message: "compilation failed".to_string(),
                },
            );
        });

        let mut bridge = connect_and_build_bridge(sock.clone());
        bridge
            .socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        bridge.read_handshake().unwrap();

        let result = bridge.compile_payloads(vec![]);
        let err = result.unwrap_err();
        assert!(err.to_string().contains("compilation failed"));

        let _ = bridge.child.kill();
        let _ = std::fs::remove_file(&sock);
        mock.join().unwrap();
    }

    #[test]
    fn bridge_evasion_error_response_propagates() {
        let sock = unique_socket_path("evasion_err");
        let mock = spawn_mock_bridge(&sock, |mut stream| {
            write_response_frame(&mut stream, &BridgeResponse::Ready);
            let _req: BridgeRequest = read_request_frame(&mut stream);
            write_response_frame(
                &mut stream,
                &BridgeResponse::Error {
                    request_id: 1,
                    message: "evasion generation failed".to_string(),
                },
            );
        });

        let mut bridge = connect_and_build_bridge(sock.clone());
        bridge
            .socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        bridge.read_handshake().unwrap();

        let result = bridge.generate_evasion(make_defense_context());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("evasion generation failed"));

        let _ = bridge.child.kill();
        let _ = std::fs::remove_file(&sock);
        mock.join().unwrap();
    }
}
