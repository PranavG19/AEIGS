#[cfg(test)]
mod tests {
    use crate::hypothesis_bridge::{
        HypothesisBridgeError, HypothesisRequest, HypothesisResult, invoke_hypothesis_engine,
    };
    use serde_json::json;

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
}
