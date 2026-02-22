#[cfg(test)]
mod tests {
    use crate::hypothesis_ipc::{
        BridgeRequest, BridgeResponse, DefenseContextIpc, HypothesisIpc, ScanContextIpc,
    };
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn scan_context_ipc_roundtrip() {
        let mut rates = HashMap::new();
        rates.insert("SQL Injection".to_string(), 0.8);
        let ctx = ScanContextIpc {
            technology_stack: vec!["express".to_string()],
            findings_summary: vec!["SQLi in /login".to_string()],
            high_centrality_nodes: vec!["/api/users".to_string()],
            defense_posture: json!({"has_waf": true}),
            class_confirmation_rates: rates,
            model_id: Some("test-model".to_string()),
        };
        let serialized = serde_json::to_string(&ctx).unwrap();
        let deserialized: ScanContextIpc = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.technology_stack, ctx.technology_stack);
        assert_eq!(deserialized.findings_summary, ctx.findings_summary);
        assert_eq!(
            deserialized.high_centrality_nodes,
            ctx.high_centrality_nodes
        );
        assert_eq!(deserialized.defense_posture, ctx.defense_posture);
        assert_eq!(deserialized.class_confirmation_rates["SQL Injection"], 0.8);
        assert_eq!(deserialized.model_id.as_deref(), Some("test-model"));
    }

    #[test]
    fn scan_context_ipc_defaults_optional_fields() {
        let json_str = r#"{
            "technology_stack": [],
            "findings_summary": [],
            "high_centrality_nodes": [],
            "defense_posture": {}
        }"#;
        let ctx: ScanContextIpc = serde_json::from_str(json_str).unwrap();
        assert!(ctx.class_confirmation_rates.is_empty());
        assert!(ctx.model_id.is_none());
    }

    #[test]
    fn hypothesis_ipc_roundtrip() {
        let h = HypothesisIpc {
            vulnerability_class: "SqlInjection".to_string(),
            description: "blind sqli in /users".to_string(),
            confidence: 0.9,
            test_specification: Some("test payload".to_string()),
        };
        let serialized = serde_json::to_string(&h).unwrap();
        let deserialized: HypothesisIpc = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.vulnerability_class, h.vulnerability_class);
        assert_eq!(deserialized.description, h.description);
        assert_eq!(deserialized.confidence, h.confidence);
        assert_eq!(deserialized.test_specification, h.test_specification);
    }

    #[test]
    fn hypothesis_ipc_null_test_specification() {
        let json_str = r#"{
            "vulnerability_class": "XSS",
            "description": "reflected xss",
            "confidence": 0.7,
            "test_specification": null
        }"#;
        let h: HypothesisIpc = serde_json::from_str(json_str).unwrap();
        assert!(h.test_specification.is_none());
    }

    #[test]
    fn defense_context_ipc_roundtrip() {
        let dc = DefenseContextIpc {
            has_waf: true,
            waf_vendor: Some("ModSecurity".to_string()),
            rate_limit_rps: Some(10.0),
            bot_detection_present: false,
        };
        let serialized = serde_json::to_string(&dc).unwrap();
        let deserialized: DefenseContextIpc = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.has_waf, dc.has_waf);
        assert_eq!(deserialized.waf_vendor, dc.waf_vendor);
        assert_eq!(deserialized.rate_limit_rps, dc.rate_limit_rps);
        assert_eq!(deserialized.bot_detection_present, dc.bot_detection_present);
    }

    #[test]
    fn bridge_request_serializes_generate_hypotheses() {
        let req = BridgeRequest::GenerateHypotheses {
            request_id: 1,
            scan_context: ScanContextIpc {
                technology_stack: vec!["flask".to_string()],
                findings_summary: vec![],
                high_centrality_nodes: vec![],
                defense_posture: json!({}),
                class_confirmation_rates: HashMap::new(),
                model_id: None,
            },
            vulnerability_class: "SSTI".to_string(),
            feedback_summary: Some("prior feedback".to_string()),
        };
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(v["type"], "GenerateHypotheses");
        assert_eq!(v["request_id"], 1);
        assert_eq!(v["scan_context"]["technology_stack"][0], "flask");
        assert_eq!(v["vulnerability_class"], "SSTI");
        assert_eq!(v["feedback_summary"], "prior feedback");
    }

    #[test]
    fn bridge_request_serializes_compile_payloads() {
        let req = BridgeRequest::CompilePayloads {
            request_id: 42,
            hypotheses: vec![HypothesisIpc {
                vulnerability_class: "XSS".to_string(),
                description: "reflected XSS".to_string(),
                confidence: 0.85,
                test_specification: None,
            }],
        };
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(v["type"], "CompilePayloads");
        assert_eq!(v["request_id"], 42);
        assert_eq!(v["hypotheses"][0]["vulnerability_class"], "XSS");
    }

    #[test]
    fn bridge_request_serializes_evasion_generate() {
        let req = BridgeRequest::EvasionGenerate {
            request_id: 7,
            defense_context: DefenseContextIpc {
                has_waf: true,
                waf_vendor: Some("ModSecurity".to_string()),
                rate_limit_rps: Some(10.0),
                bot_detection_present: false,
            },
        };
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(v["type"], "EvasionGenerate");
        assert_eq!(v["defense_context"]["has_waf"], true);
    }

    #[test]
    fn bridge_request_serializes_shutdown() {
        let req = BridgeRequest::Shutdown;
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(v, json!({"type": "Shutdown"}));
    }

    #[test]
    fn bridge_response_deserializes_ready() {
        let resp: BridgeResponse = serde_json::from_str(r#"{"type": "Ready"}"#).unwrap();
        assert!(matches!(resp, BridgeResponse::Ready));
    }

    #[test]
    fn bridge_response_deserializes_hypotheses() {
        let json_str = r#"{
            "type": "Hypotheses",
            "request_id": 1,
            "hypotheses": [{
                "vulnerability_class": "SqlInjection",
                "description": "blind sqli",
                "confidence": 0.9,
                "test_specification": null
            }],
            "reasoning_trace": "analyzed endpoints",
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
                assert_eq!(reasoning_trace, "analyzed endpoints");
                assert_eq!(input_tokens, 500);
                assert_eq!(output_tokens, 120);
            }
            other => panic!("expected Hypotheses, got {other:?}"),
        }
    }

    #[test]
    fn bridge_response_deserializes_compiled_payloads() {
        let json_str = r#"{
            "type": "CompiledPayloads",
            "request_id": 2,
            "payloads": ["payload1", "payload2"],
            "input_tokens": 200,
            "output_tokens": 80
        }"#;
        let resp: BridgeResponse = serde_json::from_str(json_str).unwrap();
        match resp {
            BridgeResponse::CompiledPayloads {
                request_id,
                payloads,
                ..
            } => {
                assert_eq!(request_id, 2);
                assert_eq!(payloads, vec!["payload1", "payload2"]);
            }
            other => panic!("expected CompiledPayloads, got {other:?}"),
        }
    }

    #[test]
    fn bridge_response_deserializes_error() {
        let json_str = r#"{
            "type": "Error",
            "request_id": 99,
            "message": "backend timeout"
        }"#;
        let resp: BridgeResponse = serde_json::from_str(json_str).unwrap();
        match resp {
            BridgeResponse::Error {
                request_id,
                message,
            } => {
                assert_eq!(request_id, 99);
                assert_eq!(message, "backend timeout");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn cross_language_fixture_scan_context() {
        let fixture = r#"{
            "technology_stack": ["express", "postgresql"],
            "findings_summary": ["SQLi in /login"],
            "high_centrality_nodes": ["/api/users"],
            "defense_posture": {"has_waf": true, "waf_vendor": "ModSecurity"},
            "class_confirmation_rates": {"SQL Injection": 0.75},
            "model_id": "claude-sonnet-4-6"
        }"#;
        let ctx: ScanContextIpc = serde_json::from_str(fixture).unwrap();
        assert_eq!(ctx.technology_stack, vec!["express", "postgresql"]);
        assert_eq!(ctx.class_confirmation_rates["SQL Injection"], 0.75);
        assert_eq!(ctx.model_id.as_deref(), Some("claude-sonnet-4-6"));
    }

    #[test]
    fn cross_language_fixture_bridge_request() {
        let fixture = r#"{
            "type": "GenerateHypotheses",
            "request_id": 1,
            "scan_context": {
                "technology_stack": ["express"],
                "findings_summary": [],
                "high_centrality_nodes": [],
                "defense_posture": {}
            },
            "vulnerability_class": "SqlInjection",
            "feedback_summary": null
        }"#;
        let req: BridgeRequest = serde_json::from_str(fixture).unwrap();
        match req {
            BridgeRequest::GenerateHypotheses {
                request_id,
                vulnerability_class,
                ..
            } => {
                assert_eq!(request_id, 1);
                assert_eq!(vulnerability_class, "SqlInjection");
            }
            other => panic!("expected GenerateHypotheses, got {other:?}"),
        }
    }

    #[test]
    fn cross_language_fixture_bridge_response() {
        let fixture = r#"{
            "type": "Hypotheses",
            "request_id": 1,
            "hypotheses": [{
                "vulnerability_class": "SqlInjection",
                "description": "blind sqli in /users",
                "confidence": 0.9,
                "test_specification": "' OR 1=1--"
            }],
            "reasoning_trace": "analyzed endpoints",
            "input_tokens": 500,
            "output_tokens": 120
        }"#;
        let resp: BridgeResponse = serde_json::from_str(fixture).unwrap();
        assert!(matches!(resp, BridgeResponse::Hypotheses { .. }));
    }
}
