#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::auth_flow::{
        AuthFlow, AuthFlowError, AuthFlowStep, AuthFlowVulnerability, ExtractionSource,
        ResponseExtraction, common_auth_flows, detect_insecure_cookie, detect_session_fixation,
        detect_weak_session_id, extract_value, render_template, validate_auth_flow,
    };

    fn vars(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn render_template_replaces_single_variable() {
        let v = vars(&[("name", "alice")]);
        let result = render_template("hello {{name}}", &v).unwrap();
        assert_eq!(result, "hello alice");
    }

    #[test]
    fn render_template_replaces_multiple_variables() {
        let v = vars(&[("user", "bob"), ("pass", "secret")]);
        let result = render_template("{{user}}:{{pass}}", &v).unwrap();
        assert_eq!(result, "bob:secret");
    }

    #[test]
    fn render_template_missing_variable_returns_error() {
        let v = vars(&[]);
        let result = render_template("{{missing}}", &v);
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), AuthFlowError::MissingVariable(name) if name == "missing")
        );
    }

    #[test]
    fn render_template_no_placeholders_returns_unchanged() {
        let v = vars(&[("unused", "val")]);
        let result = render_template("no placeholders here", &v).unwrap();
        assert_eq!(result, "no placeholders here");
    }

    #[test]
    fn extract_value_from_header() {
        let headers = vec![("Authorization".to_string(), "Bearer tok123".to_string())];
        let source = ExtractionSource::Header("Authorization".to_string());
        let val = extract_value(&source, 200, &headers, "");
        assert_eq!(val, Some("Bearer tok123".to_string()));
    }

    #[test]
    fn extract_value_from_header_case_insensitive() {
        let headers = vec![("content-type".to_string(), "application/json".to_string())];
        let source = ExtractionSource::Header("Content-Type".to_string());
        let val = extract_value(&source, 200, &headers, "");
        assert_eq!(val, Some("application/json".to_string()));
    }

    #[test]
    fn extract_value_from_json_path_simple() {
        let body = r#"{"token":"abc123"}"#;
        let source = ExtractionSource::JsonPath("token".to_string());
        let val = extract_value(&source, 200, &[], body);
        assert_eq!(val, Some("abc123".to_string()));
    }

    #[test]
    fn extract_value_from_json_path_nested() {
        let body = r#"{"data":{"access_token":"xyz"}}"#;
        let source = ExtractionSource::JsonPath("data.access_token".to_string());
        let val = extract_value(&source, 200, &[], body);
        assert_eq!(val, Some("xyz".to_string()));
    }

    #[test]
    fn extract_value_from_json_path_missing_returns_none() {
        let body = r#"{"data":{"other":"val"}}"#;
        let source = ExtractionSource::JsonPath("data.token".to_string());
        let val = extract_value(&source, 200, &[], body);
        assert_eq!(val, None);
    }

    #[test]
    fn extract_value_from_cookie() {
        let headers = vec![("Set-Cookie".to_string(), "session=abc123".to_string())];
        let source = ExtractionSource::Cookie("session".to_string());
        let val = extract_value(&source, 200, &headers, "");
        assert_eq!(val, Some("abc123".to_string()));
    }

    #[test]
    fn extract_value_from_cookie_with_attributes() {
        let headers = vec![(
            "Set-Cookie".to_string(),
            "sid=xyz789; Path=/; HttpOnly; Secure".to_string(),
        )];
        let source = ExtractionSource::Cookie("sid".to_string());
        let val = extract_value(&source, 200, &headers, "");
        assert_eq!(val, Some("xyz789".to_string()));
    }

    #[test]
    fn extract_value_status_code() {
        let source = ExtractionSource::StatusCode;
        let val = extract_value(&source, 201, &[], "");
        assert_eq!(val, Some("201".to_string()));
    }

    #[test]
    fn validate_auth_flow_valid_flow_passes() {
        let flow = AuthFlow {
            name: "test".to_string(),
            steps: vec![AuthFlowStep {
                step_id: "login".to_string(),
                endpoint: "/login".to_string(),
                method: "POST".to_string(),
                body_template: Some(r#"{"u":"{{username}}"}"#.to_string()),
                extract_from_response: vec![ResponseExtraction {
                    variable_name: "token".to_string(),
                    source: ExtractionSource::JsonPath("token".to_string()),
                }],
                expected_status: 200,
            }],
            required_inputs: vec!["username".to_string()],
        };
        assert!(validate_auth_flow(&flow).is_ok());
    }

    #[test]
    fn validate_auth_flow_empty_step_id_fails() {
        let flow = AuthFlow {
            name: "test".to_string(),
            steps: vec![AuthFlowStep {
                step_id: String::new(),
                endpoint: "/login".to_string(),
                method: "POST".to_string(),
                body_template: None,
                extract_from_response: vec![],
                expected_status: 200,
            }],
            required_inputs: vec![],
        };
        assert!(validate_auth_flow(&flow).is_err());
    }

    #[test]
    fn validate_auth_flow_duplicate_step_id_fails() {
        let step = AuthFlowStep {
            step_id: "login".to_string(),
            endpoint: "/login".to_string(),
            method: "POST".to_string(),
            body_template: None,
            extract_from_response: vec![],
            expected_status: 200,
        };
        let flow = AuthFlow {
            name: "test".to_string(),
            steps: vec![step.clone(), step],
            required_inputs: vec![],
        };
        assert!(validate_auth_flow(&flow).is_err());
    }

    #[test]
    fn validate_auth_flow_missing_variable_reference_fails() {
        let flow = AuthFlow {
            name: "test".to_string(),
            steps: vec![AuthFlowStep {
                step_id: "login".to_string(),
                endpoint: "/login".to_string(),
                method: "POST".to_string(),
                body_template: Some("{{not_provided}}".to_string()),
                extract_from_response: vec![],
                expected_status: 200,
            }],
            required_inputs: vec![],
        };
        let result = validate_auth_flow(&flow);
        assert!(result.is_err());
    }

    #[test]
    fn detect_session_fixation_same_session_returns_finding() {
        let finding = detect_session_fixation(Some("abc123"), Some("abc123"));
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.vulnerability, AuthFlowVulnerability::SessionFixation);
    }

    #[test]
    fn detect_session_fixation_different_sessions_returns_none() {
        let finding = detect_session_fixation(Some("abc123"), Some("xyz789"));
        assert!(finding.is_none());
    }

    #[test]
    fn detect_session_fixation_none_sessions_returns_none() {
        assert!(detect_session_fixation(None, None).is_none());
        assert!(detect_session_fixation(Some("abc"), None).is_none());
        assert!(detect_session_fixation(None, Some("abc")).is_none());
    }

    #[test]
    fn detect_weak_session_id_short_id_returns_finding() {
        let finding = detect_weak_session_id("abc");
        assert!(finding.is_some());
        assert_eq!(
            finding.unwrap().vulnerability,
            AuthFlowVulnerability::WeakSessionId
        );
    }

    #[test]
    fn detect_weak_session_id_all_digits_returns_finding() {
        let finding = detect_weak_session_id("1234567890123456");
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.vulnerability, AuthFlowVulnerability::WeakSessionId);
        assert!(f.evidence.contains("all-digit"));
    }

    #[test]
    fn detect_weak_session_id_strong_id_returns_none() {
        let finding = detect_weak_session_id("a3f8c2e1b9d0456789abcdef01234567");
        assert!(finding.is_none());
    }

    #[test]
    fn detect_insecure_cookie_missing_secure() {
        let issues = detect_insecure_cookie("session=abc; HttpOnly; SameSite=Strict");
        assert!(!issues.is_empty());
        assert!(
            issues
                .iter()
                .all(|v| *v == AuthFlowVulnerability::InsecureCookieAttributes)
        );
    }

    #[test]
    fn detect_insecure_cookie_missing_httponly() {
        let issues = detect_insecure_cookie("session=abc; Secure; SameSite=Strict");
        assert!(!issues.is_empty());
        assert!(
            issues
                .iter()
                .all(|v| *v == AuthFlowVulnerability::InsecureCookieAttributes)
        );
    }

    #[test]
    fn detect_insecure_cookie_all_present_returns_empty() {
        let issues =
            detect_insecure_cookie("session=abc; Secure; HttpOnly; SameSite=Strict; Path=/");
        assert!(issues.is_empty());
    }

    #[test]
    fn common_auth_flows_returns_three_flows() {
        let flows = common_auth_flows();
        assert_eq!(flows.len(), 3);
    }

    #[test]
    fn common_auth_flows_all_have_non_empty_steps() {
        let flows = common_auth_flows();
        for flow in &flows {
            assert!(!flow.steps.is_empty(), "flow '{}' has no steps", flow.name);
            assert!(
                !flow.required_inputs.is_empty(),
                "flow '{}' has no required_inputs",
                flow.name
            );
        }
    }

    #[test]
    fn auth_flow_vulnerability_display() {
        assert_eq!(
            AuthFlowVulnerability::SessionFixation.to_string(),
            "session-fixation"
        );
        assert_eq!(
            AuthFlowVulnerability::TokenReuseAfterLogout.to_string(),
            "token-reuse-after-logout"
        );
        assert_eq!(
            AuthFlowVulnerability::MissingTokenRotation.to_string(),
            "missing-token-rotation"
        );
        assert_eq!(
            AuthFlowVulnerability::WeakSessionId.to_string(),
            "weak-session-id"
        );
        assert_eq!(
            AuthFlowVulnerability::InsecureCookieAttributes.to_string(),
            "insecure-cookie-attributes"
        );
    }

    #[test]
    fn auth_flow_error_display() {
        let err = AuthFlowError::MissingVariable("token".to_string());
        assert!(err.to_string().contains("missing variable"));
        assert!(err.to_string().contains("token"));

        let err = AuthFlowError::StepFailed {
            step_id: "login".to_string(),
            expected_status: 200,
            actual_status: 401,
        };
        assert!(err.to_string().contains("login"));
        assert!(err.to_string().contains("200"));
        assert!(err.to_string().contains("401"));

        let err = AuthFlowError::ExtractionFailed {
            step_id: "get_token".to_string(),
            variable_name: "access_token".to_string(),
        };
        assert!(err.to_string().contains("get_token"));
        assert!(err.to_string().contains("access_token"));

        let err = AuthFlowError::InvalidJsonPath("bad.path".to_string());
        assert!(err.to_string().contains("invalid json path"));
    }

    #[test]
    fn validate_auth_flow_empty_endpoint_fails() {
        let flow = AuthFlow {
            name: "test".to_string(),
            steps: vec![AuthFlowStep {
                step_id: "step1".to_string(),
                endpoint: String::new(),
                method: "GET".to_string(),
                body_template: None,
                extract_from_response: vec![],
                expected_status: 200,
            }],
            required_inputs: vec![],
        };
        assert!(validate_auth_flow(&flow).is_err());
    }

    #[test]
    fn validate_auth_flow_empty_method_fails() {
        let flow = AuthFlow {
            name: "test".to_string(),
            steps: vec![AuthFlowStep {
                step_id: "step1".to_string(),
                endpoint: "/api".to_string(),
                method: String::new(),
                body_template: None,
                extract_from_response: vec![],
                expected_status: 200,
            }],
            required_inputs: vec![],
        };
        assert!(validate_auth_flow(&flow).is_err());
    }

    #[test]
    fn extract_value_json_path_returns_number_as_string() {
        let body = r#"{"count":42}"#;
        let source = ExtractionSource::JsonPath("count".to_string());
        let val = extract_value(&source, 200, &[], body);
        assert_eq!(val, Some("42".to_string()));
    }

    #[test]
    fn extract_value_header_missing_returns_none() {
        let headers = vec![("X-Other".to_string(), "val".to_string())];
        let source = ExtractionSource::Header("Authorization".to_string());
        let val = extract_value(&source, 200, &headers, "");
        assert_eq!(val, None);
    }

    #[test]
    fn extract_value_cookie_missing_returns_none() {
        let headers = vec![("Set-Cookie".to_string(), "other=val".to_string())];
        let source = ExtractionSource::Cookie("session".to_string());
        let val = extract_value(&source, 200, &headers, "");
        assert_eq!(val, None);
    }

    #[test]
    fn validate_auth_flow_step_can_use_variable_from_earlier_step() {
        let flow = AuthFlow {
            name: "two-step".to_string(),
            steps: vec![
                AuthFlowStep {
                    step_id: "login".to_string(),
                    endpoint: "/login".to_string(),
                    method: "POST".to_string(),
                    body_template: None,
                    extract_from_response: vec![ResponseExtraction {
                        variable_name: "token".to_string(),
                        source: ExtractionSource::JsonPath("token".to_string()),
                    }],
                    expected_status: 200,
                },
                AuthFlowStep {
                    step_id: "refresh".to_string(),
                    endpoint: "/refresh".to_string(),
                    method: "POST".to_string(),
                    body_template: Some(r#"{"token":"{{token}}"}"#.to_string()),
                    extract_from_response: vec![],
                    expected_status: 200,
                },
            ],
            required_inputs: vec![],
        };
        assert!(validate_auth_flow(&flow).is_ok());
    }

    #[test]
    fn common_auth_flows_all_validate() {
        let flows = common_auth_flows();
        for flow in &flows {
            assert!(
                validate_auth_flow(flow).is_ok(),
                "flow '{}' failed validation",
                flow.name
            );
        }
    }

    #[test]
    fn detect_insecure_cookie_missing_all_attributes() {
        let issues = detect_insecure_cookie("session=abc; Path=/");
        assert_eq!(issues.len(), 3);
    }

    #[test]
    fn render_template_adjacent_placeholders() {
        let v = vars(&[("a", "1"), ("b", "2")]);
        let result = render_template("{{a}}{{b}}", &v).unwrap();
        assert_eq!(result, "12");
    }
}
