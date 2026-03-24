use super::*;

fn make_invocation(name: &str, args: serde_json::Value) -> ToolInvocation {
    ToolInvocation {
        tool_name: name.to_string(),
        arguments: args
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        invocation_id: 1,
    }
}

#[test]
fn tool_registry_has_ten_tools() {
    let tools = tool_registry();
    assert_eq!(tools.len(), 10);
}

#[test]
fn all_tools_have_nonempty_names() {
    for tool in tool_registry() {
        assert!(!tool.name.is_empty());
        assert!(!tool.description.is_empty());
        assert!(!tool.returns.is_empty());
    }
}

#[test]
fn all_tools_have_at_least_one_parameter() {
    for tool in tool_registry() {
        assert!(
            !tool.parameters.is_empty(),
            "{} has no parameters",
            tool.name
        );
    }
}

#[test]
fn all_tools_have_at_least_one_required_parameter() {
    for tool in tool_registry() {
        let has_required = tool.parameters.iter().any(|p| p.required);
        assert!(has_required, "{} has no required parameters", tool.name);
    }
}

#[test]
fn parse_fuzz_endpoint_basic() {
    let inv = make_invocation(
        "fuzz_endpoint",
        serde_json::json!({
            "endpoint": "http://127.0.0.1:3000/api/users",
            "method": "GET",
            "vulnerability_classes": ["XSS", "SQLi"]
        }),
    );

    let action = parse_tool_invocation(&inv).unwrap();
    match action {
        AgentAction::FuzzEndpoint {
            endpoint,
            method,
            vulnerability_classes,
            evasion_level,
            payload_strategy,
        } => {
            assert_eq!(endpoint, "http://127.0.0.1:3000/api/users");
            assert_eq!(method, "GET");
            assert_eq!(vulnerability_classes, vec!["XSS", "SQLi"]);
            assert_eq!(evasion_level, EvasionLevel::Moderate);
            assert_eq!(payload_strategy, PayloadStrategy::Standard);
        }
        _ => panic!("expected FuzzEndpoint"),
    }
}

#[test]
fn parse_fuzz_endpoint_with_evasion() {
    let inv = make_invocation(
        "fuzz_endpoint",
        serde_json::json!({
            "endpoint": "http://127.0.0.1:3000/api",
            "method": "POST",
            "vulnerability_classes": ["SSTI"],
            "evasion_level": "paranoid",
            "payload_strategy": "waf_bypass"
        }),
    );

    let action = parse_tool_invocation(&inv).unwrap();
    match action {
        AgentAction::FuzzEndpoint {
            evasion_level,
            payload_strategy,
            ..
        } => {
            assert_eq!(evasion_level, EvasionLevel::Paranoid);
            assert_eq!(payload_strategy, PayloadStrategy::WafBypass);
        }
        _ => panic!("expected FuzzEndpoint"),
    }
}

#[test]
fn parse_exploit_finding_basic() {
    let inv = make_invocation(
        "exploit_finding",
        serde_json::json!({
            "finding_id": 42,
            "tool": "sqlmap"
        }),
    );

    let action = parse_tool_invocation(&inv).unwrap();
    match action {
        AgentAction::ExploitFinding {
            finding_id,
            tool,
            custom_args,
        } => {
            assert_eq!(finding_id, 42);
            assert_eq!(tool, "sqlmap");
            assert!(custom_args.is_empty());
        }
        _ => panic!("expected ExploitFinding"),
    }
}

#[test]
fn parse_exploit_finding_with_custom_args() {
    let inv = make_invocation(
        "exploit_finding",
        serde_json::json!({
            "finding_id": 7,
            "tool": "nuclei",
            "custom_args": ["-t", "cves/"]
        }),
    );

    let action = parse_tool_invocation(&inv).unwrap();
    match action {
        AgentAction::ExploitFinding { custom_args, .. } => {
            assert_eq!(custom_args, vec!["-t", "cves/"]);
        }
        _ => panic!("expected ExploitFinding"),
    }
}

#[test]
fn parse_discover_endpoints_basic() {
    let inv = make_invocation(
        "discover_endpoints",
        serde_json::json!({
            "technique": "directory_bruteforce",
            "scope": "http://127.0.0.1:3000"
        }),
    );

    let action = parse_tool_invocation(&inv).unwrap();
    match action {
        AgentAction::DiscoverEndpoints { technique, scope } => {
            assert_eq!(technique, DiscoveryTechnique::DirectoryBruteForce);
            assert_eq!(scope, "http://127.0.0.1:3000");
        }
        _ => panic!("expected DiscoverEndpoints"),
    }
}

#[test]
fn parse_chain_findings_basic() {
    let inv = make_invocation(
        "chain_findings",
        serde_json::json!({
            "finding_ids": ["1", "3", "7"],
            "chain_hypothesis": "SSRF to internal API to data exfil"
        }),
    );

    let action = parse_tool_invocation(&inv).unwrap();
    match action {
        AgentAction::ChainFindings {
            finding_ids,
            chain_hypothesis,
        } => {
            assert_eq!(finding_ids, vec![1, 3, 7]);
            assert_eq!(chain_hypothesis, "SSRF to internal API to data exfil");
        }
        _ => panic!("expected ChainFindings"),
    }
}

#[test]
fn parse_authenticate_basic() {
    let inv = make_invocation(
        "authenticate",
        serde_json::json!({
            "auth_endpoint": "http://127.0.0.1:3000/login",
            "auth_method": "bearer_token"
        }),
    );

    let action = parse_tool_invocation(&inv).unwrap();
    match action {
        AgentAction::AuthenticateFirst {
            auth_endpoint,
            auth_method,
        } => {
            assert_eq!(auth_endpoint, "http://127.0.0.1:3000/login");
            assert_eq!(auth_method, AuthMethod::BearerToken);
        }
        _ => panic!("expected AuthenticateFirst"),
    }
}

#[test]
fn parse_evade_defense_basic() {
    let inv = make_invocation(
        "evade_defense",
        serde_json::json!({
            "defense_type": "waf",
            "evasion_technique": "encoding_chain"
        }),
    );

    let action = parse_tool_invocation(&inv).unwrap();
    match action {
        AgentAction::EvadeDefense {
            defense_type,
            evasion_technique,
        } => {
            assert_eq!(defense_type, "waf");
            assert_eq!(evasion_technique, "encoding_chain");
        }
        _ => panic!("expected EvadeDefense"),
    }
}

#[test]
fn parse_deep_analyze_basic() {
    let inv = make_invocation(
        "deep_analyze",
        serde_json::json!({
            "endpoint": "http://127.0.0.1:3000/checkout",
            "analysis_type": "timing_oracle"
        }),
    );

    let action = parse_tool_invocation(&inv).unwrap();
    match action {
        AgentAction::DeepAnalyze {
            endpoint,
            analysis_type,
        } => {
            assert_eq!(endpoint, "http://127.0.0.1:3000/checkout");
            assert_eq!(analysis_type, AnalysisType::TimingOracle);
        }
        _ => panic!("expected DeepAnalyze"),
    }
}

#[test]
fn parse_generate_report_basic() {
    let inv = make_invocation(
        "generate_report",
        serde_json::json!({
            "format": "executive"
        }),
    );

    let action = parse_tool_invocation(&inv).unwrap();
    match action {
        AgentAction::GenerateReport { format } => {
            assert_eq!(format, "executive");
        }
        _ => panic!("expected GenerateReport"),
    }
}

#[test]
fn parse_generate_report_default_format() {
    let inv = make_invocation("generate_report", serde_json::json!({}));

    let action = parse_tool_invocation(&inv).unwrap();
    match action {
        AgentAction::GenerateReport { format } => {
            assert_eq!(format, "developer");
        }
        _ => panic!("expected GenerateReport"),
    }
}

#[test]
fn unknown_tool_returns_error() {
    let inv = make_invocation("nonexistent_tool", serde_json::json!({}));
    let result = parse_tool_invocation(&inv);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, ToolError::UnknownTool(_)));
}

#[test]
fn missing_required_parameter_returns_error() {
    let inv = make_invocation(
        "fuzz_endpoint",
        serde_json::json!({
            "method": "GET"
        }),
    );
    let result = parse_tool_invocation(&inv);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ToolError::MissingParameter(_)
    ));
}

#[test]
fn invalid_discovery_technique_returns_error() {
    let inv = make_invocation(
        "discover_endpoints",
        serde_json::json!({
            "technique": "invalid_technique",
            "scope": "http://127.0.0.1"
        }),
    );
    let result = parse_tool_invocation(&inv);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ToolError::InvalidParameterType { .. }
    ));
}

#[test]
fn invalid_auth_method_returns_error() {
    let inv = make_invocation(
        "authenticate",
        serde_json::json!({
            "auth_endpoint": "http://127.0.0.1/login",
            "auth_method": "magic_cookies"
        }),
    );
    let result = parse_tool_invocation(&inv);
    assert!(result.is_err());
}

#[test]
fn tool_error_display() {
    assert_eq!(
        ToolError::UnknownTool("foo".to_string()).to_string(),
        "unknown tool: foo"
    );
    assert_eq!(
        ToolError::MissingParameter("bar".to_string()).to_string(),
        "missing required parameter: bar"
    );
    assert!(ToolError::ExecutionFailed("oops".to_string())
        .to_string()
        .contains("oops"));
}

#[test]
fn tool_param_type_display() {
    assert_eq!(ToolParamType::String.to_string(), "string");
    assert_eq!(ToolParamType::Integer.to_string(), "integer");
    assert_eq!(ToolParamType::Boolean.to_string(), "boolean");
    assert_eq!(ToolParamType::StringArray.to_string(), "string[]");
    assert_eq!(ToolParamType::Enum.to_string(), "enum");
}

#[test]
fn format_tools_for_prompt_contains_xml() {
    let tools = tool_registry();
    let prompt = format_tools_for_prompt(&tools);

    assert!(prompt.contains("<available_tools>"));
    assert!(prompt.contains("</available_tools>"));
    assert!(prompt.contains("<tool name=\"fuzz_endpoint\">"));
    assert!(prompt.contains("<description>"));
    assert!(prompt.contains("<parameters>"));
    assert!(prompt.contains("<returns>"));
}

#[test]
fn format_tools_for_prompt_includes_all_tools() {
    let tools = tool_registry();
    let prompt = format_tools_for_prompt(&tools);

    for tool in &tools {
        assert!(
            prompt.contains(&format!("name=\"{}\"", tool.name)),
            "prompt missing tool: {}",
            tool.name
        );
    }
}

#[test]
fn all_discovery_techniques_parse() {
    let techniques = [
        "directory_bruteforce",
        "javascript_extraction",
        "parameter_discovery",
        "vhost_discovery",
        "api_schema_inference",
        "sitemap_crawl",
        "waypoint_archive",
    ];
    for t in techniques {
        assert!(parse_discovery_technique(t).is_ok(), "failed to parse: {t}");
    }
}

#[test]
fn all_analysis_types_parse() {
    let types = [
        "timing_oracle",
        "differential_response",
        "business_logic_review",
        "source_code_analysis",
        "state_machine_mapping",
        "race_condition_probe",
    ];
    for t in types {
        assert!(parse_analysis_type(t).is_ok(), "failed to parse: {t}");
    }
}

#[test]
fn all_auth_methods_parse() {
    let methods = ["basic_auth", "bearer_token", "cookie", "oauth2", "api_key"];
    for m in methods {
        assert!(parse_auth_method(m).is_ok(), "failed to parse: {m}");
    }
}

#[test]
fn all_evasion_levels_parse() {
    assert_eq!(parse_evasion_level("none"), EvasionLevel::None);
    assert_eq!(parse_evasion_level("light"), EvasionLevel::Light);
    assert_eq!(parse_evasion_level("moderate"), EvasionLevel::Moderate);
    assert_eq!(parse_evasion_level("aggressive"), EvasionLevel::Aggressive);
    assert_eq!(parse_evasion_level("paranoid"), EvasionLevel::Paranoid);
    assert_eq!(parse_evasion_level("unknown"), EvasionLevel::Moderate);
}

#[test]
fn all_payload_strategies_parse() {
    assert_eq!(
        parse_payload_strategy("standard"),
        PayloadStrategy::Standard
    );
    assert_eq!(
        parse_payload_strategy("waf_bypass"),
        PayloadStrategy::WafBypass
    );
    assert_eq!(
        parse_payload_strategy("polyglot"),
        PayloadStrategy::Polyglot
    );
    assert_eq!(
        parse_payload_strategy("context_aware"),
        PayloadStrategy::ContextAware
    );
    assert_eq!(parse_payload_strategy("unknown"), PayloadStrategy::Standard);
}
