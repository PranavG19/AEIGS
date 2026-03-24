use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::agent_loop::{
    AgentAction, AnalysisType, AuthMethod, DiscoveryTechnique, EvasionLevel, PayloadStrategy,
};

/// Schema definition for a tool the LLM agent can invoke.
///
/// Follows the function-calling convention used by Claude, GPT-4, and other
/// tool-use capable models. Each tool has a name, description, and typed
/// parameter list that the LLM must populate when invoking it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSchema {
    pub name: String,
    pub description: String,
    pub parameters: Vec<ToolParameter>,
    pub returns: String,
}

/// Typed parameter for a tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolParameter {
    pub name: String,
    pub param_type: ToolParamType,
    pub description: String,
    pub required: bool,
    pub default_value: Option<String>,
    pub enum_values: Vec<String>,
}

/// Type system for tool parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolParamType {
    String,
    Integer,
    Float,
    Boolean,
    StringArray,
    Enum,
}

impl fmt::Display for ToolParamType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String => write!(f, "string"),
            Self::Integer => write!(f, "integer"),
            Self::Float => write!(f, "float"),
            Self::Boolean => write!(f, "boolean"),
            Self::StringArray => write!(f, "string[]"),
            Self::Enum => write!(f, "enum"),
        }
    }
}

/// Raw tool invocation from the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInvocation {
    pub tool_name: String,
    pub arguments: HashMap<String, serde_json::Value>,
    pub invocation_id: u64,
}

/// Result of executing a tool, returned to the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub invocation_id: u64,
    pub success: bool,
    pub output: String,
    pub structured_data: Option<serde_json::Value>,
    pub error: Option<String>,
}

/// Errors from tool parsing or dispatch.
#[derive(Debug, Clone)]
pub enum ToolError {
    UnknownTool(String),
    MissingParameter(String),
    InvalidParameterType { param: String, expected: String },
    ExecutionFailed(String),
}

impl fmt::Display for ToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTool(name) => write!(f, "unknown tool: {name}"),
            Self::MissingParameter(name) => write!(f, "missing required parameter: {name}"),
            Self::InvalidParameterType { param, expected } => {
                write!(f, "parameter {param} has wrong type, expected {expected}")
            }
            Self::ExecutionFailed(msg) => write!(f, "tool execution failed: {msg}"),
        }
    }
}

impl std::error::Error for ToolError {}

/// Returns the complete tool registry — all tools available to the LLM agent.
///
/// Each tool maps directly to an `AgentAction` variant from the agent loop.
/// The schemas are formatted for injection into LLM prompts.
pub fn tool_registry() -> Vec<ToolSchema> {
    vec![
        fuzz_endpoint_schema(),
        exploit_finding_schema(),
        discover_endpoints_schema(),
        chain_findings_schema(),
        authenticate_schema(),
        evade_defense_schema(),
        deep_analyze_schema(),
        generate_report_schema(),
        http_request_schema(),
        read_javascript_schema(),
    ]
}

fn fuzz_endpoint_schema() -> ToolSchema {
    ToolSchema {
        name: "fuzz_endpoint".to_string(),
        description: "Fuzz a specific endpoint with chosen vulnerability classes and evasion level. Use when you want to test an endpoint for vulnerabilities.".to_string(),
        parameters: vec![
            ToolParameter {
                name: "endpoint".to_string(),
                param_type: ToolParamType::String,
                description: "Full URL of the endpoint to fuzz".to_string(),
                required: true,
                default_value: None,
                enum_values: vec![],
            },
            ToolParameter {
                name: "method".to_string(),
                param_type: ToolParamType::Enum,
                description: "HTTP method".to_string(),
                required: true,
                default_value: Some("GET".to_string()),
                enum_values: vec!["GET".to_string(), "POST".to_string(), "PUT".to_string(), "DELETE".to_string(), "PATCH".to_string()],
            },
            ToolParameter {
                name: "vulnerability_classes".to_string(),
                param_type: ToolParamType::StringArray,
                description: "Vulnerability classes to test: XSS, SQLi, SSTI, CommandInjection, PathTraversal, SSRF, CRLF, OpenRedirect, XXE, NoSQLInjection, LDAPInjection, ExpressionLanguageInjection".to_string(),
                required: true,
                default_value: None,
                enum_values: vec![],
            },
            ToolParameter {
                name: "evasion_level".to_string(),
                param_type: ToolParamType::Enum,
                description: "How aggressively to evade WAF/defenses".to_string(),
                required: false,
                default_value: Some("moderate".to_string()),
                enum_values: vec!["none".to_string(), "light".to_string(), "moderate".to_string(), "aggressive".to_string(), "paranoid".to_string()],
            },
            ToolParameter {
                name: "payload_strategy".to_string(),
                param_type: ToolParamType::Enum,
                description: "Payload generation strategy".to_string(),
                required: false,
                default_value: Some("standard".to_string()),
                enum_values: vec!["standard".to_string(), "waf_bypass".to_string(), "polyglot".to_string(), "context_aware".to_string()],
            },
        ],
        returns: "Fuzzing results: found vulnerabilities, response patterns, WAF blocks".to_string(),
    }
}

fn exploit_finding_schema() -> ToolSchema {
    ToolSchema {
        name: "exploit_finding".to_string(),
        description: "Attempt to exploit a specific finding using an external tool. Use after confirming a vulnerability exists.".to_string(),
        parameters: vec![
            ToolParameter {
                name: "finding_id".to_string(),
                param_type: ToolParamType::Integer,
                description: "ID of the finding to exploit".to_string(),
                required: true,
                default_value: None,
                enum_values: vec![],
            },
            ToolParameter {
                name: "tool".to_string(),
                param_type: ToolParamType::Enum,
                description: "Exploitation tool to use".to_string(),
                required: true,
                default_value: None,
                enum_values: vec!["sqlmap".to_string(), "nuclei".to_string(), "dalfox".to_string()],
            },
            ToolParameter {
                name: "custom_args".to_string(),
                param_type: ToolParamType::StringArray,
                description: "Additional arguments to pass to the tool".to_string(),
                required: false,
                default_value: None,
                enum_values: vec![],
            },
        ],
        returns: "Exploitation results: success/failure, extracted data, proof of exploit".to_string(),
    }
}

fn discover_endpoints_schema() -> ToolSchema {
    ToolSchema {
        name: "discover_endpoints".to_string(),
        description: "Discover new endpoints on the target using various techniques.".to_string(),
        parameters: vec![
            ToolParameter {
                name: "technique".to_string(),
                param_type: ToolParamType::Enum,
                description: "Discovery technique to use".to_string(),
                required: true,
                default_value: None,
                enum_values: vec![
                    "directory_bruteforce".to_string(),
                    "javascript_extraction".to_string(),
                    "parameter_discovery".to_string(),
                    "vhost_discovery".to_string(),
                    "api_schema_inference".to_string(),
                    "sitemap_crawl".to_string(),
                    "waypoint_archive".to_string(),
                ],
            },
            ToolParameter {
                name: "scope".to_string(),
                param_type: ToolParamType::String,
                description: "Base URL or domain to scope the discovery".to_string(),
                required: true,
                default_value: None,
                enum_values: vec![],
            },
        ],
        returns: "Newly discovered endpoints, parameters, and content types".to_string(),
    }
}

fn chain_findings_schema() -> ToolSchema {
    ToolSchema {
        name: "chain_findings".to_string(),
        description: "Attempt to chain multiple findings into a multi-step attack. Use when you see SSRF + internal access, or XSS + CSRF potential.".to_string(),
        parameters: vec![
            ToolParameter {
                name: "finding_ids".to_string(),
                param_type: ToolParamType::StringArray,
                description: "IDs of findings to chain together".to_string(),
                required: true,
                default_value: None,
                enum_values: vec![],
            },
            ToolParameter {
                name: "chain_hypothesis".to_string(),
                param_type: ToolParamType::String,
                description: "Description of the expected attack chain".to_string(),
                required: true,
                default_value: None,
                enum_values: vec![],
            },
        ],
        returns: "Chain validation results: viable/not viable, attack path, impact assessment".to_string(),
    }
}

fn authenticate_schema() -> ToolSchema {
    ToolSchema {
        name: "authenticate".to_string(),
        description: "Authenticate with the target to access protected endpoints. Use when auth_required endpoints are discovered.".to_string(),
        parameters: vec![
            ToolParameter {
                name: "auth_endpoint".to_string(),
                param_type: ToolParamType::String,
                description: "URL of the authentication endpoint".to_string(),
                required: true,
                default_value: None,
                enum_values: vec![],
            },
            ToolParameter {
                name: "auth_method".to_string(),
                param_type: ToolParamType::Enum,
                description: "Authentication method to use".to_string(),
                required: true,
                default_value: None,
                enum_values: vec![
                    "basic_auth".to_string(),
                    "bearer_token".to_string(),
                    "cookie".to_string(),
                    "oauth2".to_string(),
                    "api_key".to_string(),
                ],
            },
        ],
        returns: "Authentication result: success/failure, session token, accessible endpoints".to_string(),
    }
}

fn evade_defense_schema() -> ToolSchema {
    ToolSchema {
        name: "evade_defense".to_string(),
        description: "Apply a specific evasion technique to bypass a detected defense. Use when WAF, rate limiter, or bot detection is blocking attacks.".to_string(),
        parameters: vec![
            ToolParameter {
                name: "defense_type".to_string(),
                param_type: ToolParamType::Enum,
                description: "Type of defense to evade".to_string(),
                required: true,
                default_value: None,
                enum_values: vec!["waf".to_string(), "rate_limiter".to_string(), "bot_detection".to_string(), "ip_block".to_string()],
            },
            ToolParameter {
                name: "evasion_technique".to_string(),
                param_type: ToolParamType::String,
                description: "Specific technique: encoding_chain, unicode_normalization, case_variation, comment_insertion, header_mutation, timing_jitter, persona_rotation".to_string(),
                required: true,
                default_value: None,
                enum_values: vec![],
            },
        ],
        returns: "Evasion result: bypass successful/failed, new defense observations".to_string(),
    }
}

fn deep_analyze_schema() -> ToolSchema {
    ToolSchema {
        name: "deep_analyze".to_string(),
        description: "Perform deep analysis on a specific endpoint using advanced techniques. Use for business logic flaws, timing attacks, and race conditions.".to_string(),
        parameters: vec![
            ToolParameter {
                name: "endpoint".to_string(),
                param_type: ToolParamType::String,
                description: "URL of the endpoint to analyze".to_string(),
                required: true,
                default_value: None,
                enum_values: vec![],
            },
            ToolParameter {
                name: "analysis_type".to_string(),
                param_type: ToolParamType::Enum,
                description: "Type of deep analysis".to_string(),
                required: true,
                default_value: None,
                enum_values: vec![
                    "timing_oracle".to_string(),
                    "differential_response".to_string(),
                    "business_logic_review".to_string(),
                    "source_code_analysis".to_string(),
                    "state_machine_mapping".to_string(),
                    "race_condition_probe".to_string(),
                ],
            },
        ],
        returns: "Analysis results: observations, anomalies, potential vulnerabilities".to_string(),
    }
}

fn generate_report_schema() -> ToolSchema {
    ToolSchema {
        name: "generate_report".to_string(),
        description:
            "Generate a scan report in the specified format. Use when assessment is complete."
                .to_string(),
        parameters: vec![ToolParameter {
            name: "format".to_string(),
            param_type: ToolParamType::Enum,
            description: "Report format".to_string(),
            required: true,
            default_value: Some("developer".to_string()),
            enum_values: vec![
                "developer".to_string(),
                "security".to_string(),
                "executive".to_string(),
            ],
        }],
        returns: "Generated report path and summary statistics".to_string(),
    }
}

fn http_request_schema() -> ToolSchema {
    ToolSchema {
        name: "http_request".to_string(),
        description: "Send a custom HTTP request and inspect the response. Use for manual probing, response analysis, and verifying hypotheses.".to_string(),
        parameters: vec![
            ToolParameter {
                name: "url".to_string(),
                param_type: ToolParamType::String,
                description: "Full URL to request".to_string(),
                required: true,
                default_value: None,
                enum_values: vec![],
            },
            ToolParameter {
                name: "method".to_string(),
                param_type: ToolParamType::Enum,
                description: "HTTP method".to_string(),
                required: true,
                default_value: Some("GET".to_string()),
                enum_values: vec!["GET".to_string(), "POST".to_string(), "PUT".to_string(), "DELETE".to_string(), "PATCH".to_string(), "HEAD".to_string(), "OPTIONS".to_string()],
            },
            ToolParameter {
                name: "headers".to_string(),
                param_type: ToolParamType::String,
                description: "JSON object of headers to send".to_string(),
                required: false,
                default_value: None,
                enum_values: vec![],
            },
            ToolParameter {
                name: "body".to_string(),
                param_type: ToolParamType::String,
                description: "Request body content".to_string(),
                required: false,
                default_value: None,
                enum_values: vec![],
            },
        ],
        returns: "HTTP response: status code, headers, body (truncated), response time".to_string(),
    }
}

fn read_javascript_schema() -> ToolSchema {
    ToolSchema {
        name: "read_javascript".to_string(),
        description: "Download and analyze JavaScript source files for endpoints, API keys, secrets, and logic flaws. Use when you discover JS files during crawling.".to_string(),
        parameters: vec![
            ToolParameter {
                name: "url".to_string(),
                param_type: ToolParamType::String,
                description: "URL of the JavaScript file".to_string(),
                required: true,
                default_value: None,
                enum_values: vec![],
            },
        ],
        returns: "Extracted: API endpoints, hardcoded secrets, interesting functions, DOM sinks".to_string(),
    }
}

/// Parses a raw tool invocation from LLM output into an AgentAction.
///
/// Validates required parameters, checks types, and converts string values
/// to the appropriate enums. Returns a descriptive error if parsing fails.
pub fn parse_tool_invocation(invocation: &ToolInvocation) -> Result<AgentAction, ToolError> {
    match invocation.tool_name.as_str() {
        "fuzz_endpoint" => parse_fuzz_endpoint(&invocation.arguments),
        "exploit_finding" => parse_exploit_finding(&invocation.arguments),
        "discover_endpoints" => parse_discover_endpoints(&invocation.arguments),
        "chain_findings" => parse_chain_findings(&invocation.arguments),
        "authenticate" => parse_authenticate(&invocation.arguments),
        "evade_defense" => parse_evade_defense(&invocation.arguments),
        "deep_analyze" => parse_deep_analyze(&invocation.arguments),
        "generate_report" => parse_generate_report(&invocation.arguments),
        _ => Err(ToolError::UnknownTool(invocation.tool_name.clone())),
    }
}

fn get_string(args: &HashMap<String, serde_json::Value>, key: &str) -> Result<String, ToolError> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| ToolError::MissingParameter(key.to_string()))
}

fn get_string_or(args: &HashMap<String, serde_json::Value>, key: &str, default: &str) -> String {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| default.to_string())
}

fn get_string_array(
    args: &HashMap<String, serde_json::Value>,
    key: &str,
) -> Result<Vec<String>, ToolError> {
    args.get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .ok_or_else(|| ToolError::MissingParameter(key.to_string()))
}

fn get_u64(args: &HashMap<String, serde_json::Value>, key: &str) -> Result<u64, ToolError> {
    args.get(key)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ToolError::MissingParameter(key.to_string()))
}

fn parse_evasion_level(s: &str) -> EvasionLevel {
    match s {
        "none" => EvasionLevel::None,
        "light" => EvasionLevel::Light,
        "moderate" => EvasionLevel::Moderate,
        "aggressive" => EvasionLevel::Aggressive,
        "paranoid" => EvasionLevel::Paranoid,
        _ => EvasionLevel::Moderate,
    }
}

fn parse_payload_strategy(s: &str) -> PayloadStrategy {
    match s {
        "standard" => PayloadStrategy::Standard,
        "waf_bypass" => PayloadStrategy::WafBypass,
        "polyglot" => PayloadStrategy::Polyglot,
        "context_aware" => PayloadStrategy::ContextAware,
        _ => PayloadStrategy::Standard,
    }
}

fn parse_discovery_technique(s: &str) -> Result<DiscoveryTechnique, ToolError> {
    match s {
        "directory_bruteforce" => Ok(DiscoveryTechnique::DirectoryBruteForce),
        "javascript_extraction" => Ok(DiscoveryTechnique::JavaScriptExtraction),
        "parameter_discovery" => Ok(DiscoveryTechnique::ParameterDiscovery),
        "vhost_discovery" => Ok(DiscoveryTechnique::VirtualHostDiscovery),
        "api_schema_inference" => Ok(DiscoveryTechnique::ApiSchemaInference),
        "sitemap_crawl" => Ok(DiscoveryTechnique::SitemapCrawl),
        "waypoint_archive" => Ok(DiscoveryTechnique::WaypointArchive),
        other => Err(ToolError::InvalidParameterType {
            param: "technique".to_string(),
            expected: format!(
                "one of: directory_bruteforce, javascript_extraction, etc. Got: {other}"
            ),
        }),
    }
}

fn parse_analysis_type(s: &str) -> Result<AnalysisType, ToolError> {
    match s {
        "timing_oracle" => Ok(AnalysisType::TimingOracle),
        "differential_response" => Ok(AnalysisType::DifferentialResponse),
        "business_logic_review" => Ok(AnalysisType::BusinessLogicReview),
        "source_code_analysis" => Ok(AnalysisType::SourceCodeAnalysis),
        "state_machine_mapping" => Ok(AnalysisType::StateMachineMapping),
        "race_condition_probe" => Ok(AnalysisType::RaceConditionProbe),
        other => Err(ToolError::InvalidParameterType {
            param: "analysis_type".to_string(),
            expected: format!("one of: timing_oracle, differential_response, etc. Got: {other}"),
        }),
    }
}

fn parse_auth_method(s: &str) -> Result<AuthMethod, ToolError> {
    match s {
        "basic_auth" => Ok(AuthMethod::BasicAuth),
        "bearer_token" => Ok(AuthMethod::BearerToken),
        "cookie" => Ok(AuthMethod::Cookie),
        "oauth2" => Ok(AuthMethod::OAuth2),
        "api_key" => Ok(AuthMethod::ApiKey),
        other => Err(ToolError::InvalidParameterType {
            param: "auth_method".to_string(),
            expected: format!(
                "one of: basic_auth, bearer_token, cookie, oauth2, api_key. Got: {other}"
            ),
        }),
    }
}

fn parse_fuzz_endpoint(
    args: &HashMap<String, serde_json::Value>,
) -> Result<AgentAction, ToolError> {
    let endpoint = get_string(args, "endpoint")?;
    let method = get_string_or(args, "method", "GET");
    let vulnerability_classes = get_string_array(args, "vulnerability_classes")?;
    let evasion = parse_evasion_level(&get_string_or(args, "evasion_level", "moderate"));
    let strategy = parse_payload_strategy(&get_string_or(args, "payload_strategy", "standard"));

    Ok(AgentAction::FuzzEndpoint {
        endpoint,
        method,
        vulnerability_classes,
        evasion_level: evasion,
        payload_strategy: strategy,
    })
}

fn parse_exploit_finding(
    args: &HashMap<String, serde_json::Value>,
) -> Result<AgentAction, ToolError> {
    let finding_id = get_u64(args, "finding_id")?;
    let tool = get_string(args, "tool")?;
    let custom_args = args
        .get("custom_args")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    Ok(AgentAction::ExploitFinding {
        finding_id,
        tool,
        custom_args,
    })
}

fn parse_discover_endpoints(
    args: &HashMap<String, serde_json::Value>,
) -> Result<AgentAction, ToolError> {
    let technique_str = get_string(args, "technique")?;
    let technique = parse_discovery_technique(&technique_str)?;
    let scope = get_string(args, "scope")?;

    Ok(AgentAction::DiscoverEndpoints { technique, scope })
}

fn parse_chain_findings(
    args: &HashMap<String, serde_json::Value>,
) -> Result<AgentAction, ToolError> {
    let id_strings = get_string_array(args, "finding_ids")?;
    let finding_ids: Vec<u64> = id_strings.iter().filter_map(|s| s.parse().ok()).collect();
    let chain_hypothesis = get_string(args, "chain_hypothesis")?;

    Ok(AgentAction::ChainFindings {
        finding_ids,
        chain_hypothesis,
    })
}

fn parse_authenticate(args: &HashMap<String, serde_json::Value>) -> Result<AgentAction, ToolError> {
    let auth_endpoint = get_string(args, "auth_endpoint")?;
    let method_str = get_string(args, "auth_method")?;
    let auth_method = parse_auth_method(&method_str)?;

    Ok(AgentAction::AuthenticateFirst {
        auth_endpoint,
        auth_method,
    })
}

fn parse_evade_defense(
    args: &HashMap<String, serde_json::Value>,
) -> Result<AgentAction, ToolError> {
    let defense_type = get_string(args, "defense_type")?;
    let evasion_technique = get_string(args, "evasion_technique")?;

    Ok(AgentAction::EvadeDefense {
        defense_type,
        evasion_technique,
    })
}

fn parse_deep_analyze(args: &HashMap<String, serde_json::Value>) -> Result<AgentAction, ToolError> {
    let endpoint = get_string(args, "endpoint")?;
    let type_str = get_string(args, "analysis_type")?;
    let analysis_type = parse_analysis_type(&type_str)?;

    Ok(AgentAction::DeepAnalyze {
        endpoint,
        analysis_type,
    })
}

fn parse_generate_report(
    args: &HashMap<String, serde_json::Value>,
) -> Result<AgentAction, ToolError> {
    let format = get_string_or(args, "format", "developer");
    Ok(AgentAction::GenerateReport { format })
}

/// Formats the tool registry as a string suitable for injection into an LLM prompt.
///
/// Produces a structured description of each tool that models can parse
/// and use for function calling.
pub fn format_tools_for_prompt(tools: &[ToolSchema]) -> String {
    let mut output = String::from("<available_tools>\n");
    for tool in tools {
        output.push_str(&format!("\n<tool name=\"{}\">\n", tool.name));
        output.push_str(&format!(
            "  <description>{}</description>\n",
            tool.description
        ));
        output.push_str("  <parameters>\n");
        for param in &tool.parameters {
            let required_str = if param.required {
                "required"
            } else {
                "optional"
            };
            output.push_str(&format!(
                "    <param name=\"{}\" type=\"{}\" {}>{}</param>\n",
                param.name, param.param_type, required_str, param.description
            ));
            if !param.enum_values.is_empty() {
                output.push_str(&format!("      values: {}\n", param.enum_values.join(", ")));
            }
        }
        output.push_str("  </parameters>\n");
        output.push_str(&format!("  <returns>{}</returns>\n", tool.returns));
        output.push_str("</tool>\n");
    }
    output.push_str("\n</available_tools>");
    output
}

#[cfg(test)]
#[path = "agent_tools_test.rs"]
mod agent_tools_test;
