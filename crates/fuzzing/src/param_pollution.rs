use std::fmt;

/// Which value a server selects when the same parameter appears multiple times.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParamPrecedence {
    First,
    Last,
    Concatenated,
    Array,
    Unknown,
}

impl fmt::Display for ParamPrecedence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::First => write!(f, "first"),
            Self::Last => write!(f, "last"),
            Self::Concatenated => write!(f, "concatenated"),
            Self::Array => write!(f, "array"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Web framework identified by HPP response behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetectedFramework {
    Php,
    AspNet,
    JavaServlet,
    PythonFlask,
    PythonDjango,
    NodeExpress,
    RubyRails,
    Unknown,
}

impl fmt::Display for DetectedFramework {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Php => write!(f, "PHP"),
            Self::AspNet => write!(f, "ASP.NET"),
            Self::JavaServlet => write!(f, "Java Servlet"),
            Self::PythonFlask => write!(f, "Python/Flask"),
            Self::PythonDjango => write!(f, "Python/Django"),
            Self::NodeExpress => write!(f, "Node.js/Express"),
            Self::RubyRails => write!(f, "Ruby on Rails"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// The kind of pollution vector being tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PollutionPattern {
    /// Same param repeated in the query string.
    DuplicateQueryParam,
    /// Array bracket notation: `param[]=a&param[]=b`.
    ArrayNotation,
    /// Same param in both URL query and POST body.
    UrlBodyCollision,
    /// Semicolon delimiter: `param=a;param=b` (Apache/Tomcat).
    SemicolonDelimiter,
    /// Mixed encoding: one instance URL-encoded, one plain.
    MixedEncoding,
    /// Content-Type mismatch: form-urlencoded body sent as multipart (or vice versa).
    ContentTypeMismatch,
    /// WAF bypass: benign value first, malicious value second (or reversed).
    WafBypass,
    /// JSON parameter pollution: duplicate keys in JSON body.
    JsonDuplicateKey,
}

impl fmt::Display for PollutionPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateQueryParam => write!(f, "duplicate-query-param"),
            Self::ArrayNotation => write!(f, "array-notation"),
            Self::UrlBodyCollision => write!(f, "url-body-collision"),
            Self::SemicolonDelimiter => write!(f, "semicolon-delimiter"),
            Self::MixedEncoding => write!(f, "mixed-encoding"),
            Self::ContentTypeMismatch => write!(f, "content-type-mismatch"),
            Self::WafBypass => write!(f, "waf-bypass"),
            Self::JsonDuplicateKey => write!(f, "json-duplicate-key"),
        }
    }
}

const HIGH_SEVERITY: f64 = 7.5;
const MEDIUM_SEVERITY: f64 = 5.5;
const LOW_SEVERITY: f64 = 3.5;
const WAF_BYPASS_SEVERITY: f64 = 8.5;

/// Marker payload used to detect which value the server reflects.
const CANARY_FIRST: &str = "AEGIS_FIRST_7f3a";
const CANARY_LAST: &str = "AEGIS_LAST_9b2e";

/// Single HPP test payload ready to send.
#[derive(Debug, Clone)]
pub struct HppPayload {
    pub pattern: PollutionPattern,
    pub query_string: String,
    pub body: Option<String>,
    pub content_type: Option<String>,
    pub description: String,
}

/// Result of analyzing server HPP behavior.
#[derive(Debug, Clone)]
pub struct HppFinding {
    pub endpoint: String,
    pub method: String,
    pub pattern: PollutionPattern,
    pub precedence: ParamPrecedence,
    pub severity: f64,
    pub evidence: String,
    pub detected_framework: DetectedFramework,
}

/// Generates all HPP test payloads for a given parameter name and optional
/// malicious value to smuggle past a WAF.
pub fn generate_hpp_payloads(param: &str, malicious_value: Option<&str>) -> Vec<HppPayload> {
    let evil = malicious_value.unwrap_or("<script>alert(1)</script>");
    let mut payloads = vec![
        build_duplicate_query(param),
        build_array_notation(param),
        build_url_body_collision(param),
        build_semicolon_delimiter(param),
        build_mixed_encoding(param),
        build_content_type_mismatch(param),
    ];
    payloads.extend(build_waf_bypass_payloads(param, evil));
    payloads.push(build_json_duplicate_key(param, evil));

    payloads
}

/// Determines which value the server selected from the response body.
pub fn detect_precedence(response_body: &str) -> ParamPrecedence {
    let has_first = response_body.contains(CANARY_FIRST);
    let has_last = response_body.contains(CANARY_LAST);

    match (has_first, has_last) {
        (true, false) => ParamPrecedence::First,
        (false, true) => ParamPrecedence::Last,
        (true, true) => {
            let comma_no_space = format!("{CANARY_FIRST},{CANARY_LAST}");
            let comma_space = format!("{CANARY_FIRST}, {CANARY_LAST}");
            let has_concat =
                response_body.contains(&comma_no_space) || response_body.contains(&comma_space);
            if has_concat {
                let bracketed = response_body.contains(&format!("[{comma_no_space}"))
                    || response_body.contains(&format!("[{comma_space}"));
                if bracketed {
                    ParamPrecedence::Array
                } else {
                    ParamPrecedence::Concatenated
                }
            } else {
                ParamPrecedence::Array
            }
        }
        (false, false) => ParamPrecedence::Unknown,
    }
}

/// Maps observed HPP precedence to the most likely web framework.
pub fn fingerprint_framework(
    precedence: ParamPrecedence,
    array_notation_works: bool,
    semicolon_works: bool,
) -> DetectedFramework {
    match (precedence, array_notation_works, semicolon_works) {
        (ParamPrecedence::Last, true, false) => DetectedFramework::Php,
        (ParamPrecedence::Concatenated, _, _) => DetectedFramework::AspNet,
        (ParamPrecedence::Last, false, true) => DetectedFramework::JavaServlet,
        (ParamPrecedence::First, false, false) => DetectedFramework::PythonFlask,
        (ParamPrecedence::Last, false, false) => DetectedFramework::NodeExpress,
        (ParamPrecedence::First, true, false) => DetectedFramework::RubyRails,
        _ => DetectedFramework::Unknown,
    }
}

/// Analyzes an HPP test response and produces a finding if the behavior is exploitable.
pub fn analyze_hpp_response(
    endpoint: &str,
    method: &str,
    payload: &HppPayload,
    response_body: &str,
    response_status: u16,
) -> Option<HppFinding> {
    if response_status >= 500 {
        return None;
    }

    let precedence = detect_precedence(response_body);

    if precedence == ParamPrecedence::Unknown {
        return None;
    }

    let severity = severity_for_pattern(payload.pattern, precedence);

    let framework = fingerprint_framework(
        precedence,
        payload.pattern == PollutionPattern::ArrayNotation
            && precedence != ParamPrecedence::Unknown,
        payload.pattern == PollutionPattern::SemicolonDelimiter
            && precedence != ParamPrecedence::Unknown,
    );

    Some(HppFinding {
        endpoint: endpoint.to_string(),
        method: method.to_string(),
        pattern: payload.pattern,
        precedence,
        severity,
        evidence: format!(
            "HPP {pattern}: server uses {precedence} value (framework: {framework}). \
             Payload: {desc}",
            pattern = payload.pattern,
            precedence = precedence,
            framework = framework,
            desc = payload.description,
        ),
        detected_framework: framework,
    })
}

/// Generates WAF-bypass specific payloads that split malicious input across
/// duplicate parameters, exploiting WAF-first / app-last discrepancies.
pub fn generate_waf_bypass_payloads(param: &str, malicious: &str) -> Vec<HppPayload> {
    build_waf_bypass_payloads(param, malicious)
}

/// Returns all supported pollution patterns.
pub fn all_patterns() -> Vec<PollutionPattern> {
    vec![
        PollutionPattern::DuplicateQueryParam,
        PollutionPattern::ArrayNotation,
        PollutionPattern::UrlBodyCollision,
        PollutionPattern::SemicolonDelimiter,
        PollutionPattern::MixedEncoding,
        PollutionPattern::ContentTypeMismatch,
        PollutionPattern::WafBypass,
        PollutionPattern::JsonDuplicateKey,
    ]
}

/// Severity depends on both pattern and which value the server used.
fn severity_for_pattern(pattern: PollutionPattern, precedence: ParamPrecedence) -> f64 {
    match pattern {
        PollutionPattern::WafBypass => WAF_BYPASS_SEVERITY,
        PollutionPattern::UrlBodyCollision => HIGH_SEVERITY,
        PollutionPattern::JsonDuplicateKey => HIGH_SEVERITY,
        PollutionPattern::ContentTypeMismatch => MEDIUM_SEVERITY,
        PollutionPattern::MixedEncoding => MEDIUM_SEVERITY,
        PollutionPattern::DuplicateQueryParam | PollutionPattern::ArrayNotation => match precedence
        {
            ParamPrecedence::Concatenated | ParamPrecedence::Array => MEDIUM_SEVERITY,
            _ => LOW_SEVERITY,
        },
        PollutionPattern::SemicolonDelimiter => LOW_SEVERITY,
    }
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}

fn build_duplicate_query(param: &str) -> HppPayload {
    HppPayload {
        pattern: PollutionPattern::DuplicateQueryParam,
        query_string: format!("{param}={CANARY_FIRST}&{param}={CANARY_LAST}"),
        body: None,
        content_type: None,
        description: format!(
            "Duplicate query param '{param}' with two canary values to detect precedence"
        ),
    }
}

fn build_array_notation(param: &str) -> HppPayload {
    HppPayload {
        pattern: PollutionPattern::ArrayNotation,
        query_string: format!("{param}[]={CANARY_FIRST}&{param}[]={CANARY_LAST}"),
        body: None,
        content_type: None,
        description: format!("Array bracket notation '{param}[]' to test array parameter handling"),
    }
}

fn build_url_body_collision(param: &str) -> HppPayload {
    HppPayload {
        pattern: PollutionPattern::UrlBodyCollision,
        query_string: format!("{param}={CANARY_FIRST}"),
        body: Some(format!("{param}={CANARY_LAST}")),
        content_type: Some("application/x-www-form-urlencoded".to_string()),
        description: format!(
            "Param '{param}' in URL query (first canary) and POST body (last canary) simultaneously"
        ),
    }
}

fn build_semicolon_delimiter(param: &str) -> HppPayload {
    HppPayload {
        pattern: PollutionPattern::SemicolonDelimiter,
        query_string: format!("{param}={CANARY_FIRST};{param}={CANARY_LAST}"),
        body: None,
        content_type: None,
        description: format!(
            "Semicolon-delimited duplicate param '{param}' (Apache/Tomcat behavior)"
        ),
    }
}

fn build_mixed_encoding(param: &str) -> HppPayload {
    let encoded_param = url_encode(param);
    HppPayload {
        pattern: PollutionPattern::MixedEncoding,
        query_string: format!("{param}={CANARY_FIRST}&{encoded_param}={CANARY_LAST}"),
        body: None,
        content_type: None,
        description: format!(
            "Mixed encoding: plain '{param}' and URL-encoded '{encoded_param}' with different values"
        ),
    }
}

fn build_content_type_mismatch(param: &str) -> HppPayload {
    let boundary = "----AegisBoundary7f3a9b2e";
    let multipart_body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"{param}\"\r\n\r\n\
         {CANARY_LAST}\r\n--{boundary}--\r\n"
    );
    HppPayload {
        pattern: PollutionPattern::ContentTypeMismatch,
        query_string: format!("{param}={CANARY_FIRST}"),
        body: Some(multipart_body),
        content_type: Some(format!("multipart/form-data; boundary={boundary}")),
        description: format!(
            "Content-Type mismatch: '{param}' in query (urlencoded) and multipart body"
        ),
    }
}

fn build_waf_bypass_payloads(param: &str, malicious: &str) -> Vec<HppPayload> {
    let safe_value = "safe_normal_value";
    vec![
        HppPayload {
            pattern: PollutionPattern::WafBypass,
            query_string: format!("{param}={safe_value}&{param}={}", url_encode(malicious)),
            body: None,
            content_type: None,
            description: format!(
                "WAF bypass: benign '{param}' first, malicious second (app-uses-last exploit)"
            ),
        },
        HppPayload {
            pattern: PollutionPattern::WafBypass,
            query_string: format!("{param}={}", url_encode(malicious)),
            body: Some(format!("{param}={safe_value}")),
            content_type: Some("application/x-www-form-urlencoded".to_string()),
            description: format!(
                "WAF bypass: malicious '{param}' in URL, benign in body (WAF checks body, app uses query)"
            ),
        },
        HppPayload {
            pattern: PollutionPattern::WafBypass,
            query_string: format!("{param}={safe_value}"),
            body: Some(format!("{param}={}", url_encode(malicious))),
            content_type: Some("application/x-www-form-urlencoded".to_string()),
            description: format!(
                "WAF bypass: benign '{param}' in URL, malicious in body (WAF checks query, app uses body)"
            ),
        },
    ]
}

fn build_json_duplicate_key(param: &str, malicious: &str) -> HppPayload {
    let escaped_param = param.replace('\\', "\\\\").replace('"', "\\\"");
    let escaped_mal = malicious.replace('\\', "\\\\").replace('"', "\\\"");
    let json_body =
        format!("{{\"{escaped_param}\": \"safe_value\", \"{escaped_param}\": \"{escaped_mal}\"}}");
    HppPayload {
        pattern: PollutionPattern::JsonDuplicateKey,
        query_string: String::new(),
        body: Some(json_body),
        content_type: Some("application/json".to_string()),
        description: format!(
            "JSON duplicate key '{param}': safe value first, malicious second (RFC 8259 undefined behavior)"
        ),
    }
}
