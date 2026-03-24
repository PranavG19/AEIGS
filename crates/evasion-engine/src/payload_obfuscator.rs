/// Multi-layer payload obfuscation engine for WAF/filter evasion.
///
/// Provides 12 independent transforms that can be composed into chains
/// and applied polymorphically so no two requests carry identical payloads.
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObfuscationTransform {
    UrlEncode,
    DoubleUrlEncode,
    TripleUrlEncode,
    UnicodeFullwidth,
    HtmlEntityDecimal,
    HtmlEntityHex,
    CaseRandomization,
    SqlCommentInsertion,
    HtmlCommentInsertion,
    WhitespaceSubstitution,
    StringConcatenation,
    CharacterEscapeHex,
    Base64Wrap,
    Rot13,
    HexWrap,
}

impl ObfuscationTransform {
    pub fn all() -> &'static [ObfuscationTransform] {
        &[
            ObfuscationTransform::UrlEncode,
            ObfuscationTransform::DoubleUrlEncode,
            ObfuscationTransform::TripleUrlEncode,
            ObfuscationTransform::UnicodeFullwidth,
            ObfuscationTransform::HtmlEntityDecimal,
            ObfuscationTransform::HtmlEntityHex,
            ObfuscationTransform::CaseRandomization,
            ObfuscationTransform::SqlCommentInsertion,
            ObfuscationTransform::HtmlCommentInsertion,
            ObfuscationTransform::WhitespaceSubstitution,
            ObfuscationTransform::StringConcatenation,
            ObfuscationTransform::CharacterEscapeHex,
            ObfuscationTransform::Base64Wrap,
            ObfuscationTransform::Rot13,
            ObfuscationTransform::HexWrap,
        ]
    }
}

impl std::fmt::Display for ObfuscationTransform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            ObfuscationTransform::UrlEncode => "url-encode",
            ObfuscationTransform::DoubleUrlEncode => "double-url-encode",
            ObfuscationTransform::TripleUrlEncode => "triple-url-encode",
            ObfuscationTransform::UnicodeFullwidth => "unicode-fullwidth",
            ObfuscationTransform::HtmlEntityDecimal => "html-entity-decimal",
            ObfuscationTransform::HtmlEntityHex => "html-entity-hex",
            ObfuscationTransform::CaseRandomization => "case-randomization",
            ObfuscationTransform::SqlCommentInsertion => "sql-comment-insertion",
            ObfuscationTransform::HtmlCommentInsertion => "html-comment-insertion",
            ObfuscationTransform::WhitespaceSubstitution => "whitespace-substitution",
            ObfuscationTransform::StringConcatenation => "string-concatenation",
            ObfuscationTransform::CharacterEscapeHex => "character-escape-hex",
            ObfuscationTransform::Base64Wrap => "base64-wrap",
            ObfuscationTransform::Rot13 => "rot13",
            ObfuscationTransform::HexWrap => "hex-wrap",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone)]
pub struct ObfuscatedPayload {
    pub original: String,
    pub obfuscated: String,
    pub transforms_applied: Vec<ObfuscationTransform>,
}

#[derive(Debug, Clone)]
pub struct ObfuscationChain {
    transforms: Vec<ObfuscationTransform>,
}

impl ObfuscationChain {
    pub fn new() -> Self {
        Self {
            transforms: Vec::new(),
        }
    }

    pub fn push(mut self, transform: ObfuscationTransform) -> Self {
        self.transforms.push(transform);
        self
    }

    pub fn transforms(&self) -> &[ObfuscationTransform] {
        &self.transforms
    }

    pub fn apply(&self, input: &str) -> ObfuscatedPayload {
        let mut current = input.to_string();
        for &transform in &self.transforms {
            current = apply_transform(&current, transform);
        }
        ObfuscatedPayload {
            original: input.to_string(),
            obfuscated: current,
            transforms_applied: self.transforms.clone(),
        }
    }
}

impl Default for ObfuscationChain {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PayloadObfuscator {
    rng_seed: Option<u64>,
}

impl PayloadObfuscator {
    pub fn new() -> Self {
        Self { rng_seed: None }
    }

    /// Seed for deterministic polymorphic generation (useful in tests).
    pub fn with_seed(seed: u64) -> Self {
        Self {
            rng_seed: Some(seed),
        }
    }

    /// Apply a single transform to the payload.
    pub fn apply_single(
        &self,
        payload: &str,
        transform: ObfuscationTransform,
    ) -> ObfuscatedPayload {
        ObfuscatedPayload {
            original: payload.to_string(),
            obfuscated: apply_transform(payload, transform),
            transforms_applied: vec![transform],
        }
    }

    /// Apply a chain of transforms in sequence.
    pub fn apply_chain(&self, payload: &str, chain: &ObfuscationChain) -> ObfuscatedPayload {
        chain.apply(payload)
    }

    /// Generate `count` polymorphic variants using random transform combinations.
    /// Each variant applies 1-3 randomly selected transforms.
    pub fn generate_polymorphic(&self, payload: &str, count: usize) -> Vec<ObfuscatedPayload> {
        let mut rng = self.make_rng();
        let all_transforms = ObfuscationTransform::all();
        let mut results = Vec::with_capacity(count);
        let mut seen = std::collections::HashSet::new();

        let max_attempts = count * 20;
        let mut attempts = 0;

        while results.len() < count && attempts < max_attempts {
            attempts += 1;
            let depth = rng.random_range(1..=3);
            let mut chain = ObfuscationChain::new();

            for _ in 0..depth {
                let transform = all_transforms[rng.random_range(0..all_transforms.len())];
                chain = chain.push(transform);
            }

            let result = chain.apply(payload);
            if seen.insert(result.obfuscated.clone()) {
                results.push(result);
            }
        }

        results
    }

    fn make_rng(&self) -> rand::rngs::StdRng {
        use rand::SeedableRng;
        match self.rng_seed {
            Some(seed) => rand::rngs::StdRng::seed_from_u64(seed),
            None => rand::rngs::StdRng::from_os_rng(),
        }
    }
}

impl Default for PayloadObfuscator {
    fn default() -> Self {
        Self::new()
    }
}

fn url_encode_char(c: char) -> String {
    if c.is_ascii_alphanumeric() {
        return c.to_string();
    }
    let mut buf = [0u8; 4];
    let encoded = c.encode_utf8(&mut buf);
    encoded
        .bytes()
        .map(|b| format!("%{b:02X}"))
        .collect::<String>()
}

fn apply_url_encode(input: &str) -> String {
    input.chars().map(url_encode_char).collect()
}

fn apply_double_url_encode(input: &str) -> String {
    let first = apply_url_encode(input);
    first
        .chars()
        .map(|c| {
            if c == '%' {
                "%25".to_string()
            } else {
                url_encode_char(c)
            }
        })
        .collect()
}

fn apply_triple_url_encode(input: &str) -> String {
    let double = apply_double_url_encode(input);
    double
        .chars()
        .map(|c| {
            if c == '%' {
                "%25".to_string()
            } else {
                url_encode_char(c)
            }
        })
        .collect()
}

fn apply_unicode_fullwidth(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c.is_ascii_punctuation() {
                let code = c as u32;
                if (0x21..=0x7E).contains(&code) {
                    char::from_u32(code - 0x21 + 0xFF01).unwrap_or(c)
                } else {
                    c
                }
            } else {
                c
            }
        })
        .collect()
}

fn apply_html_entity_decimal(input: &str) -> String {
    input.chars().map(|c| format!("&#{};", c as u32)).collect()
}

fn apply_html_entity_hex(input: &str) -> String {
    input
        .chars()
        .map(|c| format!("&#x{:X};", c as u32))
        .collect()
}

fn apply_case_randomization(input: &str) -> String {
    let mut rng = rand::rng();
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                if rng.random_bool(0.5) {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            } else {
                c
            }
        })
        .collect()
}

fn apply_sql_comment_insertion(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c == ' ' {
                "/**/".to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn apply_html_comment_insertion(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c == ' ' {
                "<!-- -->".to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn apply_whitespace_substitution(input: &str) -> String {
    let substitutes = ['\t', '\x0b', '\x0c'];
    let mut rng = rand::rng();
    input
        .chars()
        .map(|c| {
            if c == ' ' {
                substitutes[rng.random_range(0..substitutes.len())]
            } else {
                c
            }
        })
        .collect()
}

fn apply_string_concatenation(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    if chars.len() < 2 {
        return input.to_string();
    }
    let mid = chars.len() / 2;
    let left: String = chars[..mid].iter().collect();
    let right: String = chars[mid..].iter().collect();
    format!("'{left}'+'{right}'")
}

fn apply_character_escape_hex(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii() {
                format!("\\x{:02X}", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn apply_base64_wrap(input: &str) -> String {
    base64_encode(input.as_bytes())
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let chunks = data.chunks(3);
    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

fn apply_rot13(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => char::from(c as u8 + 13),
            'n'..='z' | 'N'..='Z' => char::from(c as u8 - 13),
            _ => c,
        })
        .collect()
}

fn apply_hex_wrap(input: &str) -> String {
    input
        .bytes()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

fn apply_transform(input: &str, transform: ObfuscationTransform) -> String {
    match transform {
        ObfuscationTransform::UrlEncode => apply_url_encode(input),
        ObfuscationTransform::DoubleUrlEncode => apply_double_url_encode(input),
        ObfuscationTransform::TripleUrlEncode => apply_triple_url_encode(input),
        ObfuscationTransform::UnicodeFullwidth => apply_unicode_fullwidth(input),
        ObfuscationTransform::HtmlEntityDecimal => apply_html_entity_decimal(input),
        ObfuscationTransform::HtmlEntityHex => apply_html_entity_hex(input),
        ObfuscationTransform::CaseRandomization => apply_case_randomization(input),
        ObfuscationTransform::SqlCommentInsertion => apply_sql_comment_insertion(input),
        ObfuscationTransform::HtmlCommentInsertion => apply_html_comment_insertion(input),
        ObfuscationTransform::WhitespaceSubstitution => apply_whitespace_substitution(input),
        ObfuscationTransform::StringConcatenation => apply_string_concatenation(input),
        ObfuscationTransform::CharacterEscapeHex => apply_character_escape_hex(input),
        ObfuscationTransform::Base64Wrap => apply_base64_wrap(input),
        ObfuscationTransform::Rot13 => apply_rot13(input),
        ObfuscationTransform::HexWrap => apply_hex_wrap(input),
    }
}

/// Decode a URL-encoded string back to its original form.
pub fn url_decode(input: &str) -> String {
    let mut result = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let high = bytes[i + 1];
            let low = bytes[i + 2];
            if let (Some(h), Some(l)) = (hex_val(high), hex_val(low)) {
                result.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Decode HTML entities (decimal and hex) back to characters.
pub fn html_entity_decode(input: &str) -> String {
    let mut result = String::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '&' && i + 2 < chars.len() && chars[i + 1] == '#' {
            let is_hex = i + 3 < chars.len() && (chars[i + 2] == 'x' || chars[i + 2] == 'X');
            let start = if is_hex { i + 3 } else { i + 2 };
            let mut end = start;
            while end < chars.len() && chars[end] != ';' {
                end += 1;
            }
            if end < chars.len() {
                let num_str: String = chars[start..end].iter().collect();
                let code = if is_hex {
                    u32::from_str_radix(&num_str, 16).ok()
                } else {
                    num_str.parse::<u32>().ok()
                };
                if let Some(cp) = code.and_then(char::from_u32) {
                    result.push(cp);
                    i = end + 1;
                    continue;
                }
            }
        }
        result.push(chars[i]);
        i += 1;
    }
    result
}

/// Decode a hex-encoded string.
pub fn hex_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut result = Vec::new();
    for pair in bytes.chunks(2) {
        match (hex_val(pair[0]), hex_val(pair[1])) {
            (Some(h), Some(l)) => result.push(h << 4 | l),
            _ => return None,
        }
    }
    String::from_utf8(result).ok()
}

#[cfg(test)]
#[path = "payload_obfuscator_test.rs"]
mod payload_obfuscator_test;
