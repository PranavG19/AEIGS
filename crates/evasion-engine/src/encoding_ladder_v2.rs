use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Encoding types available in the ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EncodingType {
    Url,
    DoubleUrl,
    Unicode,
    OverlongUtf8,
    HtmlEntity,
    HtmlEntityHex,
    Base64,
    Hex,
    Octal,
    JsUnicode,
    JsOctal,
    CssEscape,
    XmlEntity,
    DecimalEntity,
}

impl std::fmt::Display for EncodingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Url => write!(f, "url"),
            Self::DoubleUrl => write!(f, "double-url"),
            Self::Unicode => write!(f, "unicode"),
            Self::OverlongUtf8 => write!(f, "overlong-utf8"),
            Self::HtmlEntity => write!(f, "html-entity"),
            Self::HtmlEntityHex => write!(f, "html-entity-hex"),
            Self::Base64 => write!(f, "base64"),
            Self::Hex => write!(f, "hex"),
            Self::Octal => write!(f, "octal"),
            Self::JsUnicode => write!(f, "js-unicode"),
            Self::JsOctal => write!(f, "js-octal"),
            Self::CssEscape => write!(f, "css-escape"),
            Self::XmlEntity => write!(f, "xml-entity"),
            Self::DecimalEntity => write!(f, "decimal-entity"),
        }
    }
}

/// Context determines which encoding types are appropriate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EncodingContext {
    UrlParameter,
    HtmlBody,
    HtmlAttribute,
    JavaScriptString,
    CssValue,
    XmlContent,
    JsonValue,
    HttpHeader,
}

impl std::fmt::Display for EncodingContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UrlParameter => write!(f, "url-parameter"),
            Self::HtmlBody => write!(f, "html-body"),
            Self::HtmlAttribute => write!(f, "html-attribute"),
            Self::JavaScriptString => write!(f, "javascript-string"),
            Self::CssValue => write!(f, "css-value"),
            Self::XmlContent => write!(f, "xml-content"),
            Self::JsonValue => write!(f, "json-value"),
            Self::HttpHeader => write!(f, "http-header"),
        }
    }
}

/// A single encoded result with its encoding chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodedResult {
    pub payload: String,
    pub original: String,
    pub chain: Vec<EncodingType>,
    pub context: EncodingContext,
    pub depth: usize,
}

/// Multi-layer encoding chain generator for WAF bypass.
pub struct EncodingLadderV2 {
    context_map: HashMap<EncodingContext, Vec<EncodingType>>,
    max_chain_depth: usize,
}

impl EncodingLadderV2 {
    pub fn new() -> Self {
        Self {
            context_map: build_context_map(),
            max_chain_depth: 3,
        }
    }

    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_chain_depth = depth.clamp(1, 5);
        self
    }

    /// Apply a single encoding type to a payload.
    pub fn encode_single(&self, payload: &str, encoding: EncodingType) -> String {
        apply_encoding(payload, encoding)
    }

    /// Generate all valid single-layer encodings for a context.
    pub fn encode_for_context(
        &self,
        payload: &str,
        context: EncodingContext,
    ) -> Vec<EncodedResult> {
        let encodings = self.context_map.get(&context).cloned().unwrap_or_default();

        encodings
            .into_iter()
            .map(|enc| {
                let encoded = apply_encoding(payload, enc);
                EncodedResult {
                    payload: encoded,
                    original: payload.to_string(),
                    chain: vec![enc],
                    context,
                    depth: 1,
                }
            })
            .collect()
    }

    /// Generate multi-layer encoding chains up to max depth.
    pub fn encode_chain(&self, payload: &str, context: EncodingContext) -> Vec<EncodedResult> {
        let valid_encodings = self.context_map.get(&context).cloned().unwrap_or_default();

        if valid_encodings.is_empty() {
            return Vec::new();
        }

        let mut results = Vec::new();

        for &enc in &valid_encodings {
            let encoded = apply_encoding(payload, enc);
            results.push(EncodedResult {
                payload: encoded,
                original: payload.to_string(),
                chain: vec![enc],
                context,
                depth: 1,
            });
        }

        for depth in 2..=self.max_chain_depth {
            let prev_results: Vec<EncodedResult> = results
                .iter()
                .filter(|r| r.depth == depth - 1)
                .cloned()
                .collect();

            for prev in &prev_results {
                for &enc in &valid_encodings {
                    if prev.chain.last() == Some(&enc) {
                        continue;
                    }
                    let encoded = apply_encoding(&prev.payload, enc);
                    let mut chain = prev.chain.clone();
                    chain.push(enc);
                    results.push(EncodedResult {
                        payload: encoded,
                        original: payload.to_string(),
                        chain,
                        context,
                        depth,
                    });
                }
            }
        }

        results
    }

    /// Generate all permutations of encoding types up to given length.
    pub fn permutations(
        &self,
        payload: &str,
        encodings: &[EncodingType],
        max_len: usize,
    ) -> Vec<EncodedResult> {
        let mut results = Vec::new();
        let limit = max_len.min(4);

        for &enc in encodings {
            let encoded = apply_encoding(payload, enc);
            results.push(EncodedResult {
                payload: encoded,
                original: payload.to_string(),
                chain: vec![enc],
                context: EncodingContext::UrlParameter,
                depth: 1,
            });
        }

        for depth in 2..=limit {
            let prev: Vec<EncodedResult> = results
                .iter()
                .filter(|r| r.depth == depth - 1)
                .cloned()
                .collect();

            for prev_result in &prev {
                for &enc in encodings {
                    if prev_result.chain.last() == Some(&enc) {
                        continue;
                    }
                    let encoded = apply_encoding(&prev_result.payload, enc);
                    let mut chain = prev_result.chain.clone();
                    chain.push(enc);
                    results.push(EncodedResult {
                        payload: encoded,
                        original: payload.to_string(),
                        chain,
                        context: EncodingContext::UrlParameter,
                        depth,
                    });
                }
            }
        }

        results
    }

    /// Applicable encodings for a context.
    pub fn encodings_for_context(&self, context: EncodingContext) -> Vec<EncodingType> {
        self.context_map.get(&context).cloned().unwrap_or_default()
    }

    pub fn supported_encoding_count(&self) -> usize {
        14
    }
}

impl Default for EncodingLadderV2 {
    fn default() -> Self {
        Self::new()
    }
}

fn build_context_map() -> HashMap<EncodingContext, Vec<EncodingType>> {
    let mut map = HashMap::new();

    map.insert(
        EncodingContext::UrlParameter,
        vec![
            EncodingType::Url,
            EncodingType::DoubleUrl,
            EncodingType::Unicode,
            EncodingType::OverlongUtf8,
            EncodingType::Hex,
            EncodingType::Octal,
            EncodingType::Base64,
        ],
    );

    map.insert(
        EncodingContext::HtmlBody,
        vec![
            EncodingType::HtmlEntity,
            EncodingType::HtmlEntityHex,
            EncodingType::DecimalEntity,
            EncodingType::Unicode,
            EncodingType::Base64,
        ],
    );

    map.insert(
        EncodingContext::HtmlAttribute,
        vec![
            EncodingType::HtmlEntity,
            EncodingType::HtmlEntityHex,
            EncodingType::DecimalEntity,
            EncodingType::Url,
            EncodingType::DoubleUrl,
        ],
    );

    map.insert(
        EncodingContext::JavaScriptString,
        vec![
            EncodingType::JsUnicode,
            EncodingType::JsOctal,
            EncodingType::Unicode,
            EncodingType::Hex,
            EncodingType::Base64,
        ],
    );

    map.insert(
        EncodingContext::CssValue,
        vec![
            EncodingType::CssEscape,
            EncodingType::Unicode,
            EncodingType::Hex,
        ],
    );

    map.insert(
        EncodingContext::XmlContent,
        vec![
            EncodingType::XmlEntity,
            EncodingType::HtmlEntity,
            EncodingType::DecimalEntity,
            EncodingType::Unicode,
        ],
    );

    map.insert(
        EncodingContext::JsonValue,
        vec![
            EncodingType::Unicode,
            EncodingType::JsUnicode,
            EncodingType::Hex,
            EncodingType::Base64,
        ],
    );

    map.insert(
        EncodingContext::HttpHeader,
        vec![EncodingType::Url, EncodingType::Base64, EncodingType::Hex],
    );

    map
}

fn apply_encoding(payload: &str, encoding: EncodingType) -> String {
    match encoding {
        EncodingType::Url => url_encode(payload),
        EncodingType::DoubleUrl => url_encode(&url_encode(payload)),
        EncodingType::Unicode => unicode_encode(payload),
        EncodingType::OverlongUtf8 => overlong_utf8_encode(payload),
        EncodingType::HtmlEntity => html_entity_encode(payload),
        EncodingType::HtmlEntityHex => html_entity_hex_encode(payload),
        EncodingType::Base64 => base64_encode(payload),
        EncodingType::Hex => hex_encode(payload),
        EncodingType::Octal => octal_encode(payload),
        EncodingType::JsUnicode => js_unicode_encode(payload),
        EncodingType::JsOctal => js_octal_encode(payload),
        EncodingType::CssEscape => css_escape_encode(payload),
        EncodingType::XmlEntity => xml_entity_encode(payload),
        EncodingType::DecimalEntity => decimal_entity_encode(payload),
    }
}

fn url_encode(s: &str) -> String {
    let mut encoded = String::with_capacity(s.len() * 3);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
}

fn unicode_encode(s: &str) -> String {
    s.chars().map(|c| format!("\\u{:04x}", c as u32)).collect()
}

fn overlong_utf8_encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b < 0x80 {
                format!("%{:02X}%{:02X}", 0xC0 | (b >> 6), 0x80 | (b & 0x3F))
            } else {
                format!("%{:02X}", b)
            }
        })
        .collect()
}

fn html_entity_encode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '&' => "&amp;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            _ => format!("&#{};", c as u32),
        })
        .collect()
}

fn html_entity_hex_encode(s: &str) -> String {
    s.chars().map(|c| format!("&#x{:x};", c as u32)).collect()
}

fn base64_encode(s: &str) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = s.as_bytes();
    let mut result = String::new();
    let chunks = bytes.chunks(3);
    for chunk in chunks {
        let mut buf = [0u8; 3];
        for (i, &b) in chunk.iter().enumerate() {
            buf[i] = b;
        }
        let n = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);
        result.push(CHARS[((n >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((n >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(n & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

fn hex_encode(s: &str) -> String {
    s.bytes()
        .map(|b| format!("0x{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

fn octal_encode(s: &str) -> String {
    s.bytes().map(|b| format!("\\{:03o}", b)).collect()
}

fn js_unicode_encode(s: &str) -> String {
    s.chars().map(|c| format!("\\u{:04x}", c as u32)).collect()
}

fn js_octal_encode(s: &str) -> String {
    s.bytes().map(|b| format!("\\{:o}", b)).collect()
}

fn css_escape_encode(s: &str) -> String {
    s.chars().map(|c| format!("\\{:06x}", c as u32)).collect()
}

fn xml_entity_encode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '&' => "&amp;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&apos;".to_string(),
            _ => format!("&#{};", c as u32),
        })
        .collect()
}

fn decimal_entity_encode(s: &str) -> String {
    s.chars().map(|c| format!("&#{};", c as u32)).collect()
}
