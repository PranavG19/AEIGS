use aegis_protocol::finding::VulnerabilityClass;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EncodingStrategy {
    DoubleUrlEncoding,
    UnicodeNormalization,
    MixedCase,
    CommentInsertion,
    WhitespaceVariation,
    NullByteInsertion,
    HtmlEntityEncoding,
    ConcatenationSplitting,
}

#[derive(Debug, Clone)]
pub struct EncodedPayload {
    pub encoded: String,
    pub strategy: EncodingStrategy,
    pub original: String,
}

pub struct EncodingTransformer;

impl EncodingTransformer {
    pub fn new() -> Self {
        Self
    }

    pub fn applicable_strategies(&self, class: VulnerabilityClass) -> Vec<EncodingStrategy> {
        ALL_STRATEGY_MAPPINGS
            .iter()
            .filter(|(_, classes)| classes.contains(&class))
            .map(|(strategy, _)| *strategy)
            .collect()
    }

    pub fn encode(&self, payload: &str, class: VulnerabilityClass) -> Vec<EncodedPayload> {
        if payload.is_empty() {
            return Vec::new();
        }

        self.applicable_strategies(class)
            .into_iter()
            .map(|strategy| EncodedPayload {
                encoded: apply_encoding(payload, strategy),
                strategy,
                original: payload.to_string(),
            })
            .collect()
    }
}

impl Default for EncodingTransformer {
    fn default() -> Self {
        Self::new()
    }
}

const INJECTION_CLASSES: &[VulnerabilityClass] = &[
    VulnerabilityClass::SqlInjection,
    VulnerabilityClass::CrossSiteScripting,
    VulnerabilityClass::CommandInjection,
    VulnerabilityClass::PathTraversal,
    VulnerabilityClass::ServerSideRequestForgery,
    VulnerabilityClass::HeaderInjection,
    VulnerabilityClass::OpenRedirect,
    VulnerabilityClass::CrlfInjection,
    VulnerabilityClass::ServerSideTemplateInjection,
    VulnerabilityClass::InsecureDeserialization,
];

const ALL_STRATEGY_MAPPINGS: &[(EncodingStrategy, &[VulnerabilityClass])] = &[
    (EncodingStrategy::DoubleUrlEncoding, INJECTION_CLASSES),
    (
        EncodingStrategy::UnicodeNormalization,
        &[
            VulnerabilityClass::CrossSiteScripting,
            VulnerabilityClass::ServerSideTemplateInjection,
        ],
    ),
    (
        EncodingStrategy::MixedCase,
        &[
            VulnerabilityClass::SqlInjection,
            VulnerabilityClass::CrossSiteScripting,
        ],
    ),
    (
        EncodingStrategy::CommentInsertion,
        &[VulnerabilityClass::SqlInjection],
    ),
    (
        EncodingStrategy::WhitespaceVariation,
        &[
            VulnerabilityClass::SqlInjection,
            VulnerabilityClass::CommandInjection,
        ],
    ),
    (
        EncodingStrategy::NullByteInsertion,
        &[VulnerabilityClass::PathTraversal],
    ),
    (
        EncodingStrategy::HtmlEntityEncoding,
        &[VulnerabilityClass::CrossSiteScripting],
    ),
    (
        EncodingStrategy::ConcatenationSplitting,
        &[VulnerabilityClass::SqlInjection],
    ),
];

fn apply_encoding(payload: &str, strategy: EncodingStrategy) -> String {
    match strategy {
        EncodingStrategy::DoubleUrlEncoding => apply_double_url_encoding(payload),
        EncodingStrategy::UnicodeNormalization => apply_unicode_normalization(payload),
        EncodingStrategy::MixedCase => apply_mixed_case(payload),
        EncodingStrategy::CommentInsertion => apply_comment_insertion(payload),
        EncodingStrategy::WhitespaceVariation => apply_whitespace_variation(payload),
        EncodingStrategy::NullByteInsertion => apply_null_byte_insertion(payload),
        EncodingStrategy::HtmlEntityEncoding => apply_html_entity_encoding(payload),
        EncodingStrategy::ConcatenationSplitting => apply_concatenation_splitting(payload),
    }
}

fn apply_double_url_encoding(payload: &str) -> String {
    payload
        .chars()
        .map(|c| match c {
            '<' => "%253C".to_string(),
            '>' => "%253E".to_string(),
            '\'' => "%2527".to_string(),
            '"' => "%2522".to_string(),
            '&' => "%2526".to_string(),
            ' ' => "%2520".to_string(),
            '/' => "%252F".to_string(),
            '\\' => "%255C".to_string(),
            _ => c.to_string(),
        })
        .collect()
}

fn apply_unicode_normalization(payload: &str) -> String {
    payload
        .chars()
        .map(|c| match c {
            '<' => "\\u003c".to_string(),
            '>' => "\\u003e".to_string(),
            '\'' => "\\u0027".to_string(),
            '"' => "\\u0022".to_string(),
            '&' => "\\u0026".to_string(),
            '/' => "\\u002f".to_string(),
            _ => c.to_string(),
        })
        .collect()
}

fn apply_mixed_case(payload: &str) -> String {
    let mut upper = false;
    payload
        .chars()
        .map(|c| {
            if c.is_alphabetic() {
                let result = if upper {
                    c.to_uppercase().to_string()
                } else {
                    c.to_lowercase().to_string()
                };
                upper = !upper;
                result
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn apply_comment_insertion(payload: &str) -> String {
    let sql_keywords = [
        "SELECT", "UNION", "OR", "AND", "FROM", "WHERE", "DROP", "INSERT",
    ];
    let mut result = payload.to_string();
    for keyword in &sql_keywords {
        let upper = *keyword;
        let lower = keyword.to_lowercase();
        result = result.replace(&format!("{upper} "), &format!("{upper}/**/ "));
        if upper != lower {
            result = result.replace(&format!("{lower} "), &format!("{lower}/**/ "));
        }
    }
    result
}

fn apply_whitespace_variation(payload: &str) -> String {
    payload.replace(' ', "\t")
}

fn apply_null_byte_insertion(payload: &str) -> String {
    format!("{payload}%00")
}

fn apply_html_entity_encoding(payload: &str) -> String {
    payload
        .chars()
        .map(|c| match c {
            '<' => "&#60;".to_string(),
            '>' => "&#62;".to_string(),
            '\'' => "&#39;".to_string(),
            '"' => "&#34;".to_string(),
            '&' => "&#38;".to_string(),
            _ => c.to_string(),
        })
        .collect()
}

fn apply_concatenation_splitting(payload: &str) -> String {
    if payload.len() < 2 {
        return format!("CONCAT('{payload}')");
    }
    let mid = payload.len() / 2;
    let left = &payload[..mid];
    let right = &payload[mid..];
    format!("CONCAT('{left}','{right}')")
}

#[cfg(test)]
#[path = "encoding_transformer_test.rs"]
mod encoding_transformer_test;
