use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use sha2::{Digest, Sha256};

/// Source of raw payloads before processing and encoding.
#[derive(Debug, Clone)]
pub enum PayloadSource {
    SimpleList(Vec<String>),
    FromFile(std::path::PathBuf),
    NumberRange {
        start: i64,
        end: i64,
        step: i64,
    },
    BruteForce {
        charset: String,
        min_length: usize,
        max_length: usize,
    },
    NullPayloads(usize),
}

/// Transformation applied to each payload after generation.
#[derive(Debug, Clone)]
pub enum PayloadProcessor {
    AddPrefix(String),
    AddSuffix(String),
    RegexReplace {
        pattern: String,
        replacement: String,
    },
    Substring {
        start: usize,
        length: Option<usize>,
    },
    ChangeCase(CaseMode),
    Reverse,
    SkipIf(String),
    MatchOnly(String),
}

/// Case transformation direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseMode {
    Lower,
    Upper,
}

/// Encoding applied to each payload after processing.
#[derive(Debug, Clone)]
pub enum PayloadEncoding {
    None,
    UrlEncode,
    DoubleUrlEncode,
    HtmlEncode,
    Base64Encode,
    Base64Decode,
    Hex,
    Sha256,
    Chain(Vec<PayloadEncoding>),
}

/// Full payload generation pipeline: source, processors, encoding.
#[derive(Debug, Clone)]
pub struct PayloadPipeline {
    pub source: PayloadSource,
    pub processors: Vec<PayloadProcessor>,
    pub encoding: PayloadEncoding,
}

/// Errors from payload generation, processing, or encoding.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PayloadError {
    #[error("file read error: {0}")]
    FileRead(String),
    #[error("invalid regex: {0}")]
    InvalidRegex(String),
    #[error("invalid base64: {0}")]
    InvalidBase64(String),
}

impl PayloadSource {
    /// Generate raw payloads from this source.
    pub fn generate(&self) -> Result<Vec<String>, PayloadError> {
        match self {
            PayloadSource::SimpleList(items) => Ok(items.clone()),
            PayloadSource::FromFile(path) => read_lines_from_file(path),
            PayloadSource::NumberRange { start, end, step } => {
                Ok(generate_number_range(*start, *end, *step))
            }
            PayloadSource::BruteForce {
                charset,
                min_length,
                max_length,
            } => Ok(generate_brute_force(charset, *min_length, *max_length)),
            PayloadSource::NullPayloads(count) => Ok(vec![String::new(); *count]),
        }
    }
}

fn read_lines_from_file(path: &std::path::Path) -> Result<Vec<String>, PayloadError> {
    let content =
        std::fs::read_to_string(path).map_err(|e| PayloadError::FileRead(e.to_string()))?;
    Ok(content.lines().map(String::from).collect())
}

fn generate_number_range(start: i64, end: i64, step: i64) -> Vec<String> {
    let mut results = Vec::new();
    let mut current = start;
    while current <= end {
        results.push(current.to_string());
        current += step;
    }
    results
}

fn generate_brute_force(charset: &str, min_length: usize, max_length: usize) -> Vec<String> {
    let chars: Vec<char> = charset.chars().collect();
    let mut results = Vec::new();
    for length in min_length..=max_length {
        generate_combinations_recursive(&chars, length, &mut String::new(), &mut results);
    }
    results
}

fn generate_combinations_recursive(
    chars: &[char],
    remaining: usize,
    current: &mut String,
    results: &mut Vec<String>,
) {
    if remaining == 0 {
        results.push(current.clone());
        return;
    }
    for &ch in chars {
        current.push(ch);
        generate_combinations_recursive(chars, remaining - 1, current, results);
        current.pop();
    }
}

impl PayloadProcessor {
    /// Transform one payload. Returns `None` when filtered out by `SkipIf`/`MatchOnly`.
    pub fn apply(&self, input: &str) -> Result<Option<String>, PayloadError> {
        match self {
            PayloadProcessor::AddPrefix(prefix) => Ok(Some(format!("{prefix}{input}"))),
            PayloadProcessor::AddSuffix(suffix) => Ok(Some(format!("{input}{suffix}"))),
            PayloadProcessor::RegexReplace {
                pattern,
                replacement,
            } => apply_regex_replace(input, pattern, replacement),
            PayloadProcessor::Substring { start, length } => {
                Ok(Some(apply_substring(input, *start, *length)))
            }
            PayloadProcessor::ChangeCase(CaseMode::Upper) => Ok(Some(input.to_uppercase())),
            PayloadProcessor::ChangeCase(CaseMode::Lower) => Ok(Some(input.to_lowercase())),
            PayloadProcessor::Reverse => Ok(Some(input.chars().rev().collect())),
            PayloadProcessor::SkipIf(pattern) => {
                if input.contains(pattern.as_str()) {
                    Ok(None)
                } else {
                    Ok(Some(input.to_owned()))
                }
            }
            PayloadProcessor::MatchOnly(pattern) => {
                if input.contains(pattern.as_str()) {
                    Ok(Some(input.to_owned()))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

fn apply_regex_replace(
    input: &str,
    pattern: &str,
    replacement: &str,
) -> Result<Option<String>, PayloadError> {
    let re = regex::Regex::new(pattern).map_err(|e| PayloadError::InvalidRegex(e.to_string()))?;
    Ok(Some(re.replace_all(input, replacement).into_owned()))
}

fn apply_substring(input: &str, start: usize, length: Option<usize>) -> String {
    let chars: Vec<char> = input.chars().collect();
    match length {
        Some(len) => chars.iter().skip(start).take(len).collect(),
        None => chars.iter().skip(start).collect(),
    }
}

impl PayloadEncoding {
    /// Encode one payload.
    pub fn encode(&self, input: &str) -> Result<String, PayloadError> {
        match self {
            PayloadEncoding::None => Ok(input.to_owned()),
            PayloadEncoding::UrlEncode => Ok(url_encode(input)),
            PayloadEncoding::DoubleUrlEncode => Ok(url_encode(&url_encode(input))),
            PayloadEncoding::HtmlEncode => Ok(html_encode(input)),
            PayloadEncoding::Base64Encode => Ok(BASE64_STANDARD.encode(input.as_bytes())),
            PayloadEncoding::Base64Decode => decode_base64(input),
            PayloadEncoding::Hex => Ok(hex_encode(input)),
            PayloadEncoding::Sha256 => Ok(sha256_hash(input)),
            PayloadEncoding::Chain(encodings) => apply_chain(input, encodings),
        }
    }
}

fn url_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn html_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '<' => encoded.push_str("&lt;"),
            '>' => encoded.push_str("&gt;"),
            '&' => encoded.push_str("&amp;"),
            '"' => encoded.push_str("&quot;"),
            '\'' => encoded.push_str("&#x27;"),
            _ => encoded.push(ch),
        }
    }
    encoded
}

fn decode_base64(input: &str) -> Result<String, PayloadError> {
    let bytes = BASE64_STANDARD
        .decode(input)
        .map_err(|e| PayloadError::InvalidBase64(e.to_string()))?;
    String::from_utf8(bytes).map_err(|e| PayloadError::InvalidBase64(e.to_string()))
}

fn hex_encode(input: &str) -> String {
    input
        .bytes()
        .fold(String::with_capacity(input.len() * 2), |mut acc, b| {
            acc.push_str(&format!("{b:02X}"));
            acc
        })
}

fn sha256_hash(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    result.iter().fold(String::with_capacity(64), |mut acc, b| {
        acc.push_str(&format!("{b:02x}"));
        acc
    })
}

fn apply_chain(input: &str, encodings: &[PayloadEncoding]) -> Result<String, PayloadError> {
    let mut current = input.to_owned();
    for encoding in encodings {
        current = encoding.encode(&current)?;
    }
    Ok(current)
}

impl PayloadPipeline {
    /// Run the full pipeline: source -> processors -> encoding.
    pub fn generate(&self) -> Result<Vec<String>, PayloadError> {
        let raw = self.source.generate()?;
        let mut results = Vec::new();
        for payload in &raw {
            if let Some(processed) = apply_processors(payload, &self.processors)? {
                results.push(self.encoding.encode(&processed)?);
            }
        }
        Ok(results)
    }
}

fn apply_processors(
    input: &str,
    processors: &[PayloadProcessor],
) -> Result<Option<String>, PayloadError> {
    let mut current = input.to_owned();
    for processor in processors {
        match processor.apply(&current)? {
            Some(next) => current = next,
            None => return Ok(None),
        }
    }
    Ok(Some(current))
}

#[cfg(test)]
#[path = "payload_test.rs"]
mod payload_test;
