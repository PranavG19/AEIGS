use regex::Regex;

/// Where to apply a grep pattern within an HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchTarget {
    Body,
    Headers,
    Both,
}

/// A match rule: returns the pattern string when it matches (or doesn't, if negated).
#[derive(Debug, Clone)]
pub struct GrepMatch {
    pub pattern: String,
    pub search_in: SearchTarget,
    pub negate: bool,
}

/// An extraction rule: returns the captured group value from a regex match.
#[derive(Debug, Clone)]
pub struct GrepExtract {
    pub pattern: String,
    pub group: usize,
    pub search_in: SearchTarget,
}

/// Errors produced by grep operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum GrepError {
    #[error("invalid regex pattern: {0}")]
    InvalidPattern(String),
}

fn compile_regex(pattern: &str) -> Result<Regex, GrepError> {
    Regex::new(pattern).map_err(|e| GrepError::InvalidPattern(e.to_string()))
}

fn serialize_headers(headers: &[(String, String)]) -> String {
    let mut out = String::new();
    for (name, value) in headers {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push('\n');
    }
    out
}

fn regex_matches_text(re: &Regex, text: &str) -> bool {
    re.is_match(text)
}

/// Apply grep match rules against an HTTP response.
///
/// Returns the pattern strings of all rules that triggered. For normal rules,
/// the pattern is included when it matches. For negated rules, the pattern is
/// included when it does NOT match.
pub fn apply_grep_matches(
    matchers: &[GrepMatch],
    _status: u16,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<Vec<String>, GrepError> {
    let body_text = String::from_utf8_lossy(body);
    let header_text = serialize_headers(headers);
    let mut results = Vec::new();

    for matcher in matchers {
        let re = compile_regex(&matcher.pattern)?;
        let matched = match matcher.search_in {
            SearchTarget::Body => regex_matches_text(&re, &body_text),
            SearchTarget::Headers => regex_matches_text(&re, &header_text),
            SearchTarget::Both => {
                regex_matches_text(&re, &body_text) || regex_matches_text(&re, &header_text)
            }
        };
        let should_include = if matcher.negate { !matched } else { matched };
        if should_include {
            results.push(matcher.pattern.clone());
        }
    }

    Ok(results)
}

/// Apply grep extraction rules against an HTTP response.
///
/// Returns the captured group values from all rules that match. Rules that
/// do not match are silently skipped.
pub fn apply_grep_extracts(
    extracts: &[GrepExtract],
    headers: &[(String, String)],
    body: &[u8],
) -> Result<Vec<String>, GrepError> {
    let body_text = String::from_utf8_lossy(body);
    let header_text = serialize_headers(headers);
    let mut results = Vec::new();

    for extract in extracts {
        let re = compile_regex(&extract.pattern)?;
        let texts_to_search: Vec<&str> = match extract.search_in {
            SearchTarget::Body => vec![&body_text],
            SearchTarget::Headers => vec![&header_text],
            SearchTarget::Both => vec![&body_text, &header_text],
        };
        for text in texts_to_search {
            if let Some(caps) = re.captures(text)
                && let Some(m) = caps.get(extract.group)
            {
                results.push(m.as_str().to_string());
                break;
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
#[path = "grep_test.rs"]
mod grep_test;
