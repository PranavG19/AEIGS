use serde::{Deserialize, Serialize};

/// A parsed vulnerability hypothesis from the LLM brain.
///
/// Maps to the JSON schema defined in the AEGIS-MIND system prompt:
/// endpoint, vulnerability class, reasoning, payloads, confidence, priority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedHypothesis {
    pub endpoint: String,
    pub vulnerability_class: String,
    pub reasoning: String,
    #[serde(default)]
    pub suggested_payloads: Vec<String>,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    #[serde(default = "default_priority")]
    pub priority: u32,
}

fn default_confidence() -> f64 {
    0.5
}

fn default_priority() -> u32 {
    3
}

/// A parsed next action from the LLM brain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedAction {
    pub action_type: String,
    pub target: String,
    #[serde(default)]
    pub parameters: serde_json::Value,
    #[serde(default)]
    pub rationale: String,
}

/// A parsed reasoning trace from the LLM brain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedReasoning {
    pub summary: String,
    #[serde(default)]
    pub observations: Vec<String>,
    #[serde(default)]
    pub attack_graph_notes: Vec<String>,
}

/// The complete parsed response from the LLM brain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedResponse {
    pub hypotheses: Vec<ParsedHypothesis>,
    pub actions: Vec<ParsedAction>,
    pub reasoning: ParsedReasoning,
    pub raw_text: String,
    pub parse_method: ParseMethod,
    pub tokens_used: Option<u64>,
}

/// How the response was parsed — indicates confidence in parse quality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParseMethod {
    DirectJson,
    JsonCodeFence,
    PartialJsonExtraction,
    MultiBlockMerge,
    TextFallback,
}

impl std::fmt::Display for ParseMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirectJson => write!(f, "direct_json"),
            Self::JsonCodeFence => write!(f, "json_code_fence"),
            Self::PartialJsonExtraction => write!(f, "partial_json_extraction"),
            Self::MultiBlockMerge => write!(f, "multi_block_merge"),
            Self::TextFallback => write!(f, "text_fallback"),
        }
    }
}

/// Errors specific to response parsing (non-fatal — we always produce a result).
#[derive(Debug, Clone)]
pub struct ParseWarning {
    pub message: String,
    pub field: Option<String>,
}

/// Result of parsing with optional warnings about degraded quality.
#[derive(Debug, Clone)]
pub struct ParseResult {
    pub response: ParsedResponse,
    pub warnings: Vec<ParseWarning>,
}

/// Parse a raw LLM response string into structured data.
///
/// Attempts multiple parsing strategies in order of fidelity:
/// 1. Direct JSON parse of entire response
/// 2. Extract JSON from ```json``` code fences
/// 3. Extract multiple JSON blocks and merge them
/// 4. Partial JSON extraction (find hypothesis/action arrays)
/// 5. Text fallback (treat entire response as reasoning summary)
///
/// Always succeeds — worst case returns a TextFallback with the raw text
/// as the reasoning summary and empty hypothesis/action lists.
pub fn parse_llm_response(raw: &str) -> ParseResult {
    let mut warnings = Vec::new();

    if let Some(result) = try_direct_json(raw) {
        return ParseResult {
            response: result,
            warnings,
        };
    }

    if let Some(result) = try_json_code_fence(raw) {
        return ParseResult {
            response: result,
            warnings,
        };
    }

    if let Some(result) = try_multi_block_merge(raw, &mut warnings) {
        return ParseResult {
            response: result,
            warnings,
        };
    }

    if let Some(result) = try_partial_extraction(raw, &mut warnings) {
        return ParseResult {
            response: result,
            warnings,
        };
    }

    warnings.push(ParseWarning {
        message: "could not parse any structured data; falling back to text".to_string(),
        field: None,
    });

    ParseResult {
        response: ParsedResponse {
            hypotheses: Vec::new(),
            actions: Vec::new(),
            reasoning: ParsedReasoning {
                summary: raw.to_string(),
                observations: Vec::new(),
                attack_graph_notes: Vec::new(),
            },
            raw_text: raw.to_string(),
            parse_method: ParseMethod::TextFallback,
            tokens_used: None,
        },
        warnings,
    }
}

/// Extract only hypotheses from a raw response (convenience function).
pub fn extract_hypotheses(raw: &str) -> Vec<ParsedHypothesis> {
    parse_llm_response(raw).response.hypotheses
}

/// Extract only actions from a raw response (convenience function).
pub fn extract_actions(raw: &str) -> Vec<ParsedAction> {
    parse_llm_response(raw).response.actions
}

/// Extract the reasoning summary from a raw response (convenience function).
pub fn extract_reasoning(raw: &str) -> String {
    parse_llm_response(raw).response.reasoning.summary
}

/// Validate a parsed hypothesis for field completeness.
///
/// Returns a list of issues (empty = valid). Used by the feedback loop
/// to filter out malformed hypotheses before testing.
pub fn validate_hypothesis(h: &ParsedHypothesis) -> Vec<String> {
    let mut issues = Vec::new();
    if h.endpoint.is_empty() {
        issues.push("empty endpoint".to_string());
    }
    if h.vulnerability_class.is_empty() {
        issues.push("empty vulnerability_class".to_string());
    }
    if h.confidence < 0.0 || h.confidence > 1.0 {
        issues.push(format!("confidence {} out of [0,1] range", h.confidence));
    }
    if h.priority == 0 || h.priority > 10 {
        issues.push(format!("priority {} out of [1,10] range", h.priority));
    }
    issues
}

/// Validate a parsed action for field completeness.
pub fn validate_action(a: &ParsedAction) -> Vec<String> {
    let mut issues = Vec::new();
    if a.action_type.is_empty() {
        issues.push("empty action_type".to_string());
    }
    if a.target.is_empty() {
        issues.push("empty target".to_string());
    }
    issues
}

/// Clamp hypothesis confidence to [0.0, 1.0] and priority to [1, 5].
pub fn normalize_hypothesis(h: &mut ParsedHypothesis) {
    h.confidence = h.confidence.clamp(0.0, 1.0);
    h.priority = h.priority.clamp(1, 5);
}

fn try_direct_json(raw: &str) -> Option<ParsedResponse> {
    let trimmed = raw.trim();
    let val: serde_json::Value = serde_json::from_str(trimmed).ok()?;
    build_response_from_value(&val, raw, ParseMethod::DirectJson)
}

fn try_json_code_fence(raw: &str) -> Option<ParsedResponse> {
    let block = extract_json_block(raw)?;
    let val: serde_json::Value = serde_json::from_str(&block).ok()?;
    build_response_from_value(&val, raw, ParseMethod::JsonCodeFence)
}

fn try_multi_block_merge(raw: &str, warnings: &mut Vec<ParseWarning>) -> Option<ParsedResponse> {
    let blocks = extract_all_json_blocks(raw);
    if blocks.len() < 2 {
        return None;
    }

    let mut all_hypotheses: Vec<ParsedHypothesis> = Vec::new();
    let mut all_actions: Vec<ParsedAction> = Vec::new();
    let mut summary = String::new();
    let mut tokens: Option<u64> = None;

    for block in &blocks {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(block) {
            if let Some(hyps) = val.get("hypotheses")
                && let Ok(h) = serde_json::from_value::<Vec<ParsedHypothesis>>(hyps.clone()) {
                    all_hypotheses.extend(h);
                }
            if let Some(acts) = val.get("actions")
                && let Ok(a) = serde_json::from_value::<Vec<ParsedAction>>(acts.clone()) {
                    all_actions.extend(a);
                }
            if let Some(rs) = val
                .get("reasoning_summary")
                .or_else(|| val.get("reasoning"))
                .or_else(|| val.get("summary"))
                .and_then(|v| v.as_str())
            {
                if !summary.is_empty() {
                    summary.push(' ');
                }
                summary.push_str(rs);
            }
            if let Some(t) = val.get("tokens_used").and_then(|v| v.as_u64()) {
                tokens = Some(tokens.unwrap_or(0) + t);
            }
        }
    }

    if all_hypotheses.is_empty() && all_actions.is_empty() {
        return None;
    }

    warnings.push(ParseWarning {
        message: format!("merged {} JSON blocks", blocks.len()),
        field: None,
    });

    Some(ParsedResponse {
        hypotheses: all_hypotheses,
        actions: all_actions,
        reasoning: ParsedReasoning {
            summary,
            observations: Vec::new(),
            attack_graph_notes: Vec::new(),
        },
        raw_text: raw.to_string(),
        parse_method: ParseMethod::MultiBlockMerge,
        tokens_used: tokens,
    })
}

fn try_partial_extraction(raw: &str, warnings: &mut Vec<ParseWarning>) -> Option<ParsedResponse> {
    let mut hypotheses = Vec::new();
    let mut actions = Vec::new();
    let mut summary = String::new();

    if let Some(hyp_json) = find_json_array(raw, "hypotheses") {
        match serde_json::from_str::<Vec<ParsedHypothesis>>(&hyp_json) {
            Ok(h) => hypotheses = h,
            Err(e) => {
                warnings.push(ParseWarning {
                    message: format!("partial hypotheses parse failed: {e}"),
                    field: Some("hypotheses".to_string()),
                });
            }
        }
    }

    if let Some(act_json) = find_json_array(raw, "actions") {
        match serde_json::from_str::<Vec<ParsedAction>>(&act_json) {
            Ok(a) => actions = a,
            Err(e) => {
                warnings.push(ParseWarning {
                    message: format!("partial actions parse failed: {e}"),
                    field: Some("actions".to_string()),
                });
            }
        }
    }

    if let Some(rs) = find_json_string(raw, "reasoning_summary")
        .or_else(|| find_json_string(raw, "reasoning"))
    {
        summary = rs;
    }

    if hypotheses.is_empty() && actions.is_empty() {
        return None;
    }

    Some(ParsedResponse {
        hypotheses,
        actions,
        reasoning: ParsedReasoning {
            summary,
            observations: Vec::new(),
            attack_graph_notes: Vec::new(),
        },
        raw_text: raw.to_string(),
        parse_method: ParseMethod::PartialJsonExtraction,
        tokens_used: None,
    })
}

fn build_response_from_value(
    val: &serde_json::Value,
    raw: &str,
    method: ParseMethod,
) -> Option<ParsedResponse> {
    let hypotheses: Vec<ParsedHypothesis> = val
        .get("hypotheses")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let actions: Vec<ParsedAction> = val
        .get("actions")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let summary = val
        .get("reasoning_summary")
        .or_else(|| val.get("reasoning"))
        .or_else(|| val.get("summary"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let observations = val
        .get("observations")
        .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
        .unwrap_or_default();

    let attack_graph_notes = val
        .get("attack_graph_notes")
        .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
        .unwrap_or_default();

    let tokens = val.get("tokens_used").and_then(|v| v.as_u64());

    Some(ParsedResponse {
        hypotheses,
        actions,
        reasoning: ParsedReasoning {
            summary,
            observations,
            attack_graph_notes,
        },
        raw_text: raw.to_string(),
        parse_method: method,
        tokens_used: tokens,
    })
}

fn extract_json_block(text: &str) -> Option<String> {
    let fence_start = text.find("```json")?;
    let content_start = text[fence_start..].find('\n')? + fence_start + 1;
    let fence_end = text[content_start..].find("```")?;
    Some(
        text[content_start..content_start + fence_end]
            .trim()
            .to_string(),
    )
}

fn extract_all_json_blocks(text: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut search_from = 0;

    while let Some(fence_start) = text[search_from..].find("```json") {
        let abs_fence_start = search_from + fence_start;
        let Some(newline_offset) = text[abs_fence_start..].find('\n') else {
            break;
        };
        let content_start = abs_fence_start + newline_offset + 1;
        let Some(fence_end) = text[content_start..].find("```") else {
            break;
        };
        let block = text[content_start..content_start + fence_end].trim();
        if !block.is_empty() {
            blocks.push(block.to_string());
        }
        search_from = content_start + fence_end + 3;
    }

    blocks
}

fn find_json_array(text: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let key_pos = text.find(&pattern)?;
    let after_key = &text[key_pos + pattern.len()..];
    let colon_pos = after_key.find(':')?;
    let after_colon = after_key[colon_pos + 1..].trim_start();

    if !after_colon.starts_with('[') {
        return None;
    }

    let mut depth = 0;
    let mut end_pos = 0;
    for (i, ch) in after_colon.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    end_pos = i + 1;
                    break;
                }
            }
            _ => {}
        }
    }

    if end_pos > 0 {
        Some(after_colon[..end_pos].to_string())
    } else {
        None
    }
}

fn find_json_string(text: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let key_pos = text.find(&pattern)?;
    let after_key = &text[key_pos + pattern.len()..];
    let colon_pos = after_key.find(':')?;
    let after_colon = after_key[colon_pos + 1..].trim_start();

    if !after_colon.starts_with('"') {
        return None;
    }

    let inner = &after_colon[1..];
    let mut end_pos = 0;
    let mut prev_backslash = false;
    for (i, ch) in inner.char_indices() {
        if ch == '"' && !prev_backslash {
            end_pos = i;
            break;
        }
        prev_backslash = ch == '\\';
    }

    if end_pos > 0 {
        Some(inner[..end_pos].to_string())
    } else {
        None
    }
}

#[cfg(test)]
#[path = "llm_response_parser_test.rs"]
mod llm_response_parser_test;
