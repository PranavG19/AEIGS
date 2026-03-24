use std::fmt;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// A taint source — where untrusted data enters JavaScript execution.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaintSource {
    LocationHash,
    LocationSearch,
    LocationHref,
    DocumentReferrer,
    DocumentCookie,
    PostMessage,
    WindowName,
    UrlSearchParams,
}

impl fmt::Display for TaintSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::LocationHash => "location.hash",
            Self::LocationSearch => "location.search",
            Self::LocationHref => "location.href",
            Self::DocumentReferrer => "document.referrer",
            Self::DocumentCookie => "document.cookie",
            Self::PostMessage => "postMessage event.data",
            Self::WindowName => "window.name",
            Self::UrlSearchParams => "URLSearchParams",
        };
        write!(f, "{label}")
    }
}

/// A taint sink — where untrusted data can cause DOM XSS.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaintSink {
    InnerHtml,
    OuterHtml,
    Eval,
    DocumentWrite,
    DocumentWriteln,
    JQueryHtml,
    JQueryAppend,
    SetTimeout,
    SetInterval,
    FetchUrl,
    ScriptSrc,
    LocationAssign,
    LocationReplace,
    WindowOpen,
}

impl fmt::Display for TaintSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::InnerHtml => "innerHTML",
            Self::OuterHtml => "outerHTML",
            Self::Eval => "eval()",
            Self::DocumentWrite => "document.write()",
            Self::DocumentWriteln => "document.writeln()",
            Self::JQueryHtml => "$.html()",
            Self::JQueryAppend => "$.append()",
            Self::SetTimeout => "setTimeout()",
            Self::SetInterval => "setInterval()",
            Self::FetchUrl => "fetch() URL",
            Self::ScriptSrc => "script.src",
            Self::LocationAssign => "location.assign()",
            Self::LocationReplace => "location.replace()",
            Self::WindowOpen => "window.open()",
        };
        write!(f, "{label}")
    }
}

/// A detected taint flow from a source through intermediate variables to a sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintFlow {
    pub source: TaintSource,
    pub sink: TaintSink,
    /// Variable names that propagate the taint from source to sink.
    pub propagation_chain: Vec<String>,
    /// The source line (1-indexed) where the sink usage was found.
    pub sink_line: usize,
    /// The source line (1-indexed) where the source was read.
    pub source_line: usize,
}

impl fmt::Display for TaintFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Taint: {} (line {}) → {} → {} (line {})",
            self.source,
            self.source_line,
            self.propagation_chain.join(" → "),
            self.sink,
            self.sink_line,
        )
    }
}

/// Result of analyzing a JavaScript snippet for taint flows.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaintAnalysisResult {
    pub flows: Vec<TaintFlow>,
    pub sources_found: Vec<(TaintSource, usize)>,
    pub sinks_found: Vec<(TaintSink, usize)>,
}

impl TaintAnalysisResult {
    pub fn has_flows(&self) -> bool {
        !self.flows.is_empty()
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
}

/// Intermediate representation of a tainted variable assignment.
#[derive(Debug, Clone)]
struct TaintedVar {
    name: String,
    source: TaintSource,
    source_line: usize,
    /// Chain of variable names leading from source to this var.
    chain: Vec<String>,
}

/// Analyze JavaScript source for DOM XSS taint flows.
///
/// Performs regex-based static analysis:
/// 1. Scans for taint sources (user-controlled inputs)
/// 2. Tracks variable assignments that propagate tainted data
/// 3. Detects when tainted data reaches a dangerous sink
pub fn analyze_js_taint(js_source: &str) -> TaintAnalysisResult {
    let mut result = TaintAnalysisResult::default();
    let lines: Vec<&str> = js_source.lines().collect();

    let source_hits = find_sources(&lines);
    let sink_hits = find_sinks(&lines);

    for (src, line_num) in &source_hits {
        result.sources_found.push((src.clone(), *line_num));
    }
    for (sink, line_num) in &sink_hits {
        result.sinks_found.push((sink.clone(), *line_num));
    }

    let tainted_vars = trace_tainted_variables(&lines, &source_hits);

    for (sink, sink_line) in &sink_hits {
        let sink_text = lines[sink_line - 1];

        // Check if a source is used directly in the sink line.
        for (src, src_line) in &source_hits {
            if contains_source_pattern(sink_text, src) {
                result.flows.push(TaintFlow {
                    source: src.clone(),
                    sink: sink.clone(),
                    propagation_chain: vec!["(direct)".to_string()],
                    sink_line: *sink_line,
                    source_line: *src_line,
                });
            }
        }

        // Check if any tainted variable is used in the sink line.
        for tvar in &tainted_vars {
            if var_used_in_line(sink_text, &tvar.name) {
                let already_found = result.flows.iter().any(|f| {
                    f.source == tvar.source
                        && *sink == f.sink
                        && f.sink_line == *sink_line
                        && f.propagation_chain == tvar.chain
                });
                if !already_found {
                    result.flows.push(TaintFlow {
                        source: tvar.source.clone(),
                        sink: sink.clone(),
                        propagation_chain: tvar.chain.clone(),
                        sink_line: *sink_line,
                        source_line: tvar.source_line,
                    });
                }
            }
        }
    }

    result
}

/// Locate taint sources in the JS lines. Returns (source_type, 1-indexed line number).
fn find_sources(lines: &[&str]) -> Vec<(TaintSource, usize)> {
    let mut hits = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let ln = i + 1;
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }

        if line.contains("location.hash") {
            hits.push((TaintSource::LocationHash, ln));
        }
        if line.contains("location.search") {
            hits.push((TaintSource::LocationSearch, ln));
        }
        if contains_location_href_source(line) {
            hits.push((TaintSource::LocationHref, ln));
        }
        if line.contains("document.referrer") {
            hits.push((TaintSource::DocumentReferrer, ln));
        }
        if line.contains("document.cookie") && !is_cookie_sink_only(line) {
            hits.push((TaintSource::DocumentCookie, ln));
        }
        if (line.contains("event.data")
            || line.contains("addEventListener") && line.contains("message"))
            && (line.contains("event.data") || line.contains(".data"))
        {
            hits.push((TaintSource::PostMessage, ln));
        }
        if line.contains("window.name") {
            hits.push((TaintSource::WindowName, ln));
        }
        if line.contains("URLSearchParams") || line.contains("searchParams") {
            hits.push((TaintSource::UrlSearchParams, ln));
        }
    }
    hits
}

/// Check if a `location.href` usage reads the value (source) vs assigns to it (sink).
fn contains_location_href_source(line: &str) -> bool {
    if !line.contains("location.href") {
        return false;
    }
    // If it appears on the right-hand side of an assignment, it is a source.
    // If it IS the assignment target, it is a sink (handled separately).
    let re = Regex::new(r"location\.href\s*=").unwrap();
    if re.is_match(line) {
        // Could be both — `location.href = location.href + ...` — still has a source read.
        let parts: Vec<&str> = line.splitn(2, '=').collect();
        if parts.len() == 2 && parts[1].contains("location.href") {
            return true;
        }
        return false;
    }
    true
}

/// Distinguish `document.cookie = x` (write-only) from reading document.cookie as source.
fn is_cookie_sink_only(line: &str) -> bool {
    let re = Regex::new(r"document\.cookie\s*=").unwrap();
    if re.is_match(line) {
        let parts: Vec<&str> = line.splitn(2, '=').collect();
        return parts.len() < 2 || !parts[1].contains("document.cookie");
    }
    false
}

/// Locate taint sinks in the JS lines. Returns (sink_type, 1-indexed line number).
fn find_sinks(lines: &[&str]) -> Vec<(TaintSink, usize)> {
    let mut hits = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let ln = i + 1;
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }

        if contains_inner_html_sink(line) {
            hits.push((TaintSink::InnerHtml, ln));
        }
        if contains_outer_html_sink(line) {
            hits.push((TaintSink::OuterHtml, ln));
        }
        if contains_eval_sink(line) {
            hits.push((TaintSink::Eval, ln));
        }
        if line.contains("document.write(") {
            hits.push((TaintSink::DocumentWrite, ln));
        }
        if line.contains("document.writeln(") {
            hits.push((TaintSink::DocumentWriteln, ln));
        }
        if contains_jquery_html_sink(line) {
            hits.push((TaintSink::JQueryHtml, ln));
        }
        if contains_jquery_append_sink(line) {
            hits.push((TaintSink::JQueryAppend, ln));
        }
        if contains_set_timeout_sink(line) {
            hits.push((TaintSink::SetTimeout, ln));
        }
        if contains_set_interval_sink(line) {
            hits.push((TaintSink::SetInterval, ln));
        }
        if contains_fetch_url_sink(line) {
            hits.push((TaintSink::FetchUrl, ln));
        }
        if contains_script_src_sink(line) {
            hits.push((TaintSink::ScriptSrc, ln));
        }
        if line.contains("location.assign(") {
            hits.push((TaintSink::LocationAssign, ln));
        }
        if line.contains("location.replace(") {
            hits.push((TaintSink::LocationReplace, ln));
        }
        if line.contains("window.open(") {
            hits.push((TaintSink::WindowOpen, ln));
        }
    }
    hits
}

fn contains_inner_html_sink(line: &str) -> bool {
    let re = Regex::new(r"\.innerHTML\s*[\+]?=").unwrap();
    re.is_match(line)
}

fn contains_outer_html_sink(line: &str) -> bool {
    let re = Regex::new(r"\.outerHTML\s*[\+]?=").unwrap();
    re.is_match(line)
}

fn contains_eval_sink(line: &str) -> bool {
    line.contains("eval(") && !line.contains("// eval")
}

fn contains_jquery_html_sink(line: &str) -> bool {
    let re = Regex::new(r"\.\s*html\s*\(").unwrap();
    re.is_match(line) && (line.contains('$') || line.contains("jQuery"))
}

fn contains_jquery_append_sink(line: &str) -> bool {
    let re = Regex::new(r"\.\s*append\s*\(").unwrap();
    re.is_match(line) && (line.contains('$') || line.contains("jQuery"))
}

fn contains_set_timeout_sink(line: &str) -> bool {
    if !line.contains("setTimeout(") {
        return false;
    }
    // Only a sink when first arg is a string (code execution), not a function ref.
    let re = Regex::new(r#"setTimeout\s*\(\s*[^"'f\s]"#).unwrap();
    // Heuristic: if there is a variable as the first arg, it might be string code injection.
    let re2 = Regex::new(r"setTimeout\s*\(\s*[a-zA-Z_$]").unwrap();
    re.is_match(line) || re2.is_match(line)
}

fn contains_set_interval_sink(line: &str) -> bool {
    if !line.contains("setInterval(") {
        return false;
    }
    let re = Regex::new(r"setInterval\s*\(\s*[a-zA-Z_$]").unwrap();
    re.is_match(line)
}

fn contains_fetch_url_sink(line: &str) -> bool {
    let re = Regex::new(r"fetch\s*\(").unwrap();
    re.is_match(line)
}

fn contains_script_src_sink(line: &str) -> bool {
    let re = Regex::new(r"\.src\s*=").unwrap();
    re.is_match(line)
}

/// Trace variable assignments that carry taint from sources.
///
/// Handles patterns like:
///   `var x = location.hash;`
///   `let y = x.substring(1);`
///   `const z = y + "foo";`
fn trace_tainted_variables(
    lines: &[&str],
    source_hits: &[(TaintSource, usize)],
) -> Vec<TaintedVar> {
    let mut tainted: Vec<TaintedVar> = Vec::new();

    let assign_re =
        Regex::new(r"(?:var|let|const|)\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*[\+]?=\s*(.+)").unwrap();

    for (i, line) in lines.iter().enumerate() {
        let ln = i + 1;
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }

        if let Some(caps) = assign_re.captures(trimmed) {
            let var_name = caps.get(1).unwrap().as_str().to_string();
            let rhs = caps.get(2).unwrap().as_str();

            // Direct source on RHS.
            for (src, src_line) in source_hits {
                if contains_source_pattern(rhs, src) {
                    tainted.push(TaintedVar {
                        name: var_name.clone(),
                        source: src.clone(),
                        source_line: *src_line,
                        chain: vec![var_name.clone()],
                    });
                }
            }

            // Propagation: RHS uses an already-tainted variable.
            let propagated: Vec<TaintedVar> = tainted
                .iter()
                .filter(|tv| var_used_in_expr(rhs, &tv.name))
                .map(|tv| {
                    let mut chain = tv.chain.clone();
                    chain.push(var_name.clone());
                    TaintedVar {
                        name: var_name.clone(),
                        source: tv.source.clone(),
                        source_line: tv.source_line,
                        chain,
                    }
                })
                .collect();

            tainted.extend(propagated);
        }

        // Handle function parameter propagation:
        // `function foo(e) { ... e.data ... }`
        if let Some(param_tainted) = check_function_param_taint(trimmed, ln, source_hits) {
            tainted.extend(param_tainted);
        }
    }

    tainted
}

/// Check if a function parameter carries taint (e.g., message event handler).
fn check_function_param_taint(
    line: &str,
    _line_num: usize,
    source_hits: &[(TaintSource, usize)],
) -> Option<Vec<TaintedVar>> {
    // Pattern: `function(e) {` or `(e) => {` where e.data is used later.
    let re = Regex::new(r"function\s*\w*\s*\((\w+)\)").unwrap();
    let re_arrow = Regex::new(r"\((\w+)\)\s*=>").unwrap();

    let param = re
        .captures(line)
        .or_else(|| re_arrow.captures(line))
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string());

    if let Some(p) = param
        && (line.contains("message") || line.contains("Message"))
    {
        let vars: Vec<TaintedVar> = source_hits
            .iter()
            .filter(|(src, _)| matches!(src, TaintSource::PostMessage))
            .map(|(src, sl)| TaintedVar {
                name: format!("{p}.data"),
                source: src.clone(),
                source_line: *sl,
                chain: vec![format!("{p}.data")],
            })
            .collect();
        if !vars.is_empty() {
            return Some(vars);
        }
    }
    None
}

/// Check whether `line` contains a source pattern.
fn contains_source_pattern(text: &str, source: &TaintSource) -> bool {
    match source {
        TaintSource::LocationHash => text.contains("location.hash"),
        TaintSource::LocationSearch => text.contains("location.search"),
        TaintSource::LocationHref => text.contains("location.href"),
        TaintSource::DocumentReferrer => text.contains("document.referrer"),
        TaintSource::DocumentCookie => text.contains("document.cookie"),
        TaintSource::PostMessage => text.contains("event.data") || text.contains(".data"),
        TaintSource::WindowName => text.contains("window.name"),
        TaintSource::UrlSearchParams => {
            text.contains("URLSearchParams") || text.contains("searchParams")
        }
    }
}

/// Check if a variable name is used (non-assignment) in a code line.
fn var_used_in_line(line: &str, var_name: &str) -> bool {
    is_identifier_present(line, var_name, false)
}

/// Check if a variable name appears in an expression (RHS of assignment).
fn var_used_in_expr(expr: &str, var_name: &str) -> bool {
    is_identifier_present(expr, var_name, true)
}

/// Search for an identifier in text with JS-aware boundary checking.
///
/// When `allow_dot_suffix` is true, a match like `foo.bar` still counts for `foo`.
/// Handles dotted names like `event.data` by matching the full token.
fn is_identifier_present(text: &str, name: &str, allow_dot_suffix: bool) -> bool {
    let escaped = regex::escape(name);
    let pattern = if allow_dot_suffix {
        format!(r"(^|[^a-zA-Z0-9_$.]){}", escaped)
    } else {
        format!(r"(^|[^a-zA-Z0-9_$.]){}($|[^a-zA-Z0-9_$])", escaped)
    };
    let Ok(re) = Regex::new(&pattern) else {
        return text.contains(name);
    };
    re.is_match(text)
}

#[cfg(test)]
#[path = "js_taint_analyzer_test.rs"]
mod js_taint_analyzer_test;
