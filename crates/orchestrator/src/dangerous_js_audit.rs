use std::collections::HashSet;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

const DANGEROUS_PATTERNS: &[(&str, &str, f64)] = &[
    ("eval(", "eval", 6.0),
    ("innerhtml", "innerHTML", 5.0),
    ("document.write(", "document.write", 5.0),
    ("outerhtml", "outerHTML", 4.5),
    ("insertadjacenthtml(", "insertAdjacentHTML", 4.5),
    (".html(", "jQuery.html", 4.0),
    ("dangerouslysetinnerhtml", "dangerouslySetInnerHTML", 4.0),
    ("new function(", "Function_constructor", 5.5),
    ("settimeout(", "setTimeout_string", 3.0),
    ("setinterval(", "setInterval_string", 3.0),
];

#[derive(Debug, Clone)]
pub struct DangerousJsIssue {
    pub pattern: String,
    pub severity: f64,
}

pub fn audit_dangerous_js(target: &str) -> Vec<DangerousJsIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send().and_then(|r| r.text()) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    find_dangerous_js(&body)
}

pub fn find_dangerous_js(html: &str) -> Vec<DangerousJsIssue> {
    let mut issues = Vec::new();
    let lower = html.to_ascii_lowercase();
    let mut search_from = 0;

    while let Some(start) = lower[search_from..].find("<script") {
        let abs_start = search_from + start;
        let Some(tag_end) = lower[abs_start..].find('>') else {
            break;
        };
        let tag_lower = &lower[abs_start..abs_start + tag_end + 1];

        if tag_lower.contains("src=") {
            search_from = abs_start + tag_end + 1;
            continue;
        }

        let script_end = lower[abs_start + tag_end + 1..]
            .find("</script>")
            .map(|e| abs_start + tag_end + 1 + e)
            .unwrap_or(lower.len());

        let script_body = &lower[abs_start + tag_end + 1..script_end];
        search_from = script_end;

        let mut seen = HashSet::new();
        for (pattern, name, severity) in DANGEROUS_PATTERNS {
            if script_body.contains(pattern) && seen.insert(*name) {
                issues.push(DangerousJsIssue {
                    pattern: name.to_string(),
                    severity: *severity,
                });
            }
        }
    }

    issues
}

pub fn dangerous_js_to_operations(
    issues: &[DangerousJsIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let max_severity = issues.iter().map(|i| i.severity).fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::CrossSiteScripting,
        max_severity,
        0.7,
    )]
}

#[derive(Debug, Clone, PartialEq)]
pub enum JsSecurityIssue {
    EvalUsage { context: String },
    InnerHtmlAssignment { context: String },
    DocumentWrite,
    OuterHtmlAssignment,
    InsertAdjacentHtml,
    JQueryHtml,
    DangerouslySetInnerHtml,
    FunctionConstructor,
    SetTimeoutString,
    SetIntervalString,
    PostMessageNoOriginCheck,
    JsonParseUnsafe { context: String },
    DomXssSink { sink: String },
    InlineEventHandler { handler: String },
    UnsafeUrlScheme { scheme: String },
}

impl std::fmt::Display for JsSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JsSecurityIssue::EvalUsage { context } => write!(f, "eval_usage:{}", context),
            JsSecurityIssue::InnerHtmlAssignment { context } => {
                write!(f, "innerhtml_assignment:{}", context)
            }
            JsSecurityIssue::DocumentWrite => write!(f, "document_write"),
            JsSecurityIssue::OuterHtmlAssignment => write!(f, "outerhtml_assignment"),
            JsSecurityIssue::InsertAdjacentHtml => write!(f, "insert_adjacent_html"),
            JsSecurityIssue::JQueryHtml => write!(f, "jquery_html"),
            JsSecurityIssue::DangerouslySetInnerHtml => write!(f, "dangerously_set_inner_html"),
            JsSecurityIssue::FunctionConstructor => write!(f, "function_constructor"),
            JsSecurityIssue::SetTimeoutString => write!(f, "settimeout_string"),
            JsSecurityIssue::SetIntervalString => write!(f, "setinterval_string"),
            JsSecurityIssue::PostMessageNoOriginCheck => write!(f, "postmessage_no_origin_check"),
            JsSecurityIssue::JsonParseUnsafe { context } => {
                write!(f, "json_parse_unsafe:{}", context)
            }
            JsSecurityIssue::DomXssSink { sink } => write!(f, "dom_xss_sink:{}", sink),
            JsSecurityIssue::InlineEventHandler { handler } => {
                write!(f, "inline_event_handler:{}", handler)
            }
            JsSecurityIssue::UnsafeUrlScheme { scheme } => {
                write!(f, "unsafe_url_scheme:{}", scheme)
            }
        }
    }
}

pub fn js_security_severity(issue: &JsSecurityIssue) -> f64 {
    match issue {
        JsSecurityIssue::EvalUsage { .. } => 7.0,
        JsSecurityIssue::FunctionConstructor => 6.5,
        JsSecurityIssue::DocumentWrite => 6.0,
        JsSecurityIssue::InnerHtmlAssignment { .. } => 5.5,
        JsSecurityIssue::OuterHtmlAssignment => 5.0,
        JsSecurityIssue::InsertAdjacentHtml => 5.0,
        JsSecurityIssue::DangerouslySetInnerHtml => 5.0,
        JsSecurityIssue::DomXssSink { .. } => 5.5,
        JsSecurityIssue::PostMessageNoOriginCheck => 5.0,
        JsSecurityIssue::JQueryHtml => 4.5,
        JsSecurityIssue::UnsafeUrlScheme { .. } => 4.5,
        JsSecurityIssue::InlineEventHandler { .. } => 4.0,
        JsSecurityIssue::JsonParseUnsafe { .. } => 3.5,
        JsSecurityIssue::SetTimeoutString => 3.0,
        JsSecurityIssue::SetIntervalString => 3.0,
    }
}

const DOM_XSS_SINKS: &[(&str, &str)] = &[
    ("location.href", "location.href"),
    ("location.assign(", "location.assign"),
    ("location.replace(", "location.replace"),
    ("window.open(", "window.open"),
    ("document.cookie", "document.cookie"),
];

const INLINE_HANDLERS: &[&str] = &[
    "onclick",
    "onerror",
    "onload",
    "onmouseover",
    "onfocus",
    "onblur",
    "onsubmit",
    "onchange",
    "oninput",
];

const UNSAFE_SCHEMES: &[&str] = &["javascript:", "vbscript:", "data:text/html"];

pub fn analyze_js_security(html: &str) -> Vec<JsSecurityIssue> {
    let mut issues = Vec::new();
    let lower = html.to_ascii_lowercase();

    // Analyze inline scripts
    let mut search_from = 0;
    while let Some(start) = lower[search_from..].find("<script") {
        let abs_start = search_from + start;
        let Some(tag_end) = lower[abs_start..].find('>') else {
            break;
        };
        let tag_lower = &lower[abs_start..abs_start + tag_end + 1];
        if tag_lower.contains("src=") {
            search_from = abs_start + tag_end + 1;
            continue;
        }
        let script_end = lower[abs_start + tag_end + 1..]
            .find("</script>")
            .map(|e| abs_start + tag_end + 1 + e)
            .unwrap_or(lower.len());
        let script_body = &lower[abs_start + tag_end + 1..script_end];
        search_from = script_end;

        analyze_script_body(script_body, &mut issues);
    }

    // Check for inline event handlers in HTML tags
    for handler in INLINE_HANDLERS {
        let pattern = format!("{handler}=");
        if lower.contains(&pattern) {
            issues.push(JsSecurityIssue::InlineEventHandler {
                handler: handler.to_string(),
            });
        }
    }

    // Check for unsafe URL schemes
    for scheme in UNSAFE_SCHEMES {
        if lower.contains(scheme) {
            issues.push(JsSecurityIssue::UnsafeUrlScheme {
                scheme: scheme.to_string(),
            });
        }
    }

    issues
}

fn analyze_script_body(script: &str, issues: &mut Vec<JsSecurityIssue>) {
    if script.contains("eval(") {
        issues.push(JsSecurityIssue::EvalUsage {
            context: "inline_script".to_string(),
        });
    }
    if script.contains("innerhtml") {
        issues.push(JsSecurityIssue::InnerHtmlAssignment {
            context: "inline_script".to_string(),
        });
    }
    if script.contains("document.write(") {
        issues.push(JsSecurityIssue::DocumentWrite);
    }
    if script.contains("outerhtml") {
        issues.push(JsSecurityIssue::OuterHtmlAssignment);
    }
    if script.contains("insertadjacenthtml(") {
        issues.push(JsSecurityIssue::InsertAdjacentHtml);
    }
    if script.contains(".html(") {
        issues.push(JsSecurityIssue::JQueryHtml);
    }
    if script.contains("dangerouslysetinnerhtml") {
        issues.push(JsSecurityIssue::DangerouslySetInnerHtml);
    }
    if script.contains("new function(") {
        issues.push(JsSecurityIssue::FunctionConstructor);
    }
    if script.contains("settimeout(")
        && (script.contains("settimeout(\"") || script.contains("settimeout('"))
    {
        issues.push(JsSecurityIssue::SetTimeoutString);
    }
    if script.contains("setinterval(")
        && (script.contains("setinterval(\"") || script.contains("setinterval('"))
    {
        issues.push(JsSecurityIssue::SetIntervalString);
    }
    if script.contains("postmessage") && !script.contains("origin") {
        issues.push(JsSecurityIssue::PostMessageNoOriginCheck);
    }
    if script.contains("json.parse") && !script.contains("try") {
        issues.push(JsSecurityIssue::JsonParseUnsafe {
            context: "no_try_catch".to_string(),
        });
    }
    for &(pattern, sink) in DOM_XSS_SINKS {
        if script.contains(pattern) {
            issues.push(JsSecurityIssue::DomXssSink {
                sink: sink.to_string(),
            });
        }
    }
}

pub fn js_security_to_operations(
    issues: &[JsSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::CrossSiteScripting,
                js_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
