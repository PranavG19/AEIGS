use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum DomClobberingIssue {
    NamedElementCollision {
        element: String,
        name: String,
    },
    FormElementClobbering {
        form_name: String,
        element_name: String,
    },
    AnchorHrefClobbering {
        id: String,
        has_href: bool,
    },
    ScriptGadgetChain {
        clobbered_name: String,
        context: String,
    },
    DompurifyBypassPattern {
        pattern: String,
    },
    MissingNamespaceIsolation {
        element: String,
        id: String,
    },
}

impl std::fmt::Display for DomClobberingIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NamedElementCollision { element, name } => {
                write!(f, "named_element_collision:{element}:{name}")
            }
            Self::FormElementClobbering {
                form_name,
                element_name,
            } => {
                write!(f, "form_element_clobbering:{form_name}:{element_name}")
            }
            Self::AnchorHrefClobbering { id, has_href } => {
                write!(f, "anchor_href_clobbering:{id}:{has_href}")
            }
            Self::ScriptGadgetChain {
                clobbered_name,
                context,
            } => {
                write!(f, "script_gadget_chain:{clobbered_name}:{context}")
            }
            Self::DompurifyBypassPattern { pattern } => {
                write!(f, "dompurify_bypass_pattern:{pattern}")
            }
            Self::MissingNamespaceIsolation { element, id } => {
                write!(f, "missing_namespace_isolation:{element}:{id}")
            }
        }
    }
}

const DOCUMENT_PROPERTIES: &[&str] = &[
    "cookie",
    "domain",
    "referrer",
    "location",
    "URL",
    "documentURI",
    "baseURI",
    "title",
    "body",
    "head",
    "forms",
    "images",
    "links",
    "scripts",
    "anchors",
    "children",
    "firstChild",
    "lastChild",
    "parentNode",
    "innerHTML",
    "outerHTML",
    "textContent",
    "write",
    "writeln",
    "open",
    "close",
    "createElement",
    "getElementById",
    "getElementsByTagName",
    "querySelector",
    "querySelectorAll",
];

const WINDOW_PROPERTIES: &[&str] = &[
    "name",
    "location",
    "top",
    "parent",
    "self",
    "frames",
    "opener",
    "closed",
    "length",
    "navigator",
    "document",
    "alert",
    "confirm",
    "prompt",
    "fetch",
    "XMLHttpRequest",
    "eval",
    "Function",
    "setTimeout",
    "setInterval",
];

const FORM_API_PROPERTIES: &[&str] = &[
    "action", "method", "submit", "reset", "elements", "length", "name", "target", "enctype",
];

const SCRIPT_GADGET_ATTRS: &[&str] = &["src", "href", "action", "formaction", "data"];

const DOMPURIFY_BYPASS_PATTERNS: &[&str] = &[
    "<form><input name=\"attributes\">",
    "<form><input name=\"lastChild\">",
    "<form><input id=\"x\"><input id=\"x\" name=\"y\">",
    "<form><math><mtext></form><form><mglyph><style></math><img src onerror",
    "<svg><use href=\"#x\">",
];

pub fn audit_dom_clobbering(target: &str) -> Vec<DomClobberingIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send() {
        Ok(r) => r.text().unwrap_or_default(),
        Err(_) => return Vec::new(),
    };
    analyze_dom_clobbering(&body)
}

pub fn analyze_dom_clobbering(body: &str) -> Vec<DomClobberingIssue> {
    let mut issues = Vec::new();

    check_named_element_collision(body, &mut issues);
    check_form_element_clobbering(body, &mut issues);
    check_anchor_href_clobbering(body, &mut issues);
    check_script_gadget_chains(body, &mut issues);
    check_dompurify_bypass_patterns(body, &mut issues);
    check_missing_namespace_isolation(body, &mut issues);

    issues
}

fn check_named_element_collision(body: &str, issues: &mut Vec<DomClobberingIssue>) {
    for attr in ["id", "name"] {
        for (start, value) in find_attribute_values(body, attr) {
            if is_dangerous_document_property(&value) || is_dangerous_window_property(&value) {
                let element = extract_element_tag(body, start);
                issues.push(DomClobberingIssue::NamedElementCollision {
                    element,
                    name: value,
                });
            }
        }
    }
}

fn check_form_element_clobbering(body: &str, issues: &mut Vec<DomClobberingIssue>) {
    let mut pos = 0;
    while let Some(form_start) = find_tag_start(body, pos, "<form") {
        let Some(form_end) = find_tag_end(body, form_start) else {
            break;
        };
        let form_tag = &body[form_start..form_end];
        let form_name =
            extract_attribute(form_tag, "name").unwrap_or_else(|| "unnamed".to_string());

        let mut inner_pos = form_end;
        while let Some(input_start) = find_any_tag_start(
            body,
            inner_pos,
            &["<input", "<button", "<select", "<textarea"],
        ) {
            if input_start >= body.len() || body[input_start..].starts_with("</form") {
                break;
            }
            let Some(input_end) = find_tag_end(body, input_start) else {
                break;
            };
            let input_tag = &body[input_start..input_end];
            if let Some(element_name) = extract_attribute(input_tag, "name")
                && is_form_api_property(&element_name)
            {
                issues.push(DomClobberingIssue::FormElementClobbering {
                    form_name: form_name.clone(),
                    element_name,
                });
            }
            inner_pos = input_end;
        }
        pos = form_end;
    }
}

fn check_anchor_href_clobbering(body: &str, issues: &mut Vec<DomClobberingIssue>) {
    let mut pos = 0;
    while let Some(start) = find_tag_start(body, pos, "<a ") {
        let Some(end) = find_tag_end(body, start) else {
            break;
        };
        let tag = &body[start..end];
        if let Some(id) = extract_attribute(tag, "id")
            && (is_dangerous_document_property(&id) || is_dangerous_window_property(&id))
        {
            let has_href = tag.contains("href=");
            issues.push(DomClobberingIssue::AnchorHrefClobbering { id, has_href });
        }
        pos = end;
    }
}

fn check_script_gadget_chains(body: &str, issues: &mut Vec<DomClobberingIssue>) {
    for attr in ["id", "name"] {
        for (_start, value) in find_attribute_values(body, attr) {
            if is_dangerous_document_property(&value) || is_dangerous_window_property(&value) {
                for gadget_attr in SCRIPT_GADGET_ATTRS {
                    let pattern = format!("{gadget_attr}=");
                    if body.contains(&pattern) {
                        let context = if body.contains(&format!(".{value}.")) {
                            "property_access"
                        } else if body.contains(&format!("{value}[")) {
                            "bracket_access"
                        } else if body.contains(&format!("={value}")) {
                            "assignment"
                        } else {
                            "potential"
                        };
                        issues.push(DomClobberingIssue::ScriptGadgetChain {
                            clobbered_name: value.clone(),
                            context: context.to_string(),
                        });
                        break;
                    }
                }
            }
        }
    }
}

fn check_dompurify_bypass_patterns(body: &str, issues: &mut Vec<DomClobberingIssue>) {
    for pattern in DOMPURIFY_BYPASS_PATTERNS {
        let normalized_body = body.replace(['\n', '\r', '\t'], "");
        let normalized_pattern = pattern.replace(['\n', '\r', '\t'], "");
        if normalized_body.contains(&normalized_pattern) {
            issues.push(DomClobberingIssue::DompurifyBypassPattern {
                pattern: pattern.to_string(),
            });
        }
    }
}

fn check_missing_namespace_isolation(body: &str, issues: &mut Vec<DomClobberingIssue>) {
    for (start, id_value) in find_attribute_values(body, "id") {
        if is_dangerous_document_property(&id_value) {
            let element = extract_element_tag(body, start);
            if !body.contains("ownerDocument") && !body.contains("contentDocument") {
                issues.push(DomClobberingIssue::MissingNamespaceIsolation {
                    element,
                    id: id_value,
                });
            }
        }
    }
}

fn find_attribute_values(body: &str, attr: &str) -> Vec<(usize, String)> {
    let mut results = Vec::new();
    for quote in ['"', '\''] {
        let pattern = format!("{attr}={quote}");
        let mut pos = 0;
        while let Some(idx) = body[pos..].find(&pattern) {
            let abs = pos + idx;
            let val_start = abs + pattern.len();
            if let Some(end_offset) = body[val_start..].find(quote) {
                let value = body[val_start..val_start + end_offset].to_string();
                if !value.is_empty() {
                    results.push((abs, value));
                }
                pos = val_start + end_offset + 1;
            } else {
                break;
            }
        }
    }
    results
}

fn find_tag_start(body: &str, pos: usize, tag: &str) -> Option<usize> {
    body[pos..].find(tag).map(|idx| pos + idx)
}

fn find_any_tag_start(body: &str, pos: usize, tags: &[&str]) -> Option<usize> {
    tags.iter()
        .filter_map(|tag| body[pos..].find(tag).map(|idx| pos + idx))
        .min()
}

fn find_tag_end(body: &str, start: usize) -> Option<usize> {
    body[start..].find('>').map(|idx| start + idx + 1)
}

fn extract_attribute(tag: &str, attr: &str) -> Option<String> {
    for quote in ['"', '\''] {
        let pattern = format!("{attr}={quote}");
        if let Some(start) = tag.find(&pattern) {
            let val_start = start + pattern.len();
            if let Some(end) = tag[val_start..].find(quote) {
                return Some(tag[val_start..val_start + end].to_string());
            }
        }
    }
    None
}

fn extract_element_tag(body: &str, attr_pos: usize) -> String {
    let prefix = &body[..attr_pos];
    if let Some(tag_start) = prefix.rfind('<')
        && let Some(space_or_gt) = body[tag_start..].find([' ', '>'])
    {
        return body[tag_start + 1..tag_start + space_or_gt].to_string();
    }
    "unknown".to_string()
}

fn is_dangerous_document_property(name: &str) -> bool {
    DOCUMENT_PROPERTIES.contains(&name)
}

fn is_dangerous_window_property(name: &str) -> bool {
    WINDOW_PROPERTIES.contains(&name)
}

fn is_form_api_property(name: &str) -> bool {
    FORM_API_PROPERTIES.contains(&name)
}

pub fn dom_clobbering_severity(issue: &DomClobberingIssue) -> f64 {
    match issue {
        DomClobberingIssue::NamedElementCollision { name, .. } => {
            let critical = [
                "cookie",
                "location",
                "innerHTML",
                "outerHTML",
                "write",
                "writeln",
                "eval",
                "document",
            ];
            if critical.iter().any(|&c| c == name) {
                8.0
            } else {
                5.5
            }
        }
        DomClobberingIssue::FormElementClobbering { .. } => 4.5,
        DomClobberingIssue::AnchorHrefClobbering { has_href, .. } => {
            if *has_href {
                7.0
            } else {
                5.0
            }
        }
        DomClobberingIssue::ScriptGadgetChain { context, .. } => match context.as_str() {
            "property_access" | "bracket_access" => 8.5,
            "assignment" => 7.5,
            _ => 6.0,
        },
        DomClobberingIssue::DompurifyBypassPattern { .. } => 9.0,
        DomClobberingIssue::MissingNamespaceIsolation { .. } => 6.5,
    }
}

pub fn dom_clobbering_to_operations(
    issues: &[DomClobberingIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::CrossSiteScripting,
                dom_clobbering_severity(issue),
                0.5,
            )
        })
        .collect()
}
