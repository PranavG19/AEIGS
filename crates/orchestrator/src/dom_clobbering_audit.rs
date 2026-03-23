use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum DomClobberIssue {
    ClobberedProperty { element: String, name: String },
    NamedFormAccess { form_name: String },
    AnchorIdOverride { id: String },
}

impl std::fmt::Display for DomClobberIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClobberedProperty { element, name } => {
                write!(f, "dom_clobber:{element}:{name}")
            }
            Self::NamedFormAccess { form_name } => {
                write!(f, "named_form_access:{form_name}")
            }
            Self::AnchorIdOverride { id } => {
                write!(f, "anchor_id_override:{id}")
            }
        }
    }
}

const DANGEROUS_NAMES: &[&str] = &[
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
    "fetch",
    "XMLHttpRequest",
];

pub fn audit_dom_clobbering(target: &str) -> Vec<DomClobberIssue> {
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
    analyze_dom_clobbering(&body)
}

pub fn analyze_dom_clobbering(html: &str) -> Vec<DomClobberIssue> {
    let mut issues = Vec::new();
    let lower = html.to_ascii_lowercase();

    for attr in ["id", "name"] {
        let pattern_dq = format!("{attr}=\"");
        let pattern_sq = format!("{attr}='");

        for pattern in [&pattern_dq, &pattern_sq] {
            let quote = if pattern.ends_with('"') { '"' } else { '\'' };
            let mut pos = 0;
            while let Some(idx) = lower[pos..].find(pattern.as_str()) {
                let abs = pos + idx + pattern.len();
                if let Some(end) = lower[abs..].find(quote) {
                    let value = &html[abs..abs + end];
                    check_clobber_value(value, attr, &mut issues);
                    pos = abs + end;
                } else {
                    break;
                }
            }
        }
    }

    check_form_names(html, &lower, &mut issues);
    check_anchor_overrides(html, &lower, &mut issues);

    issues
}

fn check_clobber_value(value: &str, attr: &str, issues: &mut Vec<DomClobberIssue>) {
    let val_lower = value.to_ascii_lowercase();

    for &dangerous in DANGEROUS_NAMES {
        if val_lower == dangerous.to_ascii_lowercase() {
            issues.push(DomClobberIssue::ClobberedProperty {
                element: attr.to_string(),
                name: value.to_string(),
            });
            return;
        }
    }

    for &prop in WINDOW_PROPERTIES {
        if val_lower == prop.to_ascii_lowercase() {
            issues.push(DomClobberIssue::ClobberedProperty {
                element: attr.to_string(),
                name: value.to_string(),
            });
            return;
        }
    }
}

fn check_form_names(html: &str, lower: &str, issues: &mut Vec<DomClobberIssue>) {
    let mut pos = 0;
    while let Some(idx) = lower[pos..].find("<form") {
        let abs = pos + idx;
        let tag_end = match lower[abs..].find('>') {
            Some(e) => abs + e,
            None => break,
        };
        let tag = &html[abs..tag_end + 1];
        let tag_lower = &lower[abs..tag_end + 1];

        if let Some(name) = extract_attr_value(tag, tag_lower, "name")
            && !name.is_empty()
        {
            issues.push(DomClobberIssue::NamedFormAccess {
                form_name: name,
            });
        }
        pos = tag_end + 1;
    }
}

fn check_anchor_overrides(html: &str, lower: &str, issues: &mut Vec<DomClobberIssue>) {
    let mut pos = 0;
    while let Some(idx) = lower[pos..].find("<a ") {
        let abs = pos + idx;
        let tag_end = match lower[abs..].find('>') {
            Some(e) => abs + e,
            None => break,
        };
        let tag = &html[abs..tag_end + 1];
        let tag_lower = &lower[abs..tag_end + 1];

        if let Some(id) = extract_attr_value(tag, tag_lower, "id") {
            let id_lower = id.to_ascii_lowercase();
            if DANGEROUS_NAMES
                .iter()
                .any(|d| d.to_ascii_lowercase() == id_lower)
            {
                issues.push(DomClobberIssue::AnchorIdOverride { id });
            }
        }
        pos = tag_end + 1;
    }
}

fn extract_attr_value(tag: &str, tag_lower: &str, attr: &str) -> Option<String> {
    let dq = format!("{attr}=\"");
    if let Some(start) = tag_lower.find(&dq) {
        let val_start = start + dq.len();
        if let Some(end) = tag[val_start..].find('"') {
            return Some(tag[val_start..val_start + end].to_string());
        }
    }
    let sq = format!("{attr}='");
    if let Some(start) = tag_lower.find(&sq) {
        let val_start = start + sq.len();
        if let Some(end) = tag[val_start..].find('\'') {
            return Some(tag[val_start..val_start + end].to_string());
        }
    }
    None
}

pub fn dom_clobber_severity(issue: &DomClobberIssue) -> f64 {
    match issue {
        DomClobberIssue::ClobberedProperty { name, .. } => {
            let critical = [
                "cookie", "location", "innerHTML", "outerHTML", "write", "writeln",
            ];
            if critical
                .iter()
                .any(|c| c.eq_ignore_ascii_case(name.as_str()))
            {
                7.5
            } else {
                5.0
            }
        }
        DomClobberIssue::NamedFormAccess { .. } => 4.0,
        DomClobberIssue::AnchorIdOverride { .. } => 6.0,
    }
}

pub fn dom_clobber_to_operations(
    issues: &[DomClobberIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::CrossSiteScripting,
                dom_clobber_severity(issue),
                0.7,
            )
        })
        .collect()
}
