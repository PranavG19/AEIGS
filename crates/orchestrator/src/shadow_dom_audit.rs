use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum ShadowDomIssue {
    DeclarativeShadowDom,
    OpenShadowRoot,
    InnerHtmlInjection,
    StyleInjection,
    EventRetargetBypass,
    UnsanitizedSlotContent,
}

impl std::fmt::Display for ShadowDomIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeclarativeShadowDom => write!(f, "declarative_shadow_dom"),
            Self::OpenShadowRoot => write!(f, "open_shadow_root"),
            Self::InnerHtmlInjection => write!(f, "inner_html_injection"),
            Self::StyleInjection => write!(f, "style_injection"),
            Self::EventRetargetBypass => write!(f, "event_retarget_bypass"),
            Self::UnsanitizedSlotContent => write!(f, "unsanitized_slot_content"),
        }
    }
}

pub fn audit_shadow_dom(target: &str) -> Vec<ShadowDomIssue> {
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
    analyze_shadow_dom(&body)
}

pub fn analyze_shadow_dom(body: &str) -> Vec<ShadowDomIssue> {
    let has_declarative = body.contains("shadowrootmode") || body.contains("shadowroot");
    let has_imperative = body.contains("attachShadow") || body.contains("shadowRoot");

    if !has_declarative && !has_imperative {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if has_declarative {
        issues.push(ShadowDomIssue::DeclarativeShadowDom);
    }

    if body.contains("mode: \"open\"")
        || body.contains("mode: 'open'")
        || body.contains("mode:\"open\"")
    {
        issues.push(ShadowDomIssue::OpenShadowRoot);
    }

    if (has_declarative || has_imperative)
        && (body.contains("innerHTML")
            || body.contains("insertAdjacentHTML")
            || body.contains("outerHTML"))
    {
        issues.push(ShadowDomIssue::InnerHtmlInjection);
    }

    if (has_declarative || has_imperative)
        && body.contains("<style")
        && (body.contains("var(--") || body.contains("@import"))
    {
        issues.push(ShadowDomIssue::StyleInjection);
    }

    if (has_declarative || has_imperative)
        && body.contains("composedPath")
        && !body.contains("event.target")
        && !body.contains("e.target")
    {
        issues.push(ShadowDomIssue::EventRetargetBypass);
    }

    if (has_declarative || has_imperative)
        && body.contains("<slot")
        && !body.contains("sanitize")
        && !body.contains("escapeHtml")
        && !body.contains("textContent")
    {
        issues.push(ShadowDomIssue::UnsanitizedSlotContent);
    }

    issues
}

pub fn shadow_dom_severity(issue: &ShadowDomIssue) -> f64 {
    match issue {
        ShadowDomIssue::InnerHtmlInjection => 8.0,
        ShadowDomIssue::UnsanitizedSlotContent => 7.0,
        ShadowDomIssue::StyleInjection => 6.0,
        ShadowDomIssue::EventRetargetBypass => 5.5,
        ShadowDomIssue::OpenShadowRoot => 4.0,
        ShadowDomIssue::DeclarativeShadowDom => 2.5,
    }
}

pub fn shadow_dom_to_operations(
    issues: &[ShadowDomIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::CrossSiteScripting,
                shadow_dom_severity(issue),
                0.55,
            )
        })
        .collect()
}
