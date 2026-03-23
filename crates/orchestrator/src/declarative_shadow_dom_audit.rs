use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum DeclarativeShadowDomIssue {
    ApiDetected,
    XssViaTemplate,
    StyleExfiltration,
    SlotInjection,
    OpenModeRisk,
}

impl std::fmt::Display for DeclarativeShadowDomIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiDetected => write!(f, "api_detected"),
            Self::XssViaTemplate => write!(f, "xss_via_template"),
            Self::StyleExfiltration => write!(f, "style_exfiltration"),
            Self::SlotInjection => write!(f, "slot_injection"),
            Self::OpenModeRisk => write!(f, "open_mode_risk"),
        }
    }
}

pub fn audit_declarative_shadow_dom(target: &str) -> Vec<DeclarativeShadowDomIssue> {
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
    analyze_declarative_shadow_dom(&body)
}

pub fn analyze_declarative_shadow_dom(body: &str) -> Vec<DeclarativeShadowDomIssue> {
    let mut issues = Vec::new();

    let has_api = body.contains("shadowrootmode")
        || body.contains("shadowroot")
        || body.contains("<template shadowrootmode");

    if has_api {
        issues.push(DeclarativeShadowDomIssue::ApiDetected);

        // XssViaTemplate: unsanitized content in shadow template
        let has_inner_html = body.contains("innerHTML") || body.contains("insertAdjacentHTML");
        let has_sanitize =
            body.contains("sanitize") || body.contains("DOMPurify") || body.contains("escape");
        if has_inner_html && !has_sanitize {
            issues.push(DeclarativeShadowDomIssue::XssViaTemplate);
        }

        // StyleExfiltration: CSS-based data exfiltration from shadow
        let has_style =
            body.contains("<style") || body.contains("@import") || body.contains("url(");
        let has_exfil = body.contains("fetch(")
            || body.contains("sendBeacon")
            || body.contains("XMLHttpRequest");
        if has_style && has_exfil {
            issues.push(DeclarativeShadowDomIssue::StyleExfiltration);
        }

        // SlotInjection: slot content injection
        let has_slot = body.contains("<slot") || body.contains("slot=");
        let has_dom_manip = body.contains("innerHTML")
            || body.contains("outerHTML")
            || body.contains("textContent");
        let has_encode = body.contains("sanitize") || body.contains("encode");
        if has_slot && has_dom_manip && !has_encode {
            issues.push(DeclarativeShadowDomIssue::SlotInjection);
        }

        // OpenModeRisk: open shadow root accessible from outside
        if body.contains("shadowrootmode=\"open\"") || body.contains("shadowrootmode=open") {
            issues.push(DeclarativeShadowDomIssue::OpenModeRisk);
        }
    }

    issues
}

pub fn declarative_shadow_dom_severity(issue: &DeclarativeShadowDomIssue) -> f64 {
    match issue {
        DeclarativeShadowDomIssue::ApiDetected => 2.0,
        DeclarativeShadowDomIssue::XssViaTemplate => 8.0,
        DeclarativeShadowDomIssue::StyleExfiltration => 7.0,
        DeclarativeShadowDomIssue::SlotInjection => 6.5,
        DeclarativeShadowDomIssue::OpenModeRisk => 5.5,
    }
}

pub fn declarative_shadow_dom_to_operations(
    issues: &[DeclarativeShadowDomIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::CrossSiteScripting,
                declarative_shadow_dom_severity(issue),
                0.5,
            )
        })
        .collect()
}
