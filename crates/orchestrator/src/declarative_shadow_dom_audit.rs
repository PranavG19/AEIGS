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

#[derive(Debug, Clone, PartialEq)]
pub enum DeclarativeShadowDomSecurityIssue {
    ShadowDomXssVector,
    ShadowDomStyleInjection,
    ShadowDomEventLeaking,
    ShadowDomFormHijack,
    ShadowDomSlotExposure,
    ShadowDomCloaking,
    ShadowDomClickjacking,
    OpenShadowRootAccess,
    ShadowDomCspBypass,
    ShadowDomMutationSpying,
}

impl std::fmt::Display for DeclarativeShadowDomSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShadowDomXssVector => write!(f, "shadow_dom_xss_vector"),
            Self::ShadowDomStyleInjection => write!(f, "shadow_dom_style_injection"),
            Self::ShadowDomEventLeaking => write!(f, "shadow_dom_event_leaking"),
            Self::ShadowDomFormHijack => write!(f, "shadow_dom_form_hijack"),
            Self::ShadowDomSlotExposure => write!(f, "shadow_dom_slot_exposure"),
            Self::ShadowDomCloaking => write!(f, "shadow_dom_cloaking"),
            Self::ShadowDomClickjacking => write!(f, "shadow_dom_clickjacking"),
            Self::OpenShadowRootAccess => write!(f, "open_shadow_root_access"),
            Self::ShadowDomCspBypass => write!(f, "shadow_dom_csp_bypass"),
            Self::ShadowDomMutationSpying => write!(f, "shadow_dom_mutation_spying"),
        }
    }
}

pub fn analyze_declarative_shadow_dom_security(
    body: &str,
) -> Vec<DeclarativeShadowDomSecurityIssue> {
    let mut issues = Vec::new();

    let has_shadow_api = body.contains("shadowrootmode")
        || body.contains("shadowroot")
        || body.contains("<template shadowrootmode");

    if !has_shadow_api {
        return issues;
    }

    // ShadowDomXssVector: Script injection via shadow DOM templates
    if body.contains("<template shadowrootmode") && body.contains("<script>") {
        issues.push(DeclarativeShadowDomSecurityIssue::ShadowDomXssVector);
    }

    // ShadowDomStyleInjection: CSS injection to exfiltrate data
    if (body.contains("<style") || body.contains("url("))
        && (body.contains("background:") || body.contains("background-image:"))
        && body.contains("url(")
    {
        issues.push(DeclarativeShadowDomSecurityIssue::ShadowDomStyleInjection);
    }

    // ShadowDomEventLeaking: Events leaking from shadow boundary
    if (body.contains("composed:true") || body.contains("composed: true"))
        && (body.contains("bubbles:true") || body.contains("bubbles: true"))
    {
        issues.push(DeclarativeShadowDomSecurityIssue::ShadowDomEventLeaking);
    }

    // ShadowDomFormHijack: Hidden forms in shadow DOM capturing credentials
    if body.contains("<form")
        && (body.contains("type=\"password\"") || body.contains("type='password'"))
        && (body.contains("display:none") || body.contains("visibility:hidden"))
    {
        issues.push(DeclarativeShadowDomSecurityIssue::ShadowDomFormHijack);
    }

    // ShadowDomSlotExposure: Using <slot> to expose sensitive content
    if body.contains("<slot")
        && (body.contains("token") || body.contains("password") || body.contains("secret"))
    {
        issues.push(DeclarativeShadowDomSecurityIssue::ShadowDomSlotExposure);
    }

    // ShadowDomCloaking: Using shadow DOM to cloak malicious content
    if body.contains("shadowrootmode")
        && (body.contains("user-agent") || body.contains("navigator.userAgent"))
        && (body.contains("bot") || body.contains("crawler") || body.contains("spider"))
    {
        issues.push(DeclarativeShadowDomSecurityIssue::ShadowDomCloaking);
    }

    // ShadowDomClickjacking: Overlaying transparent shadow DOM elements
    if (body.contains("opacity:0") || body.contains("opacity: 0"))
        && (body.contains("position:absolute") || body.contains("position: absolute"))
        && (body.contains("z-index:") || body.contains("z-index :"))
    {
        issues.push(DeclarativeShadowDomSecurityIssue::ShadowDomClickjacking);
    }

    // OpenShadowRootAccess: Using shadowRoot in open mode
    if body.contains("shadowrootmode=\"open\"")
        || body.contains("shadowrootmode='open'")
        || body.contains("shadowrootmode=open")
    {
        issues.push(DeclarativeShadowDomSecurityIssue::OpenShadowRootAccess);
    }

    // ShadowDomCspBypass: Bypassing CSP via shadow DOM inline styles/scripts
    if body.contains("shadowrootmode")
        && (body.contains("Content-Security-Policy")
            || body.contains("CSP")
            || body.contains("csp"))
        && (body.contains("style=") || body.contains("<script>"))
    {
        issues.push(DeclarativeShadowDomSecurityIssue::ShadowDomCspBypass);
    }

    // ShadowDomMutationSpying: Using MutationObserver on shadow DOM
    if body.contains("MutationObserver")
        && body.contains("shadowRoot")
        && (body.contains("observe(") || body.contains(".observe"))
    {
        issues.push(DeclarativeShadowDomSecurityIssue::ShadowDomMutationSpying);
    }

    issues
}

pub fn declarative_shadow_dom_security_severity(issue: &DeclarativeShadowDomSecurityIssue) -> f64 {
    match issue {
        DeclarativeShadowDomSecurityIssue::ShadowDomXssVector => 9.0,
        DeclarativeShadowDomSecurityIssue::ShadowDomStyleInjection => 7.5,
        DeclarativeShadowDomSecurityIssue::ShadowDomEventLeaking => 6.0,
        DeclarativeShadowDomSecurityIssue::ShadowDomFormHijack => 8.5,
        DeclarativeShadowDomSecurityIssue::ShadowDomSlotExposure => 7.0,
        DeclarativeShadowDomSecurityIssue::ShadowDomCloaking => 5.5,
        DeclarativeShadowDomSecurityIssue::ShadowDomClickjacking => 8.0,
        DeclarativeShadowDomSecurityIssue::OpenShadowRootAccess => 6.5,
        DeclarativeShadowDomSecurityIssue::ShadowDomCspBypass => 8.5,
        DeclarativeShadowDomSecurityIssue::ShadowDomMutationSpying => 5.0,
    }
}

pub fn declarative_shadow_dom_security_to_operations(
    issues: &[DeclarativeShadowDomSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                declarative_shadow_dom_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
