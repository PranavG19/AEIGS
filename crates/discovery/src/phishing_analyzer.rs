use regex::Regex;

/// Classification of where a form submits its data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FormActionType {
    SameOrigin,
    CrossOrigin,
    RelativePath,
    DataUri,
    JavascriptUri,
    Empty,
    Mailto,
}

impl std::fmt::Display for FormActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SameOrigin => write!(f, "Same Origin"),
            Self::CrossOrigin => write!(f, "Cross Origin"),
            Self::RelativePath => write!(f, "Relative Path"),
            Self::DataUri => write!(f, "data: URI"),
            Self::JavascriptUri => write!(f, "javascript: URI"),
            Self::Empty => write!(f, "Empty"),
            Self::Mailto => write!(f, "mailto:"),
        }
    }
}

/// Anti-phishing control mechanism.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AntiPhishingControl {
    Mfa,
    Fido2,
    CertificatePinning,
    CspStrict,
    XFrameOptions,
    ContentSecurityPolicy,
    SubresourceIntegrity,
    ReferrerPolicy,
}

impl std::fmt::Display for AntiPhishingControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mfa => write!(f, "MFA"),
            Self::Fido2 => write!(f, "FIDO2/WebAuthn"),
            Self::CertificatePinning => write!(f, "Certificate Pinning"),
            Self::CspStrict => write!(f, "Strict CSP"),
            Self::XFrameOptions => write!(f, "X-Frame-Options"),
            Self::ContentSecurityPolicy => write!(f, "Content-Security-Policy"),
            Self::SubresourceIntegrity => write!(f, "Subresource Integrity"),
            Self::ReferrerPolicy => write!(f, "Referrer-Policy"),
        }
    }
}

/// Overall phishing risk level for a target.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PhishingRisk {
    Critical,
    High,
    Medium,
    Low,
    Minimal,
}

impl std::fmt::Display for PhishingRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "Critical"),
            Self::High => write!(f, "High"),
            Self::Medium => write!(f, "Medium"),
            Self::Low => write!(f, "Low"),
            Self::Minimal => write!(f, "Minimal"),
        }
    }
}

/// A single form input field extracted from HTML.
#[derive(Debug, Clone, PartialEq)]
pub struct FormField {
    pub name: String,
    pub field_type: String,
    pub id: Option<String>,
    pub placeholder: Option<String>,
    pub autocomplete: Option<String>,
}

/// Fingerprint of a login/authentication form found on a page.
#[derive(Debug, Clone, PartialEq)]
pub struct LoginPageFingerprint {
    pub url: String,
    pub form_action: String,
    pub input_fields: Vec<FormField>,
    pub has_password_field: bool,
    pub has_username_field: bool,
    pub method: String,
    pub page_title: Option<String>,
}

/// A single factor contributing to a clonability score.
#[derive(Debug, Clone, PartialEq)]
pub struct ClonabilityFactor {
    pub name: String,
    pub score: f64,
    pub description: String,
}

/// Composite score indicating how easily a page could be cloned for phishing.
#[derive(Debug, Clone, PartialEq)]
pub struct ClonabilityScore {
    pub overall: f64,
    pub factors: Vec<ClonabilityFactor>,
}

/// Analysis of where a form submits credential data.
#[derive(Debug, Clone, PartialEq)]
pub struct FormActionAnalysis {
    pub original_url: String,
    pub action_url: String,
    pub action_type: FormActionType,
    pub cross_origin: bool,
    pub uses_https: bool,
    pub suspicious: bool,
    pub reason: Option<String>,
}

/// Assessment of anti-phishing controls present on a target.
#[derive(Debug, Clone, PartialEq)]
pub struct AntiPhishingAssessment {
    pub controls_present: Vec<AntiPhishingControl>,
    pub controls_missing: Vec<AntiPhishingControl>,
    pub resilience_score: f64,
    pub findings: Vec<String>,
}

/// Brand assets discoverable from a page that an attacker could reuse.
#[derive(Debug, Clone, PartialEq)]
pub struct BrandAssetExposure {
    pub logos_found: Vec<String>,
    pub css_urls: Vec<String>,
    pub favicon_url: Option<String>,
    pub brand_terms: Vec<String>,
    pub exposure_score: f64,
}

/// Full phishing susceptibility report for a target URL.
#[derive(Debug, Clone, PartialEq)]
pub struct PhishingAnalysisReport {
    pub url: String,
    pub login_pages: Vec<LoginPageFingerprint>,
    pub clonability: ClonabilityScore,
    pub form_actions: Vec<FormActionAnalysis>,
    pub anti_phishing: AntiPhishingAssessment,
    pub brand_exposure: BrandAssetExposure,
    pub overall_risk: PhishingRisk,
}

const USERNAME_FIELD_NAMES: &[&str] = &[
    "user",
    "username",
    "email",
    "login",
    "account",
    "uid",
    "identity",
    "user_id",
    "user_name",
    "signin",
    "log",
];

const USERNAME_FIELD_TYPES: &[&str] = &["email", "text"];

const LOGO_KEYWORDS: &[&str] = &["logo", "brand", "header-img", "site-logo", "company"];

const BRAND_TERMS: &[&str] = &[
    "sign in",
    "log in",
    "login",
    "signin",
    "authenticate",
    "credentials",
    "password",
    "account",
    "verify your identity",
    "secure login",
    "two-factor",
    "2fa",
    "sso",
    "single sign-on",
];

fn extract_attr(tag: &str, attr_name: &str) -> Option<String> {
    let pattern = format!(r#"(?i){}\s*=\s*["']([^"']*)["']"#, regex::escape(attr_name));
    Regex::new(&pattern)
        .ok()
        .and_then(|re| re.captures(tag))
        .map(|caps| caps[1].to_string())
}

fn extract_page_title(html: &str) -> Option<String> {
    let re = Regex::new(r"(?is)<title[^>]*>(.*?)</title>").ok()?;
    re.captures(html)
        .map(|caps| caps[1].trim().to_string())
        .filter(|t| !t.is_empty())
}

fn extract_origin(url: &str) -> Option<String> {
    let re = Regex::new(r"(?i)^(https?://[^/]+)").ok()?;
    re.captures(url).map(|caps| caps[1].to_lowercase())
}

fn parse_input_fields(form_html: &str) -> Vec<FormField> {
    let input_re = Regex::new(r"(?is)<input[^>]*>").unwrap();
    input_re
        .find_iter(form_html)
        .map(|m| {
            let tag = m.as_str();
            FormField {
                name: extract_attr(tag, "name").unwrap_or_default(),
                field_type: extract_attr(tag, "type").unwrap_or_else(|| "text".to_string()),
                id: extract_attr(tag, "id"),
                placeholder: extract_attr(tag, "placeholder"),
                autocomplete: extract_attr(tag, "autocomplete"),
            }
        })
        .collect()
}

fn is_username_field(field: &FormField) -> bool {
    let name_lower = field.name.to_lowercase();
    let id_lower = field.id.as_deref().unwrap_or("").to_lowercase();
    let placeholder_lower = field.placeholder.as_deref().unwrap_or("").to_lowercase();
    let autocomplete_lower = field.autocomplete.as_deref().unwrap_or("").to_lowercase();

    if !USERNAME_FIELD_TYPES.contains(&field.field_type.to_lowercase().as_str()) {
        return false;
    }

    USERNAME_FIELD_NAMES.iter().any(|keyword| {
        name_lower.contains(keyword)
            || id_lower.contains(keyword)
            || placeholder_lower.contains(keyword)
            || autocomplete_lower.contains(keyword)
    })
}

/// Parse HTML to find login/authentication forms containing password inputs.
pub fn fingerprint_login_page(url: &str, html: &str) -> Vec<LoginPageFingerprint> {
    let form_re = Regex::new(r"(?is)<form[^>]*>([\s\S]*?)</form>").unwrap();
    let form_tag_re = Regex::new(r"(?is)<form[^>]*>").unwrap();
    let title = extract_page_title(html);

    form_re
        .captures_iter(html)
        .filter_map(|caps| {
            let full_match = caps.get(0).unwrap().as_str();
            let fields = parse_input_fields(full_match);

            let has_password = fields
                .iter()
                .any(|f| f.field_type.eq_ignore_ascii_case("password"));
            if !has_password {
                return None;
            }

            let form_tag = form_tag_re.find(full_match)?.as_str();
            let action = extract_attr(form_tag, "action").unwrap_or_default();
            let method = extract_attr(form_tag, "method")
                .unwrap_or_else(|| "GET".to_string())
                .to_uppercase();

            let has_username = fields.iter().any(is_username_field);

            Some(LoginPageFingerprint {
                url: url.to_string(),
                form_action: action,
                has_password_field: true,
                has_username_field: has_username,
                input_fields: fields,
                method,
                page_title: title.clone(),
            })
        })
        .collect()
}

/// Score how easily a page could be cloned for phishing purposes.
pub fn assess_clonability(html: &str, headers: &[(&str, &str)]) -> ClonabilityScore {
    let factors = vec![
        assess_csp_factor(headers),
        assess_frame_ancestors_factor(headers, html),
        assess_external_resources_factor(html),
        assess_inline_content_factor(html),
        assess_html_complexity_factor(html),
        assess_resource_count_factor(html),
    ];

    let overall = factors.iter().map(|f| f.score).sum::<f64>() / factors.len() as f64;
    let overall = overall.clamp(0.0, 1.0);

    ClonabilityScore { overall, factors }
}

fn assess_csp_factor(headers: &[(&str, &str)]) -> ClonabilityFactor {
    let has_csp = headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-security-policy"));

    ClonabilityFactor {
        name: "csp_presence".to_string(),
        score: if has_csp { 0.2 } else { 0.8 },
        description: if has_csp {
            "CSP header present, harder to clone with inline resources".to_string()
        } else {
            "No CSP header, page resources freely loadable".to_string()
        },
    }
}

fn assess_frame_ancestors_factor(headers: &[(&str, &str)], html: &str) -> ClonabilityFactor {
    let has_xfo = headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("x-frame-options"));
    let csp_val = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-security-policy"))
        .map(|(_, v)| *v)
        .unwrap_or("");
    let has_frame_ancestors = csp_val.contains("frame-ancestors");
    let meta_re = Regex::new(r"(?is)<meta[^>]*frame-ancestors[^>]*>").unwrap();
    let has_meta_frame = meta_re.is_match(html);

    let protected = has_xfo || has_frame_ancestors || has_meta_frame;

    ClonabilityFactor {
        name: "frame_protection".to_string(),
        score: if protected { 0.3 } else { 0.9 },
        description: if protected {
            "Frame embedding restricted".to_string()
        } else {
            "No frame embedding restrictions, page can be iframed".to_string()
        },
    }
}

fn assess_external_resources_factor(html: &str) -> ClonabilityFactor {
    let external_re = Regex::new(r#"(?i)(src|href)\s*=\s*["'](https?://[^"']*)["']"#).unwrap();
    let all_res_re = Regex::new(r#"(?i)(src|href)\s*=\s*["']([^"']*)["']"#).unwrap();

    let external_count = external_re.find_iter(html).count();
    let total_count = all_res_re.find_iter(html).count().max(1);
    let ratio = external_count as f64 / total_count as f64;

    ClonabilityFactor {
        name: "external_resources".to_string(),
        score: ratio.clamp(0.0, 1.0),
        description: format!(
            "{} of {} resources are external (ratio {:.2})",
            external_count, total_count, ratio
        ),
    }
}

fn assess_inline_content_factor(html: &str) -> ClonabilityFactor {
    let inline_style_re = Regex::new(r"(?is)<style[^>]*>").unwrap();
    let inline_script_re = Regex::new(r"(?is)<script[^>]*>[^<]+</script>").unwrap();
    let style_attr_re = Regex::new(r#"(?i)style\s*=\s*["']"#).unwrap();

    let inline_styles = inline_style_re.find_iter(html).count();
    let inline_scripts = inline_script_re.find_iter(html).count();
    let style_attrs = style_attr_re.find_iter(html).count();
    let total_inline = inline_styles + inline_scripts + style_attrs;

    let score = match total_inline {
        0 => 0.3,
        1..=5 => 0.5,
        6..=15 => 0.7,
        _ => 0.9,
    };

    ClonabilityFactor {
        name: "inline_content".to_string(),
        score,
        description: format!(
            "{} inline styles, {} inline scripts, {} style attributes",
            inline_styles, inline_scripts, style_attrs
        ),
    }
}

fn assess_html_complexity_factor(html: &str) -> ClonabilityFactor {
    let tag_re = Regex::new(r"<[a-zA-Z][^>]*>").unwrap();
    let tag_count = tag_re.find_iter(html).count();

    let score = match tag_count {
        0..=50 => 0.9,
        51..=200 => 0.7,
        201..=500 => 0.5,
        _ => 0.3,
    };

    ClonabilityFactor {
        name: "html_complexity".to_string(),
        score,
        description: format!("{} HTML tags found", tag_count),
    }
}

fn assess_resource_count_factor(html: &str) -> ClonabilityFactor {
    let res_re = Regex::new(r#"(?i)(src|href)\s*=\s*["']([^"']*)["']"#).unwrap();
    let count = res_re.find_iter(html).count();

    let score = match count {
        0..=10 => 0.9,
        11..=30 => 0.7,
        31..=60 => 0.5,
        _ => 0.3,
    };

    ClonabilityFactor {
        name: "total_resources".to_string(),
        score,
        description: format!("{} total resources referenced", count),
    }
}

pub(crate) fn classify_form_action(page_url: &str, action: &str) -> FormActionType {
    let trimmed = action.trim();

    if trimmed.is_empty() {
        return FormActionType::Empty;
    }
    if trimmed.to_lowercase().starts_with("javascript:") {
        return FormActionType::JavascriptUri;
    }
    if trimmed.to_lowercase().starts_with("data:") {
        return FormActionType::DataUri;
    }
    if trimmed.to_lowercase().starts_with("mailto:") {
        return FormActionType::Mailto;
    }
    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        return FormActionType::RelativePath;
    }

    let page_origin = extract_origin(page_url).unwrap_or_default();
    let action_origin = extract_origin(trimmed).unwrap_or_default();

    if page_origin == action_origin {
        FormActionType::SameOrigin
    } else {
        FormActionType::CrossOrigin
    }
}

/// Analyze where login form submissions are directed.
pub fn analyze_form_actions(
    page_url: &str,
    forms: &[LoginPageFingerprint],
) -> Vec<FormActionAnalysis> {
    forms
        .iter()
        .map(|form| {
            let action = &form.form_action;
            let action_type = classify_form_action(page_url, action);
            let cross_origin = action_type == FormActionType::CrossOrigin;
            let uses_https = action.starts_with("https://")
                || action_type == FormActionType::RelativePath
                || action_type == FormActionType::Empty;

            let (suspicious, reason) = evaluate_action_suspicion(&action_type, action);

            FormActionAnalysis {
                original_url: page_url.to_string(),
                action_url: action.clone(),
                action_type,
                cross_origin,
                uses_https,
                suspicious,
                reason,
            }
        })
        .collect()
}

fn evaluate_action_suspicion(action_type: &FormActionType, action: &str) -> (bool, Option<String>) {
    match action_type {
        FormActionType::JavascriptUri => (
            true,
            Some("Form uses javascript: URI for submission".to_string()),
        ),
        FormActionType::DataUri => (true, Some("Form uses data: URI for submission".to_string())),
        FormActionType::CrossOrigin => (
            true,
            Some(format!(
                "Credentials submitted cross-origin to {}",
                extract_origin(action).unwrap_or_else(|| action.to_string())
            )),
        ),
        FormActionType::Empty => (
            false,
            Some("Empty action submits to current page".to_string()),
        ),
        _ => (false, None),
    }
}

fn header_value<'a>(headers: &[(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| *v)
}

/// Assess anti-phishing controls from HTTP headers and HTML content.
pub fn assess_anti_phishing_controls(
    headers: &[(&str, &str)],
    html: &str,
) -> AntiPhishingAssessment {
    let all_controls = vec![
        AntiPhishingControl::XFrameOptions,
        AntiPhishingControl::ContentSecurityPolicy,
        AntiPhishingControl::CspStrict,
        AntiPhishingControl::SubresourceIntegrity,
        AntiPhishingControl::ReferrerPolicy,
        AntiPhishingControl::Mfa,
        AntiPhishingControl::Fido2,
        AntiPhishingControl::CertificatePinning,
    ];

    let mut present = Vec::new();
    let mut findings = Vec::new();

    check_xfo_control(headers, &mut present, &mut findings);
    check_csp_control(headers, &mut present, &mut findings);
    check_sri_control(html, &mut present, &mut findings);
    check_referrer_policy(headers, &mut present, &mut findings);
    check_mfa_references(html, &mut present, &mut findings);
    check_fido2_references(html, &mut present, &mut findings);
    check_certificate_pinning(headers, &mut present, &mut findings);

    let missing: Vec<AntiPhishingControl> = all_controls
        .into_iter()
        .filter(|c| !present.contains(c))
        .collect();

    let total_controls = present.len() + missing.len();
    let resilience_score = if total_controls == 0 {
        0.0
    } else {
        (present.len() as f64 / total_controls as f64).clamp(0.0, 1.0)
    };

    AntiPhishingAssessment {
        controls_present: present,
        controls_missing: missing,
        resilience_score,
        findings,
    }
}

fn check_xfo_control(
    headers: &[(&str, &str)],
    present: &mut Vec<AntiPhishingControl>,
    findings: &mut Vec<String>,
) {
    if let Some(val) = header_value(headers, "x-frame-options") {
        present.push(AntiPhishingControl::XFrameOptions);
        findings.push(format!("X-Frame-Options: {}", val));
    }
}

fn check_csp_control(
    headers: &[(&str, &str)],
    present: &mut Vec<AntiPhishingControl>,
    findings: &mut Vec<String>,
) {
    if let Some(val) = header_value(headers, "content-security-policy") {
        present.push(AntiPhishingControl::ContentSecurityPolicy);
        findings.push(format!("CSP header present: {}", truncate_value(val, 80)));
        if val.contains("frame-ancestors") && val.contains("'none'") || val.contains("'self'") {
            present.push(AntiPhishingControl::CspStrict);
            findings.push("CSP includes strict frame-ancestors directive".to_string());
        }
    }
}

fn check_sri_control(
    html: &str,
    present: &mut Vec<AntiPhishingControl>,
    findings: &mut Vec<String>,
) {
    let sri_re = Regex::new(r#"(?i)integrity\s*=\s*["']([^"']*)["']"#).unwrap();
    let sri_count = sri_re.find_iter(html).count();
    if sri_count > 0 {
        present.push(AntiPhishingControl::SubresourceIntegrity);
        findings.push(format!("{} elements with SRI hashes", sri_count));
    }
}

fn check_referrer_policy(
    headers: &[(&str, &str)],
    present: &mut Vec<AntiPhishingControl>,
    findings: &mut Vec<String>,
) {
    if let Some(val) = header_value(headers, "referrer-policy") {
        present.push(AntiPhishingControl::ReferrerPolicy);
        findings.push(format!("Referrer-Policy: {}", val));
    }
}

fn check_mfa_references(
    html: &str,
    present: &mut Vec<AntiPhishingControl>,
    findings: &mut Vec<String>,
) {
    let html_lower = html.to_lowercase();
    let mfa_indicators = [
        "two-factor",
        "2fa",
        "multi-factor",
        "mfa",
        "one-time password",
        "otp",
        "authenticator app",
        "totp",
    ];
    let found: Vec<&&str> = mfa_indicators
        .iter()
        .filter(|ind| html_lower.contains(**ind))
        .collect();
    if !found.is_empty() {
        present.push(AntiPhishingControl::Mfa);
        findings.push(format!(
            "MFA references found: {}",
            found.iter().map(|s| **s).collect::<Vec<_>>().join(", ")
        ));
    }
}

fn check_fido2_references(
    html: &str,
    present: &mut Vec<AntiPhishingControl>,
    findings: &mut Vec<String>,
) {
    let html_lower = html.to_lowercase();
    let fido_indicators = [
        "webauthn",
        "fido2",
        "navigator.credentials",
        "publickeycredential",
        "authenticatorattestationresponse",
    ];
    let found: Vec<&&str> = fido_indicators
        .iter()
        .filter(|ind| html_lower.contains(**ind))
        .collect();
    if !found.is_empty() {
        present.push(AntiPhishingControl::Fido2);
        findings.push(format!(
            "FIDO2/WebAuthn references found: {}",
            found.iter().map(|s| **s).collect::<Vec<_>>().join(", ")
        ));
    }
}

fn check_certificate_pinning(
    headers: &[(&str, &str)],
    present: &mut Vec<AntiPhishingControl>,
    findings: &mut Vec<String>,
) {
    if let Some(val) = header_value(headers, "public-key-pins") {
        present.push(AntiPhishingControl::CertificatePinning);
        findings.push(format!("HPKP header present: {}", truncate_value(val, 60)));
    }
    if header_value(headers, "expect-ct").is_some() {
        if !present.contains(&AntiPhishingControl::CertificatePinning) {
            present.push(AntiPhishingControl::CertificatePinning);
        }
        findings.push("Expect-CT header present".to_string());
    }
}

fn truncate_value(val: &str, max_len: usize) -> String {
    if val.len() <= max_len {
        val.to_string()
    } else {
        format!("{}...", &val[..max_len])
    }
}

/// Identify brand assets in HTML that an attacker could harvest for a clone.
pub fn analyze_brand_assets(html: &str, base_url: &str) -> BrandAssetExposure {
    let logos = extract_logo_urls(html, base_url);
    let css_urls = extract_css_urls(html, base_url);
    let favicon_url = extract_favicon(html, base_url);
    let brand_terms = extract_brand_terms(html);

    let mut exposure_parts = 0.0;
    let mut exposure_total = 0.0;

    exposure_total += 1.0;
    if !logos.is_empty() {
        exposure_parts += 1.0;
    }

    exposure_total += 1.0;
    if !css_urls.is_empty() {
        exposure_parts += 1.0;
    }

    exposure_total += 1.0;
    if favicon_url.is_some() {
        exposure_parts += 1.0;
    }

    exposure_total += 1.0;
    if !brand_terms.is_empty() {
        exposure_parts += 0.5 + (brand_terms.len().min(10) as f64 / 20.0);
    }

    let exposure_score = (exposure_parts / exposure_total).clamp(0.0, 1.0);

    BrandAssetExposure {
        logos_found: logos,
        css_urls,
        favicon_url,
        brand_terms,
        exposure_score,
    }
}

fn extract_logo_urls(html: &str, base_url: &str) -> Vec<String> {
    let img_re = Regex::new(r#"(?is)<img[^>]*src=["']([^"']*)["'][^>]*>"#).unwrap();
    img_re
        .captures_iter(html)
        .filter_map(|caps| {
            let tag = caps.get(0).unwrap().as_str().to_lowercase();
            let src = caps[1].to_string();
            let is_logo = LOGO_KEYWORDS.iter().any(|kw| tag.contains(kw))
                || extract_attr(caps.get(0).unwrap().as_str(), "alt")
                    .map(|a| LOGO_KEYWORDS.iter().any(|kw| a.to_lowercase().contains(kw)))
                    .unwrap_or(false)
                || extract_attr(caps.get(0).unwrap().as_str(), "class")
                    .map(|c| LOGO_KEYWORDS.iter().any(|kw| c.to_lowercase().contains(kw)))
                    .unwrap_or(false);

            if is_logo {
                Some(resolve_url(base_url, &src))
            } else {
                None
            }
        })
        .collect()
}

fn extract_css_urls(html: &str, base_url: &str) -> Vec<String> {
    let link_re = Regex::new(r#"(?is)<link[^>]*href=["']([^"']*)["'][^>]*>"#).unwrap();
    link_re
        .captures_iter(html)
        .filter_map(|caps| {
            let tag = caps.get(0).unwrap().as_str();
            let href = caps[1].to_string();
            let rel = extract_attr(tag, "rel").unwrap_or_default().to_lowercase();
            if rel.contains("stylesheet") {
                Some(resolve_url(base_url, &href))
            } else {
                None
            }
        })
        .collect()
}

fn extract_favicon(html: &str, base_url: &str) -> Option<String> {
    let link_re = Regex::new(r#"(?is)<link[^>]*href=["']([^"']*)["'][^>]*>"#).unwrap();
    link_re.captures_iter(html).find_map(|caps| {
        let tag = caps.get(0).unwrap().as_str();
        let href = caps[1].to_string();
        let rel = extract_attr(tag, "rel").unwrap_or_default().to_lowercase();
        if rel.contains("icon") {
            Some(resolve_url(base_url, &href))
        } else {
            None
        }
    })
}

fn extract_brand_terms(html: &str) -> Vec<String> {
    let html_lower = html.to_lowercase();
    BRAND_TERMS
        .iter()
        .filter(|term| html_lower.contains(**term))
        .map(|term| (*term).to_string())
        .collect()
}

pub(crate) fn resolve_url(base_url: &str, relative: &str) -> String {
    if relative.starts_with("http://") || relative.starts_with("https://") {
        return relative.to_string();
    }
    if relative.starts_with("//") {
        return format!("https:{}", relative);
    }
    let base = base_url.trim_end_matches('/');
    if relative.starts_with('/')
        && let Some(origin) = extract_origin(base)
    {
        return format!("{}{}", origin, relative);
    }
    format!("{}/{}", base, relative.trim_start_matches('/'))
}

fn determine_overall_risk(
    clonability: &ClonabilityScore,
    anti_phishing: &AntiPhishingAssessment,
    brand_exposure: &BrandAssetExposure,
    login_page_count: usize,
    suspicious_action_count: usize,
) -> PhishingRisk {
    let mut risk_score = 0.0;

    risk_score += clonability.overall * 30.0;
    risk_score += (1.0 - anti_phishing.resilience_score) * 25.0;
    risk_score += brand_exposure.exposure_score * 20.0;
    risk_score += (login_page_count.min(3) as f64 / 3.0) * 15.0;
    risk_score += (suspicious_action_count.min(3) as f64 / 3.0) * 10.0;

    match risk_score as u32 {
        80..=u32::MAX => PhishingRisk::Critical,
        60..=79 => PhishingRisk::High,
        40..=59 => PhishingRisk::Medium,
        20..=39 => PhishingRisk::Low,
        _ => PhishingRisk::Minimal,
    }
}

/// Comprehensive phishing susceptibility analysis combining all sub-analyses.
pub fn analyze_phishing_susceptibility(
    url: &str,
    html: &str,
    headers: &[(&str, &str)],
) -> PhishingAnalysisReport {
    let login_pages = fingerprint_login_page(url, html);
    let clonability = assess_clonability(html, headers);
    let form_actions = analyze_form_actions(url, &login_pages);
    let anti_phishing = assess_anti_phishing_controls(headers, html);
    let brand_exposure = analyze_brand_assets(html, url);

    let suspicious_count = form_actions.iter().filter(|a| a.suspicious).count();
    let overall_risk = determine_overall_risk(
        &clonability,
        &anti_phishing,
        &brand_exposure,
        login_pages.len(),
        suspicious_count,
    );

    PhishingAnalysisReport {
        url: url.to_string(),
        login_pages,
        clonability,
        form_actions,
        anti_phishing,
        brand_exposure,
        overall_risk,
    }
}

#[cfg(test)]
#[path = "phishing_analyzer_test.rs"]
mod phishing_analyzer_test;
