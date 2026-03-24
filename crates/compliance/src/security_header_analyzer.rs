/// Comprehensive security header analyzer.
///
/// Parses and grades 12+ security-relevant HTTP response headers (A-F)
/// with specific remediation guidance per grade. Provides directive-level
/// CSP analysis and per-cookie attribute inspection.
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Grade {
    A,
    B,
    C,
    D,
    F,
}

impl Grade {
    pub fn as_str(&self) -> &'static str {
        match self {
            Grade::A => "A",
            Grade::B => "B",
            Grade::C => "C",
            Grade::D => "D",
            Grade::F => "F",
        }
    }
}

impl std::fmt::Display for Grade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderType {
    ContentSecurityPolicy,
    StrictTransportSecurity,
    XContentTypeOptions,
    XFrameOptions,
    ReferrerPolicy,
    PermissionsPolicy,
    CrossOriginEmbedderPolicy,
    CrossOriginOpenerPolicy,
    CrossOriginResourcePolicy,
    CacheControl,
    SetCookie,
    ReportingEndpoints,
}

impl HeaderType {
    pub fn header_name(&self) -> &'static str {
        match self {
            HeaderType::ContentSecurityPolicy => "Content-Security-Policy",
            HeaderType::StrictTransportSecurity => "Strict-Transport-Security",
            HeaderType::XContentTypeOptions => "X-Content-Type-Options",
            HeaderType::XFrameOptions => "X-Frame-Options",
            HeaderType::ReferrerPolicy => "Referrer-Policy",
            HeaderType::PermissionsPolicy => "Permissions-Policy",
            HeaderType::CrossOriginEmbedderPolicy => "Cross-Origin-Embedder-Policy",
            HeaderType::CrossOriginOpenerPolicy => "Cross-Origin-Opener-Policy",
            HeaderType::CrossOriginResourcePolicy => "Cross-Origin-Resource-Policy",
            HeaderType::CacheControl => "Cache-Control",
            HeaderType::SetCookie => "Set-Cookie",
            HeaderType::ReportingEndpoints => "Reporting-Endpoints",
        }
    }
}

impl std::fmt::Display for HeaderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.header_name())
    }
}

#[derive(Debug, Clone)]
pub struct HeaderAnalysis {
    pub header_type: HeaderType,
    pub grade: Grade,
    pub present: bool,
    pub raw_value: Option<String>,
    pub findings: Vec<String>,
    pub remediation: String,
}

#[derive(Debug, Clone)]
pub struct CspDirectiveAnalysis {
    pub directive: String,
    pub values: Vec<String>,
    pub has_unsafe_inline: bool,
    pub has_unsafe_eval: bool,
    pub has_nonce: bool,
    pub has_hash: bool,
    pub has_wildcard: bool,
    pub has_data_uri: bool,
}

#[derive(Debug, Clone)]
pub struct CookieAnalysis {
    pub name: String,
    pub has_secure: bool,
    pub has_httponly: bool,
    pub samesite: Option<String>,
    pub has_host_prefix: bool,
    pub has_secure_prefix: bool,
    pub findings: Vec<String>,
    pub grade: Grade,
}

#[derive(Debug, Clone)]
pub struct SecurityHeaderReport {
    pub header_analyses: Vec<HeaderAnalysis>,
    pub csp_directives: Vec<CspDirectiveAnalysis>,
    pub cookie_analyses: Vec<CookieAnalysis>,
    pub overall_grade: Grade,
}

/// Primary entry point: analyze a set of HTTP response headers.
///
/// `headers` maps lowercase header names to their values. Multiple
/// Set-Cookie values are semicolon-joined or provided as separate entries
/// in a `Vec<(String, String)>` via `analyze_header_pairs`.
pub fn analyze_headers(headers: &HashMap<String, String>) -> SecurityHeaderReport {
    let mut analyses = vec![
        analyze_csp(headers.get("content-security-policy")),
        analyze_hsts(headers.get("strict-transport-security")),
        analyze_xcto(headers.get("x-content-type-options")),
        analyze_xfo(headers.get("x-frame-options")),
        analyze_referrer_policy(headers.get("referrer-policy")),
        analyze_permissions_policy(headers.get("permissions-policy")),
        analyze_coep(headers.get("cross-origin-embedder-policy")),
        analyze_coop(headers.get("cross-origin-opener-policy")),
        analyze_corp(headers.get("cross-origin-resource-policy")),
        analyze_cache_control(headers.get("cache-control")),
        analyze_reporting(headers.get("reporting-endpoints"), headers.get("report-to")),
    ];

    let csp_directives = headers
        .get("content-security-policy")
        .map(|v| parse_csp_directives(v))
        .unwrap_or_default();

    let cookie_analyses = headers
        .get("set-cookie")
        .map(|v| analyze_cookies(v))
        .unwrap_or_default();

    let set_cookie_analysis = grade_set_cookie_overall(&cookie_analyses, headers.get("set-cookie"));
    analyses.push(set_cookie_analysis);

    let overall_grade = compute_overall_grade(&analyses);

    SecurityHeaderReport {
        header_analyses: analyses,
        csp_directives,
        cookie_analyses,
        overall_grade,
    }
}

/// Analyze headers from a list of (name, value) pairs. Handles duplicate
/// header names (e.g. multiple Set-Cookie lines) by joining with `; `.
pub fn analyze_header_pairs(pairs: &[(String, String)]) -> SecurityHeaderReport {
    let mut map: HashMap<String, String> = HashMap::new();
    for (name, value) in pairs {
        let key = name.to_ascii_lowercase();
        map.entry(key)
            .and_modify(|existing| {
                existing.push_str("; ");
                existing.push_str(value);
            })
            .or_insert_with(|| value.clone());
    }
    analyze_headers(&map)
}

fn analyze_csp(value: Option<&String>) -> HeaderAnalysis {
    let Some(raw) = value else {
        return missing_header(
            HeaderType::ContentSecurityPolicy,
            "Add a Content-Security-Policy header with restrictive directives: \
             default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
        );
    };

    let directives = parse_csp_directives(raw);
    let mut findings = Vec::new();
    let mut penalty: u32 = 0;

    let has_default_src = directives.iter().any(|d| d.directive == "default-src");
    if !has_default_src {
        findings
            .push("Missing default-src directive — no fallback for unlisted resource types".into());
        penalty += 2;
    }

    for d in &directives {
        if d.has_unsafe_inline {
            findings.push(format!(
                "{}: 'unsafe-inline' allows injected inline scripts/styles",
                d.directive
            ));
            penalty += 3;
        }
        if d.has_unsafe_eval {
            findings.push(format!(
                "{}: 'unsafe-eval' allows eval(), Function(), and similar sinks",
                d.directive
            ));
            penalty += 3;
        }
        if d.has_wildcard {
            findings.push(format!(
                "{}: wildcard (*) permits loading from any origin",
                d.directive
            ));
            penalty += 2;
        }
        if d.has_data_uri {
            findings.push(format!(
                "{}: data: URIs can be used to bypass CSP restrictions",
                d.directive
            ));
            penalty += 1;
        }
        if d.has_nonce || d.has_hash {
            findings.push(format!(
                "{}: uses nonce/hash — good practice for script allowlisting",
                d.directive
            ));
        }
    }

    let has_object_none = directives
        .iter()
        .any(|d| d.directive == "object-src" && d.values.contains(&"'none'".to_string()));
    if !has_object_none {
        findings
            .push("Missing object-src 'none' — plugins can be loaded without restriction".into());
        penalty += 1;
    }

    let has_base_uri = directives.iter().any(|d| d.directive == "base-uri");
    if !has_base_uri {
        findings.push("Missing base-uri directive — base tag injection possible".into());
        penalty += 1;
    }

    let grade = match penalty {
        0 => Grade::A,
        1..=2 => Grade::B,
        3..=4 => Grade::C,
        5..=6 => Grade::D,
        _ => Grade::F,
    };

    let remediation = match grade {
        Grade::A => "CSP is well-configured. Consider adding report-uri for monitoring.".into(),
        Grade::B => "CSP is solid but has minor gaps. Tighten source lists and add missing directives.".into(),
        Grade::C => "CSP has moderate weaknesses. Remove unsafe-inline/unsafe-eval where possible and restrict wildcards.".into(),
        Grade::D => "CSP provides limited protection. Replace unsafe directives with nonce-based allowlisting.".into(),
        Grade::F => "CSP is critically weak. Rewrite with strict nonce-based policy: default-src 'self'; script-src 'nonce-{random}'.".into(),
    };

    HeaderAnalysis {
        header_type: HeaderType::ContentSecurityPolicy,
        grade,
        present: true,
        raw_value: Some(raw.clone()),
        findings,
        remediation,
    }
}

fn parse_csp_directives(raw: &str) -> Vec<CspDirectiveAnalysis> {
    raw.split(';')
        .filter_map(|part| {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                return None;
            }
            let mut tokens = trimmed.split_whitespace();
            let directive = tokens.next()?.to_lowercase();
            let values: Vec<String> = tokens.map(|t| t.to_string()).collect();

            let has_unsafe_inline = values.iter().any(|v| v == "'unsafe-inline'");
            let has_unsafe_eval = values.iter().any(|v| v == "'unsafe-eval'");
            let has_nonce = values.iter().any(|v| v.starts_with("'nonce-"));
            let has_hash = values.iter().any(|v| {
                v.starts_with("'sha256-") || v.starts_with("'sha384-") || v.starts_with("'sha512-")
            });
            let has_wildcard = values.iter().any(|v| v == "*");
            let has_data_uri = values.iter().any(|v| v == "data:");

            Some(CspDirectiveAnalysis {
                directive,
                values,
                has_unsafe_inline,
                has_unsafe_eval,
                has_nonce,
                has_hash,
                has_wildcard,
                has_data_uri,
            })
        })
        .collect()
}

fn analyze_hsts(value: Option<&String>) -> HeaderAnalysis {
    let Some(raw) = value else {
        return missing_header(
            HeaderType::StrictTransportSecurity,
            "Add Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
        );
    };

    let lower = raw.to_lowercase();
    let mut findings = Vec::new();
    let mut penalty: u32 = 0;

    let max_age = extract_max_age(&lower);
    match max_age {
        Some(age) if age >= 31_536_000 => {
            findings.push(format!("max-age={age} (≥1 year) — adequate"));
        }
        Some(age) if age >= 86_400 => {
            findings.push(format!(
                "max-age={age} — below recommended minimum of 1 year (31536000)"
            ));
            penalty += 2;
        }
        Some(age) => {
            findings.push(format!(
                "max-age={age} — dangerously short, provides minimal protection"
            ));
            penalty += 4;
        }
        None => {
            findings.push("max-age directive missing or unparseable".into());
            penalty += 4;
        }
    }

    let has_subdomains = lower.contains("includesubdomains");
    if !has_subdomains {
        findings.push("Missing includeSubDomains — subdomains not covered by HSTS".into());
        penalty += 1;
    }

    let has_preload = lower.contains("preload");
    if !has_preload {
        findings.push("Missing preload — not eligible for browser HSTS preload lists".into());
        penalty += 1;
    }

    let grade = match penalty {
        0 => Grade::A,
        1 => Grade::B,
        2..=3 => Grade::C,
        4..=5 => Grade::D,
        _ => Grade::F,
    };

    let remediation = match grade {
        Grade::A => "HSTS is fully configured with long max-age, includeSubDomains, and preload.".into(),
        Grade::B => "HSTS is good. Add includeSubDomains and/or preload for full coverage.".into(),
        Grade::C => "Increase max-age to at least 31536000 (1 year) and add includeSubDomains.".into(),
        Grade::D => "HSTS max-age is too short. Set max-age=63072000; includeSubDomains; preload.".into(),
        Grade::F => "HSTS is misconfigured. Set: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload".into(),
    };

    HeaderAnalysis {
        header_type: HeaderType::StrictTransportSecurity,
        grade,
        present: true,
        raw_value: Some(raw.clone()),
        findings,
        remediation,
    }
}

fn extract_max_age(hsts_lower: &str) -> Option<u64> {
    for part in hsts_lower.split(';') {
        let trimmed = part.trim();
        if let Some(val_str) = trimmed.strip_prefix("max-age=") {
            return val_str.trim().parse::<u64>().ok();
        }
        if trimmed.starts_with("max-age") && trimmed.contains('=') {
            let val_str = trimmed.split('=').nth(1)?;
            return val_str.trim().parse::<u64>().ok();
        }
    }
    None
}

fn analyze_xcto(value: Option<&String>) -> HeaderAnalysis {
    let Some(raw) = value else {
        return missing_header(
            HeaderType::XContentTypeOptions,
            "Add X-Content-Type-Options: nosniff",
        );
    };

    let lower = raw.trim().to_lowercase();
    if lower == "nosniff" {
        HeaderAnalysis {
            header_type: HeaderType::XContentTypeOptions,
            grade: Grade::A,
            present: true,
            raw_value: Some(raw.clone()),
            findings: vec!["nosniff correctly set — MIME-type sniffing disabled".into()],
            remediation: "No action needed. Header is correctly configured.".into(),
        }
    } else {
        HeaderAnalysis {
            header_type: HeaderType::XContentTypeOptions,
            grade: Grade::D,
            present: true,
            raw_value: Some(raw.clone()),
            findings: vec![format!("Invalid value '{raw}' — only 'nosniff' is valid")],
            remediation: "Set X-Content-Type-Options: nosniff (the only valid value).".into(),
        }
    }
}

fn analyze_xfo(value: Option<&String>) -> HeaderAnalysis {
    let Some(raw) = value else {
        return missing_header(
            HeaderType::XFrameOptions,
            "Add X-Frame-Options: DENY (or SAMEORIGIN if framing is needed). \
             Prefer CSP frame-ancestors for modern browsers.",
        );
    };

    let upper = raw.trim().to_uppercase();
    let mut findings = Vec::new();
    let grade;

    if upper == "DENY" {
        findings.push("DENY — page cannot be framed by any origin".into());
        grade = Grade::A;
    } else if upper == "SAMEORIGIN" {
        findings.push("SAMEORIGIN — page can only be framed by same origin".into());
        grade = Grade::B;
    } else if upper.starts_with("ALLOW-FROM") {
        findings.push("ALLOW-FROM is deprecated and ignored by modern browsers".into());
        grade = Grade::D;
    } else {
        findings.push(format!(
            "Unrecognized value '{raw}' — header will be ignored by browsers"
        ));
        grade = Grade::F;
    }

    let remediation = match grade {
        Grade::A => "X-Frame-Options is correctly set to DENY. Consider also adding CSP frame-ancestors 'none'.".into(),
        Grade::B => "SAMEORIGIN is acceptable. Upgrade to DENY if framing is unnecessary.".into(),
        Grade::C => "Review framing requirements and tighten to DENY or SAMEORIGIN.".into(),
        Grade::D => "ALLOW-FROM is deprecated. Use CSP frame-ancestors directive instead.".into(),
        Grade::F => "Invalid value. Set to DENY or SAMEORIGIN.".into(),
    };

    HeaderAnalysis {
        header_type: HeaderType::XFrameOptions,
        grade,
        present: true,
        raw_value: Some(raw.clone()),
        findings,
        remediation,
    }
}

fn analyze_referrer_policy(value: Option<&String>) -> HeaderAnalysis {
    let Some(raw) = value else {
        return missing_header(HeaderType::ReferrerPolicy,
            "Add Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for maximum privacy)");
    };

    let lower = raw.trim().to_lowercase();
    let mut findings = Vec::new();

    let grade = match lower.as_str() {
        "no-referrer" => {
            findings.push("no-referrer — maximum privacy, no Referer header sent".into());
            Grade::A
        }
        "strict-origin-when-cross-origin" => {
            findings.push(
                "strict-origin-when-cross-origin — good balance of privacy and functionality"
                    .into(),
            );
            Grade::A
        }
        "same-origin" => {
            findings.push("same-origin — Referer only sent to same origin".into());
            Grade::A
        }
        "strict-origin" => {
            findings
                .push("strict-origin — sends origin on cross-origin, nothing on downgrade".into());
            Grade::B
        }
        "origin" => {
            findings.push(
                "origin — always sends origin (never full path), includes cross-origin".into(),
            );
            Grade::B
        }
        "origin-when-cross-origin" => {
            findings.push(
                "origin-when-cross-origin — full URL to same-origin, origin to cross-origin".into(),
            );
            Grade::C
        }
        "no-referrer-when-downgrade" => {
            findings.push(
                "no-referrer-when-downgrade — full URL sent to HTTPS origins, leaks path info"
                    .into(),
            );
            Grade::C
        }
        "unsafe-url" => {
            findings.push(
                "unsafe-url — full URL always sent, including to cross-origin and HTTP".into(),
            );
            Grade::F
        }
        _ => {
            findings.push(format!("Unrecognized policy value '{raw}'"));
            Grade::D
        }
    };

    let remediation = match grade {
        Grade::A => "Referrer-Policy is well-configured for privacy.".into(),
        Grade::B => "Referrer-Policy is acceptable. Consider strict-origin-when-cross-origin for better privacy.".into(),
        Grade::C => "Referrer-Policy leaks path information cross-origin. Use strict-origin-when-cross-origin.".into(),
        Grade::D => "Invalid Referrer-Policy value. Use: no-referrer, strict-origin-when-cross-origin, or same-origin.".into(),
        Grade::F => "unsafe-url leaks full URLs including paths and query parameters. Replace with strict-origin-when-cross-origin.".into(),
    };

    HeaderAnalysis {
        header_type: HeaderType::ReferrerPolicy,
        grade,
        present: true,
        raw_value: Some(raw.clone()),
        findings,
        remediation,
    }
}

fn analyze_permissions_policy(value: Option<&String>) -> HeaderAnalysis {
    let Some(raw) = value else {
        return missing_header(
            HeaderType::PermissionsPolicy,
            "Add Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
        );
    };

    let restricted_features = ["camera", "microphone", "geolocation", "payment"];
    let mut findings = Vec::new();
    let mut restricted_count = 0u32;

    for feature in &restricted_features {
        let pattern_empty_parens = format!("{feature}=()");
        let pattern_none = format!("{feature}=none");
        if raw.contains(&pattern_empty_parens) || raw.contains(&pattern_none) {
            restricted_count += 1;
            findings.push(format!(
                "{feature} is restricted — disabled for all origins"
            ));
        } else if raw.contains(feature) {
            findings.push(format!(
                "{feature} is present but not fully restricted — review allowed origins"
            ));
        } else {
            findings.push(format!(
                "{feature} not mentioned — browser defaults apply (typically allowed)"
            ));
        }
    }

    let grade = match restricted_count {
        4 => Grade::A,
        3 => Grade::B,
        2 => Grade::C,
        1 => Grade::D,
        _ => Grade::F,
    };

    let remediation = match grade {
        Grade::A => "Permissions-Policy restricts all sensitive features. Well configured.".into(),
        Grade::B => "Most sensitive features restricted. Disable remaining features with =().".into(),
        Grade::C => "Several sensitive features remain unrestricted. Add camera=(), microphone=(), geolocation=(), payment=().".into(),
        Grade::D => "Most sensitive features are unrestricted. Set Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=().".into(),
        Grade::F => "Permissions-Policy does not restrict sensitive features. Set: camera=(), microphone=(), geolocation=(), payment=().".into(),
    };

    HeaderAnalysis {
        header_type: HeaderType::PermissionsPolicy,
        grade,
        present: true,
        raw_value: Some(raw.clone()),
        findings,
        remediation,
    }
}

fn analyze_coep(value: Option<&String>) -> HeaderAnalysis {
    let Some(raw) = value else {
        return missing_header(
            HeaderType::CrossOriginEmbedderPolicy,
            "Add Cross-Origin-Embedder-Policy: require-corp to enable cross-origin isolation",
        );
    };

    let lower = raw.trim().to_lowercase();
    let mut findings = Vec::new();

    let grade = match lower.as_str() {
        "require-corp" => {
            findings.push("require-corp — only loads resources with CORP header or CORS".into());
            Grade::A
        }
        "credentialless" => {
            findings.push("credentialless — cross-origin requests omit credentials (more compatible than require-corp)".into());
            Grade::B
        }
        "unsafe-none" => {
            findings.push("unsafe-none — cross-origin isolation disabled".into());
            Grade::D
        }
        _ => {
            findings.push(format!("Unrecognized COEP value '{raw}'"));
            Grade::F
        }
    };

    let remediation = match grade {
        Grade::A => "COEP is correctly set to require-corp for full cross-origin isolation.".into(),
        Grade::B => {
            "credentialless provides partial isolation. Upgrade to require-corp when possible."
                .into()
        }
        Grade::C | Grade::D => {
            "COEP set to unsafe-none disables isolation. Use require-corp for Spectre mitigation."
                .into()
        }
        Grade::F => "Invalid COEP value. Use require-corp or credentialless.".into(),
    };

    HeaderAnalysis {
        header_type: HeaderType::CrossOriginEmbedderPolicy,
        grade,
        present: true,
        raw_value: Some(raw.clone()),
        findings,
        remediation,
    }
}

fn analyze_coop(value: Option<&String>) -> HeaderAnalysis {
    let Some(raw) = value else {
        return missing_header(
            HeaderType::CrossOriginOpenerPolicy,
            "Add Cross-Origin-Opener-Policy: same-origin to isolate browsing context",
        );
    };

    let lower = raw.trim().to_lowercase();
    let mut findings = Vec::new();

    let grade = match lower.as_str() {
        "same-origin" => {
            findings
                .push("same-origin — browsing context isolated from cross-origin popups".into());
            Grade::A
        }
        "same-origin-allow-popups" => {
            findings.push(
                "same-origin-allow-popups — partial isolation, popups can retain reference".into(),
            );
            Grade::B
        }
        "unsafe-none" => {
            findings.push("unsafe-none — no browsing context isolation".into());
            Grade::D
        }
        _ => {
            findings.push(format!("Unrecognized COOP value '{raw}'"));
            Grade::F
        }
    };

    let remediation = match grade {
        Grade::A => "COOP is correctly configured for same-origin isolation.".into(),
        Grade::B => "same-origin-allow-popups provides partial isolation. Upgrade to same-origin if popups are not needed.".into(),
        Grade::C | Grade::D => "COOP disabled. Set Cross-Origin-Opener-Policy: same-origin for Spectre mitigation.".into(),
        Grade::F => "Invalid COOP value. Use same-origin or same-origin-allow-popups.".into(),
    };

    HeaderAnalysis {
        header_type: HeaderType::CrossOriginOpenerPolicy,
        grade,
        present: true,
        raw_value: Some(raw.clone()),
        findings,
        remediation,
    }
}

fn analyze_corp(value: Option<&String>) -> HeaderAnalysis {
    let Some(raw) = value else {
        return missing_header(HeaderType::CrossOriginResourcePolicy,
            "Add Cross-Origin-Resource-Policy: same-origin (or same-site if cross-subdomain access needed)");
    };

    let lower = raw.trim().to_lowercase();
    let mut findings = Vec::new();

    let grade = match lower.as_str() {
        "same-origin" => {
            findings.push("same-origin — resources only loadable by same origin".into());
            Grade::A
        }
        "same-site" => {
            findings
                .push("same-site — resources loadable by same site (includes subdomains)".into());
            Grade::B
        }
        "cross-origin" => {
            findings
                .push("cross-origin — resources loadable by any origin (no restriction)".into());
            Grade::D
        }
        _ => {
            findings.push(format!("Unrecognized CORP value '{raw}'"));
            Grade::F
        }
    };

    let remediation = match grade {
        Grade::A => "CORP restricts resource loading to same-origin. Well configured.".into(),
        Grade::B => "same-site is acceptable. Tighten to same-origin if cross-subdomain loading is not required.".into(),
        Grade::C => "Review resource sharing requirements.".into(),
        Grade::D => "cross-origin allows unrestricted resource loading. Set to same-origin or same-site.".into(),
        Grade::F => "Invalid CORP value. Use same-origin, same-site, or cross-origin.".into(),
    };

    HeaderAnalysis {
        header_type: HeaderType::CrossOriginResourcePolicy,
        grade,
        present: true,
        raw_value: Some(raw.clone()),
        findings,
        remediation,
    }
}

fn analyze_cache_control(value: Option<&String>) -> HeaderAnalysis {
    let Some(raw) = value else {
        return missing_header(HeaderType::CacheControl,
            "Add Cache-Control: no-store for pages with sensitive content; no-cache, private for authenticated pages");
    };

    let lower = raw.to_lowercase();
    let mut findings = Vec::new();
    let mut penalty: u32 = 0;

    if lower.contains("no-store") {
        findings.push("no-store present — responses not persisted to disk".into());
    } else {
        findings.push("Missing no-store — sensitive responses may be cached to disk".into());
        penalty += 2;
    }

    if lower.contains("private") {
        findings.push("private — shared caches (CDNs/proxies) will not cache".into());
    } else if lower.contains("public") {
        findings.push(
            "public — response may be cached by shared proxies (risky for authenticated content)"
                .into(),
        );
        penalty += 2;
    }

    if lower.contains("no-cache") {
        findings.push("no-cache — must revalidate before reuse".into());
    }

    if lower.contains("must-revalidate") {
        findings.push("must-revalidate present — stale responses not served".into());
    }

    let grade = match penalty {
        0 => Grade::A,
        1 => Grade::B,
        2 => Grade::C,
        3 => Grade::D,
        _ => Grade::F,
    };

    let remediation = match grade {
        Grade::A => "Cache-Control is well-configured for security-sensitive content.".into(),
        Grade::B => "Cache-Control is mostly adequate. Add no-store for sensitive pages.".into(),
        Grade::C => "Cache-Control allows disk caching. Use no-store for sensitive content, private for authenticated pages.".into(),
        Grade::D => "Cache-Control is weak. Set Cache-Control: no-store, no-cache, private, must-revalidate for sensitive pages.".into(),
        Grade::F => "Cache-Control allows public caching without restrictions. Set no-store for sensitive pages.".into(),
    };

    HeaderAnalysis {
        header_type: HeaderType::CacheControl,
        grade,
        present: true,
        raw_value: Some(raw.clone()),
        findings,
        remediation,
    }
}

fn analyze_cookies(raw: &str) -> Vec<CookieAnalysis> {
    // Multiple Set-Cookie values joined by "; " in analyze_header_pairs.
    // Each individual cookie is a full "name=val; attr; attr" string.
    // When joined, the boundary between cookies looks like "...; name2=val2; ..."
    // Split on "; " then re-assemble: a segment containing '=' at position >0
    // that is NOT a known attribute starts a new cookie.
    let mut cookies = Vec::new();
    let mut current = String::new();

    for segment in raw.split("; ") {
        let lower = segment.to_lowercase();
        let is_attribute = lower == "secure"
            || lower == "httponly"
            || lower.starts_with("samesite=")
            || lower.starts_with("max-age=")
            || lower.starts_with("expires=")
            || lower.starts_with("domain=")
            || lower.starts_with("path=");

        if is_attribute || !segment.contains('=') {
            if !current.is_empty() {
                current.push_str("; ");
            }
            current.push_str(segment);
        } else if current.is_empty() {
            current.push_str(segment);
        } else {
            cookies.push(analyze_single_cookie(&current));
            current = segment.to_string();
        }
    }

    if !current.is_empty() {
        cookies.push(analyze_single_cookie(&current));
    }

    cookies
}

fn analyze_single_cookie(cookie_str: &str) -> CookieAnalysis {
    let lower = cookie_str.to_lowercase();
    let name = cookie_str
        .split('=')
        .next()
        .unwrap_or("unknown")
        .trim()
        .to_string();

    let has_secure = lower.contains("secure");
    let has_httponly = lower.contains("httponly");
    let samesite = extract_samesite(&lower);
    let has_host_prefix = name.starts_with("__Host-");
    let has_secure_prefix = name.starts_with("__Secure-");

    let mut findings = Vec::new();
    let mut penalty: u32 = 0;

    if !has_secure {
        findings.push(format!(
            "{name}: missing Secure flag — cookie sent over HTTP"
        ));
        penalty += 2;
    }
    if !has_httponly {
        findings.push(format!(
            "{name}: missing HttpOnly flag — accessible via JavaScript"
        ));
        penalty += 2;
    }
    match &samesite {
        Some(val) if val == "strict" => {
            findings.push(format!("{name}: SameSite=Strict — maximum CSRF protection"));
        }
        Some(val) if val == "lax" => {
            findings.push(format!("{name}: SameSite=Lax — moderate CSRF protection"));
            penalty += 1;
        }
        Some(val) if val == "none" => {
            findings.push(format!(
                "{name}: SameSite=None — cookie sent in all cross-site requests"
            ));
            penalty += 2;
        }
        _ => {
            findings.push(format!(
                "{name}: SameSite not set — defaults to Lax in modern browsers"
            ));
            penalty += 1;
        }
    }

    if has_host_prefix {
        findings.push(format!(
            "{name}: __Host- prefix enforces Secure, Path=/, no Domain"
        ));
    } else if has_secure_prefix {
        findings.push(format!("{name}: __Secure- prefix enforces Secure flag"));
    }

    let grade = match penalty {
        0 => Grade::A,
        1 => Grade::B,
        2..=3 => Grade::C,
        4..=5 => Grade::D,
        _ => Grade::F,
    };

    CookieAnalysis {
        name,
        has_secure,
        has_httponly,
        samesite,
        has_host_prefix,
        has_secure_prefix,
        findings,
        grade,
    }
}

fn extract_samesite(lower: &str) -> Option<String> {
    for part in lower.split(';') {
        let trimmed = part.trim();
        if let Some(val) = trimmed.strip_prefix("samesite=") {
            return Some(val.trim().to_string());
        }
    }
    None
}

fn grade_set_cookie_overall(cookies: &[CookieAnalysis], raw: Option<&String>) -> HeaderAnalysis {
    if cookies.is_empty() {
        return missing_header(
            HeaderType::SetCookie,
            "No cookies detected. When adding cookies, always set Secure; HttpOnly; SameSite=Strict.",
        );
    }

    let worst_grade = cookies.iter().map(|c| c.grade).max().unwrap_or(Grade::A);

    let all_findings: Vec<String> = cookies.iter().flat_map(|c| c.findings.clone()).collect();

    let remediation = match worst_grade {
        Grade::A => "All cookies have proper security attributes.".into(),
        Grade::B => "Cookies are mostly secure. Set SameSite=Strict where possible.".into(),
        Grade::C => "Some cookies missing Secure or HttpOnly. Add both flags to all session cookies.".into(),
        Grade::D => "Multiple cookie security attributes missing. Set Secure; HttpOnly; SameSite=Strict on all cookies.".into(),
        Grade::F => "Cookies are critically insecure. Add Secure; HttpOnly; SameSite=Strict to all cookies.".into(),
    };

    HeaderAnalysis {
        header_type: HeaderType::SetCookie,
        grade: worst_grade,
        present: true,
        raw_value: raw.cloned(),
        findings: all_findings,
        remediation,
    }
}

fn analyze_reporting(
    reporting_endpoints: Option<&String>,
    report_to: Option<&String>,
) -> HeaderAnalysis {
    let has_endpoints = reporting_endpoints.is_some();
    let has_report_to = report_to.is_some();

    if !has_endpoints && !has_report_to {
        return missing_header(
            HeaderType::ReportingEndpoints,
            "Add Reporting-Endpoints header to receive CSP, COEP, and COOP violation reports. \
             Example: Reporting-Endpoints: csp-endpoint=\"https://example.com/csp-report\"",
        );
    }

    let mut findings = Vec::new();
    let mut grade = Grade::A;

    if has_endpoints {
        findings
            .push("Reporting-Endpoints header present — modern reporting API configured".into());
    }
    if has_report_to {
        findings.push(
            "Report-To header present (legacy) — consider migrating to Reporting-Endpoints".into(),
        );
        if !has_endpoints {
            grade = Grade::B;
        }
    }

    let raw = reporting_endpoints.or(report_to).cloned();

    let remediation = match grade {
        Grade::A => "Reporting is well-configured with modern Reporting-Endpoints.".into(),
        Grade::B => {
            "Using legacy Report-To. Migrate to Reporting-Endpoints for modern browser support."
                .into()
        }
        _ => "Configure Reporting-Endpoints for violation reporting.".into(),
    };

    HeaderAnalysis {
        header_type: HeaderType::ReportingEndpoints,
        grade,
        present: true,
        raw_value: raw,
        findings,
        remediation,
    }
}

fn missing_header(header_type: HeaderType, remediation: &str) -> HeaderAnalysis {
    HeaderAnalysis {
        header_type,
        grade: Grade::F,
        present: false,
        raw_value: None,
        findings: vec!["Header is missing entirely".into()],
        remediation: remediation.to_string(),
    }
}

fn compute_overall_grade(analyses: &[HeaderAnalysis]) -> Grade {
    if analyses.is_empty() {
        return Grade::F;
    }

    let total: u32 = analyses
        .iter()
        .map(|a| match a.grade {
            Grade::A => 4,
            Grade::B => 3,
            Grade::C => 2,
            Grade::D => 1,
            Grade::F => 0,
        })
        .sum();

    let avg = total as f64 / analyses.len() as f64;

    if avg >= 3.5 {
        Grade::A
    } else if avg >= 2.5 {
        Grade::B
    } else if avg >= 1.5 {
        Grade::C
    } else if avg >= 0.5 {
        Grade::D
    } else {
        Grade::F
    }
}
