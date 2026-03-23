use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum MetaRedirectIssue {
    MetaRefreshRedirect { url: String },
    MetaRefreshShortDelay,
    JavascriptRedirect,
    WindowLocationAssign,
    DocumentWriteRedirect,
    HistoryReplaceState,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MetaRedirectSecurityIssue {
    JavascriptSchemeRedirect { url: String },
    DataSchemeRedirect { url: String },
    OpenRedirectViaMeta { url: String },
    ChainedMetaRedirects { count: usize },
    ZeroDelayRedirect,
    LongDelayRedirect { delay: u32 },
    MetaRedirectWithFragment { url: String },
    MetaRedirectInIframe,
    MetaRedirectToPhishing { url: String },
    MetaRedirectEncodedUrl { url: String },
}

impl std::fmt::Display for MetaRedirectIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MetaRefreshRedirect { url } => write!(f, "meta_refresh:{url}"),
            Self::MetaRefreshShortDelay => write!(f, "meta_refresh_short_delay"),
            Self::JavascriptRedirect => write!(f, "javascript_redirect"),
            Self::WindowLocationAssign => write!(f, "window_location_assign"),
            Self::DocumentWriteRedirect => write!(f, "document_write_redirect"),
            Self::HistoryReplaceState => write!(f, "history_replace_state"),
        }
    }
}

impl std::fmt::Display for MetaRedirectSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JavascriptSchemeRedirect { url } => write!(f, "javascript_scheme_redirect:{url}"),
            Self::DataSchemeRedirect { url } => write!(f, "data_scheme_redirect:{url}"),
            Self::OpenRedirectViaMeta { url } => write!(f, "open_redirect_via_meta:{url}"),
            Self::ChainedMetaRedirects { count } => write!(f, "chained_meta_redirects:{count}"),
            Self::ZeroDelayRedirect => write!(f, "zero_delay_redirect"),
            Self::LongDelayRedirect { delay } => write!(f, "long_delay_redirect:{delay}"),
            Self::MetaRedirectWithFragment { url } => {
                write!(f, "meta_redirect_with_fragment:{url}")
            }
            Self::MetaRedirectInIframe => write!(f, "meta_redirect_in_iframe"),
            Self::MetaRedirectToPhishing { url } => write!(f, "meta_redirect_to_phishing:{url}"),
            Self::MetaRedirectEncodedUrl { url } => write!(f, "meta_redirect_encoded_url:{url}"),
        }
    }
}

pub fn audit_meta_redirect(target: &str) -> Vec<MetaRedirectIssue> {
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
    analyze_meta_redirect(&body)
}

pub fn analyze_meta_redirect(body: &str) -> Vec<MetaRedirectIssue> {
    if !has_redirect_indicators(body) {
        return Vec::new();
    }

    let mut issues = Vec::new();

    let lower = body.to_ascii_lowercase();
    check_meta_refresh(&lower, &mut issues);

    if body.contains("location.href =")
        || body.contains("location.href=")
        || body.contains("location =")
        || body.contains("location.replace(")
    {
        issues.push(MetaRedirectIssue::JavascriptRedirect);
    }

    if body.contains("location.assign(") {
        issues.push(MetaRedirectIssue::WindowLocationAssign);
    }

    if (body.contains("document.write(") || body.contains("document.writeln("))
        && (body.contains("location") || body.contains("redirect"))
    {
        issues.push(MetaRedirectIssue::DocumentWriteRedirect);
    }

    if body.contains("history.replaceState") && body.contains("location") {
        issues.push(MetaRedirectIssue::HistoryReplaceState);
    }

    issues
}

fn has_redirect_indicators(body: &str) -> bool {
    body.contains("http-equiv")
        || body.contains("HTTP-EQUIV")
        || body.contains("location.href")
        || body.contains("location.replace")
        || body.contains("location.assign")
        || body.contains("location =")
        || body.contains("document.write")
        || body.contains("history.replaceState")
}

fn check_meta_refresh(lower: &str, issues: &mut Vec<MetaRedirectIssue>) {
    if !lower.contains("http-equiv") {
        return;
    }
    let mut pos = 0;
    while let Some(idx) = lower[pos..].find("http-equiv") {
        let abs = pos + idx;
        let ctx_start = abs.saturating_sub(50);
        let ctx_end = (abs + 200).min(lower.len());
        let ctx = &lower[ctx_start..ctx_end];

        if ctx.contains("refresh")
            && let Some(content_idx) = ctx.find("content=")
        {
            let rest = &ctx[content_idx + 8..];
            let rest = rest.trim_start_matches(['"', '\'']);
            if let Some(url_idx) = rest.find("url=") {
                let url_rest = &rest[url_idx + 4..];
                let end = url_rest.find(['"', '\'', '>']).unwrap_or(url_rest.len());
                let url = url_rest[..end].trim();
                if !url.is_empty() {
                    issues.push(MetaRedirectIssue::MetaRefreshRedirect {
                        url: url.to_string(),
                    });
                }
            }

            let delay = rest
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>();
            if let Ok(d) = delay.parse::<u32>()
                && d <= 1
            {
                issues.push(MetaRedirectIssue::MetaRefreshShortDelay);
            }
        }
        pos = abs + 10;
    }
}

pub fn meta_redirect_severity(issue: &MetaRedirectIssue) -> f64 {
    match issue {
        MetaRedirectIssue::DocumentWriteRedirect => 6.5,
        MetaRedirectIssue::MetaRefreshRedirect { .. } => 5.5,
        MetaRedirectIssue::JavascriptRedirect => 5.0,
        MetaRedirectIssue::WindowLocationAssign => 4.5,
        MetaRedirectIssue::HistoryReplaceState => 4.0,
        MetaRedirectIssue::MetaRefreshShortDelay => 3.5,
    }
}

pub fn meta_redirect_to_operations(
    issues: &[MetaRedirectIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::OpenRedirect,
                meta_redirect_severity(issue),
                0.7,
            )
        })
        .collect()
}

pub fn analyze_meta_redirect_security(html: &str) -> Vec<MetaRedirectSecurityIssue> {
    let mut issues = Vec::new();

    let lower = html.to_ascii_lowercase();

    check_dangerous_scheme_redirects(&lower, &mut issues);
    check_external_redirects(&lower, &mut issues);
    check_chained_redirects(&lower, &mut issues);
    check_redirect_delays(&lower, &mut issues);
    check_fragment_redirects(&lower, &mut issues);
    check_iframe_context(html, &mut issues);
    check_phishing_redirects(&lower, &mut issues);
    check_encoded_urls(&lower, &mut issues);

    issues
}

fn check_dangerous_scheme_redirects(lower: &str, issues: &mut Vec<MetaRedirectSecurityIssue>) {
    if !lower.contains("http-equiv") {
        return;
    }

    let mut pos = 0;
    while let Some(idx) = lower[pos..].find("http-equiv") {
        let abs = pos + idx;
        let ctx_start = abs.saturating_sub(50);
        let ctx_end = (abs + 300).min(lower.len());
        let ctx = &lower[ctx_start..ctx_end];

        if ctx.contains("refresh")
            && let Some(url_idx) = ctx.find("url=")
        {
            let url_rest = &ctx[url_idx + 4..];
            let end = url_rest
                .find(['"', '\'', '>', ' '])
                .unwrap_or(url_rest.len());
            let url = url_rest[..end].trim();

            if url.starts_with("javascript:") {
                issues.push(MetaRedirectSecurityIssue::JavascriptSchemeRedirect {
                    url: url.to_string(),
                });
            }

            if url.starts_with("data:") {
                issues.push(MetaRedirectSecurityIssue::DataSchemeRedirect {
                    url: url.to_string(),
                });
            }
        }

        pos = abs + 10;
    }
}

fn check_external_redirects(lower: &str, issues: &mut Vec<MetaRedirectSecurityIssue>) {
    if !lower.contains("http-equiv") {
        return;
    }

    let mut pos = 0;
    while let Some(idx) = lower[pos..].find("http-equiv") {
        let abs = pos + idx;
        let ctx_start = abs.saturating_sub(50);
        let ctx_end = (abs + 300).min(lower.len());
        let ctx = &lower[ctx_start..ctx_end];

        if ctx.contains("refresh")
            && let Some(url_idx) = ctx.find("url=")
        {
            let url_rest = &ctx[url_idx + 4..];
            let end = url_rest
                .find(['"', '\'', '>', ' '])
                .unwrap_or(url_rest.len());
            let url = url_rest[..end].trim();

            if (url.starts_with("http://") || url.starts_with("https://"))
                && !url.contains("localhost")
                && !url.contains("127.0.0.1")
            {
                issues.push(MetaRedirectSecurityIssue::OpenRedirectViaMeta {
                    url: url.to_string(),
                });
            }
        }

        pos = abs + 10;
    }
}

fn check_chained_redirects(lower: &str, issues: &mut Vec<MetaRedirectSecurityIssue>) {
    let count = lower.matches("http-equiv").filter(|_| true).count();

    if count > 1 {
        let refresh_count = lower
            .split("http-equiv")
            .filter(|section| section.contains("refresh"))
            .count();

        if refresh_count > 1 {
            issues.push(MetaRedirectSecurityIssue::ChainedMetaRedirects {
                count: refresh_count,
            });
        }
    }
}

fn check_redirect_delays(lower: &str, issues: &mut Vec<MetaRedirectSecurityIssue>) {
    if !lower.contains("http-equiv") {
        return;
    }

    let mut pos = 0;
    while let Some(idx) = lower[pos..].find("http-equiv") {
        let abs = pos + idx;
        let ctx_start = abs.saturating_sub(50);
        let ctx_end = (abs + 300).min(lower.len());
        let ctx = &lower[ctx_start..ctx_end];

        if ctx.contains("refresh")
            && let Some(content_idx) = ctx.find("content=")
        {
            let rest = &ctx[content_idx + 8..];
            let rest = rest.trim_start_matches(['"', '\'']);

            let delay = rest
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>();

            if let Ok(d) = delay.parse::<u32>() {
                if d == 0 {
                    issues.push(MetaRedirectSecurityIssue::ZeroDelayRedirect);
                } else if d >= 30 {
                    issues.push(MetaRedirectSecurityIssue::LongDelayRedirect { delay: d });
                }
            }
        }

        pos = abs + 10;
    }
}

fn check_fragment_redirects(lower: &str, issues: &mut Vec<MetaRedirectSecurityIssue>) {
    if !lower.contains("http-equiv") {
        return;
    }

    let mut pos = 0;
    while let Some(idx) = lower[pos..].find("http-equiv") {
        let abs = pos + idx;
        let ctx_start = abs.saturating_sub(50);
        let ctx_end = (abs + 300).min(lower.len());
        let ctx = &lower[ctx_start..ctx_end];

        if ctx.contains("refresh")
            && let Some(url_idx) = ctx.find("url=")
        {
            let url_rest = &ctx[url_idx + 4..];
            let end = url_rest
                .find(['"', '\'', '>', ' '])
                .unwrap_or(url_rest.len());
            let url = url_rest[..end].trim();

            if url.contains('#') {
                issues.push(MetaRedirectSecurityIssue::MetaRedirectWithFragment {
                    url: url.to_string(),
                });
            }
        }

        pos = abs + 10;
    }
}

fn check_iframe_context(html: &str, issues: &mut Vec<MetaRedirectSecurityIssue>) {
    let lower = html.to_ascii_lowercase();

    if !lower.contains("<iframe") || !lower.contains("http-equiv") {
        return;
    }

    let mut iframe_positions = Vec::new();
    let mut pos = 0;
    while let Some(idx) = lower[pos..].find("<iframe") {
        let abs = pos + idx;
        if let Some(end_idx) = lower[abs..].find("</iframe>") {
            iframe_positions.push((abs, abs + end_idx + 9));
        }
        pos = abs + 7;
    }

    pos = 0;
    while let Some(idx) = lower[pos..].find("http-equiv") {
        let abs = pos + idx;

        for &(start, end) in &iframe_positions {
            if abs >= start && abs < end {
                let ctx = &lower[abs.saturating_sub(50)..(abs + 200).min(lower.len())];
                if ctx.contains("refresh") {
                    issues.push(MetaRedirectSecurityIssue::MetaRedirectInIframe);
                    break;
                }
            }
        }

        pos = abs + 10;
    }
}

fn check_phishing_redirects(lower: &str, issues: &mut Vec<MetaRedirectSecurityIssue>) {
    const PHISHING_INDICATORS: &[&str] = &[
        "login", "signin", "verify", "account", "secure", "update", "confirm", "bank", "paypal",
        "amazon",
    ];

    if !lower.contains("http-equiv") {
        return;
    }

    let mut pos = 0;
    while let Some(idx) = lower[pos..].find("http-equiv") {
        let abs = pos + idx;
        let ctx_start = abs.saturating_sub(50);
        let ctx_end = (abs + 300).min(lower.len());
        let ctx = &lower[ctx_start..ctx_end];

        if ctx.contains("refresh")
            && let Some(url_idx) = ctx.find("url=")
        {
            let url_rest = &ctx[url_idx + 4..];
            let end = url_rest
                .find(['"', '\'', '>', ' '])
                .unwrap_or(url_rest.len());
            let url = url_rest[..end].trim();

            for &indicator in PHISHING_INDICATORS {
                if url.contains(indicator) {
                    issues.push(MetaRedirectSecurityIssue::MetaRedirectToPhishing {
                        url: url.to_string(),
                    });
                    break;
                }
            }
        }

        pos = abs + 10;
    }
}

fn check_encoded_urls(lower: &str, issues: &mut Vec<MetaRedirectSecurityIssue>) {
    if !lower.contains("http-equiv") {
        return;
    }

    let mut pos = 0;
    while let Some(idx) = lower[pos..].find("http-equiv") {
        let abs = pos + idx;
        let ctx_start = abs.saturating_sub(50);
        let ctx_end = (abs + 300).min(lower.len());
        let ctx = &lower[ctx_start..ctx_end];

        if ctx.contains("refresh")
            && let Some(url_idx) = ctx.find("url=")
        {
            let url_rest = &ctx[url_idx + 4..];
            let end = url_rest
                .find(['"', '\'', '>', ' '])
                .unwrap_or(url_rest.len());
            let url = url_rest[..end].trim();

            if url.contains("%2f") || url.contains("%3a") || url.contains("%2e") {
                issues.push(MetaRedirectSecurityIssue::MetaRedirectEncodedUrl {
                    url: url.to_string(),
                });
            }
        }

        pos = abs + 10;
    }
}

pub fn meta_redirect_security_severity(issue: &MetaRedirectSecurityIssue) -> f64 {
    match issue {
        MetaRedirectSecurityIssue::JavascriptSchemeRedirect { .. } => 9.0,
        MetaRedirectSecurityIssue::DataSchemeRedirect { .. } => 8.5,
        MetaRedirectSecurityIssue::OpenRedirectViaMeta { .. } => 7.5,
        MetaRedirectSecurityIssue::MetaRedirectToPhishing { .. } => 8.0,
        MetaRedirectSecurityIssue::ChainedMetaRedirects { .. } => 6.5,
        MetaRedirectSecurityIssue::MetaRedirectWithFragment { .. } => 7.0,
        MetaRedirectSecurityIssue::MetaRedirectEncodedUrl { .. } => 6.0,
        MetaRedirectSecurityIssue::MetaRedirectInIframe => 5.5,
        MetaRedirectSecurityIssue::LongDelayRedirect { .. } => 5.0,
        MetaRedirectSecurityIssue::ZeroDelayRedirect => 4.5,
    }
}

pub fn meta_redirect_security_to_operations(
    issues: &[MetaRedirectSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                meta_redirect_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
