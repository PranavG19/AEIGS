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
