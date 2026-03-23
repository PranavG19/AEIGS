use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum CspIssue {
    Missing,
    UnsafeInline,
    UnsafeEval,
    WildcardSource,
    MissingObjectSrc,
    MissingFrameAncestors,
    DataUriInScript,
    BlobUriInScript,
    MissingBaseUri,
    ReportOnlyWithoutEnforcement,
}

impl std::fmt::Display for CspIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CspIssue::Missing => write!(f, "missing_csp"),
            CspIssue::UnsafeInline => write!(f, "unsafe_inline"),
            CspIssue::UnsafeEval => write!(f, "unsafe_eval"),
            CspIssue::WildcardSource => write!(f, "wildcard_source"),
            CspIssue::MissingObjectSrc => write!(f, "missing_object_src"),
            CspIssue::MissingFrameAncestors => write!(f, "missing_frame_ancestors"),
            CspIssue::DataUriInScript => write!(f, "data_uri_in_script"),
            CspIssue::BlobUriInScript => write!(f, "blob_uri_in_script"),
            CspIssue::MissingBaseUri => write!(f, "missing_base_uri"),
            CspIssue::ReportOnlyWithoutEnforcement => {
                write!(f, "report_only_without_enforcement")
            }
        }
    }
}

pub fn csp_severity(issue: &CspIssue) -> f64 {
    match issue {
        CspIssue::Missing => 6.0,
        CspIssue::UnsafeInline => 7.0,
        CspIssue::UnsafeEval => 7.5,
        CspIssue::WildcardSource => 6.5,
        CspIssue::MissingObjectSrc => 5.5,
        CspIssue::MissingFrameAncestors => 4.0,
        CspIssue::DataUriInScript => 6.0,
        CspIssue::BlobUriInScript => 5.5,
        CspIssue::MissingBaseUri => 4.5,
        CspIssue::ReportOnlyWithoutEnforcement => 3.0,
    }
}

pub fn audit_csp(target: &str) -> Vec<CspIssue> {
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
    analyze_csp(&body)
}

pub fn analyze_csp(body: &str) -> Vec<CspIssue> {
    let csp_meta = extract_csp_from_meta(body);
    let csp_report_only_meta = extract_csp_report_only_from_meta(body);

    match (csp_meta, csp_report_only_meta) {
        (None, None) => vec![CspIssue::Missing],
        (None, Some(_)) => vec![CspIssue::ReportOnlyWithoutEnforcement],
        (Some(policy), _) => parse_csp_policy(&policy),
    }
}

pub fn analyze_csp_header(header_value: Option<&str>) -> Vec<CspIssue> {
    match header_value {
        None => vec![CspIssue::Missing],
        Some(policy) => parse_csp_policy(policy),
    }
}

pub fn extract_csp_from_meta(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let mut search_start = 0;
    loop {
        let search_slice = &lower[search_start..];
        let meta_pos = search_slice.find("<meta")?;
        let absolute_start = search_start + meta_pos;
        let rest = &lower[absolute_start..];
        let tag_end = rest.find('>')?;
        let meta_tag = &rest[..tag_end];

        if meta_tag.contains("http-equiv")
            && meta_tag.contains("content-security-policy")
            && !meta_tag.contains("report-only")
        {
            let Some(content_start) = meta_tag.find("content=") else {
                search_start = absolute_start + tag_end + 1;
                continue;
            };
            let content_rest = &meta_tag[content_start + 8..];
            let quote_char = if content_rest.starts_with('"') {
                '"'
            } else if content_rest.starts_with('\'') {
                '\''
            } else {
                search_start = absolute_start + tag_end + 1;
                continue;
            };
            if let Some(content_value) = content_rest.strip_prefix(quote_char)
                && let Some(content_end) = content_value.find(quote_char)
            {
                let policy = &content_value[..content_end];
                return Some(policy.to_string());
            }
        }

        search_start = absolute_start + tag_end + 1;
        if search_start >= lower.len() {
            break;
        }
    }

    None
}

pub fn extract_csp_report_only_from_meta(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let mut search_start = 0;
    loop {
        let search_slice = &lower[search_start..];
        let meta_pos = search_slice.find("<meta")?;
        let absolute_start = search_start + meta_pos;
        let rest = &lower[absolute_start..];
        let tag_end = rest.find('>')?;
        let meta_tag = &rest[..tag_end];

        if meta_tag.contains("http-equiv")
            && meta_tag.contains("content-security-policy-report-only")
        {
            let Some(content_start) = meta_tag.find("content=") else {
                search_start = absolute_start + tag_end + 1;
                continue;
            };
            let content_rest = &meta_tag[content_start + 8..];
            let quote_char = if content_rest.starts_with('"') {
                '"'
            } else if content_rest.starts_with('\'') {
                '\''
            } else {
                search_start = absolute_start + tag_end + 1;
                continue;
            };
            if let Some(content_value) = content_rest.strip_prefix(quote_char)
                && let Some(content_end) = content_value.find(quote_char)
            {
                let policy = &content_value[..content_end];
                return Some(policy.to_string());
            }
        }

        search_start = absolute_start + tag_end + 1;
        if search_start >= lower.len() {
            break;
        }
    }

    None
}

pub fn parse_csp_policy(policy: &str) -> Vec<CspIssue> {
    let mut issues = Vec::new();
    let directives = parse_directives(policy);

    let script_src = directives
        .iter()
        .find(|(name, _)| *name == "script-src")
        .map(|(_, values)| values);
    let default_src = directives
        .iter()
        .find(|(name, _)| *name == "default-src")
        .map(|(_, values)| values);
    let object_src = directives
        .iter()
        .find(|(name, _)| *name == "object-src")
        .map(|(_, values)| values);
    let frame_ancestors = directives
        .iter()
        .find(|(name, _)| *name == "frame-ancestors")
        .map(|(_, values)| values);
    let base_uri = directives
        .iter()
        .find(|(name, _)| *name == "base-uri")
        .map(|(_, values)| values);

    let script_or_default = script_src.or(default_src);
    if let Some(values) = script_or_default {
        if values.iter().any(|v| *v == "'unsafe-inline'") {
            issues.push(CspIssue::UnsafeInline);
        }
        if values.iter().any(|v| *v == "'unsafe-eval'") {
            issues.push(CspIssue::UnsafeEval);
        }
        if values.iter().any(|v| *v == "data:") {
            issues.push(CspIssue::DataUriInScript);
        }
        if values.iter().any(|v| *v == "blob:") {
            issues.push(CspIssue::BlobUriInScript);
        }
        if values
            .iter()
            .any(|v| *v == "*" && !v.contains('.') && !v.starts_with("*."))
        {
            issues.push(CspIssue::WildcardSource);
        }
    }

    if let Some(values) = object_src.or(default_src)
        && values
            .iter()
            .any(|v| *v == "*" && !v.contains('.') && !v.starts_with("*."))
        && !issues.contains(&CspIssue::WildcardSource)
    {
        issues.push(CspIssue::WildcardSource);
    }

    if object_src.is_none() {
        issues.push(CspIssue::MissingObjectSrc);
    }

    if frame_ancestors.is_none() {
        issues.push(CspIssue::MissingFrameAncestors);
    }

    if base_uri.is_none() {
        issues.push(CspIssue::MissingBaseUri);
    }

    issues
}

pub fn parse_directives(policy: &str) -> Vec<(String, Vec<String>)> {
    let mut directives = Vec::new();
    let parts: Vec<&str> = policy.split(';').map(|s| s.trim()).collect();

    for part in parts {
        if part.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = part.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        let name = tokens[0].to_string();
        let values: Vec<String> = tokens[1..].iter().map(|s| s.to_string()).collect();
        directives.push((name, values));
    }

    directives
}

pub fn csp_to_operations(issues: &[CspIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                csp_severity(issue),
                0.5,
            )
        })
        .collect()
}

pub fn csp_findings_to_operations(issues: &[CspIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    csp_to_operations(issues, seq)
}
