use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::html_parser::{self, TagIter};
use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum OpenerIssue {
    MissingNoopener { href: String },
    MissingNoreferrer { href: String },
    FormTargetBlank { action: String },
    AreaTargetBlank { href: String },
    BaseTargetBlank,
    WindowOpenNoFeatures { context: String },
    JavascriptWindowOpen,
    ExternalLinkNoRel { href: String },
    UserContentLink { href: String },
}

impl std::fmt::Display for OpenerIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingNoopener { href } => write!(f, "missing_noopener:{href}"),
            Self::MissingNoreferrer { href } => write!(f, "missing_noreferrer:{href}"),
            Self::FormTargetBlank { action } => write!(f, "form_target_blank:{action}"),
            Self::AreaTargetBlank { href } => write!(f, "area_target_blank:{href}"),
            Self::BaseTargetBlank => write!(f, "base_target_blank"),
            Self::WindowOpenNoFeatures { context } => {
                write!(f, "window_open_no_features:{context}")
            }
            Self::JavascriptWindowOpen => write!(f, "javascript_window_open"),
            Self::ExternalLinkNoRel { href } => write!(f, "external_link_no_rel:{href}"),
            Self::UserContentLink { href } => write!(f, "user_content_link:{href}"),
        }
    }
}

pub fn opener_severity(issue: &OpenerIssue) -> f64 {
    match issue {
        OpenerIssue::MissingNoopener { .. } => 3.5,
        OpenerIssue::MissingNoreferrer { .. } => 2.5,
        OpenerIssue::FormTargetBlank { .. } => 3.0,
        OpenerIssue::AreaTargetBlank { .. } => 3.0,
        OpenerIssue::BaseTargetBlank => 2.0,
        OpenerIssue::WindowOpenNoFeatures { .. } => 3.5,
        OpenerIssue::JavascriptWindowOpen => 4.0,
        OpenerIssue::ExternalLinkNoRel { .. } => 2.0,
        OpenerIssue::UserContentLink { .. } => 4.5,
    }
}

pub fn audit_opener(target: &str) -> Vec<OpenerIssue> {
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
    find_opener_issues(&body)
}

fn is_external(href: &str) -> bool {
    href.starts_with("http://") || href.starts_with("https://")
}

const USER_CONTENT_PATTERNS: &[&str] = &["?url=", "?redirect=", "&url=", "&redirect="];

fn is_user_content_link(href: &str) -> bool {
    let lower = href.to_ascii_lowercase();
    USER_CONTENT_PATTERNS.iter().any(|p| lower.contains(p))
}

pub fn find_opener_issues(html: &str) -> Vec<OpenerIssue> {
    let mut issues = Vec::new();

    check_anchor_tags(html, &mut issues);
    check_form_tags(html, &mut issues);
    check_area_tags(html, &mut issues);
    check_base_tags(html, &mut issues);
    check_script_window_open(html, &mut issues);
    check_javascript_hrefs(html, &mut issues);

    issues
}

fn check_anchor_tags(html: &str, issues: &mut Vec<OpenerIssue>) {
    for tag in TagIter::new(html, "a") {
        let href = html_parser::extract_attr(tag.original, &tag.lower, "href").unwrap_or_default();
        if !is_external(&href) {
            continue;
        }

        if is_user_content_link(&href) {
            issues.push(OpenerIssue::UserContentLink { href: href.clone() });
        }

        let target_attr = html_parser::extract_attr_lower(&tag.lower, "target").unwrap_or_default();
        let has_rel = tag.lower.contains("rel=");
        let rel = html_parser::extract_attr_lower(&tag.lower, "rel").unwrap_or_default();

        if target_attr == "_blank" {
            if !rel.contains("noopener") {
                issues.push(OpenerIssue::MissingNoopener { href: href.clone() });
            }
            if !rel.contains("noreferrer") {
                issues.push(OpenerIssue::MissingNoreferrer { href: href.clone() });
            }
        } else if !has_rel {
            issues.push(OpenerIssue::ExternalLinkNoRel { href: href.clone() });
        }
    }
}

fn check_form_tags(html: &str, issues: &mut Vec<OpenerIssue>) {
    for tag in TagIter::new(html, "form") {
        let target_attr = html_parser::extract_attr_lower(&tag.lower, "target").unwrap_or_default();
        if target_attr != "_blank" {
            continue;
        }
        let action =
            html_parser::extract_attr(tag.original, &tag.lower, "action").unwrap_or_default();
        if is_external(&action) {
            issues.push(OpenerIssue::FormTargetBlank { action });
        }
    }
}

fn check_area_tags(html: &str, issues: &mut Vec<OpenerIssue>) {
    for tag in TagIter::new(html, "area") {
        let target_attr = html_parser::extract_attr_lower(&tag.lower, "target").unwrap_or_default();
        if target_attr != "_blank" {
            continue;
        }
        let rel = html_parser::extract_attr_lower(&tag.lower, "rel").unwrap_or_default();
        if rel.contains("noopener") {
            continue;
        }
        let href = html_parser::extract_attr(tag.original, &tag.lower, "href").unwrap_or_default();
        if !href.is_empty() {
            issues.push(OpenerIssue::AreaTargetBlank { href });
        }
    }
}

fn check_base_tags(html: &str, issues: &mut Vec<OpenerIssue>) {
    for tag in TagIter::new(html, "base") {
        let target_attr = html_parser::extract_attr_lower(&tag.lower, "target").unwrap_or_default();
        if target_attr == "_blank" {
            issues.push(OpenerIssue::BaseTargetBlank);
        }
    }
}

fn check_script_window_open(html: &str, issues: &mut Vec<OpenerIssue>) {
    let lower = html.to_ascii_lowercase();
    let mut pos = 0;
    while let Some(start) = lower[pos..].find("<script") {
        let abs_start = pos + start;
        let Some(end_offset) = lower[abs_start..].find("</script") else {
            break;
        };
        let script_body = &html[abs_start..abs_start + end_offset];
        let script_lower = &lower[abs_start..abs_start + end_offset];
        scan_window_open_calls(script_body, script_lower, issues);
        pos = abs_start + end_offset + 9;
    }
}

fn scan_window_open_calls(script: &str, script_lower: &str, issues: &mut Vec<OpenerIssue>) {
    let mut search_pos = 0;
    while let Some(idx) = script_lower[search_pos..].find("window.open(") {
        let abs = search_pos + idx;
        let after = &script[abs + 12..];
        let paren_end = find_matching_paren(after);
        let args = &after[..paren_end];
        let comma_count = args.chars().filter(|&c| c == ',').count();
        if comma_count < 2 {
            let context_start = abs.saturating_sub(20);
            let context_end = (abs + 12 + paren_end + 1).min(script.len());
            let context = script[context_start..context_end].trim().to_string();
            issues.push(OpenerIssue::WindowOpenNoFeatures { context });
        }
        search_pos = abs + 12;
    }
}

fn find_matching_paren(s: &str) -> usize {
    let mut depth = 1u32;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => {}
        }
    }
    s.len()
}

fn check_javascript_hrefs(html: &str, issues: &mut Vec<OpenerIssue>) {
    for tag in TagIter::new(html, "a") {
        let href = html_parser::extract_attr(tag.original, &tag.lower, "href").unwrap_or_default();
        let href_lower = href.to_ascii_lowercase();
        if href_lower.starts_with("javascript:") && href_lower.contains("window.open(") {
            issues.push(OpenerIssue::JavascriptWindowOpen);
        }
    }
}

pub fn opener_to_operations(issues: &[OpenerIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                opener_severity(issue),
                0.5,
            )
        })
        .collect()
}
