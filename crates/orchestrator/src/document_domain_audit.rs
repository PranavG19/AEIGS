use std::fmt;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum DocumentDomainIssue {
    Assignment { snippet: String },
    DynamicAssignment { snippet: String },
    ParentDomainRelaxation { snippet: String },
    DeprecatedApiUsage,
    DocumentDomainInEval { snippet: String },
    DocumentDomainRead,
    ConditionalAssignment { snippet: String },
}

impl fmt::Display for DocumentDomainIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Assignment { snippet } => write!(f, "assignment: {snippet}"),
            Self::DynamicAssignment { snippet } => write!(f, "dynamic_assignment: {snippet}"),
            Self::ParentDomainRelaxation { snippet } => {
                write!(f, "parent_domain_relaxation: {snippet}")
            }
            Self::DeprecatedApiUsage => write!(f, "deprecated_api_usage"),
            Self::DocumentDomainInEval { snippet } => {
                write!(f, "document_domain_in_eval: {snippet}")
            }
            Self::DocumentDomainRead => write!(f, "document_domain_read"),
            Self::ConditionalAssignment { snippet } => {
                write!(f, "conditional_assignment: {snippet}")
            }
        }
    }
}

pub fn document_domain_severity(issue: &DocumentDomainIssue) -> f64 {
    match issue {
        DocumentDomainIssue::Assignment { .. } => 5.0,
        DocumentDomainIssue::DynamicAssignment { .. } => 6.5,
        DocumentDomainIssue::ParentDomainRelaxation { .. } => 7.0,
        DocumentDomainIssue::DeprecatedApiUsage => 3.0,
        DocumentDomainIssue::DocumentDomainInEval { .. } => 7.5,
        DocumentDomainIssue::DocumentDomainRead => 2.0,
        DocumentDomainIssue::ConditionalAssignment { .. } => 5.5,
    }
}

pub fn audit_document_domain(target: &str) -> Vec<DocumentDomainIssue> {
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
    find_document_domain(&body)
}

pub fn find_document_domain(html: &str) -> Vec<DocumentDomainIssue> {
    let lower = html.to_ascii_lowercase();
    let mut issues = Vec::new();
    let mut search_from = 0;

    while let Some(start) = lower[search_from..].find("<script") {
        let abs_start = search_from + start;
        let Some(tag_end) = lower[abs_start..].find('>') else {
            break;
        };
        let tag = &lower[abs_start..abs_start + tag_end + 1];
        if tag.contains("src=") {
            search_from = abs_start + tag_end + 1;
            continue;
        }

        let script_end = lower[abs_start + tag_end + 1..]
            .find("</script>")
            .map(|e| abs_start + tag_end + 1 + e)
            .unwrap_or(lower.len());

        let script_body_lower = &lower[abs_start + tag_end + 1..script_end];
        let original_body = &html[abs_start + tag_end + 1..script_end];
        search_from = script_end;

        if !script_body_lower.contains("document.domain") {
            continue;
        }

        issues.push(DocumentDomainIssue::DeprecatedApiUsage);

        let has_eval = script_body_lower.contains("eval(");

        if has_eval {
            let snippet = extract_snippet(original_body, "eval(");
            issues.push(DocumentDomainIssue::DocumentDomainInEval { snippet });
        }

        classify_usages(script_body_lower, original_body, &mut issues);
    }

    issues
}

fn classify_usages(script_lower: &str, original: &str, issues: &mut Vec<DocumentDomainIssue>) {
    let mut pos = 0;
    while let Some(idx) = script_lower[pos..].find("document.domain") {
        let abs = pos + idx;
        let after_keyword = abs + "document.domain".len();
        let rest = script_lower[after_keyword..].trim_start();

        if rest.starts_with('=') && !rest.starts_with("==") {
            let snippet = extract_snippet(original, "document.domain");
            let rhs = &rest[1..].trim_start();
            let line_lower = line_containing(script_lower, abs);

            if line_lower.contains("if ")
                || line_lower.contains("if(")
                || line_lower.contains("? ")
                || line_lower.contains("?\"")
            {
                issues.push(DocumentDomainIssue::ConditionalAssignment {
                    snippet: snippet.clone(),
                });
            }

            if rhs.starts_with('"') || rhs.starts_with('\'') {
                issues.push(DocumentDomainIssue::Assignment { snippet });
            } else {
                issues.push(DocumentDomainIssue::DynamicAssignment { snippet });
            }
        } else if rest.starts_with("==")
            || rest.starts_with("!=")
            || rest.is_empty()
            || rest.starts_with(')')
            || rest.starts_with(';')
            || rest.starts_with(',')
        {
            issues.push(DocumentDomainIssue::DocumentDomainRead);
        }

        pos = after_keyword;
    }
}

fn line_containing(text: &str, byte_pos: usize) -> &str {
    let start = text[..byte_pos].rfind('\n').map(|p| p + 1).unwrap_or(0);
    let end = text[byte_pos..]
        .find('\n')
        .map(|p| byte_pos + p)
        .unwrap_or(text.len());
    &text[start..end]
}

fn extract_snippet(body: &str, pattern: &str) -> String {
    let lower = body.to_ascii_lowercase();
    let Some(pos) = lower.find(pattern) else {
        return String::new();
    };
    let start = body[..pos].rfind('\n').map(|p| p + 1).unwrap_or(0);
    let end = body[pos..]
        .find('\n')
        .map(|p| pos + p)
        .unwrap_or(body.len());
    let line = body[start..end].trim();
    if line.len() > 120 {
        format!("{}...", &line[..117])
    } else {
        line.to_string()
    }
}

pub fn document_domain_to_operations(
    issues: &[DocumentDomainIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                document_domain_severity(issue),
                0.5,
            )
        })
        .collect()
}
