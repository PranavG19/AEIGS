use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

const CSRF_TOKEN_NAMES: &[&str] = &[
    "csrf",
    "csrf_token",
    "csrftoken",
    "_csrf",
    "xsrf",
    "xsrf_token",
    "_token",
    "authenticity_token",
    "__requestverificationtoken",
    "antiforgery",
    "__anti-forgery-token",
];

#[derive(Debug, Clone, PartialEq)]
pub enum FormIssue {
    InsecureAction,
    MissingCsrfToken,
    AutocompleteOnSensitive,
}

impl std::fmt::Display for FormIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FormIssue::InsecureAction => write!(f, "insecure_action"),
            FormIssue::MissingCsrfToken => write!(f, "missing_csrf_token"),
            FormIssue::AutocompleteOnSensitive => write!(f, "autocomplete_on_sensitive"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FormFinding {
    pub issue: FormIssue,
    pub action: String,
}

pub fn audit_forms(target: &str) -> Vec<FormFinding> {
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
    analyze_forms(&body)
}

pub(crate) fn analyze_forms(html: &str) -> Vec<FormFinding> {
    let mut findings = Vec::new();
    let lower = html.to_ascii_lowercase();
    let mut search_from = 0;

    while let Some(start) = lower[search_from..].find("<form") {
        let abs_start = search_from + start;
        let Some(tag_end) = lower[abs_start..].find('>') else {
            break;
        };
        let form_end = lower[abs_start..].find("</form>").unwrap_or(lower.len() - abs_start);
        let form_tag = &lower[abs_start..abs_start + tag_end + 1];
        let form_body = &lower[abs_start..abs_start + form_end];
        search_from = abs_start + form_end.max(tag_end + 1);

        let action = extract_action(form_tag).unwrap_or_default();

        if action.starts_with("http://") {
            findings.push(FormFinding {
                issue: FormIssue::InsecureAction,
                action: action.clone(),
            });
        }

        let method = extract_method(form_tag);
        if method == "post" && !has_csrf_token(form_body) {
            findings.push(FormFinding {
                issue: FormIssue::MissingCsrfToken,
                action: action.clone(),
            });
        }

        if has_sensitive_input_without_autocomplete_off(form_body) {
            findings.push(FormFinding {
                issue: FormIssue::AutocompleteOnSensitive,
                action,
            });
        }
    }

    findings
}

fn extract_action(form_tag: &str) -> Option<String> {
    let pos = form_tag.find("action=")?;
    let rest = &form_tag[pos + 7..];
    let trimmed = rest.trim_start();
    if let Some(stripped) = trimmed.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(stripped[..end].to_string())
    } else if let Some(stripped) = trimmed.strip_prefix('\'') {
        let end = stripped.find('\'')?;
        Some(stripped[..end].to_string())
    } else {
        let end = trimmed
            .find(|c: char| c.is_whitespace() || c == '>')
            .unwrap_or(trimmed.len());
        Some(trimmed[..end].to_string())
    }
}

fn extract_method(form_tag: &str) -> String {
    let pos = match form_tag.find("method=") {
        Some(p) => p,
        None => return "get".to_string(),
    };
    let rest = &form_tag[pos + 7..];
    let trimmed = rest.trim_start();
    let value = if let Some(stripped) = trimmed.strip_prefix('"') {
        stripped.find('"').map(|end| &stripped[..end])
    } else if let Some(stripped) = trimmed.strip_prefix('\'') {
        stripped.find('\'').map(|end| &stripped[..end])
    } else {
        let end = trimmed
            .find(|c: char| c.is_whitespace() || c == '>')
            .unwrap_or(trimmed.len());
        Some(&trimmed[..end])
    };
    value.unwrap_or("get").to_string()
}

fn has_csrf_token(form_body: &str) -> bool {
    CSRF_TOKEN_NAMES
        .iter()
        .any(|name| form_body.contains(name))
}

const SENSITIVE_TYPES: &[&str] = &["password", "credit", "card", "ssn", "social"];

fn has_sensitive_input_without_autocomplete_off(form_body: &str) -> bool {
    for sensitive in SENSITIVE_TYPES {
        if form_body.contains(sensitive) && !form_body.contains("autocomplete=\"off\"") {
            return true;
        }
    }
    false
}

pub fn form_findings_to_operations(
    findings: &[FormFinding],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    findings
        .iter()
        .map(|f| {
            let (vuln_class, severity) = match f.issue {
                FormIssue::InsecureAction => (VulnerabilityClass::SecurityMisconfiguration, 5.0),
                FormIssue::MissingCsrfToken => {
                    (VulnerabilityClass::SecurityMisconfiguration, 6.0)
                }
                FormIssue::AutocompleteOnSensitive => {
                    (VulnerabilityClass::SecurityMisconfiguration, 3.0)
                }
            };
            recon_client::finding_entry(seq, vuln_class, severity, 0.8)
        })
        .collect()
}
