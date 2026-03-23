use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::html_parser;
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

pub fn analyze_forms(html: &str) -> Vec<FormFinding> {
    let mut findings = Vec::new();
    let lower = html.to_ascii_lowercase();
    let mut search_from = 0;

    while let Some(start) = lower[search_from..].find("<form") {
        let abs_start = search_from + start;
        let Some(tag_end) = lower[abs_start..].find('>') else {
            break;
        };
        let form_end = lower[abs_start..]
            .find("</form>")
            .unwrap_or(lower.len() - abs_start);
        let form_tag = &lower[abs_start..abs_start + tag_end + 1];
        let form_body = &lower[abs_start..abs_start + form_end];
        search_from = abs_start + form_end.max(tag_end + 1);

        let action = html_parser::extract_attr_lower(form_tag, "action").unwrap_or_default();

        if action.starts_with("http://") {
            findings.push(FormFinding {
                issue: FormIssue::InsecureAction,
                action: action.clone(),
            });
        }

        let method =
            html_parser::extract_attr_lower(form_tag, "method").unwrap_or_else(|| "get".into());
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

fn has_csrf_token(form_body: &str) -> bool {
    CSRF_TOKEN_NAMES.iter().any(|name| form_body.contains(name))
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
                FormIssue::MissingCsrfToken => (VulnerabilityClass::SecurityMisconfiguration, 6.0),
                FormIssue::AutocompleteOnSensitive => {
                    (VulnerabilityClass::SecurityMisconfiguration, 3.0)
                }
            };
            recon_client::finding_entry(seq, vuln_class, severity, 0.8)
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub enum FormSecurityIssue {
    InsecureAction { action: String },
    MissingCsrf { action: String },
    AutocompleteOnPassword,
    AutocompleteOnCreditCard,
    MissingFormAction,
    TargetBlankWithoutNoopener,
    HiddenFieldWithValue { name: String },
    FileUploadWithoutRestriction,
    PasswordWithoutMinLength,
    MixedContentForm { action: String },
    FormMethodOverride,
    MissingEnctype { action: String },
}

impl std::fmt::Display for FormSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FormSecurityIssue::InsecureAction { .. } => write!(f, "insecure_action"),
            FormSecurityIssue::MissingCsrf { .. } => write!(f, "missing_csrf"),
            FormSecurityIssue::AutocompleteOnPassword => write!(f, "autocomplete_on_password"),
            FormSecurityIssue::AutocompleteOnCreditCard => write!(f, "autocomplete_on_credit_card"),
            FormSecurityIssue::MissingFormAction => write!(f, "missing_form_action"),
            FormSecurityIssue::TargetBlankWithoutNoopener => {
                write!(f, "target_blank_without_noopener")
            }
            FormSecurityIssue::HiddenFieldWithValue { .. } => write!(f, "hidden_field_with_value"),
            FormSecurityIssue::FileUploadWithoutRestriction => {
                write!(f, "file_upload_without_restriction")
            }
            FormSecurityIssue::PasswordWithoutMinLength => write!(f, "password_without_minlength"),
            FormSecurityIssue::MixedContentForm { .. } => write!(f, "mixed_content_form"),
            FormSecurityIssue::FormMethodOverride => write!(f, "form_method_override"),
            FormSecurityIssue::MissingEnctype { .. } => write!(f, "missing_enctype"),
        }
    }
}

pub fn form_security_severity(issue: &FormSecurityIssue) -> f64 {
    match issue {
        FormSecurityIssue::MissingCsrf { .. } => 7.0,
        FormSecurityIssue::InsecureAction { .. } => 6.0,
        FormSecurityIssue::MixedContentForm { .. } => 6.0,
        FormSecurityIssue::FileUploadWithoutRestriction => 5.5,
        FormSecurityIssue::FormMethodOverride => 5.0,
        FormSecurityIssue::PasswordWithoutMinLength => 4.5,
        FormSecurityIssue::HiddenFieldWithValue { .. } => 4.0,
        FormSecurityIssue::AutocompleteOnPassword => 3.5,
        FormSecurityIssue::AutocompleteOnCreditCard => 3.5,
        FormSecurityIssue::MissingFormAction => 3.0,
        FormSecurityIssue::TargetBlankWithoutNoopener => 3.0,
        FormSecurityIssue::MissingEnctype { .. } => 2.5,
    }
}

pub fn analyze_form_security(html: &str) -> Vec<FormSecurityIssue> {
    let mut issues = Vec::new();
    let lower = html.to_ascii_lowercase();
    let mut search_from = 0;

    while let Some(start) = lower[search_from..].find("<form") {
        let abs_start = search_from + start;
        let Some(tag_end) = lower[abs_start..].find('>') else {
            break;
        };
        let form_end = lower[abs_start..]
            .find("</form>")
            .unwrap_or(lower.len() - abs_start);
        let form_tag = &lower[abs_start..abs_start + tag_end + 1];
        let form_body = &lower[abs_start..abs_start + form_end];
        search_from = abs_start + form_end.max(tag_end + 1);

        let action = crate::html_parser::extract_attr_lower(form_tag, "action").unwrap_or_default();
        let method = crate::html_parser::extract_attr_lower(form_tag, "method")
            .unwrap_or_else(|| "get".into());

        if action.is_empty() && method == "post" {
            issues.push(FormSecurityIssue::MissingFormAction);
        }

        if action.starts_with("http://") {
            issues.push(FormSecurityIssue::InsecureAction {
                action: action.clone(),
            });
            issues.push(FormSecurityIssue::MixedContentForm {
                action: action.clone(),
            });
        }

        if method == "post" {
            let has_csrf = CSRF_TOKEN_NAMES.iter().any(|name| form_body.contains(name));
            if !has_csrf {
                issues.push(FormSecurityIssue::MissingCsrf {
                    action: action.clone(),
                });
            }
        }

        if form_body.contains("type=\"password\"") || form_body.contains("type='password'") {
            if !form_body.contains("autocomplete=\"off\"")
                && !form_body.contains("autocomplete=\"new-password\"")
            {
                issues.push(FormSecurityIssue::AutocompleteOnPassword);
            }
            if !form_body.contains("minlength") && !form_body.contains("pattern") {
                issues.push(FormSecurityIssue::PasswordWithoutMinLength);
            }
        }

        if (form_body.contains("credit") || form_body.contains("card"))
            && !form_body.contains("autocomplete=\"off\"")
        {
            issues.push(FormSecurityIssue::AutocompleteOnCreditCard);
        }

        if (form_body.contains("type=\"file\"") || form_body.contains("type='file'"))
            && !form_body.contains("accept=")
        {
            issues.push(FormSecurityIssue::FileUploadWithoutRestriction);
        }
        if (form_body.contains("type=\"file\"") || form_body.contains("type='file'"))
            && !form_tag.contains("enctype=")
        {
            issues.push(FormSecurityIssue::MissingEnctype {
                action: action.clone(),
            });
        }

        if (form_body.contains("type=\"hidden\"") || form_body.contains("type='hidden'"))
            && (form_body.contains("value=\"") || form_body.contains("value='"))
        {
            let has_non_csrf_hidden = !CSRF_TOKEN_NAMES.iter().any(|name| form_body.contains(name))
                || form_body.matches("type=\"hidden\"").count() > 1;
            if has_non_csrf_hidden {
                issues.push(FormSecurityIssue::HiddenFieldWithValue {
                    name: "hidden".to_string(),
                });
            }
        }

        if form_body.contains("_method") || form_body.contains("x-http-method") {
            issues.push(FormSecurityIssue::FormMethodOverride);
        }
    }

    if lower.contains("target=\"_blank\"")
        && !lower.contains("rel=\"noopener")
        && !lower.contains("rel=\"noreferrer")
    {
        issues.push(FormSecurityIssue::TargetBlankWithoutNoopener);
    }

    issues
}

pub fn form_security_to_operations(
    issues: &[FormSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                form_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
