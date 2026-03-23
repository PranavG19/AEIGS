use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::html_parser::{self, TagIter};
use crate::recon_client;

const CALLBACK_PARAMS: &[&str] = &[
    "jsonpcallback=",
    "jsoncallback=",
    "_callback=",
    "callback=",
    "jsonp=",
    "cb=",
];

const SENSITIVE_PATH_TOKENS: &[&str] = &["user", "account", "profile", "auth"];

const DYNAMIC_EXPRESSION_CHARS: &[char] = &['+', '.', '[', ']', '(', ')'];

#[derive(Debug, Clone, PartialEq)]
pub enum JsonpIssue {
    CallbackParam { url: String, param: String },
    JsonpEndpoint { url: String },
    UserControlledCallback { url: String },
    SensitiveJsonpEndpoint { url: String },
    CrossDomainJsonp { url: String },
    InlineJsonpHandler,
    JsonpWithoutReferrerCheck,
    DynamicCallbackName { url: String },
    JsonpOverHttp { url: String },
}

impl std::fmt::Display for JsonpIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CallbackParam { url, param } => {
                write!(f, "callback_param:{param}:{url}")
            }
            Self::JsonpEndpoint { url } => write!(f, "jsonp_endpoint:{url}"),
            Self::UserControlledCallback { url } => {
                write!(f, "user_controlled_callback:{url}")
            }
            Self::SensitiveJsonpEndpoint { url } => {
                write!(f, "sensitive_jsonp_endpoint:{url}")
            }
            Self::CrossDomainJsonp { url } => write!(f, "cross_domain_jsonp:{url}"),
            Self::InlineJsonpHandler => write!(f, "inline_jsonp_handler"),
            Self::JsonpWithoutReferrerCheck => {
                write!(f, "jsonp_without_referrer_check")
            }
            Self::DynamicCallbackName { url } => {
                write!(f, "dynamic_callback_name:{url}")
            }
            Self::JsonpOverHttp { url } => write!(f, "jsonp_over_http:{url}"),
        }
    }
}

pub fn jsonp_severity(issue: &JsonpIssue) -> f64 {
    match issue {
        JsonpIssue::CallbackParam { .. } => 5.5,
        JsonpIssue::JsonpEndpoint { .. } => 4.5,
        JsonpIssue::UserControlledCallback { .. } => 7.0,
        JsonpIssue::SensitiveJsonpEndpoint { .. } => 6.0,
        JsonpIssue::CrossDomainJsonp { .. } => 5.0,
        JsonpIssue::InlineJsonpHandler => 4.0,
        JsonpIssue::JsonpWithoutReferrerCheck => 3.5,
        JsonpIssue::DynamicCallbackName { .. } => 5.5,
        JsonpIssue::JsonpOverHttp { .. } => 4.5,
    }
}

pub fn audit_jsonp(target: &str) -> Vec<JsonpIssue> {
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
    find_jsonp_endpoints(&body)
}

pub fn find_jsonp_endpoints(html: &str) -> Vec<JsonpIssue> {
    let mut issues = Vec::new();

    scan_script_tags(html, &mut issues);
    scan_inline_scripts(html, &mut issues);

    issues
}

fn scan_script_tags(html: &str, issues: &mut Vec<JsonpIssue>) {
    for tag in TagIter::new(html, "script") {
        let Some(src) = html_parser::extract_attr(tag.original, &tag.lower, "src") else {
            continue;
        };
        let src_lower = src.to_ascii_lowercase();
        let truncated = recon_client::truncate(&src, 100);

        let matched_param = find_callback_param(&src_lower);

        if let Some(param) = &matched_param {
            issues.push(JsonpIssue::CallbackParam {
                url: truncated.clone(),
                param: param.clone(),
            });

            if has_user_controlled_value(&src_lower, param) {
                issues.push(JsonpIssue::UserControlledCallback {
                    url: truncated.clone(),
                });
            }

            if has_dynamic_callback_value(&src_lower, param) {
                issues.push(JsonpIssue::DynamicCallbackName {
                    url: truncated.clone(),
                });
            }
        }

        let is_jsonp_path = (src_lower.contains("jsonp") || src_lower.ends_with(".jsonp"))
            && matched_param.is_none();
        if is_jsonp_path {
            issues.push(JsonpIssue::JsonpEndpoint {
                url: truncated.clone(),
            });
        }

        let has_jsonp_signal = matched_param.is_some() || is_jsonp_path;

        if has_jsonp_signal && is_sensitive_path(&src_lower) {
            issues.push(JsonpIssue::SensitiveJsonpEndpoint {
                url: truncated.clone(),
            });
        }

        if has_jsonp_signal && is_cross_domain(&src_lower) {
            issues.push(JsonpIssue::CrossDomainJsonp {
                url: truncated.clone(),
            });
        }

        if has_jsonp_signal && src_lower.starts_with("http://") {
            issues.push(JsonpIssue::JsonpOverHttp {
                url: truncated.clone(),
            });
        }
    }
}

fn scan_inline_scripts(html: &str, issues: &mut Vec<JsonpIssue>) {
    let lower = html.to_ascii_lowercase();
    let mut search_from = 0;
    let mut found_inline = false;
    let mut found_no_referrer = false;

    while let Some(start) = lower[search_from..].find("<script") {
        let abs_start = search_from + start;
        let Some(tag_end) = lower[abs_start..].find('>') else {
            break;
        };
        let tag_lower = &lower[abs_start..abs_start + tag_end + 1];

        if tag_lower.contains("src=") {
            search_from = abs_start + tag_end + 1;
            continue;
        }

        let script_end = lower[abs_start + tag_end + 1..]
            .find("</script>")
            .map(|e| abs_start + tag_end + 1 + e)
            .unwrap_or(lower.len());

        let script_body = &lower[abs_start + tag_end + 1..script_end];
        search_from = script_end;

        if !found_inline && has_inline_jsonp_handler(script_body) {
            issues.push(JsonpIssue::InlineJsonpHandler);
            found_inline = true;
        }

        if !found_no_referrer && has_jsonp_without_referrer_check(script_body) {
            issues.push(JsonpIssue::JsonpWithoutReferrerCheck);
            found_no_referrer = true;
        }
    }
}

fn find_callback_param(src_lower: &str) -> Option<String> {
    for param in CALLBACK_PARAMS {
        if src_lower.contains(param) {
            let name = param.trim_end_matches('=');
            return Some(name.to_string());
        }
    }
    None
}

fn has_user_controlled_value(src_lower: &str, param: &str) -> bool {
    let pattern = format!("{param}=");
    let Some(pos) = src_lower.find(&pattern) else {
        return false;
    };
    let value_start = pos + pattern.len();
    let rest = &src_lower[value_start..];
    let value_end = rest.find('&').unwrap_or(rest.len());
    let value = &rest[..value_end];

    value.contains("http://")
        || value.contains("https://")
        || value.contains("javascript:")
        || value.contains('<')
        || value.contains('>')
        || value.contains('"')
}

fn has_dynamic_callback_value(src_lower: &str, param: &str) -> bool {
    let pattern = format!("{param}=");
    let Some(pos) = src_lower.find(&pattern) else {
        return false;
    };
    let value_start = pos + pattern.len();
    let rest = &src_lower[value_start..];
    let value_end = rest.find('&').unwrap_or(rest.len());
    let value = &rest[..value_end];

    value.chars().any(|c| DYNAMIC_EXPRESSION_CHARS.contains(&c))
}

fn is_sensitive_path(src_lower: &str) -> bool {
    SENSITIVE_PATH_TOKENS.iter().any(|t| src_lower.contains(t))
}

fn is_cross_domain(src_lower: &str) -> bool {
    src_lower.starts_with("http://") || src_lower.starts_with("https://")
}

fn has_inline_jsonp_handler(script_body: &str) -> bool {
    let has_ajax_jsonp = script_body.contains("$.ajax") && script_body.contains("jsonp");
    let has_getjson_jsonp = script_body.contains("$.getjson") && script_body.contains("callback");
    let has_datatype_jsonp = script_body.contains("datatype")
        && (script_body.contains("\"jsonp\"") || script_body.contains("'jsonp'"));

    has_ajax_jsonp || has_getjson_jsonp || has_datatype_jsonp
}

fn has_jsonp_without_referrer_check(script_body: &str) -> bool {
    let has_jsonp_call = script_body.contains("jsonp")
        || script_body.contains("callback=")
        || script_body.contains("$.getjson");
    let has_referrer_check = script_body.contains("referrer") || script_body.contains("referer");

    has_jsonp_call && !has_referrer_check
}

pub fn jsonp_to_operations(issues: &[JsonpIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::CrossSiteScripting,
                jsonp_severity(issue),
                0.5,
            )
        })
        .collect()
}
