use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum FetchCredentialIssue {
    CredentialsInclude,
    XhrWithCredentials,
    CrossOriginCredentials { url: String },
    HardcodedApiKey { pattern: String },
    HardcodedBearerToken,
    HardcodedPassword { context: String },
    CredentialsInUrl { url: String },
    InsecureFetchHttp { url: String },
    StorageCredentialAccess { storage_type: String },
    PostMessageCredentials,
    EvalWithCredentials,
}

impl std::fmt::Display for FetchCredentialIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CredentialsInclude => write!(f, "fetch_credentials_include"),
            Self::XhrWithCredentials => write!(f, "xhr_with_credentials"),
            Self::CrossOriginCredentials { url } => {
                write!(f, "cross_origin_credentials:{url}")
            }
            Self::HardcodedApiKey { pattern } => {
                write!(f, "hardcoded_api_key:{pattern}")
            }
            Self::HardcodedBearerToken => write!(f, "hardcoded_bearer_token"),
            Self::HardcodedPassword { context } => {
                write!(f, "hardcoded_password:{context}")
            }
            Self::CredentialsInUrl { url } => {
                write!(f, "credentials_in_url:{url}")
            }
            Self::InsecureFetchHttp { url } => {
                write!(f, "insecure_fetch_http:{url}")
            }
            Self::StorageCredentialAccess { storage_type } => {
                write!(f, "storage_credential_access:{storage_type}")
            }
            Self::PostMessageCredentials => write!(f, "postmessage_credentials"),
            Self::EvalWithCredentials => write!(f, "eval_with_credentials"),
        }
    }
}

const API_KEY_PATTERNS: &[&str] = &[
    "api_key",
    "apiKey",
    "api-key",
    "apikey",
    "secret_key",
    "secretKey",
    "access_key",
    "accessKey",
    "private_key",
    "privateKey",
];

const PASSWORD_PATTERNS: &[&str] = &["password", "passwd", "secret_key", "secretKey"];

const STORAGE_CREDENTIAL_KEYS: &[&str] = &[
    "token",
    "auth",
    "session",
    "jwt",
    "access_token",
    "accessToken",
    "refresh_token",
    "refreshToken",
    "api_key",
    "apiKey",
    "credential",
];

pub fn audit_fetch_credentials(target: &str) -> Vec<FetchCredentialIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };

    let resp = match client.get(target).send() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let body = resp.text().unwrap_or_default();
    analyze_fetch_credentials(&body)
}

pub fn analyze_fetch_credentials(body: &str) -> Vec<FetchCredentialIssue> {
    let mut issues = Vec::new();

    detect_credentials_include(body, &mut issues);
    detect_xhr_with_credentials(body, &mut issues);
    detect_cross_origin_credentials(body, &mut issues);
    detect_hardcoded_api_key(body, &mut issues);
    detect_hardcoded_bearer_token(body, &mut issues);
    detect_hardcoded_password(body, &mut issues);
    detect_credentials_in_url(body, &mut issues);
    detect_insecure_fetch_http(body, &mut issues);
    detect_storage_credential_access(body, &mut issues);
    detect_postmessage_credentials(body, &mut issues);
    detect_eval_with_credentials(body, &mut issues);

    issues
}

pub fn fetch_credential_severity(issue: &FetchCredentialIssue) -> f64 {
    match issue {
        FetchCredentialIssue::HardcodedApiKey { .. } => 8.0,
        FetchCredentialIssue::HardcodedBearerToken => 8.5,
        FetchCredentialIssue::HardcodedPassword { .. } => 9.0,
        FetchCredentialIssue::CredentialsInUrl { .. } => 7.5,
        FetchCredentialIssue::EvalWithCredentials => 7.0,
        FetchCredentialIssue::CrossOriginCredentials { .. } => 6.5,
        FetchCredentialIssue::InsecureFetchHttp { .. } => 6.0,
        FetchCredentialIssue::StorageCredentialAccess { .. } => 5.5,
        FetchCredentialIssue::PostMessageCredentials => 5.5,
        FetchCredentialIssue::CredentialsInclude => 5.0,
        FetchCredentialIssue::XhrWithCredentials => 5.0,
    }
}

pub fn fetch_credential_to_operations(
    issues: &[FetchCredentialIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                fetch_credential_severity(issue),
                0.5,
            )
        })
        .collect()
}

fn detect_credentials_include(body: &str, issues: &mut Vec<FetchCredentialIssue>) {
    if body.contains("credentials: \"include\"")
        || body.contains("credentials: 'include'")
        || body.contains("credentials:\"include\"")
        || body.contains("credentials:'include'")
    {
        issues.push(FetchCredentialIssue::CredentialsInclude);
    }
}

fn detect_xhr_with_credentials(body: &str, issues: &mut Vec<FetchCredentialIssue>) {
    if body.contains("withCredentials = true")
        || body.contains("withCredentials=true")
        || body.contains("withCredentials: true")
    {
        issues.push(FetchCredentialIssue::XhrWithCredentials);
    }
}

fn detect_cross_origin_credentials(body: &str, issues: &mut Vec<FetchCredentialIssue>) {
    for pattern in ["fetch(\"http", "fetch('http", "fetch(`http"] {
        if !body.contains(pattern) || !body.contains("credentials") {
            continue;
        }
        let mut search = body;
        while let Some(pos) = search.find(pattern) {
            let after = &search[pos + 7..];
            if let Some(end) = after.find(['"', '\'', '`']) {
                let url = &after[..end];
                if url.starts_with("http://") || url.starts_with("https://") {
                    let context_end = after.get(..500).unwrap_or(after).find('}').unwrap_or(500);
                    let context = &after[..context_end.min(after.len())];
                    if context.contains("credentials") {
                        issues.push(FetchCredentialIssue::CrossOriginCredentials {
                            url: url.to_string(),
                        });
                    }
                }
            }
            search = &search[pos + pattern.len()..];
        }
    }
}

fn detect_hardcoded_api_key(body: &str, issues: &mut Vec<FetchCredentialIssue>) {
    for &key_pattern in API_KEY_PATTERNS {
        let search_double = format!("{key_pattern}\":\"");
        let search_single = format!("{key_pattern}':'");
        let search_assign = format!("{key_pattern} = \"");
        let search_assign2 = format!("{key_pattern} = '");

        if body.contains(&search_double)
            || body.contains(&search_single)
            || body.contains(&search_assign)
            || body.contains(&search_assign2)
        {
            issues.push(FetchCredentialIssue::HardcodedApiKey {
                pattern: key_pattern.to_string(),
            });
            break;
        }
    }
}

fn detect_hardcoded_bearer_token(body: &str, issues: &mut Vec<FetchCredentialIssue>) {
    let lower = body.to_lowercase();
    if lower.contains("authorization: bearer ")
        || lower.contains("authorization\":\"bearer ")
        || lower.contains("authorization\": \"bearer ")
        || lower.contains("authorization':'bearer ")
        || lower.contains("authorization': 'bearer ")
        || lower.contains("\"bearer ey")
        || lower.contains("'bearer ey")
    {
        issues.push(FetchCredentialIssue::HardcodedBearerToken);
    }
}

fn detect_hardcoded_password(body: &str, issues: &mut Vec<FetchCredentialIssue>) {
    for &pwd_pattern in PASSWORD_PATTERNS {
        let search_double = format!("{pwd_pattern}\":\"");
        let search_single = format!("{pwd_pattern}':'");
        let search_colon_space_double = format!("{pwd_pattern}\": \"");
        let search_colon_space_single = format!("{pwd_pattern}': '");

        if body.contains(&search_double)
            || body.contains(&search_single)
            || body.contains(&search_colon_space_double)
            || body.contains(&search_colon_space_single)
        {
            issues.push(FetchCredentialIssue::HardcodedPassword {
                context: pwd_pattern.to_string(),
            });
            break;
        }
    }
}

fn detect_credentials_in_url(body: &str, issues: &mut Vec<FetchCredentialIssue>) {
    for prefix in ["http://", "https://"] {
        let mut search = body;
        while let Some(pos) = search.find(prefix) {
            let after = &search[pos..];
            let url_end = after
                .find(['"', '\'', '`', ' ', ')', '}', ']', '\n'])
                .unwrap_or(after.len());
            let url_candidate = &after[..url_end];
            let without_scheme = &url_candidate[prefix.len()..];
            if without_scheme.contains('@') {
                let before_at = &without_scheme[..without_scheme.find('@').unwrap_or(0)];
                if before_at.contains(':') {
                    issues.push(FetchCredentialIssue::CredentialsInUrl {
                        url: url_candidate.to_string(),
                    });
                }
            }
            search = &search[pos + prefix.len()..];
        }
    }
}

fn detect_insecure_fetch_http(body: &str, issues: &mut Vec<FetchCredentialIssue>) {
    for pattern in ["fetch(\"http://", "fetch('http://", "fetch(`http://"] {
        let mut search = body;
        while let Some(pos) = search.find(pattern) {
            let url_start = pos + 7; // skip "fetch(" + opening quote char
            let after = &search[url_start..];
            let end = after.find(['"', '\'', '`']).unwrap_or(after.len());
            let url = &after[..end];
            if url.starts_with("http://") {
                issues.push(FetchCredentialIssue::InsecureFetchHttp {
                    url: url.to_string(),
                });
            }
            search = &search[pos + pattern.len()..];
        }
    }
}

fn detect_storage_credential_access(body: &str, issues: &mut Vec<FetchCredentialIssue>) {
    for storage_type in ["localStorage", "sessionStorage"] {
        for &key in STORAGE_CREDENTIAL_KEYS {
            let get_double = format!("{storage_type}.getItem(\"{key}\")");
            let get_single = format!("{storage_type}.getItem('{key}')");
            if body.contains(&get_double) || body.contains(&get_single) {
                issues.push(FetchCredentialIssue::StorageCredentialAccess {
                    storage_type: storage_type.to_string(),
                });
                return;
            }
        }
    }
}

fn detect_postmessage_credentials(body: &str, issues: &mut Vec<FetchCredentialIssue>) {
    if !body.contains("postMessage(") {
        return;
    }
    let credential_indicators = [
        "token",
        "password",
        "credential",
        "secret",
        "auth",
        "session",
        "jwt",
        "api_key",
        "apiKey",
        "access_token",
        "accessToken",
    ];
    let mut search = body;
    while let Some(pos) = search.find("postMessage(") {
        let after = &search[pos..];
        let context_end = after.get(..300).unwrap_or(after).find(';').unwrap_or(300);
        let context = &after[..context_end.min(after.len())];
        for indicator in &credential_indicators {
            if context.contains(indicator) {
                issues.push(FetchCredentialIssue::PostMessageCredentials);
                return;
            }
        }
        search = &search[pos + 12..];
    }
}

fn detect_eval_with_credentials(body: &str, issues: &mut Vec<FetchCredentialIssue>) {
    if !body.contains("eval(") {
        return;
    }
    let credential_indicators = [
        "token",
        "password",
        "credential",
        "secret",
        "auth",
        "api_key",
        "apiKey",
        "bearer",
        "session",
    ];
    let mut search = body;
    while let Some(pos) = search.find("eval(") {
        let start = pos.saturating_sub(200);
        let end = (pos + 200).min(search.len());
        let context = &search[start..end];
        for indicator in &credential_indicators {
            if context.contains(indicator) {
                issues.push(FetchCredentialIssue::EvalWithCredentials);
                return;
            }
        }
        search = &search[pos + 5..];
    }
}
