use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum FetchCredentialIssue {
    CredentialsInclude,
    XhrWithCredentials,
    CrossOriginCredentials { url: String },
    HardcodedApiKey { pattern: String },
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

    if body.contains("credentials: \"include\"")
        || body.contains("credentials: 'include'")
        || body.contains("credentials:\"include\"")
        || body.contains("credentials:'include'")
    {
        issues.push(FetchCredentialIssue::CredentialsInclude);
    }

    if body.contains("withCredentials = true")
        || body.contains("withCredentials=true")
        || body.contains("withCredentials: true")
    {
        issues.push(FetchCredentialIssue::XhrWithCredentials);
    }

    for pattern in ["fetch(\"http", "fetch('http", "fetch(`http"] {
        if body.contains(pattern) && body.contains("credentials") {
            let mut search = body;
            while let Some(pos) = search.find(pattern) {
                let after = &search[pos + 6..];
                if let Some(end) = after.find(['"', '\'', '`']) {
                    let url = &after[..end];
                    if url.starts_with("http://") || url.starts_with("https://") {
                        let context_end =
                            after.get(..500).unwrap_or(after).find('}').unwrap_or(500);
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

    issues
}

pub fn fetch_credential_severity(issue: &FetchCredentialIssue) -> f64 {
    match issue {
        FetchCredentialIssue::HardcodedApiKey { .. } => 8.0,
        FetchCredentialIssue::CrossOriginCredentials { .. } => 6.5,
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
                0.75,
            )
        })
        .collect()
}
