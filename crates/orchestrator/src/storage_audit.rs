use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum StorageIssue {
    SensitiveInLocalStorage { key: String },
    SensitiveInSessionStorage { key: String },
    TokenInStorage { storage_type: String, key: String },
    RawCredentialInStorage { storage_type: String, pattern: String },
}

impl std::fmt::Display for StorageIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SensitiveInLocalStorage { key } => {
                write!(f, "sensitive_localstorage:{key}")
            }
            Self::SensitiveInSessionStorage { key } => {
                write!(f, "sensitive_sessionstorage:{key}")
            }
            Self::TokenInStorage { storage_type, key } => {
                write!(f, "token_in_{storage_type}:{key}")
            }
            Self::RawCredentialInStorage {
                storage_type,
                pattern,
            } => {
                write!(f, "credential_in_{storage_type}:{pattern}")
            }
        }
    }
}

const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "api-key",
    "private_key",
    "privatekey",
    "credit_card",
    "creditcard",
    "ssn",
    "social_security",
];

const TOKEN_KEYS: &[&str] = &[
    "token",
    "access_token",
    "accesstoken",
    "refresh_token",
    "refreshtoken",
    "auth_token",
    "authtoken",
    "jwt",
    "bearer",
    "id_token",
    "session_token",
];

const CREDENTIAL_PATTERNS: &[&str] = &[
    "password",
    "passwd",
    "credential",
];

pub fn audit_storage(target: &str) -> Vec<StorageIssue> {
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
    analyze_storage_usage(&body)
}

pub fn analyze_storage_usage(body: &str) -> Vec<StorageIssue> {
    let mut issues = Vec::new();

    let contexts = extract_storage_contexts(body, "localStorage");
    for (key, _) in &contexts {
        let key_lower = key.to_ascii_lowercase();
        for &sensitive in SENSITIVE_KEYS {
            if key_lower.contains(sensitive) {
                issues.push(StorageIssue::SensitiveInLocalStorage {
                    key: key.to_string(),
                });
                break;
            }
        }
        for &token in TOKEN_KEYS {
            if key_lower.contains(token) {
                issues.push(StorageIssue::TokenInStorage {
                    storage_type: "localStorage".to_string(),
                    key: key.to_string(),
                });
                break;
            }
        }
    }

    let contexts = extract_storage_contexts(body, "sessionStorage");
    for (key, _) in &contexts {
        let key_lower = key.to_ascii_lowercase();
        for &sensitive in SENSITIVE_KEYS {
            if key_lower.contains(sensitive) {
                issues.push(StorageIssue::SensitiveInSessionStorage {
                    key: key.to_string(),
                });
                break;
            }
        }
        for &token in TOKEN_KEYS {
            if key_lower.contains(token) {
                issues.push(StorageIssue::TokenInStorage {
                    storage_type: "sessionStorage".to_string(),
                    key: key.to_string(),
                });
                break;
            }
        }
    }

    for &pattern in CREDENTIAL_PATTERNS {
        let search = format!("localStorage.setItem(\"{pattern}");
        if body.contains(&search) {
            issues.push(StorageIssue::RawCredentialInStorage {
                storage_type: "localStorage".to_string(),
                pattern: pattern.to_string(),
            });
        }
        let search = format!("sessionStorage.setItem(\"{pattern}");
        if body.contains(&search) {
            issues.push(StorageIssue::RawCredentialInStorage {
                storage_type: "sessionStorage".to_string(),
                pattern: pattern.to_string(),
            });
        }
    }

    issues
}

fn extract_storage_contexts(body: &str, storage_type: &str) -> Vec<(String, String)> {
    let mut results = Vec::new();

    let set_prefix = format!("{storage_type}.setItem(");
    let mut search = body;
    while let Some(pos) = search.find(&set_prefix) {
        let after = &search[pos + set_prefix.len()..];
        if let Some(key) = extract_quoted_string(after) {
            results.push((key, "setItem".to_string()));
        }
        search = &search[pos + set_prefix.len()..];
    }

    let get_prefix = format!("{storage_type}.getItem(");
    let mut search = body;
    while let Some(pos) = search.find(&get_prefix) {
        let after = &search[pos + get_prefix.len()..];
        if let Some(key) = extract_quoted_string(after) {
            results.push((key, "getItem".to_string()));
        }
        search = &search[pos + get_prefix.len()..];
    }

    let bracket_prefix = format!("{storage_type}[");
    let mut search = body;
    while let Some(pos) = search.find(&bracket_prefix) {
        let after = &search[pos + bracket_prefix.len()..];
        if let Some(key) = extract_quoted_string(after) {
            results.push((key, "bracket".to_string()));
        }
        search = &search[pos + bracket_prefix.len()..];
    }

    results
}

fn extract_quoted_string(s: &str) -> Option<String> {
    let trimmed = s.trim_start();
    let quote = trimmed.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let inner = &trimmed[1..];
    let end = inner.find(quote)?;
    Some(inner[..end].to_string())
}

pub fn storage_severity(issue: &StorageIssue) -> f64 {
    match issue {
        StorageIssue::RawCredentialInStorage { .. } => 7.0,
        StorageIssue::SensitiveInLocalStorage { .. } => 6.0,
        StorageIssue::SensitiveInSessionStorage { .. } => 5.5,
        StorageIssue::TokenInStorage {
            storage_type, ..
        } => {
            if storage_type == "localStorage" {
                5.0
            } else {
                4.0
            }
        }
    }
}

pub fn storage_to_operations(
    issues: &[StorageIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SensitiveDataExposure,
                storage_severity(issue),
                0.8,
            )
        })
        .collect()
}
