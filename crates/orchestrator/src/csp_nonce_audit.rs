use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum CspNonceIssue {
    ShortNonce { nonce: String, length: usize },
    Base64Nonce { nonce: String },
    DuplicateNonce { nonce: String },
    NonceWithUnsafeInline,
    WeakHashAlgorithm { algorithm: String },
    MissingStrictDynamic,
}

impl std::fmt::Display for CspNonceIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShortNonce { nonce, length } => {
                write!(f, "short_csp_nonce:{length}:{nonce}")
            }
            Self::Base64Nonce { nonce } => write!(f, "base64_nonce:{nonce}"),
            Self::DuplicateNonce { nonce } => write!(f, "duplicate_nonce:{nonce}"),
            Self::NonceWithUnsafeInline => write!(f, "nonce_with_unsafe_inline"),
            Self::WeakHashAlgorithm { algorithm } => {
                write!(f, "weak_csp_hash:{algorithm}")
            }
            Self::MissingStrictDynamic => write!(f, "missing_strict_dynamic"),
        }
    }
}

const MIN_NONCE_LENGTH: usize = 16;

pub fn audit_csp_nonces(target: &str) -> Vec<CspNonceIssue> {
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

    let csp = resp
        .headers()
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    analyze_csp_nonces(csp)
}

pub fn analyze_csp_nonces(csp: &str) -> Vec<CspNonceIssue> {
    if csp.is_empty() {
        return Vec::new();
    }

    let mut issues = Vec::new();
    let mut seen_nonces = std::collections::HashSet::new();
    let has_unsafe_inline = csp.contains("'unsafe-inline'");
    let has_strict_dynamic = csp.contains("'strict-dynamic'");
    let mut has_any_nonce = false;

    for directive in csp.split(';') {
        let trimmed = directive.trim();
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let directive_name = parts[0];
        if directive_name != "script-src"
            && directive_name != "default-src"
            && directive_name != "style-src"
        {
            continue;
        }

        for &source in &parts[1..] {
            if let Some(nonce) = source
                .strip_prefix("'nonce-")
                .and_then(|s| s.strip_suffix('\''))
            {
                has_any_nonce = true;
                let owned = nonce.to_string();

                if nonce.len() < MIN_NONCE_LENGTH {
                    issues.push(CspNonceIssue::ShortNonce {
                        nonce: owned.clone(),
                        length: nonce.len(),
                    });
                }

                if is_likely_static_base64(nonce) {
                    issues.push(CspNonceIssue::Base64Nonce {
                        nonce: owned.clone(),
                    });
                }

                if !seen_nonces.insert(owned.clone()) {
                    issues.push(CspNonceIssue::DuplicateNonce { nonce: owned });
                }
            }

            if let Some(hash_part) = source.strip_prefix('\'') {
                if hash_part.starts_with("sha1-") {
                    issues.push(CspNonceIssue::WeakHashAlgorithm {
                        algorithm: "sha1".to_string(),
                    });
                }
                if hash_part.starts_with("md5-") {
                    issues.push(CspNonceIssue::WeakHashAlgorithm {
                        algorithm: "md5".to_string(),
                    });
                }
            }
        }
    }

    if has_any_nonce && has_unsafe_inline {
        issues.push(CspNonceIssue::NonceWithUnsafeInline);
    }

    if has_any_nonce && !has_strict_dynamic {
        issues.push(CspNonceIssue::MissingStrictDynamic);
    }

    issues
}

fn is_likely_static_base64(nonce: &str) -> bool {
    if nonce.len() < 8 {
        return false;
    }
    let unique_chars: std::collections::HashSet<char> = nonce.chars().collect();
    unique_chars.len() < nonce.len() / 3
}

pub fn csp_nonce_severity(issue: &CspNonceIssue) -> f64 {
    match issue {
        CspNonceIssue::DuplicateNonce { .. } => 7.0,
        CspNonceIssue::NonceWithUnsafeInline => 6.5,
        CspNonceIssue::ShortNonce { .. } => 6.0,
        CspNonceIssue::WeakHashAlgorithm { .. } => 5.5,
        CspNonceIssue::Base64Nonce { .. } => 5.0,
        CspNonceIssue::MissingStrictDynamic => 3.5,
    }
}

pub fn csp_nonce_to_operations(
    issues: &[CspNonceIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                csp_nonce_severity(issue),
                0.85,
            )
        })
        .collect()
}
