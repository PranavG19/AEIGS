use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeDocument {
    pub target: String,
    pub authorized_by: String,
    pub valid_until: String,
    pub scope_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedScopeAttestation {
    pub document: ScopeDocument,
    pub public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Debug)]
pub enum AttestationError {
    InvalidSignature,
    Expired(String),
    TargetMismatch { expected: String, actual: String },
    InvalidPublicKey(String),
    InvalidFormat(String),
}

impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "invalid Ed25519 signature"),
            Self::Expired(date) => write!(f, "scope attestation expired on {date}"),
            Self::TargetMismatch { expected, actual } => {
                write!(f, "target mismatch: expected {expected}, got {actual}")
            }
            Self::InvalidPublicKey(msg) => write!(f, "invalid public key: {msg}"),
            Self::InvalidFormat(msg) => write!(f, "invalid attestation format: {msg}"),
        }
    }
}

impl std::error::Error for AttestationError {}

/// Verifies the attestation signature and checks it matches the target.
pub fn verify_attestation(
    attestation: &SignedScopeAttestation,
    target: &str,
) -> Result<(), AttestationError> {
    let pubkey_bytes = hex_decode(&attestation.public_key_hex)
        .map_err(|e| AttestationError::InvalidPublicKey(e.to_string()))?;
    let pubkey_array: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| AttestationError::InvalidPublicKey("expected 32 bytes".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
        .map_err(|e| AttestationError::InvalidPublicKey(e.to_string()))?;

    let sig_bytes = hex_decode(&attestation.signature_hex)
        .map_err(|e| AttestationError::InvalidFormat(format!("bad signature hex: {e}")))?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| AttestationError::InvalidFormat("signature must be 64 bytes".to_string()))?;
    let signature = Signature::from_bytes(&sig_array);

    let canonical_json = serde_json::to_vec(&attestation.document)
        .map_err(|e| AttestationError::InvalidFormat(e.to_string()))?;

    verifying_key
        .verify(&canonical_json, &signature)
        .map_err(|_| AttestationError::InvalidSignature)?;

    check_target_match(&attestation.document.target, target)?;
    check_expiry(&attestation.document.valid_until)?;

    Ok(())
}

/// Signs a scope document with the given Ed25519 secret key.
pub fn sign_scope_document(
    document: &ScopeDocument,
    signing_key: &SigningKey,
) -> SignedScopeAttestation {
    let canonical_json = serde_json::to_vec(document).expect("ScopeDocument must serialize");
    let signature = signing_key.sign(&canonical_json);
    let verifying_key = signing_key.verifying_key();

    SignedScopeAttestation {
        document: document.clone(),
        public_key_hex: hex_encode(verifying_key.as_bytes()),
        signature_hex: hex_encode(&signature.to_bytes()),
    }
}

/// Loads a signed attestation from a JSON file.
pub fn load_attestation(path: &Path) -> Result<SignedScopeAttestation, AttestationError> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| AttestationError::InvalidFormat(format!("cannot read file: {e}")))?;
    serde_json::from_str(&contents)
        .map_err(|e| AttestationError::InvalidFormat(format!("invalid JSON: {e}")))
}

fn normalize_url(url: &str) -> String {
    let trimmed = url.trim_end_matches('/');
    let lower = trimmed.to_lowercase();

    if let Some(scheme_end) = lower.find("://") {
        let scheme = &lower[..scheme_end];
        let rest = &trimmed[scheme_end + 3..];
        if let Some(path_start) = rest.find('/') {
            let host = rest[..path_start].to_lowercase();
            let path = &rest[path_start..];
            let path = path.trim_end_matches('/');
            format!("{scheme}://{host}{path}")
        } else {
            format!("{scheme}://{}", rest.to_lowercase())
        }
    } else {
        lower.to_string()
    }
}

fn check_target_match(document_target: &str, request_target: &str) -> Result<(), AttestationError> {
    let normalized_doc = normalize_url(document_target);
    let normalized_req = normalize_url(request_target);
    if normalized_doc != normalized_req {
        return Err(AttestationError::TargetMismatch {
            expected: normalized_doc,
            actual: normalized_req,
        });
    }
    Ok(())
}

fn check_expiry(valid_until: &str) -> Result<(), AttestationError> {
    let parts: Vec<&str> = valid_until.split('-').collect();
    if parts.len() != 3 {
        return Err(AttestationError::InvalidFormat(format!(
            "date must be YYYY-MM-DD, got: {valid_until}"
        )));
    }
    let year: i32 = parts[0]
        .parse()
        .map_err(|_| AttestationError::InvalidFormat(format!("invalid year: {}", parts[0])))?;
    let month: u32 = parts[1]
        .parse()
        .map_err(|_| AttestationError::InvalidFormat(format!("invalid month: {}", parts[1])))?;
    let day: u32 = parts[2]
        .parse()
        .map_err(|_| AttestationError::InvalidFormat(format!("invalid day: {}", parts[2])))?;

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(AttestationError::InvalidFormat(format!(
            "invalid date: {valid_until}"
        )));
    }

    // 20260220 format for easy comparison
    let expiry_ordinal = year * 10000 + month as i32 * 100 + day as i32;
    let today_ordinal = today_as_ordinal();

    if expiry_ordinal < today_ordinal {
        return Err(AttestationError::Expired(valid_until.to_string()));
    }
    Ok(())
}

fn today_as_ordinal() -> i32 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // 86400 seconds per day
    let days_since_epoch = now / 86400;
    // Compute year/month/day from days since 1970-01-01
    let (y, m, d) = days_to_ymd(days_since_epoch);
    y * 10000 + m * 100 + d
}

fn days_to_ymd(days: u64) -> (i32, i32, i32) {
    // Civil calendar algorithm from Howard Hinnant
    let z = days as i64 + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as i32, d as i32)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("odd-length hex string".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at position {i}: {e}"))
        })
        .collect()
}

#[cfg(test)]
#[path = "scope_attestation_test.rs"]
mod scope_attestation_test;
