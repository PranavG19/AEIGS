use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignableConfig {
    pub target: String,
    pub stealth_level: String,
    pub max_iterations: u32,
    pub convergence_threshold: u32,
    pub no_llm: bool,
    pub include_endpoints: Option<Vec<String>>,
    pub exclude_endpoints: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedConfig {
    pub config: SignableConfig,
    pub config_hash: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Debug)]
pub enum SignedConfigError {
    InvalidSignature,
    HashMismatch { expected: String, actual: String },
    InvalidPublicKey(String),
    InvalidFormat(String),
}

impl std::fmt::Display for SignedConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "invalid Ed25519 signature on config"),
            Self::HashMismatch { expected, actual } => {
                write!(f, "config hash mismatch: expected {expected}, got {actual}")
            }
            Self::InvalidPublicKey(msg) => write!(f, "invalid public key: {msg}"),
            Self::InvalidFormat(msg) => write!(f, "invalid signed config format: {msg}"),
        }
    }
}

impl std::error::Error for SignedConfigError {}

/// Computes SHA3-256 hash of the canonical JSON representation.
pub fn compute_config_hash(config: &SignableConfig) -> String {
    let canonical_json = serde_json::to_vec(config).expect("SignableConfig must serialize");
    let mut hasher = Sha3_256::new();
    hasher.update(&canonical_json);
    hex_encode(&hasher.finalize())
}

/// Signs a signable configuration with Ed25519.
pub fn sign_config(config: &SignableConfig, signing_key: &SigningKey) -> SignedConfig {
    let config_hash = compute_config_hash(config);
    let canonical_json = serde_json::to_vec(config).expect("SignableConfig must serialize");
    let signature = signing_key.sign(&canonical_json);
    let verifying_key = signing_key.verifying_key();

    SignedConfig {
        config: config.clone(),
        config_hash,
        public_key_hex: hex_encode(verifying_key.as_bytes()),
        signature_hex: hex_encode(&signature.to_bytes()),
    }
}

/// Verifies signature and hash integrity.
pub fn verify_signed_config(signed: &SignedConfig) -> Result<(), SignedConfigError> {
    let actual_hash = compute_config_hash(&signed.config);
    if actual_hash != signed.config_hash {
        return Err(SignedConfigError::HashMismatch {
            expected: signed.config_hash.clone(),
            actual: actual_hash,
        });
    }

    let pubkey_bytes = hex_decode(&signed.public_key_hex)
        .map_err(|e| SignedConfigError::InvalidPublicKey(e.to_string()))?;
    let pubkey_array: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| SignedConfigError::InvalidPublicKey("expected 32 bytes".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
        .map_err(|e| SignedConfigError::InvalidPublicKey(e.to_string()))?;

    let sig_bytes = hex_decode(&signed.signature_hex)
        .map_err(|e| SignedConfigError::InvalidFormat(format!("bad signature hex: {e}")))?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| SignedConfigError::InvalidFormat("signature must be 64 bytes".to_string()))?;
    let signature = Signature::from_bytes(&sig_array);

    let canonical_json = serde_json::to_vec(&signed.config)
        .map_err(|e| SignedConfigError::InvalidFormat(e.to_string()))?;

    verifying_key
        .verify(&canonical_json, &signature)
        .map_err(|_| SignedConfigError::InvalidSignature)?;

    Ok(())
}

/// Loads a signed configuration from a JSON file.
pub fn load_signed_config(path: &Path) -> Result<SignedConfig, SignedConfigError> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| SignedConfigError::InvalidFormat(format!("cannot read file: {e}")))?;
    serde_json::from_str(&contents)
        .map_err(|e| SignedConfigError::InvalidFormat(format!("invalid JSON: {e}")))
}

/// Checks that each field in the signed config matches the actual config.
pub fn verify_config_matches(
    signed: &SignableConfig,
    actual: &SignableConfig,
) -> Result<(), String> {
    if signed.target != actual.target {
        return Err(format!(
            "target mismatch: signed={}, actual={}",
            signed.target, actual.target
        ));
    }
    if signed.stealth_level != actual.stealth_level {
        return Err(format!(
            "stealth_level mismatch: signed={}, actual={}",
            signed.stealth_level, actual.stealth_level
        ));
    }
    if signed.max_iterations != actual.max_iterations {
        return Err(format!(
            "max_iterations mismatch: signed={}, actual={}",
            signed.max_iterations, actual.max_iterations
        ));
    }
    if signed.convergence_threshold != actual.convergence_threshold {
        return Err(format!(
            "convergence_threshold mismatch: signed={}, actual={}",
            signed.convergence_threshold, actual.convergence_threshold
        ));
    }
    if signed.no_llm != actual.no_llm {
        return Err(format!(
            "no_llm mismatch: signed={}, actual={}",
            signed.no_llm, actual.no_llm
        ));
    }
    if signed.include_endpoints != actual.include_endpoints {
        return Err(format!(
            "include_endpoints mismatch: signed={:?}, actual={:?}",
            signed.include_endpoints, actual.include_endpoints
        ));
    }
    if signed.exclude_endpoints != actual.exclude_endpoints {
        return Err(format!(
            "exclude_endpoints mismatch: signed={:?}, actual={:?}",
            signed.exclude_endpoints, actual.exclude_endpoints
        ));
    }
    Ok(())
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
#[path = "signed_config_test.rs"]
mod signed_config_test;
