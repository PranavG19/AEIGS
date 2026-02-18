use crate::hash_chain::{compute_next_hash, genesis_hash, Hash};
use crate::hmac_signer::HmacSigner;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

#[derive(Debug)]
pub struct VerificationReport {
    pub entries_checked: u64,
    pub first_invalid_entry: Option<u64>,
    pub tamper_detected: bool,
    pub hash_chain_valid: bool,
    pub hmac_valid: bool,
}

#[derive(Debug)]
pub enum VerifierError {
    IoError(io::Error),
    InvalidFormat(String),
}

impl std::fmt::Display for VerifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "io error: {e}"),
            Self::InvalidFormat(msg) => write!(f, "invalid format: {msg}"),
        }
    }
}

impl std::error::Error for VerifierError {}

impl From<io::Error> for VerifierError {
    fn from(e: io::Error) -> Self {
        Self::IoError(e)
    }
}

pub fn verify_log(path: &Path, hmac_key: &[u8]) -> Result<VerificationReport, VerifierError> {
    let mut file = File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    verify_log_bytes(&data, hmac_key)
}

pub fn verify_log_bytes(data: &[u8], hmac_key: &[u8]) -> Result<VerificationReport, VerifierError> {
    let signer = HmacSigner::new(hmac_key);
    let mut offset = 0;
    let mut entries_checked = 0u64;
    let mut expected_prev_hash = genesis_hash();
    let mut hash_chain_valid = true;
    let mut hmac_valid = true;
    let mut first_invalid_entry = None;

    while offset < data.len() {
        if offset + 8 + 32 + 4 > data.len() {
            return Err(VerifierError::InvalidFormat(
                "truncated entry header".to_string(),
            ));
        }

        let seq = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let mut entry_hash: Hash = [0u8; 32];
        entry_hash.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let payload_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        if offset + payload_len + 32 > data.len() {
            return Err(VerifierError::InvalidFormat(
                "truncated entry payload or hmac".to_string(),
            ));
        }

        let payload = &data[offset..offset + payload_len];
        offset += payload_len;

        let mut recorded_hmac: [u8; 32] = [0u8; 32];
        recorded_hmac.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let computed_hash = compute_next_hash(&expected_prev_hash, payload);
        if computed_hash != entry_hash {
            hash_chain_valid = false;
            if first_invalid_entry.is_none() {
                first_invalid_entry = Some(seq);
            }
        }

        if !signer.verify(payload, &recorded_hmac) {
            hmac_valid = false;
            if first_invalid_entry.is_none() {
                first_invalid_entry = Some(seq);
            }
        }

        expected_prev_hash = entry_hash;
        entries_checked += 1;
    }

    let tamper_detected = !hash_chain_valid || !hmac_valid;

    Ok(VerificationReport {
        entries_checked,
        first_invalid_entry,
        tamper_detected,
        hash_chain_valid,
        hmac_valid,
    })
}
