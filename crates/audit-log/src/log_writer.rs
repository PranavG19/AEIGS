use crate::hash_chain::{HashChain, Hash};
use crate::hmac_signer::{HmacSigner, MacBytes};
use aegis_protocol::audit::{AuditEntry, AuditEventType};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

#[derive(Debug)]
pub enum LogWriterError {
    IoError(io::Error),
    SerializationError(String),
}

impl std::fmt::Display for LogWriterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "io error: {e}"),
            Self::SerializationError(e) => write!(f, "serialization error: {e}"),
        }
    }
}

impl std::error::Error for LogWriterError {}

impl From<io::Error> for LogWriterError {
    fn from(e: io::Error) -> Self {
        Self::IoError(e)
    }
}

pub struct AuditLogWriter {
    chain: HashChain,
    signer: HmacSigner,
    sequence: u64,
    file: File,
}

impl AuditLogWriter {
    pub fn create(path: &Path, hmac_key: &[u8]) -> Result<Self, LogWriterError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .truncate(false)
            .open(path)?;

        Ok(Self {
            chain: HashChain::new(),
            signer: HmacSigner::new(hmac_key),
            sequence: 0,
            file,
        })
    }

    pub fn append_event(&mut self, event: AuditEventType) -> Result<AuditEntry, LogWriterError> {
        let timestamp_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let payload_cbor = serialize_event_to_cbor(&event)?;
        let previous_hash = self.chain.current_hash();
        let entry_hash = self.chain.append(&payload_cbor);
        let hmac = self.signer.sign(&payload_cbor);

        let entry = AuditEntry {
            sequence_number: self.sequence,
            previous_hash,
            timestamp_unix_ms,
            event,
            payload_cbor: payload_cbor.clone(),
            hmac,
        };

        self.write_entry_to_file(&entry_hash, &payload_cbor, &hmac)?;
        self.sequence += 1;

        Ok(entry)
    }

    fn write_entry_to_file(
        &mut self,
        entry_hash: &Hash,
        payload_cbor: &[u8],
        hmac: &MacBytes,
    ) -> Result<(), LogWriterError> {
        let seq_bytes = self.sequence.to_le_bytes();
        let payload_len = (payload_cbor.len() as u32).to_le_bytes();

        self.file.write_all(&seq_bytes)?;
        self.file.write_all(entry_hash)?;
        self.file.write_all(&payload_len)?;
        self.file.write_all(payload_cbor)?;
        self.file.write_all(hmac)?;
        self.file.flush()?;

        Ok(())
    }

    pub fn sequence_number(&self) -> u64 {
        self.sequence
    }
}

fn serialize_event_to_cbor(event: &AuditEventType) -> Result<Vec<u8>, LogWriterError> {
    let mut buf = Vec::new();
    ciborium::into_writer(event, &mut buf)
        .map_err(|e| LogWriterError::SerializationError(e.to_string()))?;
    Ok(buf)
}

pub fn serialize_event(event: &AuditEventType) -> Result<Vec<u8>, LogWriterError> {
    serialize_event_to_cbor(event)
}
